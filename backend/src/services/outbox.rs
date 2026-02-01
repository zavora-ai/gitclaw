//! Event Outbox Service
//!
//! Handles async event delivery for projections like trending and reputation.
//! Uses the transactional outbox pattern with FOR UPDATE SKIP LOCKED for
//! distributed worker coordination.
//!
//! Design Reference: DR-14.1 (Audit Service - Event Outbox)
//! Requirements: 11.7

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// Outbox service errors
#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Event not found: {0}")]
    EventNotFound(Uuid),

    #[error("Invalid topic: {0}")]
    InvalidTopic(String),
}

/// Topics for outbox events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxTopic {
    /// Trending score updates
    Trending,
    /// Reputation score updates
    Reputation,
    /// Analytics events
    Analytics,
    /// Webhook delivery
    Webhook,
}

impl OutboxTopic {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trending => "trending",
            Self::Reputation => "reputation",
            Self::Analytics => "analytics",
            Self::Webhook => "webhook",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "trending" => Some(Self::Trending),
            "reputation" => Some(Self::Reputation),
            "analytics" => Some(Self::Analytics),
            "webhook" => Some(Self::Webhook),
            _ => None,
        }
    }
}

impl std::fmt::Display for OutboxTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Outbox event status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "outbox_status", rename_all = "lowercase")]
pub enum OutboxStatus {
    Pending,
    Processing,
    Processed,
    Dead,
}

impl OutboxStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Processed => "processed",
            Self::Dead => "dead",
        }
    }
}

/// Outbox event entry
#[derive(Debug, Clone, Serialize)]
pub struct OutboxEvent {
    pub outbox_id: Uuid,
    pub audit_event_id: Uuid,
    pub topic: String,
    pub status: OutboxStatus,
    pub attempts: i32,
    pub available_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub locked_by: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
}

/// Configuration for the outbox service
#[derive(Debug, Clone)]
pub struct OutboxConfig {
    /// Maximum number of retry attempts before dead-lettering
    pub max_attempts: i32,
    /// Base delay for exponential backoff (in seconds)
    pub base_delay_secs: i64,
    /// Maximum delay for exponential backoff (in seconds)
    pub max_delay_secs: i64,
    /// Lock timeout (in seconds) - events locked longer than this are considered abandoned
    pub lock_timeout_secs: i64,
    /// Batch size for claiming events
    pub batch_size: i32,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_secs: 5,
            max_delay_secs: 3600, // 1 hour max
            lock_timeout_secs: 300, // 5 minutes
            batch_size: 10,
        }
    }
}

/// Service for managing the event outbox
#[derive(Debug, Clone)]
pub struct OutboxService {
    pool: PgPool,
    config: OutboxConfig,
}

impl OutboxService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: OutboxConfig::default(),
        }
    }

    pub fn with_config(pool: PgPool, config: OutboxConfig) -> Self {
        Self { pool, config }
    }

    /// Insert a new outbox entry for an audit event
    ///
    /// Requirements: 11.7
    pub async fn insert(
        &self,
        audit_event_id: Uuid,
        topic: OutboxTopic,
    ) -> Result<OutboxEvent, OutboxError> {
        let outbox_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO event_outbox (outbox_id, audit_event_id, topic, status, attempts, available_at, created_at)
            VALUES ($1, $2, $3, 'pending', 0, $4, $4)
            "#,
        )
        .bind(outbox_id)
        .bind(audit_event_id)
        .bind(topic.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(OutboxEvent {
            outbox_id,
            audit_event_id,
            topic: topic.to_string(),
            status: OutboxStatus::Pending,
            attempts: 0,
            available_at: now,
            locked_at: None,
            locked_by: None,
            last_error: None,
            created_at: now,
            processed_at: None,
        })
    }

    /// Insert a new outbox entry within an existing transaction
    pub async fn insert_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        audit_event_id: Uuid,
        topic: OutboxTopic,
    ) -> Result<OutboxEvent, OutboxError> {
        let outbox_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO event_outbox (outbox_id, audit_event_id, topic, status, attempts, available_at, created_at)
            VALUES ($1, $2, $3, 'pending', 0, $4, $4)
            "#,
        )
        .bind(outbox_id)
        .bind(audit_event_id)
        .bind(topic.as_str())
        .bind(now)
        .execute(&mut **tx)
        .await?;

        Ok(OutboxEvent {
            outbox_id,
            audit_event_id,
            topic: topic.to_string(),
            status: OutboxStatus::Pending,
            attempts: 0,
            available_at: now,
            locked_at: None,
            locked_by: None,
            last_error: None,
            created_at: now,
            processed_at: None,
        })
    }

    /// Claim pending events for processing using FOR UPDATE SKIP LOCKED
    ///
    /// This implements the worker claim pattern for distributed processing.
    /// Events that are already being processed by other workers are skipped.
    ///
    /// Requirements: 11.7
    pub async fn claim_events(
        &self,
        topic: OutboxTopic,
        worker_id: &str,
    ) -> Result<Vec<OutboxEvent>, OutboxError> {
        let now = Utc::now();
        let lock_timeout = now - Duration::seconds(self.config.lock_timeout_secs);

        // Claim events that are:
        // 1. Pending and available
        // 2. Processing but lock has timed out (abandoned)
        let rows = sqlx::query_as::<_, OutboxEventRow>(
            r#"
            UPDATE event_outbox
            SET status = 'processing',
                locked_at = $1,
                locked_by = $2,
                attempts = attempts + 1
            WHERE outbox_id IN (
                SELECT outbox_id FROM event_outbox
                WHERE topic = $3
                AND (
                    (status = 'pending' AND available_at <= $1)
                    OR (status = 'processing' AND locked_at < $4)
                )
                ORDER BY available_at ASC
                LIMIT $5
                FOR UPDATE SKIP LOCKED
            )
            RETURNING outbox_id, audit_event_id, topic, status, attempts, available_at,
                      locked_at, locked_by, last_error, created_at, processed_at
            "#,
        )
        .bind(now)
        .bind(worker_id)
        .bind(topic.as_str())
        .bind(lock_timeout)
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Mark an event as successfully processed
    pub async fn mark_processed(&self, outbox_id: Uuid) -> Result<(), OutboxError> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE event_outbox
            SET status = 'processed',
                processed_at = $1,
                locked_at = NULL,
                locked_by = NULL
            WHERE outbox_id = $2
            "#,
        )
        .bind(now)
        .bind(outbox_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(OutboxError::EventNotFound(outbox_id));
        }

        Ok(())
    }

    /// Mark an event as failed and schedule retry with exponential backoff
    ///
    /// If max attempts exceeded, moves to dead-letter status.
    pub async fn mark_failed(
        &self,
        outbox_id: Uuid,
        error: &str,
    ) -> Result<OutboxStatus, OutboxError> {
        // First, get the current attempt count
        let row = sqlx::query_as::<_, (i32,)>(
            "SELECT attempts FROM event_outbox WHERE outbox_id = $1",
        )
        .bind(outbox_id)
        .fetch_optional(&self.pool)
        .await?;

        let attempts = match row {
            Some((a,)) => a,
            None => return Err(OutboxError::EventNotFound(outbox_id)),
        };

        let new_status = if attempts >= self.config.max_attempts {
            OutboxStatus::Dead
        } else {
            OutboxStatus::Pending
        };

        // Calculate exponential backoff delay
        let delay_secs = self.calculate_backoff_delay(attempts);
        let next_available = Utc::now() + Duration::seconds(delay_secs);

        sqlx::query(
            r#"
            UPDATE event_outbox
            SET status = $1,
                available_at = $2,
                last_error = $3,
                locked_at = NULL,
                locked_by = NULL
            WHERE outbox_id = $4
            "#,
        )
        .bind(new_status)
        .bind(next_available)
        .bind(error)
        .bind(outbox_id)
        .execute(&self.pool)
        .await?;

        Ok(new_status)
    }

    /// Calculate exponential backoff delay
    fn calculate_backoff_delay(&self, attempts: i32) -> i64 {
        let delay = self.config.base_delay_secs * 2_i64.pow(attempts as u32);
        delay.min(self.config.max_delay_secs)
    }

    /// Get dead-lettered events for manual inspection
    pub async fn get_dead_letters(
        &self,
        topic: Option<OutboxTopic>,
        limit: i64,
    ) -> Result<Vec<OutboxEvent>, OutboxError> {
        let rows = if let Some(t) = topic {
            sqlx::query_as::<_, OutboxEventRow>(
                r#"
                SELECT outbox_id, audit_event_id, topic, status, attempts, available_at,
                       locked_at, locked_by, last_error, created_at, processed_at
                FROM event_outbox
                WHERE status = 'dead' AND topic = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(t.as_str())
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, OutboxEventRow>(
                r#"
                SELECT outbox_id, audit_event_id, topic, status, attempts, available_at,
                       locked_at, locked_by, last_error, created_at, processed_at
                FROM event_outbox
                WHERE status = 'dead'
                ORDER BY created_at DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Retry a dead-lettered event
    pub async fn retry_dead_letter(&self, outbox_id: Uuid) -> Result<(), OutboxError> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE event_outbox
            SET status = 'pending',
                attempts = 0,
                available_at = $1,
                last_error = NULL
            WHERE outbox_id = $2 AND status = 'dead'
            "#,
        )
        .bind(now)
        .bind(outbox_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(OutboxError::EventNotFound(outbox_id));
        }

        Ok(())
    }

    /// Get outbox statistics
    pub async fn get_stats(&self) -> Result<OutboxStats, OutboxError> {
        let row = sqlx::query_as::<_, OutboxStatsRow>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE status = 'processing') as processing_count,
                COUNT(*) FILTER (WHERE status = 'processed') as processed_count,
                COUNT(*) FILTER (WHERE status = 'dead') as dead_count
            FROM event_outbox
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(OutboxStats {
            pending: row.pending_count.unwrap_or(0),
            processing: row.processing_count.unwrap_or(0),
            processed: row.processed_count.unwrap_or(0),
            dead: row.dead_count.unwrap_or(0),
        })
    }

    /// Clean up old processed events
    pub async fn cleanup_processed(&self, older_than_days: i64) -> Result<u64, OutboxError> {
        let cutoff = Utc::now() - Duration::days(older_than_days);

        let result = sqlx::query(
            r#"
            DELETE FROM event_outbox
            WHERE status = 'processed' AND processed_at < $1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Outbox statistics
#[derive(Debug, Clone, Serialize)]
pub struct OutboxStats {
    pub pending: i64,
    pub processing: i64,
    pub processed: i64,
    pub dead: i64,
}

/// Internal row type for database queries
#[derive(Debug, sqlx::FromRow)]
struct OutboxEventRow {
    outbox_id: Uuid,
    audit_event_id: Uuid,
    topic: String,
    status: OutboxStatus,
    attempts: i32,
    available_at: DateTime<Utc>,
    locked_at: Option<DateTime<Utc>>,
    locked_by: Option<String>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    processed_at: Option<DateTime<Utc>>,
}

impl From<OutboxEventRow> for OutboxEvent {
    fn from(row: OutboxEventRow) -> Self {
        Self {
            outbox_id: row.outbox_id,
            audit_event_id: row.audit_event_id,
            topic: row.topic,
            status: row.status,
            attempts: row.attempts,
            available_at: row.available_at,
            locked_at: row.locked_at,
            locked_by: row.locked_by,
            last_error: row.last_error,
            created_at: row.created_at,
            processed_at: row.processed_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct OutboxStatsRow {
    pending_count: Option<i64>,
    processing_count: Option<i64>,
    processed_count: Option<i64>,
    dead_count: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbox_topic_as_str() {
        assert_eq!(OutboxTopic::Trending.as_str(), "trending");
        assert_eq!(OutboxTopic::Reputation.as_str(), "reputation");
        assert_eq!(OutboxTopic::Analytics.as_str(), "analytics");
        assert_eq!(OutboxTopic::Webhook.as_str(), "webhook");
    }

    #[test]
    fn test_outbox_topic_from_str() {
        assert_eq!(OutboxTopic::from_str("trending"), Some(OutboxTopic::Trending));
        assert_eq!(OutboxTopic::from_str("reputation"), Some(OutboxTopic::Reputation));
        assert_eq!(OutboxTopic::from_str("invalid"), None);
    }

    #[test]
    fn test_outbox_config_default() {
        let config = OutboxConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.base_delay_secs, 5);
        assert_eq!(config.max_delay_secs, 3600);
        assert_eq!(config.lock_timeout_secs, 300);
        assert_eq!(config.batch_size, 10);
    }

    #[test]
    fn test_calculate_backoff_delay() {
        let config = OutboxConfig {
            base_delay_secs: 5,
            max_delay_secs: 3600,
            ..Default::default()
        };

        // Helper function to calculate backoff
        fn calc_backoff(config: &OutboxConfig, attempts: i32) -> i64 {
            let delay = config.base_delay_secs * 2_i64.pow(attempts as u32);
            delay.min(config.max_delay_secs)
        }

        // Test exponential backoff
        assert_eq!(calc_backoff(&config, 0), 5);   // 5 * 2^0 = 5
        assert_eq!(calc_backoff(&config, 1), 10);  // 5 * 2^1 = 10
        assert_eq!(calc_backoff(&config, 2), 20);  // 5 * 2^2 = 20
        assert_eq!(calc_backoff(&config, 3), 40);  // 5 * 2^3 = 40
        assert_eq!(calc_backoff(&config, 10), 3600); // Capped at max
    }
}

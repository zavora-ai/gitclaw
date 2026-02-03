//! Reputation Service
//!
//! Computes and maintains agent reputation scores (0.0 to 1.0).
//! Reputation increases on successful merges and accurate reviews.
//! Reputation decreases on reverted merges, inaccurate reviews, and policy violations.
//!
//! Design Reference: DR-13.1 (Reputation Service)
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::services::{
    AuditAction, AuditEvent, AuditService, OutboxService, OutboxTopic, ResourceType,
};

/// Reputation service errors
#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Audit error: {0}")]
    Audit(String),

    #[error("Invalid event data: {0}")]
    InvalidEventData(String),
}

/// Reputation score bounds
const MIN_REPUTATION: f64 = 0.0;
const MAX_REPUTATION: f64 = 1.0;

/// Reputation change amounts
const MERGE_SUCCESS_INCREASE: f64 = 0.02;
const REVIEW_ACCURATE_INCREASE: f64 = 0.01;
const MERGE_REVERT_DECREASE: f64 = 0.05;
const INACCURATE_REVIEW_DECREASE: f64 = 0.03;
const POLICY_VIOLATION_DECREASE: f64 = 0.10;

/// Agent reputation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReputation {
    pub agent_id: String,
    pub score: f64,
    pub cluster_ids: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

/// Reputation history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationHistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub old_score: f64,
    pub new_score: f64,
    pub reason: ReputationChangeReason,
    pub related_resource_id: Option<String>,
}

/// Reasons for reputation changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationChangeReason {
    /// PR was successfully merged
    MergeSuccess,
    /// Review was accurate (approved PR didn't cause issues)
    AccurateReview,
    /// Merged PR was reverted
    MergeReverted,
    /// Review was inaccurate (approved PR caused issues)
    InaccurateReview,
    /// Policy violation detected
    PolicyViolation,
    /// Manual adjustment by admin
    ManualAdjustment,
}

impl ReputationChangeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MergeSuccess => "merge_success",
            Self::AccurateReview => "accurate_review",
            Self::MergeReverted => "merge_reverted",
            Self::InaccurateReview => "inaccurate_review",
            Self::PolicyViolation => "policy_violation",
            Self::ManualAdjustment => "manual_adjustment",
        }
    }
}

/// Response for GET /v1/agents/{agentId}/reputation
#[derive(Debug, Clone, Serialize)]
pub struct ReputationResponse {
    pub agent_id: String,
    pub score: f64,
    pub updated_at: DateTime<Utc>,
}

/// Configuration for the reputation job
#[derive(Debug, Clone)]
pub struct ReputationJobConfig {
    /// Interval between job runs (default: 1 minute)
    pub interval: Duration,
    /// Whether the job is enabled
    pub enabled: bool,
    /// Worker ID for distributed locking
    pub worker_id: String,
}

impl Default for ReputationJobConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60), // 1 minute
            enabled: true,
            worker_id: format!("reputation-worker-{}", Uuid::new_v4()),
        }
    }
}

/// Reputation Service
///
/// Design Reference: DR-13.1
#[derive(Debug, Clone)]
pub struct ReputationService {
    pool: PgPool,
}

impl ReputationService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get an agent's reputation score
    ///
    /// Requirements: 10.4 - Expose reputation scores via API
    pub async fn get_reputation(
        &self,
        agent_id: &str,
    ) -> Result<ReputationResponse, ReputationError> {
        let row = sqlx::query_as::<_, ReputationRow>(
            r#"
            SELECT agent_id, CAST(score AS DOUBLE PRECISION) as score, cluster_ids, updated_at
            FROM reputation
            WHERE agent_id = $1
            "#,
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(ReputationResponse {
                agent_id: r.agent_id,
                score: r.score,
                updated_at: r.updated_at,
            }),
            None => Err(ReputationError::AgentNotFound(agent_id.to_string())),
        }
    }

    /// Update an agent's reputation score
    ///
    /// Requirements: 10.1 - Clamp score to [0.0, 1.0]
    /// Requirements: 10.5 - Store history in audit_log
    pub async fn update_reputation(
        &self,
        agent_id: &str,
        delta: f64,
        reason: ReputationChangeReason,
        related_resource_id: Option<&str>,
    ) -> Result<AgentReputation, ReputationError> {
        let mut tx = self.pool.begin().await?;

        // Get current reputation
        let current = sqlx::query_as::<_, ReputationRow>(
            r#"
            SELECT agent_id, CAST(score AS DOUBLE PRECISION) as score, cluster_ids, updated_at
            FROM reputation
            WHERE agent_id = $1
            FOR UPDATE
            "#,
        )
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (old_score, cluster_ids) = match current {
            Some(r) => {
                let clusters: Vec<String> =
                    serde_json::from_value(r.cluster_ids).unwrap_or_default();
                (r.score, clusters)
            }
            None => return Err(ReputationError::AgentNotFound(agent_id.to_string())),
        };

        // Calculate new score with clamping (Requirement 10.1)
        let new_score: f64 = (old_score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        let now = Utc::now();

        // Update reputation
        sqlx::query(
            r#"
            UPDATE reputation
            SET score = $1, updated_at = $2
            WHERE agent_id = $3
            "#,
        )
        .bind(new_score)
        .bind(now)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;

        // Record in audit log (Requirement 10.5)
        let audit_data = serde_json::json!({
            "old_score": old_score,
            "new_score": new_score,
            "delta": delta,
            "reason": reason.as_str(),
            "related_resource_id": related_resource_id,
        });

        let audit_event = AuditEvent::new(
            agent_id,
            AuditAction::ReputationUpdate,
            ResourceType::Reputation,
            agent_id,
            audit_data,
            "system", // System-generated event
        );

        AuditService::append_in_tx(&mut tx, audit_event)
            .await
            .map_err(|e| ReputationError::Audit(e.to_string()))?;

        tx.commit().await?;

        info!(
            agent_id = agent_id,
            old_score = old_score,
            new_score = new_score,
            reason = reason.as_str(),
            "Reputation updated"
        );

        Ok(AgentReputation {
            agent_id: agent_id.to_string(),
            score: new_score,
            cluster_ids,
            updated_at: now,
        })
    }

    /// Process a merge success event
    ///
    /// Requirements: 10.2 - Increase reputation on merge success
    pub async fn process_merge_success(
        &self,
        author_id: &str,
        pr_id: &str,
    ) -> Result<(), ReputationError> {
        self.update_reputation(
            author_id,
            MERGE_SUCCESS_INCREASE,
            ReputationChangeReason::MergeSuccess,
            Some(pr_id),
        )
        .await?;
        Ok(())
    }

    /// Process a merge revert event
    ///
    /// Requirements: 10.3 - Decrease reputation on merge revert
    pub async fn process_merge_revert(
        &self,
        author_id: &str,
        pr_id: &str,
    ) -> Result<(), ReputationError> {
        self.update_reputation(
            author_id,
            -MERGE_REVERT_DECREASE,
            ReputationChangeReason::MergeReverted,
            Some(pr_id),
        )
        .await?;
        Ok(())
    }

    /// Process an inaccurate review event
    ///
    /// Requirements: 10.3 - Decrease reviewer reputation for inaccurate reviews
    pub async fn process_inaccurate_review(
        &self,
        reviewer_id: &str,
        pr_id: &str,
    ) -> Result<(), ReputationError> {
        self.update_reputation(
            reviewer_id,
            -INACCURATE_REVIEW_DECREASE,
            ReputationChangeReason::InaccurateReview,
            Some(pr_id),
        )
        .await?;
        Ok(())
    }

    /// Process a policy violation
    pub async fn process_policy_violation(
        &self,
        agent_id: &str,
        violation_id: &str,
    ) -> Result<(), ReputationError> {
        self.update_reputation(
            agent_id,
            -POLICY_VIOLATION_DECREASE,
            ReputationChangeReason::PolicyViolation,
            Some(violation_id),
        )
        .await?;
        Ok(())
    }

    /// Process events from the outbox
    ///
    /// This is the main entry point for the background job.
    pub async fn process_outbox_events(&self, worker_id: &str) -> Result<u32, ReputationError> {
        let outbox = OutboxService::new(self.pool.clone());

        // Claim events for processing
        let events = outbox
            .claim_events(OutboxTopic::Reputation, worker_id)
            .await
            .map_err(|e| ReputationError::Database(sqlx::Error::Protocol(e.to_string())))?;

        let mut processed = 0;

        for event in events {
            match self.process_single_event(&event.audit_event_id).await {
                Ok(()) => {
                    if let Err(e) = outbox.mark_processed(event.outbox_id).await {
                        error!(
                            outbox_id = %event.outbox_id,
                            error = %e,
                            "Failed to mark event as processed"
                        );
                    }
                    processed += 1;
                }
                Err(e) => {
                    warn!(
                        outbox_id = %event.outbox_id,
                        error = %e,
                        "Failed to process reputation event"
                    );
                    if let Err(mark_err) = outbox.mark_failed(event.outbox_id, &e.to_string()).await
                    {
                        error!(
                            outbox_id = %event.outbox_id,
                            error = %mark_err,
                            "Failed to mark event as failed"
                        );
                    }
                }
            }
        }

        Ok(processed)
    }

    /// Process a single audit event for reputation updates
    async fn process_single_event(&self, audit_event_id: &Uuid) -> Result<(), ReputationError> {
        // Fetch the audit event
        let row = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature
            FROM audit_log
            WHERE event_id = $1
            "#,
        )
        .bind(audit_event_id)
        .fetch_optional(&self.pool)
        .await?;

        let event = match row {
            Some(r) => r,
            None => {
                return Err(ReputationError::InvalidEventData(format!(
                    "Audit event not found: {audit_event_id}"
                )));
            }
        };

        // Process based on action type
        match event.action.as_str() {
            "pr_merge" => {
                // Extract author_id from event data
                let author_id = event
                    .data
                    .get("author_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.agent_id);

                self.process_merge_success(author_id, &event.resource_id)
                    .await?;

                // Also reward reviewers who approved
                if let Some(reviewers) = event
                    .data
                    .get("approving_reviewers")
                    .and_then(|v| v.as_array())
                {
                    for reviewer in reviewers {
                        if let Some(reviewer_id) = reviewer.as_str() {
                            self.update_reputation(
                                reviewer_id,
                                REVIEW_ACCURATE_INCREASE,
                                ReputationChangeReason::AccurateReview,
                                Some(&event.resource_id),
                            )
                            .await?;
                        }
                    }
                }
            }
            "pr_reverted" => {
                // Extract author_id from event data
                let author_id = event
                    .data
                    .get("author_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.agent_id);

                self.process_merge_revert(author_id, &event.resource_id)
                    .await?;

                // Also penalize reviewers who approved the reverted PR
                if let Some(reviewers) = event
                    .data
                    .get("approving_reviewers")
                    .and_then(|v| v.as_array())
                {
                    for reviewer in reviewers {
                        if let Some(reviewer_id) = reviewer.as_str() {
                            self.process_inaccurate_review(reviewer_id, &event.resource_id)
                                .await?;
                        }
                    }
                }
            }
            "policy_violation" => {
                let violation_id = event
                    .data
                    .get("violation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.resource_id);

                self.process_policy_violation(&event.agent_id, violation_id)
                    .await?;
            }
            _ => {
                // Ignore other event types
            }
        }

        Ok(())
    }
}

/// Background job runner for reputation calculation
///
/// Design Reference: DR-13.1 (Reputation Service)
pub struct ReputationJob {
    pool: PgPool,
    config: ReputationJobConfig,
}

impl ReputationJob {
    pub fn new(pool: PgPool, config: ReputationJobConfig) -> Self {
        Self { pool, config }
    }

    /// Start the reputation calculation job
    ///
    /// Returns a shutdown sender that can be used to stop the job.
    pub fn start(self) -> watch::Sender<bool> {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        if !self.config.enabled {
            info!("Reputation calculation job is disabled");
            return shutdown_tx;
        }

        let pool = self.pool.clone();
        let interval = self.config.interval;
        let worker_id = self.config.worker_id.clone();

        tokio::spawn(async move {
            info!(
                worker_id = %worker_id,
                interval = ?interval,
                "Starting reputation calculation job"
            );

            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let service = ReputationService::new(pool.clone());
                        match service.process_outbox_events(&worker_id).await {
                            Ok(count) => {
                                if count > 0 {
                                    info!(processed = count, "Processed reputation events");
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Reputation job failed");
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Reputation calculation job shutting down");
                            break;
                        }
                    }
                }
            }
        });

        shutdown_tx
    }
}

/// Run a single reputation processing cycle (for manual triggering or testing)
pub async fn run_reputation_processing(pool: &PgPool) -> Result<u32, ReputationError> {
    let service = ReputationService::new(pool.clone());
    let worker_id = format!("manual-{}", Uuid::new_v4());
    service.process_outbox_events(&worker_id).await
}

/// Internal row type for reputation queries
#[derive(Debug, sqlx::FromRow)]
struct ReputationRow {
    agent_id: String,
    score: f64,
    cluster_ids: serde_json::Value,
    updated_at: DateTime<Utc>,
}

/// Internal row type for audit event queries
#[derive(Debug, sqlx::FromRow)]
struct AuditEventRow {
    #[allow(dead_code)]
    event_id: Uuid,
    agent_id: String,
    action: String,
    #[allow(dead_code)]
    resource_type: String,
    resource_id: String,
    data: serde_json::Value,
    #[allow(dead_code)]
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_bounds() {
        // Test clamping logic
        let test_cases: Vec<(f64, f64, f64)> = vec![
            (0.5, 0.1, 0.6),   // Normal increase
            (0.5, -0.1, 0.4),  // Normal decrease
            (0.95, 0.1, 1.0),  // Clamped at max
            (0.05, -0.1, 0.0), // Clamped at min
            (1.0, 0.1, 1.0),   // Already at max
            (0.0, -0.1, 0.0),  // Already at min
        ];

        for (current, delta, expected) in test_cases {
            let result: f64 = (current + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
            assert!(
                (result - expected).abs() < f64::EPSILON,
                "Expected {expected}, got {result} for current={current}, delta={delta}"
            );
        }
    }

    #[test]
    fn test_reputation_change_reason_as_str() {
        assert_eq!(
            ReputationChangeReason::MergeSuccess.as_str(),
            "merge_success"
        );
        assert_eq!(
            ReputationChangeReason::AccurateReview.as_str(),
            "accurate_review"
        );
        assert_eq!(
            ReputationChangeReason::MergeReverted.as_str(),
            "merge_reverted"
        );
        assert_eq!(
            ReputationChangeReason::InaccurateReview.as_str(),
            "inaccurate_review"
        );
        assert_eq!(
            ReputationChangeReason::PolicyViolation.as_str(),
            "policy_violation"
        );
        assert_eq!(
            ReputationChangeReason::ManualAdjustment.as_str(),
            "manual_adjustment"
        );
    }

    #[test]
    fn test_reputation_job_config_default() {
        let config = ReputationJobConfig::default();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert!(config.enabled);
        assert!(config.worker_id.starts_with("reputation-worker-"));
    }
}

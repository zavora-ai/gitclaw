//! Star Service
//!
//! Manages repository endorsements (stars).
//! Design Reference: DR-11.1 (Star Service)
//!
//! Requirements: 14.1-14.7, 15.1-15.5, 16.1-16.4

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;

use crate::models::{GetStarsResponse, StarRepoBody, StarResponse, StarredByAgent};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::idempotency::{IdempotencyError, IdempotencyResult, IdempotencyService};
use crate::services::rate_limiter::{RateLimitError, RateLimiterService};
use crate::services::signature::{
    SignatureEnvelope, SignatureError, SignatureValidator, get_agent_public_key_if_not_suspended,
};

/// Maximum length for star reason
const MAX_REASON_LENGTH: usize = 500;

/// Errors that can occur during star operations
#[derive(Debug, Error)]
pub enum StarError {
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Duplicate star: agent {0} has already starred repository {1}")]
    DuplicateStar(String, String),

    #[error("No existing star: agent {0} has not starred repository {1}")]
    NoExistingStar(String, String),

    #[error("Invalid reason: {0}")]
    InvalidReason(String),

    /// Agent is suspended and cannot perform mutating operations
    /// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
    #[error("Agent is suspended: {0}")]
    Suspended(String),

    #[error("Signature validation failed: {0}")]
    SignatureError(SignatureError),

    #[error("Idempotency error: {0}")]
    IdempotencyError(#[from] IdempotencyError),

    #[error("Rate limit exceeded: {0}")]
    RateLimited(#[from] RateLimitError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
}

impl From<SignatureError> for StarError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::Suspended(msg) => StarError::Suspended(msg),
            SignatureError::MissingField(msg) if msg.starts_with("Agent not found:") => {
                // Extract agent_id from the message
                let agent_id = msg.strip_prefix("Agent not found: ").unwrap_or(&msg);
                StarError::AgentNotFound(agent_id.to_string())
            }
            other => StarError::SignatureError(other),
        }
    }
}

/// Service for managing repository stars
///
/// Design Reference: DR-11.1 (Star Service)
#[derive(Debug, Clone)]
pub struct StarService {
    pool: PgPool,
    signature_validator: SignatureValidator,
    idempotency_service: IdempotencyService,
}

impl StarService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            signature_validator: SignatureValidator::default(),
            idempotency_service: IdempotencyService::new(pool.clone()),
            pool,
        }
    }

    /// Star a repository
    ///
    /// Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7
    /// Design: DR-11.1 (Star Service)
    #[allow(clippy::too_many_arguments)]
    pub async fn star(
        &self,
        repo_id: &str,
        agent_id: &str,
        nonce: &str,
        timestamp: DateTime<Utc>,
        signature: &str,
        body: StarRepoBody,
        rate_limiter: &RateLimiterService,
    ) -> Result<StarResponse, StarError> {
        const ACTION: &str = "star";

        // Check idempotency first (Requirement 14.7)
        match self
            .idempotency_service
            .check(agent_id, nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: StarResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| StarError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(StarError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Check rate limit (DR-10.1)
        rate_limiter.check_and_record(agent_id, ACTION).await?;

        // Validate reason length (Requirement 14.1)
        if let Some(ref reason) = body.reason {
            if reason.len() > MAX_REASON_LENGTH {
                return Err(StarError::InvalidReason(format!(
                    "Reason exceeds maximum length of {} characters",
                    MAX_REASON_LENGTH
                )));
            }
        }

        // Check repository exists (Requirement 14.6)
        let repo_exists: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if repo_exists.is_none() {
            return Err(StarError::RepoNotFound(repo_id.to_string()));
        }

        // Get agent's public key for signature validation (Requirement 14.3)
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let envelope_body = serde_json::json!({
            "repoId": repo_id,
            "reason": body.reason,
            "reasonPublic": body.reason_public,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.to_string(),
            action: ACTION.to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body: envelope_body,
        };

        // Validate signature (Requirement 14.3)
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check for existing star (Requirement 14.2)
        let existing_star: Option<String> = sqlx::query_scalar(
            "SELECT agent_id FROM repo_stars WHERE repo_id = $1 AND agent_id = $2",
        )
        .bind(repo_id)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        if existing_star.is_some() {
            return Err(StarError::DuplicateStar(
                agent_id.to_string(),
                repo_id.to_string(),
            ));
        }

        let now = Utc::now();

        // Create star record (Requirement 14.1)
        sqlx::query(
            r#"
            INSERT INTO repo_stars (repo_id, agent_id, reason, reason_public, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(repo_id)
        .bind(agent_id)
        .bind(&body.reason)
        .bind(body.reason_public)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Atomically increment star count (Requirement 14.5)
        sqlx::query(
            r#"
            UPDATE repo_star_counts
            SET stars = stars + 1, updated_at = $2
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Get updated star count
        let star_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        // Append star event to audit_log (Requirement 14.4)
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "reason": body.reason,
            "reason_public": body.reason_public,
            "star_count": star_count,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "repo_star".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Also insert into star_events table for analytics
        sqlx::query(
            r#"
            INSERT INTO star_events (repo_id, agent_id, action, timestamp, nonce, signature)
            VALUES ($1, $2, 'star', $3, $4, $5)
            "#,
        )
        .bind(repo_id)
        .bind(agent_id)
        .bind(now)
        .bind(nonce)
        .bind(signature)
        .execute(&mut *tx)
        .await?;

        let response = StarResponse {
            repo_id: repo_id.to_string(),
            agent_id: agent_id.to_string(),
            action: "starred".to_string(),
            star_count,
        };

        // Store idempotency result (Requirement 14.7, DR-3.2)
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 200, &response, 24)
            .await?;

        tx.commit().await?;

        Ok(response)
    }

    /// Unstar a repository
    ///
    /// Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
    /// Design: DR-11.1 (Star Service)
    pub async fn unstar(
        &self,
        repo_id: &str,
        agent_id: &str,
        nonce: &str,
        timestamp: DateTime<Utc>,
        signature: &str,
        rate_limiter: &RateLimiterService,
    ) -> Result<StarResponse, StarError> {
        const ACTION: &str = "unstar";

        // Check idempotency first (Requirement 15.5)
        match self
            .idempotency_service
            .check(agent_id, nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: StarResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| StarError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(StarError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Check rate limit
        rate_limiter.check_and_record(agent_id, ACTION).await?;

        // Check repository exists
        let repo_exists: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if repo_exists.is_none() {
            return Err(StarError::RepoNotFound(repo_id.to_string()));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let envelope_body = serde_json::json!({
            "repoId": repo_id,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.to_string(),
            action: ACTION.to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body: envelope_body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check for existing star (Requirement 15.2)
        let existing_star: Option<String> = sqlx::query_scalar(
            "SELECT agent_id FROM repo_stars WHERE repo_id = $1 AND agent_id = $2",
        )
        .bind(repo_id)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        if existing_star.is_none() {
            return Err(StarError::NoExistingStar(
                agent_id.to_string(),
                repo_id.to_string(),
            ));
        }

        let now = Utc::now();

        // Delete star record (Requirement 15.1)
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1 AND agent_id = $2")
            .bind(repo_id)
            .bind(agent_id)
            .execute(&mut *tx)
            .await?;

        // Atomically decrement star count with floor at 0 (Requirement 15.4)
        sqlx::query(
            r#"
            UPDATE repo_star_counts
            SET stars = GREATEST(stars - 1, 0), updated_at = $2
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Get updated star count
        let star_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        // Append unstar event to audit_log (Requirement 15.3)
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "star_count": star_count,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "repo_star".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Also insert into star_events table for analytics
        sqlx::query(
            r#"
            INSERT INTO star_events (repo_id, agent_id, action, timestamp, nonce, signature)
            VALUES ($1, $2, 'unstar', $3, $4, $5)
            "#,
        )
        .bind(repo_id)
        .bind(agent_id)
        .bind(now)
        .bind(nonce)
        .bind(signature)
        .execute(&mut *tx)
        .await?;

        let response = StarResponse {
            repo_id: repo_id.to_string(),
            agent_id: agent_id.to_string(),
            action: "unstarred".to_string(),
            star_count,
        };

        // Store idempotency result (Requirement 15.5)
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 200, &response, 24)
            .await?;

        tx.commit().await?;

        Ok(response)
    }

    /// Get stars for a repository
    ///
    /// Requirements: 16.1, 16.2, 16.3, 16.4
    /// Design: DR-11.1 (Star Service)
    pub async fn get_stars(&self, repo_id: &str) -> Result<GetStarsResponse, StarError> {
        // Check repository exists
        let repo_exists: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if repo_exists.is_none() {
            return Err(StarError::RepoNotFound(repo_id.to_string()));
        }

        // Get star count from repo_star_counts (Requirement 16.1)
        let star_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&self.pool)
                .await?;

        // Get starred by list with reputation scores (Requirement 16.2)
        // Sort by timestamp descending (Requirement 16.3)
        // Only include public reasons (Requirement 16.4)
        let rows = sqlx::query(
            r#"
            SELECT 
                rs.agent_id,
                a.agent_name,
                CAST(COALESCE(r.score, 0.5) AS DOUBLE PRECISION) as reputation_score,
                CASE WHEN rs.reason_public THEN rs.reason ELSE NULL END as reason,
                rs.created_at as starred_at
            FROM repo_stars rs
            JOIN agents a ON rs.agent_id = a.agent_id
            LEFT JOIN reputation r ON rs.agent_id = r.agent_id
            WHERE rs.repo_id = $1
            ORDER BY rs.created_at DESC
            "#,
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;

        let starred_by: Vec<StarredByAgent> = rows
            .into_iter()
            .map(|row| StarredByAgent {
                agent_id: row.get("agent_id"),
                agent_name: row.get("agent_name"),
                reputation_score: row.get("reputation_score"),
                reason: row.get("reason"),
                starred_at: row.get("starred_at"),
            })
            .collect();

        Ok(GetStarsResponse {
            repo_id: repo_id.to_string(),
            star_count,
            starred_by,
        })
    }

    /// Get agent's public key for signature validation
    /// Also checks if the agent is suspended (Requirement 2.6)
    async fn get_agent_public_key(&self, agent_id: &str) -> Result<String, StarError> {
        get_agent_public_key_if_not_suspended(&self.pool, agent_id)
            .await
            .map_err(StarError::from)
    }
}

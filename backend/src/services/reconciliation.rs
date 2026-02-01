//! Reconciliation Jobs Service
//!
//! Periodic consistency checks to ensure domain tables match the authoritative
//! audit log and maintain data integrity.
//!
//! Design Reference: DR-14.1 (Audit Service - Reconciliation)
//! Requirements: 11.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::services::audit::{AuditAction, AuditEvent, AuditService, ResourceType};

/// Reconciliation service errors
#[derive(Debug, Error)]
pub enum ReconciliationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] crate::services::audit::AuditError),
}

/// Types of drift that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    /// Star count mismatch between repo_star_counts and actual COUNT(*)
    StarCountMismatch {
        repo_id: String,
        expected: i64,
        actual: i64,
    },
    /// Ref points to unknown commit
    OrphanedRef {
        repo_id: String,
        ref_name: String,
        oid: String,
    },
    /// Merged PR missing merged_at timestamp
    MergedPrMissingTimestamp { pr_id: String },
    /// PR has merged_at but status is not merged
    PrStatusInconsistent {
        pr_id: String,
        status: String,
        has_merged_at: bool,
    },
}

/// Result of a reconciliation check
#[derive(Debug, Clone, Serialize)]
pub struct ReconciliationResult {
    pub check_type: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub drifts_found: Vec<DriftType>,
    pub items_checked: i64,
}

/// Configuration for reconciliation jobs
#[derive(Debug, Clone)]
pub struct ReconciliationConfig {
    /// Interval between star count checks (in seconds)
    pub star_count_interval_secs: u64,
    /// Interval between ref consistency checks (in seconds)
    pub ref_consistency_interval_secs: u64,
    /// Interval between PR state checks (in seconds)
    pub pr_state_interval_secs: u64,
    /// Whether to auto-fix detected drifts
    pub auto_fix: bool,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            star_count_interval_secs: 300,      // 5 minutes
            ref_consistency_interval_secs: 600, // 10 minutes
            pr_state_interval_secs: 300,        // 5 minutes
            auto_fix: false,                    // Don't auto-fix by default
        }
    }
}

/// Service for running reconciliation checks
#[derive(Debug, Clone)]
pub struct ReconciliationService {
    pool: PgPool,
    audit_service: AuditService,
}

impl ReconciliationService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: AuditService::new(pool.clone()),
            pool,
        }
    }

    /// Check star count consistency
    ///
    /// Verifies that repo_star_counts.stars == COUNT(*) FROM repo_stars
    ///
    /// Requirements: 11.5
    pub async fn check_star_counts(&self) -> Result<ReconciliationResult, ReconciliationError> {
        let started_at = Utc::now();
        let mut drifts = Vec::new();

        // Find mismatches between repo_star_counts and actual star counts
        let rows = sqlx::query_as::<_, StarCountMismatchRow>(
            r#"
            SELECT 
                rsc.repo_id,
                rsc.stars as expected_count,
                COALESCE(actual.count, 0) as actual_count
            FROM repo_star_counts rsc
            LEFT JOIN (
                SELECT repo_id, COUNT(*) as count
                FROM repo_stars
                GROUP BY repo_id
            ) actual ON rsc.repo_id = actual.repo_id
            WHERE rsc.stars != COALESCE(actual.count, 0)
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let items_checked = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM repo_star_counts")
            .fetch_one(&self.pool)
            .await?;

        for row in rows {
            let drift = DriftType::StarCountMismatch {
                repo_id: row.repo_id.clone(),
                expected: row.actual_count,
                actual: row.expected_count,
            };

            // Log the drift
            warn!(
                "Star count drift detected for repo {}: expected {}, actual {}",
                row.repo_id, row.actual_count, row.expected_count
            );

            // Emit audit event for drift detection
            self.emit_drift_event(&drift).await?;

            drifts.push(drift);
        }

        let completed_at = Utc::now();

        Ok(ReconciliationResult {
            check_type: "star_count".to_string(),
            started_at,
            completed_at,
            drifts_found: drifts,
            items_checked,
        })
    }

    /// Fix star count drifts by updating repo_star_counts to match actual counts
    pub async fn fix_star_counts(&self) -> Result<i64, ReconciliationError> {
        let result = sqlx::query(
            r#"
            UPDATE repo_star_counts rsc
            SET stars = COALESCE(actual.count, 0),
                updated_at = NOW()
            FROM (
                SELECT repo_id, COUNT(*) as count
                FROM repo_stars
                GROUP BY repo_id
            ) actual
            WHERE rsc.repo_id = actual.repo_id
            AND rsc.stars != actual.count
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Check ref consistency
    ///
    /// Verifies that all refs point to known commits in repo_objects
    ///
    /// Requirements: 11.5
    pub async fn check_ref_consistency(&self) -> Result<ReconciliationResult, ReconciliationError> {
        let started_at = Utc::now();
        let mut drifts = Vec::new();

        // Find refs that point to non-existent objects
        let rows = sqlx::query_as::<_, OrphanedRefRow>(
            r#"
            SELECT rr.repo_id, rr.ref_name, rr.oid
            FROM repo_refs rr
            LEFT JOIN repo_objects ro ON rr.repo_id = ro.repo_id AND rr.oid = ro.oid
            WHERE ro.oid IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let items_checked = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM repo_refs")
            .fetch_one(&self.pool)
            .await?;

        for row in rows {
            let drift = DriftType::OrphanedRef {
                repo_id: row.repo_id.clone(),
                ref_name: row.ref_name.clone(),
                oid: row.oid.clone(),
            };

            warn!(
                "Orphaned ref detected: repo={}, ref={}, oid={}",
                row.repo_id, row.ref_name, row.oid
            );

            self.emit_drift_event(&drift).await?;

            drifts.push(drift);
        }

        let completed_at = Utc::now();

        Ok(ReconciliationResult {
            check_type: "ref_consistency".to_string(),
            started_at,
            completed_at,
            drifts_found: drifts,
            items_checked,
        })
    }

    /// Check PR state invariants
    ///
    /// Verifies:
    /// - Merged PRs have merged_at timestamp
    /// - PRs with merged_at have status = 'merged'
    ///
    /// Requirements: 11.5
    pub async fn check_pr_state_invariants(
        &self,
    ) -> Result<ReconciliationResult, ReconciliationError> {
        let started_at = Utc::now();
        let mut drifts = Vec::new();

        // Find merged PRs without merged_at
        let missing_timestamp_rows = sqlx::query_as::<_, PrIdRow>(
            r#"
            SELECT pr_id
            FROM pull_requests
            WHERE status = 'merged' AND merged_at IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        for row in missing_timestamp_rows {
            let drift = DriftType::MergedPrMissingTimestamp {
                pr_id: row.pr_id.clone(),
            };

            warn!("Merged PR {} missing merged_at timestamp", row.pr_id);

            self.emit_drift_event(&drift).await?;

            drifts.push(drift);
        }

        // Find PRs with merged_at but wrong status
        let inconsistent_rows = sqlx::query_as::<_, PrStatusRow>(
            r#"
            SELECT pr_id, status::text as status, merged_at IS NOT NULL as has_merged_at
            FROM pull_requests
            WHERE (status = 'merged' AND merged_at IS NULL)
               OR (status != 'merged' AND merged_at IS NOT NULL)
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        for row in inconsistent_rows {
            // Skip if already added as missing timestamp
            if row.status == "merged" && !row.has_merged_at {
                continue;
            }

            let drift = DriftType::PrStatusInconsistent {
                pr_id: row.pr_id.clone(),
                status: row.status.clone(),
                has_merged_at: row.has_merged_at,
            };

            warn!(
                "PR {} has inconsistent state: status={}, has_merged_at={}",
                row.pr_id, row.status, row.has_merged_at
            );

            self.emit_drift_event(&drift).await?;

            drifts.push(drift);
        }

        let items_checked = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pull_requests")
            .fetch_one(&self.pool)
            .await?;

        let completed_at = Utc::now();

        Ok(ReconciliationResult {
            check_type: "pr_state_invariants".to_string(),
            started_at,
            completed_at,
            drifts_found: drifts,
            items_checked,
        })
    }

    /// Run all reconciliation checks
    pub async fn run_all_checks(&self) -> Result<Vec<ReconciliationResult>, ReconciliationError> {
        let mut results = Vec::new();

        results.push(self.check_star_counts().await?);
        results.push(self.check_ref_consistency().await?);
        results.push(self.check_pr_state_invariants().await?);

        Ok(results)
    }

    /// Emit an audit event for drift detection
    async fn emit_drift_event(&self, drift: &DriftType) -> Result<(), ReconciliationError> {
        let (resource_type, resource_id) = match drift {
            DriftType::StarCountMismatch { repo_id, .. } => {
                (ResourceType::Repository, repo_id.clone())
            }
            DriftType::OrphanedRef { repo_id, .. } => (ResourceType::Repository, repo_id.clone()),
            DriftType::MergedPrMissingTimestamp { pr_id } => {
                (ResourceType::PullRequest, pr_id.clone())
            }
            DriftType::PrStatusInconsistent { pr_id, .. } => {
                (ResourceType::PullRequest, pr_id.clone())
            }
        };

        let event = AuditEvent::new(
            "system",
            AuditAction::ReputationUpdate, // Using this as a generic system action
            resource_type,
            resource_id,
            serde_json::json!({
                "type": "drift_detected",
                "drift": drift,
            }),
            "system-reconciliation",
        );

        self.audit_service.append(event).await?;

        Ok(())
    }
}

/// Background job for running periodic reconciliation checks
pub struct ReconciliationJob {
    pool: PgPool,
    config: ReconciliationConfig,
}

impl ReconciliationJob {
    pub fn new(pool: PgPool, config: ReconciliationConfig) -> Self {
        Self { pool, config }
    }

    /// Start the reconciliation job
    ///
    /// Returns a shutdown sender that can be used to stop the job
    pub fn start(self) -> watch::Sender<bool> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let pool = self.pool.clone();
        let config = self.config.clone();

        // Spawn star count check task
        {
            let pool = pool.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let interval = Duration::from_secs(config.star_count_interval_secs);

            tokio::spawn(async move {
                let service = ReconciliationService::new(pool);
                let mut interval_timer = tokio::time::interval(interval);

                loop {
                    tokio::select! {
                        _ = interval_timer.tick() => {
                            match service.check_star_counts().await {
                                Ok(result) => {
                                    if result.drifts_found.is_empty() {
                                        info!("Star count check completed: {} items checked, no drifts", result.items_checked);
                                    } else {
                                        warn!("Star count check completed: {} drifts found", result.drifts_found.len());
                                    }
                                }
                                Err(e) => {
                                    error!("Star count check failed: {}", e);
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!("Star count reconciliation job shutting down");
                                break;
                            }
                        }
                    }
                }
            });
        }

        // Spawn ref consistency check task
        {
            let pool = pool.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let interval = Duration::from_secs(config.ref_consistency_interval_secs);

            tokio::spawn(async move {
                let service = ReconciliationService::new(pool);
                let mut interval_timer = tokio::time::interval(interval);

                loop {
                    tokio::select! {
                        _ = interval_timer.tick() => {
                            match service.check_ref_consistency().await {
                                Ok(result) => {
                                    if result.drifts_found.is_empty() {
                                        info!("Ref consistency check completed: {} items checked, no drifts", result.items_checked);
                                    } else {
                                        warn!("Ref consistency check completed: {} drifts found", result.drifts_found.len());
                                    }
                                }
                                Err(e) => {
                                    error!("Ref consistency check failed: {}", e);
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!("Ref consistency reconciliation job shutting down");
                                break;
                            }
                        }
                    }
                }
            });
        }

        // Spawn PR state check task
        {
            let pool = pool.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            let interval = Duration::from_secs(config.pr_state_interval_secs);

            tokio::spawn(async move {
                let service = ReconciliationService::new(pool);
                let mut interval_timer = tokio::time::interval(interval);

                loop {
                    tokio::select! {
                        _ = interval_timer.tick() => {
                            match service.check_pr_state_invariants().await {
                                Ok(result) => {
                                    if result.drifts_found.is_empty() {
                                        info!("PR state check completed: {} items checked, no drifts", result.items_checked);
                                    } else {
                                        warn!("PR state check completed: {} drifts found", result.drifts_found.len());
                                    }
                                }
                                Err(e) => {
                                    error!("PR state check failed: {}", e);
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!("PR state reconciliation job shutting down");
                                break;
                            }
                        }
                    }
                }
            });
        }

        shutdown_tx
    }
}

// Database row types
#[derive(Debug, sqlx::FromRow)]
struct StarCountMismatchRow {
    repo_id: String,
    expected_count: i64,
    actual_count: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct OrphanedRefRow {
    repo_id: String,
    ref_name: String,
    oid: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PrIdRow {
    pr_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PrStatusRow {
    pr_id: String,
    status: String,
    has_merged_at: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_config_default() {
        let config = ReconciliationConfig::default();
        assert_eq!(config.star_count_interval_secs, 300);
        assert_eq!(config.ref_consistency_interval_secs, 600);
        assert_eq!(config.pr_state_interval_secs, 300);
        assert!(!config.auto_fix);
    }

    #[test]
    fn test_drift_type_serialization() {
        let drift = DriftType::StarCountMismatch {
            repo_id: "repo-123".to_string(),
            expected: 10,
            actual: 8,
        };

        let json = serde_json::to_string(&drift).unwrap();
        assert!(json.contains("star_count_mismatch"));
        assert!(json.contains("repo-123"));
    }
}

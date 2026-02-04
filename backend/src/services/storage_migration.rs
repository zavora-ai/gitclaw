//! Storage Migration Service
//!
//! Migrates Git objects from PostgreSQL to S3-compatible object storage.
//! Design Reference: DR-S3-3.1
//!
//! Requirements: 7.1, 7.2, 7.5, 7.6, 7.7

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::object_storage::{GitObjectType, ObjectStorageBackend, S3ObjectStorage, StorageError};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the migration service
///
/// Design Reference: DR-S3-3.1
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Number of objects to process in each batch
    pub batch_size: usize,
    /// Maximum concurrent uploads
    pub max_concurrent_uploads: usize,
    /// Whether to verify SHA-1 after migration
    pub verify_after_migration: bool,
    /// Delay between batches in milliseconds (to avoid overwhelming S3)
    pub batch_delay_ms: u64,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_concurrent_uploads: 10,
            verify_after_migration: true,
            batch_delay_ms: 100,
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Migration-specific errors
///
/// Design Reference: DR-S3-3.1
#[derive(Debug, Error)]
pub enum MigrationError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Object verification failed
    #[error("Object verification failed for {oid}: expected hash {expected}, got {actual}")]
    VerificationFailed {
        oid: String,
        expected: String,
        actual: String,
    },

    /// Repository not found
    #[error("Repository not found: {0}")]
    RepositoryNotFound(String),

    /// Migration already in progress
    #[error("Migration already in progress for repository: {0}")]
    MigrationInProgress(String),

    /// Invalid migration state
    #[error("Invalid migration state: {0}")]
    InvalidState(String),
}

// ============================================================================
// Data Types
// ============================================================================

/// Migration status for a repository
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Migration has not started
    Pending,
    /// Migration is currently running
    InProgress,
    /// Migration completed successfully
    Completed,
    /// Migration failed
    Failed,
}

impl MigrationStatus {
    /// Convert from database string representation
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            _ => Self::Pending,
        }
    }

    /// Convert to database string representation
    pub fn to_db_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Detailed migration status for a repository
#[derive(Debug, Clone)]
pub struct RepoMigrationStatus {
    /// Repository ID
    pub repo_id: String,
    /// Current migration status
    pub status: MigrationStatus,
    /// Total number of objects to migrate
    pub objects_total: i32,
    /// Number of objects migrated so far
    pub objects_migrated: i32,
    /// When migration started
    pub started_at: Option<DateTime<Utc>>,
    /// When migration completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Last error message if failed
    pub last_error: Option<String>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl RepoMigrationStatus {
    /// Calculate migration progress as a percentage
    #[must_use]
    pub fn progress_percent(&self) -> f64 {
        if self.objects_total == 0 {
            return 100.0;
        }
        (self.objects_migrated as f64 / self.objects_total as f64) * 100.0
    }

    /// Estimate remaining time based on current progress
    #[must_use]
    pub fn estimated_remaining_secs(&self) -> Option<u64> {
        let started = self.started_at?;
        if self.objects_migrated == 0 {
            return None;
        }

        let elapsed = Utc::now().signed_duration_since(started);
        let elapsed_secs = elapsed.num_seconds() as f64;
        let rate = self.objects_migrated as f64 / elapsed_secs;

        if rate <= 0.0 {
            return None;
        }

        let remaining = self.objects_total - self.objects_migrated;
        Some((remaining as f64 / rate) as u64)
    }
}

/// Result of migrating a single repository
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Repository ID
    pub repo_id: String,
    /// Number of objects migrated
    pub objects_migrated: usize,
    /// Number of objects that failed to migrate
    pub objects_failed: usize,
    /// Number of objects verified
    pub objects_verified: usize,
    /// Duration of migration
    pub duration: Duration,
}

/// Progress report for migration operations
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    /// Total repositories to migrate
    pub total_repos: usize,
    /// Repositories completed
    pub repos_completed: usize,
    /// Repositories failed
    pub repos_failed: usize,
    /// Total objects migrated across all repos
    pub total_objects_migrated: usize,
    /// Estimated time remaining in seconds
    pub estimated_remaining_secs: Option<u64>,
}

/// Result of verifying a migration
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Repository ID
    pub repo_id: String,
    /// Number of objects verified
    pub objects_verified: usize,
    /// Number of objects that failed verification
    pub objects_failed: usize,
    /// List of failed object OIDs
    pub failed_oids: Vec<String>,
}

/// Detailed progress report for a migration
///
/// Requirements: 7.7
#[derive(Debug, Clone)]
pub struct DetailedProgressReport {
    /// Repository ID
    pub repo_id: String,
    /// Current migration status
    pub status: MigrationStatus,
    /// Total number of objects to migrate
    pub objects_total: i32,
    /// Number of objects migrated so far
    pub objects_migrated: i32,
    /// Number of objects verified
    pub objects_verified: i32,
    /// Progress percentage (0-100)
    pub progress_percent: f64,
    /// Migration rate (objects per second)
    pub rate_per_second: Option<f64>,
    /// Estimated time remaining in seconds
    pub estimated_remaining_secs: Option<u64>,
    /// Elapsed time in seconds
    pub elapsed_secs: Option<u64>,
    /// When migration started
    pub started_at: Option<DateTime<Utc>>,
    /// When migration completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Last error message if failed
    pub last_error: Option<String>,
}

// ============================================================================
// Storage Migration Service
// ============================================================================

/// Service for migrating Git objects from PostgreSQL to S3
///
/// Design Reference: DR-S3-3.1
/// Requirements: 7.1, 7.2, 7.5, 7.6, 7.7
pub struct StorageMigrationService {
    pool: PgPool,
    s3_storage: Arc<S3ObjectStorage>,
    config: MigrationConfig,
}

impl StorageMigrationService {
    /// Create a new migration service
    pub fn new(
        pool: PgPool,
        s3_storage: Arc<S3ObjectStorage>,
        config: MigrationConfig,
    ) -> Self {
        Self {
            pool,
            s3_storage,
            config,
        }
    }

    /// Get migration status for a repository
    ///
    /// Requirements: 7.6
    pub async fn get_status(&self, repo_id: &str) -> Result<RepoMigrationStatus, MigrationError> {
        // Check if repository exists
        let repo_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM repositories WHERE repo_id = $1) as "exists!""#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await?;

        if !repo_exists {
            return Err(MigrationError::RepositoryNotFound(repo_id.to_string()));
        }

        // Get or create migration status
        let status = sqlx::query!(
            r#"
            SELECT 
                repo_id,
                status as "status!: String",
                objects_total,
                objects_migrated,
                started_at,
                completed_at,
                last_error,
                updated_at
            FROM repo_migration_status
            WHERE repo_id = $1
            "#,
            repo_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match status {
            Some(row) => Ok(RepoMigrationStatus {
                repo_id: row.repo_id,
                status: MigrationStatus::from_db_str(&row.status),
                objects_total: row.objects_total,
                objects_migrated: row.objects_migrated,
                started_at: row.started_at,
                completed_at: row.completed_at,
                last_error: row.last_error,
                updated_at: row.updated_at,
            }),
            None => {
                // Count objects for this repository
                let objects_total = sqlx::query_scalar!(
                    r#"SELECT COUNT(*) as "count!" FROM repo_objects WHERE repo_id = $1"#,
                    repo_id
                )
                .fetch_one(&self.pool)
                .await? as i32;

                Ok(RepoMigrationStatus {
                    repo_id: repo_id.to_string(),
                    status: MigrationStatus::Pending,
                    objects_total,
                    objects_migrated: 0,
                    started_at: None,
                    completed_at: None,
                    last_error: None,
                    updated_at: Utc::now(),
                })
            }
        }
    }

    /// Get detailed progress report for a repository migration
    ///
    /// Requirements: 7.7
    pub async fn get_detailed_progress(
        &self,
        repo_id: &str,
    ) -> Result<DetailedProgressReport, MigrationError> {
        let status = self.get_status(repo_id).await?;

        // Count verified objects
        let objects_verified = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!" 
            FROM object_migration_log 
            WHERE repo_id = $1 AND verified = true
            "#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await? as i32;

        // Calculate progress percentage
        let progress_percent = status.progress_percent();

        // Calculate rate and estimated remaining time
        let (rate_per_second, elapsed_secs, estimated_remaining_secs) = 
            if let Some(started) = status.started_at {
                let elapsed = Utc::now().signed_duration_since(started);
                let elapsed_secs = elapsed.num_seconds().max(1) as u64;
                
                if status.objects_migrated > 0 {
                    let rate = status.objects_migrated as f64 / elapsed_secs as f64;
                    let remaining = status.objects_total - status.objects_migrated;
                    let estimated = if rate > 0.0 {
                        Some((remaining as f64 / rate) as u64)
                    } else {
                        None
                    };
                    (Some(rate), Some(elapsed_secs), estimated)
                } else {
                    (Some(0.0), Some(elapsed_secs), None)
                }
            } else {
                (None, None, None)
            };

        Ok(DetailedProgressReport {
            repo_id: status.repo_id,
            status: status.status,
            objects_total: status.objects_total,
            objects_migrated: status.objects_migrated,
            objects_verified,
            progress_percent,
            rate_per_second,
            estimated_remaining_secs,
            elapsed_secs,
            started_at: status.started_at,
            completed_at: status.completed_at,
            last_error: status.last_error,
        })
    }

    /// Get overall migration progress across all repositories
    ///
    /// Requirements: 7.7
    pub async fn get_overall_progress(&self) -> Result<MigrationProgress, MigrationError> {
        // Count repositories by status
        let stats = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE status = 'completed') as "completed!",
                COUNT(*) FILTER (WHERE status = 'failed') as "failed!",
                COUNT(*) FILTER (WHERE status IN ('pending', 'in_progress')) as "remaining!",
                COALESCE(SUM(objects_migrated), 0) as "total_migrated!"
            FROM repo_migration_status
            "#
        )
        .fetch_one(&self.pool)
        .await?;

        // Count total repositories that need migration
        let total_repos = sqlx::query_scalar!(
            r#"
            SELECT COUNT(DISTINCT repo_id) as "count!"
            FROM repo_objects
            "#
        )
        .fetch_one(&self.pool)
        .await? as usize;

        let repos_completed = stats.completed as usize;
        let repos_failed = stats.failed as usize;
        let total_objects_migrated = stats.total_migrated as usize;

        // Estimate remaining time based on average migration rate
        let estimated_remaining_secs = if repos_completed > 0 {
            // Get average migration time per repository
            let avg_duration = sqlx::query_scalar!(
                r#"
                SELECT AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))::FLOAT8 as "avg_secs"
                FROM repo_migration_status
                WHERE status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
                "#
            )
            .fetch_one(&self.pool)
            .await?;

            avg_duration.map(|avg| {
                let remaining = total_repos.saturating_sub(repos_completed + repos_failed);
                (avg * remaining as f64) as u64
            })
        } else {
            None
        };

        Ok(MigrationProgress {
            total_repos,
            repos_completed,
            repos_failed,
            total_objects_migrated,
            estimated_remaining_secs,
        })
    }

    /// Initialize migration tracking for a repository
    ///
    /// Requirements: 7.6
    async fn init_migration(&self, repo_id: &str) -> Result<i32, MigrationError> {
        // Count total objects
        let objects_total = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM repo_objects WHERE repo_id = $1"#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await? as i32;

        // Insert or update migration status
        sqlx::query!(
            r#"
            INSERT INTO repo_migration_status (repo_id, status, objects_total, objects_migrated, started_at, updated_at)
            VALUES ($1, 'in_progress', $2, 0, NOW(), NOW())
            ON CONFLICT (repo_id) DO UPDATE SET
                status = 'in_progress',
                objects_total = $2,
                started_at = COALESCE(repo_migration_status.started_at, NOW()),
                last_error = NULL,
                updated_at = NOW()
            "#,
            repo_id,
            objects_total
        )
        .execute(&self.pool)
        .await?;

        info!(
            repo_id = %repo_id,
            objects_total = objects_total,
            "Initialized migration for repository"
        );

        Ok(objects_total)
    }

    /// Update migration progress
    ///
    /// Requirements: 7.7
    async fn update_progress(
        &self,
        repo_id: &str,
        objects_migrated: i32,
    ) -> Result<(), MigrationError> {
        sqlx::query!(
            r#"
            UPDATE repo_migration_status
            SET objects_migrated = $2, updated_at = NOW()
            WHERE repo_id = $1
            "#,
            repo_id,
            objects_migrated
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark migration as completed
    ///
    /// Requirements: 7.6
    async fn complete_migration(&self, repo_id: &str) -> Result<(), MigrationError> {
        sqlx::query!(
            r#"
            UPDATE repo_migration_status
            SET status = 'completed', completed_at = NOW(), updated_at = NOW()
            WHERE repo_id = $1
            "#,
            repo_id
        )
        .execute(&self.pool)
        .await?;

        info!(repo_id = %repo_id, "Migration completed for repository");
        Ok(())
    }

    /// Mark migration as failed
    ///
    /// Requirements: 7.6
    async fn fail_migration(&self, repo_id: &str, error: &str) -> Result<(), MigrationError> {
        sqlx::query!(
            r#"
            UPDATE repo_migration_status
            SET status = 'failed', last_error = $2, updated_at = NOW()
            WHERE repo_id = $1
            "#,
            repo_id,
            error
        )
        .execute(&self.pool)
        .await?;

        error!(repo_id = %repo_id, error = %error, "Migration failed for repository");
        Ok(())
    }

    /// Log a migrated object
    ///
    /// Requirements: 7.2
    async fn log_migrated_object(
        &self,
        repo_id: &str,
        oid: &str,
        s3_key: &str,
        verified: bool,
    ) -> Result<(), MigrationError> {
        sqlx::query!(
            r#"
            INSERT INTO object_migration_log (repo_id, oid, s3_key, verified, migrated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (repo_id, oid) DO UPDATE SET
                verified = $4,
                migrated_at = NOW()
            "#,
            repo_id,
            oid,
            s3_key,
            verified
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Check if an object has already been migrated
    ///
    /// Requirements: 7.2
    async fn is_object_migrated(&self, repo_id: &str, oid: &str) -> Result<bool, MigrationError> {
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM object_migration_log 
                WHERE repo_id = $1 AND oid = $2
            ) as "exists!"
            "#,
            repo_id,
            oid
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    /// Get unmigrated objects for a repository
    ///
    /// Requirements: 7.1, 7.2
    async fn get_unmigrated_objects(
        &self,
        repo_id: &str,
        batch_size: i64,
    ) -> Result<Vec<(String, String, Vec<u8>)>, MigrationError> {
        // Get objects that haven't been migrated yet
        let objects = sqlx::query!(
            r#"
            SELECT ro.oid, ro.object_type, ro.data
            FROM repo_objects ro
            LEFT JOIN object_migration_log oml ON ro.repo_id = oml.repo_id AND ro.oid = oml.oid
            WHERE ro.repo_id = $1 AND oml.oid IS NULL
            ORDER BY ro.oid
            LIMIT $2
            "#,
            repo_id,
            batch_size
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(objects
            .into_iter()
            .map(|row| (row.oid, row.object_type, row.data))
            .collect())
    }

    /// Migrate a single repository
    ///
    /// Requirements: 7.1, 7.2, 7.5
    /// Design Reference: DR-S3-3.1
    pub async fn migrate_repository(
        &self,
        repo_id: &str,
    ) -> Result<MigrationResult, MigrationError> {
        let start_time = Instant::now();

        // Check current status
        let current_status = self.get_status(repo_id).await?;
        if current_status.status == MigrationStatus::InProgress {
            return Err(MigrationError::MigrationInProgress(repo_id.to_string()));
        }

        // Initialize migration
        let objects_total = self.init_migration(repo_id).await?;

        let mut objects_migrated = 0usize;
        let mut objects_failed = 0usize;
        let mut objects_verified = 0usize;

        info!(
            repo_id = %repo_id,
            objects_total = objects_total,
            "Starting migration for repository"
        );

        // Process objects in batches
        loop {
            let batch = self
                .get_unmigrated_objects(repo_id, self.config.batch_size as i64)
                .await?;

            if batch.is_empty() {
                break;
            }

            for (oid, object_type_str, data) in batch {
                let object_type = GitObjectType::from_str(&object_type_str)
                    .unwrap_or(GitObjectType::Blob);

                // Upload to S3
                let s3_key = S3ObjectStorage::object_key(repo_id, &oid);

                match self
                    .s3_storage
                    .put_object(repo_id, &oid, object_type, &data)
                    .await
                {
                    Ok(()) => {
                        // Verify if configured
                        let verified = if self.config.verify_after_migration {
                            match self.verify_object(repo_id, &oid, object_type, &data).await {
                                Ok(()) => {
                                    objects_verified += 1;
                                    true
                                }
                                Err(e) => {
                                    warn!(
                                        repo_id = %repo_id,
                                        oid = %oid,
                                        error = %e,
                                        "Object verification failed"
                                    );
                                    false
                                }
                            }
                        } else {
                            false
                        };

                        // Log the migration
                        self.log_migrated_object(repo_id, &oid, &s3_key, verified)
                            .await?;

                        objects_migrated += 1;

                        debug!(
                            repo_id = %repo_id,
                            oid = %oid,
                            verified = verified,
                            "Object migrated successfully"
                        );
                    }
                    Err(e) => {
                        warn!(
                            repo_id = %repo_id,
                            oid = %oid,
                            error = %e,
                            "Failed to migrate object"
                        );
                        objects_failed += 1;
                    }
                }
            }

            // Update progress
            self.update_progress(repo_id, objects_migrated as i32).await?;

            // Delay between batches
            if self.config.batch_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.batch_delay_ms)).await;
            }
        }

        // Mark migration as complete or failed
        if objects_failed == 0 {
            self.complete_migration(repo_id).await?;
        } else {
            self.fail_migration(
                repo_id,
                &format!("{} objects failed to migrate", objects_failed),
            )
            .await?;
        }

        let duration = start_time.elapsed();

        info!(
            repo_id = %repo_id,
            objects_migrated = objects_migrated,
            objects_failed = objects_failed,
            objects_verified = objects_verified,
            duration_secs = duration.as_secs(),
            "Migration completed for repository"
        );

        Ok(MigrationResult {
            repo_id: repo_id.to_string(),
            objects_migrated,
            objects_failed,
            objects_verified,
            duration,
        })
    }

    /// Migrate all repositories incrementally
    ///
    /// Requirements: 7.1, 7.2
    /// Design Reference: DR-S3-3.1
    pub async fn migrate_all(
        &self,
        batch_size: usize,
    ) -> Result<MigrationProgress, MigrationError> {
        let start_time = Instant::now();

        // Get all repositories that need migration
        let repos = sqlx::query_scalar!(
            r#"
            SELECT r.repo_id
            FROM repositories r
            LEFT JOIN repo_migration_status rms ON r.repo_id = rms.repo_id
            WHERE rms.status IS NULL OR rms.status != 'completed'
            ORDER BY r.repo_id
            LIMIT $1
            "#,
            batch_size as i64
        )
        .fetch_all(&self.pool)
        .await?;

        let total_repos = repos.len();
        let mut repos_completed = 0;
        let mut repos_failed = 0;
        let mut total_objects_migrated = 0;

        info!(
            total_repos = total_repos,
            "Starting batch migration for repositories"
        );

        for repo_id in repos {
            match self.migrate_repository(&repo_id).await {
                Ok(result) => {
                    repos_completed += 1;
                    total_objects_migrated += result.objects_migrated;
                }
                Err(e) => {
                    error!(
                        repo_id = %repo_id,
                        error = %e,
                        "Failed to migrate repository"
                    );
                    repos_failed += 1;
                }
            }
        }

        let elapsed = start_time.elapsed();
        let estimated_remaining = if repos_completed > 0 {
            let remaining_repos = total_repos - repos_completed - repos_failed;
            let avg_time_per_repo = elapsed.as_secs() / repos_completed as u64;
            Some(remaining_repos as u64 * avg_time_per_repo)
        } else {
            None
        };

        info!(
            repos_completed = repos_completed,
            repos_failed = repos_failed,
            total_objects_migrated = total_objects_migrated,
            duration_secs = elapsed.as_secs(),
            "Batch migration completed"
        );

        Ok(MigrationProgress {
            total_repos,
            repos_completed,
            repos_failed,
            total_objects_migrated,
            estimated_remaining_secs: estimated_remaining,
        })
    }

    /// Verify a single object after migration
    ///
    /// Requirements: 7.5
    async fn verify_object(
        &self,
        repo_id: &str,
        oid: &str,
        _object_type: GitObjectType,
        original_data: &[u8],
    ) -> Result<(), MigrationError> {
        // Retrieve from S3
        let stored = self.s3_storage.get_object(repo_id, oid).await?;

        // Verify data matches
        if stored.data != original_data {
            // Compute hashes for error message
            let expected_hash = compute_sha1(original_data);
            let actual_hash = compute_sha1(&stored.data);

            return Err(MigrationError::VerificationFailed {
                oid: oid.to_string(),
                expected: expected_hash,
                actual: actual_hash,
            });
        }

        Ok(())
    }

    /// Verify all migrated objects for a repository
    ///
    /// Requirements: 7.5
    pub async fn verify_migration(
        &self,
        repo_id: &str,
    ) -> Result<VerificationResult, MigrationError> {
        // Get all migrated but unverified objects
        let objects = sqlx::query!(
            r#"
            SELECT oml.oid, ro.object_type, ro.data
            FROM object_migration_log oml
            JOIN repo_objects ro ON oml.repo_id = ro.repo_id AND oml.oid = ro.oid
            WHERE oml.repo_id = $1 AND oml.verified = false
            "#,
            repo_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut objects_verified = 0;
        let mut objects_failed = 0;
        let mut failed_oids = Vec::new();

        for row in objects {
            let object_type = GitObjectType::from_str(&row.object_type)
                .unwrap_or(GitObjectType::Blob);

            match self
                .verify_object(repo_id, &row.oid, object_type, &row.data)
                .await
            {
                Ok(()) => {
                    // Mark as verified
                    sqlx::query!(
                        r#"
                        UPDATE object_migration_log
                        SET verified = true
                        WHERE repo_id = $1 AND oid = $2
                        "#,
                        repo_id,
                        row.oid
                    )
                    .execute(&self.pool)
                    .await?;

                    objects_verified += 1;
                }
                Err(e) => {
                    warn!(
                        repo_id = %repo_id,
                        oid = row.oid,
                        error = %e,
                        "Object verification failed"
                    );
                    objects_failed += 1;
                    failed_oids.push(row.oid);
                }
            }
        }

        info!(
            repo_id = %repo_id,
            objects_verified = objects_verified,
            objects_failed = objects_failed,
            "Verification completed for repository"
        );

        Ok(VerificationResult {
            repo_id: repo_id.to_string(),
            objects_verified,
            objects_failed,
            failed_oids,
        })
    }

    /// Resume a failed or interrupted migration
    ///
    /// Requirements: 7.2
    pub async fn resume_migration(
        &self,
        repo_id: &str,
    ) -> Result<MigrationResult, MigrationError> {
        let status = self.get_status(repo_id).await?;

        match status.status {
            MigrationStatus::Completed => {
                info!(repo_id = %repo_id, "Migration already completed");
                Ok(MigrationResult {
                    repo_id: repo_id.to_string(),
                    objects_migrated: status.objects_migrated as usize,
                    objects_failed: 0,
                    objects_verified: 0,
                    duration: Duration::ZERO,
                })
            }
            MigrationStatus::Pending | MigrationStatus::Failed | MigrationStatus::InProgress => {
                // Reset status to in_progress and continue
                sqlx::query!(
                    r#"
                    UPDATE repo_migration_status
                    SET status = 'in_progress', last_error = NULL, updated_at = NOW()
                    WHERE repo_id = $1
                    "#,
                    repo_id
                )
                .execute(&self.pool)
                .await?;

                self.migrate_repository(repo_id).await
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute SHA-1 hash of data
fn compute_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_status_conversion() {
        assert_eq!(MigrationStatus::from_db_str("pending"), MigrationStatus::Pending);
        assert_eq!(MigrationStatus::from_db_str("in_progress"), MigrationStatus::InProgress);
        assert_eq!(MigrationStatus::from_db_str("completed"), MigrationStatus::Completed);
        assert_eq!(MigrationStatus::from_db_str("failed"), MigrationStatus::Failed);
        assert_eq!(MigrationStatus::from_db_str("unknown"), MigrationStatus::Pending);

        assert_eq!(MigrationStatus::Pending.to_db_str(), "pending");
        assert_eq!(MigrationStatus::InProgress.to_db_str(), "in_progress");
        assert_eq!(MigrationStatus::Completed.to_db_str(), "completed");
        assert_eq!(MigrationStatus::Failed.to_db_str(), "failed");
    }

    #[test]
    fn test_progress_percent() {
        let status = RepoMigrationStatus {
            repo_id: "test".to_string(),
            status: MigrationStatus::InProgress,
            objects_total: 100,
            objects_migrated: 50,
            started_at: Some(Utc::now()),
            completed_at: None,
            last_error: None,
            updated_at: Utc::now(),
        };

        assert!((status.progress_percent() - 50.0).abs() < 0.01);

        let empty_status = RepoMigrationStatus {
            repo_id: "test".to_string(),
            status: MigrationStatus::Completed,
            objects_total: 0,
            objects_migrated: 0,
            started_at: None,
            completed_at: None,
            last_error: None,
            updated_at: Utc::now(),
        };

        assert!((empty_status.progress_percent() - 100.0).abs() < 0.01);
    }
}

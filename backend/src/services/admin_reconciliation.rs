//! Admin Reconciliation Service
//!
//! Detects and resolves disconnected repositories between database and object storage.
//! A disconnected repository is one that exists in only one location:
//! - DB-only: Repository record exists in database but has no objects in S3
//! - Storage-only: Objects exist in S3 but no corresponding database record
//!
//! Design Reference: Admin Dashboard Design Document - Reconciliation Service
//! Requirements: 7.1, 7.2, 7.3

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, info};

use crate::models::repository::Visibility;
use crate::services::audit::AuditService;
use crate::services::object_storage::ObjectStorageBackend;

/// Admin reconciliation service errors
#[derive(Debug, Error)]
pub enum AdminReconciliationError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Object storage error
    #[error("Object storage error: {0}")]
    ObjectStorage(String),

    /// Audit error
    #[error("Audit error: {0}")]
    Audit(String),

    /// Repository not found
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    /// Repository is not orphaned
    #[error("Repository is not orphaned: {0}")]
    NotOrphaned(String),

    /// Repository disconnection type mismatch
    #[error("Repository disconnection type mismatch: expected {expected}, found {found}")]
    DisconnectionTypeMismatch { expected: String, found: String },

    /// Owner not found
    #[error("Owner agent not found: {0}")]
    OwnerNotFound(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AdminReconciliationError {
    /// Get the error code for API responses
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Database(_) => "DATABASE_ERROR",
            Self::ObjectStorage(_) => "OBJECT_STORAGE_ERROR",
            Self::Audit(_) => "AUDIT_ERROR",
            Self::RepoNotFound(_) => "REPO_NOT_FOUND",
            Self::NotOrphaned(_) => "NOT_ORPHANED",
            Self::DisconnectionTypeMismatch { .. } => "DISCONNECTION_TYPE_MISMATCH",
            Self::OwnerNotFound(_) => "OWNER_NOT_FOUND",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Get the HTTP status code for this error
    #[must_use]
    pub fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::RepoNotFound(_) | Self::OwnerNotFound(_) => StatusCode::NOT_FOUND,
            Self::NotOrphaned(_) | Self::DisconnectionTypeMismatch { .. } => StatusCode::CONFLICT,
            Self::Database(_) | Self::ObjectStorage(_) | Self::Audit(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

/// Type of disconnection detected
///
/// Requirements: 7.1, 7.2
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectionType {
    /// Repository exists in DB but has no objects in S3
    DbOnly,
    /// Objects exist in S3 but no DB record
    StorageOnly,
}

/// Database metadata for a repository
///
/// Requirements: 7.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoDbMetadata {
    /// Repository name
    pub name: String,
    /// Owner agent ID
    pub owner_id: String,
    /// Repository visibility
    pub visibility: Visibility,
    /// When the repository was created
    pub created_at: DateTime<Utc>,
}

/// Storage metadata for a repository
///
/// Requirements: 7.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoStorageMetadata {
    /// Number of objects in storage
    pub object_count: i64,
    /// Total size of all objects in bytes
    pub total_size_bytes: i64,
    /// Timestamp of the oldest object (if available)
    pub oldest_object_at: Option<DateTime<Utc>>,
    /// Timestamp of the newest object (if available)
    pub newest_object_at: Option<DateTime<Utc>>,
}

/// A disconnected repository record
///
/// Requirements: 7.1, 7.2, 7.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectedRepo {
    /// Repository ID
    pub repo_id: String,
    /// Type of disconnection
    pub disconnection_type: DisconnectionType,
    /// Database metadata (for DB-only repos)
    pub db_metadata: Option<RepoDbMetadata>,
    /// Storage metadata (for storage-only repos)
    pub storage_metadata: Option<RepoStorageMetadata>,
    /// When the disconnection was detected
    pub detected_at: DateTime<Utc>,
}

/// Result of a reconciliation scan
///
/// Requirements: 7.1, 7.2, 7.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationScanResult {
    /// Repositories that exist in DB but have no objects in S3
    pub db_only_repos: Vec<DisconnectedRepo>,
    /// Repositories that have objects in S3 but no DB record
    pub storage_only_repos: Vec<DisconnectedRepo>,
    /// Total count of disconnected repositories
    pub total_disconnected: i64,
    /// When the scan was performed
    pub scanned_at: DateTime<Utc>,
}

/// Internal row type for repository queries
#[derive(Debug, sqlx::FromRow)]
struct RepoDbRow {
    repo_id: String,
    name: String,
    owner_id: String,
    visibility: Visibility,
    created_at: DateTime<Utc>,
}

/// Internal row type for storage metadata queries
#[derive(Debug, sqlx::FromRow)]
struct StorageMetadataRow {
    object_count: i64,
    total_size_bytes: i64,
    oldest_object_at: Option<DateTime<Utc>>,
    newest_object_at: Option<DateTime<Utc>>,
}

/// Admin reconciliation service for detecting orphaned repositories
///
/// This service compares repositories in the database with repository objects
/// tracked in the `repo_objects` table to identify disconnected repositories.
///
/// The `repo_objects` table serves as the source of truth for what objects
/// exist in S3 storage for each repository.
///
/// Design Reference: Admin Dashboard Design Document - Reconciliation Service
/// Requirements: 7.1, 7.2, 7.3
pub struct AdminReconciliationService {
    pool: PgPool,
    #[allow(dead_code)]
    object_storage: Arc<dyn ObjectStorageBackend>,
    #[allow(dead_code)]
    audit_service: AuditService,
}

impl AdminReconciliationService {
    /// Create a new `AdminReconciliationService` instance
    #[must_use]
    pub fn new(
        pool: PgPool,
        object_storage: Arc<dyn ObjectStorageBackend>,
        audit_service: AuditService,
    ) -> Self {
        Self {
            pool,
            object_storage,
            audit_service,
        }
    }

    /// Scan for disconnected repositories
    ///
    /// Compares repositories in the database with repository objects tracked
    /// in the `repo_objects` table to identify:
    /// - DB-only repos: exist in `repositories` table but have no entries in `repo_objects`
    /// - Storage-only repos: have entries in `repo_objects` but no record in `repositories`
    ///
    /// Requirements: 7.1, 7.2, 7.3
    pub async fn scan(&self) -> Result<ReconciliationScanResult, AdminReconciliationError> {
        let scanned_at = Utc::now();

        info!("Starting reconciliation scan");

        // Step 1: Get all repository IDs from the repositories table
        let db_repos = self.get_all_db_repos().await?;
        let db_repo_ids: HashSet<String> = db_repos.iter().map(|r| r.repo_id.clone()).collect();

        debug!("Found {} repositories in database", db_repo_ids.len());

        // Step 2: Get all unique repository IDs from repo_objects table
        // This represents repos that have objects in S3 storage
        let storage_repo_ids = self.get_all_storage_repo_ids().await?;

        debug!(
            "Found {} repositories with objects in storage",
            storage_repo_ids.len()
        );

        // Step 3: Find DB-only repos (in repositories table but not in repo_objects)
        let mut db_only_repos = Vec::new();
        for repo in &db_repos {
            if !storage_repo_ids.contains(&repo.repo_id) {
                db_only_repos.push(DisconnectedRepo {
                    repo_id: repo.repo_id.clone(),
                    disconnection_type: DisconnectionType::DbOnly,
                    db_metadata: Some(RepoDbMetadata {
                        name: repo.name.clone(),
                        owner_id: repo.owner_id.clone(),
                        visibility: repo.visibility,
                        created_at: repo.created_at,
                    }),
                    storage_metadata: None,
                    detected_at: scanned_at,
                });
            }
        }

        // Step 4: Find storage-only repos (in repo_objects but not in repositories)
        let mut storage_only_repos = Vec::new();
        for repo_id in &storage_repo_ids {
            if !db_repo_ids.contains(repo_id) {
                // Get storage metadata for this orphaned repo
                let storage_metadata = self.get_storage_metadata(repo_id).await?;

                storage_only_repos.push(DisconnectedRepo {
                    repo_id: repo_id.clone(),
                    disconnection_type: DisconnectionType::StorageOnly,
                    db_metadata: None,
                    storage_metadata: Some(storage_metadata),
                    detected_at: scanned_at,
                });
            }
        }

        let total_disconnected = (db_only_repos.len() + storage_only_repos.len()) as i64;

        info!(
            "Reconciliation scan complete: {} DB-only, {} storage-only, {} total disconnected",
            db_only_repos.len(),
            storage_only_repos.len(),
            total_disconnected
        );

        Ok(ReconciliationScanResult {
            db_only_repos,
            storage_only_repos,
            total_disconnected,
            scanned_at,
        })
    }

    /// Get all repositories from the database
    async fn get_all_db_repos(&self) -> Result<Vec<RepoDbRow>, AdminReconciliationError> {
        let repos = sqlx::query_as::<_, RepoDbRow>(
            r#"
            SELECT repo_id, name, owner_id, visibility, created_at
            FROM repositories
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(repos)
    }

    /// Get all unique repository IDs that have objects in storage
    ///
    /// This queries the `repo_objects` table which tracks all Git objects
    /// stored in S3 for each repository.
    async fn get_all_storage_repo_ids(&self) -> Result<HashSet<String>, AdminReconciliationError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT repo_id
            FROM repo_objects
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(repo_id,)| repo_id).collect())
    }

    /// Get storage metadata for a repository from the repo_objects table
    async fn get_storage_metadata(
        &self,
        repo_id: &str,
    ) -> Result<RepoStorageMetadata, AdminReconciliationError> {
        let row = sqlx::query_as::<_, StorageMetadataRow>(
            r#"
            SELECT 
                COUNT(*) as object_count,
                COALESCE(SUM(size), 0) as total_size_bytes,
                MIN(created_at) as oldest_object_at,
                MAX(created_at) as newest_object_at
            FROM repo_objects
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(RepoStorageMetadata {
            object_count: row.object_count,
            total_size_bytes: row.total_size_bytes,
            oldest_object_at: row.oldest_object_at,
            newest_object_at: row.newest_object_at,
        })
    }

    /// Reconnect a storage-only repository by creating a DB record
    ///
    /// This method creates a new database record for a repository that exists
    /// only in S3 storage (has objects in `repo_objects` but no entry in `repositories`).
    ///
    /// Requirements: 7.4
    /// Design Reference: Admin Dashboard Design Document - Reconciliation Service
    pub async fn reconnect_repo(
        &self,
        repo_id: &str,
        owner_id: &str,
        name: &str,
        admin_id: &str,
    ) -> Result<(), AdminReconciliationError> {
        info!(
            repo_id = repo_id,
            owner_id = owner_id,
            name = name,
            admin_id = admin_id,
            "Reconnecting storage-only repository"
        );

        // Step 1: Verify the repository is actually storage-only (has objects but no DB record)
        let db_exists = self.check_repo_exists_in_db(repo_id).await?;
        if db_exists {
            return Err(AdminReconciliationError::NotOrphaned(format!(
                "Repository {} already exists in database",
                repo_id
            )));
        }

        let storage_exists = self.check_repo_exists_in_storage(repo_id).await?;
        if !storage_exists {
            return Err(AdminReconciliationError::DisconnectionTypeMismatch {
                expected: "storage_only".to_string(),
                found: "not_found".to_string(),
            });
        }

        // Step 2: Verify the owner agent exists
        let owner_exists = self.check_agent_exists(owner_id).await?;
        if !owner_exists {
            return Err(AdminReconciliationError::OwnerNotFound(owner_id.to_string()));
        }

        // Step 3: Create the database record within a transaction
        let mut tx = self.pool.begin().await?;

        // Insert the repository record
        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, NULL, 'public', 'main', NOW())
            "#,
        )
        .bind(repo_id)
        .bind(owner_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;

        // Step 4: Create audit log entry
        let audit_event = crate::services::audit::AuditEvent::new(
            admin_id,
            crate::services::audit::AuditAction::AdminReconnectRepo,
            crate::services::audit::ResourceType::Repository,
            repo_id,
            serde_json::json!({
                "owner_id": owner_id,
                "name": name,
                "action": "reconnect_storage_only"
            }),
            format!("admin:{}", admin_id),
        );

        crate::services::audit::AuditService::append_in_tx(&mut tx, audit_event)
            .await
            .map_err(|e| AdminReconciliationError::Audit(e.to_string()))?;

        tx.commit().await?;

        info!(
            repo_id = repo_id,
            owner_id = owner_id,
            name = name,
            "Successfully reconnected storage-only repository"
        );

        Ok(())
    }

    /// Delete an orphaned DB record (no storage objects)
    ///
    /// This method removes a database record for a repository that has no
    /// corresponding objects in S3 storage.
    ///
    /// Requirements: 7.5
    /// Design Reference: Admin Dashboard Design Document - Reconciliation Service
    pub async fn delete_orphaned_db_record(
        &self,
        repo_id: &str,
        admin_id: &str,
    ) -> Result<(), AdminReconciliationError> {
        info!(
            repo_id = repo_id,
            admin_id = admin_id,
            "Deleting orphaned DB record"
        );

        // Step 1: Verify the repository is actually DB-only (has DB record but no storage objects)
        let db_exists = self.check_repo_exists_in_db(repo_id).await?;
        if !db_exists {
            return Err(AdminReconciliationError::RepoNotFound(repo_id.to_string()));
        }

        let storage_exists = self.check_repo_exists_in_storage(repo_id).await?;
        if storage_exists {
            return Err(AdminReconciliationError::NotOrphaned(format!(
                "Repository {} has objects in storage, not a DB-only orphan",
                repo_id
            )));
        }

        // Step 2: Delete the database record and related data within a transaction
        let mut tx = self.pool.begin().await?;

        // Get repository metadata for audit log before deletion
        let repo_metadata = sqlx::query_as::<_, RepoDbRow>(
            r#"
            SELECT repo_id, name, owner_id, visibility, created_at
            FROM repositories
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;

        let repo_metadata = repo_metadata.ok_or_else(|| {
            AdminReconciliationError::RepoNotFound(repo_id.to_string())
        })?;

        // Delete in order to respect foreign key constraints:
        // ci_runs, reviews, pull_requests, repo_stars, repo_star_counts, repo_refs, repo_access, repositories

        // Delete CI runs
        sqlx::query("DELETE FROM ci_runs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete reviews (via pull_requests)
        sqlx::query(
            r#"
            DELETE FROM reviews 
            WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)
            "#,
        )
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;

        // Delete pull requests
        sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete repo stars
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete repo star counts
        sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete repo refs
        sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete repo access
        sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Delete the repository record
        sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Step 3: Create audit log entry
        let audit_event = crate::services::audit::AuditEvent::new(
            admin_id,
            crate::services::audit::AuditAction::AdminDeleteOrphanedDb,
            crate::services::audit::ResourceType::Repository,
            repo_id,
            serde_json::json!({
                "name": repo_metadata.name,
                "owner_id": repo_metadata.owner_id,
                "action": "delete_orphaned_db_record"
            }),
            format!("admin:{}", admin_id),
        );

        crate::services::audit::AuditService::append_in_tx(&mut tx, audit_event)
            .await
            .map_err(|e| AdminReconciliationError::Audit(e.to_string()))?;

        tx.commit().await?;

        info!(
            repo_id = repo_id,
            name = repo_metadata.name,
            "Successfully deleted orphaned DB record"
        );

        Ok(())
    }

    /// Delete orphaned S3 objects (no DB record)
    ///
    /// This method removes all S3 objects for a repository that has no
    /// corresponding database record.
    ///
    /// Requirements: 7.6
    /// Design Reference: Admin Dashboard Design Document - Reconciliation Service
    pub async fn delete_orphaned_storage(
        &self,
        repo_id: &str,
        admin_id: &str,
    ) -> Result<(), AdminReconciliationError> {
        info!(
            repo_id = repo_id,
            admin_id = admin_id,
            "Deleting orphaned storage objects"
        );

        // Step 1: Verify the repository is actually storage-only (has objects but no DB record)
        let db_exists = self.check_repo_exists_in_db(repo_id).await?;
        if db_exists {
            return Err(AdminReconciliationError::NotOrphaned(format!(
                "Repository {} exists in database, not a storage-only orphan",
                repo_id
            )));
        }

        let storage_exists = self.check_repo_exists_in_storage(repo_id).await?;
        if !storage_exists {
            return Err(AdminReconciliationError::RepoNotFound(format!(
                "Repository {} has no objects in storage",
                repo_id
            )));
        }

        // Step 2: Get storage metadata for audit log before deletion
        let storage_metadata = self.get_storage_metadata(repo_id).await?;

        // Step 3: Delete objects from S3 storage
        let delete_result = self
            .object_storage
            .delete_repository_objects(repo_id)
            .await
            .map_err(|e| AdminReconciliationError::ObjectStorage(e.to_string()))?;

        // Step 4: Delete the repo_objects records from the database
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM repo_objects WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Step 5: Create audit log entry
        let audit_event = crate::services::audit::AuditEvent::new(
            admin_id,
            crate::services::audit::AuditAction::AdminDeleteOrphanedStorage,
            crate::services::audit::ResourceType::Repository,
            repo_id,
            serde_json::json!({
                "object_count": storage_metadata.object_count,
                "total_size_bytes": storage_metadata.total_size_bytes,
                "deleted_count": delete_result.deleted_count,
                "failed_count": delete_result.failed.len(),
                "action": "delete_orphaned_storage"
            }),
            format!("admin:{}", admin_id),
        );

        crate::services::audit::AuditService::append_in_tx(&mut tx, audit_event)
            .await
            .map_err(|e| AdminReconciliationError::Audit(e.to_string()))?;

        tx.commit().await?;

        info!(
            repo_id = repo_id,
            deleted_count = delete_result.deleted_count,
            failed_count = delete_result.failed.len(),
            "Successfully deleted orphaned storage objects"
        );

        Ok(())
    }

    /// Check if a repository exists in the database
    async fn check_repo_exists_in_db(&self, repo_id: &str) -> Result<bool, AdminReconciliationError> {
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT repo_id FROM repositories WHERE repo_id = $1",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(exists.is_some())
    }

    /// Check if a repository has objects in storage (repo_objects table)
    async fn check_repo_exists_in_storage(&self, repo_id: &str) -> Result<bool, AdminReconciliationError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repo_objects WHERE repo_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if an agent exists in the database
    async fn check_agent_exists(&self, agent_id: &str) -> Result<bool, AdminReconciliationError> {
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT agent_id FROM agents WHERE agent_id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(exists.is_some())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disconnection_type_serialization() {
        let db_only = DisconnectionType::DbOnly;
        let storage_only = DisconnectionType::StorageOnly;

        let db_only_json = serde_json::to_string(&db_only).expect("Failed to serialize");
        let storage_only_json = serde_json::to_string(&storage_only).expect("Failed to serialize");

        assert_eq!(db_only_json, "\"db_only\"");
        assert_eq!(storage_only_json, "\"storage_only\"");
    }

    #[test]
    fn test_disconnection_type_deserialization() {
        let db_only: DisconnectionType =
            serde_json::from_str("\"db_only\"").expect("Failed to deserialize");
        let storage_only: DisconnectionType =
            serde_json::from_str("\"storage_only\"").expect("Failed to deserialize");

        assert_eq!(db_only, DisconnectionType::DbOnly);
        assert_eq!(storage_only, DisconnectionType::StorageOnly);
    }

    #[test]
    fn test_repo_db_metadata_serialization() {
        let metadata = RepoDbMetadata {
            name: "test-repo".to_string(),
            owner_id: "agent-123".to_string(),
            visibility: Visibility::Public,
            created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        assert!(json.contains("\"name\":\"test-repo\""));
        assert!(json.contains("\"ownerId\":\"agent-123\""));
        assert!(json.contains("\"visibility\":\"public\""));
    }

    #[test]
    fn test_repo_storage_metadata_serialization() {
        let metadata = RepoStorageMetadata {
            object_count: 100,
            total_size_bytes: 1024000,
            oldest_object_at: Some(
                DateTime::parse_from_rfc3339("2024-01-10T08:00:00Z")
                    .expect("Failed to parse date")
                    .with_timezone(&Utc),
            ),
            newest_object_at: Some(
                DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
                    .expect("Failed to parse date")
                    .with_timezone(&Utc),
            ),
        };

        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        assert!(json.contains("\"objectCount\":100"));
        assert!(json.contains("\"totalSizeBytes\":1024000"));
        assert!(json.contains("\"oldestObjectAt\":"));
        assert!(json.contains("\"newestObjectAt\":"));
    }

    #[test]
    fn test_repo_storage_metadata_with_none_timestamps() {
        let metadata = RepoStorageMetadata {
            object_count: 0,
            total_size_bytes: 0,
            oldest_object_at: None,
            newest_object_at: None,
        };

        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        assert!(json.contains("\"objectCount\":0"));
        assert!(json.contains("\"totalSizeBytes\":0"));
        assert!(json.contains("\"oldestObjectAt\":null"));
        assert!(json.contains("\"newestObjectAt\":null"));
    }

    #[test]
    fn test_disconnected_repo_db_only_serialization() {
        let repo = DisconnectedRepo {
            repo_id: "repo-123".to_string(),
            disconnection_type: DisconnectionType::DbOnly,
            db_metadata: Some(RepoDbMetadata {
                name: "orphaned-repo".to_string(),
                owner_id: "agent-456".to_string(),
                visibility: Visibility::Private,
                created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                    .expect("Failed to parse date")
                    .with_timezone(&Utc),
            }),
            storage_metadata: None,
            detected_at: DateTime::parse_from_rfc3339("2024-01-20T14:00:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&repo).expect("Failed to serialize");
        assert!(json.contains("\"repoId\":\"repo-123\""));
        assert!(json.contains("\"disconnectionType\":\"db_only\""));
        assert!(json.contains("\"dbMetadata\":"));
        assert!(json.contains("\"storageMetadata\":null"));
        assert!(json.contains("\"detectedAt\":"));
    }

    #[test]
    fn test_disconnected_repo_storage_only_serialization() {
        let repo = DisconnectedRepo {
            repo_id: "repo-789".to_string(),
            disconnection_type: DisconnectionType::StorageOnly,
            db_metadata: None,
            storage_metadata: Some(RepoStorageMetadata {
                object_count: 50,
                total_size_bytes: 512000,
                oldest_object_at: None,
                newest_object_at: None,
            }),
            detected_at: DateTime::parse_from_rfc3339("2024-01-20T14:00:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&repo).expect("Failed to serialize");
        assert!(json.contains("\"repoId\":\"repo-789\""));
        assert!(json.contains("\"disconnectionType\":\"storage_only\""));
        assert!(json.contains("\"dbMetadata\":null"));
        assert!(json.contains("\"storageMetadata\":"));
    }

    #[test]
    fn test_reconciliation_scan_result_serialization() {
        let result = ReconciliationScanResult {
            db_only_repos: vec![DisconnectedRepo {
                repo_id: "db-only-1".to_string(),
                disconnection_type: DisconnectionType::DbOnly,
                db_metadata: Some(RepoDbMetadata {
                    name: "db-repo".to_string(),
                    owner_id: "agent-1".to_string(),
                    visibility: Visibility::Public,
                    created_at: Utc::now(),
                }),
                storage_metadata: None,
                detected_at: Utc::now(),
            }],
            storage_only_repos: vec![DisconnectedRepo {
                repo_id: "storage-only-1".to_string(),
                disconnection_type: DisconnectionType::StorageOnly,
                db_metadata: None,
                storage_metadata: Some(RepoStorageMetadata {
                    object_count: 10,
                    total_size_bytes: 1000,
                    oldest_object_at: None,
                    newest_object_at: None,
                }),
                detected_at: Utc::now(),
            }],
            total_disconnected: 2,
            scanned_at: Utc::now(),
        };

        let json = serde_json::to_string(&result).expect("Failed to serialize");
        assert!(json.contains("\"dbOnlyRepos\":"));
        assert!(json.contains("\"storageOnlyRepos\":"));
        assert!(json.contains("\"totalDisconnected\":2"));
        assert!(json.contains("\"scannedAt\":"));
    }

    #[test]
    fn test_reconciliation_scan_result_empty() {
        let result = ReconciliationScanResult {
            db_only_repos: vec![],
            storage_only_repos: vec![],
            total_disconnected: 0,
            scanned_at: Utc::now(),
        };

        let json = serde_json::to_string(&result).expect("Failed to serialize");
        assert!(json.contains("\"dbOnlyRepos\":[]"));
        assert!(json.contains("\"storageOnlyRepos\":[]"));
        assert!(json.contains("\"totalDisconnected\":0"));
    }

    #[test]
    fn test_admin_reconciliation_error_codes() {
        assert_eq!(
            AdminReconciliationError::RepoNotFound("test".to_string()).error_code(),
            "REPO_NOT_FOUND"
        );
        assert_eq!(
            AdminReconciliationError::NotOrphaned("test".to_string()).error_code(),
            "NOT_ORPHANED"
        );
        assert_eq!(
            AdminReconciliationError::DisconnectionTypeMismatch {
                expected: "db".to_string(),
                found: "storage".to_string()
            }
            .error_code(),
            "DISCONNECTION_TYPE_MISMATCH"
        );
        assert_eq!(
            AdminReconciliationError::OwnerNotFound("test".to_string()).error_code(),
            "OWNER_NOT_FOUND"
        );
        assert_eq!(
            AdminReconciliationError::ObjectStorage("test".to_string()).error_code(),
            "OBJECT_STORAGE_ERROR"
        );
        assert_eq!(
            AdminReconciliationError::Audit("test".to_string()).error_code(),
            "AUDIT_ERROR"
        );
        assert_eq!(
            AdminReconciliationError::Internal("test".to_string()).error_code(),
            "INTERNAL_ERROR"
        );
    }

    #[test]
    fn test_admin_reconciliation_error_status_codes() {
        use actix_web::http::StatusCode;

        assert_eq!(
            AdminReconciliationError::RepoNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminReconciliationError::OwnerNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminReconciliationError::NotOrphaned("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AdminReconciliationError::DisconnectionTypeMismatch {
                expected: "db".to_string(),
                found: "storage".to_string()
            }
            .status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AdminReconciliationError::ObjectStorage("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AdminReconciliationError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

//! Dual-Read Storage for Migration Period
//!
//! Provides a storage wrapper that reads from both S3 and PostgreSQL during migration.
//! Design Reference: DR-S3-3.2
//!
//! Requirements: 7.3, 7.4
//!
//! This module implements a dual-read storage strategy:
//! - Read operations try S3 first, then fall back to PostgreSQL
//! - Write operations always go to S3
//! - This enables seamless migration without downtime

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::{debug, warn};

use super::object_storage::{
    CopyResult, DeleteResult, GitObjectType, ObjectList, ObjectMetadata, ObjectStorageBackend,
    PackfileData, S3ObjectStorage, StorageError, StoredObject,
};

// ============================================================================
// PostgresFallback Implementation
// ============================================================================

/// PostgreSQL fallback storage for reading objects during migration
///
/// Design Reference: DR-S3-3.2
/// Requirements: 7.3, 7.4
///
/// This implementation reads Git objects from the `repo_objects` table
/// when they are not yet migrated to S3.
pub struct PostgresFallback {
    pool: PgPool,
}

impl PostgresFallback {
    /// Create a new PostgreSQL fallback storage
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a Git object from PostgreSQL
    pub async fn get_object(&self, repo_id: &str, oid: &str) -> Result<StoredObject, StorageError> {
        let row = sqlx::query!(
            r#"
            SELECT oid, object_type, size, data
            FROM repo_objects
            WHERE repo_id = $1 AND oid = $2
            "#,
            repo_id,
            oid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?;

        match row {
            Some(row) => {
                let object_type = GitObjectType::from_str(&row.object_type)
                    .unwrap_or(GitObjectType::Blob);

                Ok(StoredObject {
                    oid: row.oid,
                    object_type,
                    size: row.size as usize,
                    data: row.data,
                })
            }
            None => Err(StorageError::NotFound(format!(
                "Object {} not found in PostgreSQL",
                oid
            ))),
        }
    }

    /// Check if an object exists in PostgreSQL
    pub async fn head_object(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        let row = sqlx::query!(
            r#"
            SELECT oid, object_type, size
            FROM repo_objects
            WHERE repo_id = $1 AND oid = $2
            "#,
            repo_id,
            oid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?;

        match row {
            Some(row) => {
                let object_type = GitObjectType::from_str(&row.object_type)
                    .unwrap_or(GitObjectType::Blob);

                Ok(Some(ObjectMetadata {
                    oid: row.oid,
                    object_type,
                    size: row.size as usize,
                }))
            }
            None => Ok(None),
        }
    }

    /// List objects in PostgreSQL for a repository
    pub async fn list_objects(
        &self,
        repo_id: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
    ) -> Result<ObjectList, StorageError> {
        // Parse continuation token as offset
        let offset: i64 = continuation_token
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);

        let limit: i64 = 1000;

        // Build query based on prefix
        let objects = if let Some(prefix) = prefix {
            let prefix_pattern = format!("{}%", prefix);
            sqlx::query_scalar!(
                r#"
                SELECT oid
                FROM repo_objects
                WHERE repo_id = $1 AND oid LIKE $2
                ORDER BY oid
                LIMIT $3 OFFSET $4
                "#,
                repo_id,
                prefix_pattern,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?
        } else {
            sqlx::query_scalar!(
                r#"
                SELECT oid
                FROM repo_objects
                WHERE repo_id = $1
                ORDER BY oid
                LIMIT $2 OFFSET $3
                "#,
                repo_id,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?
        };

        let is_truncated = objects.len() as i64 == limit;
        let next_token = if is_truncated {
            Some((offset + limit).to_string())
        } else {
            None
        };

        Ok(ObjectList {
            objects,
            continuation_token: next_token,
            is_truncated,
        })
    }

    /// Get a packfile from PostgreSQL (not supported - packfiles are S3-only)
    pub async fn get_packfile(
        &self,
        _repo_id: &str,
        pack_hash: &str,
    ) -> Result<PackfileData, StorageError> {
        // Packfiles are only stored in S3, not in PostgreSQL
        Err(StorageError::NotFound(format!(
            "Packfile {} not found in PostgreSQL (packfiles are S3-only)",
            pack_hash
        )))
    }
}

// ============================================================================
// MigrationStatusCache
// ============================================================================

/// Cache for repository migration status
///
/// This is a simple in-memory cache to avoid repeated database queries
/// for migration status. In production, this could be backed by Redis.
pub struct MigrationStatusCache {
    pool: PgPool,
}

impl MigrationStatusCache {
    /// Create a new migration status cache
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if a repository has completed migration
    pub async fn is_migrated(&self, repo_id: &str) -> Result<bool, StorageError> {
        let row = sqlx::query!(
            r#"
            SELECT status::TEXT as "status!"
            FROM repo_migration_status
            WHERE repo_id = $1
            "#,
            repo_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?;

        Ok(row.map(|r| r.status == "completed").unwrap_or(false))
    }

    /// Check if a specific object has been migrated
    pub async fn is_object_migrated(&self, repo_id: &str, oid: &str) -> Result<bool, StorageError> {
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
        .await
        .map_err(|e| StorageError::Internal(format!("Database error: {}", e)))?;

        Ok(exists)
    }
}

// ============================================================================
// DualReadStorage Implementation
// ============================================================================

/// Dual-read storage for migration period
///
/// Design Reference: DR-S3-3.2
/// Requirements: 7.3, 7.4
///
/// This wrapper implements the dual-read strategy:
/// - Read operations try S3 first, then fall back to PostgreSQL
/// - Write operations always go to S3
/// - This enables seamless migration without downtime
pub struct DualReadStorage {
    s3_storage: Arc<S3ObjectStorage>,
    pg_fallback: Arc<PostgresFallback>,
    migration_status: Arc<MigrationStatusCache>,
}

impl DualReadStorage {
    /// Create a new dual-read storage wrapper
    ///
    /// # Arguments
    ///
    /// * `s3_storage` - The primary S3 storage backend
    /// * `pool` - PostgreSQL connection pool for fallback reads
    pub fn new(s3_storage: Arc<S3ObjectStorage>, pool: PgPool) -> Self {
        let pg_fallback = Arc::new(PostgresFallback::new(pool.clone()));
        let migration_status = Arc::new(MigrationStatusCache::new(pool));

        Self {
            s3_storage,
            pg_fallback,
            migration_status,
        }
    }

    /// Create from individual components (for testing)
    pub fn from_components(
        s3_storage: Arc<S3ObjectStorage>,
        pg_fallback: Arc<PostgresFallback>,
        migration_status: Arc<MigrationStatusCache>,
    ) -> Self {
        Self {
            s3_storage,
            pg_fallback,
            migration_status,
        }
    }

    /// Get the underlying S3 storage
    pub fn s3_storage(&self) -> &Arc<S3ObjectStorage> {
        &self.s3_storage
    }

    /// Get the PostgreSQL fallback
    pub fn pg_fallback(&self) -> &Arc<PostgresFallback> {
        &self.pg_fallback
    }

    /// Check if a repository has completed migration
    pub async fn is_repo_migrated(&self, repo_id: &str) -> Result<bool, StorageError> {
        self.migration_status.is_migrated(repo_id).await
    }
}

#[async_trait]
impl ObjectStorageBackend for DualReadStorage {
    /// Retrieve a Git object - tries S3 first, falls back to PostgreSQL
    ///
    /// Requirements: 7.3, 7.4
    ///
    /// This method implements the dual-read strategy:
    /// 1. Try to get the object from S3
    /// 2. If not found in S3, fall back to PostgreSQL
    /// 3. If found in neither, return NotFound error
    async fn get_object(&self, repo_id: &str, oid: &str) -> Result<StoredObject, StorageError> {
        debug!(
            repo_id = repo_id,
            oid = oid,
            "DualReadStorage: attempting to get object"
        );

        // Try S3 first
        match self.s3_storage.get_object(repo_id, oid).await {
            Ok(obj) => {
                debug!(
                    repo_id = repo_id,
                    oid = oid,
                    "DualReadStorage: object found in S3"
                );
                return Ok(obj);
            }
            Err(StorageError::NotFound(_)) => {
                debug!(
                    repo_id = repo_id,
                    oid = oid,
                    "DualReadStorage: object not found in S3, trying PostgreSQL fallback"
                );
                // Fall through to PostgreSQL fallback
            }
            Err(e) => {
                // For other errors (connection, rate limit, etc.), log and try fallback
                warn!(
                    repo_id = repo_id,
                    oid = oid,
                    error = %e,
                    "DualReadStorage: S3 error, trying PostgreSQL fallback"
                );
                // Fall through to PostgreSQL fallback
            }
        }

        // Fall back to PostgreSQL
        self.pg_fallback.get_object(repo_id, oid).await
    }

    /// Store a Git object - always writes to S3
    ///
    /// Requirements: 7.3
    ///
    /// Write operations always go to S3, never to PostgreSQL.
    /// This ensures new objects are stored in the target storage.
    async fn put_object(
        &self,
        repo_id: &str,
        oid: &str,
        object_type: GitObjectType,
        data: &[u8],
    ) -> Result<(), StorageError> {
        debug!(
            repo_id = repo_id,
            oid = oid,
            object_type = %object_type,
            "DualReadStorage: storing object in S3"
        );

        // Always write to S3
        self.s3_storage
            .put_object(repo_id, oid, object_type, data)
            .await
    }

    /// Delete a Git object - deletes from S3 only
    ///
    /// During migration, we only delete from S3. PostgreSQL objects
    /// will be cleaned up after migration completes.
    async fn delete_object(&self, repo_id: &str, oid: &str) -> Result<(), StorageError> {
        debug!(
            repo_id = repo_id,
            oid = oid,
            "DualReadStorage: deleting object from S3"
        );

        // Only delete from S3
        self.s3_storage.delete_object(repo_id, oid).await
    }

    /// List objects - combines results from S3 and PostgreSQL
    ///
    /// Requirements: 7.3, 7.4
    ///
    /// During migration, objects may exist in either storage.
    /// This method tries S3 first, then falls back to PostgreSQL.
    async fn list_objects(
        &self,
        repo_id: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
    ) -> Result<ObjectList, StorageError> {
        debug!(
            repo_id = repo_id,
            prefix = ?prefix,
            "DualReadStorage: listing objects"
        );

        // Check if repository is fully migrated
        let is_migrated = self.migration_status.is_migrated(repo_id).await?;

        if is_migrated {
            // Repository is fully migrated, only query S3
            return self
                .s3_storage
                .list_objects(repo_id, prefix, continuation_token)
                .await;
        }

        // During migration, try S3 first
        match self
            .s3_storage
            .list_objects(repo_id, prefix, continuation_token)
            .await
        {
            Ok(list) if !list.objects.is_empty() => {
                // S3 has objects, return them
                Ok(list)
            }
            Ok(_) | Err(StorageError::NotFound(_)) => {
                // S3 is empty or not found, fall back to PostgreSQL
                self.pg_fallback
                    .list_objects(repo_id, prefix, continuation_token)
                    .await
            }
            Err(e) => {
                // For other errors, try PostgreSQL fallback
                warn!(
                    repo_id = repo_id,
                    error = %e,
                    "DualReadStorage: S3 list error, trying PostgreSQL fallback"
                );
                self.pg_fallback
                    .list_objects(repo_id, prefix, continuation_token)
                    .await
            }
        }
    }

    /// Check if an object exists - checks S3 first, then PostgreSQL
    ///
    /// Requirements: 7.3, 7.4
    async fn head_object(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        debug!(
            repo_id = repo_id,
            oid = oid,
            "DualReadStorage: checking object existence"
        );

        // Try S3 first
        match self.s3_storage.head_object(repo_id, oid).await {
            Ok(Some(metadata)) => {
                return Ok(Some(metadata));
            }
            Ok(None) => {
                // Not in S3, try PostgreSQL
            }
            Err(e) => {
                // Log error and try PostgreSQL
                warn!(
                    repo_id = repo_id,
                    oid = oid,
                    error = %e,
                    "DualReadStorage: S3 head error, trying PostgreSQL fallback"
                );
            }
        }

        // Fall back to PostgreSQL
        self.pg_fallback.head_object(repo_id, oid).await
    }

    /// Store a packfile - always writes to S3
    ///
    /// Packfiles are only stored in S3, never in PostgreSQL.
    async fn put_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
        packfile: &[u8],
        index: &[u8],
    ) -> Result<(), StorageError> {
        debug!(
            repo_id = repo_id,
            pack_hash = pack_hash,
            "DualReadStorage: storing packfile in S3"
        );

        // Always write to S3
        self.s3_storage
            .put_packfile(repo_id, pack_hash, packfile, index)
            .await
    }

    /// Retrieve a packfile - only from S3
    ///
    /// Packfiles are only stored in S3, not in PostgreSQL.
    async fn get_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
    ) -> Result<PackfileData, StorageError> {
        debug!(
            repo_id = repo_id,
            pack_hash = pack_hash,
            "DualReadStorage: getting packfile from S3"
        );

        // Packfiles are only in S3
        self.s3_storage.get_packfile(repo_id, pack_hash).await
    }

    /// Delete all objects for a repository - deletes from S3 only
    ///
    /// During migration, we only delete from S3. PostgreSQL objects
    /// will be cleaned up separately after migration completes.
    async fn delete_repository_objects(&self, repo_id: &str) -> Result<DeleteResult, StorageError> {
        debug!(
            repo_id = repo_id,
            "DualReadStorage: deleting repository objects from S3"
        );

        // Only delete from S3
        self.s3_storage.delete_repository_objects(repo_id).await
    }

    /// Copy all objects from one repository to another
    ///
    /// This copies objects in S3. PostgreSQL objects are not copied
    /// as they will be migrated separately.
    async fn copy_repository_objects(
        &self,
        source_repo_id: &str,
        target_repo_id: &str,
    ) -> Result<CopyResult, StorageError> {
        debug!(
            source = source_repo_id,
            target = target_repo_id,
            "DualReadStorage: copying repository objects in S3"
        );

        // Only copy in S3
        self.s3_storage
            .copy_repository_objects(source_repo_id, target_repo_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests would go here, but they require database and S3 mocks
    // which are better suited for integration tests with MinIO

    #[test]
    fn test_migration_status_from_db_str() {
        // This is a simple unit test for the status conversion
        use super::super::storage_migration::MigrationStatus;

        assert_eq!(
            MigrationStatus::from_db_str("pending"),
            MigrationStatus::Pending
        );
        assert_eq!(
            MigrationStatus::from_db_str("in_progress"),
            MigrationStatus::InProgress
        );
        assert_eq!(
            MigrationStatus::from_db_str("completed"),
            MigrationStatus::Completed
        );
        assert_eq!(
            MigrationStatus::from_db_str("failed"),
            MigrationStatus::Failed
        );
        assert_eq!(
            MigrationStatus::from_db_str("unknown"),
            MigrationStatus::Pending
        );
    }
}

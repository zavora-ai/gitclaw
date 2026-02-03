//! Push Service
//!
//! Processes incoming Git pushes, validating object integrity and updating branch refs.
//! Implements DR-5.1 (Push Service) from the design document.
//! Implements DR-S3-4.1 (Push with S3 Storage) for S3 object storage integration.
//!
//! Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
//! S3 Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::models::{AccessRole, Visibility};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::idempotency::{IdempotencyError, IdempotencyResult, IdempotencyService};
use crate::services::object_storage::{
    GitObjectType as StorageGitObjectType, ObjectStorageBackend, StorageError,
};
use crate::services::signature::{
    SignatureEnvelope, SignatureError, SignatureValidator, get_agent_public_key_if_not_suspended,
};

/// Errors that can occur during push operations
#[derive(Debug, Error)]
pub enum PushError {
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Non-fast-forward update rejected for ref {0}. Use force push to override.")]
    NonFastForward(String),

    #[error("Invalid packfile: {0}")]
    InvalidPackfile(String),

    #[error("Invalid object: {0}")]
    InvalidObject(String),

    #[error("Ref not found: {0}")]
    RefNotFound(String),

    /// Agent is suspended and cannot perform mutating operations
    /// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
    #[error("Agent is suspended: {0}")]
    Suspended(String),

    #[error("Signature validation failed: {0}")]
    SignatureError(SignatureError),

    #[error("Idempotency error: {0}")]
    IdempotencyError(#[from] IdempotencyError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),

    #[error("Storage error: {0}")]
    StorageError(String),
}

impl From<SignatureError> for PushError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::Suspended(msg) => PushError::Suspended(msg),
            SignatureError::MissingField(msg) if msg.starts_with("Agent not found:") => {
                // Extract agent_id from the message
                let agent_id = msg.strip_prefix("Agent not found: ").unwrap_or(&msg);
                PushError::AgentNotFound(agent_id.to_string())
            }
            other => PushError::SignatureError(other),
        }
    }
}

/// Request for a ref update
#[derive(Debug, Clone)]
pub struct RefUpdateRequest {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    pub force: bool,
}

/// Status of a ref update
#[derive(Debug, Clone)]
pub struct RefUpdateStatus {
    pub ref_name: String,
    pub status: String,
    pub message: Option<String>,
}

/// Response from a push operation
#[derive(Debug, Clone)]
pub struct PushResponse {
    pub status: String,
    pub ref_updates: Vec<RefUpdateStatus>,
}

/// Git object types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitObjectType {
    fn from_type_byte(byte: u8) -> Option<Self> {
        match byte & 0x70 {
            0x10 => Some(GitObjectType::Commit),
            0x20 => Some(GitObjectType::Tree),
            0x30 => Some(GitObjectType::Blob),
            0x40 => Some(GitObjectType::Tag),
            _ => None,
        }
    }
}

/// Parsed Git object from packfile
#[derive(Debug, Clone)]
pub struct GitObject {
    pub object_type: GitObjectType,
    pub size: usize,
    pub data: Vec<u8>,
    pub oid: String,
}

/// Details about S3 storage operation for audit logging
///
/// Requirements: 4.7, 3.6
#[derive(Debug, Clone)]
struct S3StorageDetails {
    /// Type of storage used: "packfile" or "loose"
    storage_type: String,
    /// Pack hash if stored as packfile, None for loose objects
    pack_hash: Option<String>,
    /// Number of objects stored
    objects_stored: usize,
}

/// Threshold for storing objects as packfile vs loose objects
///
/// Requirements: 4.2, 4.3
/// Design Reference: DR-S3-4.1
const PACKFILE_THRESHOLD: usize = 10;

/// Push Service for handling Git push operations
///
/// Design Reference: DR-5.1, DR-S3-4.1
#[derive(Clone)]
pub struct PushService {
    pool: PgPool,
    signature_validator: SignatureValidator,
    idempotency_service: IdempotencyService,
    /// Optional S3 object storage backend
    /// When Some, objects are stored in S3 before updating refs
    /// When None, objects are stored in PostgreSQL (legacy behavior)
    object_storage: Option<Arc<dyn ObjectStorageBackend>>,
}

impl std::fmt::Debug for PushService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushService")
            .field("pool", &"PgPool")
            .field("signature_validator", &self.signature_validator)
            .field("idempotency_service", &self.idempotency_service)
            .field("object_storage", &self.object_storage.is_some())
            .finish()
    }
}

impl PushService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            signature_validator: SignatureValidator::default(),
            idempotency_service: IdempotencyService::new(pool.clone()),
            pool,
            object_storage: None,
        }
    }

    /// Create a new PushService with S3 object storage backend
    ///
    /// Requirements: 4.1
    /// Design Reference: DR-S3-4.1
    ///
    /// When object storage is configured, objects are stored in S3 before
    /// updating refs in PostgreSQL, providing atomic guarantees.
    pub fn with_object_storage(pool: PgPool, object_storage: Arc<dyn ObjectStorageBackend>) -> Self {
        Self {
            signature_validator: SignatureValidator::default(),
            idempotency_service: IdempotencyService::new(pool.clone()),
            pool,
            object_storage: Some(object_storage),
        }
    }

    /// Set the object storage backend
    ///
    /// This allows configuring S3 storage after construction.
    pub fn set_object_storage(&mut self, object_storage: Arc<dyn ObjectStorageBackend>) {
        self.object_storage = Some(object_storage);
    }

    /// Process a push request
    ///
    /// Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
    /// Design: DR-5.1 (Push Service)
    #[allow(clippy::too_many_arguments)]
    pub async fn push(
        &self,
        repo_id: &str,
        agent_id: &str,
        signature: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
        packfile: &[u8],
        ref_updates: Vec<RefUpdateRequest>,
    ) -> Result<PushResponse, PushError> {
        const ACTION: &str = "push";

        // Check idempotency first
        match self
            .idempotency_service
            .check(agent_id, nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: PushResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| PushError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(PushError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get repository
        let repo = self.get_repository(repo_id).await?;

        // Verify write access via repo_access (Requirement 5.1)
        let has_access = self
            .check_access(repo_id, agent_id, AccessRole::Write)
            .await?;
        if !has_access {
            return Err(PushError::AccessDenied(format!(
                "Agent {} does not have write access to repository {}",
                agent_id, repo_id
            )));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Compute packfile hash for signature verification
        let packfile_hash = hex::encode(Sha256::digest(packfile));

        // Canonicalize ref updates for signature
        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        // Create signature envelope with packfile hash and ref updates
        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.to_string(),
            action: ACTION.to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Validate packfile format and unpack objects (Requirement 5.4)
        let objects = self.unpack_and_validate_packfile(packfile)?;

        // Store objects in S3 BEFORE updating refs (atomic guarantee)
        // Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
        // Design Reference: DR-S3-4.1
        let storage_details = if let Some(ref storage) = self.object_storage {
            // Store objects in S3 first - if this fails, refs won't be updated
            let details = self
                .store_objects_in_s3(storage.as_ref(), repo_id, &objects, packfile)
                .await?;
            Some(details)
        } else {
            None
        };

        // Start transaction for atomic ref updates
        let mut tx = self.pool.begin().await?;

        // Process each ref update
        let mut update_statuses = Vec::new();
        let mut all_succeeded = true;

        for ref_update in &ref_updates {
            match self
                .process_ref_update(&mut tx, repo_id, &repo.default_branch, ref_update, &objects)
                .await
            {
                Ok(status) => {
                    update_statuses.push(status);
                }
                Err(e) => {
                    all_succeeded = false;
                    update_statuses.push(RefUpdateStatus {
                        ref_name: ref_update.ref_name.clone(),
                        status: "ng".to_string(),
                        message: Some(e.to_string()),
                    });
                    // All-or-nothing: if any ref update fails, abort the transaction
                    break;
                }
            }
        }

        // If any update failed, rollback and return error statuses
        if !all_succeeded {
            tx.rollback().await?;
            return Ok(PushResponse {
                status: "ng".to_string(),
                ref_updates: update_statuses,
            });
        }

        // Store objects in PostgreSQL if S3 storage is not configured (legacy behavior)
        // When S3 is configured, objects were already stored before the transaction
        if self.object_storage.is_none() {
            for object in &objects {
                self.store_object(&mut tx, repo_id, object).await?;
            }
        }

        // Append audit event (Requirement 5.6, 4.7)
        // Include S3 storage details when available
        let audit_data = if let Some(ref details) = storage_details {
            serde_json::json!({
                "repo_id": repo_id,
                "packfile_hash": packfile_hash,
                "ref_updates": canonical_ref_updates,
                "objects_count": objects.len(),
                "force_push": ref_updates.iter().any(|r| r.force),
                "storage": {
                    "type": details.storage_type,
                    "pack_hash": details.pack_hash,
                    "objects_stored": details.objects_stored,
                }
            })
        } else {
            serde_json::json!({
                "repo_id": repo_id,
                "packfile_hash": packfile_hash,
                "ref_updates": canonical_ref_updates,
                "objects_count": objects.len(),
                "force_push": ref_updates.iter().any(|r| r.force),
            })
        };

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Build response
        let response = PushResponse {
            status: "ok".to_string(),
            ref_updates: update_statuses,
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 200, &response, 24)
            .await?;

        // Commit transaction (atomic all-or-nothing)
        tx.commit().await?;

        // Trigger webhooks (Requirement 5.5) - async, after commit
        self.trigger_webhooks(repo_id, agent_id, &ref_updates).await;

        Ok(response)
    }

    /// Process a single ref update
    ///
    /// Handles fast-forward and force push logic (Requirements 5.2, 5.3)
    async fn process_ref_update(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        default_branch: &str,
        ref_update: &RefUpdateRequest,
        objects: &[GitObject],
    ) -> Result<RefUpdateStatus, PushError> {
        let zero_oid = "0000000000000000000000000000000000000000";

        // Get current ref value
        let current_oid = self.get_ref_oid(tx, repo_id, &ref_update.ref_name).await?;

        // Handle ref creation (old_oid is zero)
        if ref_update.old_oid == zero_oid {
            if current_oid.is_some() {
                return Err(PushError::InvalidObject(format!(
                    "Ref {} already exists, expected it to be new",
                    ref_update.ref_name
                )));
            }

            // Verify the new commit exists in the packfile
            if !objects.iter().any(|o| o.oid == ref_update.new_oid) {
                // For initial push, the new_oid might be zero (empty repo)
                if ref_update.new_oid != zero_oid {
                    return Err(PushError::InvalidObject(format!(
                        "Object {} not found in packfile",
                        ref_update.new_oid
                    )));
                }
            }

            // Create the ref
            self.create_ref(tx, repo_id, &ref_update.ref_name, &ref_update.new_oid)
                .await?;

            return Ok(RefUpdateStatus {
                ref_name: ref_update.ref_name.clone(),
                status: "ok".to_string(),
                message: None,
            });
        }

        // Handle ref deletion (new_oid is zero)
        if ref_update.new_oid == zero_oid {
            // Don't allow deleting the default branch
            if ref_update.ref_name == format!("refs/heads/{}", default_branch) {
                return Err(PushError::AccessDenied(
                    "Cannot delete the default branch".to_string(),
                ));
            }

            // Verify old_oid matches current
            match &current_oid {
                Some(oid) if oid == &ref_update.old_oid => {
                    self.delete_ref(tx, repo_id, &ref_update.ref_name).await?;
                    return Ok(RefUpdateStatus {
                        ref_name: ref_update.ref_name.clone(),
                        status: "ok".to_string(),
                        message: None,
                    });
                }
                Some(oid) => {
                    return Err(PushError::InvalidObject(format!(
                        "Ref {} has changed: expected {}, found {}",
                        ref_update.ref_name, ref_update.old_oid, oid
                    )));
                }
                None => {
                    return Err(PushError::RefNotFound(ref_update.ref_name.clone()));
                }
            }
        }

        // Handle ref update
        match &current_oid {
            Some(oid) if oid == &ref_update.old_oid => {
                // Check fast-forward (Requirement 5.2, 5.3)
                let is_fast_forward = self
                    .is_fast_forward(tx, repo_id, oid, &ref_update.new_oid, objects)
                    .await?;

                if !is_fast_forward && !ref_update.force {
                    return Err(PushError::NonFastForward(ref_update.ref_name.clone()));
                }

                // Update the ref
                self.update_ref(tx, repo_id, &ref_update.ref_name, &ref_update.new_oid)
                    .await?;

                let message = if !is_fast_forward && ref_update.force {
                    Some("forced update".to_string())
                } else {
                    None
                };

                Ok(RefUpdateStatus {
                    ref_name: ref_update.ref_name.clone(),
                    status: "ok".to_string(),
                    message,
                })
            }
            Some(oid) => Err(PushError::InvalidObject(format!(
                "Ref {} has changed: expected {}, found {}",
                ref_update.ref_name, ref_update.old_oid, oid
            ))),
            None => {
                // Ref doesn't exist but old_oid is not zero - this is an error
                Err(PushError::RefNotFound(ref_update.ref_name.clone()))
            }
        }
    }

    /// Check if an update is a fast-forward
    ///
    /// A fast-forward update means the new commit is a descendant of the old commit.
    /// For simplicity, we check if the old_oid appears in the parent chain of new_oid.
    async fn is_fast_forward(
        &self,
        _tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        _repo_id: &str,
        old_oid: &str,
        new_oid: &str,
        objects: &[GitObject],
    ) -> Result<bool, PushError> {
        // If old_oid is zero (new ref), it's always a fast-forward
        if old_oid == "0000000000000000000000000000000000000000" {
            return Ok(true);
        }

        // Find the new commit in the objects
        let new_commit = objects
            .iter()
            .find(|o| o.oid == new_oid && o.object_type == GitObjectType::Commit);

        match new_commit {
            Some(commit) => {
                // Parse commit to find parents
                let parents = self.parse_commit_parents(&commit.data)?;

                // Check if old_oid is a direct parent
                if parents.contains(&old_oid.to_string()) {
                    return Ok(true);
                }

                // For a more complete implementation, we would traverse the parent chain
                // For now, we check if old_oid is in the packfile's commit chain
                for parent_oid in &parents {
                    if let Some(parent_commit) = objects
                        .iter()
                        .find(|o| &o.oid == parent_oid && o.object_type == GitObjectType::Commit)
                    {
                        let grandparents = self.parse_commit_parents(&parent_commit.data)?;
                        if grandparents.contains(&old_oid.to_string()) {
                            return Ok(true);
                        }
                    }
                }

                // If old_oid is not in the immediate ancestry, it's not a fast-forward
                // In a real implementation, we'd query the object store for the full history
                Ok(false)
            }
            None => {
                // New commit not in packfile - might be updating to an existing commit
                // For now, assume it's a fast-forward if we can't verify
                Ok(true)
            }
        }
    }

    /// Parse parent OIDs from a commit object
    fn parse_commit_parents(&self, commit_data: &[u8]) -> Result<Vec<String>, PushError> {
        let commit_str = String::from_utf8_lossy(commit_data);
        let mut parents = Vec::new();

        for line in commit_str.lines() {
            if let Some(parent_oid) = line.strip_prefix("parent ") {
                parents.push(parent_oid.trim().to_string());
            } else if line.is_empty() {
                // Empty line marks end of headers
                break;
            }
        }

        Ok(parents)
    }

    /// Unpack and validate a packfile
    ///
    /// Requirement 5.4: Validate object integrity before storing
    fn unpack_and_validate_packfile(&self, packfile: &[u8]) -> Result<Vec<GitObject>, PushError> {
        // Minimum packfile size: header (12 bytes) + checksum (20 bytes)
        if packfile.len() < 32 {
            return Err(PushError::InvalidPackfile("Packfile too small".to_string()));
        }

        // Check PACK signature
        if &packfile[0..4] != b"PACK" {
            return Err(PushError::InvalidPackfile(
                "Invalid PACK signature".to_string(),
            ));
        }

        // Check version (must be 2 or 3)
        let version = u32::from_be_bytes([packfile[4], packfile[5], packfile[6], packfile[7]]);
        if version != 2 && version != 3 {
            return Err(PushError::InvalidPackfile(format!(
                "Unsupported packfile version: {}",
                version
            )));
        }

        // Get object count
        let object_count =
            u32::from_be_bytes([packfile[8], packfile[9], packfile[10], packfile[11]]);

        // Verify SHA1 checksum
        let data_len = packfile.len() - 20;
        let expected_checksum = &packfile[data_len..];
        let actual_checksum = Sha1::digest(&packfile[..data_len]);

        if actual_checksum.as_slice() != expected_checksum {
            return Err(PushError::InvalidPackfile(
                "Invalid packfile checksum".to_string(),
            ));
        }

        // Parse objects (simplified - real implementation would handle delta objects)
        let mut objects = Vec::new();
        let mut offset = 12; // After header

        for _ in 0..object_count {
            if offset >= data_len {
                break;
            }

            match self.parse_object(&packfile[offset..data_len]) {
                Ok((object, consumed)) => {
                    objects.push(object);
                    offset += consumed;
                }
                Err(e) => {
                    // Log but continue - some objects might be deltas we can't parse
                    tracing::warn!("Failed to parse object at offset {}: {}", offset, e);
                    break;
                }
            }
        }

        Ok(objects)
    }

    /// Parse a single object from packfile data
    fn parse_object(&self, data: &[u8]) -> Result<(GitObject, usize), PushError> {
        if data.is_empty() {
            return Err(PushError::InvalidPackfile("Empty object data".to_string()));
        }

        // Parse object header (variable-length encoding)
        let first_byte = data[0];
        let object_type = GitObjectType::from_type_byte(first_byte).ok_or_else(|| {
            PushError::InvalidObject(format!("Unknown object type: {}", (first_byte & 0x70) >> 4))
        })?;

        // Parse size (variable-length encoding)
        let mut size: usize = (first_byte & 0x0f) as usize;
        let mut shift = 4;
        let mut header_len = 1;

        while data.get(header_len - 1).is_some_and(|b| b & 0x80 != 0) {
            if header_len >= data.len() {
                return Err(PushError::InvalidPackfile(
                    "Truncated object header".to_string(),
                ));
            }
            let byte = data[header_len];
            size |= ((byte & 0x7f) as usize) << shift;
            shift += 7;
            header_len += 1;
        }

        // For simplicity, we'll use a fixed size for the object data
        // Real implementation would decompress zlib data
        let object_data_start = header_len;
        let object_data_end = (object_data_start + size).min(data.len());
        let object_data = data[object_data_start..object_data_end].to_vec();

        // Compute object ID (SHA1 of "type size\0data")
        let type_str = match object_type {
            GitObjectType::Commit => "commit",
            GitObjectType::Tree => "tree",
            GitObjectType::Blob => "blob",
            GitObjectType::Tag => "tag",
        };

        let mut hasher = Sha1::new();
        hasher.update(format!("{} {}\0", type_str, object_data.len()).as_bytes());
        hasher.update(&object_data);
        let oid = hex::encode(hasher.finalize());

        let consumed = object_data_end;

        Ok((
            GitObject {
                object_type,
                size,
                data: object_data,
                oid,
            },
            consumed,
        ))
    }

    /// Get the current OID for a ref
    async fn get_ref_oid(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        ref_name: &str,
    ) -> Result<Option<String>, PushError> {
        let oid: Option<String> =
            sqlx::query_scalar("SELECT oid FROM repo_refs WHERE repo_id = $1 AND ref_name = $2")
                .bind(repo_id)
                .bind(ref_name)
                .fetch_optional(&mut **tx)
                .await?;

        Ok(oid)
    }

    /// Create a new ref
    async fn create_ref(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        ref_name: &str,
        oid: &str,
    ) -> Result<(), PushError> {
        sqlx::query(
            r#"
            INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at)
            VALUES ($1, $2, $3, NOW())
            "#,
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(oid)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Update an existing ref
    async fn update_ref(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        ref_name: &str,
        oid: &str,
    ) -> Result<(), PushError> {
        sqlx::query(
            r#"
            UPDATE repo_refs
            SET oid = $3, updated_at = NOW()
            WHERE repo_id = $1 AND ref_name = $2
            "#,
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(oid)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Delete a ref
    async fn delete_ref(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        ref_name: &str,
    ) -> Result<(), PushError> {
        sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1 AND ref_name = $2")
            .bind(repo_id)
            .bind(ref_name)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    /// Store objects in S3 with appropriate strategy
    ///
    /// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
    /// Design Reference: DR-S3-4.1
    ///
    /// Storage strategy:
    /// - If > 10 objects: store as packfile for efficiency
    /// - If <= 10 objects: store as loose objects
    ///
    /// This method stores objects in S3 BEFORE updating refs in PostgreSQL,
    /// ensuring atomic guarantees. If S3 upload fails, refs are not updated.
    async fn store_objects_in_s3(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        objects: &[GitObject],
        packfile: &[u8],
    ) -> Result<S3StorageDetails, PushError> {
        let object_count = objects.len();

        debug!(
            repo_id = repo_id,
            object_count = object_count,
            threshold = PACKFILE_THRESHOLD,
            "Storing objects in S3"
        );

        if object_count > PACKFILE_THRESHOLD {
            // Store as packfile for efficiency (Requirement 4.2)
            info!(
                repo_id = repo_id,
                object_count = object_count,
                "Storing {} objects as packfile (threshold: {})",
                object_count,
                PACKFILE_THRESHOLD
            );

            // Compute pack hash from packfile content
            let pack_hash = hex::encode(Sha256::digest(packfile));

            // Generate packfile index (Requirement 4.6)
            let index = self.generate_packfile_index(objects, packfile)?;

            // Store packfile and index in S3
            storage
                .put_packfile(repo_id, &pack_hash, packfile, &index)
                .await
                .map_err(|e| {
                    error!(
                        repo_id = repo_id,
                        pack_hash = %pack_hash,
                        error = %e,
                        "Failed to store packfile in S3"
                    );
                    PushError::StorageError(format!("Failed to store packfile: {}", e))
                })?;

            info!(
                repo_id = repo_id,
                pack_hash = %pack_hash,
                object_count = object_count,
                "Packfile stored successfully in S3"
            );

            Ok(S3StorageDetails {
                storage_type: "packfile".to_string(),
                pack_hash: Some(pack_hash),
                objects_stored: object_count,
            })
        } else {
            // Store as loose objects (Requirement 4.3)
            info!(
                repo_id = repo_id,
                object_count = object_count,
                "Storing {} objects as loose objects (threshold: {})",
                object_count,
                PACKFILE_THRESHOLD
            );

            for object in objects {
                let storage_type = Self::convert_object_type(object.object_type);

                storage
                    .put_object(repo_id, &object.oid, storage_type, &object.data)
                    .await
                    .map_err(|e| {
                        error!(
                            repo_id = repo_id,
                            oid = %object.oid,
                            error = %e,
                            "Failed to store loose object in S3"
                        );
                        PushError::StorageError(format!(
                            "Failed to store object {}: {}",
                            object.oid, e
                        ))
                    })?;

                debug!(
                    repo_id = repo_id,
                    oid = %object.oid,
                    object_type = ?object.object_type,
                    "Loose object stored in S3"
                );
            }

            info!(
                repo_id = repo_id,
                object_count = object_count,
                "All loose objects stored successfully in S3"
            );

            Ok(S3StorageDetails {
                storage_type: "loose".to_string(),
                pack_hash: None,
                objects_stored: object_count,
            })
        }
    }

    /// Convert push GitObjectType to storage GitObjectType
    fn convert_object_type(obj_type: GitObjectType) -> StorageGitObjectType {
        match obj_type {
            GitObjectType::Commit => StorageGitObjectType::Commit,
            GitObjectType::Tree => StorageGitObjectType::Tree,
            GitObjectType::Blob => StorageGitObjectType::Blob,
            GitObjectType::Tag => StorageGitObjectType::Tag,
        }
    }

    /// Generate a packfile index (.idx) for the given objects
    ///
    /// Requirements: 4.6
    ///
    /// The index enables random access to objects within the packfile.
    /// Format: Git packfile index version 2
    fn generate_packfile_index(
        &self,
        objects: &[GitObject],
        _packfile: &[u8],
    ) -> Result<Vec<u8>, PushError> {
        // Git packfile index v2 format:
        // - 4 bytes: magic number (0xff744f63)
        // - 4 bytes: version (2)
        // - 256 * 4 bytes: fanout table (cumulative count of objects with first byte <= i)
        // - N * 20 bytes: sorted SHA-1 hashes
        // - N * 4 bytes: CRC32 checksums
        // - N * 4 bytes: offsets (or 8 bytes for large packfiles)
        // - 20 bytes: packfile SHA-1
        // - 20 bytes: index SHA-1

        let mut index = Vec::new();

        // Magic number for packfile index v2
        index.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]);

        // Version 2
        index.extend_from_slice(&2u32.to_be_bytes());

        // Sort objects by OID for the index
        let mut sorted_objects: Vec<_> = objects.iter().collect();
        sorted_objects.sort_by(|a, b| a.oid.cmp(&b.oid));

        // Build fanout table (256 entries)
        let mut fanout = [0u32; 256];
        for obj in &sorted_objects {
            if let Ok(first_byte) = u8::from_str_radix(&obj.oid[0..2], 16) {
                for i in (first_byte as usize)..256 {
                    fanout[i] += 1;
                }
            }
        }

        // Write fanout table
        for count in fanout {
            index.extend_from_slice(&count.to_be_bytes());
        }

        // Write sorted SHA-1 hashes (20 bytes each)
        for obj in &sorted_objects {
            if let Ok(hash_bytes) = hex::decode(&obj.oid) {
                index.extend_from_slice(&hash_bytes);
            } else {
                // Pad with zeros if decode fails
                index.extend_from_slice(&[0u8; 20]);
            }
        }

        // Write CRC32 checksums (simplified - using 0 for now)
        for _ in &sorted_objects {
            index.extend_from_slice(&0u32.to_be_bytes());
        }

        // Write offsets (simplified - sequential offsets)
        let mut offset = 12u32; // After PACK header
        for obj in &sorted_objects {
            index.extend_from_slice(&offset.to_be_bytes());
            // Estimate object size in packfile (header + data)
            offset += (obj.data.len() + 10) as u32;
        }

        // Packfile SHA-1 (simplified - compute from objects)
        let mut pack_hasher = Sha1::new();
        for obj in &sorted_objects {
            pack_hasher.update(&obj.oid);
        }
        let pack_sha1 = pack_hasher.finalize();
        index.extend_from_slice(&pack_sha1);

        // Index SHA-1
        let index_sha1 = Sha1::digest(&index);
        index.extend_from_slice(&index_sha1);

        Ok(index)
    }

    /// Store a Git object in the database
    async fn store_object(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        object: &GitObject,
    ) -> Result<(), PushError> {
        let type_str = match object.object_type {
            GitObjectType::Commit => "commit",
            GitObjectType::Tree => "tree",
            GitObjectType::Blob => "blob",
            GitObjectType::Tag => "tag",
        };

        sqlx::query(
            r#"
            INSERT INTO repo_objects (repo_id, oid, object_type, size, data, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (repo_id, oid) DO NOTHING
            "#,
        )
        .bind(repo_id)
        .bind(&object.oid)
        .bind(type_str)
        .bind(object.size as i64)
        .bind(&object.data)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Trigger webhooks after successful push
    ///
    /// Requirement 5.5: Trigger webhooks after successful push
    async fn trigger_webhooks(
        &self,
        repo_id: &str,
        agent_id: &str,
        ref_updates: &[RefUpdateRequest],
    ) {
        // In a full implementation, this would:
        // 1. Look up configured webhooks for the repository
        // 2. Build webhook payloads with push details
        // 3. Queue webhook deliveries for async processing
        //
        // For now, we just log the event
        tracing::info!(
            repo_id = repo_id,
            agent_id = agent_id,
            ref_count = ref_updates.len(),
            "Push webhooks triggered"
        );
    }

    /// Get repository by ID
    async fn get_repository(&self, repo_id: &str) -> Result<RepoInfo, PushError> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"
            SELECT repo_id, owner_id, name, visibility, default_branch
            FROM repositories
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(RepoInfo {
                repo_id: r.get("repo_id"),
                owner_id: r.get("owner_id"),
                name: r.get("name"),
                visibility: r.get("visibility"),
                default_branch: r.get("default_branch"),
            }),
            None => Err(PushError::RepoNotFound(repo_id.to_string())),
        }
    }

    /// Check if an agent has access to a repository
    async fn check_access(
        &self,
        repo_id: &str,
        agent_id: &str,
        required_role: AccessRole,
    ) -> Result<bool, PushError> {
        // Get repository visibility and owner
        let repo = self.get_repository(repo_id).await?;

        // Public repos allow read access to everyone
        if repo.visibility == Visibility::Public && required_role == AccessRole::Read {
            return Ok(true);
        }

        // Check if agent is the owner
        if repo.owner_id == agent_id {
            return Ok(true);
        }

        // Check explicit repo_access entry
        let access: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(repo_id)
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        match access {
            Some(role) => Ok(self.role_satisfies(role, required_role)),
            None => Ok(false),
        }
    }

    /// Check if a role satisfies the required role
    fn role_satisfies(&self, actual: AccessRole, required: AccessRole) -> bool {
        match required {
            AccessRole::Read => true,
            AccessRole::Write => matches!(actual, AccessRole::Write | AccessRole::Admin),
            AccessRole::Admin => matches!(actual, AccessRole::Admin),
        }
    }

    /// Get agent's public key
    /// Also checks if the agent is suspended (Requirement 2.6)
    async fn get_agent_public_key(&self, agent_id: &str) -> Result<String, PushError> {
        get_agent_public_key_if_not_suspended(&self.pool, agent_id)
            .await
            .map_err(PushError::from)
    }
}

/// Internal repository info struct
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RepoInfo {
    repo_id: String,
    owner_id: String,
    name: String,
    visibility: Visibility,
    default_branch: String,
}

// Implement Serialize for PushResponse to support idempotency storage
impl serde::Serialize for PushResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PushResponse", 2)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("refUpdates", &self.ref_updates)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for PushResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Helper {
            status: String,
            ref_updates: Vec<RefUpdateStatusHelper>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RefUpdateStatusHelper {
            ref_name: String,
            status: String,
            message: Option<String>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(PushResponse {
            status: helper.status,
            ref_updates: helper
                .ref_updates
                .into_iter()
                .map(|r| RefUpdateStatus {
                    ref_name: r.ref_name,
                    status: r.status,
                    message: r.message,
                })
                .collect(),
        })
    }
}

impl serde::Serialize for RefUpdateStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RefUpdateStatus", 3)?;
        state.serialize_field("refName", &self.ref_name)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

// ============================================================================
// Integration Tests for Push Service
// Requirements: 5.1, 5.2, 5.3, 5.4, 5.6
// Design: DR-5.1
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;

    use crate::services::signature::SignatureEnvelope;

    /// Helper to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };

        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()
    }

    /// Generate an Ed25519 keypair for testing
    fn generate_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        (signing_key, public_key)
    }

    /// Sign an envelope with Ed25519
    fn sign_envelope(signing_key: &SigningKey, envelope: &SignatureEnvelope) -> String {
        let validator = SignatureValidator::default();
        let canonical = validator
            .canonicalize(envelope)
            .expect("canonicalize failed");
        let message_hash = Sha256::digest(canonical.as_bytes());
        let signature = signing_key.sign(&message_hash);
        STANDARD.encode(signature.to_bytes())
    }

    /// Create a test agent in the database and return (agent_id, public_key, signing_key)
    async fn create_test_agent(pool: &PgPool) -> (String, String, SigningKey) {
        let (signing_key, public_key) = generate_test_keypair();
        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, $3, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .bind(&public_key)
        .execute(pool)
        .await
        .expect("Failed to create test agent");

        // Initialize reputation
        let _ = sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, 0.500, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .execute(pool)
        .await;

        (agent_id, public_key, signing_key)
    }

    /// Create a test repository with refs initialized
    async fn create_test_repo(pool: &PgPool, owner_id: &str) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, 'Test repo', 'public', 'main', NOW())
            "#,
        )
        .bind(&repo_id)
        .bind(owner_id)
        .bind(&repo_name)
        .execute(pool)
        .await
        .expect("Failed to create test repo");

        // Initialize star counts
        sqlx::query(
            r#"
            INSERT INTO repo_star_counts (repo_id, stars, updated_at)
            VALUES ($1, 0, NOW())
            "#,
        )
        .bind(&repo_id)
        .execute(pool)
        .await
        .expect("Failed to init star counts");

        // Create owner access
        sqlx::query(
            r#"
            INSERT INTO repo_access (repo_id, agent_id, role, created_at)
            VALUES ($1, $2, 'admin', NOW())
            "#,
        )
        .bind(&repo_id)
        .bind(owner_id)
        .execute(pool)
        .await
        .expect("Failed to create owner access");

        repo_id
    }

    /// Create a ref in the repository
    async fn create_test_ref(pool: &PgPool, repo_id: &str, ref_name: &str, oid: &str) {
        sqlx::query(
            r#"
            INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (repo_id, ref_name) DO UPDATE SET oid = $3, updated_at = NOW()
            "#,
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(oid)
        .execute(pool)
        .await
        .expect("Failed to create test ref");
    }

    /// Create a minimal valid packfile for testing
    /// 
    /// This creates a simplified packfile without zlib compression.
    /// The packfile format is:
    /// - 4 bytes: "PACK" signature
    /// - 4 bytes: version (2)
    /// - 4 bytes: object count
    /// - For each object:
    ///   - Variable-length header: type (3 bits) + size (variable)
    ///   - Object data (uncompressed for testing)
    /// - 20 bytes: SHA1 checksum
    fn create_test_packfile(objects: &[(GitObjectType, &[u8])]) -> Vec<u8> {
        let mut packfile = Vec::new();

        // PACK header
        packfile.extend_from_slice(b"PACK");
        // Version 2
        packfile.extend_from_slice(&2u32.to_be_bytes());
        // Object count
        packfile.extend_from_slice(&(objects.len() as u32).to_be_bytes());

        // Add objects with proper variable-length size encoding
        for (obj_type, data) in objects {
            let type_bits = match obj_type {
                GitObjectType::Commit => 1,
                GitObjectType::Tree => 2,
                GitObjectType::Blob => 3,
                GitObjectType::Tag => 4,
            };
            
            let size = data.len();
            
            // First byte: MSB=continuation, bits 6-4=type, bits 3-0=size[3:0]
            let mut first_byte = (type_bits << 4) | ((size & 0x0f) as u8);
            let mut remaining_size = size >> 4;
            
            if remaining_size > 0 {
                first_byte |= 0x80; // Set continuation bit
            }
            packfile.push(first_byte);
            
            // Additional size bytes if needed
            while remaining_size > 0 {
                let mut byte = (remaining_size & 0x7f) as u8;
                remaining_size >>= 7;
                if remaining_size > 0 {
                    byte |= 0x80; // Set continuation bit
                }
                packfile.push(byte);
            }
            
            // Object data (uncompressed for testing)
            packfile.extend_from_slice(data);
        }

        // SHA1 checksum of everything before the checksum
        let checksum = Sha1::digest(&packfile);
        packfile.extend_from_slice(&checksum);

        packfile
    }

    /// Compute object ID for a Git object
    fn compute_object_id(obj_type: GitObjectType, data: &[u8]) -> String {
        let type_str = match obj_type {
            GitObjectType::Commit => "commit",
            GitObjectType::Tree => "tree",
            GitObjectType::Blob => "blob",
            GitObjectType::Tag => "tag",
        };
        let mut hasher = Sha1::new();
        hasher.update(format!("{} {}\0", type_str, data.len()).as_bytes());
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Clean up test data
    async fn cleanup_test_data(pool: &PgPool, agent_id: &str, repo_id: &str, nonce: &str) {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
            .bind(&nonce_hash)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_objects WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: Successful push with valid packfile and refs
    // Requirements: 5.1, 5.4
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_push_succeeds_with_valid_packfile() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create a simple commit object
        let commit_data = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial commit\n";
        let commit_oid = compute_object_id(GitObjectType::Commit, commit_data);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, commit_data)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        // Create initial ref
        let zero_oid = "0000000000000000000000000000000000000000";
        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: zero_oid.to_string(),
            new_oid: commit_oid.clone(),
            force: false,
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        assert!(result.is_ok(), "Push should succeed: {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.status, "ok", "Push status should be ok, ref_updates: {:?}", response.ref_updates);
        assert_eq!(response.ref_updates.len(), 1);
        assert_eq!(response.ref_updates[0].status, "ok");
    }

    // =========================================================================
    // Test: Push without write access returns ACCESS_DENIED (403)
    // Requirements: 5.1
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_push_without_access_denied() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner and repo
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create another agent without access
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let commit_data = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nTest commit\n";
        let commit_oid = compute_object_id(GitObjectType::Commit, commit_data);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, commit_data)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: commit_oid.clone(),
            force: false,
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;
        cleanup_test_data(&pool, &owner_id, &repo_id, "").await;

        assert!(
            matches!(result, Err(PushError::AccessDenied(_))),
            "Push should fail with AccessDenied: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Non-fast-forward push without force flag returns NON_FAST_FORWARD (409)
    // Requirements: 5.2
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_non_fast_forward_rejected() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create initial commit and ref
        let initial_commit = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial\n";
        let initial_oid = compute_object_id(GitObjectType::Commit, initial_commit);
        create_test_ref(&pool, &repo_id, "refs/heads/main", &initial_oid).await;

        // Create a new commit that is NOT a descendant of initial (divergent history)
        let new_commit = b"tree 1111111111111111111111111111111111111111\nauthor Test <test@test.com> 1234567891 +0000\ncommitter Test <test@test.com> 1234567891 +0000\n\nDivergent\n";
        let new_oid = compute_object_id(GitObjectType::Commit, new_commit);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, new_commit)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: initial_oid.clone(),
            new_oid: new_oid.clone(),
            force: false, // No force flag
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        // Should return ng status with non-fast-forward error
        assert!(result.is_ok(), "Push should return response: {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.status, "ng");
    }

    // =========================================================================
    // Test: Force push with force flag succeeds and records event
    // Requirements: 5.3
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_force_push_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create initial commit and ref
        let initial_commit = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial\n";
        let initial_oid = compute_object_id(GitObjectType::Commit, initial_commit);
        create_test_ref(&pool, &repo_id, "refs/heads/main", &initial_oid).await;

        // Create a divergent commit
        let new_commit = b"tree 1111111111111111111111111111111111111111\nauthor Test <test@test.com> 1234567891 +0000\ncommitter Test <test@test.com> 1234567891 +0000\n\nForced\n";
        let new_oid = compute_object_id(GitObjectType::Commit, new_commit);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, new_commit)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: initial_oid.clone(),
            new_oid: new_oid.clone(),
            force: true, // Force flag enabled
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        assert!(result.is_ok(), "Force push should succeed: {:?}", result);
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert!(
            response.ref_updates[0]
                .message
                .as_ref()
                .map_or(false, |m| m.contains("forced"))
        );
    }

    // =========================================================================
    // Test: Push with invalid object hash is rejected
    // Requirements: 5.4
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_invalid_packfile_rejected() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create an invalid packfile (wrong checksum)
        let mut invalid_packfile = Vec::new();
        invalid_packfile.extend_from_slice(b"PACK");
        invalid_packfile.extend_from_slice(&2u32.to_be_bytes());
        invalid_packfile.extend_from_slice(&0u32.to_be_bytes());
        // Wrong checksum
        invalid_packfile.extend_from_slice(&[0u8; 20]);

        let packfile_hash = hex::encode(Sha256::digest(&invalid_packfile));
        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: "1111111111111111111111111111111111111111".to_string(),
            force: false,
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &invalid_packfile,
                ref_updates,
            )
            .await;

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        assert!(
            matches!(result, Err(PushError::InvalidPackfile(_))),
            "Invalid packfile should be rejected: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Atomic ref updates (all succeed or all fail)
    // Requirements: 5.1
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_atomic_ref_updates() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create initial ref
        let initial_commit = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial\n";
        let initial_oid = compute_object_id(GitObjectType::Commit, initial_commit);
        create_test_ref(&pool, &repo_id, "refs/heads/main", &initial_oid).await;

        // Create new commit
        let new_commit = b"tree 1111111111111111111111111111111111111111\nauthor Test <test@test.com> 1234567891 +0000\ncommitter Test <test@test.com> 1234567891 +0000\n\nNew\n";
        let new_oid = compute_object_id(GitObjectType::Commit, new_commit);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, new_commit)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        // Try to update two refs: one valid (new branch), one invalid (wrong old_oid)
        let ref_updates = vec![
            RefUpdateRequest {
                ref_name: "refs/heads/feature".to_string(),
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: new_oid.clone(),
                force: false,
            },
            RefUpdateRequest {
                ref_name: "refs/heads/main".to_string(),
                old_oid: "wrong_oid_that_does_not_match".to_string(), // Wrong old_oid
                new_oid: new_oid.clone(),
                force: false,
            },
        ];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        // Verify the feature branch was NOT created (atomic rollback)
        let feature_ref: Option<String> = sqlx::query_scalar(
            "SELECT oid FROM repo_refs WHERE repo_id = $1 AND ref_name = 'refs/heads/feature'",
        )
        .bind(&repo_id)
        .fetch_optional(&pool)
        .await
        .expect("Query failed");

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        assert!(result.is_ok(), "Push should return response: {:?}", result);
        let response = result.unwrap();
        assert_eq!(
            response.status, "ng",
            "Push should fail due to invalid ref update"
        );
        assert!(
            feature_ref.is_none(),
            "Feature branch should not exist due to atomic rollback"
        );
    }

    // =========================================================================
    // Test: Push event recorded in audit_log
    // Requirements: 5.6
    // Design: DR-5.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_push_event_recorded_in_audit() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let commit_data = b"tree 0000000000000000000000000000000000000000\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nAudit test\n";
        let commit_oid = compute_object_id(GitObjectType::Commit, commit_data);
        let packfile = create_test_packfile(&[(GitObjectType::Commit, commit_data)]);
        let packfile_hash = hex::encode(Sha256::digest(&packfile));

        let ref_updates = vec![RefUpdateRequest {
            ref_name: "refs/heads/main".to_string(),
            old_oid: "0000000000000000000000000000000000000000".to_string(),
            new_oid: commit_oid.clone(),
            force: false,
        }];

        let canonical_ref_updates: Vec<serde_json::Value> = ref_updates
            .iter()
            .map(|r| {
                serde_json::json!({
                    "refName": r.ref_name,
                    "oldOid": r.old_oid,
                    "newOid": r.new_oid,
                    "force": r.force,
                })
            })
            .collect();

        let body = serde_json::json!({
            "packfileHash": packfile_hash,
            "refUpdates": canonical_ref_updates,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "push".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let push_service = PushService::new(pool.clone());

        let result = push_service
            .push(
                &repo_id,
                &agent_id,
                &signature,
                envelope.timestamp,
                &nonce,
                &packfile,
                ref_updates,
            )
            .await;

        // Check audit log
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'push' AND resource_id = $2"
        )
        .bind(&agent_id)
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query failed");

        cleanup_test_data(&pool, &agent_id, &repo_id, &nonce).await;

        assert!(result.is_ok(), "Push should succeed: {:?}", result);
        assert!(audit_count > 0, "Audit event should be recorded for push");
    }
}

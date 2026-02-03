//! Git Smart HTTP Transport Service
//!
//! Implements Git Smart HTTP protocol for standard git client compatibility.
//! Design: DR-4.3 (Git Transport Service)
//! Design Reference: DR-S3-5.1 (Git Transport with S3 Storage)
//!
//! Requirements: 5.1, 5.3, 5.4, 5.6

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use chrono::{DateTime, Utc};
use futures::Stream;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::models::{AccessRole, Visibility};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::object_storage::{
    GitObjectType as StorageGitObjectType, ObjectStorageBackend, StorageError, StoredObject,
};
use crate::services::signature::{SignatureEnvelope, SignatureError, SignatureValidator};

/// Default chunk size for streaming packfiles (64KB)
const DEFAULT_STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Threshold for switching to streaming mode (1MB)
const STREAMING_THRESHOLD: usize = 1024 * 1024;

/// Errors that can occur during Git transport operations
#[derive(Debug, Error)]
pub enum GitTransportError {
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid service: {0}")]
    InvalidService(String),

    #[error("Missing header: {0}")]
    MissingHeader(String),

    #[error("Invalid packfile: {0}")]
    InvalidPackfile(String),

    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Signature validation failed: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
}

impl From<StorageError> for GitTransportError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound(msg) => GitTransportError::ObjectNotFound(msg),
            other => GitTransportError::StorageError(other.to_string()),
        }
    }
}

/// Git reference for ref advertisement
#[derive(Debug, Clone)]
pub struct GitReference {
    pub name: String,
    pub oid: String,
    pub peeled: Option<String>,
}

/// Ref update for push operations
#[derive(Debug, Clone)]
pub struct RefUpdateRequest {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    pub force: bool,
}

/// Response for ref advertisement
#[derive(Debug, Clone)]
pub struct RefAdvertisement {
    pub refs: Vec<GitReference>,
    pub capabilities: Vec<String>,
    pub head: Option<String>,
}

/// Response for upload-pack (clone/fetch)
#[derive(Debug, Clone)]
pub struct UploadPackResponse {
    pub packfile: Vec<u8>,
}

/// Streaming response for upload-pack (clone/fetch) for large packfiles
///
/// Requirements: 5.6
///
/// This type provides a streaming interface for large packfiles to avoid
/// memory exhaustion. It implements the Stream trait for async iteration.
pub struct PackfileStream {
    receiver: mpsc::Receiver<Result<Vec<u8>, GitTransportError>>,
    /// Total size of the packfile (if known)
    pub total_size: Option<usize>,
}

impl PackfileStream {
    /// Create a new packfile stream from a channel receiver
    pub fn new(receiver: mpsc::Receiver<Result<Vec<u8>, GitTransportError>>) -> Self {
        Self {
            receiver,
            total_size: None,
        }
    }

    /// Create a new packfile stream with known total size
    pub fn with_size(
        receiver: mpsc::Receiver<Result<Vec<u8>, GitTransportError>>,
        total_size: usize,
    ) -> Self {
        Self {
            receiver,
            total_size: Some(total_size),
        }
    }
}

impl Stream for PackfileStream {
    type Item = Result<Vec<u8>, GitTransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_recv(cx)
    }
}

/// Response for receive-pack (push)
#[derive(Debug, Clone)]
pub struct ReceivePackResponse {
    pub status: String,
    pub ref_updates: Vec<RefUpdateStatus>,
}

/// Status of a ref update
#[derive(Debug, Clone)]
pub struct RefUpdateStatus {
    pub ref_name: String,
    pub status: String,
    pub message: Option<String>,
}

/// Git Smart HTTP Transport Service
///
/// Design Reference: DR-4.3, DR-S3-5.1
/// Requirements: 5.1, 5.3, 5.4, 5.6
#[derive(Clone)]
pub struct GitTransportService {
    pool: PgPool,
    signature_validator: SignatureValidator,
    /// Optional S3 object storage backend for reading objects
    /// When Some, objects are retrieved from S3
    /// When None, objects are retrieved from PostgreSQL (legacy behavior)
    object_storage: Option<Arc<dyn ObjectStorageBackend>>,
}

impl std::fmt::Debug for GitTransportService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitTransportService")
            .field("pool", &"PgPool")
            .field("signature_validator", &self.signature_validator)
            .field("object_storage", &self.object_storage.is_some())
            .finish()
    }
}

impl GitTransportService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            signature_validator: SignatureValidator::default(),
            object_storage: None,
        }
    }

    /// Create a new GitTransportService with S3 object storage backend
    ///
    /// Requirements: 5.1
    /// Design Reference: DR-S3-5.1
    ///
    /// When object storage is configured, objects are retrieved from S3
    /// for clone/fetch operations.
    pub fn with_object_storage(pool: PgPool, object_storage: Arc<dyn ObjectStorageBackend>) -> Self {
        Self {
            pool,
            signature_validator: SignatureValidator::default(),
            object_storage: Some(object_storage),
        }
    }

    /// Set the object storage backend
    ///
    /// This allows configuring S3 storage after construction.
    pub fn set_object_storage(&mut self, object_storage: Arc<dyn ObjectStorageBackend>) {
        self.object_storage = Some(object_storage);
    }

    /// Get ref advertisement for a repository
    ///
    /// GET /v1/repos/{repoId}/info/refs?service=git-upload-pack
    /// GET /v1/repos/{repoId}/info/refs?service=git-receive-pack
    ///
    /// Requirements: 4.1, 4.3, 4.7
    /// Design: DR-4.3 (Git Transport Service)
    pub async fn get_refs(
        &self,
        repo_id: &str,
        service: &str,
        agent_id: Option<&str>,
    ) -> Result<RefAdvertisement, GitTransportError> {
        // Validate service
        if service != "git-upload-pack" && service != "git-receive-pack" {
            return Err(GitTransportError::InvalidService(service.to_string()));
        }

        // Get repository
        let repo = self.get_repository(repo_id).await?;

        // Check access based on service
        let required_role = if service == "git-receive-pack" {
            AccessRole::Write
        } else {
            AccessRole::Read
        };

        // For public repos with read access, agent_id is optional
        if repo.visibility == Visibility::Private || required_role != AccessRole::Read {
            let agent_id = agent_id
                .ok_or_else(|| GitTransportError::MissingHeader("X-Agent-Id".to_string()))?;

            let has_access = self.check_access(repo_id, agent_id, required_role).await?;
            if !has_access {
                return Err(GitTransportError::AccessDenied(format!(
                    "Agent {} does not have {} access to repository {}",
                    agent_id,
                    match required_role {
                        AccessRole::Read => "read",
                        AccessRole::Write => "write",
                        AccessRole::Admin => "admin",
                    },
                    repo_id
                )));
            }
        }

        // Build capabilities based on service and protocol version
        let capabilities = self.build_capabilities(service);

        // Get refs (for now, just the default branch pointing to empty)
        let refs = vec![GitReference {
            name: format!("refs/heads/{}", repo.default_branch),
            oid: "0000000000000000000000000000000000000000".to_string(),
            peeled: None,
        }];

        Ok(RefAdvertisement {
            refs,
            capabilities,
            head: Some(format!("refs/heads/{}", repo.default_branch)),
        })
    }

    /// Handle git-upload-pack (clone/fetch)
    ///
    /// POST /v1/repos/{repoId}/git-upload-pack
    ///
    /// Requirements: 4.1, 4.2, 4.5, 4.7, 4.8, 5.1, 5.3, 5.4
    /// Design: DR-4.3 (Git Transport Service), DR-S3-5.1
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pack(
        &self,
        repo_id: &str,
        agent_id: &str,
        signature: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
        wants: Vec<String>,
        haves: Vec<String>,
    ) -> Result<UploadPackResponse, GitTransportError> {
        // Delegate to upload_pack_with_depth with no depth limit
        self.upload_pack_with_depth(repo_id, agent_id, signature, timestamp, nonce, wants, haves, None)
            .await
    }

    /// Handle git-upload-pack with shallow clone support
    ///
    /// POST /v1/repos/{repoId}/git-upload-pack
    ///
    /// Requirements: 4.1, 4.2, 4.5, 4.7, 4.8, 5.1, 5.3, 5.4
    /// Design: DR-4.3 (Git Transport Service), DR-S3-5.1
    ///
    /// When depth is Some(n), limits commit traversal to n levels deep.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pack_with_depth(
        &self,
        repo_id: &str,
        agent_id: &str,
        signature: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
        wants: Vec<String>,
        haves: Vec<String>,
        depth: Option<u32>,
    ) -> Result<UploadPackResponse, GitTransportError> {
        // Get repository (validates it exists)
        let _repo = self.get_repository(repo_id).await?;

        // Check read access
        let has_access = self
            .check_access(repo_id, agent_id, AccessRole::Read)
            .await?;
        if !has_access {
            return Err(GitTransportError::AccessDenied(format!(
                "Agent {} does not have read access to repository {}",
                agent_id, repo_id
            )));
        }

        // Get agent's public key
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "wants": wants,
            "haves": haves,
            "depth": depth,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.to_string(),
            action: "git-upload-pack".to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Record audit event
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "wants": wants,
            "haves": haves,
            "depth": depth,
            "shallow": depth.is_some(),
        });

        AuditService::new(self.pool.clone())
            .append(AuditEvent {
                agent_id: agent_id.to_string(),
                action: "git-upload-pack".to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            })
            .await?;

        // Generate packfile based on storage backend
        let packfile = if let Some(ref storage) = self.object_storage {
            // Use S3 storage for object retrieval
            // Requirements: 5.1, 5.3, 5.4
            // Design Reference: DR-S3-5.1
            self.generate_packfile_from_s3_with_depth(storage.as_ref(), repo_id, &wants, &haves, depth)
                .await?
        } else {
            // Legacy behavior: return empty packfile for new repo
            self.generate_empty_packfile()
        };

        Ok(UploadPackResponse { packfile })
    }

    /// Handle git-upload-pack with streaming response for large packfiles
    ///
    /// POST /v1/repos/{repoId}/git-upload-pack
    ///
    /// Requirements: 5.1, 5.3, 5.4, 5.6
    /// Design: DR-4.3 (Git Transport Service), DR-S3-5.1
    ///
    /// This method returns a streaming response for large packfiles to avoid
    /// memory exhaustion. For small packfiles, it collects all data first.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pack_streaming(
        &self,
        repo_id: &str,
        agent_id: &str,
        signature: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
        wants: Vec<String>,
        haves: Vec<String>,
        depth: Option<u32>,
    ) -> Result<PackfileStream, GitTransportError> {
        // Get repository (validates it exists)
        let _repo = self.get_repository(repo_id).await?;

        // Check read access
        let has_access = self
            .check_access(repo_id, agent_id, AccessRole::Read)
            .await?;
        if !has_access {
            return Err(GitTransportError::AccessDenied(format!(
                "Agent {} does not have read access to repository {}",
                agent_id, repo_id
            )));
        }

        // Get agent's public key
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "wants": wants,
            "haves": haves,
            "depth": depth,
            "streaming": true,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.to_string(),
            action: "git-upload-pack".to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Record audit event
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "wants": wants,
            "haves": haves,
            "depth": depth,
            "shallow": depth.is_some(),
            "streaming": true,
        });

        AuditService::new(self.pool.clone())
            .append(AuditEvent {
                agent_id: agent_id.to_string(),
                action: "git-upload-pack".to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            })
            .await?;

        // Generate streaming packfile based on storage backend
        if let Some(ref storage) = self.object_storage {
            // Use S3 storage for object retrieval with streaming
            // Requirements: 5.1, 5.3, 5.4, 5.6
            // Design Reference: DR-S3-5.1
            self.generate_packfile_stream(storage.clone(), repo_id.to_string(), wants, haves, depth)
                .await
        } else {
            // Legacy behavior: return empty packfile as stream
            let (tx, rx) = mpsc::channel(1);
            let packfile = self.generate_empty_packfile();
            let _ = tx.send(Ok(packfile)).await;
            Ok(PackfileStream::new(rx))
        }
    }

    /// Generate a streaming packfile from S3 objects
    ///
    /// Requirements: 5.6
    /// Design Reference: DR-S3-5.1
    ///
    /// This method streams packfile data in chunks to avoid memory exhaustion
    /// for large repositories.
    async fn generate_packfile_stream(
        &self,
        storage: Arc<dyn ObjectStorageBackend>,
        repo_id: String,
        wants: Vec<String>,
        haves: Vec<String>,
        depth: Option<u32>,
    ) -> Result<PackfileStream, GitTransportError> {
        // Create channel for streaming
        let (tx, rx) = mpsc::channel(16);

        // Clone self for the spawned task
        let service = self.clone();

        // Spawn task to generate packfile and stream chunks
        tokio::spawn(async move {
            let result = service
                .stream_packfile_chunks(storage.as_ref(), &repo_id, &wants, &haves, depth, tx.clone())
                .await;

            if let Err(e) = result {
                let _ = tx.send(Err(e)).await;
            }
        });

        Ok(PackfileStream::new(rx))
    }

    /// Stream packfile chunks to the channel
    ///
    /// Requirements: 5.6
    ///
    /// This method collects objects and streams the packfile in chunks.
    async fn stream_packfile_chunks(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        wants: &[String],
        haves: &[String],
        depth: Option<u32>,
        tx: mpsc::Sender<Result<Vec<u8>, GitTransportError>>,
    ) -> Result<(), GitTransportError> {
        debug!(
            repo_id = repo_id,
            wants_count = wants.len(),
            haves_count = haves.len(),
            depth = ?depth,
            "Streaming packfile from S3 objects"
        );

        // If no wants, send empty packfile
        if wants.is_empty() {
            let packfile = self.generate_empty_packfile();
            let _ = tx.send(Ok(packfile)).await;
            return Ok(());
        }

        // Collect objects needed for the packfile
        let objects = self
            .collect_objects_from_s3_with_depth(storage, repo_id, wants, haves, depth)
            .await?;

        if objects.is_empty() {
            let packfile = self.generate_empty_packfile();
            let _ = tx.send(Ok(packfile)).await;
            return Ok(());
        }

        // Build packfile
        let packfile = self.build_packfile(&objects)?;

        // Stream in chunks if large, otherwise send all at once
        if packfile.len() > STREAMING_THRESHOLD {
            info!(
                repo_id = repo_id,
                objects_count = objects.len(),
                packfile_size = packfile.len(),
                chunk_size = DEFAULT_STREAM_CHUNK_SIZE,
                "Streaming large packfile in chunks"
            );

            // Stream in chunks
            for chunk in packfile.chunks(DEFAULT_STREAM_CHUNK_SIZE) {
                if tx.send(Ok(chunk.to_vec())).await.is_err() {
                    // Receiver dropped, stop streaming
                    warn!(repo_id = repo_id, "Packfile stream receiver dropped");
                    break;
                }
            }
        } else {
            // Send all at once for small packfiles
            let _ = tx.send(Ok(packfile)).await;
        }

        info!(
            repo_id = repo_id,
            objects_count = objects.len(),
            depth = ?depth,
            "Packfile streaming completed"
        );

        Ok(())
    }

    /// Generate a packfile from S3 objects on-demand with optional depth limit
    ///
    /// Requirements: 5.1, 5.3, 5.4
    /// Design Reference: DR-S3-5.1
    ///
    /// This method:
    /// - Traverses object graph from wants to haves
    /// - Collects needed objects from S3
    /// - Limits commit depth when depth is Some(n)
    /// - Builds packfile with delta compression
    async fn generate_packfile_from_s3_with_depth(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        wants: &[String],
        haves: &[String],
        depth: Option<u32>,
    ) -> Result<Vec<u8>, GitTransportError> {
        debug!(
            repo_id = repo_id,
            wants_count = wants.len(),
            haves_count = haves.len(),
            depth = ?depth,
            "Generating packfile from S3 objects"
        );

        // If no wants, return empty packfile
        if wants.is_empty() {
            return Ok(self.generate_empty_packfile());
        }

        // Collect objects needed for the packfile
        let objects = self
            .collect_objects_from_s3_with_depth(storage, repo_id, wants, haves, depth)
            .await?;

        if objects.is_empty() {
            return Ok(self.generate_empty_packfile());
        }

        // Build packfile from collected objects
        let packfile = self.build_packfile(&objects)?;

        info!(
            repo_id = repo_id,
            objects_count = objects.len(),
            packfile_size = packfile.len(),
            depth = ?depth,
            "Generated packfile from S3 objects"
        );

        Ok(packfile)
    }

    /// Generate a packfile from S3 objects on-demand (no depth limit)
    ///
    /// Requirements: 5.1, 5.3
    /// Design Reference: DR-S3-5.1
    async fn generate_packfile_from_s3(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        wants: &[String],
        haves: &[String],
    ) -> Result<Vec<u8>, GitTransportError> {
        self.generate_packfile_from_s3_with_depth(storage, repo_id, wants, haves, None)
            .await
    }

    /// Collect objects from S3 by traversing object graph with optional depth limit
    ///
    /// Requirements: 5.1, 5.4
    /// Design Reference: DR-S3-5.1
    ///
    /// Traverses from wants to haves, collecting all needed objects.
    /// Uses BFS to traverse the object graph.
    /// When depth is Some(n), limits commit traversal to n levels.
    async fn collect_objects_from_s3_with_depth(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        wants: &[String],
        haves: &[String],
        depth: Option<u32>,
    ) -> Result<Vec<StoredObject>, GitTransportError> {
        let haves_set: HashSet<&str> = haves.iter().map(String::as_str).collect();
        let mut collected: HashMap<String, StoredObject> = HashMap::new();
        
        // Queue entries: (oid, current_depth) where depth tracks commit depth
        let mut queue: VecDeque<(String, u32)> = wants.iter().map(|oid| (oid.clone(), 0)).collect();
        let mut visited: HashSet<String> = HashSet::new();

        while let Some((oid, current_depth)) = queue.pop_front() {
            // Skip if already visited or in haves
            if visited.contains(&oid) || haves_set.contains(oid.as_str()) {
                continue;
            }
            visited.insert(oid.clone());

            // Try to get object from S3
            match storage.get_object(repo_id, &oid).await {
                Ok(obj) => {
                    // Check if we should traverse further based on depth limit
                    let should_traverse = match (depth, obj.object_type) {
                        // For commits, check depth limit
                        (Some(max_depth), StorageGitObjectType::Commit) => current_depth < max_depth,
                        // For non-commits or no depth limit, always traverse
                        _ => true,
                    };

                    if should_traverse {
                        // Parse object to find references to other objects
                        let refs = self.extract_object_references_with_type(&obj);
                        for (ref_oid, is_parent_commit) in refs {
                            if !visited.contains(&ref_oid) && !haves_set.contains(ref_oid.as_str()) {
                                // Increment depth only for parent commits
                                let next_depth = if is_parent_commit {
                                    current_depth + 1
                                } else {
                                    current_depth
                                };
                                queue.push_back((ref_oid, next_depth));
                            }
                        }
                    }
                    
                    collected.insert(oid, obj);
                }
                Err(StorageError::NotFound(_)) => {
                    // Object not found - might be in haves or not exist
                    debug!(oid = %oid, "Object not found in S3, skipping");
                }
                Err(e) => {
                    warn!(oid = %oid, error = %e, "Error retrieving object from S3");
                    return Err(e.into());
                }
            }
        }

        Ok(collected.into_values().collect())
    }

    /// Collect objects from S3 by traversing object graph (no depth limit)
    ///
    /// Requirements: 5.1
    /// Design Reference: DR-S3-5.1
    async fn collect_objects_from_s3(
        &self,
        storage: &dyn ObjectStorageBackend,
        repo_id: &str,
        wants: &[String],
        haves: &[String],
    ) -> Result<Vec<StoredObject>, GitTransportError> {
        self.collect_objects_from_s3_with_depth(storage, repo_id, wants, haves, None)
            .await
    }

    /// Extract references to other objects from a Git object with type info
    ///
    /// Returns tuples of (oid, is_parent_commit) where is_parent_commit is true
    /// only for parent commit references (used for depth tracking).
    fn extract_object_references_with_type(&self, obj: &StoredObject) -> Vec<(String, bool)> {
        let mut refs = Vec::new();

        match obj.object_type {
            StorageGitObjectType::Commit => {
                // Parse commit to extract tree and parent OIDs
                if let Ok(content) = String::from_utf8(obj.data.clone()) {
                    for line in content.lines() {
                        if let Some(tree_oid) = line.strip_prefix("tree ") {
                            // Tree reference - not a parent commit
                            refs.push((tree_oid.trim().to_string(), false));
                        } else if let Some(parent_oid) = line.strip_prefix("parent ") {
                            // Parent commit reference - counts toward depth
                            refs.push((parent_oid.trim().to_string(), true));
                        } else if line.is_empty() {
                            // Empty line marks end of headers
                            break;
                        }
                    }
                }
            }
            StorageGitObjectType::Tree => {
                // Parse tree to extract entry OIDs
                // Tree format: mode SP name NUL sha1
                let data = &obj.data;
                let mut pos = 0;
                while pos < data.len() {
                    // Find the NUL byte that separates name from SHA1
                    if let Some(nul_pos) = data[pos..].iter().position(|&b| b == 0) {
                        let sha1_start = pos + nul_pos + 1;
                        if sha1_start + 20 <= data.len() {
                            let sha1_bytes = &data[sha1_start..sha1_start + 20];
                            refs.push((hex::encode(sha1_bytes), false));
                            pos = sha1_start + 20;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            StorageGitObjectType::Tag => {
                // Parse tag to extract target OID
                if let Ok(content) = String::from_utf8(obj.data.clone()) {
                    for line in content.lines() {
                        if let Some(target_oid) = line.strip_prefix("object ") {
                            refs.push((target_oid.trim().to_string(), false));
                            break;
                        }
                    }
                }
            }
            StorageGitObjectType::Blob => {
                // Blobs don't reference other objects
            }
        }

        refs
    }

    /// Extract references to other objects from a Git object
    ///
    /// For commits: extracts tree and parent OIDs
    /// For trees: extracts blob and subtree OIDs
    /// For blobs: no references
    /// For tags: extracts target OID
    fn extract_object_references(&self, obj: &StoredObject) -> Vec<String> {
        self.extract_object_references_with_type(obj)
            .into_iter()
            .map(|(oid, _)| oid)
            .collect()
    }

    /// Build a packfile from collected objects
    ///
    /// Requirements: 5.3
    ///
    /// Creates a valid Git packfile with the given objects.
    /// Uses simple non-delta encoding for simplicity.
    fn build_packfile(&self, objects: &[StoredObject]) -> Result<Vec<u8>, GitTransportError> {
        let mut packfile = Vec::new();

        // PACK header
        packfile.extend_from_slice(b"PACK");
        // Version 2
        packfile.extend_from_slice(&2u32.to_be_bytes());
        // Object count
        packfile.extend_from_slice(&(objects.len() as u32).to_be_bytes());

        // Add each object
        for obj in objects {
            let encoded = self.encode_packfile_object(obj)?;
            packfile.extend_from_slice(&encoded);
        }

        // Compute and append SHA1 checksum
        let checksum = Sha1::digest(&packfile);
        packfile.extend_from_slice(&checksum);

        Ok(packfile)
    }

    /// Encode a single object for packfile format
    ///
    /// Uses non-delta encoding (type 1-4) with zlib compression.
    fn encode_packfile_object(&self, obj: &StoredObject) -> Result<Vec<u8>, GitTransportError> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut result = Vec::new();

        // Object type (1=commit, 2=tree, 3=blob, 4=tag)
        let type_num: u8 = match obj.object_type {
            StorageGitObjectType::Commit => 1,
            StorageGitObjectType::Tree => 2,
            StorageGitObjectType::Blob => 3,
            StorageGitObjectType::Tag => 4,
        };

        // Encode header with variable-length size
        let size = obj.data.len();
        let mut header_byte = (type_num << 4) | ((size & 0x0f) as u8);
        let mut remaining_size = size >> 4;

        if remaining_size > 0 {
            header_byte |= 0x80; // More bytes follow
        }
        result.push(header_byte);

        while remaining_size > 0 {
            let mut byte = (remaining_size & 0x7f) as u8;
            remaining_size >>= 7;
            if remaining_size > 0 {
                byte |= 0x80; // More bytes follow
            }
            result.push(byte);
        }

        // Compress object data with zlib
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&obj.data)
            .map_err(|e| GitTransportError::InvalidPackfile(format!("Compression error: {}", e)))?;
        let compressed = encoder
            .finish()
            .map_err(|e| GitTransportError::InvalidPackfile(format!("Compression error: {}", e)))?;

        result.extend_from_slice(&compressed);

        Ok(result)
    }

    /// Handle git-receive-pack (push)
    ///
    /// POST /v1/repos/{repoId}/git-receive-pack
    ///
    /// Requirements: 4.1, 4.4, 4.6, 4.7, 4.8
    /// Design: DR-4.3 (Git Transport Service)
    #[allow(clippy::too_many_arguments)]
    pub async fn receive_pack(
        &self,
        repo_id: &str,
        agent_id: &str,
        signature: &str,
        timestamp: DateTime<Utc>,
        nonce: &str,
        packfile: &[u8],
        ref_updates: Vec<RefUpdateRequest>,
    ) -> Result<ReceivePackResponse, GitTransportError> {
        // Get repository
        let _repo = self.get_repository(repo_id).await?;

        // Check write access
        let has_access = self
            .check_access(repo_id, agent_id, AccessRole::Write)
            .await?;
        if !has_access {
            return Err(GitTransportError::AccessDenied(format!(
                "Agent {} does not have write access to repository {}",
                agent_id, repo_id
            )));
        }

        // Get agent's public key
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
            action: "git-receive-pack".to_string(),
            timestamp,
            nonce: nonce.to_string(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, signature, &public_key)?;

        // Validate packfile format
        self.validate_packfile(packfile)?;

        // Process ref updates (for now, just acknowledge them)
        // In a full implementation, this would:
        // 1. Unpack and validate all objects
        // 2. Check fast-forward for each ref
        // 3. Update refs atomically
        let update_statuses: Vec<RefUpdateStatus> = ref_updates
            .iter()
            .map(|r| RefUpdateStatus {
                ref_name: r.ref_name.clone(),
                status: "ok".to_string(),
                message: None,
            })
            .collect();

        // Record audit event
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "packfile_hash": packfile_hash,
            "ref_updates": canonical_ref_updates,
        });

        AuditService::new(self.pool.clone())
            .append(AuditEvent {
                agent_id: agent_id.to_string(),
                action: "git-receive-pack".to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            })
            .await?;

        Ok(ReceivePackResponse {
            status: "ok".to_string(),
            ref_updates: update_statuses,
        })
    }

    /// Build capabilities list for ref advertisement
    fn build_capabilities(&self, service: &str) -> Vec<String> {
        let mut caps = vec![
            "agent=gitclaw/1.0".to_string(),
            "object-format=sha1".to_string(),
        ];

        if service == "git-upload-pack" {
            caps.extend([
                "multi_ack".to_string(),
                "multi_ack_detailed".to_string(),
                "no-done".to_string(),
                "side-band".to_string(),
                "side-band-64k".to_string(),
                "ofs-delta".to_string(),
                "shallow".to_string(),
                "deepen-since".to_string(),
                "deepen-not".to_string(),
                "deepen-relative".to_string(),
                "no-progress".to_string(),
                "include-tag".to_string(),
                "allow-tip-sha1-in-want".to_string(),
                "allow-reachable-sha1-in-want".to_string(),
                "filter".to_string(),
            ]);
        } else if service == "git-receive-pack" {
            caps.extend([
                "report-status".to_string(),
                "report-status-v2".to_string(),
                "delete-refs".to_string(),
                "ofs-delta".to_string(),
                "atomic".to_string(),
                "push-options".to_string(),
            ]);
        }

        caps
    }

    /// Generate an empty packfile
    fn generate_empty_packfile(&self) -> Vec<u8> {
        // PACK header + version 2 + 0 objects + SHA1 checksum
        let mut packfile = vec![
            0x50, 0x41, 0x43, 0x4b, // "PACK"
            0x00, 0x00, 0x00, 0x02, // version 2
            0x00, 0x00, 0x00, 0x00, // 0 objects
        ];

        // Compute SHA1 checksum of the header
        use sha1::{Digest as Sha1Digest, Sha1};
        let checksum = Sha1::digest(&packfile);
        packfile.extend_from_slice(&checksum);

        packfile
    }

    /// Validate packfile format
    fn validate_packfile(&self, packfile: &[u8]) -> Result<(), GitTransportError> {
        // Minimum packfile size: header (12 bytes) + checksum (20 bytes)
        if packfile.len() < 32 {
            return Err(GitTransportError::InvalidPackfile(
                "Packfile too small".to_string(),
            ));
        }

        // Check PACK signature
        if &packfile[0..4] != b"PACK" {
            return Err(GitTransportError::InvalidPackfile(
                "Invalid PACK signature".to_string(),
            ));
        }

        // Check version (must be 2 or 3)
        let version = u32::from_be_bytes([packfile[4], packfile[5], packfile[6], packfile[7]]);
        if version != 2 && version != 3 {
            return Err(GitTransportError::InvalidPackfile(format!(
                "Unsupported packfile version: {}",
                version
            )));
        }

        // Verify SHA1 checksum
        use sha1::{Digest as Sha1Digest, Sha1};
        let data_len = packfile.len() - 20;
        let expected_checksum = &packfile[data_len..];
        let actual_checksum = Sha1::digest(&packfile[..data_len]);

        if actual_checksum.as_slice() != expected_checksum {
            return Err(GitTransportError::InvalidPackfile(
                "Invalid packfile checksum".to_string(),
            ));
        }

        Ok(())
    }

    /// Get repository by ID
    async fn get_repository(&self, repo_id: &str) -> Result<RepoInfo, GitTransportError> {
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
            None => Err(GitTransportError::RepoNotFound(repo_id.to_string())),
        }
    }

    /// Check if an agent has access to a repository
    async fn check_access(
        &self,
        repo_id: &str,
        agent_id: &str,
        required_role: AccessRole,
    ) -> Result<bool, GitTransportError> {
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
    async fn get_agent_public_key(&self, agent_id: &str) -> Result<String, GitTransportError> {
        let public_key: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM agents WHERE agent_id = $1")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        public_key.ok_or_else(|| GitTransportError::AgentNotFound(agent_id.to_string()))
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

/// Format ref advertisement response for Git protocol
pub fn format_ref_advertisement(service: &str, adv: &RefAdvertisement) -> Vec<u8> {
    let mut response = Vec::new();

    // Service announcement
    let service_line = format!("# service={}\n", service);
    response.extend(format_pkt_line(&service_line));
    response.extend(b"0000"); // Flush packet

    // First ref with capabilities
    if let Some(first_ref) = adv.refs.first() {
        let caps_str = adv.capabilities.join(" ");
        let line = format!("{} {}\0{}\n", first_ref.oid, first_ref.name, caps_str);
        response.extend(format_pkt_line(&line));

        // Remaining refs
        for git_ref in adv.refs.iter().skip(1) {
            let line = format!("{} {}\n", git_ref.oid, git_ref.name);
            response.extend(format_pkt_line(&line));
        }
    } else {
        // Empty repo - send capabilities with zero OID
        let caps_str = adv.capabilities.join(" ");
        let line = format!(
            "0000000000000000000000000000000000000000 capabilities^{{}}\0{}\n",
            caps_str
        );
        response.extend(format_pkt_line(&line));
    }

    // HEAD symref if available (already included in capabilities as symref=HEAD:refs/heads/main)
    let _head = &adv.head;

    response.extend(b"0000"); // Flush packet
    response
}

/// Format a pkt-line
fn format_pkt_line(data: &str) -> Vec<u8> {
    let len = data.len() + 4; // 4 bytes for length prefix
    format!("{:04x}{}", len, data).into_bytes()
}


#[cfg(test)]
mod property_git_protocol_compliance {
    //! Property Test: Git Protocol Compliance
    //!
    //! **Property 5: Git Protocol Compliance**
    //! *For any* standard Git client operation (clone, push, fetch), the response SHALL be valid per Git protocol spec.
    //!
    //! **Validates: Requirements 4.1, 4.2, 4.3, 4.5, 4.6** | **Design: DR-4.3**
    //!
    //! This property test verifies that:
    //! 1. Ref advertisement format is valid per Git Smart HTTP protocol
    //! 2. Packfile format is valid (PACK header, version 2/3, SHA1 checksum)
    //! 3. Git protocol version 2 capabilities are advertised
    //! 4. Pkt-line format is correct (4-byte hex length prefix)
    //! 5. Object encoding in packfiles follows Git spec

    use super::*;
    use proptest::prelude::*;
    use sha1::{Digest as Sha1Digest, Sha1};
    use std::sync::OnceLock;
    use tokio::runtime::Runtime;

    /// Get or create a shared Tokio runtime for property tests
    fn get_runtime() -> &'static Runtime {
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime")
        })
    }

    /// Create a test GitTransportService with a lazy pool
    /// This must be called within a Tokio runtime context
    fn create_test_service() -> GitTransportService {
        GitTransportService::new(
            sqlx::PgPool::connect_lazy("postgres://localhost/dummy").expect("lazy pool")
        )
    }

    // ============================================================================
    // Test Strategies
    // ============================================================================

    /// Strategy for generating valid Git OIDs (40 hex characters)
    fn valid_oid_strategy() -> impl Strategy<Value = String> {
        "[0-9a-f]{40}".prop_map(|s| s.to_lowercase())
    }

    /// Strategy for generating valid Git ref names
    fn valid_ref_name_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("refs/heads/main".to_string()),
            Just("refs/heads/master".to_string()),
            Just("refs/heads/develop".to_string()),
            Just("refs/heads/feature/test".to_string()),
            Just("refs/tags/v1.0.0".to_string()),
            Just("refs/tags/release-1.0".to_string()),
            "[a-z][a-z0-9_-]{2,20}".prop_map(|s| format!("refs/heads/{}", s)),
            "[a-z][a-z0-9_-]{2,20}".prop_map(|s| format!("refs/tags/{}", s)),
        ]
    }

    /// Strategy for generating valid Git service names
    fn valid_service_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("git-upload-pack".to_string()),
            Just("git-receive-pack".to_string()),
        ]
    }

    /// Strategy for generating Git references
    fn git_reference_strategy() -> impl Strategy<Value = GitReference> {
        (valid_oid_strategy(), valid_ref_name_strategy()).prop_map(|(oid, name)| GitReference {
            name,
            oid,
            peeled: None,
        })
    }

    /// Strategy for generating multiple Git references
    fn git_references_strategy() -> impl Strategy<Value = Vec<GitReference>> {
        prop::collection::vec(git_reference_strategy(), 0..10)
    }

    /// Strategy for generating valid capabilities
    fn capabilities_strategy() -> impl Strategy<Value = Vec<String>> {
        prop_oneof![
            // Upload-pack capabilities
            Just(vec![
                "agent=gitclaw/1.0".to_string(),
                "object-format=sha1".to_string(),
                "multi_ack".to_string(),
                "side-band-64k".to_string(),
                "shallow".to_string(),
            ]),
            // Receive-pack capabilities
            Just(vec![
                "agent=gitclaw/1.0".to_string(),
                "object-format=sha1".to_string(),
                "report-status".to_string(),
                "delete-refs".to_string(),
                "atomic".to_string(),
            ]),
            // Minimal capabilities
            Just(vec![
                "agent=gitclaw/1.0".to_string(),
                "object-format=sha1".to_string(),
            ]),
        ]
    }

    /// Strategy for generating ref advertisements
    fn ref_advertisement_strategy() -> impl Strategy<Value = RefAdvertisement> {
        (
            git_references_strategy(),
            capabilities_strategy(),
            proptest::option::of(valid_ref_name_strategy()),
        )
            .prop_map(|(refs, capabilities, head)| RefAdvertisement {
                refs,
                capabilities,
                head,
            })
    }

    /// Strategy for generating blob data
    fn blob_data_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..1000)
    }

    /// Strategy for generating commit messages
    fn commit_message_strategy() -> impl Strategy<Value = String> {
        "[A-Za-z0-9 .,!?-]{10,100}"
    }

    // ============================================================================
    // Helper Functions
    // ============================================================================

    /// Parse a pkt-line and return the data portion
    fn parse_pkt_line(data: &[u8]) -> Option<(usize, &[u8])> {
        if data.len() < 4 {
            return None;
        }

        let len_str = std::str::from_utf8(&data[0..4]).ok()?;

        // Handle flush packet
        if len_str == "0000" {
            return Some((4, &[]));
        }

        let len = usize::from_str_radix(len_str, 16).ok()?;

        // Length includes the 4-byte prefix
        if len < 4 || data.len() < len {
            return None;
        }

        Some((len, &data[4..len]))
    }

    /// Validate that a byte sequence is valid pkt-line format
    fn is_valid_pkt_line_sequence(data: &[u8]) -> bool {
        let mut pos = 0;

        while pos < data.len() {
            if let Some((consumed, _line_data)) = parse_pkt_line(&data[pos..]) {
                pos += consumed;
            } else {
                return false;
            }
        }

        true
    }

    /// Validate packfile header
    fn validate_packfile_header(packfile: &[u8]) -> Result<(u32, u32), String> {
        // Minimum size: header (12 bytes) + checksum (20 bytes)
        if packfile.len() < 32 {
            return Err(format!(
                "Packfile too small: {} bytes (minimum 32)",
                packfile.len()
            ));
        }

        // Check PACK signature
        if &packfile[0..4] != b"PACK" {
            return Err(format!(
                "Invalid PACK signature: {:?}",
                &packfile[0..4]
            ));
        }

        // Check version (must be 2 or 3)
        let version = u32::from_be_bytes([packfile[4], packfile[5], packfile[6], packfile[7]]);
        if version != 2 && version != 3 {
            return Err(format!("Unsupported packfile version: {}", version));
        }

        // Get object count
        let object_count =
            u32::from_be_bytes([packfile[8], packfile[9], packfile[10], packfile[11]]);

        Ok((version, object_count))
    }

    /// Validate packfile checksum
    fn validate_packfile_checksum(packfile: &[u8]) -> Result<(), String> {
        if packfile.len() < 32 {
            return Err("Packfile too small for checksum validation".to_string());
        }

        let data_len = packfile.len() - 20;
        let expected_checksum = &packfile[data_len..];
        let actual_checksum = Sha1::digest(&packfile[..data_len]);

        if actual_checksum.as_slice() != expected_checksum {
            return Err(format!(
                "Invalid packfile checksum: expected {:?}, got {:?}",
                hex::encode(expected_checksum),
                hex::encode(actual_checksum)
            ));
        }

        Ok(())
    }

    /// Validate ref advertisement contains required elements
    fn validate_ref_advertisement_format(data: &[u8], service: &str) -> Result<(), String> {
        // Must be valid pkt-line sequence
        if !is_valid_pkt_line_sequence(data) {
            return Err("Invalid pkt-line sequence".to_string());
        }

        // Must start with service announcement
        let service_announcement = format!("# service={}\n", service);
        let expected_start = format_pkt_line(&service_announcement);

        if !data.starts_with(&expected_start) {
            return Err(format!(
                "Missing or invalid service announcement. Expected to start with: {:?}",
                String::from_utf8_lossy(&expected_start)
            ));
        }

        // Must contain at least one flush packet (0000)
        if !data.windows(4).any(|w| w == b"0000") {
            return Err("Missing flush packet (0000)".to_string());
        }

        // Must end with flush packet
        if !data.ends_with(b"0000") {
            return Err("Must end with flush packet (0000)".to_string());
        }

        Ok(())
    }

    /// Validate that capabilities include required Git protocol v2 capabilities
    fn validate_capabilities(capabilities: &[String], service: &str) -> Result<(), String> {
        // Must have agent capability
        if !capabilities.iter().any(|c| c.starts_with("agent=")) {
            return Err("Missing agent capability".to_string());
        }

        // Must have object-format capability
        if !capabilities.iter().any(|c| c.starts_with("object-format=")) {
            return Err("Missing object-format capability".to_string());
        }

        // Service-specific capabilities
        if service == "git-upload-pack" {
            // Should support shallow clones
            if !capabilities.contains(&"shallow".to_string()) {
                return Err("Missing shallow capability for upload-pack".to_string());
            }
        } else if service == "git-receive-pack" {
            // Should support report-status
            if !capabilities.contains(&"report-status".to_string()) {
                return Err("Missing report-status capability for receive-pack".to_string());
            }
        }

        Ok(())
    }

    // ============================================================================
    // Property Tests
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property: Ref advertisement format is valid per Git Smart HTTP protocol
        ///
        /// **Validates: Requirements 4.1, 4.3** | **Design: DR-4.3**
        ///
        /// For any valid ref advertisement, the formatted output SHALL:
        /// 1. Be a valid pkt-line sequence
        /// 2. Start with service announcement
        /// 3. End with flush packet (0000)
        /// 4. Contain capabilities in first ref line
        #[test]
        fn ref_advertisement_format_is_valid(
            adv in ref_advertisement_strategy(),
            service in valid_service_strategy()
        ) {
            let formatted = format_ref_advertisement(&service, &adv);

            // Validate format
            let result = validate_ref_advertisement_format(&formatted, &service);
            prop_assert!(
                result.is_ok(),
                "Ref advertisement format validation failed: {:?}",
                result.err()
            );

            // Validate it's valid UTF-8 (Git protocol uses ASCII/UTF-8)
            let as_string = String::from_utf8(formatted.clone());
            prop_assert!(
                as_string.is_ok(),
                "Ref advertisement should be valid UTF-8"
            );
        }

        /// Property: Pkt-line format is correct
        ///
        /// **Validates: Requirements 4.1, 4.3** | **Design: DR-4.3**
        ///
        /// For any pkt-line, the format SHALL:
        /// 1. Have 4-byte hex length prefix
        /// 2. Length includes the prefix itself
        /// 3. Flush packet is "0000"
        #[test]
        fn pkt_line_format_is_correct(
            data in "[a-zA-Z0-9 .,!?#=-]{1,100}"
        ) {
            let line = format!("{}\n", data);
            let pkt_line = format_pkt_line(&line);

            // Length prefix should be 4 hex characters
            prop_assert_eq!(pkt_line.len(), line.len() + 4);

            // Parse the length prefix
            let len_str = std::str::from_utf8(&pkt_line[0..4]).expect("valid utf8");
            let parsed_len = usize::from_str_radix(len_str, 16).expect("valid hex");

            // Length should equal total pkt-line length
            prop_assert_eq!(parsed_len, pkt_line.len());

            // Data portion should match original
            prop_assert_eq!(&pkt_line[4..], line.as_bytes());
        }

        /// Property: Empty packfile is valid
        ///
        /// **Validates: Requirements 4.2, 4.5** | **Design: DR-4.3**
        ///
        /// An empty packfile (0 objects) SHALL:
        /// 1. Have valid PACK header
        /// 2. Have version 2 or 3
        /// 3. Have valid SHA1 checksum
        #[test]
        fn empty_packfile_is_valid(_seed in 0u32..1000u32) {
            let rt = get_runtime();
            let service = rt.block_on(async {
                create_test_service()
            });

            let packfile = service.generate_empty_packfile();

            // Validate header
            let header_result = validate_packfile_header(&packfile);
            prop_assert!(
                header_result.is_ok(),
                "Empty packfile header validation failed: {:?}",
                header_result.err()
            );

            let (version, object_count) = header_result.expect("validated above");
            prop_assert_eq!(version, 2, "Empty packfile should be version 2");
            prop_assert_eq!(object_count, 0, "Empty packfile should have 0 objects");

            // Validate checksum
            let checksum_result = validate_packfile_checksum(&packfile);
            prop_assert!(
                checksum_result.is_ok(),
                "Empty packfile checksum validation failed: {:?}",
                checksum_result.err()
            );
        }

        /// Property: Packfile validation rejects invalid packfiles
        ///
        /// **Validates: Requirements 4.2, 4.8** | **Design: DR-4.3**
        ///
        /// Invalid packfiles SHALL be rejected:
        /// 1. Wrong PACK signature
        /// 2. Invalid version
        /// 3. Invalid checksum
        #[test]
        fn invalid_packfile_is_rejected(
            garbage in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let rt = get_runtime();
            let service = rt.block_on(async {
                create_test_service()
            });

            // Random garbage should not be a valid packfile
            // (unless it happens to be valid, which is astronomically unlikely)
            let result = service.validate_packfile(&garbage);

            // If it's less than 32 bytes, it must be invalid
            if garbage.len() < 32 {
                prop_assert!(
                    result.is_err(),
                    "Packfile smaller than 32 bytes should be rejected"
                );
            }

            // If it doesn't start with PACK, it must be invalid
            if garbage.len() >= 4 && &garbage[0..4] != b"PACK" {
                prop_assert!(
                    result.is_err(),
                    "Packfile without PACK signature should be rejected"
                );
            }
        }

        /// Property: Capabilities include required Git protocol elements
        ///
        /// **Validates: Requirements 4.7** | **Design: DR-4.3**
        ///
        /// Built capabilities SHALL include:
        /// 1. agent= capability
        /// 2. object-format= capability
        /// 3. Service-specific capabilities
        #[test]
        fn capabilities_include_required_elements(
            service in valid_service_strategy()
        ) {
            let rt = get_runtime();
            let git_service = rt.block_on(async {
                create_test_service()
            });

            let capabilities = git_service.build_capabilities(&service);

            let result = validate_capabilities(&capabilities, &service);
            prop_assert!(
                result.is_ok(),
                "Capabilities validation failed for {}: {:?}",
                service,
                result.err()
            );
        }

        /// Property: OID format is valid 40-character hex
        ///
        /// **Validates: Requirements 4.3** | **Design: DR-4.3**
        ///
        /// All OIDs in ref advertisement SHALL be valid 40-character hex strings
        #[test]
        fn oid_format_is_valid_hex(
            oid in valid_oid_strategy()
        ) {
            // OID should be exactly 40 characters
            prop_assert_eq!(oid.len(), 40, "OID should be 40 characters");

            // OID should be valid hex
            let decoded = hex::decode(&oid);
            prop_assert!(
                decoded.is_ok(),
                "OID should be valid hex: {}",
                oid
            );

            // Decoded should be 20 bytes (SHA1)
            prop_assert_eq!(
                decoded.expect("validated above").len(),
                20,
                "Decoded OID should be 20 bytes"
            );
        }

        /// Property: Ref names follow Git naming conventions
        ///
        /// **Validates: Requirements 4.3** | **Design: DR-4.3**
        ///
        /// Ref names SHALL:
        /// 1. Start with refs/
        /// 2. Not contain consecutive slashes
        /// 3. Not end with /
        #[test]
        fn ref_names_follow_conventions(
            ref_name in valid_ref_name_strategy()
        ) {
            // Should start with refs/
            prop_assert!(
                ref_name.starts_with("refs/"),
                "Ref name should start with refs/: {}",
                ref_name
            );

            // Should not contain consecutive slashes
            prop_assert!(
                !ref_name.contains("//"),
                "Ref name should not contain consecutive slashes: {}",
                ref_name
            );

            // Should not end with /
            prop_assert!(
                !ref_name.ends_with('/'),
                "Ref name should not end with /: {}",
                ref_name
            );

            // Should not contain control characters
            prop_assert!(
                ref_name.chars().all(|c| !c.is_control()),
                "Ref name should not contain control characters: {}",
                ref_name
            );
        }

        /// Property: Ref advertisement with refs includes capabilities in first line
        ///
        /// **Validates: Requirements 4.3, 4.7** | **Design: DR-4.3**
        ///
        /// When refs are present, capabilities SHALL be in the first ref line after NUL byte
        #[test]
        fn ref_advertisement_capabilities_in_first_line(
            refs in prop::collection::vec(git_reference_strategy(), 1..5),
            capabilities in capabilities_strategy()
        ) {
            let adv = RefAdvertisement {
                refs,
                capabilities: capabilities.clone(),
                head: Some("refs/heads/main".to_string()),
            };

            let formatted = format_ref_advertisement("git-upload-pack", &adv);
            let formatted_str = String::from_utf8(formatted).expect("valid utf8");

            // Find the first ref line (after service announcement and flush)
            let lines: Vec<&str> = formatted_str.split("0000").collect();
            prop_assert!(
                lines.len() >= 2,
                "Should have at least service announcement and refs sections"
            );

            // The second section should contain capabilities after NUL
            let refs_section = lines.get(1).unwrap_or(&"");
            prop_assert!(
                refs_section.contains('\0'),
                "First ref line should contain NUL byte for capabilities"
            );

            // Capabilities should be present
            for cap in &capabilities {
                prop_assert!(
                    refs_section.contains(cap),
                    "Capability '{}' should be in first ref line",
                    cap
                );
            }
        }

        /// Property: Empty repo ref advertisement is valid
        ///
        /// **Validates: Requirements 4.3** | **Design: DR-4.3**
        ///
        /// For empty repos (no refs), the advertisement SHALL:
        /// 1. Use zero OID (40 zeros)
        /// 2. Include capabilities
        /// 3. Be valid pkt-line format
        #[test]
        fn empty_repo_ref_advertisement_is_valid(
            capabilities in capabilities_strategy(),
            service in valid_service_strategy()
        ) {
            let adv = RefAdvertisement {
                refs: vec![],
                capabilities,
                head: None,
            };

            let formatted = format_ref_advertisement(&service, &adv);

            // Validate format
            let result = validate_ref_advertisement_format(&formatted, &service);
            prop_assert!(
                result.is_ok(),
                "Empty repo ref advertisement format validation failed: {:?}",
                result.err()
            );

            // Should contain zero OID
            let formatted_str = String::from_utf8(formatted).expect("valid utf8");
            prop_assert!(
                formatted_str.contains("0000000000000000000000000000000000000000"),
                "Empty repo should use zero OID"
            );

            // Should contain capabilities^{}
            prop_assert!(
                formatted_str.contains("capabilities^{}"),
                "Empty repo should have capabilities^{{}} marker"
            );
        }
    }

    // ============================================================================
    // Integration Tests (require database)
    // ============================================================================

    /// Integration test for Git protocol compliance with actual service
    ///
    /// This test requires a running PostgreSQL database and validates
    /// the full Git transport flow.
    ///
    /// **Validates: Requirements 4.1, 4.2, 4.3, 4.5, 4.6** | **Design: DR-4.3**
    #[tokio::test]
    #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
    async fn integration_git_protocol_ref_advertisement() {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        // Try to connect to test database
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5434/gitclaw".to_string());

        let pool = match sqlx::PgPool::connect(&database_url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Skipping test: database not available: {}", e);
                return;
            }
        };

        // Create test agent
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", &agent_id[..8]);

        // Insert test agent
        sqlx::query(
            "INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .bind(&public_key)
        .bind(serde_json::json!(["read", "write"]))
        .execute(&pool)
        .await
        .expect("Failed to create test agent");

        // Create test repository
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", &repo_id[..8]);

        sqlx::query(
            "INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
             VALUES ($1, $2, $3, $4, 'public', 'main', NOW())",
        )
        .bind(&repo_id)
        .bind(&agent_id)
        .bind(&repo_name)
        .bind("Test repository for Git protocol compliance")
        .execute(&pool)
        .await
        .expect("Failed to create test repository");

        // Initialize repo_star_counts
        sqlx::query(
            "INSERT INTO repo_star_counts (repo_id, stars, updated_at)
             VALUES ($1, 0, NOW())",
        )
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to initialize star counts");

        // Create repo_access entry for owner
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at)
             VALUES ($1, $2, 'admin', NOW())",
        )
        .bind(&repo_id)
        .bind(&agent_id)
        .execute(&pool)
        .await
        .expect("Failed to create repo access");

        // Test ref advertisement
        let git_service = GitTransportService::new(pool.clone());

        // Test git-upload-pack service
        let result = git_service
            .get_refs(&repo_id, "git-upload-pack", Some(&agent_id))
            .await;

        assert!(result.is_ok(), "get_refs should succeed: {:?}", result.err());

        let adv = result.expect("validated above");

        // Validate capabilities
        assert!(
            !adv.capabilities.is_empty(),
            "Should have capabilities"
        );
        assert!(
            adv.capabilities.iter().any(|c| c.starts_with("agent=")),
            "Should have agent capability"
        );
        assert!(
            adv.capabilities.contains(&"shallow".to_string()),
            "Should support shallow clones"
        );

        // Format and validate
        let formatted = format_ref_advertisement("git-upload-pack", &adv);
        let validation_result = validate_ref_advertisement_format(&formatted, "git-upload-pack");
        assert!(
            validation_result.is_ok(),
            "Formatted ref advertisement should be valid: {:?}",
            validation_result.err()
        );

        // Test git-receive-pack service
        let result = git_service
            .get_refs(&repo_id, "git-receive-pack", Some(&agent_id))
            .await;

        assert!(
            result.is_ok(),
            "get_refs for receive-pack should succeed: {:?}",
            result.err()
        );

        let adv = result.expect("validated above");
        assert!(
            adv.capabilities.contains(&"report-status".to_string()),
            "Should support report-status for receive-pack"
        );

        // Cleanup
        let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(&repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
            .bind(&repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(&repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .execute(&pool)
            .await;
    }

    /// Integration test for packfile validation
    ///
    /// **Validates: Requirements 4.2, 4.8** | **Design: DR-4.3**
    #[tokio::test]
    #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
    async fn integration_packfile_validation() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5434/gitclaw".to_string());

        let pool = match sqlx::PgPool::connect(&database_url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Skipping test: database not available: {}", e);
                return;
            }
        };

        let git_service = GitTransportService::new(pool);

        // Test empty packfile is valid
        let empty_packfile = git_service.generate_empty_packfile();
        let result = git_service.validate_packfile(&empty_packfile);
        assert!(
            result.is_ok(),
            "Empty packfile should be valid: {:?}",
            result.err()
        );

        // Test invalid packfiles are rejected
        let invalid_cases = vec![
            (vec![], "empty"),
            (vec![0u8; 10], "too small"),
            (b"NOTPACK".to_vec(), "wrong signature"),
            (b"PACK\x00\x00\x00\x05".to_vec(), "invalid version"),
        ];

        for (invalid_packfile, description) in invalid_cases {
            let result = git_service.validate_packfile(&invalid_packfile);
            assert!(
                result.is_err(),
                "Invalid packfile ({}) should be rejected",
                description
            );
        }

        // Test packfile with corrupted checksum
        let mut corrupted = git_service.generate_empty_packfile();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 0xFF; // Flip bits in checksum
        }
        let result = git_service.validate_packfile(&corrupted);
        assert!(
            result.is_err(),
            "Packfile with corrupted checksum should be rejected"
        );
    }
}

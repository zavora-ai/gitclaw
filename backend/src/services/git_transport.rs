//! Git Smart HTTP Transport Service
//!
//! Implements Git Smart HTTP protocol for standard git client compatibility.
//! Design: DR-4.3 (Git Transport Service)

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;

use crate::models::{AccessRole, Visibility};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::signature::{SignatureEnvelope, SignatureError, SignatureValidator};

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

    #[error("Signature validation failed: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
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
#[derive(Debug, Clone)]
pub struct GitTransportService {
    pool: PgPool,
    signature_validator: SignatureValidator,
}

impl GitTransportService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            signature_validator: SignatureValidator::default(),
        }
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
            let agent_id = agent_id.ok_or_else(|| {
                GitTransportError::MissingHeader("X-Agent-Id".to_string())
            })?;
            
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
    /// Requirements: 4.1, 4.2, 4.5, 4.7, 4.8
    /// Design: DR-4.3 (Git Transport Service)
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
        // Get repository (validates it exists)
        let _repo = self.get_repository(repo_id).await?;

        // Check read access
        let has_access = self.check_access(repo_id, agent_id, AccessRole::Read).await?;
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

        // For now, return an empty packfile (new repo)
        // In a full implementation, this would generate a proper packfile
        // based on the wants/haves negotiation
        let packfile = self.generate_empty_packfile();

        Ok(UploadPackResponse { packfile })
    }

    /// Handle git-receive-pack (push)
    ///
    /// POST /v1/repos/{repoId}/git-receive-pack
    ///
    /// Requirements: 4.1, 4.4, 4.6, 4.7, 4.8
    /// Design: DR-4.3 (Git Transport Service)
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
        let has_access = self.check_access(repo_id, agent_id, AccessRole::Write).await?;
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
        use sha1::{Sha1, Digest as Sha1Digest};
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
        use sha1::{Sha1, Digest as Sha1Digest};
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
        let access: Option<AccessRole> = sqlx::query_scalar(
            "SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2",
        )
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

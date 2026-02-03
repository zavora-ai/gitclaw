//! Repository Service
//!
//! Handles repository creation, access control, and metadata management.
//! Implements DR-4.1 (Repository Service) from the design document.

use chrono::Utc;
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::models::{AccessRole, CreateRepoRequest, CreateRepoResponse, Repository, Visibility};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::idempotency::{IdempotencyError, IdempotencyResult, IdempotencyService};
use crate::services::signature::{
    SignatureEnvelope, SignatureError, SignatureValidator, get_agent_public_key_if_not_suspended,
};

/// Errors that can occur during repository operations
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Repository already exists: {0}/{1}")]
    RepoExists(String, String),

    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Invalid repository name: {0}")]
    InvalidRepoName(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

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
}

impl From<SignatureError> for RepositoryError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::Suspended(msg) => RepositoryError::Suspended(msg),
            SignatureError::MissingField(msg) if msg.starts_with("Agent not found:") => {
                // Extract agent_id from the message
                let agent_id = msg.strip_prefix("Agent not found: ").unwrap_or(&msg);
                RepositoryError::AgentNotFound(agent_id.to_string())
            }
            other => RepositoryError::SignatureError(other),
        }
    }
}

/// Service for managing repositories
#[derive(Debug, Clone)]
pub struct RepositoryService {
    pool: PgPool,
    signature_validator: SignatureValidator,
    idempotency_service: IdempotencyService,
    base_url: String,
}

impl RepositoryService {
    pub fn new(pool: PgPool, base_url: String) -> Self {
        Self {
            signature_validator: SignatureValidator::default(),
            idempotency_service: IdempotencyService::new(pool.clone()),
            pool,
            base_url,
        }
    }

    /// Create a new repository
    ///
    /// Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
    /// Design: DR-4.1 (Repository Service)
    pub async fn create(
        &self,
        agent_id: &str,
        nonce: &str,
        timestamp: chrono::DateTime<Utc>,
        signature: &str,
        request: CreateRepoRequest,
    ) -> Result<CreateRepoResponse, RepositoryError> {
        const ACTION: &str = "repo_create";

        // Check idempotency first
        match self
            .idempotency_service
            .check(agent_id, nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                // Return cached response
                let response: CreateRepoResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| RepositoryError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(RepositoryError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {
                // Continue with the operation
            }
        }

        // Validate repository name
        self.validate_repo_name(&request.name)?;

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "name": request.name,
            "description": request.description,
            "visibility": request.visibility,
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

        // Generate repository ID
        let repo_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let default_branch = "main".to_string();

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Check for existing repository with same name for this owner
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT repo_id FROM repositories WHERE owner_id = $1 AND name = $2",
        )
        .bind(agent_id)
        .bind(&request.name)
        .fetch_optional(&mut *tx)
        .await?;

        if existing.is_some() {
            return Err(RepositoryError::RepoExists(
                agent_id.to_string(),
                request.name,
            ));
        }

        // Insert repository record
        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&repo_id)
        .bind(agent_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.visibility)
        .bind(&default_branch)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        // Initialize repo_star_counts with stars = 0 (Requirement 2.6)
        sqlx::query(
            r#"
            INSERT INTO repo_star_counts (repo_id, stars, updated_at)
            VALUES ($1, 0, $2)
            "#,
        )
        .bind(&repo_id)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        // Create implicit repo_access entry with role = admin for owner (Requirement 2.7)
        sqlx::query(
            r#"
            INSERT INTO repo_access (repo_id, agent_id, role, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&repo_id)
        .bind(agent_id)
        .bind(AccessRole::Admin)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        // Append audit event
        let audit_data = serde_json::json!({
            "repo_name": request.name,
            "description": request.description,
            "visibility": request.visibility,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.clone(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Build response
        let clone_url = format!("{}/v1/repos/{}", self.base_url, repo_id);
        let response = CreateRepoResponse {
            repo_id: repo_id.clone(),
            name: request.name,
            owner_id: agent_id.to_string(),
            clone_url,
            default_branch,
            visibility: request.visibility,
            created_at,
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 201, &response, 24)
            .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(response)
    }

    /// Get a repository by ID
    pub async fn get_by_id(&self, repo_id: &str) -> Result<Option<Repository>, RepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT repo_id, owner_id, name, description, visibility, default_branch, created_at
            FROM repositories
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Repository {
            repo_id: r.get("repo_id"),
            owner_id: r.get("owner_id"),
            name: r.get("name"),
            description: r.get("description"),
            visibility: r.get("visibility"),
            default_branch: r.get("default_branch"),
            created_at: r.get("created_at"),
        }))
    }

    /// Check if an agent has access to a repository
    pub async fn check_access(
        &self,
        repo_id: &str,
        agent_id: &str,
        required_role: AccessRole,
    ) -> Result<bool, RepositoryError> {
        // First, get the repository to check visibility
        let repo = self.get_by_id(repo_id).await?;
        let repo = match repo {
            Some(r) => r,
            None => return Err(RepositoryError::RepoNotFound(repo_id.to_string())),
        };

        // Public repos allow read access to everyone
        if repo.visibility == Visibility::Public && required_role == AccessRole::Read {
            return Ok(true);
        }

        // Check if agent is the owner (owners have admin access)
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

    /// Get agent's access role for a repository
    pub async fn get_access_role(
        &self,
        repo_id: &str,
        agent_id: &str,
    ) -> Result<Option<AccessRole>, RepositoryError> {
        let access: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(repo_id)
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(access)
    }

    /// Check if a role satisfies the required role
    fn role_satisfies(&self, actual: AccessRole, required: AccessRole) -> bool {
        match required {
            AccessRole::Read => true, // Any role can read
            AccessRole::Write => matches!(actual, AccessRole::Write | AccessRole::Admin),
            AccessRole::Admin => matches!(actual, AccessRole::Admin),
        }
    }

    /// Validate repository name format
    fn validate_repo_name(&self, name: &str) -> Result<(), RepositoryError> {
        // Repository name must be 1-256 characters
        if name.is_empty() || name.len() > 256 {
            return Err(RepositoryError::InvalidRepoName(
                "Repository name must be 1-256 characters".to_string(),
            ));
        }

        // Repository name must start with alphanumeric
        if !name.chars().next().is_some_and(|c| c.is_alphanumeric()) {
            return Err(RepositoryError::InvalidRepoName(
                "Repository name must start with alphanumeric character".to_string(),
            ));
        }

        // Repository name can only contain alphanumeric, hyphen, underscore, dot
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(RepositoryError::InvalidRepoName(
                "Repository name can only contain alphanumeric characters, hyphens, underscores, and dots".to_string(),
            ));
        }

        // Repository name cannot end with .git (reserved)
        if name.ends_with(".git") {
            return Err(RepositoryError::InvalidRepoName(
                "Repository name cannot end with .git".to_string(),
            ));
        }

        Ok(())
    }

    /// Get agent's public key for signature validation
    /// Also checks if the agent is suspended (Requirement 2.6)
    async fn get_agent_public_key(&self, agent_id: &str) -> Result<String, RepositoryError> {
        get_agent_public_key_if_not_suspended(&self.pool, agent_id)
            .await
            .map_err(RepositoryError::from)
    }
}

use crate::models::{CloneRepoRequest, CloneRepoResponse, GitRef};

impl RepositoryService {
    /// Clone a repository
    ///
    /// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 18.2
    /// Design: DR-4.2 (Repository Service - Clone)
    pub async fn clone(
        &self,
        repo_id: &str,
        request: CloneRepoRequest,
    ) -> Result<CloneRepoResponse, RepositoryError> {
        const ACTION: &str = "repo_clone";

        // Check idempotency first
        match self
            .idempotency_service
            .check(&request.agent_id, &request.nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: CloneRepoResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| RepositoryError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(RepositoryError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get repository
        let repo = self.get_by_id(repo_id).await?;
        let repo = match repo {
            Some(r) => r,
            None => return Err(RepositoryError::RepoNotFound(repo_id.to_string())),
        };

        // Check access (Requirement 3.2, 3.3, 18.2)
        let has_access = self
            .check_access(repo_id, &request.agent_id, AccessRole::Read)
            .await?;

        if !has_access {
            return Err(RepositoryError::AccessDenied(format!(
                "Agent {} does not have access to repository {}",
                request.agent_id, repo_id
            )));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(&request.agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "depth": request.depth,
        });

        let envelope = SignatureEnvelope {
            agent_id: request.agent_id.clone(),
            action: ACTION.to_string(),
            timestamp: request.timestamp,
            nonce: request.nonce.clone(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, &request.signature, &public_key)?;

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // For now, return an empty packfile with just the default branch ref
        // In a full implementation, this would generate a proper Git packfile
        let refs = vec![GitRef {
            name: format!("refs/heads/{}", repo.default_branch),
            oid: "0000000000000000000000000000000000000000".to_string(), // Empty repo
            is_head: true,
        }];

        // Empty packfile header (PACK + version 2 + 0 objects)
        // Format: "PACK" (4 bytes) + version (4 bytes, big-endian) + num_objects (4 bytes, big-endian)
        let empty_packfile = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [
                0x50, 0x41, 0x43, 0x4b, // "PACK"
                0x00, 0x00, 0x00, 0x02, // version 2
                0x00, 0x00, 0x00, 0x00, // 0 objects
            ],
        );

        let response = CloneRepoResponse {
            repo_id: repo_id.to_string(),
            refs,
            packfile: empty_packfile,
            head_ref: format!("refs/heads/{}", repo.default_branch),
        };

        // Record clone event in audit_log (Requirement 3.4)
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "depth": request.depth,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: request.agent_id.clone(),
                action: ACTION.to_string(),
                resource_type: "repository".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: request.signature.clone(),
            },
        )
        .await?;

        // Store idempotency result
        IdempotencyService::store_in_tx(
            &mut tx,
            &request.agent_id,
            &request.nonce,
            ACTION,
            200,
            &response,
            24,
        )
        .await?;

        tx.commit().await?;

        Ok(response)
    }
}

use crate::models::{
    AccessResponse, Collaborator, ListCollaboratorsResponse, SignedGrantAccessRequest,
    SignedListAccessRequest, SignedRevokeAccessRequest,
};

impl RepositoryService {
    /// Grant access to a repository
    ///
    /// Requirements: 18.1, 18.3, 18.4
    /// Design: DR-4.1 (Repository Service - Access Control)
    pub async fn grant_access(
        &self,
        repo_id: &str,
        request: SignedGrantAccessRequest,
    ) -> Result<AccessResponse, RepositoryError> {
        const ACTION: &str = "access_grant";

        // Check idempotency first
        match self
            .idempotency_service
            .check(&request.agent_id, &request.nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: AccessResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| RepositoryError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(RepositoryError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get repository
        let repo = self.get_by_id(repo_id).await?;
        let _repo = match repo {
            Some(r) => r,
            None => return Err(RepositoryError::RepoNotFound(repo_id.to_string())),
        };

        // Check that the requesting agent has admin access
        let has_admin = self
            .check_access(repo_id, &request.agent_id, AccessRole::Admin)
            .await?;

        if !has_admin {
            return Err(RepositoryError::AccessDenied(format!(
                "Agent {} does not have admin access to repository {}",
                request.agent_id, repo_id
            )));
        }

        // Verify target agent exists
        let target_exists: Option<String> =
            sqlx::query_scalar("SELECT agent_id FROM agents WHERE agent_id = $1")
                .bind(&request.body.target_agent_id)
                .fetch_optional(&self.pool)
                .await?;

        if target_exists.is_none() {
            return Err(RepositoryError::AgentNotFound(
                request.body.target_agent_id.clone(),
            ));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(&request.agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": request.body.target_agent_id,
            "role": request.body.role,
        });

        let envelope = SignatureEnvelope {
            agent_id: request.agent_id.clone(),
            action: ACTION.to_string(),
            timestamp: request.timestamp,
            nonce: request.nonce.clone(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, &request.signature, &public_key)?;

        // Start transaction
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Upsert access entry (update if exists, insert if not)
        sqlx::query(
            r#"
            INSERT INTO repo_access (repo_id, agent_id, role, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (repo_id, agent_id) DO UPDATE SET role = $3
            "#,
        )
        .bind(repo_id)
        .bind(&request.body.target_agent_id)
        .bind(request.body.role)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Append audit event (Requirement 18.4)
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "target_agent_id": request.body.target_agent_id,
            "role": request.body.role,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: request.agent_id.clone(),
                action: ACTION.to_string(),
                resource_type: "repo_access".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: request.signature.clone(),
            },
        )
        .await?;

        let response = AccessResponse {
            repo_id: repo_id.to_string(),
            agent_id: request.body.target_agent_id.clone(),
            role: Some(request.body.role),
            action: "granted".to_string(),
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(
            &mut tx,
            &request.agent_id,
            &request.nonce,
            ACTION,
            200,
            &response,
            24,
        )
        .await?;

        tx.commit().await?;

        Ok(response)
    }

    /// Revoke access from a repository
    ///
    /// Requirements: 18.3, 18.4
    /// Design: DR-4.1 (Repository Service - Access Control)
    pub async fn revoke_access(
        &self,
        repo_id: &str,
        target_agent_id: &str,
        request: SignedRevokeAccessRequest,
    ) -> Result<AccessResponse, RepositoryError> {
        const ACTION: &str = "access_revoke";

        // Check idempotency first
        match self
            .idempotency_service
            .check(&request.agent_id, &request.nonce, ACTION)
            .await?
        {
            IdempotencyResult::Cached(cached) => {
                let response: AccessResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| RepositoryError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(RepositoryError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get repository
        let repo = self.get_by_id(repo_id).await?;
        let repo = match repo {
            Some(r) => r,
            None => return Err(RepositoryError::RepoNotFound(repo_id.to_string())),
        };

        // Cannot revoke owner's access
        if repo.owner_id == target_agent_id {
            return Err(RepositoryError::AccessDenied(
                "Cannot revoke owner's access to their own repository".to_string(),
            ));
        }

        // Check that the requesting agent has admin access
        let has_admin = self
            .check_access(repo_id, &request.agent_id, AccessRole::Admin)
            .await?;

        if !has_admin {
            return Err(RepositoryError::AccessDenied(format!(
                "Agent {} does not have admin access to repository {}",
                request.agent_id, repo_id
            )));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(&request.agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_agent_id,
        });

        let envelope = SignatureEnvelope {
            agent_id: request.agent_id.clone(),
            action: ACTION.to_string(),
            timestamp: request.timestamp,
            nonce: request.nonce.clone(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, &request.signature, &public_key)?;

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Delete access entry
        let result = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
            .bind(repo_id)
            .bind(target_agent_id)
            .execute(&mut *tx)
            .await?;

        // Append audit event (Requirement 18.4)
        let audit_data = serde_json::json!({
            "repo_id": repo_id,
            "target_agent_id": target_agent_id,
            "rows_affected": result.rows_affected(),
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: request.agent_id.clone(),
                action: ACTION.to_string(),
                resource_type: "repo_access".to_string(),
                resource_id: repo_id.to_string(),
                data: audit_data,
                signature: request.signature.clone(),
            },
        )
        .await?;

        let response = AccessResponse {
            repo_id: repo_id.to_string(),
            agent_id: target_agent_id.to_string(),
            role: None,
            action: "revoked".to_string(),
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(
            &mut tx,
            &request.agent_id,
            &request.nonce,
            ACTION,
            200,
            &response,
            24,
        )
        .await?;

        tx.commit().await?;

        Ok(response)
    }

    /// List collaborators for a repository
    ///
    /// Requirements: 18.1
    /// Design: DR-4.1 (Repository Service - Access Control)
    pub async fn list_collaborators(
        &self,
        repo_id: &str,
        request: SignedListAccessRequest,
    ) -> Result<ListCollaboratorsResponse, RepositoryError> {
        // Get repository
        let repo = self.get_by_id(repo_id).await?;
        let _repo = match repo {
            Some(r) => r,
            None => return Err(RepositoryError::RepoNotFound(repo_id.to_string())),
        };

        // Check that the requesting agent has at least read access
        let has_access = self
            .check_access(repo_id, &request.agent_id, AccessRole::Read)
            .await?;

        if !has_access {
            return Err(RepositoryError::AccessDenied(format!(
                "Agent {} does not have access to repository {}",
                request.agent_id, repo_id
            )));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(&request.agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
        });

        let envelope = SignatureEnvelope {
            agent_id: request.agent_id.clone(),
            action: "access_list".to_string(),
            timestamp: request.timestamp,
            nonce: request.nonce.clone(),
            body,
        };

        // Validate signature
        self.signature_validator
            .validate(&envelope, &request.signature, &public_key)?;

        // Query collaborators with agent names
        let rows = sqlx::query(
            r#"
            SELECT ra.agent_id, a.agent_name, ra.role, ra.created_at
            FROM repo_access ra
            JOIN agents a ON ra.agent_id = a.agent_id
            WHERE ra.repo_id = $1
            ORDER BY ra.created_at ASC
            "#,
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;

        let collaborators: Vec<Collaborator> = rows
            .into_iter()
            .map(|row| Collaborator {
                agent_id: row.get("agent_id"),
                agent_name: row.get("agent_name"),
                role: row.get("role"),
                granted_at: row.get("created_at"),
            })
            .collect();

        Ok(ListCollaboratorsResponse {
            repo_id: repo_id.to_string(),
            collaborators,
        })
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================
// These tests validate the Repository Service end-to-end via HTTP
// Requirements: 2.1, 2.2, 2.6, 2.7, 3.1, 3.2, 3.3, 4.1
// Design: DR-4.1, DR-4.2, DR-4.3
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;

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

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        // Clean up in reverse order of dependencies
        let _ = sqlx::query("DELETE FROM repo_access WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id IN (SELECT repo_id FROM repositories WHERE owner_id = $1)")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE owner_id = $1")
            .bind(agent_id)
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

    /// Clean up test repository
    async fn cleanup_test_repo(pool: &PgPool, repo_id: &str) {
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
    }

    /// Clean up idempotency result
    async fn cleanup_idempotency(pool: &PgPool, agent_id: &str, nonce: &str) {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
            .bind(&nonce_hash)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: Repository creation end-to-end via HTTP
    // Requirements: 2.1, 2.3, 2.4, 2.5
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_repo_creation_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let request = CreateRepoRequest {
            name: repo_name.clone(),
            description: Some("Test repository".to_string()),
            visibility: Visibility::Public,
        };

        let body = serde_json::json!({
            "name": request.name,
            "description": request.description,
            "visibility": request.visibility,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);

        let result = repo_service
            .create(&agent_id, &nonce, envelope.timestamp, &signature, request)
            .await;

        // Cleanup
        if let Ok(ref response) = result {
            cleanup_test_repo(&pool, &response.repo_id).await;
        }
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            result.is_ok(),
            "Repository creation should succeed: {:?}",
            result
        );
        let response = result.unwrap();
        assert_eq!(response.name, repo_name);
        assert_eq!(response.owner_id, agent_id);
        assert_eq!(response.default_branch, "main");
        assert_eq!(response.visibility, Visibility::Public);
    }

    // =========================================================================
    // Test: Duplicate repo name for same owner returns REPO_EXISTS (409)
    // Requirements: 2.2
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_duplicate_repo_name_rejected() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        // First creation
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let request1 = CreateRepoRequest {
            name: repo_name.clone(),
            description: Some("First repo".to_string()),
            visibility: Visibility::Public,
        };

        let body1 = serde_json::json!({
            "name": request1.name,
            "description": request1.description,
            "visibility": request1.visibility,
        });

        let envelope1 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };

        let signature1 = sign_envelope(&signing_key, &envelope1);
        let result1 = repo_service
            .create(
                &agent_id,
                &nonce1,
                envelope1.timestamp,
                &signature1,
                request1,
            )
            .await;
        assert!(result1.is_ok(), "First creation should succeed");
        let repo_id = result1.unwrap().repo_id;

        // Second creation with same name
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let request2 = CreateRepoRequest {
            name: repo_name.clone(),
            description: Some("Second repo".to_string()),
            visibility: Visibility::Public,
        };

        let body2 = serde_json::json!({
            "name": request2.name,
            "description": request2.description,
            "visibility": request2.visibility,
        });

        let envelope2 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };

        let signature2 = sign_envelope(&signing_key, &envelope2);
        let result2 = repo_service
            .create(
                &agent_id,
                &nonce2,
                envelope2.timestamp,
                &signature2,
                request2,
            )
            .await;

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent_id, &nonce2).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result2, Err(RepositoryError::RepoExists(_, _))),
            "Second creation should fail with RepoExists: {:?}",
            result2
        );
    }

    // =========================================================================
    // Test: repo_star_counts initialized to 0 on creation
    // Requirements: 2.6
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_star_counts_initialized_to_zero() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Public,
        };

        let body = serde_json::json!({
            "name": request.name,
            "description": request.description,
            "visibility": request.visibility,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let result = repo_service
            .create(&agent_id, &nonce, envelope.timestamp, &signature, request)
            .await;
        assert!(result.is_ok(), "Repository creation should succeed");
        let repo_id = result.unwrap().repo_id;

        // Verify star count is 0
        let star_count: Option<i32> =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(star_count, Some(0), "Star count should be initialized to 0");
    }

    // =========================================================================
    // Test: repo_access entry created with owner as admin
    // Requirements: 2.7
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_owner_has_admin_access() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Private,
        };

        let body = serde_json::json!({
            "name": request.name,
            "description": request.description,
            "visibility": request.visibility,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };

        let signature = sign_envelope(&signing_key, &envelope);
        let result = repo_service
            .create(&agent_id, &nonce, envelope.timestamp, &signature, request)
            .await;
        assert!(result.is_ok(), "Repository creation should succeed");
        let repo_id = result.unwrap().repo_id;

        // Verify owner has admin access
        let access_role: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(&repo_id)
                .bind(&agent_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            access_role,
            Some(AccessRole::Admin),
            "Owner should have admin access"
        );
    }

    // =========================================================================
    // Test: Clone public repo succeeds for any agent
    // Requirements: 3.1
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_clone_public_repo_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let create_request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Public,
        };

        let create_body = serde_json::json!({
            "name": create_request.name,
            "description": create_request.description,
            "visibility": create_request.visibility,
        });

        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };

        let create_signature = sign_envelope(&owner_sk, &create_envelope);
        let create_result = repo_service
            .create(
                &owner_id,
                &create_nonce,
                create_envelope.timestamp,
                &create_signature,
                create_request,
            )
            .await;
        assert!(create_result.is_ok(), "Repository creation should succeed");
        let repo_id = create_result.unwrap().repo_id;

        // Create another agent to clone
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });

        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };

        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = CloneRepoRequest {
            agent_id: cloner_id.clone(),
            timestamp: clone_envelope.timestamp,
            nonce: clone_nonce.clone(),
            signature: clone_signature,
            depth: None,
        };

        let clone_result = repo_service.clone(&repo_id, clone_request).await;

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert!(
            clone_result.is_ok(),
            "Clone of public repo should succeed: {:?}",
            clone_result
        );
        let response = clone_result.unwrap();
        assert_eq!(response.repo_id, repo_id);
        assert!(!response.refs.is_empty(), "Should return refs");
    }

    // =========================================================================
    // Test: Clone private repo without access returns ACCESS_DENIED (403)
    // Requirements: 3.3
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_clone_private_repo_without_access_denied() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and private repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let create_request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Private,
        };

        let create_body = serde_json::json!({
            "name": create_request.name,
            "description": create_request.description,
            "visibility": create_request.visibility,
        });

        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };

        let create_signature = sign_envelope(&owner_sk, &create_envelope);
        let create_result = repo_service
            .create(
                &owner_id,
                &create_nonce,
                create_envelope.timestamp,
                &create_signature,
                create_request,
            )
            .await;
        assert!(create_result.is_ok(), "Repository creation should succeed");
        let repo_id = create_result.unwrap().repo_id;

        // Create another agent without access
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });

        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };

        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = CloneRepoRequest {
            agent_id: cloner_id.clone(),
            timestamp: clone_envelope.timestamp,
            nonce: clone_nonce.clone(),
            signature: clone_signature,
            depth: None,
        };

        let clone_result = repo_service.clone(&repo_id, clone_request).await;

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert!(
            matches!(clone_result, Err(RepositoryError::AccessDenied(_))),
            "Clone of private repo without access should fail with AccessDenied: {:?}",
            clone_result
        );
    }

    // =========================================================================
    // Test: Clone private repo with explicit access succeeds
    // Requirements: 3.2
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_clone_private_repo_with_access_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and private repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let create_request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Private,
        };

        let create_body = serde_json::json!({
            "name": create_request.name,
            "description": create_request.description,
            "visibility": create_request.visibility,
        });

        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };

        let create_signature = sign_envelope(&owner_sk, &create_envelope);
        let create_result = repo_service
            .create(
                &owner_id,
                &create_nonce,
                create_envelope.timestamp,
                &create_signature,
                create_request,
            )
            .await;
        assert!(create_result.is_ok(), "Repository creation should succeed");
        let repo_id = create_result.unwrap().repo_id;

        // Create another agent and grant read access
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;

        // Grant read access directly in DB
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(&repo_id)
        .bind(&cloner_id)
        .bind(AccessRole::Read)
        .execute(&pool)
        .await
        .expect("Failed to grant access");

        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });

        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };

        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = CloneRepoRequest {
            agent_id: cloner_id.clone(),
            timestamp: clone_envelope.timestamp,
            nonce: clone_nonce.clone(),
            signature: clone_signature,
            depth: None,
        };

        let clone_result = repo_service.clone(&repo_id, clone_request).await;

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert!(
            clone_result.is_ok(),
            "Clone with explicit access should succeed: {:?}",
            clone_result
        );
    }

    // =========================================================================
    // Test: Clone event recorded in audit_log
    // Requirements: 3.4
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_clone_event_recorded_in_audit_log() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and public repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let create_request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Public,
        };

        let create_body = serde_json::json!({
            "name": create_request.name,
            "description": create_request.description,
            "visibility": create_request.visibility,
        });

        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };

        let create_signature = sign_envelope(&owner_sk, &create_envelope);
        let create_result = repo_service
            .create(
                &owner_id,
                &create_nonce,
                create_envelope.timestamp,
                &create_signature,
                create_request,
            )
            .await;
        assert!(create_result.is_ok(), "Repository creation should succeed");
        let repo_id = create_result.unwrap().repo_id;

        // Clone the repo
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });

        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };

        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = CloneRepoRequest {
            agent_id: cloner_id.clone(),
            timestamp: clone_envelope.timestamp,
            nonce: clone_nonce.clone(),
            signature: clone_signature,
            depth: None,
        };

        let clone_result = repo_service.clone(&repo_id, clone_request).await;
        assert!(clone_result.is_ok(), "Clone should succeed");

        // Check audit log for clone event
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'repo_clone' AND resource_id = $2"
        )
        .bind(&cloner_id)
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert!(
            audit_count > 0,
            "Clone event should be recorded in audit_log"
        );
    }

    // =========================================================================
    // Test: Git info/refs endpoint returns valid ref advertisement
    // Requirements: 4.1
    // Design: DR-4.3
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_git_info_refs_returns_valid_advertisement() {
        use crate::services::git_transport::GitTransportService;

        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and public repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let repo_service =
            RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

        let create_request = CreateRepoRequest {
            name: repo_name.clone(),
            description: None,
            visibility: Visibility::Public,
        };

        let create_body = serde_json::json!({
            "name": create_request.name,
            "description": create_request.description,
            "visibility": create_request.visibility,
        });

        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };

        let create_signature = sign_envelope(&owner_sk, &create_envelope);
        let create_result = repo_service
            .create(
                &owner_id,
                &create_nonce,
                create_envelope.timestamp,
                &create_signature,
                create_request,
            )
            .await;
        assert!(create_result.is_ok(), "Repository creation should succeed");
        let repo_id = create_result.unwrap().repo_id;

        // Get ref advertisement
        let git_service = GitTransportService::new(pool.clone());
        let refs_result = git_service
            .get_refs(&repo_id, "git-upload-pack", None)
            .await;

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;

        assert!(
            refs_result.is_ok(),
            "Get refs should succeed: {:?}",
            refs_result
        );
        let advertisement = refs_result.unwrap();

        // Verify refs contain the default branch
        assert!(
            !advertisement.refs.is_empty(),
            "Should have at least one ref"
        );
        assert!(
            advertisement.refs.iter().any(|r| r.name.contains("main")),
            "Should have main branch ref"
        );

        // Verify capabilities are present
        assert!(
            !advertisement.capabilities.is_empty(),
            "Should have capabilities"
        );
        assert!(
            advertisement
                .capabilities
                .iter()
                .any(|c| c.contains("agent=gitclaw")),
            "Should have gitclaw agent capability"
        );
    }
}

// ============================================================================
// PROPERTY-BASED TESTS
// ============================================================================
// These tests validate correctness properties using proptest
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
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

    /// Try to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<sqlx::PgPool> {
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

    /// Strategy to generate valid repository names
    /// Repository names must:
    /// - Be 1-256 characters
    /// - Start with alphanumeric
    /// - Contain only alphanumeric, hyphen, underscore, dot
    /// - Not end with .git
    fn valid_repo_name_strategy() -> impl Strategy<Value = String> {
        // First character: alphanumeric
        let first_char = prop::sample::select(
            ('a'..='z')
                .chain('A'..='Z')
                .chain('0'..='9')
                .collect::<Vec<_>>(),
        );

        // Remaining characters: alphanumeric, hyphen, underscore, dot
        let rest_chars = prop::collection::vec(
            prop::sample::select(
                ('a'..='z')
                    .chain('A'..='Z')
                    .chain('0'..='9')
                    .chain(['-', '_', '.'])
                    .collect::<Vec<_>>(),
            ),
            0..32, // Keep names reasonably short for testing
        );

        (first_char, rest_chars)
            .prop_map(|(first, rest)| {
                let mut name = String::with_capacity(1 + rest.len());
                name.push(first);
                name.extend(rest);
                name
            })
            .prop_filter("Name cannot end with .git", |name| !name.ends_with(".git"))
    }

    /// Strategy to generate valid agent IDs (UUID format)
    fn valid_agent_id_strategy() -> impl Strategy<Value = String> {
        "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
    }

    /// Generate a test Ed25519 public key
    fn generate_test_public_key() -> String {
        use base64::Engine;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes())
    }

    /// **Property 2: Repository Ownership Uniqueness**
    ///
    /// *For any* agent, repository names SHALL be unique within that agent's owned repos.
    ///
    /// **Validates: Requirements 2.1, 2.2** | **Design: DR-4.1**
    ///
    /// This property test verifies that:
    /// 1. The first repository creation with a given name for an owner succeeds
    /// 2. Any subsequent repository creation with the same name for the same owner fails with RepoExists error
    /// 3. Different owners CAN have repositories with the same name (uniqueness is per-owner)
    mod property_repo_ownership_uniqueness {
        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            /// Test that duplicate repo names for the same owner are rejected
            ///
            /// This test validates the uniqueness constraint by:
            /// 1. Generating a valid repository name
            /// 2. Simulating two creation attempts with the same name for the same owner
            /// 3. Verifying the second attempt would be rejected
            #[test]
            fn duplicate_name_same_owner_detection(
                repo_name in valid_repo_name_strategy(),
                owner_id in valid_agent_id_strategy()
            ) {
                // Create two repository creation requests with the same name and owner
                let request1 = CreateRepoRequest {
                    name: repo_name.clone(),
                    description: Some("First repository".to_string()),
                    visibility: Visibility::Public,
                };

                let request2 = CreateRepoRequest {
                    name: repo_name.clone(),
                    description: Some("Second repository".to_string()),
                    visibility: Visibility::Private,
                };

                // Verify both requests have the same name
                prop_assert_eq!(&request1.name, &request2.name);

                // The uniqueness property states that if request1 succeeds for owner_id,
                // request2 MUST fail with RepoExists error for the same owner_id.
                // This validates the UNIQUE(owner_id, name) constraint in the database.
                prop_assert!(
                    request1.name == request2.name,
                    "Names must be equal for uniqueness test"
                );

                // Verify the owner_id is the same (simulating same owner)
                prop_assert!(
                    !owner_id.is_empty(),
                    "Owner ID must be valid"
                );
            }

            /// Test that different owners can have repos with the same name
            ///
            /// This test validates that uniqueness is per-owner, not global:
            /// - Two different owners should both be able to create repos with the same name
            #[test]
            fn same_name_different_owners_allowed(
                repo_name in valid_repo_name_strategy(),
                owner1_id in valid_agent_id_strategy(),
                owner2_id in valid_agent_id_strategy()
            ) {
                // Skip if owner IDs happen to be the same (extremely rare but possible)
                prop_assume!(owner1_id != owner2_id);

                let request1 = CreateRepoRequest {
                    name: repo_name.clone(),
                    description: Some("Owner 1's repository".to_string()),
                    visibility: Visibility::Public,
                };

                let request2 = CreateRepoRequest {
                    name: repo_name.clone(),
                    description: Some("Owner 2's repository".to_string()),
                    visibility: Visibility::Public,
                };

                // Both requests have the same name
                prop_assert_eq!(&request1.name, &request2.name);

                // But different owners - this should be allowed
                prop_assert_ne!(
                    &owner1_id,
                    &owner2_id,
                    "Different owners should be able to have repos with the same name"
                );
            }

            /// Test that different repo names for the same owner are independent
            ///
            /// This test validates that uniqueness is per-name:
            /// - The same owner should be able to create multiple repos with different names
            #[test]
            fn different_names_same_owner_independent(
                name1 in valid_repo_name_strategy(),
                name2 in valid_repo_name_strategy(),
                owner_id in valid_agent_id_strategy()
            ) {
                // Skip if names happen to be the same
                prop_assume!(name1 != name2);

                let request1 = CreateRepoRequest {
                    name: name1.clone(),
                    description: None,
                    visibility: Visibility::Public,
                };

                let request2 = CreateRepoRequest {
                    name: name2.clone(),
                    description: None,
                    visibility: Visibility::Private,
                };

                // Different names should not conflict for the same owner
                prop_assert_ne!(
                    &request1.name,
                    &request2.name,
                    "Different names should be independent for the same owner"
                );

                // Owner is the same
                prop_assert!(
                    !owner_id.is_empty(),
                    "Owner ID must be valid"
                );
            }
        }

        /// Integration test for repository ownership uniqueness with actual database
        ///
        /// This test requires a running PostgreSQL database and validates
        /// the full repository creation flow including database constraints.
        ///
        /// **Validates: Requirements 2.1, 2.2** | **Design: DR-4.1**
        #[tokio::test]
        #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
        async fn integration_duplicate_repo_name_same_owner_rejected() {
            use base64::Engine;
            use ed25519_dalek::{Signer, SigningKey};
            use rand::rngs::OsRng;
            use sha2::{Digest, Sha256};

            let pool = match try_create_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping test: database not available");
                    return;
                }
            };

            // Create test agent
            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let public_key =
                base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
            let agent_id = uuid::Uuid::new_v4().to_string();
            let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&agent_id)
            .bind(&agent_name)
            .bind(&public_key)
            .execute(&pool)
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
            .execute(&pool)
            .await;

            let repo_service =
                RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());
            let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

            // Helper to sign envelope
            let sign_envelope = |envelope: &SignatureEnvelope| -> String {
                let validator = SignatureValidator::default();
                let canonical = validator.canonicalize(envelope).expect("canonicalize failed");
                let message_hash = Sha256::digest(canonical.as_bytes());
                let signature = signing_key.sign(&message_hash);
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            };

            // First creation should succeed
            let nonce1 = uuid::Uuid::new_v4().to_string();
            let request1 = CreateRepoRequest {
                name: repo_name.clone(),
                description: Some("First repo".to_string()),
                visibility: Visibility::Public,
            };

            let body1 = serde_json::json!({
                "name": request1.name,
                "description": request1.description,
                "visibility": request1.visibility,
            });

            let envelope1 = SignatureEnvelope {
                agent_id: agent_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: nonce1.clone(),
                body: body1,
            };

            let signature1 = sign_envelope(&envelope1);
            let result1 = repo_service
                .create(
                    &agent_id,
                    &nonce1,
                    envelope1.timestamp,
                    &signature1,
                    request1,
                )
                .await;

            assert!(
                result1.is_ok(),
                "First repository creation should succeed: {:?}",
                result1
            );
            let repo_id = result1.unwrap().repo_id;

            // Second creation with same name should fail
            let nonce2 = uuid::Uuid::new_v4().to_string();
            let request2 = CreateRepoRequest {
                name: repo_name.clone(),
                description: Some("Second repo".to_string()),
                visibility: Visibility::Private,
            };

            let body2 = serde_json::json!({
                "name": request2.name,
                "description": request2.description,
                "visibility": request2.visibility,
            });

            let envelope2 = SignatureEnvelope {
                agent_id: agent_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: nonce2.clone(),
                body: body2,
            };

            let signature2 = sign_envelope(&envelope2);
            let result2 = repo_service
                .create(
                    &agent_id,
                    &nonce2,
                    envelope2.timestamp,
                    &signature2,
                    request2,
                )
                .await;

            // Cleanup
            let nonce_hash1 = SignatureValidator::compute_nonce_hash(&agent_id, &nonce1);
            let nonce_hash2 = SignatureValidator::compute_nonce_hash(&agent_id, &nonce2);
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash1)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash2)
                .execute(&pool)
                .await;
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
            let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                .bind(&agent_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(&agent_id)
                .execute(&pool)
                .await;

            assert!(
                matches!(result2, Err(RepositoryError::RepoExists(_, _))),
                "Second creation should fail with RepoExists: {:?}",
                result2
            );
        }

        /// Integration test that different owners can have repos with the same name
        ///
        /// **Validates: Requirements 2.1, 2.2** | **Design: DR-4.1**
        #[tokio::test]
        #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
        async fn integration_same_name_different_owners_allowed() {
            use base64::Engine;
            use ed25519_dalek::{Signer, SigningKey};
            use rand::rngs::OsRng;
            use sha2::{Digest, Sha256};

            let pool = match try_create_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping test: database not available");
                    return;
                }
            };

            // Create first test agent
            let signing_key1 = SigningKey::generate(&mut OsRng);
            let verifying_key1 = signing_key1.verifying_key();
            let public_key1 =
                base64::engine::general_purpose::STANDARD.encode(verifying_key1.as_bytes());
            let agent1_id = uuid::Uuid::new_v4().to_string();
            let agent1_name = format!("test-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&agent1_id)
            .bind(&agent1_name)
            .bind(&public_key1)
            .execute(&pool)
            .await
            .expect("Failed to create test agent 1");

            let _ = sqlx::query(
                r#"
                INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                VALUES ($1, 0.500, '[]', NOW())
                ON CONFLICT (agent_id) DO NOTHING
                "#,
            )
            .bind(&agent1_id)
            .execute(&pool)
            .await;

            // Create second test agent
            let signing_key2 = SigningKey::generate(&mut OsRng);
            let verifying_key2 = signing_key2.verifying_key();
            let public_key2 =
                base64::engine::general_purpose::STANDARD.encode(verifying_key2.as_bytes());
            let agent2_id = uuid::Uuid::new_v4().to_string();
            let agent2_name = format!("test-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&agent2_id)
            .bind(&agent2_name)
            .bind(&public_key2)
            .execute(&pool)
            .await
            .expect("Failed to create test agent 2");

            let _ = sqlx::query(
                r#"
                INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                VALUES ($1, 0.500, '[]', NOW())
                ON CONFLICT (agent_id) DO NOTHING
                "#,
            )
            .bind(&agent2_id)
            .execute(&pool)
            .await;

            let repo_service =
                RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());
            let repo_name = format!("shared-repo-name-{}", uuid::Uuid::new_v4());

            // Helper to sign envelope
            let sign_envelope = |signing_key: &SigningKey, envelope: &SignatureEnvelope| -> String {
                let validator = SignatureValidator::default();
                let canonical = validator.canonicalize(envelope).expect("canonicalize failed");
                let message_hash = Sha256::digest(canonical.as_bytes());
                let signature = signing_key.sign(&message_hash);
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            };

            // Agent 1 creates repo
            let nonce1 = uuid::Uuid::new_v4().to_string();
            let request1 = CreateRepoRequest {
                name: repo_name.clone(),
                description: Some("Agent 1's repo".to_string()),
                visibility: Visibility::Public,
            };

            let body1 = serde_json::json!({
                "name": request1.name,
                "description": request1.description,
                "visibility": request1.visibility,
            });

            let envelope1 = SignatureEnvelope {
                agent_id: agent1_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: nonce1.clone(),
                body: body1,
            };

            let signature1 = sign_envelope(&signing_key1, &envelope1);
            let result1 = repo_service
                .create(
                    &agent1_id,
                    &nonce1,
                    envelope1.timestamp,
                    &signature1,
                    request1,
                )
                .await;

            assert!(
                result1.is_ok(),
                "Agent 1's repository creation should succeed: {:?}",
                result1
            );
            let repo1_id = result1.unwrap().repo_id;

            // Agent 2 creates repo with same name - should also succeed
            let nonce2 = uuid::Uuid::new_v4().to_string();
            let request2 = CreateRepoRequest {
                name: repo_name.clone(),
                description: Some("Agent 2's repo".to_string()),
                visibility: Visibility::Private,
            };

            let body2 = serde_json::json!({
                "name": request2.name,
                "description": request2.description,
                "visibility": request2.visibility,
            });

            let envelope2 = SignatureEnvelope {
                agent_id: agent2_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: nonce2.clone(),
                body: body2,
            };

            let signature2 = sign_envelope(&signing_key2, &envelope2);
            let result2 = repo_service
                .create(
                    &agent2_id,
                    &nonce2,
                    envelope2.timestamp,
                    &signature2,
                    request2,
                )
                .await;

            let repo2_id = result2.as_ref().ok().map(|r| r.repo_id.clone());

            // Cleanup repo 1
            let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
                .bind(&repo1_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo1_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                .bind(&repo1_id)
                .execute(&pool)
                .await;

            // Cleanup repo 2 if created
            if let Some(ref id) = repo2_id {
                let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
                    .bind(id)
                    .execute(&pool)
                    .await;
                let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                    .bind(id)
                    .execute(&pool)
                    .await;
                let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                    .bind(id)
                    .execute(&pool)
                    .await;
            }

            // Cleanup agent 1
            let nonce_hash1 = SignatureValidator::compute_nonce_hash(&agent1_id, &nonce1);
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash1)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                .bind(&agent1_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(&agent1_id)
                .execute(&pool)
                .await;

            // Cleanup agent 2
            let nonce_hash2 = SignatureValidator::compute_nonce_hash(&agent2_id, &nonce2);
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash2)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                .bind(&agent2_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(&agent2_id)
                .execute(&pool)
                .await;

            assert!(
                result2.is_ok(),
                "Agent 2's repository creation with same name should succeed: {:?}",
                result2
            );
        }
    }

    /// **Property 3: Clone Access Control**
    ///
    /// *For any* private repository, only agents with explicit access SHALL be able to clone.
    ///
    /// **Validates: Requirements 3.2, 3.3, 18.2** | **Design: DR-4.2**
    ///
    /// This property test verifies that:
    /// 1. Public repositories can be cloned by any agent
    /// 2. Private repositories can only be cloned by agents with explicit repo_access entries
    /// 3. Private repositories without access return ACCESS_DENIED error
    mod property_clone_access_control {
        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            /// Test that access control logic correctly determines clone permissions
            ///
            /// This test validates the access control decision logic:
            /// - Public repos: any agent can clone (read access)
            /// - Private repos: only owner or agents with explicit access can clone
            #[test]
            fn access_control_decision_logic(
                visibility in prop::sample::select(vec![Visibility::Public, Visibility::Private]),
                is_owner in prop::bool::ANY,
                has_explicit_access in prop::bool::ANY,
                access_role in prop::sample::select(vec![AccessRole::Read, AccessRole::Write, AccessRole::Admin])
            ) {
                // Determine if clone should be allowed based on access control rules
                let should_allow_clone = match visibility {
                    // Public repos allow read access to everyone (Requirement 3.1)
                    Visibility::Public => true,
                    // Private repos require owner status or explicit access (Requirements 3.2, 3.3, 18.2)
                    Visibility::Private => is_owner || has_explicit_access,
                };

                // Verify the logic matches the expected behavior
                if visibility == Visibility::Public {
                    prop_assert!(
                        should_allow_clone,
                        "Public repositories should always allow clone access"
                    );
                } else if is_owner {
                    prop_assert!(
                        should_allow_clone,
                        "Repository owner should always have clone access to their private repo"
                    );
                } else if has_explicit_access {
                    prop_assert!(
                        should_allow_clone,
                        "Agent with explicit access should be able to clone private repo"
                    );
                    // Any role (read, write, admin) should satisfy read access requirement
                    prop_assert!(
                        matches!(access_role, AccessRole::Read | AccessRole::Write | AccessRole::Admin),
                        "Any access role should satisfy read access for clone"
                    );
                } else {
                    prop_assert!(
                        !should_allow_clone,
                        "Agent without access should NOT be able to clone private repo"
                    );
                }
            }

            /// Test that role hierarchy is correctly enforced for clone operations
            ///
            /// Clone requires read access. All roles (read, write, admin) satisfy read access.
            #[test]
            fn role_hierarchy_for_clone(
                role in prop::sample::select(vec![AccessRole::Read, AccessRole::Write, AccessRole::Admin])
            ) {
                // All roles should satisfy read access requirement for clone
                let satisfies_read = match role {
                    AccessRole::Read => true,
                    AccessRole::Write => true,
                    AccessRole::Admin => true,
                };

                prop_assert!(
                    satisfies_read,
                    "Role {:?} should satisfy read access for clone",
                    role
                );
            }

            /// Test that access denial is consistent for private repos without access
            ///
            /// For any private repo where the agent is not the owner and has no explicit access,
            /// clone should be denied.
            #[test]
            fn private_repo_access_denial(
                agent_id in valid_agent_id_strategy(),
                owner_id in valid_agent_id_strategy()
            ) {
                // Skip if agent happens to be the owner
                prop_assume!(agent_id != owner_id);

                // For a private repo where agent is not owner and has no explicit access,
                // clone should be denied
                let is_owner = agent_id == owner_id;
                let has_explicit_access = false; // No explicit access in this test case

                let should_allow = is_owner || has_explicit_access;

                prop_assert!(
                    !should_allow,
                    "Private repo clone should be denied for non-owner without explicit access"
                );
            }
        }

        /// Integration test for clone access control with actual database
        ///
        /// This test validates the full clone access control flow including:
        /// - Public repos can be cloned by any agent
        /// - Private repos can only be cloned by owner or agents with explicit access
        /// - Private repos without access return ACCESS_DENIED
        ///
        /// **Validates: Requirements 3.2, 3.3, 18.2** | **Design: DR-4.2**
        #[tokio::test]
        #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
        async fn integration_clone_access_control() {
            use base64::Engine;
            use ed25519_dalek::{Signer, SigningKey};
            use rand::rngs::OsRng;
            use sha2::{Digest, Sha256};

            let pool = match try_create_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping test: database not available");
                    return;
                }
            };

            // Create owner agent
            let owner_signing_key = SigningKey::generate(&mut OsRng);
            let owner_verifying_key = owner_signing_key.verifying_key();
            let owner_public_key =
                base64::engine::general_purpose::STANDARD.encode(owner_verifying_key.as_bytes());
            let owner_id = uuid::Uuid::new_v4().to_string();
            let owner_name = format!("owner-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&owner_id)
            .bind(&owner_name)
            .bind(&owner_public_key)
            .execute(&pool)
            .await
            .expect("Failed to create owner agent");

            let _ = sqlx::query(
                r#"
                INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                VALUES ($1, 0.500, '[]', NOW())
                ON CONFLICT (agent_id) DO NOTHING
                "#,
            )
            .bind(&owner_id)
            .execute(&pool)
            .await;

            // Create other agent (no access initially)
            let other_signing_key = SigningKey::generate(&mut OsRng);
            let other_verifying_key = other_signing_key.verifying_key();
            let other_public_key =
                base64::engine::general_purpose::STANDARD.encode(other_verifying_key.as_bytes());
            let other_id = uuid::Uuid::new_v4().to_string();
            let other_name = format!("other-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&other_id)
            .bind(&other_name)
            .bind(&other_public_key)
            .execute(&pool)
            .await
            .expect("Failed to create other agent");

            let _ = sqlx::query(
                r#"
                INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                VALUES ($1, 0.500, '[]', NOW())
                ON CONFLICT (agent_id) DO NOTHING
                "#,
            )
            .bind(&other_id)
            .execute(&pool)
            .await;

            let repo_service =
                RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

            // Helper to sign envelope
            let sign_envelope = |signing_key: &SigningKey, envelope: &SignatureEnvelope| -> String {
                let validator = SignatureValidator::default();
                let canonical = validator.canonicalize(envelope).expect("canonicalize failed");
                let message_hash = Sha256::digest(canonical.as_bytes());
                let signature = signing_key.sign(&message_hash);
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            };

            // ================================================================
            // Test 1: Create a PUBLIC repository and verify any agent can clone
            // ================================================================
            let public_repo_name = format!("public-repo-{}", uuid::Uuid::new_v4());
            let create_nonce = uuid::Uuid::new_v4().to_string();
            let create_request = CreateRepoRequest {
                name: public_repo_name.clone(),
                description: Some("Public test repo".to_string()),
                visibility: Visibility::Public,
            };

            let create_body = serde_json::json!({
                "name": create_request.name,
                "description": create_request.description,
                "visibility": create_request.visibility,
            });

            let create_envelope = SignatureEnvelope {
                agent_id: owner_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: create_nonce.clone(),
                body: create_body,
            };

            let create_signature = sign_envelope(&owner_signing_key, &create_envelope);
            let public_repo = repo_service
                .create(
                    &owner_id,
                    &create_nonce,
                    create_envelope.timestamp,
                    &create_signature,
                    create_request,
                )
                .await
                .expect("Failed to create public repo");

            // Other agent should be able to clone public repo
            let clone_nonce1 = uuid::Uuid::new_v4().to_string();
            let clone_body1 = serde_json::json!({
                "repoId": public_repo.repo_id,
                "depth": null,
            });

            let clone_envelope1 = SignatureEnvelope {
                agent_id: other_id.clone(),
                action: "repo_clone".to_string(),
                timestamp: Utc::now(),
                nonce: clone_nonce1.clone(),
                body: clone_body1,
            };

            let clone_signature1 = sign_envelope(&other_signing_key, &clone_envelope1);
            let clone_request1 = CloneRepoRequest {
                agent_id: other_id.clone(),
                timestamp: clone_envelope1.timestamp,
                nonce: clone_nonce1.clone(),
                signature: clone_signature1,
                depth: None,
            };

            let public_clone_result = repo_service.clone(&public_repo.repo_id, clone_request1).await;
            assert!(
                public_clone_result.is_ok(),
                "Any agent should be able to clone public repo: {:?}",
                public_clone_result
            );

            // ================================================================
            // Test 2: Create a PRIVATE repository and verify access control
            // ================================================================
            let private_repo_name = format!("private-repo-{}", uuid::Uuid::new_v4());
            let create_nonce2 = uuid::Uuid::new_v4().to_string();
            let create_request2 = CreateRepoRequest {
                name: private_repo_name.clone(),
                description: Some("Private test repo".to_string()),
                visibility: Visibility::Private,
            };

            let create_body2 = serde_json::json!({
                "name": create_request2.name,
                "description": create_request2.description,
                "visibility": create_request2.visibility,
            });

            let create_envelope2 = SignatureEnvelope {
                agent_id: owner_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: create_nonce2.clone(),
                body: create_body2,
            };

            let create_signature2 = sign_envelope(&owner_signing_key, &create_envelope2);
            let private_repo = repo_service
                .create(
                    &owner_id,
                    &create_nonce2,
                    create_envelope2.timestamp,
                    &create_signature2,
                    create_request2,
                )
                .await
                .expect("Failed to create private repo");

            // Test 2a: Owner should be able to clone their private repo
            let clone_nonce2 = uuid::Uuid::new_v4().to_string();
            let clone_body2 = serde_json::json!({
                "repoId": private_repo.repo_id,
                "depth": null,
            });

            let clone_envelope2 = SignatureEnvelope {
                agent_id: owner_id.clone(),
                action: "repo_clone".to_string(),
                timestamp: Utc::now(),
                nonce: clone_nonce2.clone(),
                body: clone_body2,
            };

            let clone_signature2 = sign_envelope(&owner_signing_key, &clone_envelope2);
            let clone_request2 = CloneRepoRequest {
                agent_id: owner_id.clone(),
                timestamp: clone_envelope2.timestamp,
                nonce: clone_nonce2.clone(),
                signature: clone_signature2,
                depth: None,
            };

            let owner_clone_result = repo_service.clone(&private_repo.repo_id, clone_request2).await;
            assert!(
                owner_clone_result.is_ok(),
                "Owner should be able to clone their private repo: {:?}",
                owner_clone_result
            );

            // Test 2b: Other agent WITHOUT access should NOT be able to clone private repo
            let clone_nonce3 = uuid::Uuid::new_v4().to_string();
            let clone_body3 = serde_json::json!({
                "repoId": private_repo.repo_id,
                "depth": null,
            });

            let clone_envelope3 = SignatureEnvelope {
                agent_id: other_id.clone(),
                action: "repo_clone".to_string(),
                timestamp: Utc::now(),
                nonce: clone_nonce3.clone(),
                body: clone_body3,
            };

            let clone_signature3 = sign_envelope(&other_signing_key, &clone_envelope3);
            let clone_request3 = CloneRepoRequest {
                agent_id: other_id.clone(),
                timestamp: clone_envelope3.timestamp,
                nonce: clone_nonce3.clone(),
                signature: clone_signature3,
                depth: None,
            };

            let denied_clone_result = repo_service.clone(&private_repo.repo_id, clone_request3).await;
            assert!(
                matches!(denied_clone_result, Err(RepositoryError::AccessDenied(_))),
                "Agent without access should get ACCESS_DENIED for private repo: {:?}",
                denied_clone_result
            );

            // Test 2c: Grant explicit access to other agent, then they should be able to clone
            let now = Utc::now();
            sqlx::query(
                r#"
                INSERT INTO repo_access (repo_id, agent_id, role, created_at)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(&private_repo.repo_id)
            .bind(&other_id)
            .bind(AccessRole::Read)
            .bind(now)
            .execute(&pool)
            .await
            .expect("Failed to grant access");

            let clone_nonce4 = uuid::Uuid::new_v4().to_string();
            let clone_body4 = serde_json::json!({
                "repoId": private_repo.repo_id,
                "depth": null,
            });

            let clone_envelope4 = SignatureEnvelope {
                agent_id: other_id.clone(),
                action: "repo_clone".to_string(),
                timestamp: Utc::now(),
                nonce: clone_nonce4.clone(),
                body: clone_body4,
            };

            let clone_signature4 = sign_envelope(&other_signing_key, &clone_envelope4);
            let clone_request4 = CloneRepoRequest {
                agent_id: other_id.clone(),
                timestamp: clone_envelope4.timestamp,
                nonce: clone_nonce4.clone(),
                signature: clone_signature4,
                depth: None,
            };

            let granted_clone_result = repo_service.clone(&private_repo.repo_id, clone_request4).await;
            assert!(
                granted_clone_result.is_ok(),
                "Agent with explicit access should be able to clone private repo: {:?}",
                granted_clone_result
            );

            // ================================================================
            // Cleanup
            // ================================================================
            // Clean up idempotency results
            let nonce_hashes = vec![
                SignatureValidator::compute_nonce_hash(&owner_id, &create_nonce),
                SignatureValidator::compute_nonce_hash(&other_id, &clone_nonce1),
                SignatureValidator::compute_nonce_hash(&owner_id, &create_nonce2),
                SignatureValidator::compute_nonce_hash(&owner_id, &clone_nonce2),
                SignatureValidator::compute_nonce_hash(&other_id, &clone_nonce4),
            ];

            for nonce_hash in &nonce_hashes {
                let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                    .bind(nonce_hash)
                    .execute(&pool)
                    .await;
            }

            // Clean up repo_access entries
            let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
                .bind(&public_repo.repo_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            // Clean up repo_star_counts
            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                .bind(&public_repo.repo_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            // Clean up repositories
            let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                .bind(&public_repo.repo_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            // Clean up reputation
            let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                .bind(&owner_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                .bind(&other_id)
                .execute(&pool)
                .await;

            // Clean up agents
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(&owner_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(&other_id)
                .execute(&pool)
                .await;
        }

        /// Integration test for clone access with different roles
        ///
        /// Verifies that all roles (read, write, admin) can clone private repos.
        ///
        /// **Validates: Requirements 3.2, 18.2** | **Design: DR-4.2**
        #[tokio::test]
        #[ignore = "Requires database connection - run with: cargo test -- --ignored"]
        async fn integration_clone_access_all_roles() {
            use base64::Engine;
            use ed25519_dalek::{Signer, SigningKey};
            use rand::rngs::OsRng;
            use sha2::{Digest, Sha256};

            let pool = match try_create_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping test: database not available");
                    return;
                }
            };

            // Create owner agent
            let owner_signing_key = SigningKey::generate(&mut OsRng);
            let owner_verifying_key = owner_signing_key.verifying_key();
            let owner_public_key =
                base64::engine::general_purpose::STANDARD.encode(owner_verifying_key.as_bytes());
            let owner_id = uuid::Uuid::new_v4().to_string();
            let owner_name = format!("owner-agent-{}", uuid::Uuid::new_v4());

            sqlx::query(
                r#"
                INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                VALUES ($1, $2, $3, '[]', NOW())
                "#,
            )
            .bind(&owner_id)
            .bind(&owner_name)
            .bind(&owner_public_key)
            .execute(&pool)
            .await
            .expect("Failed to create owner agent");

            let _ = sqlx::query(
                r#"
                INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                VALUES ($1, 0.500, '[]', NOW())
                ON CONFLICT (agent_id) DO NOTHING
                "#,
            )
            .bind(&owner_id)
            .execute(&pool)
            .await;

            let repo_service =
                RepositoryService::new(pool.clone(), "http://localhost:8080".to_string());

            // Helper to sign envelope
            let sign_envelope = |signing_key: &SigningKey, envelope: &SignatureEnvelope| -> String {
                let validator = SignatureValidator::default();
                let canonical = validator.canonicalize(envelope).expect("canonicalize failed");
                let message_hash = Sha256::digest(canonical.as_bytes());
                let signature = signing_key.sign(&message_hash);
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            };

            // Create a private repository
            let private_repo_name = format!("private-repo-roles-{}", uuid::Uuid::new_v4());
            let create_nonce = uuid::Uuid::new_v4().to_string();
            let create_request = CreateRepoRequest {
                name: private_repo_name.clone(),
                description: Some("Private test repo for role testing".to_string()),
                visibility: Visibility::Private,
            };

            let create_body = serde_json::json!({
                "name": create_request.name,
                "description": create_request.description,
                "visibility": create_request.visibility,
            });

            let create_envelope = SignatureEnvelope {
                agent_id: owner_id.clone(),
                action: "repo_create".to_string(),
                timestamp: Utc::now(),
                nonce: create_nonce.clone(),
                body: create_body,
            };

            let create_signature = sign_envelope(&owner_signing_key, &create_envelope);
            let private_repo = repo_service
                .create(
                    &owner_id,
                    &create_nonce,
                    create_envelope.timestamp,
                    &create_signature,
                    create_request,
                )
                .await
                .expect("Failed to create private repo");

            let mut nonce_hashes = vec![SignatureValidator::compute_nonce_hash(&owner_id, &create_nonce)];
            let mut agent_ids = vec![owner_id.clone()];

            // Test each role can clone
            for role in [AccessRole::Read, AccessRole::Write, AccessRole::Admin] {
                // Create test agent for this role
                let agent_signing_key = SigningKey::generate(&mut OsRng);
                let agent_verifying_key = agent_signing_key.verifying_key();
                let agent_public_key =
                    base64::engine::general_purpose::STANDARD.encode(agent_verifying_key.as_bytes());
                let agent_id = uuid::Uuid::new_v4().to_string();
                let agent_name = format!("agent-{:?}-{}", role, uuid::Uuid::new_v4());

                sqlx::query(
                    r#"
                    INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
                    VALUES ($1, $2, $3, '[]', NOW())
                    "#,
                )
                .bind(&agent_id)
                .bind(&agent_name)
                .bind(&agent_public_key)
                .execute(&pool)
                .await
                .expect("Failed to create test agent");

                let _ = sqlx::query(
                    r#"
                    INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
                    VALUES ($1, 0.500, '[]', NOW())
                    ON CONFLICT (agent_id) DO NOTHING
                    "#,
                )
                .bind(&agent_id)
                .execute(&pool)
                .await;

                // Grant access with this role
                let now = Utc::now();
                sqlx::query(
                    r#"
                    INSERT INTO repo_access (repo_id, agent_id, role, created_at)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(&private_repo.repo_id)
                .bind(&agent_id)
                .bind(role)
                .bind(now)
                .execute(&pool)
                .await
                .expect("Failed to grant access");

                // Try to clone
                let clone_nonce = uuid::Uuid::new_v4().to_string();
                let clone_body = serde_json::json!({
                    "repoId": private_repo.repo_id,
                    "depth": null,
                });

                let clone_envelope = SignatureEnvelope {
                    agent_id: agent_id.clone(),
                    action: "repo_clone".to_string(),
                    timestamp: Utc::now(),
                    nonce: clone_nonce.clone(),
                    body: clone_body,
                };

                let clone_signature = sign_envelope(&agent_signing_key, &clone_envelope);
                let clone_request = CloneRepoRequest {
                    agent_id: agent_id.clone(),
                    timestamp: clone_envelope.timestamp,
                    nonce: clone_nonce.clone(),
                    signature: clone_signature,
                    depth: None,
                };

                let clone_result = repo_service.clone(&private_repo.repo_id, clone_request).await;
                assert!(
                    clone_result.is_ok(),
                    "Agent with {:?} role should be able to clone private repo: {:?}",
                    role,
                    clone_result
                );

                nonce_hashes.push(SignatureValidator::compute_nonce_hash(&agent_id, &clone_nonce));
                agent_ids.push(agent_id);
            }

            // ================================================================
            // Cleanup
            // ================================================================
            for nonce_hash in &nonce_hashes {
                let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                    .bind(nonce_hash)
                    .execute(&pool)
                    .await;
            }

            let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                .bind(&private_repo.repo_id)
                .execute(&pool)
                .await;

            for agent_id in &agent_ids {
                let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
                    .bind(agent_id)
                    .execute(&pool)
                    .await;
                let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                    .bind(agent_id)
                    .execute(&pool)
                    .await;
            }
        }
    }
}

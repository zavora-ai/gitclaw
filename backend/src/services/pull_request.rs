//! Pull Request Service
//!
//! Handles PR creation, reviews, and merging.
//! Implements DR-7.1 (Pull Request Service), DR-7.2 (Review Service), DR-7.3 (Merge Service)

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    AccessRole, CiStatus, CreatePrRequest, CreatePrResponse, CreateReviewRequest,
    CreateReviewResponse, DiffStats, MergePrResponse, MergeStrategy, PrInfo, PrStatus,
    PullRequest, Review, ReviewVerdict,
};
use crate::services::audit::{AuditError, AuditEvent, AuditService};
use crate::services::ci::CiService;
use crate::services::idempotency::{IdempotencyError, IdempotencyResult, IdempotencyService};
use crate::services::signature::{SignatureEnvelope, SignatureError, SignatureValidator};

/// Errors that can occur during pull request operations
#[derive(Debug, Error)]
pub enum PullRequestError {
    #[error("Pull request not found: {0}")]
    PrNotFound(String),

    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Branch not found: {0}")]
    BranchNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Self-approval not allowed: PR author cannot approve their own PR")]
    SelfApprovalNotAllowed,

    #[error("PR not approved: {0}")]
    NotApproved(String),

    #[error("CI not passed: current status is {0:?}")]
    CiNotPassed(CiStatus),

    #[error("Merge conflicts detected: {0}")]
    MergeConflicts(String),

    #[error("PR already merged")]
    AlreadyMerged,

    #[error("PR is closed")]
    PrClosed,

    #[error("Invalid PR state: {0}")]
    InvalidState(String),

    #[error("Signature validation failed: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Idempotency error: {0}")]
    IdempotencyError(#[from] IdempotencyError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
}

/// Service for managing pull requests
#[derive(Debug, Clone)]
pub struct PullRequestService {
    pool: PgPool,
    signature_validator: SignatureValidator,
    idempotency_service: IdempotencyService,
    ci_service: CiService,
}

impl PullRequestService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            signature_validator: SignatureValidator::default(),
            idempotency_service: IdempotencyService::new(pool.clone()),
            ci_service: CiService::new(pool.clone()),
            pool,
        }
    }

    /// Create a new pull request
    ///
    /// Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    /// Design: DR-7.1 (Pull Request Service)
    pub async fn create(
        &self,
        repo_id: &str,
        agent_id: &str,
        nonce: &str,
        timestamp: DateTime<Utc>,
        signature: &str,
        request: CreatePrRequest,
    ) -> Result<CreatePrResponse, PullRequestError> {
        const ACTION: &str = "pr_create";

        // Check idempotency first
        match self.idempotency_service.check(agent_id, nonce, ACTION).await? {
            IdempotencyResult::Cached(cached) => {
                let response: CreatePrResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| PullRequestError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(PullRequestError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Verify repository exists
        let repo_exists: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if repo_exists.is_none() {
            return Err(PullRequestError::RepoNotFound(repo_id.to_string()));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "sourceBranch": request.source_branch,
            "targetBranch": request.target_branch,
            "title": request.title,
            "description": request.description,
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

        // Validate source and target branches exist (Requirement 6.5)
        self.validate_branch_exists(repo_id, &request.source_branch)
            .await?;
        self.validate_branch_exists(repo_id, &request.target_branch)
            .await?;

        // Generate PR ID
        let pr_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Compute diff statistics (Requirement 6.2)
        let diff_stats = self
            .compute_diff_stats(repo_id, &request.source_branch, &request.target_branch)
            .await?;

        // Determine initial mergeability (Requirement 6.2)
        let mergeable = self
            .check_mergeability(repo_id, &request.source_branch, &request.target_branch)
            .await?;

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Insert PR record
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, description, status, ci_status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&pr_id)
        .bind(repo_id)
        .bind(agent_id)
        .bind(&request.source_branch)
        .bind(&request.target_branch)
        .bind(&request.title)
        .bind(&request.description)
        .bind(PrStatus::Open)
        .bind(CiStatus::Pending)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        // Append audit event
        let audit_data = serde_json::json!({
            "pr_id": pr_id,
            "repo_id": repo_id,
            "source_branch": request.source_branch,
            "target_branch": request.target_branch,
            "title": request.title,
            "diff_stats": diff_stats,
            "mergeable": mergeable,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "pull_request".to_string(),
                resource_id: pr_id.clone(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Build response
        let response = CreatePrResponse {
            pr_id: pr_id.clone(),
            repo_id: repo_id.to_string(),
            author_id: agent_id.to_string(),
            source_branch: request.source_branch,
            target_branch: request.target_branch,
            title: request.title,
            description: request.description,
            status: PrStatus::Open,
            ci_status: CiStatus::Pending,
            diff_stats,
            mergeable,
            created_at,
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 201, &response, 24)
            .await?;

        // Commit transaction
        tx.commit().await?;

        // Trigger CI pipeline (Requirement 6.3, 9.1)
        // Get the commit SHA from the source branch
        if let Ok(Some(commit_sha)) = self.get_branch_commit_sha(repo_id, &response.source_branch).await {
            // Trigger CI asynchronously - don't fail PR creation if CI trigger fails
            if let Err(e) = self.ci_service.trigger_for_pr(repo_id, &response.pr_id, &commit_sha).await {
                tracing::warn!("Failed to trigger CI for PR {}: {}", response.pr_id, e);
            }
        }

        Ok(response)
    }

    /// Submit a review for a pull request
    ///
    /// Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    /// Design: DR-7.2 (Review Service)
    pub async fn submit_review(
        &self,
        repo_id: &str,
        pr_id: &str,
        agent_id: &str,
        nonce: &str,
        timestamp: DateTime<Utc>,
        signature: &str,
        request: CreateReviewRequest,
    ) -> Result<CreateReviewResponse, PullRequestError> {
        const ACTION: &str = "pr_review";

        // Check idempotency first
        match self.idempotency_service.check(agent_id, nonce, ACTION).await? {
            IdempotencyResult::Cached(cached) => {
                let response: CreateReviewResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| PullRequestError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(PullRequestError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get the PR to validate it exists and check author
        let pr = self.get_pr(pr_id).await?;
        let pr = pr.ok_or_else(|| PullRequestError::PrNotFound(pr_id.to_string()))?;

        // Verify PR belongs to the specified repo
        if pr.repo_id != repo_id {
            return Err(PullRequestError::PrNotFound(pr_id.to_string()));
        }

        // Check PR is open
        if pr.status != PrStatus::Open {
            return Err(PullRequestError::InvalidState(format!(
                "PR is {:?}, cannot submit review",
                pr.status
            )));
        }

        // Validate reviewer != author (Requirement 7.4)
        if pr.author_id == agent_id && request.verdict == ReviewVerdict::Approve {
            return Err(PullRequestError::SelfApprovalNotAllowed);
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": request.verdict,
            "body": request.body,
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

        // Generate review ID
        let review_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Insert review record
        sqlx::query(
            r#"
            INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&review_id)
        .bind(pr_id)
        .bind(agent_id)
        .bind(&request.verdict)
        .bind(&request.body)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        // Append audit event
        let audit_data = serde_json::json!({
            "review_id": review_id,
            "pr_id": pr_id,
            "repo_id": repo_id,
            "verdict": request.verdict,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "review".to_string(),
                resource_id: review_id.clone(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Build response
        let response = CreateReviewResponse {
            review_id: review_id.clone(),
            pr_id: pr_id.to_string(),
            reviewer_id: agent_id.to_string(),
            verdict: request.verdict,
            body: request.body,
            created_at,
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 201, &response, 24)
            .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(response)
    }

    /// Merge a pull request
    ///
    /// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
    /// Design: DR-7.3 (Merge Service)
    pub async fn merge(
        &self,
        repo_id: &str,
        pr_id: &str,
        agent_id: &str,
        nonce: &str,
        timestamp: DateTime<Utc>,
        signature: &str,
        merge_strategy: MergeStrategy,
    ) -> Result<MergePrResponse, PullRequestError> {
        const ACTION: &str = "pr_merge";

        // Check idempotency first
        match self.idempotency_service.check(agent_id, nonce, ACTION).await? {
            IdempotencyResult::Cached(cached) => {
                let response: MergePrResponse = serde_json::from_value(cached.response_json)
                    .map_err(|e| PullRequestError::Database(sqlx::Error::Decode(Box::new(e))))?;
                return Ok(response);
            }
            IdempotencyResult::ReplayAttack { previous_action } => {
                return Err(PullRequestError::IdempotencyError(
                    IdempotencyError::ReplayAttack {
                        previous_action,
                        attempted_action: ACTION.to_string(),
                    },
                ));
            }
            IdempotencyResult::New => {}
        }

        // Get the PR
        let pr = self.get_pr(pr_id).await?;
        let pr = pr.ok_or_else(|| PullRequestError::PrNotFound(pr_id.to_string()))?;

        // Verify PR belongs to the specified repo
        if pr.repo_id != repo_id {
            return Err(PullRequestError::PrNotFound(pr_id.to_string()));
        }

        // Check PR status
        match pr.status {
            PrStatus::Merged => return Err(PullRequestError::AlreadyMerged),
            PrStatus::Closed => return Err(PullRequestError::PrClosed),
            PrStatus::Open => {}
        }

        // Check write access (Requirement 8.1)
        let has_access = self.check_write_access(repo_id, agent_id).await?;
        if !has_access {
            return Err(PullRequestError::AccessDenied(format!(
                "Agent {} does not have write access to repository {}",
                agent_id, repo_id
            )));
        }

        // Check approval status (Requirement 8.1)
        let is_approved = self.check_approval_status(pr_id).await?;
        if !is_approved {
            return Err(PullRequestError::NotApproved(
                "PR requires at least one approval and no outstanding change requests".to_string(),
            ));
        }

        // Check CI status (Requirement 8.1)
        if pr.ci_status != CiStatus::Passed {
            return Err(PullRequestError::CiNotPassed(pr.ci_status));
        }

        // Check for merge conflicts (Requirement 8.3)
        let has_conflicts = self
            .check_merge_conflicts(repo_id, &pr.source_branch, &pr.target_branch)
            .await?;
        if has_conflicts {
            return Err(PullRequestError::MergeConflicts(
                "Cannot merge due to conflicts between source and target branches".to_string(),
            ));
        }

        // Get agent's public key for signature validation
        let public_key = self.get_agent_public_key(agent_id).await?;

        // Create signature envelope
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": merge_strategy,
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

        let merged_at = Utc::now();

        // Generate merge commit OID (in a real implementation, this would be the actual commit hash)
        let merge_commit_oid = format!("{:040x}", rand::random::<u128>());

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Update PR status to merged (Requirement 8.4)
        sqlx::query(
            r#"
            UPDATE pull_requests
            SET status = $1, merged_at = $2
            WHERE pr_id = $3
            "#,
        )
        .bind(PrStatus::Merged)
        .bind(merged_at)
        .bind(pr_id)
        .execute(&mut *tx)
        .await?;

        // Update target branch ref (Requirement 8.4)
        // In a real implementation, this would perform the actual Git merge
        self.update_branch_ref_in_tx(&mut tx, repo_id, &pr.target_branch, &merge_commit_oid)
            .await?;

        // Append audit event
        let audit_data = serde_json::json!({
            "pr_id": pr_id,
            "repo_id": repo_id,
            "merge_strategy": merge_strategy,
            "merge_commit_oid": merge_commit_oid,
            "source_branch": pr.source_branch,
            "target_branch": pr.target_branch,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: agent_id.to_string(),
                action: ACTION.to_string(),
                resource_type: "pull_request".to_string(),
                resource_id: pr_id.to_string(),
                data: audit_data,
                signature: signature.to_string(),
            },
        )
        .await?;

        // Build response
        let response = MergePrResponse {
            pr_id: pr_id.to_string(),
            repo_id: repo_id.to_string(),
            merge_strategy,
            merged_at,
            merge_commit_oid,
        };

        // Store idempotency result
        IdempotencyService::store_in_tx(&mut tx, agent_id, nonce, ACTION, 200, &response, 24)
            .await?;

        // Commit transaction
        tx.commit().await?;

        // Note: Reputation updates (Requirement 8.6) would be done via event_outbox
        // Note: Webhooks (Requirement 8.5) would be triggered via event_outbox

        Ok(response)
    }

    /// Get a pull request by ID
    pub async fn get_pr(&self, pr_id: &str) -> Result<Option<PullRequest>, PullRequestError> {
        let row = sqlx::query(
            r#"
            SELECT pr_id, repo_id, author_id, source_branch, target_branch, title, description, status, ci_status, created_at, merged_at
            FROM pull_requests
            WHERE pr_id = $1
            "#,
        )
        .bind(pr_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PullRequest {
            pr_id: r.get("pr_id"),
            repo_id: r.get("repo_id"),
            author_id: r.get("author_id"),
            source_branch: r.get("source_branch"),
            target_branch: r.get("target_branch"),
            title: r.get("title"),
            description: r.get("description"),
            status: r.get("status"),
            ci_status: r.get("ci_status"),
            created_at: r.get("created_at"),
            merged_at: r.get("merged_at"),
        }))
    }

    /// Get PR info with computed fields
    pub async fn get_pr_info(&self, pr_id: &str) -> Result<Option<PrInfo>, PullRequestError> {
        let pr = self.get_pr(pr_id).await?;
        let pr = match pr {
            Some(p) => p,
            None => return Ok(None),
        };

        let is_approved = self.check_approval_status(pr_id).await?;
        let review_count = self.get_review_count(pr_id).await?;

        Ok(Some(PrInfo {
            pr_id: pr.pr_id,
            repo_id: pr.repo_id,
            author_id: pr.author_id,
            source_branch: pr.source_branch,
            target_branch: pr.target_branch,
            title: pr.title,
            description: pr.description,
            status: pr.status,
            ci_status: pr.ci_status,
            is_approved,
            review_count,
            created_at: pr.created_at,
            merged_at: pr.merged_at,
        }))
    }

    /// Get reviews for a PR
    pub async fn get_reviews(&self, pr_id: &str) -> Result<Vec<Review>, PullRequestError> {
        let rows = sqlx::query(
            r#"
            SELECT review_id, pr_id, reviewer_id, verdict, body, created_at
            FROM reviews
            WHERE pr_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Review {
                review_id: r.get("review_id"),
                pr_id: r.get("pr_id"),
                reviewer_id: r.get("reviewer_id"),
                verdict: r.get("verdict"),
                body: r.get("body"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Check if a PR is approved
    ///
    /// A PR is approved if it has at least one "approve" verdict
    /// and no outstanding "request_changes" verdicts.
    async fn check_approval_status(&self, pr_id: &str) -> Result<bool, PullRequestError> {
        // Get the latest review from each reviewer
        let reviews = self.get_reviews(pr_id).await?;

        // Group by reviewer and get latest verdict
        let mut latest_verdicts: std::collections::HashMap<String, ReviewVerdict> =
            std::collections::HashMap::new();

        for review in reviews {
            // Only update if this is the first (most recent) review from this reviewer
            latest_verdicts
                .entry(review.reviewer_id)
                .or_insert(review.verdict);
        }

        // Check for at least one approval
        let has_approval = latest_verdicts
            .values()
            .any(|v| *v == ReviewVerdict::Approve);

        // Check for no outstanding change requests
        let has_change_requests = latest_verdicts
            .values()
            .any(|v| *v == ReviewVerdict::RequestChanges);

        Ok(has_approval && !has_change_requests)
    }

    /// Get the number of reviews for a PR
    async fn get_review_count(&self, pr_id: &str) -> Result<i32, PullRequestError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE pr_id = $1")
            .bind(pr_id)
            .fetch_one(&self.pool)
            .await?;

        Ok(count as i32)
    }

    /// Validate that a branch exists in the repository
    async fn validate_branch_exists(
        &self,
        repo_id: &str,
        branch_name: &str,
    ) -> Result<(), PullRequestError> {
        // Check repo_refs table for the branch
        let ref_name = format!("refs/heads/{}", branch_name);
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT ref_name FROM repo_refs WHERE repo_id = $1 AND ref_name = $2",
        )
        .bind(repo_id)
        .bind(&ref_name)
        .fetch_optional(&self.pool)
        .await?;

        // If no refs exist yet (new repo), check if it's the default branch
        if exists.is_none() {
            let default_branch: Option<String> =
                sqlx::query_scalar("SELECT default_branch FROM repositories WHERE repo_id = $1")
                    .bind(repo_id)
                    .fetch_optional(&self.pool)
                    .await?;

            if let Some(default) = default_branch {
                if default == branch_name {
                    // Default branch is implicitly valid even if no refs exist yet
                    return Ok(());
                }
            }

            return Err(PullRequestError::BranchNotFound(branch_name.to_string()));
        }

        Ok(())
    }

    /// Compute diff statistics between two branches
    async fn compute_diff_stats(
        &self,
        _repo_id: &str,
        _source_branch: &str,
        _target_branch: &str,
    ) -> Result<DiffStats, PullRequestError> {
        // In a real implementation, this would compute actual diff stats
        // For now, return placeholder values
        Ok(DiffStats {
            files_changed: 0,
            insertions: 0,
            deletions: 0,
        })
    }

    /// Check if branches can be merged without conflicts
    async fn check_mergeability(
        &self,
        _repo_id: &str,
        _source_branch: &str,
        _target_branch: &str,
    ) -> Result<bool, PullRequestError> {
        // In a real implementation, this would check for merge conflicts
        // For now, assume mergeable
        Ok(true)
    }

    /// Check for merge conflicts between branches
    async fn check_merge_conflicts(
        &self,
        _repo_id: &str,
        _source_branch: &str,
        _target_branch: &str,
    ) -> Result<bool, PullRequestError> {
        // In a real implementation, this would perform a trial merge
        // For now, assume no conflicts
        Ok(false)
    }

    /// Check if an agent has write access to a repository
    async fn check_write_access(
        &self,
        repo_id: &str,
        agent_id: &str,
    ) -> Result<bool, PullRequestError> {
        // Check if agent is owner
        let owner_id: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if let Some(owner) = owner_id {
            if owner == agent_id {
                return Ok(true);
            }
        }

        // Check repo_access for write or admin role
        let role: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(repo_id)
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(matches!(role, Some(AccessRole::Write | AccessRole::Admin)))
    }

    /// Update a branch reference within a transaction
    async fn update_branch_ref_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        branch_name: &str,
        new_oid: &str,
    ) -> Result<(), PullRequestError> {
        let ref_name = format!("refs/heads/{}", branch_name);

        sqlx::query(
            r#"
            INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (repo_id, ref_name)
            DO UPDATE SET oid = $3, updated_at = NOW()
            "#,
        )
        .bind(repo_id)
        .bind(&ref_name)
        .bind(new_oid)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Get agent's public key for signature validation
    async fn get_agent_public_key(&self, agent_id: &str) -> Result<String, PullRequestError> {
        let public_key: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM agents WHERE agent_id = $1")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        public_key.ok_or_else(|| PullRequestError::AgentNotFound(agent_id.to_string()))
    }

    /// Get the commit SHA for a branch
    async fn get_branch_commit_sha(
        &self,
        repo_id: &str,
        branch_name: &str,
    ) -> Result<Option<String>, PullRequestError> {
        let ref_name = format!("refs/heads/{}", branch_name);
        let oid: Option<String> = sqlx::query_scalar(
            "SELECT oid FROM repo_refs WHERE repo_id = $1 AND ref_name = $2",
        )
        .bind(repo_id)
        .bind(&ref_name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(oid)
    }
}

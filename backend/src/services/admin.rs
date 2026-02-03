//! Admin Service
//!
//! Provides administrative operations for platform management including
//! statistics aggregation, agent management, and repository management.
//!
//! Design Reference: Admin Dashboard Design Document
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 3.1, 3.2

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

use crate::models::repository::Visibility;
use crate::services::audit::{AuditAction, AuditEvent, AuditService, ResourceType};

/// Admin service errors
#[derive(Debug, Error)]
pub enum AdminError {
    /// Agent not found
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// Repository not found
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    /// Agent already suspended
    #[error("Agent is already suspended: {0}")]
    AlreadySuspended(String),

    /// Agent not suspended
    #[error("Agent is not suspended: {0}")]
    NotSuspended(String),

    /// Invalid credentials
    #[error("Invalid admin credentials")]
    InvalidCredentials,

    /// Session expired
    #[error("Admin session expired")]
    SessionExpired,

    /// Unauthorized access
    #[error("Unauthorized access to admin endpoint")]
    Unauthorized,

    /// Invalid pagination parameters
    #[error("Invalid pagination parameters: {0}")]
    InvalidPagination(String),

    /// Repository is not orphaned
    #[error("Repository is not orphaned: {0}")]
    NotOrphaned(String),

    /// Repository disconnection type mismatch
    #[error("Repository disconnection type mismatch: expected {expected}, found {found}")]
    DisconnectionTypeMismatch { expected: String, found: String },

    /// Owner not found
    #[error("Owner agent not found: {0}")]
    OwnerNotFound(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Object storage error
    #[error("Object storage error: {0}")]
    ObjectStorage(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AdminError {
    /// Get the error code for API responses
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::AgentNotFound(_) => "AGENT_NOT_FOUND",
            Self::RepoNotFound(_) => "REPO_NOT_FOUND",
            Self::AlreadySuspended(_) => "ALREADY_SUSPENDED",
            Self::NotSuspended(_) => "NOT_SUSPENDED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::SessionExpired => "SESSION_EXPIRED",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidPagination(_) => "INVALID_PAGINATION",
            Self::NotOrphaned(_) => "NOT_ORPHANED",
            Self::DisconnectionTypeMismatch { .. } => "DISCONNECTION_TYPE_MISMATCH",
            Self::OwnerNotFound(_) => "OWNER_NOT_FOUND",
            Self::Database(_) => "DATABASE_ERROR",
            Self::ObjectStorage(_) => "OBJECT_STORAGE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::AgentNotFound(_) | Self::RepoNotFound(_) | Self::OwnerNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            Self::AlreadySuspended(_)
            | Self::NotSuspended(_)
            | Self::NotOrphaned(_)
            | Self::DisconnectionTypeMismatch { .. } => StatusCode::CONFLICT,
            Self::InvalidCredentials | Self::SessionExpired | Self::Unauthorized => {
                StatusCode::UNAUTHORIZED
            }
            Self::InvalidPagination(_) => StatusCode::BAD_REQUEST,
            Self::Database(_) | Self::ObjectStorage(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

/// Platform statistics
///
/// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformStats {
    /// Total count of registered agents (Requirement 1.1)
    pub total_agents: i64,
    /// Total count of repositories (Requirement 1.2)
    pub total_repos: i64,
    /// Total count of stars across all repositories (Requirement 1.3)
    pub total_stars: i64,
    /// Pull request counts by status (Requirement 1.4)
    pub pull_requests: PullRequestStats,
    /// CI run counts by status (Requirement 1.5)
    pub ci_runs: CIRunStats,
    /// Count of suspended agents
    pub suspended_agents: i64,
}

/// Pull request statistics by status
///
/// Requirement: 1.4
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PullRequestStats {
    /// Count of open pull requests
    pub open: i64,
    /// Count of merged pull requests
    pub merged: i64,
    /// Count of closed pull requests
    pub closed: i64,
}

/// CI run statistics by status
///
/// Requirement: 1.5
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CIRunStats {
    /// Count of pending CI runs
    pub pending: i64,
    /// Count of running CI runs
    pub running: i64,
    /// Count of passed CI runs
    pub passed: i64,
    /// Count of failed CI runs
    pub failed: i64,
}

/// Agent with admin details
///
/// Requirements: 2.1, 2.3, 2.7
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAgentDetails {
    /// Unique agent identifier
    pub agent_id: String,
    /// Agent's display name
    pub agent_name: String,
    /// Agent's public key for signature verification
    pub public_key: String,
    /// Agent's capabilities
    pub capabilities: Vec<String>,
    /// When the agent was created
    pub created_at: DateTime<Utc>,
    /// Whether the agent is suspended
    pub suspended: bool,
    /// When the agent was suspended (if applicable)
    pub suspended_at: Option<DateTime<Utc>>,
    /// Reason for suspension (if applicable)
    pub suspended_reason: Option<String>,
    /// Agent's reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Number of repositories owned by the agent
    pub repo_count: i64,
    /// Number of pull requests created by the agent
    pub pr_count: i64,
    /// Number of reviews submitted by the agent
    pub review_count: i64,
}

/// Repository with admin details
///
/// Requirements: 3.1, 3.2, 3.3
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRepoDetails {
    /// Unique repository identifier
    pub repo_id: String,
    /// Repository name
    pub name: String,
    /// Owner agent's identifier
    pub owner_id: String,
    /// Owner agent's display name
    pub owner_name: String,
    /// Repository description
    pub description: Option<String>,
    /// Repository visibility (public/private)
    pub visibility: Visibility,
    /// Default branch name
    pub default_branch: String,
    /// When the repository was created
    pub created_at: DateTime<Utc>,
    /// Number of stars on the repository
    pub star_count: i64,
    /// Number of pull requests in the repository
    pub pr_count: i64,
    /// Number of CI runs for the repository
    pub ci_run_count: i64,
    /// Number of Git objects in the repository
    pub object_count: i64,
    /// Total size of all objects in bytes
    pub total_size_bytes: i64,
}

/// Pagination parameters for list endpoints
///
/// Requirements: 2.1, 2.2
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams {
    /// Page number (1-indexed, defaults to 1)
    pub page: Option<i64>,
    /// Items per page (defaults to 20, max 100)
    pub per_page: Option<i64>,
    /// Search query for filtering
    pub search: Option<String>,
}

impl PaginationParams {
    /// Default page size
    const DEFAULT_PER_PAGE: i64 = 20;
    /// Maximum page size
    const MAX_PER_PAGE: i64 = 100;

    /// Get the validated page number (1-indexed)
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    /// Get the validated per_page value
    pub fn per_page(&self) -> i64 {
        self.per_page
            .unwrap_or(Self::DEFAULT_PER_PAGE)
            .clamp(1, Self::MAX_PER_PAGE)
    }

    /// Calculate the offset for SQL queries
    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.per_page()
    }
}

/// Paginated response wrapper
///
/// Requirements: 2.1
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    /// Items for the current page
    pub items: Vec<T>,
    /// Total number of items across all pages
    pub total: i64,
    /// Current page number (1-indexed)
    pub page: i64,
    /// Items per page
    pub per_page: i64,
    /// Total number of pages
    pub total_pages: i64,
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response
    pub fn new(items: Vec<T>, total: i64, page: i64, per_page: i64) -> Self {
        let total_pages = if total == 0 {
            1
        } else {
            (total + per_page - 1) / per_page
        };

        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

/// Internal row type for agent queries
///
/// Used to map database results to `AdminAgentDetails`
#[derive(Debug, sqlx::FromRow)]
struct AgentRow {
    agent_id: String,
    agent_name: String,
    public_key: String,
    capabilities: sqlx::types::Json<Vec<String>>,
    created_at: DateTime<Utc>,
    suspended: bool,
    suspended_at: Option<DateTime<Utc>>,
    suspended_reason: Option<String>,
    reputation_score: f64,
    repo_count: i64,
    pr_count: i64,
    review_count: i64,
}

impl From<AgentRow> for AdminAgentDetails {
    fn from(row: AgentRow) -> Self {
        Self {
            agent_id: row.agent_id,
            agent_name: row.agent_name,
            public_key: row.public_key,
            capabilities: row.capabilities.0,
            created_at: row.created_at,
            suspended: row.suspended,
            suspended_at: row.suspended_at,
            suspended_reason: row.suspended_reason,
            reputation_score: row.reputation_score,
            repo_count: row.repo_count,
            pr_count: row.pr_count,
            review_count: row.review_count,
        }
    }
}

/// Internal row type for repository queries
///
/// Used to map database results to `AdminRepoDetails`
#[derive(Debug, sqlx::FromRow)]
struct RepoRow {
    repo_id: String,
    name: String,
    owner_id: String,
    owner_name: String,
    description: Option<String>,
    visibility: Visibility,
    default_branch: String,
    created_at: DateTime<Utc>,
    star_count: i64,
    pr_count: i64,
    ci_run_count: i64,
    object_count: i64,
    total_size_bytes: i64,
}

impl From<RepoRow> for AdminRepoDetails {
    fn from(row: RepoRow) -> Self {
        Self {
            repo_id: row.repo_id,
            name: row.name,
            owner_id: row.owner_id,
            owner_name: row.owner_name,
            description: row.description,
            visibility: row.visibility,
            default_branch: row.default_branch,
            created_at: row.created_at,
            star_count: row.star_count,
            pr_count: row.pr_count,
            ci_run_count: row.ci_run_count,
            object_count: row.object_count,
            total_size_bytes: row.total_size_bytes,
        }
    }
}

/// Admin service for platform management
///
/// Design Reference: Admin Dashboard Design Document
#[derive(Debug, Clone)]
pub struct AdminService {
    pool: PgPool,
    #[allow(dead_code)]
    audit_service: AuditService,
}

impl AdminService {
    /// Create a new AdminService instance
    pub fn new(pool: PgPool, audit_service: AuditService) -> Self {
        Self {
            pool,
            audit_service,
        }
    }

    /// Get platform-wide statistics
    ///
    /// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
    pub async fn get_stats(&self) -> Result<PlatformStats, AdminError> {
        // Get total agents count (Requirement 1.1)
        let total_agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents")
            .fetch_one(&self.pool)
            .await?;

        // Get total repositories count (Requirement 1.2)
        let total_repos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repositories")
            .fetch_one(&self.pool)
            .await?;

        // Get total stars count (Requirement 1.3)
        // Using repo_star_counts for efficiency as it's the denormalized count table
        let total_stars: i64 =
            sqlx::query_scalar("SELECT COALESCE(SUM(stars), 0) FROM repo_star_counts")
                .fetch_one(&self.pool)
                .await?;

        // Get pull request counts by status (Requirement 1.4)
        let pr_open: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pull_requests WHERE status = 'open'")
                .fetch_one(&self.pool)
                .await?;

        let pr_merged: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pull_requests WHERE status = 'merged'")
                .fetch_one(&self.pool)
                .await?;

        let pr_closed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pull_requests WHERE status = 'closed'")
                .fetch_one(&self.pool)
                .await?;

        // Get CI run counts by status (Requirement 1.5)
        let ci_pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ci_runs WHERE status = 'pending'")
                .fetch_one(&self.pool)
                .await?;

        let ci_running: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ci_runs WHERE status = 'running'")
                .fetch_one(&self.pool)
                .await?;

        let ci_passed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ci_runs WHERE status = 'passed'")
                .fetch_one(&self.pool)
                .await?;

        let ci_failed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ci_runs WHERE status = 'failed'")
                .fetch_one(&self.pool)
                .await?;

        // Get suspended agents count
        let suspended_agents: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE suspended = TRUE")
                .fetch_one(&self.pool)
                .await?;

        Ok(PlatformStats {
            total_agents,
            total_repos,
            total_stars,
            pull_requests: PullRequestStats {
                open: pr_open,
                merged: pr_merged,
                closed: pr_closed,
            },
            ci_runs: CIRunStats {
                pending: ci_pending,
                running: ci_running,
                passed: ci_passed,
                failed: ci_failed,
            },
            suspended_agents,
        })
    }

    /// List agents with pagination and search
    ///
    /// Requirements: 2.1, 2.2
    ///
    /// Supports searching by agent_name or agent_id using case-insensitive ILIKE.
    /// Returns paginated results with agent details including reputation and activity counts.
    pub async fn list_agents(
        &self,
        params: PaginationParams,
    ) -> Result<PaginatedResponse<AdminAgentDetails>, AdminError> {
        let page = params.page();
        let per_page = params.per_page();
        let offset = params.offset();

        // Build the search condition if a search term is provided
        let search_pattern = params
            .search
            .as_ref()
            .map(|s| format!("%{}%", s.replace('%', "\\%").replace('_', "\\_")));

        // Count total matching agents
        let total: i64 = if let Some(ref pattern) = search_pattern {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM agents
                WHERE agent_name ILIKE $1 OR agent_id ILIKE $1
                "#,
            )
            .bind(pattern)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM agents")
                .fetch_one(&self.pool)
                .await?
        };

        // Fetch agents with their details
        // Join with reputation table for score, and count repos/PRs/reviews
        let agents = if let Some(ref pattern) = search_pattern {
            sqlx::query_as::<_, AgentRow>(
                r#"
                SELECT 
                    a.agent_id,
                    a.agent_name,
                    a.public_key,
                    a.capabilities,
                    a.created_at,
                    a.suspended,
                    a.suspended_at,
                    a.suspended_reason,
                    CAST(COALESCE(r.score, 0.5) AS DOUBLE PRECISION) as reputation_score,
                    COALESCE(repo_counts.count, 0) as repo_count,
                    COALESCE(pr_counts.count, 0) as pr_count,
                    COALESCE(review_counts.count, 0) as review_count
                FROM agents a
                LEFT JOIN reputation r ON a.agent_id = r.agent_id
                LEFT JOIN (
                    SELECT owner_id, COUNT(*) as count
                    FROM repositories
                    GROUP BY owner_id
                ) repo_counts ON a.agent_id = repo_counts.owner_id
                LEFT JOIN (
                    SELECT author_id, COUNT(*) as count
                    FROM pull_requests
                    GROUP BY author_id
                ) pr_counts ON a.agent_id = pr_counts.author_id
                LEFT JOIN (
                    SELECT reviewer_id, COUNT(*) as count
                    FROM reviews
                    GROUP BY reviewer_id
                ) review_counts ON a.agent_id = review_counts.reviewer_id
                WHERE a.agent_name ILIKE $1 OR a.agent_id ILIKE $1
                ORDER BY a.created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(pattern)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AgentRow>(
                r#"
                SELECT 
                    a.agent_id,
                    a.agent_name,
                    a.public_key,
                    a.capabilities,
                    a.created_at,
                    a.suspended,
                    a.suspended_at,
                    a.suspended_reason,
                    CAST(COALESCE(r.score, 0.5) AS DOUBLE PRECISION) as reputation_score,
                    COALESCE(repo_counts.count, 0) as repo_count,
                    COALESCE(pr_counts.count, 0) as pr_count,
                    COALESCE(review_counts.count, 0) as review_count
                FROM agents a
                LEFT JOIN reputation r ON a.agent_id = r.agent_id
                LEFT JOIN (
                    SELECT owner_id, COUNT(*) as count
                    FROM repositories
                    GROUP BY owner_id
                ) repo_counts ON a.agent_id = repo_counts.owner_id
                LEFT JOIN (
                    SELECT author_id, COUNT(*) as count
                    FROM pull_requests
                    GROUP BY author_id
                ) pr_counts ON a.agent_id = pr_counts.author_id
                LEFT JOIN (
                    SELECT reviewer_id, COUNT(*) as count
                    FROM reviews
                    GROUP BY reviewer_id
                ) review_counts ON a.agent_id = review_counts.reviewer_id
                ORDER BY a.created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(per_page)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        };

        // Convert rows to AdminAgentDetails
        let items: Vec<AdminAgentDetails> = agents.into_iter().map(|row| row.into()).collect();

        Ok(PaginatedResponse::new(items, total, page, per_page))
    }

    /// Get detailed agent information
    ///
    /// Requirements: 2.3, 2.7
    ///
    /// Returns full agent details including reputation score and activity counts
    /// (repo_count, pr_count, review_count).
    pub async fn get_agent(&self, agent_id: &str) -> Result<AdminAgentDetails, AdminError> {
        let agent = sqlx::query_as::<_, AgentRow>(
            r#"
            SELECT 
                a.agent_id,
                a.agent_name,
                a.public_key,
                a.capabilities,
                a.created_at,
                a.suspended,
                a.suspended_at,
                a.suspended_reason,
                CAST(COALESCE(r.score, 0.5) AS DOUBLE PRECISION) as reputation_score,
                COALESCE(repo_counts.count, 0) as repo_count,
                COALESCE(pr_counts.count, 0) as pr_count,
                COALESCE(review_counts.count, 0) as review_count
            FROM agents a
            LEFT JOIN reputation r ON a.agent_id = r.agent_id
            LEFT JOIN (
                SELECT owner_id, COUNT(*) as count
                FROM repositories
                GROUP BY owner_id
            ) repo_counts ON a.agent_id = repo_counts.owner_id
            LEFT JOIN (
                SELECT author_id, COUNT(*) as count
                FROM pull_requests
                GROUP BY author_id
            ) pr_counts ON a.agent_id = pr_counts.author_id
            LEFT JOIN (
                SELECT reviewer_id, COUNT(*) as count
                FROM reviews
                GROUP BY reviewer_id
            ) review_counts ON a.agent_id = review_counts.reviewer_id
            WHERE a.agent_id = $1
            "#,
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match agent {
            Some(row) => Ok(row.into()),
            None => Err(AdminError::AgentNotFound(agent_id.to_string())),
        }
    }

    /// Suspend an agent
    ///
    /// Requirements: 2.4
    ///
    /// Sets the agent's suspension status to true, records the suspension timestamp,
    /// reason, and admin who performed the action. Creates an audit log entry.
    ///
    /// # Errors
    /// - `AgentNotFound` if the agent does not exist
    /// - `AlreadySuspended` if the agent is already suspended
    pub async fn suspend_agent(
        &self,
        agent_id: &str,
        admin_id: &str,
        reason: Option<String>,
    ) -> Result<(), AdminError> {
        // Start a transaction to ensure atomicity
        let mut tx = self.pool.begin().await?;

        // Check if agent exists and get current suspension status
        let agent = sqlx::query_as::<_, (bool,)>(
            "SELECT suspended FROM agents WHERE agent_id = $1 FOR UPDATE",
        )
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        match agent {
            None => {
                return Err(AdminError::AgentNotFound(agent_id.to_string()));
            }
            Some((true,)) => {
                return Err(AdminError::AlreadySuspended(agent_id.to_string()));
            }
            Some((false,)) => {
                // Agent exists and is not suspended, proceed
            }
        }

        // Update the agent's suspension status
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            UPDATE agents
            SET suspended = TRUE,
                suspended_at = $1,
                suspended_reason = $2,
                suspended_by = $3
            WHERE agent_id = $4
            "#,
        )
        .bind(now)
        .bind(&reason)
        .bind(admin_id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;

        // Create audit log entry
        let audit_data = serde_json::json!({
            "reason": reason,
            "admin_id": admin_id,
        });

        let audit_event = AuditEvent::new(
            admin_id,
            AuditAction::AdminSuspendAgent,
            ResourceType::Agent,
            agent_id,
            audit_data,
            "", // Admin actions don't require cryptographic signatures
        );

        AuditService::append_in_tx(&mut tx, audit_event).await.map_err(|e| {
            AdminError::Internal(format!("Failed to create audit entry: {e}"))
        })?;

        tx.commit().await?;

        Ok(())
    }

    /// Unsuspend an agent
    ///
    /// Requirements: 2.5
    ///
    /// Clears the agent's suspension status and related fields.
    /// Creates an audit log entry.
    ///
    /// # Errors
    /// - `AgentNotFound` if the agent does not exist
    /// - `NotSuspended` if the agent is not currently suspended
    pub async fn unsuspend_agent(&self, agent_id: &str, admin_id: &str) -> Result<(), AdminError> {
        // Start a transaction to ensure atomicity
        let mut tx = self.pool.begin().await?;

        // Check if agent exists and get current suspension status
        let agent = sqlx::query_as::<_, (bool,)>(
            "SELECT suspended FROM agents WHERE agent_id = $1 FOR UPDATE",
        )
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        match agent {
            None => {
                return Err(AdminError::AgentNotFound(agent_id.to_string()));
            }
            Some((false,)) => {
                return Err(AdminError::NotSuspended(agent_id.to_string()));
            }
            Some((true,)) => {
                // Agent exists and is suspended, proceed
            }
        }

        // Clear the agent's suspension status
        sqlx::query(
            r#"
            UPDATE agents
            SET suspended = FALSE,
                suspended_at = NULL,
                suspended_reason = NULL,
                suspended_by = NULL
            WHERE agent_id = $1
            "#,
        )
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;

        // Create audit log entry
        let audit_data = serde_json::json!({
            "admin_id": admin_id,
        });

        let audit_event = AuditEvent::new(
            admin_id,
            AuditAction::AdminUnsuspendAgent,
            ResourceType::Agent,
            agent_id,
            audit_data,
            "", // Admin actions don't require cryptographic signatures
        );

        AuditService::append_in_tx(&mut tx, audit_event).await.map_err(|e| {
            AdminError::Internal(format!("Failed to create audit entry: {e}"))
        })?;

        tx.commit().await?;

        Ok(())
    }

    /// List repositories with pagination and search
    ///
    /// Requirements: 3.1, 3.2
    ///
    /// Supports searching by name, owner_name, or repo_id using case-insensitive ILIKE.
    /// Returns paginated results with repository details including star count, PR count,
    /// CI run count, object count, and total size.
    pub async fn list_repos(
        &self,
        params: PaginationParams,
    ) -> Result<PaginatedResponse<AdminRepoDetails>, AdminError> {
        let page = params.page();
        let per_page = params.per_page();
        let offset = params.offset();

        // Build the search condition if a search term is provided
        let search_pattern = params
            .search
            .as_ref()
            .map(|s| format!("%{}%", s.replace('%', "\\%").replace('_', "\\_")));

        // Count total matching repositories
        let total: i64 = if let Some(ref pattern) = search_pattern {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM repositories r
                JOIN agents a ON r.owner_id = a.agent_id
                WHERE r.name ILIKE $1 OR a.agent_name ILIKE $1 OR r.repo_id ILIKE $1
                "#,
            )
            .bind(pattern)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM repositories")
                .fetch_one(&self.pool)
                .await?
        };

        // Fetch repositories with their details
        // Join with agents for owner_name, and aggregate counts from related tables
        let repos = if let Some(ref pattern) = search_pattern {
            sqlx::query_as::<_, RepoRow>(
                r#"
                SELECT 
                    r.repo_id,
                    r.name,
                    r.owner_id,
                    a.agent_name as owner_name,
                    r.description,
                    r.visibility,
                    r.default_branch,
                    r.created_at,
                    COALESCE(star_counts.stars, 0) as star_count,
                    COALESCE(pr_counts.count, 0) as pr_count,
                    COALESCE(ci_counts.count, 0) as ci_run_count,
                    COALESCE(obj_stats.object_count, 0) as object_count,
                    COALESCE(obj_stats.total_size, 0) as total_size_bytes
                FROM repositories r
                JOIN agents a ON r.owner_id = a.agent_id
                LEFT JOIN repo_star_counts star_counts ON r.repo_id = star_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as count
                    FROM pull_requests
                    GROUP BY repo_id
                ) pr_counts ON r.repo_id = pr_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as count
                    FROM ci_runs
                    GROUP BY repo_id
                ) ci_counts ON r.repo_id = ci_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as object_count, COALESCE(SUM(size), 0) as total_size
                    FROM repo_objects
                    GROUP BY repo_id
                ) obj_stats ON r.repo_id = obj_stats.repo_id
                WHERE r.name ILIKE $1 OR a.agent_name ILIKE $1 OR r.repo_id ILIKE $1
                ORDER BY r.created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(pattern)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, RepoRow>(
                r#"
                SELECT 
                    r.repo_id,
                    r.name,
                    r.owner_id,
                    a.agent_name as owner_name,
                    r.description,
                    r.visibility,
                    r.default_branch,
                    r.created_at,
                    COALESCE(star_counts.stars, 0) as star_count,
                    COALESCE(pr_counts.count, 0) as pr_count,
                    COALESCE(ci_counts.count, 0) as ci_run_count,
                    COALESCE(obj_stats.object_count, 0) as object_count,
                    COALESCE(obj_stats.total_size, 0) as total_size_bytes
                FROM repositories r
                JOIN agents a ON r.owner_id = a.agent_id
                LEFT JOIN repo_star_counts star_counts ON r.repo_id = star_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as count
                    FROM pull_requests
                    GROUP BY repo_id
                ) pr_counts ON r.repo_id = pr_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as count
                    FROM ci_runs
                    GROUP BY repo_id
                ) ci_counts ON r.repo_id = ci_counts.repo_id
                LEFT JOIN (
                    SELECT repo_id, COUNT(*) as object_count, COALESCE(SUM(size), 0) as total_size
                    FROM repo_objects
                    GROUP BY repo_id
                ) obj_stats ON r.repo_id = obj_stats.repo_id
                ORDER BY r.created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(per_page)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        };

        // Convert rows to AdminRepoDetails
        let items: Vec<AdminRepoDetails> = repos.into_iter().map(|row| row.into()).collect();

        Ok(PaginatedResponse::new(items, total, page, per_page))
    }

    /// Get detailed repository information
    ///
    /// Requirements: 3.3, 3.5
    ///
    /// Returns full repository details including star_count, pr_count, ci_run_count,
    /// object_count, and total_size_bytes.
    pub async fn get_repo(&self, repo_id: &str) -> Result<AdminRepoDetails, AdminError> {
        let repo = sqlx::query_as::<_, RepoRow>(
            r#"
            SELECT 
                r.repo_id,
                r.name,
                r.owner_id,
                a.agent_name as owner_name,
                r.description,
                r.visibility,
                r.default_branch,
                r.created_at,
                COALESCE(star_counts.stars, 0) as star_count,
                COALESCE(pr_counts.count, 0) as pr_count,
                COALESCE(ci_counts.count, 0) as ci_run_count,
                COALESCE(obj_stats.object_count, 0) as object_count,
                COALESCE(obj_stats.total_size, 0) as total_size_bytes
            FROM repositories r
            JOIN agents a ON r.owner_id = a.agent_id
            LEFT JOIN repo_star_counts star_counts ON r.repo_id = star_counts.repo_id
            LEFT JOIN (
                SELECT repo_id, COUNT(*) as count
                FROM pull_requests
                GROUP BY repo_id
            ) pr_counts ON r.repo_id = pr_counts.repo_id
            LEFT JOIN (
                SELECT repo_id, COUNT(*) as count
                FROM ci_runs
                GROUP BY repo_id
            ) ci_counts ON r.repo_id = ci_counts.repo_id
            LEFT JOIN (
                SELECT repo_id, COUNT(*) as object_count, COALESCE(SUM(size), 0) as total_size
                FROM repo_objects
                GROUP BY repo_id
            ) obj_stats ON r.repo_id = obj_stats.repo_id
            WHERE r.repo_id = $1
            "#,
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;

        match repo {
            Some(row) => Ok(row.into()),
            None => Err(AdminError::RepoNotFound(repo_id.to_string())),
        }
    }

    /// Delete a repository and all associated data
    ///
    /// Requirements: 3.4
    ///
    /// Deletes the repository and all associated data in the correct order to respect
    /// foreign key constraints. Creates an audit log entry recording the deletion.
    ///
    /// Deletion order:
    /// 1. ci_step_results (via ci_runs)
    /// 2. ci_runs
    /// 3. reviews (via pull_requests)
    /// 4. pull_requests
    /// 5. repo_stars
    /// 6. repo_star_counts
    /// 7. repo_trending_scores
    /// 8. repo_objects
    /// 9. repo_refs
    /// 10. repo_access
    /// 11. repositories
    ///
    /// # Errors
    /// - `RepoNotFound` if the repository does not exist
    pub async fn delete_repo(&self, repo_id: &str, admin_id: &str) -> Result<(), AdminError> {
        // Start a transaction to ensure atomicity
        let mut tx = self.pool.begin().await?;

        // Check if repository exists and get metadata for audit log
        let repo_metadata = sqlx::query_as::<_, (String, String, String)>(
            "SELECT repo_id, name, owner_id FROM repositories WHERE repo_id = $1 FOR UPDATE",
        )
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (repo_id_confirmed, repo_name, owner_id) = match repo_metadata {
            Some(metadata) => metadata,
            None => {
                return Err(AdminError::RepoNotFound(repo_id.to_string()));
            }
        };

        // Collect counts for audit log before deletion
        let star_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM repo_stars WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        let pr_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pull_requests WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        let ci_run_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ci_runs WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        let object_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM repo_objects WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;

        // Delete in order to respect foreign key constraints
        // Note: Many tables have ON DELETE CASCADE, but we delete explicitly for clarity
        // and to ensure proper cleanup

        // 1. Delete ci_step_results (references ci_runs)
        sqlx::query(
            r#"
            DELETE FROM ci_step_results
            WHERE run_id IN (SELECT run_id FROM ci_runs WHERE repo_id = $1)
            "#,
        )
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;

        // 2. Delete ci_runs
        sqlx::query("DELETE FROM ci_runs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 3. Delete reviews (references pull_requests)
        sqlx::query(
            r#"
            DELETE FROM reviews
            WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)
            "#,
        )
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;

        // 4. Delete pull_requests
        sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 5. Delete repo_stars
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 6. Delete repo_star_counts
        sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 7. Delete repo_trending_scores
        sqlx::query("DELETE FROM repo_trending_scores WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 8. Delete repo_objects
        sqlx::query("DELETE FROM repo_objects WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 9. Delete repo_refs
        sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 10. Delete repo_access
        sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // 11. Delete the repository itself
        sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        // Create audit log entry with deletion metadata
        let audit_data = serde_json::json!({
            "admin_id": admin_id,
            "repo_name": repo_name,
            "owner_id": owner_id,
            "deleted_counts": {
                "stars": star_count,
                "pull_requests": pr_count,
                "ci_runs": ci_run_count,
                "objects": object_count,
            }
        });

        let audit_event = AuditEvent::new(
            admin_id,
            AuditAction::AdminDeleteRepo,
            ResourceType::Repository,
            &repo_id_confirmed,
            audit_data,
            "", // Admin actions don't require cryptographic signatures
        );

        AuditService::append_in_tx(&mut tx, audit_event)
            .await
            .map_err(|e| AdminError::Internal(format!("Failed to create audit entry: {e}")))?;

        tx.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_error_codes() {
        assert_eq!(
            AdminError::AgentNotFound("test".to_string()).error_code(),
            "AGENT_NOT_FOUND"
        );
        assert_eq!(
            AdminError::RepoNotFound("test".to_string()).error_code(),
            "REPO_NOT_FOUND"
        );
        assert_eq!(
            AdminError::AlreadySuspended("test".to_string()).error_code(),
            "ALREADY_SUSPENDED"
        );
        assert_eq!(
            AdminError::NotSuspended("test".to_string()).error_code(),
            "NOT_SUSPENDED"
        );
        assert_eq!(
            AdminError::InvalidCredentials.error_code(),
            "INVALID_CREDENTIALS"
        );
        assert_eq!(AdminError::SessionExpired.error_code(), "SESSION_EXPIRED");
        assert_eq!(AdminError::Unauthorized.error_code(), "UNAUTHORIZED");
        assert_eq!(
            AdminError::InvalidPagination("test".to_string()).error_code(),
            "INVALID_PAGINATION"
        );
        assert_eq!(
            AdminError::NotOrphaned("test".to_string()).error_code(),
            "NOT_ORPHANED"
        );
        assert_eq!(
            AdminError::DisconnectionTypeMismatch {
                expected: "db".to_string(),
                found: "storage".to_string()
            }
            .error_code(),
            "DISCONNECTION_TYPE_MISMATCH"
        );
        assert_eq!(
            AdminError::OwnerNotFound("test".to_string()).error_code(),
            "OWNER_NOT_FOUND"
        );
    }

    #[test]
    fn test_admin_error_status_codes() {
        use actix_web::http::StatusCode;

        assert_eq!(
            AdminError::AgentNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminError::RepoNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminError::OwnerNotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AdminError::AlreadySuspended("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AdminError::NotSuspended("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AdminError::NotOrphaned("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AdminError::InvalidCredentials.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::SessionExpired.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::Unauthorized.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::InvalidPagination("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_platform_stats_serialization() {
        let stats = PlatformStats {
            total_agents: 100,
            total_repos: 50,
            total_stars: 500,
            pull_requests: PullRequestStats {
                open: 10,
                merged: 30,
                closed: 5,
            },
            ci_runs: CIRunStats {
                pending: 2,
                running: 3,
                passed: 40,
                failed: 5,
            },
            suspended_agents: 2,
        };

        let json = serde_json::to_string(&stats).expect("Failed to serialize");
        assert!(json.contains("\"totalAgents\":100"));
        assert!(json.contains("\"totalRepos\":50"));
        assert!(json.contains("\"totalStars\":500"));
        assert!(json.contains("\"pullRequests\""));
        assert!(json.contains("\"ciRuns\""));
        assert!(json.contains("\"suspendedAgents\":2"));
    }

    #[test]
    fn test_pull_request_stats_serialization() {
        let stats = PullRequestStats {
            open: 10,
            merged: 20,
            closed: 5,
        };

        let json = serde_json::to_string(&stats).expect("Failed to serialize");
        assert!(json.contains("\"open\":10"));
        assert!(json.contains("\"merged\":20"));
        assert!(json.contains("\"closed\":5"));
    }

    #[test]
    fn test_ci_run_stats_serialization() {
        let stats = CIRunStats {
            pending: 1,
            running: 2,
            passed: 30,
            failed: 3,
        };

        let json = serde_json::to_string(&stats).expect("Failed to serialize");
        assert!(json.contains("\"pending\":1"));
        assert!(json.contains("\"running\":2"));
        assert!(json.contains("\"passed\":30"));
        assert!(json.contains("\"failed\":3"));
    }

    #[test]
    fn test_pagination_params_defaults() {
        let params = PaginationParams::default();
        assert_eq!(params.page(), 1);
        assert_eq!(params.per_page(), 20);
        assert_eq!(params.offset(), 0);
    }

    #[test]
    fn test_pagination_params_custom_values() {
        let params = PaginationParams {
            page: Some(3),
            per_page: Some(50),
            search: Some("test".to_string()),
        };
        assert_eq!(params.page(), 3);
        assert_eq!(params.per_page(), 50);
        assert_eq!(params.offset(), 100); // (3-1) * 50
    }

    #[test]
    fn test_pagination_params_clamps_per_page() {
        // Test max clamping
        let params = PaginationParams {
            page: Some(1),
            per_page: Some(200),
            search: None,
        };
        assert_eq!(params.per_page(), 100); // Clamped to max

        // Test min clamping
        let params = PaginationParams {
            page: Some(1),
            per_page: Some(0),
            search: None,
        };
        assert_eq!(params.per_page(), 1); // Clamped to min
    }

    #[test]
    fn test_pagination_params_negative_page() {
        let params = PaginationParams {
            page: Some(-5),
            per_page: Some(20),
            search: None,
        };
        assert_eq!(params.page(), 1); // Clamped to 1
        assert_eq!(params.offset(), 0);
    }

    #[test]
    fn test_paginated_response_new() {
        let items = vec!["a", "b", "c"];
        let response = PaginatedResponse::new(items, 25, 2, 10);

        assert_eq!(response.items.len(), 3);
        assert_eq!(response.total, 25);
        assert_eq!(response.page, 2);
        assert_eq!(response.per_page, 10);
        assert_eq!(response.total_pages, 3); // ceil(25/10) = 3
    }

    #[test]
    fn test_paginated_response_empty() {
        let items: Vec<String> = vec![];
        let response = PaginatedResponse::new(items, 0, 1, 10);

        assert_eq!(response.items.len(), 0);
        assert_eq!(response.total, 0);
        assert_eq!(response.total_pages, 1); // At least 1 page even when empty
    }

    #[test]
    fn test_paginated_response_exact_pages() {
        let items = vec![1, 2, 3, 4, 5];
        let response = PaginatedResponse::new(items, 20, 1, 5);

        assert_eq!(response.total_pages, 4); // Exactly 20/5 = 4 pages
    }

    #[test]
    fn test_paginated_response_serialization() {
        let items = vec!["item1".to_string(), "item2".to_string()];
        let response = PaginatedResponse::new(items, 10, 1, 5);

        let json = serde_json::to_string(&response).expect("Failed to serialize");
        assert!(json.contains("\"items\":[\"item1\",\"item2\"]"));
        assert!(json.contains("\"total\":10"));
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"perPage\":5"));
        assert!(json.contains("\"totalPages\":2"));
    }

    #[test]
    fn test_admin_agent_details_serialization() {
        let agent = AdminAgentDetails {
            agent_id: "agent-123".to_string(),
            agent_name: "TestAgent".to_string(),
            public_key: "pk_test".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string()],
            created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
            suspended: false,
            suspended_at: None,
            suspended_reason: None,
            reputation_score: 0.75,
            repo_count: 5,
            pr_count: 10,
            review_count: 15,
        };

        let json = serde_json::to_string(&agent).expect("Failed to serialize");
        assert!(json.contains("\"agentId\":\"agent-123\""));
        assert!(json.contains("\"agentName\":\"TestAgent\""));
        assert!(json.contains("\"publicKey\":\"pk_test\""));
        assert!(json.contains("\"capabilities\":[\"read\",\"write\"]"));
        assert!(json.contains("\"suspended\":false"));
        assert!(json.contains("\"reputationScore\":0.75"));
        assert!(json.contains("\"repoCount\":5"));
        assert!(json.contains("\"prCount\":10"));
        assert!(json.contains("\"reviewCount\":15"));
    }

    #[test]
    fn test_admin_agent_details_with_suspension() {
        let agent = AdminAgentDetails {
            agent_id: "agent-456".to_string(),
            agent_name: "SuspendedAgent".to_string(),
            public_key: "pk_suspended".to_string(),
            capabilities: vec![],
            created_at: DateTime::parse_from_rfc3339("2024-01-10T08:00:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
            suspended: true,
            suspended_at: Some(
                DateTime::parse_from_rfc3339("2024-01-14T12:00:00Z")
                    .expect("Failed to parse date")
                    .with_timezone(&Utc),
            ),
            suspended_reason: Some("Violation of terms".to_string()),
            reputation_score: 0.2,
            repo_count: 0,
            pr_count: 0,
            review_count: 0,
        };

        let json = serde_json::to_string(&agent).expect("Failed to serialize");
        assert!(json.contains("\"suspended\":true"));
        assert!(json.contains("\"suspendedAt\":"));
        assert!(json.contains("\"suspendedReason\":\"Violation of terms\""));
    }

    #[test]
    fn test_pagination_params_deserialization() {
        let json = r#"{"page": 2, "perPage": 25, "search": "test"}"#;
        let params: PaginationParams = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(params.page, Some(2));
        assert_eq!(params.per_page, Some(25));
        assert_eq!(params.search, Some("test".to_string()));
    }

    #[test]
    fn test_pagination_params_deserialization_partial() {
        let json = r#"{"page": 5}"#;
        let params: PaginationParams = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(params.page, Some(5));
        assert_eq!(params.per_page, None);
        assert_eq!(params.search, None);
        assert_eq!(params.page(), 5);
        assert_eq!(params.per_page(), 20); // Default
    }

    #[test]
    fn test_pagination_params_deserialization_empty() {
        let json = r#"{}"#;
        let params: PaginationParams = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(params.page, None);
        assert_eq!(params.per_page, None);
        assert_eq!(params.search, None);
    }

    #[test]
    fn test_admin_repo_details_serialization() {
        let repo = AdminRepoDetails {
            repo_id: "repo-123".to_string(),
            name: "test-repo".to_string(),
            owner_id: "agent-456".to_string(),
            owner_name: "TestAgent".to_string(),
            description: Some("A test repository".to_string()),
            visibility: Visibility::Public,
            default_branch: "main".to_string(),
            created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
            star_count: 42,
            pr_count: 10,
            ci_run_count: 25,
            object_count: 100,
            total_size_bytes: 1024000,
        };

        let json = serde_json::to_string(&repo).expect("Failed to serialize");
        assert!(json.contains("\"repoId\":\"repo-123\""));
        assert!(json.contains("\"name\":\"test-repo\""));
        assert!(json.contains("\"ownerId\":\"agent-456\""));
        assert!(json.contains("\"ownerName\":\"TestAgent\""));
        assert!(json.contains("\"description\":\"A test repository\""));
        assert!(json.contains("\"visibility\":\"public\""));
        assert!(json.contains("\"defaultBranch\":\"main\""));
        assert!(json.contains("\"starCount\":42"));
        assert!(json.contains("\"prCount\":10"));
        assert!(json.contains("\"ciRunCount\":25"));
        assert!(json.contains("\"objectCount\":100"));
        assert!(json.contains("\"totalSizeBytes\":1024000"));
    }

    #[test]
    fn test_admin_repo_details_private_visibility() {
        let repo = AdminRepoDetails {
            repo_id: "repo-789".to_string(),
            name: "private-repo".to_string(),
            owner_id: "agent-123".to_string(),
            owner_name: "PrivateAgent".to_string(),
            description: None,
            visibility: Visibility::Private,
            default_branch: "develop".to_string(),
            created_at: DateTime::parse_from_rfc3339("2024-02-01T08:00:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
            star_count: 0,
            pr_count: 0,
            ci_run_count: 0,
            object_count: 0,
            total_size_bytes: 0,
        };

        let json = serde_json::to_string(&repo).expect("Failed to serialize");
        assert!(json.contains("\"visibility\":\"private\""));
        assert!(json.contains("\"description\":null"));
        assert!(json.contains("\"starCount\":0"));
    }

    #[test]
    fn test_repo_row_to_admin_repo_details_conversion() {
        let row = RepoRow {
            repo_id: "repo-conv".to_string(),
            name: "converted-repo".to_string(),
            owner_id: "owner-id".to_string(),
            owner_name: "OwnerName".to_string(),
            description: Some("Converted description".to_string()),
            visibility: Visibility::Public,
            default_branch: "main".to_string(),
            created_at: DateTime::parse_from_rfc3339("2024-03-01T12:00:00Z")
                .expect("Failed to parse date")
                .with_timezone(&Utc),
            star_count: 5,
            pr_count: 3,
            ci_run_count: 10,
            object_count: 50,
            total_size_bytes: 512000,
        };

        let details: AdminRepoDetails = row.into();

        assert_eq!(details.repo_id, "repo-conv");
        assert_eq!(details.name, "converted-repo");
        assert_eq!(details.owner_id, "owner-id");
        assert_eq!(details.owner_name, "OwnerName");
        assert_eq!(details.description, Some("Converted description".to_string()));
        assert_eq!(details.visibility, Visibility::Public);
        assert_eq!(details.default_branch, "main");
        assert_eq!(details.star_count, 5);
        assert_eq!(details.pr_count, 3);
        assert_eq!(details.ci_run_count, 10);
        assert_eq!(details.object_count, 50);
        assert_eq!(details.total_size_bytes, 512000);
    }
}

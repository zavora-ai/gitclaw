//! Audit Service
//!
//! Manages the append-only audit log which is the authoritative source of truth
//! for all platform activity.
//!
//! Design Reference: DR-14.1 (Audit Service)
//! Requirements: 11.1, 11.2, 11.3, 11.4, 11.6

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// Audit service errors
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Invalid query parameters: {0}")]
    InvalidQuery(String),
}

/// Action types that can be audited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Agent registration
    AgentRegister,
    /// Repository creation
    RepoCreate,
    /// Repository clone
    RepoClone,
    /// Git push
    Push,
    /// Pull request opened
    PrOpen,
    /// Pull request reviewed
    PrReview,
    /// Pull request merged
    PrMerge,
    /// Pull request closed
    PrClose,
    /// CI run started
    CiStart,
    /// CI run completed
    CiComplete,
    /// Repository starred
    Star,
    /// Repository unstarred
    Unstar,
    /// Access granted
    AccessGrant,
    /// Access revoked
    AccessRevoke,
    /// Reputation updated
    ReputationUpdate,
    /// Admin suspended an agent
    AdminSuspendAgent,
    /// Admin unsuspended an agent
    AdminUnsuspendAgent,
    /// Admin deleted a repository
    AdminDeleteRepo,
    /// Admin logged in
    AdminLogin,
    /// Admin logged out
    AdminLogout,
    /// Admin reconnected orphaned storage to database
    AdminReconnectRepo,
    /// Admin deleted orphaned DB record
    AdminDeleteOrphanedDb,
    /// Admin deleted orphaned storage objects
    AdminDeleteOrphanedStorage,
}

impl AuditAction {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentRegister => "agent_register",
            Self::RepoCreate => "repo_create",
            Self::RepoClone => "repo_clone",
            Self::Push => "push",
            Self::PrOpen => "pr_open",
            Self::PrReview => "pr_review",
            Self::PrMerge => "pr_merge",
            Self::PrClose => "pr_close",
            Self::CiStart => "ci_start",
            Self::CiComplete => "ci_complete",
            Self::Star => "star",
            Self::Unstar => "unstar",
            Self::AccessGrant => "access_grant",
            Self::AccessRevoke => "access_revoke",
            Self::ReputationUpdate => "reputation_update",
            Self::AdminSuspendAgent => "admin_suspend_agent",
            Self::AdminUnsuspendAgent => "admin_unsuspend_agent",
            Self::AdminDeleteRepo => "admin_delete_repo",
            Self::AdminLogin => "admin_login",
            Self::AdminLogout => "admin_logout",
            Self::AdminReconnectRepo => "admin_reconnect_repo",
            Self::AdminDeleteOrphanedDb => "admin_delete_orphaned_db",
            Self::AdminDeleteOrphanedStorage => "admin_delete_orphaned_storage",
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Resource types that can be audited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Agent,
    Repository,
    PullRequest,
    Review,
    CiRun,
    Star,
    Access,
    Reputation,
    /// Admin session for login/logout events
    AdminSession,
}

impl ResourceType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Repository => "repository",
            Self::PullRequest => "pull_request",
            Self::Review => "review",
            Self::CiRun => "ci_run",
            Self::Star => "star",
            Self::Access => "access",
            Self::Reputation => "reputation",
            Self::AdminSession => "admin_session",
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Service for managing the audit log
#[derive(Debug, Clone)]
pub struct AuditService {
    pool: PgPool,
}

/// Audit event to be recorded
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub agent_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub data: serde_json::Value,
    pub signature: String,
}

impl AuditEvent {
    /// Create a new audit event with typed action and resource
    pub fn new(
        agent_id: impl Into<String>,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: impl Into<String>,
        data: serde_json::Value,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.into(),
            data,
            signature: signature.into(),
        }
    }
}

/// Recorded audit event with generated fields
#[derive(Debug, Clone, Serialize)]
pub struct RecordedAuditEvent {
    pub event_id: Uuid,
    pub agent_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

/// Query parameters for filtering audit events
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Filter by resource ID
    pub resource_id: Option<String>,
    /// Filter by action type
    pub action: Option<String>,
    /// Filter events after this timestamp
    pub from_timestamp: Option<DateTime<Utc>>,
    /// Filter events before this timestamp
    pub to_timestamp: Option<DateTime<Utc>>,
    /// Maximum number of results to return
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

impl AuditQuery {
    /// Create a new query builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by agent ID
    pub fn agent(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Filter by resource type
    pub fn resource_type(mut self, resource_type: ResourceType) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self
    }

    /// Filter by resource ID
    pub fn resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Filter by action type
    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action.to_string());
        self
    }

    /// Filter events after this timestamp
    pub fn from(mut self, timestamp: DateTime<Utc>) -> Self {
        self.from_timestamp = Some(timestamp);
        self
    }

    /// Filter events before this timestamp
    pub fn to(mut self, timestamp: DateTime<Utc>) -> Self {
        self.to_timestamp = Some(timestamp);
        self
    }

    /// Set maximum number of results
    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination
    pub fn offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Response for paginated audit queries
#[derive(Debug, Clone, Serialize)]
pub struct AuditQueryResponse {
    pub events: Vec<RecordedAuditEvent>,
    pub total_count: i64,
    pub has_more: bool,
}

impl AuditService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Append an audit event to the log
    ///
    /// Requirements: 11.1, 11.2
    pub async fn append(&self, event: AuditEvent) -> Result<RecordedAuditEvent, AuditError> {
        let event_id = Uuid::new_v4();
        let timestamp = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(event_id)
        .bind(&event.agent_id)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&event.data)
        .bind(timestamp)
        .bind(&event.signature)
        .execute(&self.pool)
        .await?;

        Ok(RecordedAuditEvent {
            event_id,
            agent_id: event.agent_id,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            data: event.data,
            timestamp,
            signature: event.signature,
        })
    }

    /// Append an audit event within an existing transaction
    ///
    /// Requirements: 11.1, 11.2
    pub async fn append_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        event: AuditEvent,
    ) -> Result<RecordedAuditEvent, AuditError> {
        let event_id = Uuid::new_v4();
        let timestamp = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(event_id)
        .bind(&event.agent_id)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&event.data)
        .bind(timestamp)
        .bind(&event.signature)
        .execute(&mut **tx)
        .await?;

        Ok(RecordedAuditEvent {
            event_id,
            agent_id: event.agent_id,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            data: event.data,
            timestamp,
            signature: event.signature,
        })
    }

    /// Query audit events with filters
    ///
    /// Requirements: 11.3
    pub async fn query(&self, query: AuditQuery) -> Result<AuditQueryResponse, AuditError> {
        let limit = query.limit.unwrap_or(100).min(1000);
        let offset = query.offset.unwrap_or(0);

        // Build the WHERE clause dynamically
        let mut conditions = Vec::new();
        let mut param_idx = 1;

        if query.agent_id.is_some() {
            conditions.push(format!("agent_id = ${param_idx}"));
            param_idx += 1;
        }
        if query.resource_type.is_some() {
            conditions.push(format!("resource_type = ${param_idx}"));
            param_idx += 1;
        }
        if query.resource_id.is_some() {
            conditions.push(format!("resource_id = ${param_idx}"));
            param_idx += 1;
        }
        if query.action.is_some() {
            conditions.push(format!("action = ${param_idx}"));
            param_idx += 1;
        }
        if query.from_timestamp.is_some() {
            conditions.push(format!("timestamp >= ${param_idx}"));
            param_idx += 1;
        }
        if query.to_timestamp.is_some() {
            conditions.push(format!("timestamp <= ${param_idx}"));
            param_idx += 1;
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        // Count total matching events
        let count_sql = format!("SELECT COUNT(*) as count FROM audit_log {where_clause}");
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);

        if let Some(ref agent_id) = query.agent_id {
            count_query = count_query.bind(agent_id);
        }
        if let Some(ref resource_type) = query.resource_type {
            count_query = count_query.bind(resource_type);
        }
        if let Some(ref resource_id) = query.resource_id {
            count_query = count_query.bind(resource_id);
        }
        if let Some(ref action) = query.action {
            count_query = count_query.bind(action);
        }
        if let Some(from_ts) = query.from_timestamp {
            count_query = count_query.bind(from_ts);
        }
        if let Some(to_ts) = query.to_timestamp {
            count_query = count_query.bind(to_ts);
        }

        let total_count = count_query.fetch_one(&self.pool).await?;

        // Fetch events with pagination
        let select_sql = format!(
            r#"
            SELECT event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature
            FROM audit_log
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ${param_idx} OFFSET ${next_param}
            "#,
            param_idx = param_idx,
            next_param = param_idx + 1
        );

        let mut select_query = sqlx::query_as::<_, AuditEventRow>(&select_sql);

        if let Some(ref agent_id) = query.agent_id {
            select_query = select_query.bind(agent_id);
        }
        if let Some(ref resource_type) = query.resource_type {
            select_query = select_query.bind(resource_type);
        }
        if let Some(ref resource_id) = query.resource_id {
            select_query = select_query.bind(resource_id);
        }
        if let Some(ref action) = query.action {
            select_query = select_query.bind(action);
        }
        if let Some(from_ts) = query.from_timestamp {
            select_query = select_query.bind(from_ts);
        }
        if let Some(to_ts) = query.to_timestamp {
            select_query = select_query.bind(to_ts);
        }

        select_query = select_query.bind(limit).bind(offset);

        let rows = select_query.fetch_all(&self.pool).await?;

        let events: Vec<RecordedAuditEvent> = rows.into_iter().map(|row| row.into()).collect();
        let has_more = (offset + events.len() as i64) < total_count;

        Ok(AuditQueryResponse {
            events,
            total_count,
            has_more,
        })
    }

    /// Get a single audit event by ID
    pub async fn get_by_id(
        &self,
        event_id: Uuid,
    ) -> Result<Option<RecordedAuditEvent>, AuditError> {
        let row = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature
            FROM audit_log
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Get audit events for a specific resource
    pub async fn get_for_resource(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
    ) -> Result<Vec<RecordedAuditEvent>, AuditError> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature
            FROM audit_log
            WHERE resource_type = $1 AND resource_id = $2
            ORDER BY timestamp DESC
            "#,
        )
        .bind(resource_type.as_str())
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get audit events for a specific agent
    pub async fn get_for_agent(
        &self,
        agent_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<RecordedAuditEvent>, AuditError> {
        let limit = limit.unwrap_or(100).min(1000);

        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature
            FROM audit_log
            WHERE agent_id = $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }
}

/// Internal row type for database queries
#[derive(Debug, sqlx::FromRow)]
struct AuditEventRow {
    event_id: Uuid,
    agent_id: String,
    action: String,
    resource_type: String,
    resource_id: String,
    data: serde_json::Value,
    timestamp: DateTime<Utc>,
    signature: String,
}

impl From<AuditEventRow> for RecordedAuditEvent {
    fn from(row: AuditEventRow) -> Self {
        Self {
            event_id: row.event_id,
            agent_id: row.agent_id,
            action: row.action,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            data: row.data,
            timestamp: row.timestamp,
            signature: row.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_as_str() {
        assert_eq!(AuditAction::AgentRegister.as_str(), "agent_register");
        assert_eq!(AuditAction::Star.as_str(), "star");
        assert_eq!(AuditAction::PrMerge.as_str(), "pr_merge");
    }

    #[test]
    fn test_admin_audit_action_as_str() {
        assert_eq!(AuditAction::AdminSuspendAgent.as_str(), "admin_suspend_agent");
        assert_eq!(AuditAction::AdminUnsuspendAgent.as_str(), "admin_unsuspend_agent");
        assert_eq!(AuditAction::AdminDeleteRepo.as_str(), "admin_delete_repo");
        assert_eq!(AuditAction::AdminLogin.as_str(), "admin_login");
        assert_eq!(AuditAction::AdminLogout.as_str(), "admin_logout");
        assert_eq!(AuditAction::AdminReconnectRepo.as_str(), "admin_reconnect_repo");
        assert_eq!(AuditAction::AdminDeleteOrphanedDb.as_str(), "admin_delete_orphaned_db");
        assert_eq!(AuditAction::AdminDeleteOrphanedStorage.as_str(), "admin_delete_orphaned_storage");
    }

    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::Agent.as_str(), "agent");
        assert_eq!(ResourceType::Repository.as_str(), "repository");
        assert_eq!(ResourceType::Star.as_str(), "star");
        assert_eq!(ResourceType::AdminSession.as_str(), "admin_session");
    }

    #[test]
    fn test_audit_event_new() {
        let event = AuditEvent::new(
            "agent-123",
            AuditAction::Star,
            ResourceType::Star,
            "repo-456",
            serde_json::json!({"reason": "great code"}),
            "sig-789",
        );

        assert_eq!(event.agent_id, "agent-123");
        assert_eq!(event.action, "star");
        assert_eq!(event.resource_type, "star");
        assert_eq!(event.resource_id, "repo-456");
        assert_eq!(event.signature, "sig-789");
    }

    #[test]
    fn test_audit_event_new_admin_action() {
        let event = AuditEvent::new(
            "admin-user",
            AuditAction::AdminSuspendAgent,
            ResourceType::Agent,
            "agent-456",
            serde_json::json!({"reason": "policy violation"}),
            "admin-sig",
        );

        assert_eq!(event.agent_id, "admin-user");
        assert_eq!(event.action, "admin_suspend_agent");
        assert_eq!(event.resource_type, "agent");
        assert_eq!(event.resource_id, "agent-456");
    }

    #[test]
    fn test_audit_query_builder() {
        let query = AuditQuery::new()
            .agent("agent-123")
            .action(AuditAction::Star)
            .resource_type(ResourceType::Star)
            .limit(50)
            .offset(10);

        assert_eq!(query.agent_id, Some("agent-123".to_string()));
        assert_eq!(query.action, Some("star".to_string()));
        assert_eq!(query.resource_type, Some("star".to_string()));
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(10));
    }
}

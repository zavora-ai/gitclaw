//! Admin HTTP Handlers
//!
//! HTTP handlers for admin dashboard endpoints including authentication,
//! stats, agent management, repository management, audit log, health,
//! and reconciliation operations.
//!
//! Design Reference: Admin Dashboard Design Document - Admin Handlers
//! Requirements: 6.2, 8.1-8.13

use actix_web::{HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::services::admin::{AdminError, AdminService, PaginationParams};
use crate::services::admin_auth::{AdminAuth, AdminSession, AuthError};
use crate::services::admin_reconciliation::{AdminReconciliationError, AdminReconciliationService};
use crate::services::audit::{AuditAction, AuditEvent, AuditQuery, AuditService, ResourceType};
use crate::services::health::HealthService;

// ============================================================================
// Response Types
// ============================================================================

/// Standard API response wrapper for admin endpoints
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T: Serialize> {
    data: T,
    meta: ResponseMeta,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseMeta {
    request_id: String,
}

impl<T: Serialize> ApiResponse<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            meta: ResponseMeta {
                request_id: Uuid::new_v4().to_string(),
            },
        }
    }
}

/// Error response for admin endpoints
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: ErrorBody,
    meta: ResponseMeta,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: String,
    message: String,
}

impl ErrorResponse {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
            meta: ResponseMeta {
                request_id: Uuid::new_v4().to_string(),
            },
        }
    }

    fn from_admin_error(err: &AdminError) -> Self {
        Self::new(err.error_code(), err.to_string())
    }

    fn from_reconciliation_error(err: &AdminReconciliationError) -> Self {
        Self::new(err.error_code(), err.to_string())
    }
}

// ============================================================================
// Request/Response Types for Auth
// ============================================================================

/// Login request body
///
/// Requirements: 6.2
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response
///
/// Requirements: 6.2
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

// ============================================================================
// Request Types for Agent Operations
// ============================================================================

/// Suspend agent request body
///
/// Requirements: 8.4
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

// ============================================================================
// Request Types for Audit Log
// ============================================================================

/// Audit log query parameters
///
/// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 8.9
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQueryParams {
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub from_timestamp: Option<DateTime<Utc>>,
    pub to_timestamp: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

// ============================================================================
// Request Types for Reconciliation
// ============================================================================

/// Reconnect request body
///
/// Requirements: 8.12
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconnectRequest {
    pub owner_id: String,
    pub name: String,
    pub visibility: Option<String>,
}

/// Orphaned delete query parameters
///
/// Requirements: 8.13
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrphanedDeleteParams {
    #[serde(rename = "type")]
    pub delete_type: String,
}

// ============================================================================
// Auth Handlers (Task 10.1)
// ============================================================================

/// POST /admin/login - Admin login
///
/// Authenticates admin credentials and returns a session token.
///
/// Requirements: 6.2
pub async fn login(
    admin_auth: web::Data<AdminAuth>,
    audit_service: web::Data<AuditService>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    let request = body.into_inner();

    match admin_auth.login(&request.username, &request.password).await {
        Ok((token, session)) => {
            // Log successful login to audit log
            let audit_event = AuditEvent::new(
                &session.admin_id,
                AuditAction::AdminLogin,
                ResourceType::AdminSession,
                &session.admin_id,
                serde_json::json!({
                    "admin_id": session.admin_id,
                }),
                "", // Admin actions don't require cryptographic signatures
            );

            // Best effort audit logging - don't fail login if audit fails
            if let Err(e) = audit_service.append(audit_event).await {
                tracing::warn!("Failed to log admin login to audit: {}", e);
            }

            HttpResponse::Ok().json(ApiResponse::new(LoginResponse {
                token,
                expires_at: session.expires_at,
            }))
        }
        Err(AuthError::InvalidCredentials) => {
            HttpResponse::Unauthorized().json(ErrorResponse::new(
                "INVALID_CREDENTIALS",
                "Invalid admin credentials",
            ))
        }
        Err(e) => {
            tracing::error!("Admin login error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse::new(
                "INTERNAL_ERROR",
                "An error occurred during login",
            ))
        }
    }
}

/// POST /admin/logout - Admin logout
///
/// Invalidates the current admin session.
///
/// Requirements: 6.2
pub async fn logout(
    admin_auth: web::Data<AdminAuth>,
    audit_service: web::Data<AuditService>,
    admin: AdminSession,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    // Extract token from Authorization header
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.len() > 7 && auth_str[..7].eq_ignore_ascii_case("Bearer ") {
                let token = &auth_str[7..];
                admin_auth.logout(token).await;
            }
        }
    }

    // Log logout to audit log
    let audit_event = AuditEvent::new(
        &admin.admin_id,
        AuditAction::AdminLogout,
        ResourceType::AdminSession,
        &admin.admin_id,
        serde_json::json!({
            "admin_id": admin.admin_id,
        }),
        "",
    );

    // Best effort audit logging
    if let Err(e) = audit_service.append(audit_event).await {
        tracing::warn!("Failed to log admin logout to audit: {}", e);
    }

    HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
        "message": "Logged out successfully"
    })))
}

// ============================================================================
// Stats and Agent Handlers (Task 10.2)
// ============================================================================

/// GET /admin/stats - Get platform statistics
///
/// Returns platform-wide statistics including agent, repo, star, PR, and CI counts.
///
/// Requirements: 8.1
pub async fn get_stats(
    admin_service: web::Data<AdminService>,
    _admin: AdminSession,
) -> HttpResponse {
    match admin_service.get_stats().await {
        Ok(stats) => HttpResponse::Ok().json(ApiResponse::new(stats)),
        Err(e) => {
            tracing::error!("Failed to get platform stats: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// GET /admin/agents - List agents with pagination
///
/// Returns a paginated list of agents with optional search filtering.
///
/// Requirements: 8.2
pub async fn list_agents(
    admin_service: web::Data<AdminService>,
    query: web::Query<PaginationParams>,
    _admin: AdminSession,
) -> HttpResponse {
    match admin_service.list_agents(query.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(ApiResponse::new(response)),
        Err(e) => {
            tracing::error!("Failed to list agents: {}", e);
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// GET /admin/agents/{agent_id} - Get agent details
///
/// Returns detailed information about a specific agent.
///
/// Requirements: 8.3
pub async fn get_agent(
    admin_service: web::Data<AdminService>,
    path: web::Path<String>,
    _admin: AdminSession,
) -> HttpResponse {
    let agent_id = path.into_inner();

    match admin_service.get_agent(&agent_id).await {
        Ok(agent) => HttpResponse::Ok().json(ApiResponse::new(agent)),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// POST /admin/agents/{agent_id}/suspend - Suspend an agent
///
/// Suspends an agent, preventing them from performing mutating operations.
///
/// Requirements: 8.4
pub async fn suspend_agent(
    admin_service: web::Data<AdminService>,
    path: web::Path<String>,
    body: web::Json<SuspendRequest>,
    admin: AdminSession,
) -> HttpResponse {
    let agent_id = path.into_inner();
    let request = body.into_inner();

    match admin_service
        .suspend_agent(&agent_id, &admin.admin_id, request.reason)
        .await
    {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
            "message": "Agent suspended successfully",
            "agentId": agent_id
        }))),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// POST /admin/agents/{agent_id}/unsuspend - Unsuspend an agent
///
/// Removes suspension from an agent, allowing them to perform operations again.
///
/// Requirements: 8.5
pub async fn unsuspend_agent(
    admin_service: web::Data<AdminService>,
    path: web::Path<String>,
    admin: AdminSession,
) -> HttpResponse {
    let agent_id = path.into_inner();

    match admin_service
        .unsuspend_agent(&agent_id, &admin.admin_id)
        .await
    {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
            "message": "Agent unsuspended successfully",
            "agentId": agent_id
        }))),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

// ============================================================================
// Repository Handlers (Task 10.3)
// ============================================================================

/// GET /admin/repos - List repositories with pagination
///
/// Returns a paginated list of repositories with optional search filtering.
///
/// Requirements: 8.6
pub async fn list_repos(
    admin_service: web::Data<AdminService>,
    query: web::Query<PaginationParams>,
    _admin: AdminSession,
) -> HttpResponse {
    match admin_service.list_repos(query.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(ApiResponse::new(response)),
        Err(e) => {
            tracing::error!("Failed to list repos: {}", e);
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// GET /admin/repos/{repo_id} - Get repository details
///
/// Returns detailed information about a specific repository.
///
/// Requirements: 8.7
pub async fn get_repo(
    admin_service: web::Data<AdminService>,
    path: web::Path<String>,
    _admin: AdminSession,
) -> HttpResponse {
    let repo_id = path.into_inner();

    match admin_service.get_repo(&repo_id).await {
        Ok(repo) => HttpResponse::Ok().json(ApiResponse::new(repo)),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

/// DELETE /admin/repos/{repo_id} - Delete a repository
///
/// Deletes a repository and all associated data.
///
/// Requirements: 8.8
pub async fn delete_repo(
    admin_service: web::Data<AdminService>,
    path: web::Path<String>,
    admin: AdminSession,
) -> HttpResponse {
    let repo_id = path.into_inner();

    match admin_service.delete_repo(&repo_id, &admin.admin_id).await {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
            "message": "Repository deleted successfully",
            "repoId": repo_id
        }))),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_admin_error(&e))
        }
    }
}

// ============================================================================
// Audit Log Handler (Task 10.4)
// ============================================================================

/// GET /admin/audit - Query audit log
///
/// Returns a paginated list of audit events with optional filtering.
///
/// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 8.9
pub async fn query_audit(
    audit_service: web::Data<AuditService>,
    query: web::Query<AuditQueryParams>,
    _admin: AdminSession,
) -> HttpResponse {
    let params = query.into_inner();

    // Build audit query from parameters
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;

    let mut audit_query = AuditQuery::new().limit(per_page).offset(offset);

    if let Some(agent_id) = params.agent_id {
        audit_query = audit_query.agent(agent_id);
    }
    if let Some(action) = params.action {
        audit_query.action = Some(action);
    }
    if let Some(resource_type) = params.resource_type {
        audit_query.resource_type = Some(resource_type);
    }
    if let Some(resource_id) = params.resource_id {
        audit_query = audit_query.resource_id(resource_id);
    }
    if let Some(from_ts) = params.from_timestamp {
        audit_query = audit_query.from(from_ts);
    }
    if let Some(to_ts) = params.to_timestamp {
        audit_query = audit_query.to(to_ts);
    }

    match audit_service.query(audit_query).await {
        Ok(response) => {
            // Calculate pagination info
            let total_pages = if response.total_count == 0 {
                1
            } else {
                (response.total_count + per_page - 1) / per_page
            };

            HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
                "items": response.events,
                "total": response.total_count,
                "page": page,
                "perPage": per_page,
                "totalPages": total_pages,
                "hasMore": response.has_more
            })))
        }
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse::new(
                "DATABASE_ERROR",
                format!("Failed to query audit log: {e}"),
            ))
        }
    }
}

// ============================================================================
// Health and Reconciliation Handlers (Task 10.6)
// ============================================================================

/// GET /admin/health - Get system health
///
/// Returns health status for all system components.
///
/// Requirements: 8.10
pub async fn get_health(health_service: web::Data<HealthService>, _admin: AdminSession) -> HttpResponse {
    let health = health_service.check_health().await;
    HttpResponse::Ok().json(ApiResponse::new(health))
}

/// GET /admin/repos/reconcile - Scan for disconnected repositories
///
/// Scans for repositories that exist in only one location (DB or storage).
///
/// Requirements: 8.11
pub async fn scan_disconnected_repos(
    reconciliation_service: web::Data<AdminReconciliationService>,
    _admin: AdminSession,
) -> HttpResponse {
    match reconciliation_service.scan().await {
        Ok(result) => HttpResponse::Ok().json(ApiResponse::new(result)),
        Err(e) => {
            tracing::error!("Failed to scan for disconnected repos: {}", e);
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_reconciliation_error(&e))
        }
    }
}

/// POST /admin/repos/{repo_id}/reconnect - Reconnect orphaned storage to database
///
/// Creates a database record for a repository that exists only in storage.
///
/// Requirements: 8.12
pub async fn reconnect_repo(
    reconciliation_service: web::Data<AdminReconciliationService>,
    path: web::Path<String>,
    body: web::Json<ReconnectRequest>,
    admin: AdminSession,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let request = body.into_inner();

    match reconciliation_service
        .reconnect_repo(&repo_id, &request.owner_id, &request.name, &admin.admin_id)
        .await
    {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
            "message": "Repository reconnected successfully",
            "repoId": repo_id
        }))),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_reconciliation_error(&e))
        }
    }
}

/// DELETE /admin/repos/{repo_id}/orphaned - Delete orphaned records or objects
///
/// Deletes orphaned database records or storage objects.
///
/// Requirements: 8.13
pub async fn delete_orphaned(
    reconciliation_service: web::Data<AdminReconciliationService>,
    path: web::Path<String>,
    query: web::Query<OrphanedDeleteParams>,
    admin: AdminSession,
) -> HttpResponse {
    let repo_id = path.into_inner();
    let params = query.into_inner();

    let result = match params.delete_type.as_str() {
        "db" => {
            reconciliation_service
                .delete_orphaned_db_record(&repo_id, &admin.admin_id)
                .await
        }
        "storage" => {
            reconciliation_service
                .delete_orphaned_storage(&repo_id, &admin.admin_id)
                .await
        }
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse::new(
                "INVALID_TYPE",
                "Type must be 'db' or 'storage'",
            ));
        }
    };

    match result {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
            "message": format!("Orphaned {} deleted successfully", params.delete_type),
            "repoId": repo_id
        }))),
        Err(e) => {
            let status = e.status_code();
            HttpResponse::build(status).json(ErrorResponse::from_reconciliation_error(&e))
        }
    }
}

// ============================================================================
// Route Configuration (Task 10.7)
// ============================================================================

/// Configure admin routes
///
/// Registers all admin endpoints under the /admin scope.
/// The login endpoint is public; all other endpoints require authentication
/// via the AdminSession extractor.
///
/// Requirements: 8.1-8.13
pub fn configure_admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            // Public endpoint - no auth required
            .route("/login", web::post().to(login))
            // Protected endpoints - auth required via AdminSession extractor
            .route("/logout", web::post().to(logout))
            .route("/stats", web::get().to(get_stats))
            // Agent management
            .route("/agents", web::get().to(list_agents))
            .route("/agents/{agent_id}", web::get().to(get_agent))
            .route("/agents/{agent_id}/suspend", web::post().to(suspend_agent))
            .route("/agents/{agent_id}/unsuspend", web::post().to(unsuspend_agent))
            // Repository management - reconcile must come before {repo_id}
            .route("/repos/reconcile", web::get().to(scan_disconnected_repos))
            .route("/repos", web::get().to(list_repos))
            .route("/repos/{repo_id}", web::get().to(get_repo))
            .route("/repos/{repo_id}", web::delete().to(delete_repo))
            .route("/repos/{repo_id}/reconnect", web::post().to(reconnect_repo))
            .route("/repos/{repo_id}/orphaned", web::delete().to(delete_orphaned))
            // Audit log
            .route("/audit", web::get().to(query_audit))
            // Health
            .route("/health", web::get().to(get_health)),
    );
}

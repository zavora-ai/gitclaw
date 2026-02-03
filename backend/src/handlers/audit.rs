//! Audit handlers
//!
//! HTTP handlers for audit log queries.
//! Design Reference: DR-14.1 (Audit Service)
//! Requirements: 11.3

use actix_web::{HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::services::audit::{AuditError, AuditQuery, AuditService};

/// Standard API response wrapper
#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    data: T,
    meta: ResponseMeta,
}

#[derive(Serialize)]
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

/// Query parameters for audit log endpoint
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Filter by resource ID
    pub resource_id: Option<String>,
    /// Filter by action type
    pub action: Option<String>,
    /// Filter events after this timestamp (ISO 8601)
    pub from: Option<DateTime<Utc>>,
    /// Filter events before this timestamp (ISO 8601)
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results (default: 100, max: 1000)
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// GET /v1/audit
///
/// Query audit events with optional filters.
/// Supports filtering by agent, resource, action, and time range.
///
/// Requirements: 11.3
/// Design: DR-14.1 (Audit Service)
pub async fn query_audit_events(
    state: web::Data<AppState>,
    query_params: web::Query<AuditQueryParams>,
) -> Result<HttpResponse, AppError> {
    let audit_service = AuditService::new(state.db.clone());

    let mut query = AuditQuery::new();

    if let Some(ref agent_id) = query_params.agent_id {
        query = query.agent(agent_id);
    }
    if let Some(ref resource_type) = query_params.resource_type {
        query.resource_type = Some(resource_type.clone());
    }
    if let Some(ref resource_id) = query_params.resource_id {
        query = query.resource_id(resource_id);
    }
    if let Some(ref action) = query_params.action {
        query.action = Some(action.clone());
    }
    if let Some(from) = query_params.from {
        query = query.from(from);
    }
    if let Some(to) = query_params.to {
        query = query.to(to);
    }
    if let Some(limit) = query_params.limit {
        query = query.limit(limit);
    }
    if let Some(offset) = query_params.offset {
        query = query.offset(offset);
    }

    let response = audit_service.query(query).await.map_err(map_audit_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// GET /v1/audit/{eventId}
///
/// Get a single audit event by ID.
///
/// Requirements: 11.3
/// Design: DR-14.1 (Audit Service)
pub async fn get_audit_event(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let event_id = path.into_inner();
    let audit_service = AuditService::new(state.db.clone());

    let event = audit_service
        .get_by_id(event_id)
        .await
        .map_err(map_audit_error)?;

    match event {
        Some(e) => Ok(HttpResponse::Ok().json(ApiResponse::new(e))),
        None => Err(AppError::NotFound(format!(
            "Audit event not found: {event_id}"
        ))),
    }
}

/// GET /v1/agents/{agentId}/audit
///
/// Get audit events for a specific agent.
///
/// Requirements: 11.3
/// Design: DR-14.1 (Audit Service)
#[allow(dead_code)]
pub async fn get_agent_audit_events(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query_params: web::Query<LimitParam>,
) -> Result<HttpResponse, AppError> {
    let agent_id = path.into_inner();
    let audit_service = AuditService::new(state.db.clone());

    let events = audit_service
        .get_for_agent(&agent_id, query_params.limit)
        .await
        .map_err(map_audit_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(events)))
}

/// GET /v1/repos/{repoId}/audit
///
/// Get audit events for a specific repository.
///
/// Requirements: 11.3
/// Design: DR-14.1 (Audit Service)
#[allow(dead_code)]
pub async fn get_repo_audit_events(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query_params: web::Query<LimitParam>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let audit_service = AuditService::new(state.db.clone());

    let query = AuditQuery::new()
        .resource_id(&repo_id)
        .limit(query_params.limit.unwrap_or(100));

    let response = audit_service.query(query).await.map_err(map_audit_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response.events)))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LimitParam {
    pub limit: Option<i64>,
}

/// Map audit errors to application errors
fn map_audit_error(e: AuditError) -> AppError {
    match e {
        AuditError::Database(e) => AppError::Database(e),
        AuditError::InvalidQuery(msg) => AppError::Validation(msg),
    }
}

/// Configure audit routes
pub fn configure_audit_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/audit")
            .route("", web::get().to(query_audit_events))
            .route("/{eventId}", web::get().to(get_audit_event)),
    );
}

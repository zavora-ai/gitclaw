//! Star handlers
//!
//! HTTP handlers for repository star operations.
//! Design Reference: DR-11.1 (Star Service)

use actix_web::{web, HttpResponse};
use serde::Serialize;

use crate::error::AppError;
use crate::models::{SignedStarRequest, SignedUnstarRequest};
use crate::services::star::StarError;
use crate::services::StarService;
use crate::AppState;

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
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        }
    }
}

/// POST /v1/repos/{repoId}/stars:star
///
/// Star a repository.
/// Requires a valid signature over the request body.
///
/// Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7
/// Design: DR-11.1 (Star Service)
pub async fn star_repo(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignedStarRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let star_service = StarService::new(state.db.clone());

    let response = star_service
        .star(
            &repo_id,
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            request.body,
            &state.rate_limiter,
        )
        .await
        .map_err(map_star_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// POST /v1/repos/{repoId}/stars:unstar
///
/// Unstar a repository.
/// Requires a valid signature over the request body.
///
/// Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
/// Design: DR-11.1 (Star Service)
pub async fn unstar_repo(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignedUnstarRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let star_service = StarService::new(state.db.clone());

    let response = star_service
        .unstar(
            &repo_id,
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            &state.rate_limiter,
        )
        .await
        .map_err(map_star_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/stars
///
/// Get stars for a repository.
/// Returns the star count and list of agents who starred.
///
/// Requirements: 16.1, 16.2, 16.3, 16.4
/// Design: DR-11.1 (Star Service)
pub async fn get_stars(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let star_service = StarService::new(state.db.clone());

    let response = star_service.get_stars(&repo_id).await.map_err(map_star_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Map star errors to application errors
fn map_star_error(e: StarError) -> AppError {
    match e {
        StarError::RepoNotFound(id) => AppError::NotFound(format!("Repository not found: {id}")),
        StarError::AgentNotFound(id) => AppError::NotFound(format!("Agent not found: {id}")),
        StarError::DuplicateStar(agent, repo) => {
            AppError::Conflict(format!("Agent {agent} has already starred repository {repo}"))
        }
        StarError::NoExistingStar(agent, repo) => {
            AppError::NotFound(format!("Agent {agent} has not starred repository {repo}"))
        }
        StarError::InvalidReason(msg) => AppError::Validation(msg),
        StarError::SignatureError(e) => AppError::Unauthorized(e.to_string()),
        StarError::IdempotencyError(e) => match e {
            crate::services::IdempotencyError::ReplayAttack { .. } => {
                AppError::Conflict(e.to_string())
            }
            _ => AppError::Internal(e.to_string()),
        },
        StarError::RateLimited(e) => e.into(),
        StarError::Database(e) => AppError::Database(e),
        StarError::Audit(e) => AppError::Internal(format!("Audit error: {e}")),
    }
}

/// Configure star routes
pub fn configure_star_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/repos/{repoId}/stars")
            .route(":star", web::post().to(star_repo))
            .route(":unstar", web::post().to(unstar_repo))
            .route("", web::get().to(get_stars)),
    );
}

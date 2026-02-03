//! Repository handlers
//!
//! HTTP handlers for repository operations.

use actix_web::{HttpResponse, web};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;
use crate::models::{
    CloneRepoRequest, SignedCreateRepoRequest, SignedGrantAccessRequest, SignedListAccessRequest,
    SignedRevokeAccessRequest,
};
use crate::services::RepositoryService;
use crate::services::repository::RepositoryError;

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

/// POST /v1/repos
///
/// Create a new repository.
/// Requires a valid signature over the request body.
///
/// Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
/// Design: DR-4.1 (Repository Service)
pub async fn create_repo(
    state: web::Data<AppState>,
    body: web::Json<SignedCreateRepoRequest>,
) -> Result<HttpResponse, AppError> {
    let request = body.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let response = repo_service
        .create(
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            request.body,
        )
        .await
        .map_err(map_repo_error)?;

    Ok(HttpResponse::Created().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}
///
/// Get repository information by ID.
pub async fn get_repo(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let repo = repo_service
        .get_by_id(&repo_id)
        .await
        .map_err(map_repo_error)?;

    match repo {
        Some(repo) => Ok(HttpResponse::Ok().json(ApiResponse::new(repo))),
        None => Err(AppError::NotFound(format!(
            "Repository not found: {repo_id}"
        ))),
    }
}

/// POST /v1/repos/{repoId}/clone
///
/// Clone a repository.
/// Returns packfile and refs for the repository.
/// Requires read access (public repos or explicit access).
///
/// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 18.2
/// Design: DR-4.2 (Repository Service - Clone)
pub async fn clone_repo(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CloneRepoRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let response = repo_service
        .clone(&repo_id, request)
        .await
        .map_err(map_repo_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Map repository errors to application errors
fn map_repo_error(e: RepositoryError) -> AppError {
    match e {
        RepositoryError::RepoExists(owner, name) => {
            AppError::Conflict(format!("Repository already exists: {owner}/{name}"))
        }
        RepositoryError::RepoNotFound(id) => {
            AppError::NotFound(format!("Repository not found: {id}"))
        }
        RepositoryError::AgentNotFound(id) => AppError::NotFound(format!("Agent not found: {id}")),
        RepositoryError::InvalidRepoName(msg) => AppError::Validation(msg),
        RepositoryError::AccessDenied(msg) => AppError::Unauthorized(msg),
        RepositoryError::Suspended(msg) => AppError::Forbidden(format!("SUSPENDED_AGENT: {msg}")),
        RepositoryError::SignatureError(e) => AppError::Unauthorized(e.to_string()),
        RepositoryError::IdempotencyError(e) => match e {
            crate::services::IdempotencyError::ReplayAttack { .. } => {
                AppError::Conflict(e.to_string())
            }
            _ => AppError::Internal(e.to_string()),
        },
        RepositoryError::Database(e) => AppError::Database(e),
        RepositoryError::Audit(e) => AppError::Internal(format!("Audit error: {e}")),
    }
}

/// POST /v1/repos/{repoId}/access
///
/// Grant access to a repository.
/// Requires admin access to the repository.
///
/// Requirements: 18.1, 18.3, 18.4
/// Design: DR-4.1 (Repository Service - Access Control)
pub async fn grant_access(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignedGrantAccessRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let response = repo_service
        .grant_access(&repo_id, request)
        .await
        .map_err(map_repo_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Path parameters for revoke access endpoint
#[derive(Debug, serde::Deserialize)]
pub struct RevokeAccessPath {
    #[serde(rename = "repoId")]
    pub repo_id: String,
    pub agent_id: String,
}

/// DELETE /v1/repos/{repoId}/access/{agentId}
///
/// Revoke access from a repository.
/// Requires admin access to the repository.
///
/// Requirements: 18.3, 18.4
/// Design: DR-4.1 (Repository Service - Access Control)
pub async fn revoke_access(
    state: web::Data<AppState>,
    path: web::Path<RevokeAccessPath>,
    body: web::Json<SignedRevokeAccessRequest>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let request = body.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let response = repo_service
        .revoke_access(&path.repo_id, &path.agent_id, request)
        .await
        .map_err(map_repo_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/access
///
/// List collaborators for a repository.
/// Requires at least read access to the repository.
///
/// Requirements: 18.1
/// Design: DR-4.1 (Repository Service - Access Control)
pub async fn list_collaborators(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignedListAccessRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let base_url = format!("http://{}:{}", state.config.host, state.config.port);
    let repo_service = RepositoryService::new(state.db.clone(), base_url);

    let response = repo_service
        .list_collaborators(&repo_id, request)
        .await
        .map_err(map_repo_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Configure access control routes (must be registered before main repo routes)
pub fn configure_access_routes(cfg: &mut web::ServiceConfig) {
    // Use resource-based routing instead of scope to avoid path parameter conflicts
    cfg.service(
        web::resource("/repos/{repoId}/access")
            .route(web::post().to(grant_access))
            .route(web::get().to(list_collaborators)),
    );
    cfg.service(
        web::resource("/repos/{repoId}/access/{agent_id}").route(web::delete().to(revoke_access)),
    );
}

/// Configure repository routes
pub fn configure_repo_routes(cfg: &mut web::ServiceConfig) {
    // Use resources instead of scope to avoid conflicts with other /repos/* routes
    cfg.service(web::resource("/repos").route(web::post().to(create_repo)));
    cfg.service(web::resource("/repos/{repoId}").route(web::get().to(get_repo)));
    cfg.service(web::resource("/repos/{repoId}/clone").route(web::post().to(clone_repo)));
}

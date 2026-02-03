//! Pull Request handlers
//!
//! HTTP handlers for pull request operations.
//! Requirements: 6.1-6.5, 7.1-7.5, 8.1-8.6
//! Design: DR-7.1, DR-7.2, DR-7.3

use actix_web::{HttpResponse, web};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;
use crate::models::{SignedCreatePrRequest, SignedCreateReviewRequest, SignedMergePrRequest};
use crate::services::PullRequestService;
use crate::services::pull_request::PullRequestError;

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

/// Path parameters for PR endpoints
#[derive(serde::Deserialize)]
pub struct PrPath {
    pub repo_id: String,
    pub pr_id: String,
}

/// POST /v1/repos/{repoId}/pulls
///
/// Create a new pull request.
/// Requires a valid signature over the request body.
///
/// Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
/// Design: DR-7.1 (Pull Request Service)
pub async fn create_pr(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignedCreatePrRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();
    let pr_service = PullRequestService::new(state.db.clone());

    let response = pr_service
        .create(
            &repo_id,
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            request.body,
        )
        .await
        .map_err(map_pr_error)?;

    Ok(HttpResponse::Created().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/pulls/{prId}
///
/// Get pull request information by ID.
pub async fn get_pr(
    state: web::Data<AppState>,
    path: web::Path<PrPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let pr_service = PullRequestService::new(state.db.clone());

    let pr_info = pr_service
        .get_pr_info(&path.pr_id)
        .await
        .map_err(map_pr_error)?;

    match pr_info {
        Some(info) => {
            // Verify PR belongs to the specified repo
            if info.repo_id != path.repo_id {
                return Err(AppError::NotFound(format!(
                    "Pull request not found: {}",
                    path.pr_id
                )));
            }
            Ok(HttpResponse::Ok().json(ApiResponse::new(info)))
        }
        None => Err(AppError::NotFound(format!(
            "Pull request not found: {}",
            path.pr_id
        ))),
    }
}

/// POST /v1/repos/{repoId}/pulls/{prId}/reviews
///
/// Submit a review for a pull request.
/// Requires a valid signature over the request body.
///
/// Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
/// Design: DR-7.2 (Review Service)
pub async fn submit_review(
    state: web::Data<AppState>,
    path: web::Path<PrPath>,
    body: web::Json<SignedCreateReviewRequest>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let request = body.into_inner();
    let pr_service = PullRequestService::new(state.db.clone());

    let response = pr_service
        .submit_review(
            &path.repo_id,
            &path.pr_id,
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            request.body,
        )
        .await
        .map_err(map_pr_error)?;

    Ok(HttpResponse::Created().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/pulls/{prId}/reviews
///
/// Get all reviews for a pull request.
pub async fn get_reviews(
    state: web::Data<AppState>,
    path: web::Path<PrPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let pr_service = PullRequestService::new(state.db.clone());

    // First verify the PR exists and belongs to the repo
    let pr = pr_service.get_pr(&path.pr_id).await.map_err(map_pr_error)?;

    match pr {
        Some(pr) if pr.repo_id == path.repo_id => {
            let reviews = pr_service
                .get_reviews(&path.pr_id)
                .await
                .map_err(map_pr_error)?;
            Ok(HttpResponse::Ok().json(ApiResponse::new(reviews)))
        }
        _ => Err(AppError::NotFound(format!(
            "Pull request not found: {}",
            path.pr_id
        ))),
    }
}

/// POST /v1/repos/{repoId}/pulls/{prId}/merge
///
/// Merge a pull request.
/// Requires a valid signature over the request body.
///
/// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
/// Design: DR-7.3 (Merge Service)
pub async fn merge_pr(
    state: web::Data<AppState>,
    path: web::Path<PrPath>,
    body: web::Json<SignedMergePrRequest>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let request = body.into_inner();
    let pr_service = PullRequestService::new(state.db.clone());

    let response = pr_service
        .merge(
            &path.repo_id,
            &path.pr_id,
            &request.agent_id,
            &request.nonce,
            request.timestamp,
            &request.signature,
            request.body.merge_strategy,
        )
        .await
        .map_err(map_pr_error)?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// Map pull request errors to application errors
fn map_pr_error(e: PullRequestError) -> AppError {
    match e {
        PullRequestError::PrNotFound(id) => {
            AppError::NotFound(format!("Pull request not found: {id}"))
        }
        PullRequestError::RepoNotFound(id) => {
            AppError::NotFound(format!("Repository not found: {id}"))
        }
        PullRequestError::AgentNotFound(id) => AppError::NotFound(format!("Agent not found: {id}")),
        PullRequestError::BranchNotFound(name) => {
            AppError::Validation(format!("Branch not found: {name}"))
        }
        PullRequestError::AccessDenied(msg) => AppError::Unauthorized(msg),
        PullRequestError::SelfApprovalNotAllowed => {
            AppError::Validation("PR author cannot approve their own PR".to_string())
        }
        PullRequestError::NotApproved(msg) => AppError::Validation(msg),
        PullRequestError::CiNotPassed(status) => {
            AppError::Validation(format!("CI not passed: current status is {status:?}"))
        }
        PullRequestError::MergeConflicts(msg) => AppError::Conflict(msg),
        PullRequestError::AlreadyMerged => AppError::Conflict("PR already merged".to_string()),
        PullRequestError::PrClosed => AppError::Validation("PR is closed".to_string()),
        PullRequestError::InvalidState(msg) => AppError::Validation(msg),
        PullRequestError::Suspended(msg) => AppError::Forbidden(format!("SUSPENDED_AGENT: {msg}")),
        PullRequestError::SignatureError(e) => AppError::Unauthorized(e.to_string()),
        PullRequestError::IdempotencyError(e) => match e {
            crate::services::IdempotencyError::ReplayAttack { .. } => {
                AppError::Conflict(e.to_string())
            }
            _ => AppError::Internal(e.to_string()),
        },
        PullRequestError::Database(e) => AppError::Database(e),
        PullRequestError::Audit(e) => AppError::Internal(format!("Audit error: {e}")),
    }
}

/// Configure pull request routes
pub fn configure_pull_routes(cfg: &mut web::ServiceConfig) {
    // Use resources instead of scope to avoid catching all /repos/{repo_id}/pulls requests
    cfg.service(web::resource("/repos/{repo_id}/pulls").route(web::post().to(create_pr)));
    cfg.service(web::resource("/repos/{repo_id}/pulls/{pr_id}").route(web::get().to(get_pr)));
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/reviews")
            .route(web::post().to(submit_review))
            .route(web::get().to(get_reviews)),
    );
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/merge").route(web::post().to(merge_pr)),
    );
}

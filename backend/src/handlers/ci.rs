//! CI handlers
//!
//! HTTP handlers for CI pipeline operations.
//! Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
//! Design: DR-8.1 (CI Service)

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::AppError;
use crate::services::CiService;
use crate::services::ci::CiError;

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

/// Path parameters for CI run endpoints
#[derive(Deserialize)]
pub struct CiRunPath {
    pub repo_id: String,
    pub pr_id: String,
    pub run_id: String,
}

/// Path parameters for PR CI endpoints
#[derive(Deserialize)]
pub struct PrCiPath {
    pub repo_id: String,
    pub pr_id: String,
}

/// Request to trigger CI for a PR
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerCiRequest {
    pub commit_sha: String,
}

/// Response for CI trigger
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerCiResponse {
    pub run_id: String,
    pub status: String,
    pub message: String,
}

/// Response for CI run info
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CiRunResponse {
    pub run_id: String,
    pub pr_id: String,
    pub repo_id: String,
    pub commit_sha: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// Response for CI run logs
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CiLogsResponse {
    pub run_id: String,
    pub logs: String,
}

/// POST /v1/repos/{repoId}/pulls/{prId}/ci/trigger
///
/// Trigger CI pipeline for a pull request.
///
/// Requirements: 9.1
/// Design: DR-8.1 (CI Service)
pub async fn trigger_ci(
    state: web::Data<AppState>,
    path: web::Path<PrCiPath>,
    body: web::Json<TriggerCiRequest>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let request = body.into_inner();
    let ci_service = CiService::new(state.db.clone());

    let run_id = ci_service
        .trigger_for_pr(&path.repo_id, &path.pr_id, &request.commit_sha)
        .await
        .map_err(map_ci_error)?;

    let response = TriggerCiResponse {
        run_id,
        status: "pending".to_string(),
        message: "CI pipeline triggered successfully".to_string(),
    };

    Ok(HttpResponse::Accepted().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/pulls/{prId}/ci/runs
///
/// Get all CI runs for a pull request.
///
/// Requirements: 9.3
pub async fn get_ci_runs(
    state: web::Data<AppState>,
    path: web::Path<PrCiPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let ci_service = CiService::new(state.db.clone());

    let runs = ci_service
        .get_runs_for_pr(&path.pr_id)
        .await
        .map_err(map_ci_error)?;

    let response: Vec<CiRunResponse> = runs
        .into_iter()
        .map(|r| CiRunResponse {
            run_id: r.run_id,
            pr_id: r.pr_id,
            repo_id: r.repo_id,
            commit_sha: r.commit_sha,
            status: format!("{:?}", r.status).to_lowercase(),
            started_at: r.started_at.to_rfc3339(),
            completed_at: r.completed_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
}

/// GET /v1/repos/{repoId}/pulls/{prId}/ci/runs/{runId}
///
/// Get a specific CI run.
///
/// Requirements: 9.3
pub async fn get_ci_run(
    state: web::Data<AppState>,
    path: web::Path<CiRunPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let ci_service = CiService::new(state.db.clone());

    let run = ci_service
        .get_run(&path.run_id)
        .await
        .map_err(map_ci_error)?;

    match run {
        Some(r) => {
            // Verify run belongs to the specified PR and repo
            if r.pr_id != path.pr_id || r.repo_id != path.repo_id {
                return Err(AppError::NotFound(format!(
                    "CI run not found: {}",
                    path.run_id
                )));
            }

            let response = CiRunResponse {
                run_id: r.run_id,
                pr_id: r.pr_id,
                repo_id: r.repo_id,
                commit_sha: r.commit_sha,
                status: format!("{:?}", r.status).to_lowercase(),
                started_at: r.started_at.to_rfc3339(),
                completed_at: r.completed_at.map(|t| t.to_rfc3339()),
            };

            Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
        }
        None => Err(AppError::NotFound(format!(
            "CI run not found: {}",
            path.run_id
        ))),
    }
}

/// GET /v1/repos/{repoId}/pulls/{prId}/ci/runs/{runId}/logs
///
/// Get logs for a CI run.
///
/// Requirements: 9.4
pub async fn get_ci_logs(
    state: web::Data<AppState>,
    path: web::Path<CiRunPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let ci_service = CiService::new(state.db.clone());

    // First verify the run exists and belongs to the PR
    let run = ci_service
        .get_run(&path.run_id)
        .await
        .map_err(map_ci_error)?;

    match run {
        Some(r) => {
            if r.pr_id != path.pr_id || r.repo_id != path.repo_id {
                return Err(AppError::NotFound(format!(
                    "CI run not found: {}",
                    path.run_id
                )));
            }

            let logs = ci_service
                .get_run_logs(&path.run_id)
                .await
                .map_err(map_ci_error)?
                .unwrap_or_default();

            let response = CiLogsResponse {
                run_id: path.run_id,
                logs,
            };

            Ok(HttpResponse::Ok().json(ApiResponse::new(response)))
        }
        None => Err(AppError::NotFound(format!(
            "CI run not found: {}",
            path.run_id
        ))),
    }
}

/// POST /v1/repos/{repoId}/pulls/{prId}/ci/runs/{runId}/cancel
///
/// Cancel a running CI pipeline.
pub async fn cancel_ci_run(
    state: web::Data<AppState>,
    path: web::Path<CiRunPath>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let ci_service = CiService::new(state.db.clone());

    // First verify the run exists and belongs to the PR
    let run = ci_service
        .get_run(&path.run_id)
        .await
        .map_err(map_ci_error)?;

    match run {
        Some(r) => {
            if r.pr_id != path.pr_id || r.repo_id != path.repo_id {
                return Err(AppError::NotFound(format!(
                    "CI run not found: {}",
                    path.run_id
                )));
            }

            ci_service
                .cancel_run(&path.run_id)
                .await
                .map_err(map_ci_error)?;

            Ok(HttpResponse::Ok().json(ApiResponse::new(serde_json::json!({
                "run_id": path.run_id,
                "status": "cancelled",
                "message": "CI run cancelled successfully"
            }))))
        }
        None => Err(AppError::NotFound(format!(
            "CI run not found: {}",
            path.run_id
        ))),
    }
}

/// Map CI errors to application errors
fn map_ci_error(e: CiError) -> AppError {
    match e {
        CiError::RepoNotFound(id) => AppError::NotFound(format!("Repository not found: {id}")),
        CiError::PrNotFound(id) => AppError::NotFound(format!("Pull request not found: {id}")),
        CiError::ConfigNotFound => {
            AppError::Validation("CI configuration not found in repository".to_string())
        }
        CiError::InvalidConfig(msg) => AppError::Validation(format!("Invalid CI config: {msg}")),
        CiError::ExecutionFailed(msg) => AppError::Internal(format!("CI execution failed: {msg}")),
        CiError::Timeout(secs) => {
            AppError::Internal(format!("CI pipeline timed out after {secs} seconds"))
        }
        CiError::ResourceLimitExceeded(msg) => {
            AppError::Internal(format!("Resource limit exceeded: {msg}"))
        }
        CiError::SandboxError(msg) => AppError::Internal(format!("Sandbox error: {msg}")),
        CiError::Database(e) => AppError::Database(e),
        CiError::Audit(e) => AppError::Internal(format!("Audit error: {e}")),
    }
}

/// Configure CI routes
pub fn configure_ci_routes(cfg: &mut web::ServiceConfig) {
    // Use resources instead of scope to avoid catching all /repos/{repo_id}/pulls/{pr_id}/ci requests
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/ci/trigger")
            .route(web::post().to(trigger_ci)),
    );
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/ci/runs").route(web::get().to(get_ci_runs)),
    );
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/ci/runs/{run_id}")
            .route(web::get().to(get_ci_run)),
    );
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/ci/runs/{run_id}/logs")
            .route(web::get().to(get_ci_logs)),
    );
    cfg.service(
        web::resource("/repos/{repo_id}/pulls/{pr_id}/ci/runs/{run_id}/cancel")
            .route(web::post().to(cancel_ci_run)),
    );
}

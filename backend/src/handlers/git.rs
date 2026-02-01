//! Git Smart HTTP Transport handlers
//!
//! HTTP handlers for Git protocol operations.
//! Design: DR-4.3 (Git Transport Service), DR-5.1 (Push Service)

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::services::git_transport::{format_ref_advertisement, GitTransportError};
use crate::services::push::{PushError, PushService, RefUpdateRequest as PushRefUpdate};
use crate::services::GitTransportService;
use crate::AppState;

/// Query parameters for info/refs endpoint
#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: String,
}

/// Request body for git-upload-pack
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadPackRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(default)]
    pub wants: Vec<String>,
    #[serde(default)]
    pub haves: Vec<String>,
}

/// Request body for git-receive-pack
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivePackRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    /// Base64-encoded packfile
    pub packfile: String,
    pub ref_updates: Vec<RefUpdateRequestBody>,
}

/// Ref update in request body
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefUpdateRequestBody {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    #[serde(default)]
    pub force: bool,
}

/// Response for receive-pack
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivePackResponseBody {
    pub status: String,
    pub ref_updates: Vec<RefUpdateStatusBody>,
}

/// Ref update status in response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefUpdateStatusBody {
    pub ref_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// GET/POST /v1/repos/{repoId}/info/refs
///
/// Git ref advertisement endpoint.
/// Returns list of refs and capabilities.
///
/// Requirements: 4.1, 4.3, 4.7
/// Design: DR-4.3 (Git Transport Service)
pub async fn info_refs(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<InfoRefsQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let service = &query.service;

    // Get optional agent ID from header
    let agent_id = req
        .headers()
        .get("X-Agent-Id")
        .and_then(|v| v.to_str().ok());

    let git_service = GitTransportService::new(state.db.clone());

    let advertisement = git_service
        .get_refs(&repo_id, service, agent_id)
        .await
        .map_err(map_git_error)?;

    // Format response according to Git protocol
    let response_body = format_ref_advertisement(service, &advertisement);

    let content_type = format!("application/x-{}-advertisement", service);

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Cache-Control", "no-cache"))
        .body(response_body))
}

/// POST /v1/repos/{repoId}/git-upload-pack
///
/// Git upload-pack endpoint for clone/fetch operations.
/// Returns packfile with requested objects.
///
/// Requirements: 4.1, 4.2, 4.5, 4.7, 4.8
/// Design: DR-4.3 (Git Transport Service)
pub async fn git_upload_pack(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UploadPackRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();

    let git_service = GitTransportService::new(state.db.clone());

    let response = git_service
        .upload_pack(
            &repo_id,
            &request.agent_id,
            &request.signature,
            request.timestamp,
            &request.nonce,
            request.wants,
            request.haves,
        )
        .await
        .map_err(map_git_error)?;

    // Return packfile as binary
    Ok(HttpResponse::Ok()
        .content_type("application/x-git-upload-pack-result")
        .body(response.packfile))
}

/// POST /v1/repos/{repoId}/git-receive-pack
///
/// Git receive-pack endpoint for push operations.
/// Accepts packfile and ref updates.
///
/// Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
/// Design: DR-5.1 (Push Service)
pub async fn git_receive_pack(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ReceivePackRequest>,
) -> Result<HttpResponse, AppError> {
    let repo_id = path.into_inner();
    let request = body.into_inner();

    // Decode base64 packfile
    let packfile = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.packfile,
    )
    .map_err(|e| AppError::Validation(format!("Invalid packfile encoding: {}", e)))?;

    // Convert ref updates to Push Service format
    let ref_updates: Vec<PushRefUpdate> = request
        .ref_updates
        .into_iter()
        .map(|r| PushRefUpdate {
            ref_name: r.ref_name,
            old_oid: r.old_oid,
            new_oid: r.new_oid,
            force: r.force,
        })
        .collect();

    let push_service = PushService::new(state.db.clone());

    let response = push_service
        .push(
            &repo_id,
            &request.agent_id,
            &request.signature,
            request.timestamp,
            &request.nonce,
            &packfile,
            ref_updates,
        )
        .await
        .map_err(map_push_error)?;

    // Convert to response body
    let response_body = ReceivePackResponseBody {
        status: response.status,
        ref_updates: response
            .ref_updates
            .into_iter()
            .map(|r| RefUpdateStatusBody {
                ref_name: r.ref_name,
                status: r.status,
                message: r.message,
            })
            .collect(),
    };

    Ok(HttpResponse::Ok().json(response_body))
}

/// Map Git transport errors to application errors
fn map_git_error(e: GitTransportError) -> AppError {
    match e {
        GitTransportError::RepoNotFound(id) => {
            AppError::NotFound(format!("Repository not found: {}", id))
        }
        GitTransportError::AgentNotFound(id) => {
            AppError::NotFound(format!("Agent not found: {}", id))
        }
        GitTransportError::AccessDenied(msg) => AppError::Unauthorized(msg),
        GitTransportError::InvalidService(s) => {
            AppError::Validation(format!("Invalid service: {}", s))
        }
        GitTransportError::MissingHeader(h) => {
            AppError::Validation(format!("Missing header: {}", h))
        }
        GitTransportError::InvalidPackfile(msg) => {
            AppError::Validation(format!("Invalid packfile: {}", msg))
        }
        GitTransportError::SignatureError(e) => AppError::Unauthorized(e.to_string()),
        GitTransportError::Database(e) => AppError::Database(e),
        GitTransportError::Audit(e) => AppError::Internal(format!("Audit error: {}", e)),
    }
}

/// Map Push service errors to application errors
fn map_push_error(e: PushError) -> AppError {
    match e {
        PushError::RepoNotFound(id) => {
            AppError::NotFound(format!("Repository not found: {}", id))
        }
        PushError::AgentNotFound(id) => {
            AppError::NotFound(format!("Agent not found: {}", id))
        }
        PushError::AccessDenied(msg) => AppError::Unauthorized(msg),
        PushError::NonFastForward(ref_name) => {
            AppError::Conflict(format!(
                "Non-fast-forward update rejected for ref {}. Use force push to override.",
                ref_name
            ))
        }
        PushError::InvalidPackfile(msg) => {
            AppError::Validation(format!("Invalid packfile: {}", msg))
        }
        PushError::InvalidObject(msg) => {
            AppError::Validation(format!("Invalid object: {}", msg))
        }
        PushError::RefNotFound(ref_name) => {
            AppError::NotFound(format!("Ref not found: {}", ref_name))
        }
        PushError::SignatureError(e) => AppError::Unauthorized(e.to_string()),
        PushError::IdempotencyError(e) => {
            AppError::Conflict(format!("Idempotency error: {}", e))
        }
        PushError::Database(e) => AppError::Database(e),
        PushError::Audit(e) => AppError::Internal(format!("Audit error: {}", e)),
    }
}

/// Configure Git transport routes
pub fn configure_git_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/repos/{repoId}")
            .route("/info/refs", web::get().to(info_refs))
            .route("/info/refs", web::post().to(info_refs))
            .route("/git-upload-pack", web::post().to(git_upload_pack))
            .route("/git-receive-pack", web::post().to(git_receive_pack)),
    );
}

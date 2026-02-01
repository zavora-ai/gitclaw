use actix_web::{web, HttpResponse};
use serde::Serialize;

use crate::error::AppError;
use crate::models::{AgentProfile, RegisterAgentRequest};
use crate::services::{AgentRegistryService, ReputationService};
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

/// POST /v1/agents/register
/// 
/// Register a new agent on the platform.
/// This is the only unsigned operation - all subsequent actions require valid signatures.
pub async fn register_agent(
    state: web::Data<AppState>,
    body: web::Json<RegisterAgentRequest>,
) -> Result<HttpResponse, AppError> {
    let registry = AgentRegistryService::new(state.db.clone());
    
    let response = registry
        .register(body.into_inner())
        .await
        .map_err(|e| match e {
            crate::services::agent_registry::AgentRegistryError::AgentNameExists(name) => {
                AppError::Conflict(format!("Agent name already exists: {name}"))
            }
            crate::services::agent_registry::AgentRegistryError::InvalidPublicKey(e) => {
                AppError::Validation(format!("Invalid public key: {e}"))
            }
            crate::services::agent_registry::AgentRegistryError::InvalidAgentName(msg) => {
                AppError::Validation(msg)
            }
            crate::services::agent_registry::AgentRegistryError::Database(e) => {
                AppError::Database(e)
            }
            crate::services::agent_registry::AgentRegistryError::Audit(e) => {
                AppError::Internal(format!("Audit error: {e}"))
            }
        })?;

    Ok(HttpResponse::Created().json(ApiResponse::new(response)))
}

/// GET /v1/agents/{agentId}
/// 
/// Get agent profile by ID.
pub async fn get_agent(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let agent_id = path.into_inner();
    let registry = AgentRegistryService::new(state.db.clone());
    
    let agent = registry
        .get_by_id(&agent_id)
        .await
        .map_err(|e| match e {
            crate::services::agent_registry::AgentRegistryError::Database(e) => {
                AppError::Database(e)
            }
            _ => AppError::Internal("Unexpected error".to_string()),
        })?;

    match agent {
        Some(agent) => {
            let capabilities: Vec<String> = serde_json::from_value(agent.capabilities.clone())
                .unwrap_or_default();
            
            let profile = AgentProfile {
                agent_id: agent.agent_id,
                agent_name: agent.agent_name,
                capabilities,
                created_at: agent.created_at,
            };
            
            Ok(HttpResponse::Ok().json(ApiResponse::new(profile)))
        }
        None => Err(AppError::NotFound(format!("Agent not found: {agent_id}"))),
    }
}

/// GET /v1/agents/{agentId}/reputation
/// 
/// Get agent reputation score.
/// Design Reference: DR-13.1
/// Requirements: 10.4 - Expose reputation scores via API
pub async fn get_agent_reputation(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let agent_id = path.into_inner();
    let service = ReputationService::new(state.db.clone());
    
    let reputation = service
        .get_reputation(&agent_id)
        .await
        .map_err(|e| match e {
            crate::services::ReputationError::AgentNotFound(id) => {
                AppError::NotFound(format!("Agent not found: {id}"))
            }
            crate::services::ReputationError::Database(e) => {
                AppError::Database(e)
            }
            _ => AppError::Internal(e.to_string()),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::new(reputation)))
}

/// Configure agent routes
pub fn configure_agent_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/agents")
            .route("/register", web::post().to(register_agent))
            .route("/{agentId}", web::get().to(get_agent))
            .route("/{agentId}/reputation", web::get().to(get_agent_reputation)),
    );
}

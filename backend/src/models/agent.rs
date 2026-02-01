use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Agent entity representing an AI agent registered on GitClaw
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Agent {
    pub agent_id: String,
    pub agent_name: String,
    pub public_key: String,
    pub capabilities: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Request payload for agent registration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAgentRequest {
    pub agent_name: String,
    pub public_key: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Response payload for successful agent registration
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub agent_name: String,
    pub created_at: DateTime<Utc>,
}

/// Public agent profile information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProfile {
    pub agent_id: String,
    pub agent_name: String,
    pub capabilities: Vec<String>,
    pub created_at: DateTime<Utc>,
}

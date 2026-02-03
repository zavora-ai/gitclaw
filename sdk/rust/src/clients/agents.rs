//! Agents resource client.
//!
//! Design Reference: DR-5
//! Requirements: 6.1, 6.2, 6.3, 6.4

use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::{Agent, AgentProfile, Reputation};

/// Client for agent-related operations.
pub struct AgentsClient {
    transport: Arc<HttpTransport>,
}

impl AgentsClient {
    /// Create a new agents client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Register a new agent.
    ///
    /// This is an unsigned request - no authentication required.
    ///
    /// # Arguments
    ///
    /// * `agent_name` - Display name for the agent
    /// * `public_key` - Public key in format "ed25519:base64..." or "ecdsa:base64..."
    /// * `capabilities` - Optional list of agent capabilities
    ///
    /// # Returns
    ///
    /// Agent object with agent_id, agent_name, and created_at
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    ///
    /// Requirements: 6.1, 6.2
    pub async fn register(
        &self,
        agent_name: &str,
        public_key: &str,
        capabilities: Option<Vec<String>>,
    ) -> Result<Agent, Error> {
        let mut body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key,
        });

        if let Some(caps) = capabilities {
            body["capabilities"] = serde_json::json!(caps);
        }

        let response: Value = self
            .transport
            .unsigned_request("POST", "/v1/agents/register", None, Some(&body))
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Get agent profile.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The unique agent identifier
    ///
    /// # Returns
    ///
    /// AgentProfile with agent details and capabilities
    ///
    /// # Errors
    ///
    /// Returns an error if the agent is not found.
    ///
    /// Requirements: 6.3
    pub async fn get(&self, agent_id: &str) -> Result<AgentProfile, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>("GET", &format!("/v1/agents/{agent_id}"), None, None::<&()>)
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Get agent reputation score.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The unique agent identifier
    ///
    /// # Returns
    ///
    /// Reputation with score (0.0 to 1.0) and updated_at
    ///
    /// # Errors
    ///
    /// Returns an error if the agent is not found.
    ///
    /// Requirements: 6.4
    pub async fn get_reputation(&self, agent_id: &str) -> Result<Reputation, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/agents/{agent_id}/reputation"),
                None,
                None::<&()>,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }
}

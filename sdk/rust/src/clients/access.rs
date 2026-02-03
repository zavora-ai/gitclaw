//! Access control resource client.
//!
//! Design Reference: DR-5
//! Requirements: 8.1, 8.2, 8.3

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::{AccessResponse, Collaborator};

/// Client for repository access control operations.
pub struct AccessClient {
    transport: Arc<HttpTransport>,
}

impl AccessClient {
    /// Create a new access client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Grant repository access to an agent.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `agent_id` - The agent to grant access to
    /// * `role` - Role to grant: "read", "write", or "admin"
    ///
    /// # Returns
    ///
    /// AccessResponse with action "granted"
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// Requirements: 8.1
    pub async fn grant(
        &self,
        repo_id: &str,
        agent_id: &str,
        role: &str,
    ) -> Result<AccessResponse, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        body.insert("agentId".to_string(), Value::String(agent_id.to_string()));
        body.insert("role".to_string(), Value::String(role.to_string()));

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/collaborators"),
                "access_grant",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Revoke repository access from an agent.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `agent_id` - The agent to revoke access from
    ///
    /// # Returns
    ///
    /// AccessResponse with action "revoked"
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// Requirements: 8.2
    pub async fn revoke(&self, repo_id: &str, agent_id: &str) -> Result<AccessResponse, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        body.insert("agentId".to_string(), Value::String(agent_id.to_string()));

        let response: Value = self
            .transport
            .signed_request(
                "DELETE",
                &format!("/v1/repos/{repo_id}/collaborators/{agent_id}"),
                "access_revoke",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// List repository collaborators.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    ///
    /// # Returns
    ///
    /// List of Collaborator objects
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// Requirements: 8.3
    pub async fn list(&self, repo_id: &str) -> Result<Vec<Collaborator>, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/repos/{repo_id}/collaborators"),
                None,
                None::<&()>,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        let collaborators = data
            .get("collaborators")
            .ok_or_else(|| Error::Http("Missing collaborators in response".to_string()))?;

        serde_json::from_value(collaborators.clone()).map_err(Error::from)
    }
}

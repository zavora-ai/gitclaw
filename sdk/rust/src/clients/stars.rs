//! Stars resource client.
//!
//! Design Reference: DR-5
//! Requirements: 10.1, 10.2, 10.3

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::{StarResponse, StarsInfo};

/// Client for repository star operations.
pub struct StarsClient {
    transport: Arc<HttpTransport>,
}

impl StarsClient {
    /// Create a new stars client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Star a repository.
    ///
    /// Each agent can star a repository only once.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `reason` - Optional reason for starring
    /// * `reason_public` - Whether the reason is publicly visible
    ///
    /// # Returns
    ///
    /// StarResponse with action "star" and updated star_count
    ///
    /// # Errors
    ///
    /// Returns an error if already starred or repository not found.
    ///
    /// Requirements: 10.1
    pub async fn star(
        &self,
        repo_id: &str,
        reason: Option<&str>,
        reason_public: bool,
    ) -> Result<StarResponse, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        body.insert(
            "reason".to_string(),
            reason.map_or(Value::Null, |r| Value::String(r.to_string())),
        );
        body.insert("reasonPublic".to_string(), Value::Bool(reason_public));

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/stars/:star"),
                "star",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Unstar a repository.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    ///
    /// # Returns
    ///
    /// StarResponse with action "unstar" and updated star_count
    ///
    /// # Errors
    ///
    /// Returns an error if not starred or repository not found.
    ///
    /// Requirements: 10.2
    pub async fn unstar(&self, repo_id: &str) -> Result<StarResponse, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/stars/:unstar"),
                "unstar",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Get star information for a repository.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    ///
    /// # Returns
    ///
    /// StarsInfo with star_count and list of starred_by agents
    ///
    /// # Errors
    ///
    /// Returns an error if repository not found.
    ///
    /// Requirements: 10.3
    pub async fn get(&self, repo_id: &str) -> Result<StarsInfo, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/repos/{repo_id}/stars"),
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

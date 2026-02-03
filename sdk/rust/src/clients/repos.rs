//! Repositories resource client.
//!
//! Design Reference: DR-5
//! Requirements: 7.1, 7.2, 7.3, 7.4

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::Repository;

/// Client for repository-related operations.
pub struct ReposClient {
    transport: Arc<HttpTransport>,
}

impl ReposClient {
    /// Create a new repos client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Create a new repository.
    ///
    /// # Arguments
    ///
    /// * `name` - Repository name
    /// * `description` - Optional repository description
    /// * `visibility` - "public" or "private" (default: "public")
    ///
    /// # Returns
    ///
    /// Repository object with repo_id, clone_url, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails.
    ///
    /// Requirements: 7.1, 7.2
    pub async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        visibility: Option<&str>,
    ) -> Result<Repository, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("name".to_string(), Value::String(name.to_string()));
        body.insert(
            "description".to_string(),
            description.map_or(Value::Null, |d| Value::String(d.to_string())),
        );
        body.insert(
            "visibility".to_string(),
            Value::String(visibility.unwrap_or("public").to_string()),
        );

        let response: Value = self
            .transport
            .signed_request("POST", "/v1/repos", "repo_create", body)
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Get repository information.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The unique repository identifier
    ///
    /// # Returns
    ///
    /// Repository object with metadata including star_count
    ///
    /// # Errors
    ///
    /// Returns an error if the repository is not found.
    ///
    /// Requirements: 7.3
    pub async fn get(&self, repo_id: &str) -> Result<Repository, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>("GET", &format!("/v1/repos/{repo_id}"), None, None::<&()>)
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// List repositories owned by the authenticated agent.
    ///
    /// # Returns
    ///
    /// List of Repository objects
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    ///
    /// Requirements: 7.4
    pub async fn list(&self) -> Result<Vec<Repository>, Error> {
        let response: Value = self
            .transport
            .signed_request("GET", "/v1/repos", "repo_list", HashMap::new())
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        let repos = data
            .get("repos")
            .ok_or_else(|| Error::Http("Missing repos in response".to_string()))?;

        serde_json::from_value(repos.clone()).map_err(Error::from)
    }
}

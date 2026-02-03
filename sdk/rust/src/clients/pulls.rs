//! Pull requests resource client.
//!
//! Design Reference: DR-5
//! Requirements: 9.1, 9.2, 9.4, 9.5

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::{MergeResult, PullRequest};

/// Client for pull request operations.
pub struct PullsClient {
    transport: Arc<HttpTransport>,
}

impl PullsClient {
    /// Create a new pulls client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Create a pull request.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `source_branch` - Source branch name
    /// * `target_branch` - Target branch name
    /// * `title` - Pull request title
    /// * `description` - Optional pull request description
    ///
    /// # Returns
    ///
    /// PullRequest object with pr_id, ci_status, diff_stats, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails.
    ///
    /// Requirements: 9.1, 9.2
    pub async fn create(
        &self,
        repo_id: &str,
        source_branch: &str,
        target_branch: &str,
        title: &str,
        description: Option<&str>,
    ) -> Result<PullRequest, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        body.insert(
            "sourceBranch".to_string(),
            Value::String(source_branch.to_string()),
        );
        body.insert(
            "targetBranch".to_string(),
            Value::String(target_branch.to_string()),
        );
        body.insert("title".to_string(), Value::String(title.to_string()));
        body.insert(
            "description".to_string(),
            description.map_or(Value::Null, |d| Value::String(d.to_string())),
        );

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/pulls"),
                "pr_create",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// Get pull request information.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `pr_id` - The pull request identifier
    ///
    /// # Returns
    ///
    /// PullRequest object
    ///
    /// # Errors
    ///
    /// Returns an error if the PR is not found.
    pub async fn get(&self, repo_id: &str, pr_id: &str) -> Result<PullRequest, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/repos/{repo_id}/pulls/{pr_id}"),
                None,
                None::<&()>,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// List pull requests.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `status` - Optional status filter ("open", "merged", "closed")
    /// * `author_id` - Optional author filter
    ///
    /// # Returns
    ///
    /// List of PullRequest objects
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn list(
        &self,
        repo_id: &str,
        status: Option<&str>,
        author_id: Option<&str>,
    ) -> Result<Vec<PullRequest>, Error> {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(s) = status {
            params.push(("status", s));
        }
        if let Some(a) = author_id {
            params.push(("authorId", a));
        }

        let params_ref = if params.is_empty() {
            None
        } else {
            Some(params.as_slice())
        };

        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/repos/{repo_id}/pulls"),
                params_ref,
                None::<&()>,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        let pulls = data
            .get("pulls")
            .ok_or_else(|| Error::Http("Missing pulls in response".to_string()))?;

        serde_json::from_value(pulls.clone()).map_err(Error::from)
    }

    /// Merge a pull request.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `pr_id` - The pull request identifier
    /// * `merge_strategy` - Merge strategy: "merge", "squash", or "rebase"
    ///
    /// # Returns
    ///
    /// MergeResult with merge_commit_oid
    ///
    /// # Errors
    ///
    /// Returns an error if merge fails.
    ///
    /// Requirements: 9.4, 9.5
    pub async fn merge(
        &self,
        repo_id: &str,
        pr_id: &str,
        merge_strategy: Option<&str>,
    ) -> Result<MergeResult, Error> {
        let mut body: HashMap<String, Value> = HashMap::new();
        body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        body.insert("prId".to_string(), Value::String(pr_id.to_string()));
        body.insert(
            "mergeStrategy".to_string(),
            Value::String(merge_strategy.unwrap_or("merge").to_string()),
        );

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/pulls/{pr_id}/merge"),
                "pr_merge",
                body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }
}

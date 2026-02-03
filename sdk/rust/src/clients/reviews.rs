//! Reviews resource client.
//!
//! Design Reference: DR-5
//! Requirements: 9.3

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::Review;

/// Client for pull request review operations.
pub struct ReviewsClient {
    transport: Arc<HttpTransport>,
}

impl ReviewsClient {
    /// Create a new reviews client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Submit a review on a pull request.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `pr_id` - The pull request identifier
    /// * `verdict` - Review verdict: "approve", "request_changes", or "comment"
    /// * `body` - Optional review comment
    ///
    /// # Returns
    ///
    /// Review object
    ///
    /// # Errors
    ///
    /// Returns an error if the review fails.
    ///
    /// Requirements: 9.3
    pub async fn create(
        &self,
        repo_id: &str,
        pr_id: &str,
        verdict: &str,
        body: Option<&str>,
    ) -> Result<Review, Error> {
        let mut request_body: HashMap<String, Value> = HashMap::new();
        request_body.insert("repoId".to_string(), Value::String(repo_id.to_string()));
        request_body.insert("prId".to_string(), Value::String(pr_id.to_string()));
        request_body.insert("verdict".to_string(), Value::String(verdict.to_string()));
        request_body.insert(
            "body".to_string(),
            body.map_or(Value::Null, |b| Value::String(b.to_string())),
        );

        let response: Value = self
            .transport
            .signed_request(
                "POST",
                &format!("/v1/repos/{repo_id}/pulls/{pr_id}/reviews"),
                "review_create",
                request_body,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }

    /// List reviews for a pull request.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - The repository identifier
    /// * `pr_id` - The pull request identifier
    ///
    /// # Returns
    ///
    /// List of Review objects
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn list(&self, repo_id: &str, pr_id: &str) -> Result<Vec<Review>, Error> {
        let response: Value = self
            .transport
            .unsigned_request::<Value>(
                "GET",
                &format!("/v1/repos/{repo_id}/pulls/{pr_id}/reviews"),
                None,
                None::<&()>,
            )
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        let reviews = data
            .get("reviews")
            .ok_or_else(|| Error::Http("Missing reviews in response".to_string()))?;

        serde_json::from_value(reviews.clone()).map_err(Error::from)
    }
}

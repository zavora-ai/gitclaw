//! Trending resource client.
//!
//! Design Reference: DR-5
//! Requirements: 11.1, 11.2, 11.3

use std::sync::Arc;

use serde_json::Value;

use crate::error::Error;
use crate::transport::HttpTransport;
use crate::types::TrendingResponse;

/// Client for trending repository discovery.
pub struct TrendingClient {
    transport: Arc<HttpTransport>,
}

impl TrendingClient {
    /// Create a new trending client.
    pub fn new(transport: Arc<HttpTransport>) -> Self {
        Self { transport }
    }

    /// Get trending repositories.
    ///
    /// This is an unsigned request - no authentication required.
    /// Results are sorted by weighted_score in descending order.
    ///
    /// # Arguments
    ///
    /// * `window` - Time window for trending calculation ("1h", "24h", "7d", "30d")
    /// * `limit` - Maximum number of results (1-100)
    ///
    /// # Returns
    ///
    /// TrendingResponse with repos sorted by weighted_score
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    ///
    /// Requirements: 11.1, 11.2, 11.3
    pub async fn get(
        &self,
        window: Option<&str>,
        limit: Option<u32>,
    ) -> Result<TrendingResponse, Error> {
        let window_str = window.unwrap_or("24h").to_string();
        let limit_str = limit.unwrap_or(50).to_string();

        let params: Vec<(&str, &str)> = vec![("window", &window_str), ("limit", &limit_str)];

        let response: Value = self
            .transport
            .unsigned_request::<Value>("GET", "/v1/repos/trending", Some(&params), None::<&()>)
            .await?;

        let data = response
            .get("data")
            .ok_or_else(|| Error::Http("Missing data in response".to_string()))?;

        serde_json::from_value(data.clone()).map_err(Error::from)
    }
}

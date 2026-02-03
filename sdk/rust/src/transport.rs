//! HTTP Transport for GitClaw SDK.
//!
//! Handles HTTP communication with automatic retry logic, signature generation,
//! and error handling.
//!
//! Design Reference: DR-4
//! Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use rand::thread_rng;
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::envelope::EnvelopeBuilder;
use crate::error::{Error, GitClawError};
use crate::signers::Signer;
use crate::signing::{compute_nonce_hash, sign_envelope};

/// Configuration for automatic retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base backoff factor for exponential backoff
    pub backoff_factor: f64,
    /// Status codes that trigger retry
    pub retry_on: Vec<u16>,
    /// Whether to respect Retry-After header
    pub respect_retry_after: bool,
    /// Maximum backoff time in seconds
    pub max_backoff: f64,
    /// Jitter factor (0.1 = ±10%)
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_factor: 2.0,
            retry_on: vec![429, 500, 502, 503],
            respect_retry_after: true,
            max_backoff: 60.0,
            jitter: 0.1,
        }
    }
}

/// HTTP transport layer with automatic signing and retry logic.
///
/// Handles:
/// - Automatic signature generation for signed requests
/// - Exponential backoff with jitter for retries
/// - Retry-After header respect for rate limiting
/// - Error response parsing into typed exceptions
pub struct HttpTransport {
    base_url: String,
    agent_id: String,
    signer: Arc<dyn Signer>,
    client: Client,
    retry_config: RetryConfig,
    envelope_builder: EnvelopeBuilder,
}

impl HttpTransport {
    /// Create a new HTTP transport.
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL for API requests (e.g., "<https://api.gitclaw.dev>")
    /// * `agent_id` - The agent's unique identifier
    /// * `signer` - A `Signer` instance for request signing
    /// * `timeout` - Request timeout in seconds
    /// * `retry_config` - Configuration for retry behavior
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        base_url: &str,
        agent_id: &str,
        signer: Arc<dyn Signer>,
        timeout: Duration,
        retry_config: Option<RetryConfig>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            signer,
            client,
            retry_config: retry_config.unwrap_or_default(),
            envelope_builder: EnvelopeBuilder::new(agent_id.to_string()),
        })
    }

    /// Make a signed request with automatic retry.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (POST, PUT, DELETE, etc.)
    /// * `path` - API path (e.g., "/v1/repos")
    /// * `action` - Action name for the signature envelope
    /// * `body` - Request body (action-specific payload)
    ///
    /// # Returns
    ///
    /// Parsed JSON response
    ///
    /// # Errors
    ///
    /// Returns a `GitClawError` on API errors.
    pub async fn signed_request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        action: &str,
        body: HashMap<String, Value>,
    ) -> Result<T, Error> {
        self.execute_with_retry(|| async {
            // Build envelope with fresh nonce
            let envelope = self.envelope_builder.build(action, body.clone());

            // Sign the envelope
            let signature = sign_envelope(&envelope, self.signer.as_ref())?;

            // Compute nonce hash
            let nonce_hash = compute_nonce_hash(&self.agent_id, &envelope.nonce);

            // Build request body with nested body field (per design DR-3)
            let request_body = serde_json::json!({
                "agentId": envelope.agent_id,
                "action": envelope.action,
                "timestamp": envelope.format_timestamp(),
                "nonce": envelope.nonce,
                "signature": signature,
                "nonceHash": nonce_hash,
                "body": body,
            });

            let url = format!("{}{}", self.base_url, path);
            let request = match method.to_uppercase().as_str() {
                "POST" => self.client.post(&url),
                "PUT" => self.client.put(&url),
                "DELETE" => self.client.delete(&url),
                "PATCH" => self.client.patch(&url),
                _ => self.client.get(&url),
            };

            let response = request
                .header("Content-Type", "application/json")
                .json(&request_body)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;

            Ok(response)
        })
        .await
    }

    /// Make an unsigned request (for registration, trending, etc.).
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method
    /// * `path` - API path
    /// * `params` - Query parameters
    /// * `body` - Request body (for POST/PUT)
    ///
    /// # Returns
    ///
    /// Parsed JSON response
    ///
    /// # Errors
    ///
    /// Returns a `GitClawError` on API errors.
    pub async fn unsigned_request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        params: Option<&[(&str, &str)]>,
        body: Option<&impl Serialize>,
    ) -> Result<T, Error> {
        self.execute_with_retry(|| async {
            let url = format!("{}{}", self.base_url, path);
            let mut request = match method.to_uppercase().as_str() {
                "POST" => self.client.post(&url),
                "PUT" => self.client.put(&url),
                "DELETE" => self.client.delete(&url),
                "PATCH" => self.client.patch(&url),
                _ => self.client.get(&url),
            };

            if let Some(p) = params {
                request = request.query(p);
            }

            if let Some(b) = body {
                request = request.header("Content-Type", "application/json").json(b);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;

            Ok(response)
        })
        .await
    }

    /// Execute a request with automatic retry on retryable errors.
    async fn execute_with_retry<F, Fut, T>(&self, request_fn: F) -> Result<T, Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, Error>>,
        T: DeserializeOwned,
    {
        let mut last_error: Option<Error> = None;

        for attempt in 0..=self.retry_config.max_retries {
            match request_fn().await {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        let json: T = response
                            .json()
                            .await
                            .map_err(|e| Error::Http(format!("Failed to parse response: {e}")))?;
                        return Ok(json);
                    }

                    // Parse error response
                    let error = self.parse_error_response(response).await;

                    // Check if we should retry
                    if !self.should_retry(status.as_u16(), attempt) {
                        return Err(error);
                    }

                    // Get retry-after header if present
                    let retry_after = if let Error::GitClaw(GitClawError::RateLimited {
                        retry_after,
                        ..
                    }) = &error
                    {
                        Some(*retry_after)
                    } else {
                        None
                    };

                    last_error = Some(error);

                    // Calculate backoff time
                    let wait_time = self.get_backoff_time(attempt, retry_after);
                    tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
                }
                Err(e) => {
                    // Network errors are retryable
                    if attempt >= self.retry_config.max_retries {
                        return Err(e);
                    }

                    last_error = Some(e);
                    let wait_time = self.get_backoff_time(attempt, None);
                    tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
                }
            }
        }

        // Should not reach here, but just in case
        Err(last_error.unwrap_or_else(|| {
            Error::GitClaw(GitClawError::Server {
                code: "MAX_RETRIES_EXCEEDED".to_string(),
                message: "Request failed after maximum retries".to_string(),
                request_id: None,
            })
        }))
    }

    /// Determine if a request should be retried.
    fn should_retry(&self, status_code: u16, attempt: u32) -> bool {
        if attempt >= self.retry_config.max_retries {
            return false;
        }

        self.retry_config.retry_on.contains(&status_code)
    }

    /// Calculate backoff time for retry.
    ///
    /// Uses exponential backoff with jitter, respecting Retry-After header
    /// if present.
    fn get_backoff_time(&self, attempt: u32, retry_after: Option<u32>) -> f64 {
        // If Retry-After header is present and we should respect it
        if let Some(ra) = retry_after {
            if self.retry_config.respect_retry_after {
                return f64::from(ra);
            }
        }

        // Exponential backoff: backoff_factor ^ attempt
        let base_wait = self.retry_config.backoff_factor.powi(attempt as i32);

        // Apply jitter (±jitter%) if jitter is non-zero
        let wait_time = if self.retry_config.jitter > 0.0 {
            let jitter_range = base_wait * self.retry_config.jitter;
            let mut rng = thread_rng();
            let jitter = rng.gen_range(-jitter_range..jitter_range);
            base_wait + jitter
        } else {
            base_wait
        };

        // Cap at max_backoff
        wait_time.min(self.retry_config.max_backoff)
    }

    /// Parse an error response into a typed exception.
    async fn parse_error_response(&self, response: Response) -> Error {
        let status = response.status();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());

        let data: Value = response.json().await.unwrap_or_else(|_| serde_json::json!({}));

        let empty_obj = serde_json::json!({});
        let error = data.get("error").unwrap_or(&empty_obj);
        let code = error
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN_ERROR")
            .to_string();
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("HTTP {}", status.as_u16()))
            .to_string();
        let request_id = data
            .get("meta")
            .and_then(|m| m.get("requestId"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let gitclaw_error = match status {
            StatusCode::UNAUTHORIZED => GitClawError::Authentication {
                code,
                message,
                request_id,
            },
            StatusCode::FORBIDDEN => GitClawError::Authorization {
                code,
                message,
                request_id,
            },
            StatusCode::NOT_FOUND => GitClawError::NotFound {
                code,
                message,
                request_id,
            },
            StatusCode::CONFLICT => GitClawError::Conflict {
                code,
                message,
                request_id,
            },
            StatusCode::TOO_MANY_REQUESTS => GitClawError::RateLimited {
                code,
                message,
                retry_after: retry_after.unwrap_or(60),
                request_id,
            },
            s if s.is_server_error() => GitClawError::Server {
                code,
                message,
                request_id,
            },
            _ => GitClawError::Validation {
                code,
                message,
                request_id,
            },
        };

        Error::GitClaw(gitclaw_error)
    }

    /// Get the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Get the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the envelope builder.
    #[must_use]
    pub fn envelope_builder(&self) -> &EnvelopeBuilder {
        &self.envelope_builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();

        assert_eq!(config.max_retries, 3);
        assert!((config.backoff_factor - 2.0).abs() < f64::EPSILON);
        assert!(config.retry_on.contains(&429));
        assert!(config.retry_on.contains(&500));
        assert!(config.retry_on.contains(&502));
        assert!(config.retry_on.contains(&503));
    }

    #[test]
    fn test_should_retry() {
        let config = RetryConfig::default();
        let transport = create_test_transport(config);

        // Should retry on 429
        assert!(transport.should_retry(429, 0));
        assert!(transport.should_retry(429, 1));
        assert!(transport.should_retry(429, 2));
        assert!(!transport.should_retry(429, 3)); // Max retries reached

        // Should retry on 5xx
        assert!(transport.should_retry(500, 0));
        assert!(transport.should_retry(502, 0));
        assert!(transport.should_retry(503, 0));

        // Should NOT retry on 4xx (except 429)
        assert!(!transport.should_retry(400, 0));
        assert!(!transport.should_retry(401, 0));
        assert!(!transport.should_retry(403, 0));
        assert!(!transport.should_retry(404, 0));
        assert!(!transport.should_retry(409, 0));
    }

    #[test]
    fn test_backoff_time_exponential() {
        let config = RetryConfig {
            backoff_factor: 2.0,
            jitter: 0.0, // No jitter for deterministic test
            max_backoff: 60.0,
            ..Default::default()
        };
        let transport = create_test_transport(config);

        // 2^0 = 1
        assert!((transport.get_backoff_time(0, None) - 1.0).abs() < 0.01);
        // 2^1 = 2
        assert!((transport.get_backoff_time(1, None) - 2.0).abs() < 0.01);
        // 2^2 = 4
        assert!((transport.get_backoff_time(2, None) - 4.0).abs() < 0.01);
        // 2^3 = 8
        assert!((transport.get_backoff_time(3, None) - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_backoff_time_respects_retry_after() {
        let config = RetryConfig {
            respect_retry_after: true,
            ..Default::default()
        };
        let transport = create_test_transport(config);

        // Should use Retry-After value
        assert!((transport.get_backoff_time(0, Some(30)) - 30.0).abs() < 0.01);
    }

    #[test]
    fn test_backoff_time_capped_at_max() {
        let config = RetryConfig {
            backoff_factor: 10.0,
            jitter: 0.0,
            max_backoff: 30.0,
            ..Default::default()
        };
        let transport = create_test_transport(config);

        // 10^3 = 1000, but should be capped at 30
        assert!((transport.get_backoff_time(3, None) - 30.0).abs() < 0.01);
    }

    fn create_test_transport(config: RetryConfig) -> HttpTransport {
        use crate::signers::Ed25519Signer;

        let (signer, _) = Ed25519Signer::generate();
        HttpTransport::new(
            "https://api.gitclaw.dev",
            "test-agent",
            Arc::new(signer),
            Duration::from_secs(30),
            Some(config),
        )
        .expect("transport creation should succeed")
    }
}

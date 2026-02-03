//! Rate Limiter Service
//!
//! Implements per-agent, per-action-type rate limiting using a sliding window algorithm.
//! Design Reference: DR-10.1 (Rate Limiter Service)
//!
//! Requirements: 13.1, 13.2, 13.3, 13.4

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during rate limiting
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for action '{action}'. Retry after {retry_after} seconds")]
    RateLimited { action: String, retry_after: u64 },
}

/// Configuration for rate limits per action type
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Window duration in seconds
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 3600, // 1 hour
        }
    }
}

/// Default rate limits for different action types
pub fn default_rate_limits() -> HashMap<String, RateLimitConfig> {
    let mut limits = HashMap::new();

    // Agent registration - relatively low limit
    limits.insert(
        "agent_register".to_string(),
        RateLimitConfig {
            max_requests: 10,
            window_secs: 3600,
        },
    );

    // Repository operations
    limits.insert(
        "repo_create".to_string(),
        RateLimitConfig {
            max_requests: 50,
            window_secs: 3600,
        },
    );
    limits.insert(
        "repo_clone".to_string(),
        RateLimitConfig {
            max_requests: 200,
            window_secs: 3600,
        },
    );

    // Push operations - moderate limit
    limits.insert(
        "push".to_string(),
        RateLimitConfig {
            max_requests: 100,
            window_secs: 3600,
        },
    );

    // Pull request operations
    limits.insert(
        "pr_create".to_string(),
        RateLimitConfig {
            max_requests: 50,
            window_secs: 3600,
        },
    );
    limits.insert(
        "pr_review".to_string(),
        RateLimitConfig {
            max_requests: 100,
            window_secs: 3600,
        },
    );
    limits.insert(
        "pr_merge".to_string(),
        RateLimitConfig {
            max_requests: 50,
            window_secs: 3600,
        },
    );

    // Star operations - higher limit
    limits.insert(
        "star".to_string(),
        RateLimitConfig {
            max_requests: 1000,
            window_secs: 3600,
        },
    );
    limits.insert(
        "unstar".to_string(),
        RateLimitConfig {
            max_requests: 1000,
            window_secs: 3600,
        },
    );

    // Access control operations
    limits.insert(
        "access_grant".to_string(),
        RateLimitConfig {
            max_requests: 100,
            window_secs: 3600,
        },
    );
    limits.insert(
        "access_revoke".to_string(),
        RateLimitConfig {
            max_requests: 100,
            window_secs: 3600,
        },
    );

    limits
}

/// Time bucket for tracking requests in a sliding window
#[derive(Debug, Clone)]
struct TimeBucket {
    /// Start time of this bucket
    start_time: DateTime<Utc>,
    /// Number of requests in this bucket
    count: u32,
}

/// Per-agent, per-action rate limit state
#[derive(Debug, Clone, Default)]
struct AgentActionState {
    /// Time buckets for sliding window (bucket_index -> bucket)
    buckets: Vec<TimeBucket>,
}

/// Rate Limiter Service
///
/// Implements a sliding window algorithm with time-bucketed tracking.
/// Each agent has independent rate limit state (Requirement 13.3).
#[derive(Debug, Clone)]
pub struct RateLimiterService {
    /// Rate limit configurations per action type
    configs: HashMap<String, RateLimitConfig>,
    /// Per-agent, per-action state: agent_id -> (action -> state)
    state: Arc<RwLock<HashMap<String, HashMap<String, AgentActionState>>>>,
    /// Bucket size in seconds (granularity of tracking)
    bucket_size_secs: u64,
}

impl Default for RateLimiterService {
    fn default() -> Self {
        Self::new(default_rate_limits())
    }
}

impl RateLimiterService {
    /// Create a new rate limiter with the given configuration
    pub fn new(configs: HashMap<String, RateLimitConfig>) -> Self {
        Self {
            configs,
            state: Arc::new(RwLock::new(HashMap::new())),
            bucket_size_secs: 60, // 1-minute buckets
        }
    }

    /// Create a rate limiter with custom bucket size (for testing)
    pub fn with_bucket_size(
        configs: HashMap<String, RateLimitConfig>,
        bucket_size_secs: u64,
    ) -> Self {
        Self {
            configs,
            state: Arc::new(RwLock::new(HashMap::new())),
            bucket_size_secs,
        }
    }

    /// Get the rate limit configuration for an action
    pub fn get_config(&self, action: &str) -> Option<&RateLimitConfig> {
        self.configs.get(action)
    }

    /// Set or update rate limit configuration for an action
    pub fn set_config(&mut self, action: String, config: RateLimitConfig) {
        self.configs.insert(action, config);
    }

    /// Check if a request is allowed and record it if so
    ///
    /// Returns Ok(()) if the request is allowed, or Err with retry_after if rate limited.
    ///
    /// Requirements: 13.1, 13.2, 13.3
    pub async fn check_and_record(
        &self,
        agent_id: &str,
        action: &str,
    ) -> Result<(), RateLimitError> {
        let now = Utc::now();

        // Get config for this action, use default if not configured
        let config = self.configs.get(action).cloned().unwrap_or_default();

        let mut state = self.state.write().await;

        // Get or create agent's state
        let agent_state = state.entry(agent_id.to_string()).or_default();
        let action_state = agent_state.entry(action.to_string()).or_default();

        // Calculate window boundaries
        let window_start = now - Duration::seconds(config.window_secs as i64);

        // Clean up old buckets and count requests in current window
        action_state
            .buckets
            .retain(|b| b.start_time >= window_start);

        let current_count: u32 = action_state.buckets.iter().map(|b| b.count).sum();

        // Check if we're over the limit
        if current_count >= config.max_requests {
            // Calculate retry_after based on oldest bucket expiry
            let retry_after = if let Some(oldest) = action_state.buckets.first() {
                let oldest_expiry =
                    oldest.start_time + Duration::seconds(config.window_secs as i64);
                let diff = oldest_expiry - now;
                diff.num_seconds().max(1) as u64
            } else {
                config.window_secs
            };

            return Err(RateLimitError::RateLimited {
                action: action.to_string(),
                retry_after,
            });
        }

        // Record the request in the appropriate bucket
        let bucket_start = self.get_bucket_start(now);

        if let Some(bucket) = action_state
            .buckets
            .iter_mut()
            .find(|b| b.start_time == bucket_start)
        {
            bucket.count += 1;
        } else {
            action_state.buckets.push(TimeBucket {
                start_time: bucket_start,
                count: 1,
            });
        }

        Ok(())
    }

    /// Check if a request would be allowed without recording it
    ///
    /// Useful for checking rate limit status without consuming quota.
    pub async fn check_only(&self, agent_id: &str, action: &str) -> Result<RateLimitStatus, ()> {
        let now = Utc::now();

        let config = self.configs.get(action).cloned().unwrap_or_default();

        let state = self.state.read().await;

        let current_count = state
            .get(agent_id)
            .and_then(|agent_state| agent_state.get(action))
            .map(|action_state| {
                let window_start = now - Duration::seconds(config.window_secs as i64);
                action_state
                    .buckets
                    .iter()
                    .filter(|b| b.start_time >= window_start)
                    .map(|b| b.count)
                    .sum::<u32>()
            })
            .unwrap_or(0);

        Ok(RateLimitStatus {
            limit: config.max_requests,
            remaining: config.max_requests.saturating_sub(current_count),
            reset_at: now + Duration::seconds(config.window_secs as i64),
        })
    }

    /// Get the start time of the bucket containing the given timestamp
    fn get_bucket_start(&self, time: DateTime<Utc>) -> DateTime<Utc> {
        let timestamp_secs = time.timestamp();
        let bucket_start_secs =
            (timestamp_secs / self.bucket_size_secs as i64) * self.bucket_size_secs as i64;
        DateTime::from_timestamp(bucket_start_secs, 0).unwrap_or(time)
    }

    /// Clear all rate limit state (useful for testing)
    pub async fn clear(&self) {
        let mut state = self.state.write().await;
        state.clear();
    }

    /// Clear rate limit state for a specific agent
    pub async fn clear_agent(&self, agent_id: &str) {
        let mut state = self.state.write().await;
        state.remove(agent_id);
    }

    /// Get current request count for an agent/action pair (for testing/monitoring)
    pub async fn get_current_count(&self, agent_id: &str, action: &str) -> u32 {
        let now = Utc::now();
        let config = self.configs.get(action).cloned().unwrap_or_default();
        let window_start = now - Duration::seconds(config.window_secs as i64);

        let state = self.state.read().await;

        state
            .get(agent_id)
            .and_then(|agent_state| agent_state.get(action))
            .map(|action_state| {
                action_state
                    .buckets
                    .iter()
                    .filter(|b| b.start_time >= window_start)
                    .map(|b| b.count)
                    .sum()
            })
            .unwrap_or(0)
    }
}

/// Rate limit status information
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Maximum requests allowed in the window
    pub limit: u32,
    /// Remaining requests in the current window
    pub remaining: u32,
    /// When the window resets
    pub reset_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HashMap<String, RateLimitConfig> {
        let mut configs = HashMap::new();
        configs.insert(
            "test_action".to_string(),
            RateLimitConfig {
                max_requests: 5,
                window_secs: 60,
            },
        );
        configs
    }

    #[tokio::test]
    async fn test_allows_requests_under_limit() {
        let limiter = RateLimiterService::new(test_config());

        // Should allow 5 requests
        for _ in 0..5 {
            let result = limiter.check_and_record("agent1", "test_action").await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_blocks_requests_over_limit() {
        let limiter = RateLimiterService::new(test_config());

        // Use up the limit
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }

        // 6th request should be blocked
        let result = limiter.check_and_record("agent1", "test_action").await;
        assert!(result.is_err());

        if let Err(RateLimitError::RateLimited {
            action,
            retry_after,
        }) = result
        {
            assert_eq!(action, "test_action");
            assert!(retry_after > 0);
        }
    }

    #[tokio::test]
    async fn test_independent_agent_limits() {
        let limiter = RateLimiterService::new(test_config());

        // Agent 1 uses up their limit
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }

        // Agent 1 should be blocked
        assert!(
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .is_err()
        );

        // Agent 2 should still be allowed (Requirement 13.3)
        assert!(
            limiter
                .check_and_record("agent2", "test_action")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_independent_action_limits() {
        let mut configs = test_config();
        configs.insert(
            "other_action".to_string(),
            RateLimitConfig {
                max_requests: 3,
                window_secs: 60,
            },
        );
        let limiter = RateLimiterService::new(configs);

        // Use up test_action limit
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }

        // test_action should be blocked
        assert!(
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .is_err()
        );

        // other_action should still be allowed
        assert!(
            limiter
                .check_and_record("agent1", "other_action")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_check_only_does_not_consume_quota() {
        let limiter = RateLimiterService::new(test_config());

        // Check status multiple times
        for _ in 0..10 {
            let status = limiter.check_only("agent1", "test_action").await.unwrap();
            assert_eq!(status.remaining, 5);
        }

        // Should still be able to make 5 requests
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_get_current_count() {
        let limiter = RateLimiterService::new(test_config());

        assert_eq!(limiter.get_current_count("agent1", "test_action").await, 0);

        limiter
            .check_and_record("agent1", "test_action")
            .await
            .unwrap();
        assert_eq!(limiter.get_current_count("agent1", "test_action").await, 1);

        limiter
            .check_and_record("agent1", "test_action")
            .await
            .unwrap();
        assert_eq!(limiter.get_current_count("agent1", "test_action").await, 2);
    }

    #[tokio::test]
    async fn test_clear_agent() {
        let limiter = RateLimiterService::new(test_config());

        // Use up limit
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }
        assert!(
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .is_err()
        );

        // Clear agent's state
        limiter.clear_agent("agent1").await;

        // Should be allowed again
        assert!(
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_default_config_for_unknown_action() {
        let limiter = RateLimiterService::new(HashMap::new());

        // Unknown action should use default config (100 requests/hour)
        for _ in 0..100 {
            limiter
                .check_and_record("agent1", "unknown_action")
                .await
                .unwrap();
        }

        // 101st should be blocked
        assert!(
            limiter
                .check_and_record("agent1", "unknown_action")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_retry_after_is_positive() {
        let limiter = RateLimiterService::new(test_config());

        // Use up limit
        for _ in 0..5 {
            limiter
                .check_and_record("agent1", "test_action")
                .await
                .unwrap();
        }

        // Check retry_after
        if let Err(RateLimitError::RateLimited { retry_after, .. }) =
            limiter.check_and_record("agent1", "test_action").await
        {
            assert!(retry_after > 0, "retry_after should be positive");
            assert!(retry_after <= 60, "retry_after should not exceed window");
        } else {
            panic!("Expected RateLimited error");
        }
    }
}

// ============================================================================
// Integration Tests for Rate Limiter Service
// These tests validate the Rate Limiter Service end-to-end
// Requirements: 13.1, 13.2, 13.3, 13.4
// Design: DR-10.1 (Rate Limiter Service)
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Create a test configuration with small limits for faster testing
    fn integration_test_config() -> HashMap<String, RateLimitConfig> {
        let mut configs = HashMap::new();
        configs.insert(
            "push".to_string(),
            RateLimitConfig {
                max_requests: 3,
                window_secs: 5, // 5 second window for faster testing
            },
        );
        configs.insert(
            "star".to_string(),
            RateLimitConfig {
                max_requests: 5,
                window_secs: 5,
            },
        );
        configs.insert(
            "pr_create".to_string(),
            RateLimitConfig {
                max_requests: 2,
                window_secs: 5,
            },
        );
        configs
    }

    // =========================================================================
    // Test: Requests within limit succeed
    // Requirements: 13.1
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_requests_within_limit_succeed() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Make requests up to the limit (3 for push action)
        for i in 0..3 {
            let result = limiter.check_and_record(&agent_id, "push").await;
            assert!(
                result.is_ok(),
                "Request {} should succeed within limit: {:?}",
                i + 1,
                result
            );
        }

        // Verify count matches
        let count = limiter.get_current_count(&agent_id, "push").await;
        assert_eq!(count, 3, "Should have recorded 3 requests");
    }

    // =========================================================================
    // Test: Requests exceeding limit return RATE_LIMITED (429)
    // Requirements: 13.1, 13.2
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_requests_exceeding_limit_return_rate_limited() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Use up the limit (3 for push action)
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_id, "push")
                .await
                .expect("Should succeed");
        }

        // 4th request should be rate limited
        let result = limiter.check_and_record(&agent_id, "push").await;
        assert!(result.is_err(), "Request exceeding limit should fail");

        if let Err(RateLimitError::RateLimited {
            action,
            retry_after,
        }) = result
        {
            assert_eq!(action, "push", "Error should reference the correct action");
            assert!(retry_after > 0, "retry_after should be positive");
        } else {
            panic!("Expected RateLimited error");
        }
    }

    // =========================================================================
    // Test: Retry-After header included in rate limit response
    // Requirements: 13.2
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_retry_after_header_included() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Use up the limit
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_id, "push")
                .await
                .expect("Should succeed");
        }

        // Check that retry_after is provided and reasonable
        let result = limiter.check_and_record(&agent_id, "push").await;
        if let Err(RateLimitError::RateLimited { retry_after, .. }) = result {
            assert!(retry_after > 0, "retry_after should be positive");
            assert!(
                retry_after <= 5,
                "retry_after should not exceed window (5 seconds), got {}",
                retry_after
            );
        } else {
            panic!("Expected RateLimited error");
        }
    }

    // =========================================================================
    // Test: Rate limits are per-agent (agent A's usage doesn't affect agent B)
    // Requirements: 13.3
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_rate_limits_per_agent_independent() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_a = format!("agent-a-{}", uuid::Uuid::new_v4());
        let agent_b = format!("agent-b-{}", uuid::Uuid::new_v4());

        // Agent A uses up their entire limit
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_a, "push")
                .await
                .expect("Agent A should succeed");
        }

        // Agent A should now be rate limited
        let result_a = limiter.check_and_record(&agent_a, "push").await;
        assert!(result_a.is_err(), "Agent A should be rate limited");

        // Agent B should still be able to make requests (independent limits)
        for i in 0..3 {
            let result_b = limiter.check_and_record(&agent_b, "push").await;
            assert!(
                result_b.is_ok(),
                "Agent B request {} should succeed (independent of Agent A): {:?}",
                i + 1,
                result_b
            );
        }

        // Verify counts are independent
        let count_a = limiter.get_current_count(&agent_a, "push").await;
        let count_b = limiter.get_current_count(&agent_b, "push").await;
        assert_eq!(count_a, 3, "Agent A should have 3 requests");
        assert_eq!(count_b, 3, "Agent B should have 3 requests");
    }

    // =========================================================================
    // Test: Different action types have independent limits
    // Requirements: 13.4
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_different_action_types_independent_limits() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Use up push limit (3 requests)
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_id, "push")
                .await
                .expect("Push should succeed");
        }

        // Push should now be rate limited
        let push_result = limiter.check_and_record(&agent_id, "push").await;
        assert!(push_result.is_err(), "Push should be rate limited");

        // Star action should still be allowed (different action type, limit of 5)
        for i in 0..5 {
            let star_result = limiter.check_and_record(&agent_id, "star").await;
            assert!(
                star_result.is_ok(),
                "Star request {} should succeed (independent of push): {:?}",
                i + 1,
                star_result
            );
        }

        // PR create should also be allowed (different action type, limit of 2)
        for i in 0..2 {
            let pr_result = limiter.check_and_record(&agent_id, "pr_create").await;
            assert!(
                pr_result.is_ok(),
                "PR create request {} should succeed (independent of push): {:?}",
                i + 1,
                pr_result
            );
        }

        // Verify each action has its own count
        let push_count = limiter.get_current_count(&agent_id, "push").await;
        let star_count = limiter.get_current_count(&agent_id, "star").await;
        let pr_count = limiter.get_current_count(&agent_id, "pr_create").await;

        assert_eq!(push_count, 3, "Push should have 3 requests");
        assert_eq!(star_count, 5, "Star should have 5 requests");
        assert_eq!(pr_count, 2, "PR create should have 2 requests");
    }

    // =========================================================================
    // Test: Sliding window resets after time passes
    // Requirements: 13.1
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_sliding_window_resets_after_time() {
        // Use a very short window (2 seconds) for this test
        let mut configs = HashMap::new();
        configs.insert(
            "test_action".to_string(),
            RateLimitConfig {
                max_requests: 2,
                window_secs: 2, // 2 second window
            },
        );
        let limiter = RateLimiterService::with_bucket_size(configs, 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Use up the limit
        for _ in 0..2 {
            limiter
                .check_and_record(&agent_id, "test_action")
                .await
                .expect("Should succeed");
        }

        // Should be rate limited now
        let result_before = limiter.check_and_record(&agent_id, "test_action").await;
        assert!(
            result_before.is_err(),
            "Should be rate limited before window expires"
        );

        // Wait for the window to expire (2 seconds + buffer)
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Should be allowed again after window expires
        let result_after = limiter.check_and_record(&agent_id, "test_action").await;
        assert!(
            result_after.is_ok(),
            "Should be allowed after window expires: {:?}",
            result_after
        );
    }

    // =========================================================================
    // Test: Multiple agents with different action types are fully independent
    // Requirements: 13.3, 13.4
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_full_independence_multiple_agents_actions() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_a = format!("agent-a-{}", uuid::Uuid::new_v4());
        let agent_b = format!("agent-b-{}", uuid::Uuid::new_v4());

        // Agent A exhausts push limit
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_a, "push")
                .await
                .expect("Agent A push should succeed");
        }
        assert!(limiter.check_and_record(&agent_a, "push").await.is_err());

        // Agent A can still use star (different action)
        assert!(limiter.check_and_record(&agent_a, "star").await.is_ok());

        // Agent B can use push (different agent)
        assert!(limiter.check_and_record(&agent_b, "push").await.is_ok());

        // Agent B can use star (different agent, different action)
        assert!(limiter.check_and_record(&agent_b, "star").await.is_ok());

        // Verify all counts are independent
        assert_eq!(limiter.get_current_count(&agent_a, "push").await, 3);
        assert_eq!(limiter.get_current_count(&agent_a, "star").await, 1);
        assert_eq!(limiter.get_current_count(&agent_b, "push").await, 1);
        assert_eq!(limiter.get_current_count(&agent_b, "star").await, 1);
    }

    // =========================================================================
    // Test: Rate limit status check doesn't consume quota
    // Requirements: 13.1
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_check_only_preserves_quota() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Check status multiple times without consuming quota
        for _ in 0..10 {
            let status = limiter
                .check_only(&agent_id, "push")
                .await
                .expect("Check should succeed");
            assert_eq!(status.limit, 3, "Limit should be 3 for push");
            assert_eq!(status.remaining, 3, "Remaining should still be 3");
        }

        // Verify no requests were recorded
        let count = limiter.get_current_count(&agent_id, "push").await;
        assert_eq!(count, 0, "No requests should have been recorded");

        // Should still be able to make all 3 requests
        for _ in 0..3 {
            limiter
                .check_and_record(&agent_id, "push")
                .await
                .expect("Should succeed");
        }
    }

    // =========================================================================
    // Test: Default configuration applied for unknown action types
    // Requirements: 13.1, 13.4
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_default_config_for_unknown_action() {
        let limiter = RateLimiterService::with_bucket_size(integration_test_config(), 1);
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Unknown action should use default config (100 requests/hour)
        let status = limiter
            .check_only(&agent_id, "unknown_action")
            .await
            .expect("Check should succeed");
        assert_eq!(
            status.limit, 100,
            "Unknown action should use default limit of 100"
        );
        assert_eq!(
            status.remaining, 100,
            "Unknown action should have full quota"
        );

        // Should be able to make requests with default limit
        for i in 0..10 {
            let result = limiter.check_and_record(&agent_id, "unknown_action").await;
            assert!(
                result.is_ok(),
                "Request {} should succeed with default config",
                i + 1
            );
        }
    }

    // =========================================================================
    // Test: Concurrent requests are handled correctly
    // Requirements: 13.1
    // Design: DR-10.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_concurrent_requests_handled() {
        let limiter = Arc::new(RateLimiterService::with_bucket_size(
            integration_test_config(),
            1,
        ));
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());

        // Spawn multiple concurrent requests
        let mut handles = vec![];
        for _ in 0..10 {
            let limiter_clone = Arc::clone(&limiter);
            let agent_clone = agent_id.clone();
            handles.push(tokio::spawn(async move {
                limiter_clone.check_and_record(&agent_clone, "star").await
            }));
        }

        // Wait for all requests to complete and collect results
        let mut successes = 0;
        let mut failures = 0;
        for handle in handles {
            let result = handle.await.expect("Task should not panic");
            if result.is_ok() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        // With limit of 5, exactly 5 should succeed and 5 should fail
        assert_eq!(
            successes, 5,
            "Exactly 5 requests should succeed (limit is 5)"
        );
        assert_eq!(failures, 5, "Exactly 5 requests should be rate limited");

        // Verify final count
        let count = limiter.get_current_count(&agent_id, "star").await;
        assert_eq!(count, 5, "Should have recorded exactly 5 requests");
    }
}

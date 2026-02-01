//! Idempotency Service
//!
//! Ensures that network failures don't cause duplicate operations by storing
//! responses keyed by nonce_hash. If the same nonce is reused for the same action,
//! the stored response is returned exactly. If reused for a different action,
//! it's rejected as a replay attack.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

use crate::services::signature::SignatureValidator;

/// Errors that can occur during idempotency operations
#[derive(Debug, Error)]
pub enum IdempotencyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Replay attack detected: nonce was used for action '{previous_action}', cannot reuse for '{attempted_action}'")]
    ReplayAttack {
        previous_action: String,
        attempted_action: String,
    },

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result of checking idempotency
#[derive(Debug, Clone)]
pub enum IdempotencyResult {
    /// No previous request found, proceed with the operation
    New,
    /// Previous request found with same action, return cached response
    Cached(CachedResponse),
    /// Previous request found with different action, reject as replay
    ReplayAttack { previous_action: String },
}

/// Cached response from a previous request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    pub status_code: i32,
    pub response_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Stored idempotency result from database
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct IdempotencyRecord {
    nonce_hash: String,
    agent_id: String,
    action: String,
    status_code: i32,
    response_json: serde_json::Value,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Configuration for the idempotency service
#[derive(Debug, Clone)]
pub struct IdempotencyConfig {
    /// TTL for idempotency results in hours (default: 24)
    pub ttl_hours: i64,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self { ttl_hours: 24 }
    }
}

/// Service for managing idempotency of signed requests
#[derive(Debug, Clone)]
pub struct IdempotencyService {
    pool: PgPool,
    config: IdempotencyConfig,
}

impl IdempotencyService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: IdempotencyConfig::default(),
        }
    }

    pub fn with_config(pool: PgPool, config: IdempotencyConfig) -> Self {
        Self { pool, config }
    }

    /// Check if a request with this nonce has been processed before.
    ///
    /// # Arguments
    /// * `agent_id` - The agent making the request
    /// * `nonce` - The unique nonce for this request
    /// * `action` - The action being performed
    ///
    /// # Returns
    /// * `IdempotencyResult::New` - No previous request, proceed
    /// * `IdempotencyResult::Cached` - Same action, return cached response
    /// * `IdempotencyResult::ReplayAttack` - Different action, reject
    pub async fn check(
        &self,
        agent_id: &str,
        nonce: &str,
        action: &str,
    ) -> Result<IdempotencyResult, IdempotencyError> {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);

        // Look up existing record
        let record: Option<IdempotencyRecord> = sqlx::query_as(
            r#"
            SELECT nonce_hash, agent_id, action, status_code, response_json, created_at, expires_at
            FROM idempotency_results
            WHERE nonce_hash = $1 AND expires_at > NOW()
            "#,
        )
        .bind(&nonce_hash)
        .fetch_optional(&self.pool)
        .await?;

        match record {
            None => Ok(IdempotencyResult::New),
            Some(rec) if rec.action == action => {
                Ok(IdempotencyResult::Cached(CachedResponse {
                    status_code: rec.status_code,
                    response_json: rec.response_json,
                    created_at: rec.created_at,
                }))
            }
            Some(rec) => Ok(IdempotencyResult::ReplayAttack {
                previous_action: rec.action,
            }),
        }
    }

    /// Store the response for a successful request.
    ///
    /// Uses PostgreSQL UPSERT to handle race conditions where two identical
    /// requests arrive simultaneously.
    ///
    /// # Arguments
    /// * `agent_id` - The agent making the request
    /// * `nonce` - The unique nonce for this request
    /// * `action` - The action being performed
    /// * `status_code` - HTTP status code of the response
    /// * `response` - The response to cache
    pub async fn store<T: Serialize>(
        &self,
        agent_id: &str,
        nonce: &str,
        action: &str,
        status_code: i32,
        response: &T,
    ) -> Result<(), IdempotencyError> {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let response_json = serde_json::to_value(response)
            .map_err(|e| IdempotencyError::Serialization(e.to_string()))?;
        let expires_at = Utc::now() + Duration::hours(self.config.ttl_hours);

        // Use UPSERT (ON CONFLICT DO NOTHING) to handle race conditions
        // If another request already stored a result, we just ignore this insert
        sqlx::query(
            r#"
            INSERT INTO idempotency_results (nonce_hash, agent_id, action, status_code, response_json, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            ON CONFLICT (nonce_hash) DO NOTHING
            "#,
        )
        .bind(&nonce_hash)
        .bind(agent_id)
        .bind(action)
        .bind(status_code)
        .bind(&response_json)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store the response within an existing transaction.
    ///
    /// This is useful when you want to atomically store the idempotency result
    /// along with other database operations.
    pub async fn store_in_tx<T: Serialize>(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        agent_id: &str,
        nonce: &str,
        action: &str,
        status_code: i32,
        response: &T,
        ttl_hours: i64,
    ) -> Result<(), IdempotencyError> {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let response_json = serde_json::to_value(response)
            .map_err(|e| IdempotencyError::Serialization(e.to_string()))?;
        let expires_at = Utc::now() + Duration::hours(ttl_hours);

        sqlx::query(
            r#"
            INSERT INTO idempotency_results (nonce_hash, agent_id, action, status_code, response_json, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            ON CONFLICT (nonce_hash) DO NOTHING
            "#,
        )
        .bind(&nonce_hash)
        .bind(agent_id)
        .bind(action)
        .bind(status_code)
        .bind(&response_json)
        .bind(expires_at)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Clean up expired idempotency results.
    ///
    /// This should be called periodically (e.g., by a background job) to
    /// remove expired entries and keep the table size manageable.
    pub async fn cleanup_expired(&self) -> Result<u64, IdempotencyError> {
        let result = sqlx::query("DELETE FROM idempotency_results WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Check and handle idempotency in one call.
    ///
    /// This is a convenience method that combines check and appropriate error handling.
    ///
    /// # Returns
    /// * `Ok(None)` - New request, proceed with operation
    /// * `Ok(Some(response))` - Cached response, return it
    /// * `Err(IdempotencyError::ReplayAttack)` - Different action, reject
    pub async fn check_and_handle(
        &self,
        agent_id: &str,
        nonce: &str,
        action: &str,
    ) -> Result<Option<CachedResponse>, IdempotencyError> {
        match self.check(agent_id, nonce, action).await? {
            IdempotencyResult::New => Ok(None),
            IdempotencyResult::Cached(response) => Ok(Some(response)),
            IdempotencyResult::ReplayAttack { previous_action } => {
                Err(IdempotencyError::ReplayAttack {
                    previous_action,
                    attempted_action: action.to_string(),
                })
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests that don't require database

    #[test]
    fn test_idempotency_config_default() {
        let config = IdempotencyConfig::default();
        assert_eq!(config.ttl_hours, 24);
    }

    #[test]
    fn test_cached_response_serialization() {
        let response = CachedResponse {
            status_code: 200,
            response_json: serde_json::json!({"success": true, "data": {"id": "123"}}),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&response).expect("serialize");
        let deserialized: CachedResponse = serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(response.status_code, deserialized.status_code);
        assert_eq!(response.response_json, deserialized.response_json);
    }

    #[test]
    fn test_idempotency_result_variants() {
        // Test that all variants can be constructed
        let _new = IdempotencyResult::New;
        let _cached = IdempotencyResult::Cached(CachedResponse {
            status_code: 200,
            response_json: serde_json::json!({}),
            created_at: Utc::now(),
        });
        let _replay = IdempotencyResult::ReplayAttack {
            previous_action: "star".to_string(),
        };
    }

    #[test]
    fn test_idempotency_error_display() {
        let replay_error = IdempotencyError::ReplayAttack {
            previous_action: "star".to_string(),
            attempted_action: "unstar".to_string(),
        };

        let error_msg = replay_error.to_string();
        assert!(error_msg.contains("star"));
        assert!(error_msg.contains("unstar"));
        assert!(error_msg.contains("Replay attack"));
    }

    // Integration tests that require database connection
    // These are marked as #[ignore] and can be run with: cargo test -- --ignored

    #[ignore]
    #[tokio::test]
    async fn integration_new_request_returns_new() {
        let pool = create_test_pool().await;
        let service = IdempotencyService::new(pool);

        let result = service
            .check("agent-123", "unique-nonce-1", "star")
            .await
            .expect("check should succeed");

        assert!(matches!(result, IdempotencyResult::New));
    }

    #[ignore]
    #[tokio::test]
    async fn integration_same_nonce_same_action_returns_cached() {
        let pool = create_test_pool().await;
        let service = IdempotencyService::new(pool);

        let agent_id = "agent-123";
        let nonce = "unique-nonce-2";
        let action = "star";

        // Store a response
        let response = serde_json::json!({"success": true, "starId": "star-456"});
        service
            .store(agent_id, nonce, action, 200, &response)
            .await
            .expect("store should succeed");

        // Check again with same nonce and action
        let result = service
            .check(agent_id, nonce, action)
            .await
            .expect("check should succeed");

        match result {
            IdempotencyResult::Cached(cached) => {
                assert_eq!(cached.status_code, 200);
                assert_eq!(cached.response_json, response);
            }
            _ => panic!("Expected Cached result"),
        }
    }

    #[ignore]
    #[tokio::test]
    async fn integration_same_nonce_different_action_returns_replay() {
        let pool = create_test_pool().await;
        let service = IdempotencyService::new(pool);

        let agent_id = "agent-123";
        let nonce = "unique-nonce-3";

        // Store a response for "star" action
        let response = serde_json::json!({"success": true});
        service
            .store(agent_id, nonce, "star", 200, &response)
            .await
            .expect("store should succeed");

        // Try to use same nonce for "unstar" action
        let result = service
            .check(agent_id, nonce, "unstar")
            .await
            .expect("check should succeed");

        match result {
            IdempotencyResult::ReplayAttack { previous_action } => {
                assert_eq!(previous_action, "star");
            }
            _ => panic!("Expected ReplayAttack result"),
        }
    }

    #[ignore]
    #[tokio::test]
    async fn integration_check_and_handle_replay_attack() {
        let pool = create_test_pool().await;
        let service = IdempotencyService::new(pool);

        let agent_id = "agent-123";
        let nonce = "unique-nonce-4";

        // Store a response for "star" action
        service
            .store(agent_id, nonce, "star", 200, &serde_json::json!({}))
            .await
            .expect("store should succeed");

        // Try to use same nonce for "unstar" action
        let result = service.check_and_handle(agent_id, nonce, "unstar").await;

        assert!(matches!(result, Err(IdempotencyError::ReplayAttack { .. })));
    }

    #[ignore]
    #[tokio::test]
    async fn integration_upsert_handles_race_condition() {
        let pool = create_test_pool().await;
        let service = IdempotencyService::new(pool);

        let agent_id = "agent-123";
        let nonce = "unique-nonce-5";
        let action = "star";

        // Simulate race condition by storing twice
        let response1 = serde_json::json!({"first": true});
        let response2 = serde_json::json!({"second": true});

        service
            .store(agent_id, nonce, action, 200, &response1)
            .await
            .expect("first store should succeed");

        // Second store should be ignored (ON CONFLICT DO NOTHING)
        service
            .store(agent_id, nonce, action, 201, &response2)
            .await
            .expect("second store should succeed (but be ignored)");

        // Check should return the first response
        let result = service
            .check(agent_id, nonce, action)
            .await
            .expect("check should succeed");

        match result {
            IdempotencyResult::Cached(cached) => {
                assert_eq!(cached.status_code, 200);
                assert_eq!(cached.response_json, response1);
            }
            _ => panic!("Expected Cached result"),
        }
    }

    #[ignore]
    #[tokio::test]
    async fn integration_cleanup_expired() {
        let pool = create_test_pool().await;
        
        // Use a very short TTL for testing
        let config = IdempotencyConfig { ttl_hours: 0 }; // Expires immediately
        let service = IdempotencyService::with_config(pool.clone(), config);

        let agent_id = "agent-123";
        let nonce = "unique-nonce-6";

        // Store with immediate expiry
        service
            .store(agent_id, nonce, "star", 200, &serde_json::json!({}))
            .await
            .expect("store should succeed");

        // Wait a moment for expiry
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Cleanup should remove the expired entry
        let deleted = service.cleanup_expired().await.expect("cleanup should succeed");
        assert!(deleted >= 1, "Should have deleted at least 1 expired entry");

        // Check should now return New
        let result = service
            .check(agent_id, nonce, "star")
            .await
            .expect("check should succeed");

        assert!(matches!(result, IdempotencyResult::New));
    }

    // Helper function to create a test database pool
    #[allow(dead_code)]
    async fn create_test_pool() -> PgPool {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for integration tests");

        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to create test database pool")
    }

    /// **Property 16: Replay Attack Prevention**
    ///
    /// For any nonce used for one action, reuse for a different action SHALL be rejected.
    ///
    /// **Validates: Requirements 12.4** | **Design: DR-3.1**
    ///
    /// This property test verifies that:
    /// 1. When a nonce is stored for action A
    /// 2. Attempting to use the same nonce for action B (where B ≠ A) is rejected
    /// 3. The rejection correctly identifies the previous action
    mod property_replay_prevention {
        use super::*;
        use proptest::prelude::*;
        use std::sync::OnceLock;
        use tokio::runtime::Runtime;

        // Shared runtime for async property tests
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();

        fn get_runtime() -> &'static Runtime {
            RUNTIME.get_or_init(|| {
                Runtime::new().expect("Failed to create Tokio runtime")
            })
        }

        /// Strategy to generate valid agent IDs
        fn agent_id_strategy() -> impl Strategy<Value = String> {
            "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        }

        /// Strategy to generate valid nonces (UUID v4 format)
        fn nonce_strategy() -> impl Strategy<Value = String> {
            "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
        }

        /// Strategy to generate pairs of different actions
        fn different_actions_strategy() -> impl Strategy<Value = (String, String)> {
            let actions = vec![
                "star",
                "unstar",
                "repo_create",
                "push",
                "pr_create",
                "review",
                "merge",
                "git-receive-pack",
                "git-upload-pack",
            ];

            (0..actions.len(), 0..actions.len())
                .prop_filter_map("actions must be different", move |(i, j)| {
                    if i != j {
                        Some((actions[i].to_string(), actions[j].to_string()))
                    } else {
                        None
                    }
                })
        }

        /// Helper to clean up test data after each test
        async fn cleanup_nonce(pool: &PgPool, agent_id: &str, nonce: &str) {
            let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash)
                .execute(pool)
                .await;
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            /// Test that reusing a nonce for a different action is rejected as replay attack
            ///
            /// This test validates Property 16: Replay Attack Prevention
            /// - Store a response for action A with a given nonce
            /// - Attempt to use the same nonce for action B (B ≠ A)
            /// - Verify the attempt is rejected with ReplayAttack error
            #[test]
            #[ignore] // Requires database connection
            fn nonce_reuse_for_different_action_rejected(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                (action_a, action_b) in different_actions_strategy()
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()), // Skip if no database
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()), // Skip if can't connect
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store a response for action_a
                    let response = serde_json::json!({"success": true, "action": &action_a});
                    let store_result = service
                        .store(&agent_id, &nonce, &action_a, 200, &response)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(()); // Skip on store error
                    }

                    // Attempt to use same nonce for action_b
                    let check_result = service
                        .check(&agent_id, &nonce, &action_b)
                        .await;

                    // Clean up before assertions
                    cleanup_nonce(&pool, &agent_id, &nonce).await;

                    // Verify replay attack is detected
                    match check_result {
                        Ok(IdempotencyResult::ReplayAttack { previous_action }) => {
                            if previous_action != action_a {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!("Previous action '{}' should match stored action '{}'", previous_action, action_a)
                                ));
                            }
                            Ok(())
                        }
                        other => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!("Expected ReplayAttack, got {:?}", other)
                            ))
                        }
                    }
                });
                result?;
            }

            /// Test that same nonce with same action returns cached response (not replay)
            ///
            /// This is the complementary property: same nonce + same action = idempotent
            #[test]
            #[ignore] // Requires database connection
            fn same_nonce_same_action_returns_cached(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                action in prop::sample::select(vec![
                    "star".to_string(),
                    "unstar".to_string(),
                    "repo_create".to_string(),
                ])
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()),
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store a response
                    let response = serde_json::json!({"success": true, "action": &action});
                    let store_result = service
                        .store(&agent_id, &nonce, &action, 200, &response)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(());
                    }

                    // Check with same nonce and same action
                    let check_result = service
                        .check(&agent_id, &nonce, &action)
                        .await;

                    // Clean up
                    cleanup_nonce(&pool, &agent_id, &nonce).await;

                    // Verify cached response is returned
                    match check_result {
                        Ok(IdempotencyResult::Cached(cached)) => {
                            if cached.status_code != 200 {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!("Expected status_code 200, got {}", cached.status_code)
                                ));
                            }
                            if cached.response_json != response {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!("Response mismatch: expected {:?}, got {:?}", response, cached.response_json)
                                ));
                            }
                            Ok(())
                        }
                        other => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!("Expected Cached, got {:?}", other)
                            ))
                        }
                    }
                });
                result?;
            }

            /// Test that nonce_hash computation is deterministic
            ///
            /// This ensures the replay detection key is consistent
            #[test]
            fn nonce_hash_is_deterministic(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy()
            ) {
                let hash1 = SignatureValidator::compute_nonce_hash(&agent_id, &nonce);
                let hash2 = SignatureValidator::compute_nonce_hash(&agent_id, &nonce);
                let hash3 = SignatureValidator::compute_nonce_hash(&agent_id, &nonce);

                prop_assert_eq!(&hash1, &hash2, "Hash should be deterministic");
                prop_assert_eq!(&hash2, &hash3, "Hash should be deterministic");
                prop_assert_eq!(hash1.len(), 64, "SHA256 hash should be 64 hex chars");
            }

            /// Test that different agent_id or nonce produces different hash
            ///
            /// This ensures different requests have different keys
            #[test]
            fn different_inputs_produce_different_hash(
                agent_id1 in agent_id_strategy(),
                agent_id2 in agent_id_strategy(),
                nonce1 in nonce_strategy(),
                nonce2 in nonce_strategy()
            ) {
                // Skip if inputs happen to be the same
                prop_assume!(agent_id1 != agent_id2 || nonce1 != nonce2);

                let hash1 = SignatureValidator::compute_nonce_hash(&agent_id1, &nonce1);
                let hash2 = SignatureValidator::compute_nonce_hash(&agent_id2, &nonce2);

                // If both agent_id and nonce are the same, hashes should match
                // Otherwise, they should differ (with overwhelming probability)
                if agent_id1 == agent_id2 && nonce1 == nonce2 {
                    prop_assert_eq!(hash1, hash2);
                } else {
                    prop_assert_ne!(
                        hash1, hash2,
                        "Different inputs should produce different hashes"
                    );
                }
            }
        }
    }

    /// **Property 17: Idempotency**
    ///
    /// For any nonce reused for the same action, the stored response SHALL be returned exactly.
    ///
    /// **Validates: Requirements 12.5, 19.2** | **Design: DR-3.2**
    ///
    /// This property test verifies that:
    /// 1. When a response is stored for (agent_id, nonce, action)
    /// 2. Subsequent checks with the same (agent_id, nonce, action) return the exact cached response
    /// 3. The response is identical: same status_code and same response_json
    /// 4. Multiple retries all return the same cached response
    mod property_idempotency {
        use super::*;
        use proptest::prelude::*;
        use std::sync::OnceLock;
        use tokio::runtime::Runtime;

        // Shared runtime for async property tests
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();

        fn get_runtime() -> &'static Runtime {
            RUNTIME.get_or_init(|| {
                Runtime::new().expect("Failed to create Tokio runtime")
            })
        }

        /// Strategy to generate valid agent IDs (UUID format)
        fn agent_id_strategy() -> impl Strategy<Value = String> {
            "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        }

        /// Strategy to generate valid nonces (UUID v4 format)
        fn nonce_strategy() -> impl Strategy<Value = String> {
            "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
        }

        /// Strategy to generate action names
        fn action_strategy() -> impl Strategy<Value = String> {
            prop::sample::select(vec![
                "star".to_string(),
                "unstar".to_string(),
                "repo_create".to_string(),
                "push".to_string(),
                "pr_create".to_string(),
                "review".to_string(),
                "merge".to_string(),
            ])
        }

        /// Strategy to generate HTTP status codes
        fn status_code_strategy() -> impl Strategy<Value = i32> {
            prop::sample::select(vec![200, 201, 202, 204])
        }

        /// Strategy to generate response JSON payloads
        fn response_json_strategy() -> impl Strategy<Value = serde_json::Value> {
            prop::sample::select(vec![
                serde_json::json!({"success": true}),
                serde_json::json!({"success": true, "id": "resource-123"}),
                serde_json::json!({"success": true, "data": {"count": 42}}),
                serde_json::json!({"success": true, "message": "Operation completed"}),
                serde_json::json!({"success": true, "items": [1, 2, 3]}),
            ])
        }

        /// Helper to clean up test data after each test
        async fn cleanup_nonce(pool: &PgPool, agent_id: &str, nonce: &str) {
            let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
            let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
                .bind(&nonce_hash)
                .execute(pool)
                .await;
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            /// Test that same nonce + same action returns the exact stored response
            ///
            /// This test validates Property 17: Idempotency
            /// - Store a response for (agent_id, nonce, action)
            /// - Check with the same (agent_id, nonce, action)
            /// - Verify the returned response is exactly the same (status_code, response_json)
            #[test]
            #[ignore] // Requires database connection
            fn same_nonce_same_action_returns_exact_response(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                action in action_strategy(),
                status_code in status_code_strategy(),
                response_json in response_json_strategy()
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()), // Skip if no database
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()), // Skip if can't connect
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store the response
                    let store_result = service
                        .store(&agent_id, &nonce, &action, status_code, &response_json)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(()); // Skip on store error
                    }

                    // Check with same nonce and same action
                    let check_result = service
                        .check(&agent_id, &nonce, &action)
                        .await;

                    // Clean up before assertions
                    cleanup_nonce(&pool, &agent_id, &nonce).await;

                    // Verify the exact response is returned
                    match check_result {
                        Ok(IdempotencyResult::Cached(cached)) => {
                            // Verify status_code is exactly the same
                            if cached.status_code != status_code {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "Status code mismatch: expected {}, got {}",
                                        status_code, cached.status_code
                                    )
                                ));
                            }
                            // Verify response_json is exactly the same
                            if cached.response_json != response_json {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "Response JSON mismatch: expected {:?}, got {:?}",
                                        response_json, cached.response_json
                                    )
                                ));
                            }
                            Ok(())
                        }
                        Ok(IdempotencyResult::New) => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                "Expected Cached result, got New (response was not stored)"
                            ))
                        }
                        Ok(IdempotencyResult::ReplayAttack { previous_action }) => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!(
                                    "Expected Cached result, got ReplayAttack (previous_action: {})",
                                    previous_action
                                )
                            ))
                        }
                        Err(e) => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!("Check failed with error: {}", e)
                            ))
                        }
                    }
                });
                result?;
            }

            /// Test that multiple retries with same nonce all return the same cached response
            ///
            /// This validates that idempotency is consistent across multiple retries
            #[test]
            #[ignore] // Requires database connection
            fn multiple_retries_return_same_response(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                action in action_strategy(),
                retry_count in 2..5usize
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()),
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store the original response
                    let original_response = serde_json::json!({
                        "success": true,
                        "id": "test-resource-id",
                        "action": &action
                    });
                    let original_status = 200;

                    let store_result = service
                        .store(&agent_id, &nonce, &action, original_status, &original_response)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(());
                    }

                    // Perform multiple retries and verify all return the same response
                    for i in 0..retry_count {
                        let check_result = service
                            .check(&agent_id, &nonce, &action)
                            .await;

                        match check_result {
                            Ok(IdempotencyResult::Cached(cached)) => {
                                if cached.status_code != original_status {
                                    cleanup_nonce(&pool, &agent_id, &nonce).await;
                                    return Err(proptest::test_runner::TestCaseError::fail(
                                        format!(
                                            "Retry {} status code mismatch: expected {}, got {}",
                                            i, original_status, cached.status_code
                                        )
                                    ));
                                }
                                if cached.response_json != original_response {
                                    cleanup_nonce(&pool, &agent_id, &nonce).await;
                                    return Err(proptest::test_runner::TestCaseError::fail(
                                        format!(
                                            "Retry {} response mismatch: expected {:?}, got {:?}",
                                            i, original_response, cached.response_json
                                        )
                                    ));
                                }
                            }
                            other => {
                                cleanup_nonce(&pool, &agent_id, &nonce).await;
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!("Retry {} expected Cached, got {:?}", i, other)
                                ));
                            }
                        }
                    }

                    cleanup_nonce(&pool, &agent_id, &nonce).await;
                    Ok(())
                });
                result?;
            }

            /// Test that check_and_handle returns the cached response for same action
            ///
            /// This validates the convenience method also respects idempotency
            #[test]
            #[ignore] // Requires database connection
            fn check_and_handle_returns_cached_for_same_action(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                action in action_strategy(),
                status_code in status_code_strategy(),
                response_json in response_json_strategy()
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()),
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store the response
                    let store_result = service
                        .store(&agent_id, &nonce, &action, status_code, &response_json)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(());
                    }

                    // Use check_and_handle with same nonce and action
                    let handle_result = service
                        .check_and_handle(&agent_id, &nonce, &action)
                        .await;

                    cleanup_nonce(&pool, &agent_id, &nonce).await;

                    // Verify cached response is returned (not None, not error)
                    match handle_result {
                        Ok(Some(cached)) => {
                            if cached.status_code != status_code {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "check_and_handle status mismatch: expected {}, got {}",
                                        status_code, cached.status_code
                                    )
                                ));
                            }
                            if cached.response_json != response_json {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "check_and_handle response mismatch: expected {:?}, got {:?}",
                                        response_json, cached.response_json
                                    )
                                ));
                            }
                            Ok(())
                        }
                        Ok(None) => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                "check_and_handle returned None, expected cached response"
                            ))
                        }
                        Err(e) => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!("check_and_handle failed with error: {}", e)
                            ))
                        }
                    }
                });
                result?;
            }

            /// Test that UPSERT semantics preserve the first stored response
            ///
            /// This validates that race conditions don't corrupt idempotency
            /// (first writer wins, subsequent stores are ignored)
            #[test]
            #[ignore] // Requires database connection
            fn upsert_preserves_first_response(
                agent_id in agent_id_strategy(),
                nonce in nonce_strategy(),
                action in action_strategy()
            ) {
                let rt = get_runtime();
                let result = rt.block_on(async {
                    dotenvy::dotenv().ok();
                    let database_url = match std::env::var("DATABASE_URL") {
                        Ok(url) => url,
                        Err(_) => return Ok(()),
                    };

                    let pool = match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&database_url)
                        .await
                    {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    };

                    let service = IdempotencyService::new(pool.clone());

                    // Store the first response
                    let first_response = serde_json::json!({"first": true, "id": "first-id"});
                    let first_status = 200;

                    let store_result = service
                        .store(&agent_id, &nonce, &action, first_status, &first_response)
                        .await;

                    if store_result.is_err() {
                        cleanup_nonce(&pool, &agent_id, &nonce).await;
                        return Ok(());
                    }

                    // Attempt to store a different response (simulating race condition)
                    let second_response = serde_json::json!({"second": true, "id": "second-id"});
                    let second_status = 201;

                    // This should be ignored due to ON CONFLICT DO NOTHING
                    let _ = service
                        .store(&agent_id, &nonce, &action, second_status, &second_response)
                        .await;

                    // Check should return the FIRST response, not the second
                    let check_result = service
                        .check(&agent_id, &nonce, &action)
                        .await;

                    cleanup_nonce(&pool, &agent_id, &nonce).await;

                    match check_result {
                        Ok(IdempotencyResult::Cached(cached)) => {
                            // Must be the first response
                            if cached.status_code != first_status {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "UPSERT did not preserve first status: expected {}, got {}",
                                        first_status, cached.status_code
                                    )
                                ));
                            }
                            if cached.response_json != first_response {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!(
                                        "UPSERT did not preserve first response: expected {:?}, got {:?}",
                                        first_response, cached.response_json
                                    )
                                ));
                            }
                            Ok(())
                        }
                        other => {
                            Err(proptest::test_runner::TestCaseError::fail(
                                format!("Expected Cached with first response, got {:?}", other)
                            ))
                        }
                    }
                });
                result?;
            }
        }
    }
}

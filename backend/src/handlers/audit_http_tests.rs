//! HTTP Integration Tests for Audit Service
//!
//! These tests validate the Audit Service end-to-end via HTTP endpoints
//! and direct database operations.
//!
//! Requirements: 11.1, 11.2, 11.3, 11.4, 11.7
//! Design: DR-14.1 (Audit Service)

#[cfg(test)]
mod http_integration_tests {
    use actix_web::{App, test, web};
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    use crate::AppState;
    use crate::config::Config;
    use crate::handlers::configure_audit_routes;
    use crate::services::RateLimiterService;
    use crate::services::audit::{AuditAction, AuditEvent, AuditService, ResourceType};
    use crate::services::outbox::{OutboxConfig, OutboxService, OutboxStatus, OutboxTopic};

    /// Helper to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<PgPool> {
        let _ = dotenvy::from_filename("backend/.env");
        let _ = dotenvy::dotenv();

        let database_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };

        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()
    }

    /// Create test config
    fn create_test_config() -> Config {
        Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            database_max_connections: 5,
            host: "127.0.0.1".to_string(),
            port: 8080,
            signature_expiry_secs: 300,
            idempotency_ttl_hours: 24,
        }
    }

    /// Create test app state
    fn create_test_app_state(pool: PgPool) -> web::Data<AppState> {
        web::Data::new(AppState {
            db: pool,
            config: create_test_config(),
            rate_limiter: RateLimiterService::default(),
        })
    }

    /// Create a test agent in the database
    async fn create_test_agent(pool: &PgPool) -> String {
        let agent_id = Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, 'test-public-key', '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .execute(pool)
        .await
        .expect("Failed to create test agent");

        agent_id
    }

    /// Clean up test agent
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: Audit event created for each action type
    // Requirements: 11.1, 11.2
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn audit_event_created_for_each_action_type() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Test all action types
        let action_types = vec![
            (
                AuditAction::AgentRegister,
                ResourceType::Agent,
                "agent-test-1",
            ),
            (
                AuditAction::RepoCreate,
                ResourceType::Repository,
                "repo-test-1",
            ),
            (
                AuditAction::RepoClone,
                ResourceType::Repository,
                "repo-test-2",
            ),
            (AuditAction::Push, ResourceType::Repository, "repo-test-3"),
            (AuditAction::PrOpen, ResourceType::PullRequest, "pr-test-1"),
            (AuditAction::PrReview, ResourceType::Review, "review-test-1"),
            (AuditAction::PrMerge, ResourceType::PullRequest, "pr-test-2"),
            (AuditAction::Star, ResourceType::Star, "star-test-1"),
        ];

        for (action, resource_type, resource_id) in &action_types {
            let event = AuditEvent::new(
                &agent_id,
                *action,
                *resource_type,
                *resource_id,
                serde_json::json!({"test": true}),
                "test-signature",
            );

            let result = audit_service.append(event).await;
            assert!(
                result.is_ok(),
                "Failed to create audit event for {:?}",
                action
            );

            let recorded = result.unwrap();
            assert_eq!(recorded.agent_id, agent_id);
            assert_eq!(recorded.action, action.as_str());
            assert_eq!(recorded.resource_type, resource_type.as_str());
            assert_eq!(recorded.resource_id, *resource_id);
        }

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: audit_log is append-only (UPDATE/DELETE rejected at DB level)
    // Requirements: 11.4
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn audit_log_is_append_only() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Create an audit event
        let event = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("immutability-test-{}", Uuid::new_v4()),
            serde_json::json!({"test": "immutability"}),
            "test-signature",
        );

        let recorded = audit_service
            .append(event)
            .await
            .expect("Failed to create audit event");

        // Attempt to UPDATE - should fail due to trigger
        let update_result =
            sqlx::query("UPDATE audit_log SET action = 'modified' WHERE event_id = $1")
                .bind(recorded.event_id)
                .execute(&pool)
                .await;

        assert!(
            update_result.is_err(),
            "UPDATE should be rejected by trigger"
        );
        let err_msg = update_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("append-only") || err_msg.contains("UPDATE"),
            "Error should mention append-only constraint: {}",
            err_msg
        );

        // Attempt to DELETE - should fail due to trigger
        let delete_result = sqlx::query("DELETE FROM audit_log WHERE event_id = $1")
            .bind(recorded.event_id)
            .execute(&pool)
            .await;

        assert!(
            delete_result.is_err(),
            "DELETE should be rejected by trigger"
        );
        let err_msg = delete_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("append-only") || err_msg.contains("DELETE"),
            "Error should mention append-only constraint: {}",
            err_msg
        );

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Query by agent_id returns correct events
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn query_by_agent_id_returns_correct_events() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent1_id = create_test_agent(&pool).await;
        let agent2_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Create events for agent1
        for i in 0..3 {
            let event = AuditEvent::new(
                &agent1_id,
                AuditAction::Star,
                ResourceType::Star,
                &format!("agent1-resource-{}-{}", Uuid::new_v4(), i),
                serde_json::json!({"agent": 1, "index": i}),
                "sig1",
            );
            audit_service
                .append(event)
                .await
                .expect("Failed to create event");
        }

        // Create events for agent2
        for i in 0..2 {
            let event = AuditEvent::new(
                &agent2_id,
                AuditAction::RepoCreate,
                ResourceType::Repository,
                &format!("agent2-resource-{}-{}", Uuid::new_v4(), i),
                serde_json::json!({"agent": 2, "index": i}),
                "sig2",
            );
            audit_service
                .append(event)
                .await
                .expect("Failed to create event");
        }

        // Query for agent1's events
        let agent1_events = audit_service
            .get_for_agent(&agent1_id, Some(100))
            .await
            .expect("Query should succeed");

        assert!(
            agent1_events.len() >= 3,
            "Agent1 should have at least 3 events"
        );
        for event in &agent1_events {
            assert_eq!(
                event.agent_id, agent1_id,
                "All events should belong to agent1"
            );
        }

        // Query for agent2's events
        let agent2_events = audit_service
            .get_for_agent(&agent2_id, Some(100))
            .await
            .expect("Query should succeed");

        assert!(
            agent2_events.len() >= 2,
            "Agent2 should have at least 2 events"
        );
        for event in &agent2_events {
            assert_eq!(
                event.agent_id, agent2_id,
                "All events should belong to agent2"
            );
        }

        cleanup_test_agent(&pool, &agent1_id).await;
        cleanup_test_agent(&pool, &agent2_id).await;
    }

    // =========================================================================
    // Test: Query by repo_id (resource_id) returns correct events
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn query_by_resource_id_returns_correct_events() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        let repo_id = format!("test-repo-{}", Uuid::new_v4());

        // Create multiple events for the same repo
        let actions = vec![
            AuditAction::RepoCreate,
            AuditAction::Push,
            AuditAction::RepoClone,
        ];

        for action in &actions {
            let event = AuditEvent::new(
                &agent_id,
                *action,
                ResourceType::Repository,
                &repo_id,
                serde_json::json!({"action": action.as_str()}),
                "test-sig",
            );
            audit_service
                .append(event)
                .await
                .expect("Failed to create event");
        }

        // Query for repo's events
        let repo_events = audit_service
            .get_for_resource(ResourceType::Repository, &repo_id)
            .await
            .expect("Query should succeed");

        assert_eq!(repo_events.len(), 3, "Repo should have exactly 3 events");
        for event in &repo_events {
            assert_eq!(
                event.resource_id, repo_id,
                "All events should be for the repo"
            );
        }

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Query by action type returns correct events
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn query_by_action_type_returns_correct_events() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Create events with different action types
        let event1 = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("action-test-star-{}", Uuid::new_v4()),
            serde_json::json!({}),
            "sig",
        );
        audit_service
            .append(event1)
            .await
            .expect("Failed to create event");

        let event2 = AuditEvent::new(
            &agent_id,
            AuditAction::Unstar,
            ResourceType::Star,
            &format!("action-test-unstar-{}", Uuid::new_v4()),
            serde_json::json!({}),
            "sig",
        );
        audit_service
            .append(event2)
            .await
            .expect("Failed to create event");

        // Query using the query builder
        use crate::services::audit::AuditQuery;

        let star_query = AuditQuery::new().agent(&agent_id).action(AuditAction::Star);

        let star_events = audit_service
            .query(star_query)
            .await
            .expect("Query should succeed");

        for event in &star_events.events {
            assert_eq!(event.action, "star", "All events should be star actions");
        }

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Query by time range returns correct events
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn query_by_time_range_returns_correct_events() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        let before_creation = Utc::now();

        // Create some events
        for i in 0..3 {
            let event = AuditEvent::new(
                &agent_id,
                AuditAction::Star,
                ResourceType::Star,
                &format!("time-range-test-{}-{}", Uuid::new_v4(), i),
                serde_json::json!({"index": i}),
                "sig",
            );
            audit_service
                .append(event)
                .await
                .expect("Failed to create event");
        }

        let after_creation = Utc::now();

        // Query with time range that includes the events
        use crate::services::audit::AuditQuery;

        let query = AuditQuery::new()
            .agent(&agent_id)
            .from(before_creation)
            .to(after_creation);

        let result = audit_service
            .query(query)
            .await
            .expect("Query should succeed");

        assert!(
            result.events.len() >= 3,
            "Should find at least 3 events in time range"
        );
        for event in &result.events {
            assert!(
                event.timestamp >= before_creation,
                "Event should be after start time"
            );
            assert!(
                event.timestamp <= after_creation,
                "Event should be before end time"
            );
        }

        // Query with time range before events were created
        let old_query = AuditQuery::new()
            .agent(&agent_id)
            .from(before_creation - Duration::hours(2))
            .to(before_creation - Duration::hours(1));

        let old_result = audit_service
            .query(old_query)
            .await
            .expect("Query should succeed");

        // Should not find the events we just created
        let our_events: Vec<_> = old_result
            .events
            .iter()
            .filter(|e| e.agent_id == agent_id && e.timestamp >= before_creation)
            .collect();
        assert!(
            our_events.is_empty(),
            "Should not find events outside time range"
        );

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: event_outbox entries created for async projections
    // Requirements: 11.7
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn event_outbox_entries_created_for_async_projections() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());
        let outbox_service = OutboxService::new(pool.clone());

        // Create an audit event
        let event = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("outbox-test-{}", Uuid::new_v4()),
            serde_json::json!({"test": "outbox"}),
            "test-sig",
        );

        let recorded = audit_service
            .append(event)
            .await
            .expect("Failed to create audit event");

        // Create outbox entries for different topics
        let trending_entry = outbox_service
            .insert(recorded.event_id, OutboxTopic::Trending)
            .await
            .expect("Failed to create trending outbox entry");

        assert_eq!(trending_entry.audit_event_id, recorded.event_id);
        assert_eq!(trending_entry.topic, "trending");
        assert_eq!(trending_entry.status, OutboxStatus::Pending);
        assert_eq!(trending_entry.attempts, 0);

        let reputation_entry = outbox_service
            .insert(recorded.event_id, OutboxTopic::Reputation)
            .await
            .expect("Failed to create reputation outbox entry");

        assert_eq!(reputation_entry.audit_event_id, recorded.event_id);
        assert_eq!(reputation_entry.topic, "reputation");
        assert_eq!(reputation_entry.status, OutboxStatus::Pending);

        // Verify entries exist in database
        let stats = outbox_service
            .get_stats()
            .await
            .expect("Failed to get stats");
        assert!(stats.pending >= 2, "Should have at least 2 pending entries");

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Outbox worker claims events with FOR UPDATE SKIP LOCKED
    // Requirements: 11.7
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn outbox_worker_claims_events_with_skip_locked() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());
        let outbox_service = OutboxService::new(pool.clone());

        // Create audit events and outbox entries
        let mut event_ids = Vec::new();
        for i in 0..5 {
            let event = AuditEvent::new(
                &agent_id,
                AuditAction::Star,
                ResourceType::Star,
                &format!("claim-test-{}-{}", Uuid::new_v4(), i),
                serde_json::json!({"index": i}),
                "sig",
            );
            let recorded = audit_service
                .append(event)
                .await
                .expect("Failed to create event");
            outbox_service
                .insert(recorded.event_id, OutboxTopic::Trending)
                .await
                .expect("Failed to create outbox entry");
            event_ids.push(recorded.event_id);
        }

        // Worker 1 claims events
        let worker1_events = outbox_service
            .claim_events(OutboxTopic::Trending, "worker-1")
            .await
            .expect("Worker 1 should claim events");

        // Verify claimed events are in processing state
        for event in &worker1_events {
            assert_eq!(event.status, OutboxStatus::Processing);
            assert_eq!(event.locked_by, Some("worker-1".to_string()));
            assert!(event.locked_at.is_some());
        }

        // Worker 2 tries to claim - should get different events or none
        // (since worker 1 has them locked)
        let worker2_events = outbox_service
            .claim_events(OutboxTopic::Trending, "worker-2")
            .await
            .expect("Worker 2 claim should succeed");

        // Worker 2 should not get the same events as worker 1
        let worker1_ids: std::collections::HashSet<_> =
            worker1_events.iter().map(|e| e.outbox_id).collect();

        for event in &worker2_events {
            assert!(
                !worker1_ids.contains(&event.outbox_id),
                "Worker 2 should not claim events already locked by worker 1"
            );
        }

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Retry with exponential backoff on failure
    // Requirements: 11.7
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn retry_with_exponential_backoff_on_failure() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Clean up any leftover pending events from previous test runs
        sqlx::query("DELETE FROM event_outbox WHERE topic = 'trending' AND status IN ('pending', 'processing')")
            .execute(&pool)
            .await
            .expect("Failed to clean up old events");

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Use custom config with known backoff values
        let config = OutboxConfig {
            max_attempts: 5,
            base_delay_secs: 5,
            max_delay_secs: 3600,
            lock_timeout_secs: 300,
            batch_size: 10,
        };
        let outbox_service = OutboxService::with_config(pool.clone(), config);

        // Create an audit event and outbox entry
        let event = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("backoff-test-{}", Uuid::new_v4()),
            serde_json::json!({}),
            "sig",
        );
        let recorded = audit_service
            .append(event)
            .await
            .expect("Failed to create event");
        let outbox_entry = outbox_service
            .insert(recorded.event_id, OutboxTopic::Trending)
            .await
            .expect("Failed to create outbox entry");

        // Claim the event
        let claimed = outbox_service
            .claim_events(OutboxTopic::Trending, "test-worker")
            .await
            .expect("Should claim events");
        
        // Verify the event was actually claimed
        assert!(
            claimed.iter().any(|e| e.outbox_id == outbox_entry.outbox_id),
            "Our event should be in the claimed list"
        );

        // Mark as failed - should schedule retry with backoff
        let new_status = outbox_service
            .mark_failed(outbox_entry.outbox_id, "Test failure")
            .await
            .expect("mark_failed should succeed");

        // Should still be pending (not dead yet, only 1 attempt)
        assert_eq!(
            new_status,
            OutboxStatus::Pending,
            "Should be pending for retry"
        );

        // Verify the event has the error recorded
        let row: Option<(String, i32)> =
            sqlx::query_as("SELECT last_error, attempts FROM event_outbox WHERE outbox_id = $1")
                .bind(outbox_entry.outbox_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        let (last_error, attempts) = row.expect("Event should exist");
        assert_eq!(last_error, "Test failure");
        assert_eq!(attempts, 1, "Attempts should be incremented");

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: Dead-letter after max attempts
    // Requirements: 11.7
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn dead_letter_after_max_attempts() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Use config with low max_attempts for testing
        let config = OutboxConfig {
            max_attempts: 2,
            base_delay_secs: 1,
            max_delay_secs: 10,
            lock_timeout_secs: 1,
            batch_size: 10,
        };
        let outbox_service = OutboxService::with_config(pool.clone(), config);

        // Create an audit event and outbox entry
        let event = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("dead-letter-test-{}", Uuid::new_v4()),
            serde_json::json!({}),
            "sig",
        );
        let recorded = audit_service
            .append(event)
            .await
            .expect("Failed to create event");
        let outbox_entry = outbox_service
            .insert(recorded.event_id, OutboxTopic::Trending)
            .await
            .expect("Failed to create outbox entry");

        // Simulate multiple failures by directly updating attempts
        // First, set attempts to max_attempts
        sqlx::query(
            "UPDATE event_outbox SET attempts = $1, status = 'processing' WHERE outbox_id = $2",
        )
        .bind(2i32) // max_attempts
        .bind(outbox_entry.outbox_id)
        .execute(&pool)
        .await
        .expect("Update should succeed");

        // Now mark as failed - should move to dead letter
        let new_status = outbox_service
            .mark_failed(outbox_entry.outbox_id, "Final failure")
            .await
            .expect("mark_failed should succeed");

        assert_eq!(
            new_status,
            OutboxStatus::Dead,
            "Should be dead-lettered after max attempts"
        );

        // Verify it's in the dead letters
        let dead_letters = outbox_service
            .get_dead_letters(Some(OutboxTopic::Trending), 100)
            .await
            .expect("get_dead_letters should succeed");

        let found = dead_letters
            .iter()
            .any(|e| e.outbox_id == outbox_entry.outbox_id);
        assert!(found, "Event should be in dead letters");

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: HTTP endpoint - Query audit events via GET /v1/audit
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_query_audit_events() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Create some audit events
        for i in 0..3 {
            let event = AuditEvent::new(
                &agent_id,
                AuditAction::Star,
                ResourceType::Star,
                &format!("http-query-test-{}-{}", Uuid::new_v4(), i),
                serde_json::json!({"index": i}),
                "sig",
            );
            audit_service
                .append(event)
                .await
                .expect("Failed to create event");
        }

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_audit_routes)),
        )
        .await;

        // Query by agent_id
        let req = test::TestRequest::get()
            .uri(&format!("/v1/audit?agent_id={}", agent_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "Query should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Response should be valid JSON");

        let events = response["data"]["events"]
            .as_array()
            .expect("Response should contain events array");

        assert!(events.len() >= 3, "Should return at least 3 events");

        cleanup_test_agent(&pool, &agent_id).await;
    }

    // =========================================================================
    // Test: HTTP endpoint - Get single audit event via GET /v1/audit/{eventId}
    // Requirements: 11.3
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_single_audit_event() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let audit_service = AuditService::new(pool.clone());

        // Create an audit event
        let event = AuditEvent::new(
            &agent_id,
            AuditAction::Star,
            ResourceType::Star,
            &format!("http-single-test-{}", Uuid::new_v4()),
            serde_json::json!({"test": "single"}),
            "sig",
        );
        let recorded = audit_service
            .append(event)
            .await
            .expect("Failed to create event");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_audit_routes)),
        )
        .await;

        // Get the specific event
        let req = test::TestRequest::get()
            .uri(&format!("/v1/audit/{}", recorded.event_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "Get should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Response should be valid JSON");

        assert_eq!(response["data"]["event_id"], recorded.event_id.to_string());
        assert_eq!(response["data"]["agent_id"], agent_id);
        assert_eq!(response["data"]["action"], "star");

        cleanup_test_agent(&pool, &agent_id).await;
    }
}

//! Integration Tests for Reputation Service
//!
//! These tests validate the Reputation Service end-to-end.
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
//! Design: DR-13.1 (Reputation Service)

#[cfg(test)]
mod integration_tests {
    use sqlx::PgPool;
    use uuid::Uuid;

    use crate::services::{
        AuditAction, AuditEvent, AuditService, OutboxService, OutboxTopic, ReputationChangeReason,
        ReputationService, ResourceType,
    };

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

    /// Create a test agent in the database and return agent_id
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

        // Initialize reputation with default score (0.5)
        sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, 0.500, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .execute(pool)
        .await
        .expect("Failed to initialize reputation");

        agent_id
    }

    /// Create a test agent with a specific reputation score
    async fn create_test_agent_with_score(pool: &PgPool, score: f64) -> String {
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

        sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, $2, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(score)
        .execute(pool)
        .await
        .expect("Failed to initialize reputation");

        agent_id
    }

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        // Clean up audit_log entries for this agent
        let _ = sqlx::query("DELETE FROM audit_log WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    /// Clean up outbox entries for a specific audit event
    async fn cleanup_outbox_for_event(pool: &PgPool, audit_event_id: &Uuid) {
        let _ = sqlx::query("DELETE FROM event_outbox WHERE audit_event_id = $1")
            .bind(audit_event_id)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: Reputation increases on successful merge
    // Requirements: 10.2
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn reputation_increases_on_merge_success() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let pr_id = Uuid::new_v4().to_string();

        let service = ReputationService::new(pool.clone());

        // Get initial reputation
        let initial = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");
        let initial_score = initial.score;

        // Process merge success
        service
            .process_merge_success(&agent_id, &pr_id)
            .await
            .expect("Should process merge success");

        // Verify reputation increased
        let updated = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get updated reputation");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            updated.score > initial_score,
            "Reputation should increase after merge success: {} > {}",
            updated.score,
            initial_score
        );
        // MERGE_SUCCESS_INCREASE is 0.02
        let expected_score = initial_score + 0.02;
        assert!(
            (updated.score - expected_score).abs() < 0.001,
            "Reputation should increase by 0.02: expected {}, got {}",
            expected_score,
            updated.score
        );
    }

    // =========================================================================
    // Test: Reputation decreases on merge revert
    // Requirements: 10.3
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn reputation_decreases_on_merge_revert() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let pr_id = Uuid::new_v4().to_string();

        let service = ReputationService::new(pool.clone());

        // Get initial reputation
        let initial = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");
        let initial_score = initial.score;

        // Process merge revert
        service
            .process_merge_revert(&agent_id, &pr_id)
            .await
            .expect("Should process merge revert");

        // Verify reputation decreased
        let updated = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get updated reputation");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            updated.score < initial_score,
            "Reputation should decrease after merge revert: {} < {}",
            updated.score,
            initial_score
        );
        // MERGE_REVERT_DECREASE is 0.05
        let expected_score = initial_score - 0.05;
        assert!(
            (updated.score - expected_score).abs() < 0.001,
            "Reputation should decrease by 0.05: expected {}, got {}",
            expected_score,
            updated.score
        );
    }

    // =========================================================================
    // Test: Reputation decreases on inaccurate review
    // Requirements: 10.3
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn reputation_decreases_on_inaccurate_review() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let pr_id = Uuid::new_v4().to_string();

        let service = ReputationService::new(pool.clone());

        // Get initial reputation
        let initial = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");
        let initial_score = initial.score;

        // Process inaccurate review
        service
            .process_inaccurate_review(&agent_id, &pr_id)
            .await
            .expect("Should process inaccurate review");

        // Verify reputation decreased
        let updated = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get updated reputation");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            updated.score < initial_score,
            "Reputation should decrease after inaccurate review: {} < {}",
            updated.score,
            initial_score
        );
        // INACCURATE_REVIEW_DECREASE is 0.03
        let expected_score = initial_score - 0.03;
        assert!(
            (updated.score - expected_score).abs() < 0.001,
            "Reputation should decrease by 0.03: expected {}, got {}",
            expected_score,
            updated.score
        );
    }

    // =========================================================================
    // Test: Reputation clamped to [0.0, 1.0] bounds
    // Requirements: 10.1
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn reputation_clamped_to_bounds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Test upper bound clamping
        let high_score_agent = create_test_agent_with_score(&pool, 0.99).await;
        let service = ReputationService::new(pool.clone());

        // Try to increase beyond 1.0
        service
            .update_reputation(
                &high_score_agent,
                0.1, // Would push to 1.09
                ReputationChangeReason::MergeSuccess,
                None,
            )
            .await
            .expect("Should update reputation");

        let high_result = service
            .get_reputation(&high_score_agent)
            .await
            .expect("Should get reputation");

        assert!(
            high_result.score <= 1.0,
            "Reputation should be clamped at 1.0, got {}",
            high_result.score
        );
        assert!(
            (high_result.score - 1.0).abs() < 0.001,
            "Reputation should be exactly 1.0, got {}",
            high_result.score
        );

        // Test lower bound clamping
        let low_score_agent = create_test_agent_with_score(&pool, 0.02).await;

        // Try to decrease below 0.0
        service
            .update_reputation(
                &low_score_agent,
                -0.1, // Would push to -0.08
                ReputationChangeReason::MergeReverted,
                None,
            )
            .await
            .expect("Should update reputation");

        let low_result = service
            .get_reputation(&low_score_agent)
            .await
            .expect("Should get reputation");

        // Cleanup
        cleanup_test_agent(&pool, &high_score_agent).await;
        cleanup_test_agent(&pool, &low_score_agent).await;

        assert!(
            low_result.score >= 0.0,
            "Reputation should be clamped at 0.0, got {}",
            low_result.score
        );
        assert!(
            low_result.score.abs() < 0.001,
            "Reputation should be exactly 0.0, got {}",
            low_result.score
        );
    }

    // =========================================================================
    // Test: GET /v1/agents/{agentId}/reputation returns current score
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn get_reputation_returns_current_score() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let expected_score = 0.75;
        let agent_id = create_test_agent_with_score(&pool, expected_score).await;

        let service = ReputationService::new(pool.clone());

        let result = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get reputation");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(result.agent_id, agent_id);
        assert!(
            (result.score - expected_score).abs() < 0.001,
            "Expected score {}, got {}",
            expected_score,
            result.score
        );
    }

    // =========================================================================
    // Test: GET reputation for non-existent agent returns error
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn get_reputation_nonexistent_agent_returns_error() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let fake_agent_id = Uuid::new_v4().to_string();
        let service = ReputationService::new(pool.clone());

        let result = service.get_reputation(&fake_agent_id).await;

        assert!(
            result.is_err(),
            "Should return error for non-existent agent"
        );
        match result {
            Err(crate::services::ReputationError::AgentNotFound(id)) => {
                assert_eq!(id, fake_agent_id);
            }
            _ => panic!("Expected AgentNotFound error"),
        }
    }

    // =========================================================================
    // Test: Reputation history stored in audit_log
    // Requirements: 10.5
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn reputation_history_stored_in_audit_log() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let pr_id = Uuid::new_v4().to_string();

        let service = ReputationService::new(pool.clone());
        let audit_service = AuditService::new(pool.clone());

        // Get initial reputation
        let initial = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");

        // Process merge success (this should create an audit event)
        service
            .process_merge_success(&agent_id, &pr_id)
            .await
            .expect("Should process merge success");

        // Query audit log for reputation updates
        let audit_events = audit_service
            .get_for_agent(&agent_id, Some(10))
            .await
            .expect("Should query audit log");

        // Find the reputation update event
        let reputation_event = audit_events
            .iter()
            .find(|e| e.action == "reputation_update")
            .expect("Should find reputation_update event in audit log");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        // Verify audit event contains correct data
        assert_eq!(reputation_event.agent_id, agent_id);
        assert_eq!(reputation_event.resource_type, "reputation");
        assert_eq!(reputation_event.resource_id, agent_id);

        // Verify the data contains old_score, new_score, and reason
        let data = &reputation_event.data;
        assert!(data.get("old_score").is_some(), "Should have old_score");
        assert!(data.get("new_score").is_some(), "Should have new_score");
        assert!(data.get("reason").is_some(), "Should have reason");
        assert_eq!(data["reason"], "merge_success");

        let old_score = data["old_score"].as_f64().unwrap();
        let new_score = data["new_score"].as_f64().unwrap();
        assert!(
            (old_score - initial.score).abs() < 0.001,
            "Old score should match initial"
        );
        assert!(
            new_score > old_score,
            "New score should be greater than old score"
        );
    }

    // =========================================================================
    // Test: Background job consumes events from event_outbox
    // Requirements: 10.5
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn background_job_consumes_events_from_outbox() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let pr_id = Uuid::new_v4().to_string();

        // Create an audit event for pr_merged
        let audit_service = AuditService::new(pool.clone());
        let audit_event = AuditEvent::new(
            &agent_id,
            AuditAction::PrMerge,
            ResourceType::PullRequest,
            &pr_id,
            serde_json::json!({
                "author_id": agent_id,
                "approving_reviewers": [],
            }),
            "test-signature",
        );

        let recorded_event = audit_service
            .append(audit_event)
            .await
            .expect("Should append audit event");

        // Insert outbox entry for reputation processing
        let outbox_service = OutboxService::new(pool.clone());
        let _outbox_entry = outbox_service
            .insert(recorded_event.event_id, OutboxTopic::Reputation)
            .await
            .expect("Should insert outbox entry");

        // Get initial reputation
        let reputation_service = ReputationService::new(pool.clone());
        let initial = reputation_service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");

        // Process outbox events (simulating background job)
        let worker_id = format!("test-worker-{}", Uuid::new_v4());
        let processed_count = reputation_service
            .process_outbox_events(&worker_id)
            .await
            .expect("Should process outbox events");

        // Verify at least one event was processed
        assert!(
            processed_count >= 1,
            "Should process at least one event, processed {}",
            processed_count
        );

        // Verify reputation was updated
        let updated = reputation_service
            .get_reputation(&agent_id)
            .await
            .expect("Should get updated reputation");

        // Cleanup
        cleanup_outbox_for_event(&pool, &recorded_event.event_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            updated.score > initial.score,
            "Reputation should increase after processing pr_merged event: {} > {}",
            updated.score,
            initial.score
        );
    }

    // =========================================================================
    // Test: Multiple reputation changes accumulate correctly
    // Requirements: 10.1, 10.2, 10.3
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn multiple_reputation_changes_accumulate() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let service = ReputationService::new(pool.clone());

        // Get initial reputation (0.5)
        let initial = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get initial reputation");

        // Apply multiple changes
        // +0.02 (merge success)
        service
            .process_merge_success(&agent_id, "pr-1")
            .await
            .expect("Should process merge success 1");

        // +0.02 (merge success)
        service
            .process_merge_success(&agent_id, "pr-2")
            .await
            .expect("Should process merge success 2");

        // -0.03 (inaccurate review)
        service
            .process_inaccurate_review(&agent_id, "pr-3")
            .await
            .expect("Should process inaccurate review");

        // Final reputation should be: 0.5 + 0.02 + 0.02 - 0.03 = 0.51
        let final_rep = service
            .get_reputation(&agent_id)
            .await
            .expect("Should get final reputation");

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        let expected = initial.score + 0.02 + 0.02 - 0.03;
        assert!(
            (final_rep.score - expected).abs() < 0.001,
            "Expected accumulated score {}, got {}",
            expected,
            final_rep.score
        );
    }
}

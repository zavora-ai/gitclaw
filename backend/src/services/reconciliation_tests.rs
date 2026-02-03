//! Integration Tests for Reconciliation Jobs
//!
//! These tests validate the Reconciliation Service functionality.
//! Requirements: 11.5
//! Design: DR-14.1 (Audit Service - Reconciliation)

#[cfg(test)]
mod integration_tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sqlx::PgPool;

    use crate::services::{AuditService, ReconciliationService};
    use crate::services::audit::{AuditAction, ResourceType};

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

    /// Generate an Ed25519 keypair for testing
    fn generate_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        (signing_key, public_key)
    }

    /// Create a test agent in the database
    async fn create_test_agent(pool: &PgPool) -> String {
        let (_, public_key) = generate_test_keypair();
        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, $3, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .bind(&public_key)
        .execute(pool)
        .await
        .expect("Failed to create test agent");

        agent_id
    }

    /// Create a test repository
    async fn create_test_repo(pool: &PgPool, owner_id: &str) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, 'Test repo', 'public', 'main', NOW())
            "#,
        )
        .bind(&repo_id)
        .bind(owner_id)
        .bind(&repo_name)
        .execute(pool)
        .await
        .expect("Failed to create test repo");

        // Initialize star count
        sqlx::query(
            r#"
            INSERT INTO repo_star_counts (repo_id, stars, updated_at)
            VALUES ($1, 0, NOW())
            "#,
        )
        .bind(&repo_id)
        .execute(pool)
        .await
        .expect("Failed to initialize star count");

        repo_id
    }

    /// Create a star for a repo
    async fn create_star(pool: &PgPool, repo_id: &str, agent_id: &str) {
        sqlx::query(
            r#"
            INSERT INTO repo_stars (repo_id, agent_id, reason, reason_public, created_at)
            VALUES ($1, $2, 'Test star', true, NOW())
            ON CONFLICT (repo_id, agent_id) DO NOTHING
            "#,
        )
        .bind(repo_id)
        .bind(agent_id)
        .execute(pool)
        .await
        .expect("Failed to create star");
    }

    /// Clean up test data
    async fn cleanup_test_data(pool: &PgPool, agent_ids: &[String], repo_ids: &[String]) {
        for repo_id in repo_ids {
            let _ = sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_objects WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
        }
        for agent_id in agent_ids {
            let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
                .bind(agent_id)
                .execute(pool)
                .await;
        }
    }

    // =========================================================================
    // Test: Star count reconciliation detects drift
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn star_count_reconciliation_detects_drift() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let starrer_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create a star (this updates repo_stars but not repo_star_counts)
        create_star(&pool, &repo_id, &starrer_id).await;

        // repo_star_counts is still 0, but repo_stars has 1 entry
        // This creates a drift

        let service = ReconciliationService::new(pool.clone());
        let result = service.check_star_counts().await.expect("Check should succeed");

        // Find our repo's drift
        let our_drift = result.drifts_found.iter().find(|d| {
            match d {
                crate::services::DriftType::StarCountMismatch { repo_id: rid, .. } => rid == &repo_id,
                _ => false,
            }
        });

        assert!(our_drift.is_some(), "Should detect star count drift for our repo");

        if let Some(crate::services::DriftType::StarCountMismatch { expected, actual, .. }) = our_drift {
            // expected is what the count SHOULD be (1 star in repo_stars)
            // actual is what repo_star_counts says (0)
            assert_eq!(*expected, 1, "Expected count should be 1 (actual stars)");
            assert_eq!(*actual, 0, "Actual count should be 0 (repo_star_counts value)");
        }

        cleanup_test_data(&pool, &[owner_id, starrer_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Star count reconciliation no drift when consistent
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn star_count_reconciliation_no_drift_when_consistent() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let starrer_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create a star AND update the count properly
        create_star(&pool, &repo_id, &starrer_id).await;
        sqlx::query("UPDATE repo_star_counts SET stars = 1 WHERE repo_id = $1")
            .bind(&repo_id)
            .execute(&pool)
            .await
            .expect("Failed to update star count");

        let service = ReconciliationService::new(pool.clone());
        let result = service.check_star_counts().await.expect("Check should succeed");

        // Should not find drift for our repo
        let our_drift = result.drifts_found.iter().find(|d| {
            match d {
                crate::services::DriftType::StarCountMismatch { repo_id: rid, .. } => rid == &repo_id,
                _ => false,
            }
        });

        assert!(our_drift.is_none(), "Should not detect drift when counts are consistent");

        cleanup_test_data(&pool, &[owner_id, starrer_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Repo refs consistency check detects invalid refs
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn ref_consistency_check_detects_invalid_refs() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create a ref pointing to a non-existent object
        let fake_oid = "0000000000000000000000000000000000000000";
        sqlx::query(
            r#"
            INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at)
            VALUES ($1, 'refs/heads/orphan', $2, NOW())
            ON CONFLICT (repo_id, ref_name) DO UPDATE SET oid = $2
            "#,
        )
        .bind(&repo_id)
        .bind(fake_oid)
        .execute(&pool)
        .await
        .expect("Failed to create orphan ref");

        let service = ReconciliationService::new(pool.clone());
        let result = service.check_ref_consistency().await.expect("Check should succeed");

        // Find our repo's drift
        let our_drift = result.drifts_found.iter().find(|d| {
            match d {
                crate::services::DriftType::OrphanedRef { repo_id: rid, .. } => rid == &repo_id,
                _ => false,
            }
        });

        assert!(our_drift.is_some(), "Should detect orphaned ref for our repo");

        if let Some(crate::services::DriftType::OrphanedRef { ref_name, oid, .. }) = our_drift {
            assert_eq!(ref_name, "refs/heads/orphan");
            assert_eq!(oid, fake_oid);
        }

        // Clean up the ref
        let _ = sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(&repo_id)
            .execute(&pool)
            .await;

        cleanup_test_data(&pool, &[owner_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: PR state invariant check detects inconsistencies
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn pr_state_invariant_check_detects_inconsistencies() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;
        let pr_id = uuid::Uuid::new_v4().to_string();

        // Create a PR with status 'merged' but no merged_at timestamp
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, title, source_branch, target_branch, status, created_at)
            VALUES ($1, $2, $3, 'Test PR', 'feature', 'main', 'merged', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&owner_id)
        .execute(&pool)
        .await
        .expect("Failed to create test PR");

        let service = ReconciliationService::new(pool.clone());
        let result = service.check_pr_state_invariants().await.expect("Check should succeed");

        // Find our PR's drift
        let our_drift = result.drifts_found.iter().find(|d| {
            match d {
                crate::services::DriftType::MergedPrMissingTimestamp { pr_id: pid } => pid == &pr_id,
                crate::services::DriftType::PrStatusInconsistent { pr_id: pid, .. } => pid == &pr_id,
                _ => false,
            }
        });

        assert!(our_drift.is_some(), "Should detect PR state inconsistency");

        // Clean up
        let _ = sqlx::query("DELETE FROM pull_requests WHERE pr_id = $1")
            .bind(&pr_id)
            .execute(&pool)
            .await;

        cleanup_test_data(&pool, &[owner_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Audit event emitted on drift detection
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn audit_event_emitted_on_drift_detection() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let starrer_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create a drift
        create_star(&pool, &repo_id, &starrer_id).await;

        // Get count of audit events before
        let before_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND data::text LIKE '%drift_detected%'"
        )
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Run reconciliation
        let service = ReconciliationService::new(pool.clone());
        let _ = service.check_star_counts().await.expect("Check should succeed");

        // Get count of audit events after
        let after_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND data::text LIKE '%drift_detected%'"
        )
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        assert!(
            after_count.0 > before_count.0,
            "Should have created audit event for drift detection"
        );

        cleanup_test_data(&pool, &[owner_id, starrer_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Fix star counts corrects drift
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn fix_star_counts_corrects_drift() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent(&pool).await;
        let starrer1_id = create_test_agent(&pool).await;
        let starrer2_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create stars without updating count
        create_star(&pool, &repo_id, &starrer1_id).await;
        create_star(&pool, &repo_id, &starrer2_id).await;

        // Verify drift exists
        let service = ReconciliationService::new(pool.clone());
        let result = service.check_star_counts().await.expect("Check should succeed");
        let has_drift = result.drifts_found.iter().any(|d| {
            match d {
                crate::services::DriftType::StarCountMismatch { repo_id: rid, .. } => rid == &repo_id,
                _ => false,
            }
        });
        assert!(has_drift, "Should have drift before fix");

        // Fix the drift
        let fixed = service.fix_star_counts().await.expect("Fix should succeed");
        assert!(fixed >= 1, "Should have fixed at least one drift");

        // Verify drift is gone
        let result_after = service.check_star_counts().await.expect("Check should succeed");
        let has_drift_after = result_after.drifts_found.iter().any(|d| {
            match d {
                crate::services::DriftType::StarCountMismatch { repo_id: rid, .. } => rid == &repo_id,
                _ => false,
            }
        });
        assert!(!has_drift_after, "Should not have drift after fix");

        // Verify the count is correct
        let count: (i32,) = sqlx::query_as("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
            .bind(&repo_id)
            .fetch_one(&pool)
            .await
            .expect("Query should succeed");
        assert_eq!(count.0, 2, "Star count should be 2");

        cleanup_test_data(&pool, &[owner_id, starrer1_id, starrer2_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Run all checks returns results for all check types
    // Requirements: 11.5
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn run_all_checks_returns_all_results() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let service = ReconciliationService::new(pool.clone());
        let results = service.run_all_checks().await.expect("Run all checks should succeed");

        assert_eq!(results.len(), 3, "Should have 3 check results");

        let check_types: Vec<&str> = results.iter().map(|r| r.check_type.as_str()).collect();
        assert!(check_types.contains(&"star_count"), "Should have star_count check");
        assert!(check_types.contains(&"ref_consistency"), "Should have ref_consistency check");
        assert!(check_types.contains(&"pr_state_invariants"), "Should have pr_state_invariants check");
    }
}

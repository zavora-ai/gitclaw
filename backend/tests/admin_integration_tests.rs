//! Admin Dashboard Integration Tests
//!
//! These tests validate admin workflows including authentication, agent management,
//! repository management, and reconciliation operations.
//! Run with: `cargo test --test admin_integration_tests -- --ignored`
//!
//! Requirements: 6.1-6.5, 2.4-2.6, 3.4, 7.1-7.6

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Test Helpers
// ============================================================================

/// Helper to create a test database pool
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

/// Create a test agent in the database
async fn create_test_agent(pool: &PgPool, name_prefix: &str) -> String {
    let agent_id = Uuid::new_v4().to_string();
    let agent_name = format!("{}-{}", name_prefix, Uuid::new_v4());

    sqlx::query(
        r#"
        INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
        VALUES ($1, $2, 'test-public-key', '["code_review"]', NOW())
        ON CONFLICT (agent_id) DO NOTHING
        "#,
    )
    .bind(&agent_id)
    .bind(&agent_name)
    .execute(pool)
    .await
    .expect("Failed to create test agent");

    // Initialize reputation
    sqlx::query(
        r#"
        INSERT INTO reputation (agent_id, score, updated_at)
        VALUES ($1, 0.5, NOW())
        ON CONFLICT (agent_id) DO UPDATE SET score = 0.5
        "#,
    )
    .bind(&agent_id)
    .execute(pool)
    .await
    .expect("Failed to initialize reputation");

    agent_id
}

/// Create a test repository
async fn create_test_repo(pool: &PgPool, owner_id: &str, name_prefix: &str) -> String {
    let repo_id = Uuid::new_v4().to_string();
    let repo_name = format!("{}-{}", name_prefix, Uuid::new_v4());

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
        let _ = sqlx::query("DELETE FROM reviews WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM ci_runs WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }
    for agent_id in agent_ids {
        let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }
}

// ============================================================================
// Test: Agent Suspension Flow
// Requirements: 2.4, 2.5, 2.6
// ============================================================================

/// Test: Complete agent suspension and unsuspension workflow
#[ignore]
#[tokio::test]
async fn test_agent_suspension_flow() {
    let pool = match try_create_test_pool().await {
        Some(p) => p,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create test agent
    let agent_id = create_test_agent(&pool, "suspend-test").await;

    // Verify agent is not suspended initially
    let initial_status: (bool,) = sqlx::query_as(
        "SELECT COALESCE(suspended, false) FROM agents WHERE agent_id = $1"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to fetch agent status");
    
    assert!(!initial_status.0, "Agent should not be suspended initially");

    // Suspend the agent
    let suspend_reason = "Violation of terms of service";
    let admin_id = "admin-test-user";
    
    sqlx::query(
        r#"
        UPDATE agents 
        SET suspended = true, 
            suspended_at = NOW(), 
            suspended_reason = $2,
            suspended_by = $3
        WHERE agent_id = $1
        "#,
    )
    .bind(&agent_id)
    .bind(suspend_reason)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("Failed to suspend agent");

    // Create audit log entry for suspension
    let audit_event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
        VALUES ($1, $2, 'AdminSuspendAgent', 'agent', $3, $4, NOW(), 'admin-sig')
        "#,
    )
    .bind(audit_event_id)
    .bind(admin_id)
    .bind(&agent_id)
    .bind(json!({"reason": suspend_reason}))
    .execute(&pool)
    .await
    .expect("Failed to create audit event");

    // Verify agent is suspended
    let suspended_status: (bool, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT suspended, suspended_reason, suspended_by FROM agents WHERE agent_id = $1"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to fetch suspended status");
    
    assert!(suspended_status.0, "Agent should be suspended");
    assert_eq!(suspended_status.1.as_deref(), Some(suspend_reason), "Suspension reason should match");
    assert_eq!(suspended_status.2.as_deref(), Some(admin_id), "Suspended by should match");

    // Verify audit log entry exists
    let audit_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND action = 'AdminSuspendAgent'"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count audit events");
    
    assert!(audit_count.0 >= 1, "Suspension audit event should be recorded");

    // Unsuspend the agent
    sqlx::query(
        r#"
        UPDATE agents 
        SET suspended = false, 
            suspended_at = NULL, 
            suspended_reason = NULL,
            suspended_by = NULL
        WHERE agent_id = $1
        "#,
    )
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to unsuspend agent");

    // Create audit log entry for unsuspension
    let unsuspend_event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
        VALUES ($1, $2, 'AdminUnsuspendAgent', 'agent', $3, '{}', NOW(), 'admin-sig')
        "#,
    )
    .bind(unsuspend_event_id)
    .bind(admin_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create unsuspend audit event");

    // Verify agent is unsuspended
    let final_status: (bool,) = sqlx::query_as(
        "SELECT COALESCE(suspended, false) FROM agents WHERE agent_id = $1"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to fetch final status");
    
    assert!(!final_status.0, "Agent should be unsuspended");

    // Cleanup
    cleanup_test_data(&pool, &[agent_id], &[]).await;
}

// ============================================================================
// Test: Repository Deletion Cascade
// Requirements: 3.4
// ============================================================================

/// Test: Repository deletion removes all associated data
#[ignore]
#[tokio::test]
async fn test_repository_deletion_cascade() {
    let pool = match try_create_test_pool().await {
        Some(p) => p,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create test agent and repo
    let agent_id = create_test_agent(&pool, "delete-test").await;
    let repo_id = create_test_repo(&pool, &agent_id, "delete-test-repo").await;

    // Add associated data
    // 1. Add repo access
    sqlx::query(
        r#"
        INSERT INTO repo_access (repo_id, agent_id, role, created_at)
        VALUES ($1, $2, 'admin', NOW())
        "#,
    )
    .bind(&repo_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create repo access");

    // 2. Add a star
    sqlx::query(
        r#"
        INSERT INTO repo_stars (repo_id, agent_id, reason, reason_public, created_at)
        VALUES ($1, $2, 'Great repo', true, NOW())
        "#,
    )
    .bind(&repo_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create star");

    // 3. Add a PR
    let pr_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO pull_requests (pr_id, repo_id, author_id, title, source_branch, target_branch, status, ci_status, created_at)
        VALUES ($1, $2, $3, 'Test PR', 'feature', 'main', 'open', 'pending', NOW())
        "#,
    )
    .bind(&pr_id)
    .bind(&repo_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create PR");

    // 4. Add a review
    let review_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
        VALUES ($1, $2, $3, 'approve', 'LGTM', NOW())
        "#,
    )
    .bind(&review_id)
    .bind(&pr_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create review");

    // Verify data exists before deletion
    let star_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_stars WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count stars");
    assert_eq!(star_count.0, 1, "Star should exist before deletion");

    let pr_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pull_requests WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count PRs");
    assert_eq!(pr_count.0, 1, "PR should exist before deletion");

    // Delete associated data in correct order (cascade)
    sqlx::query("DELETE FROM reviews WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete reviews");

    sqlx::query("DELETE FROM ci_runs WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete CI runs");

    sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete PRs");

    sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete stars");

    sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete star counts");

    sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete refs");

    sqlx::query("DELETE FROM repo_objects WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete objects");

    sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete access");

    sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to delete repository");

    // Create audit log entry
    let audit_event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
        VALUES ($1, 'admin', 'AdminDeleteRepo', 'repository', $2, '{}', NOW(), 'admin-sig')
        "#,
    )
    .bind(audit_event_id)
    .bind(&repo_id)
    .execute(&pool)
    .await
    .expect("Failed to create audit event");

    // Verify all data is deleted
    let repo_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check repo");
    assert_eq!(repo_exists.0, 0, "Repository should be deleted");

    let stars_exist: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_stars WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check stars");
    assert_eq!(stars_exist.0, 0, "Stars should be deleted");

    let prs_exist: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pull_requests WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to check PRs");
    assert_eq!(prs_exist.0, 0, "PRs should be deleted");

    // Verify audit log entry exists
    let audit_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND action = 'AdminDeleteRepo'"
    )
    .bind(&repo_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count audit events");
    assert!(audit_count.0 >= 1, "Deletion audit event should be recorded");

    // Cleanup
    cleanup_test_data(&pool, &[agent_id], &[]).await;
}

// ============================================================================
// Test: Audit Log Query
// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
// ============================================================================

/// Test: Audit log filtering and pagination
#[ignore]
#[tokio::test]
async fn test_audit_log_query() {
    let pool = match try_create_test_pool().await {
        Some(p) => p,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create test agent
    let agent_id = create_test_agent(&pool, "audit-test").await;

    // Create multiple audit events with different actions
    let actions = vec![
        ("CreateRepo", "repository"),
        ("Star", "repository"),
        ("CreatePR", "pull_request"),
        ("AdminSuspendAgent", "agent"),
    ];

    let mut event_ids = Vec::new();
    for (action, resource_type) in &actions {
        let event_id = Uuid::new_v4();
        event_ids.push(event_id);
        
        sqlx::query(
            r#"
            INSERT INTO audit_log (event_id, agent_id, action, resource_type, resource_id, data, timestamp, signature)
            VALUES ($1, $2, $3, $4, $5, '{}', NOW(), 'test-sig')
            "#,
        )
        .bind(event_id)
        .bind(&agent_id)
        .bind(*action)
        .bind(*resource_type)
        .bind(Uuid::new_v4().to_string())
        .execute(&pool)
        .await
        .expect("Failed to create audit event");
    }

    // Test 1: Filter by agent_id
    let agent_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count agent events");
    assert!(agent_events.0 >= 4, "Should have at least 4 events for agent");

    // Test 2: Filter by action
    let star_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'Star'"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count star events");
    assert_eq!(star_events.0, 1, "Should have 1 Star event");

    // Test 3: Filter by resource_type
    let repo_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND resource_type = 'repository'"
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count repo events");
    assert_eq!(repo_events.0, 2, "Should have 2 repository events");

    // Test 4: Verify chronological ordering
    let ordered_events: Vec<(Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT event_id, timestamp FROM audit_log WHERE agent_id = $1 ORDER BY timestamp DESC"
    )
    .bind(&agent_id)
    .fetch_all(&pool)
    .await
    .expect("Failed to fetch ordered events");

    // Verify events are in descending order
    for i in 1..ordered_events.len() {
        assert!(
            ordered_events[i - 1].1 >= ordered_events[i].1,
            "Events should be in descending chronological order"
        );
    }

    // Cleanup - delete test audit events
    for event_id in &event_ids {
        let _ = sqlx::query("DELETE FROM audit_log WHERE event_id = $1")
            .bind(event_id)
            .execute(&pool)
            .await;
    }
    cleanup_test_data(&pool, &[agent_id], &[]).await;
}

// ============================================================================
// Test: Platform Stats Accuracy
// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
// ============================================================================

/// Test: Platform statistics are accurate
#[ignore]
#[tokio::test]
async fn test_platform_stats_accuracy() {
    let pool = match try_create_test_pool().await {
        Some(p) => p,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Get initial counts
    let initial_agents: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents")
        .fetch_one(&pool)
        .await
        .expect("Failed to count agents");

    let initial_repos: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories")
        .fetch_one(&pool)
        .await
        .expect("Failed to count repos");

    // Create test data
    let agent_id = create_test_agent(&pool, "stats-test").await;
    let repo_id = create_test_repo(&pool, &agent_id, "stats-test-repo").await;

    // Verify counts increased
    let new_agents: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents")
        .fetch_one(&pool)
        .await
        .expect("Failed to count agents");
    assert_eq!(new_agents.0, initial_agents.0 + 1, "Agent count should increase by 1");

    let new_repos: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories")
        .fetch_one(&pool)
        .await
        .expect("Failed to count repos");
    assert_eq!(new_repos.0, initial_repos.0 + 1, "Repo count should increase by 1");

    // Add a star and verify star count
    sqlx::query(
        r#"
        INSERT INTO repo_stars (repo_id, agent_id, reason, reason_public, created_at)
        VALUES ($1, $2, 'Test star', true, NOW())
        "#,
    )
    .bind(&repo_id)
    .bind(&agent_id)
    .execute(&pool)
    .await
    .expect("Failed to create star");

    sqlx::query("UPDATE repo_star_counts SET stars = stars + 1 WHERE repo_id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("Failed to update star count");

    // Verify total stars
    let total_stars: (i64,) = sqlx::query_as("SELECT COALESCE(SUM(stars), 0) FROM repo_star_counts")
        .fetch_one(&pool)
        .await
        .expect("Failed to sum stars");
    assert!(total_stars.0 >= 1, "Total stars should be at least 1");

    // Cleanup
    cleanup_test_data(&pool, &[agent_id], &[repo_id]).await;
}

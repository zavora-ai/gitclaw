//! HTTP Integration Tests for Trending Service
//!
//! These tests validate the Trending Service end-to-end via HTTP endpoints.
//! Requirements: 17.1, 17.2, 17.3, 17.4, 17.5
//! Design: DR-12.1 (Trending Service)

#[cfg(test)]
mod http_integration_tests {
    use actix_web::{App, test, web};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::Value;
    use sqlx::PgPool;

    use crate::AppState;
    use crate::config::Config;
    use crate::handlers::configure_trending_routes;
    use crate::models::TrendingWindow;
    use crate::services::{RateLimiterService, TrendingService};

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

    /// Create a test agent in the database and return (agent_id, public_key)
    async fn create_test_agent(pool: &PgPool) -> (String, String) {
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

        (agent_id, public_key)
    }

    /// Create a test agent with specific reputation
    async fn create_test_agent_with_reputation(pool: &PgPool, reputation: f64) -> String {
        let (agent_id, _) = create_test_agent(pool).await;

        sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, $2, '[]', NOW())
            ON CONFLICT (agent_id) DO UPDATE SET score = $2
            "#,
        )
        .bind(&agent_id)
        .bind(reputation)
        .execute(pool)
        .await
        .expect("Failed to set reputation");

        agent_id
    }

    /// Create a test repository and return repo_id
    async fn create_test_repo(pool: &PgPool, owner_id: &str, name: Option<&str>) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = name.map(String::from).unwrap_or_else(|| format!("test-repo-{}", uuid::Uuid::new_v4()));

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

    /// Create a star for a repo by an agent
    async fn create_star(pool: &PgPool, repo_id: &str, agent_id: &str, created_at: chrono::DateTime<Utc>) {
        sqlx::query(
            r#"
            INSERT INTO repo_stars (repo_id, agent_id, reason, reason_public, created_at)
            VALUES ($1, $2, 'Test star', true, $3)
            ON CONFLICT (repo_id, agent_id) DO NOTHING
            "#,
        )
        .bind(repo_id)
        .bind(agent_id)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("Failed to create star");

        // Update star count
        sqlx::query(
            r#"
            UPDATE repo_star_counts SET stars = stars + 1, updated_at = NOW()
            WHERE repo_id = $1
            "#,
        )
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("Failed to update star count");
    }

    /// Clean up test data
    async fn cleanup_test_data(pool: &PgPool, agent_ids: &[String], repo_ids: &[String]) {
        for repo_id in repo_ids {
            let _ = sqlx::query("DELETE FROM repo_trending_scores WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
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

    // =========================================================================
    // Test: Trending endpoint returns repos sorted by weighted_score DESC
    // Requirements: 17.1
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_trending_returns_repos_sorted_by_score() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Create test agents and repos
        let agent_id = create_test_agent_with_reputation(&pool, 0.8).await;
        let repo1_id = create_test_repo(&pool, &agent_id, Some("trending-test-repo-1")).await;
        let repo2_id = create_test_repo(&pool, &agent_id, Some("trending-test-repo-2")).await;
        let repo3_id = create_test_repo(&pool, &agent_id, Some("trending-test-repo-3")).await;

        // Insert trending scores directly (simulating aggregation job output)
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO repo_trending_scores ("window", repo_id, weighted_score, stars_delta, computed_at)
            VALUES ('24h', $1, 5.0, 5, $4),
                   ('24h', $2, 10.0, 10, $4),
                   ('24h', $3, 2.5, 2, $4)
            ON CONFLICT ("window", repo_id) DO UPDATE SET weighted_score = EXCLUDED.weighted_score
            "#,
        )
        .bind(&repo1_id)
        .bind(&repo2_id)
        .bind(&repo3_id)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to insert trending scores");

        let app_state = create_test_app_state(pool.clone());

        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .configure(|cfg| {
                    cfg.service(web::scope("/v1").configure(configure_trending_routes));
                }),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v1/repos/trending?window=24h")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Request should succeed");

        let body: Value = test::read_body_json(resp).await;
        let repos = body["data"]["repos"].as_array().expect("repos should be array");

        // Verify sorted by weighted_score DESC (check all repos in response)
        let mut prev_score = f64::MAX;
        for repo in repos {
            let score = repo["weightedScore"].as_f64().unwrap_or(0.0);
            assert!(score <= prev_score, "Repos should be sorted by weighted_score DESC");
            prev_score = score;
        }

        // Find our test repos in the results and verify their relative order
        let our_repos: Vec<(&str, f64)> = repos.iter()
            .filter_map(|r| {
                let id = r["repoId"].as_str()?;
                if id == repo1_id || id == repo2_id || id == repo3_id {
                    Some((id, r["weightedScore"].as_f64().unwrap_or(0.0)))
                } else {
                    None
                }
            })
            .collect();

        // We should find at least some of our repos (may not find all if cleanup races)
        // The important thing is that the overall sort order is correct
        if our_repos.len() >= 2 {
            // Verify our repos are in correct relative order
            let mut sorted_our_repos = our_repos.clone();
            sorted_our_repos.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            assert_eq!(our_repos, sorted_our_repos, "Our repos should be in descending score order");
        }

        cleanup_test_data(&pool, &[agent_id], &[repo1_id, repo2_id, repo3_id]).await;
    }

    // =========================================================================
    // Test: Window parameter validation (1h, 24h, 7d, 30d)
    // Requirements: 17.1
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_window_parameter_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let app_state = create_test_app_state(pool.clone());

        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .configure(|cfg| {
                    cfg.service(web::scope("/v1").configure(configure_trending_routes));
                }),
        )
        .await;

        // Test valid windows
        for window in ["1h", "24h", "7d", "30d"] {
            let req = test::TestRequest::get()
                .uri(&format!("/v1/repos/trending?window={}", window))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert!(
                resp.status().is_success(),
                "Window {} should be valid",
                window
            );

            let body: Value = test::read_body_json(resp).await;
            assert_eq!(
                body["data"]["window"].as_str().unwrap(),
                window,
                "Response should include correct window"
            );
        }

        // Test default window (no parameter)
        let req = test::TestRequest::get()
            .uri("/v1/repos/trending")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Default window should work");

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(
            body["data"]["window"].as_str().unwrap(),
            "24h",
            "Default window should be 24h"
        );
    }

    // =========================================================================
    // Test: Invalid window parameter returns error
    // Requirements: 17.1
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_invalid_window_returns_error() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let app_state = create_test_app_state(pool.clone());

        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .configure(|cfg| {
                    cfg.service(web::scope("/v1").configure(configure_trending_routes));
                }),
        )
        .await;

        // Test invalid windows
        for invalid_window in ["2h", "48h", "invalid", "1d", "1w"] {
            let req = test::TestRequest::get()
                .uri(&format!("/v1/repos/trending?window={}", invalid_window))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(
                resp.status().as_u16(),
                400,
                "Invalid window '{}' should return 400",
                invalid_window
            );
        }
    }


    // =========================================================================
    // Test: Trending aggregation job computes scores correctly
    // Requirements: 17.2
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_aggregation_job_computes_scores() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Create test agents with different reputations
        let agent1_id = create_test_agent_with_reputation(&pool, 1.0).await; // High rep
        let agent2_id = create_test_agent_with_reputation(&pool, 0.0).await; // Low rep
        let owner_id = create_test_agent_with_reputation(&pool, 0.5).await;

        let repo_id = create_test_repo(&pool, &owner_id, Some("aggregation-test-repo")).await;

        // Create stars from both agents (recent)
        let now = Utc::now();
        create_star(&pool, &repo_id, &agent1_id, now - Duration::minutes(5)).await;
        create_star(&pool, &repo_id, &agent2_id, now - Duration::minutes(10)).await;

        // Run aggregation
        let trending_service = TrendingService::new(pool.clone());
        trending_service
            .run_aggregation()
            .await
            .expect("Aggregation should succeed");

        // Check that scores were computed
        let row: Option<(f64, i32)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION), stars_delta FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '24h'"#,
        )
        .bind(&repo_id)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        let (weighted_score, stars_delta) = row.expect("Score should exist");
        assert_eq!(stars_delta, 2, "Should have 2 stars");
        assert!(weighted_score > 0.0, "Weighted score should be positive");

        cleanup_test_data(&pool, &[agent1_id, agent2_id, owner_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Weight formula: 0.5 + 0.5 * starrer_reputation
    // Requirements: 17.2
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_weight_formula_applied_correctly() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Create agent with known reputation
        let high_rep_agent = create_test_agent_with_reputation(&pool, 1.0).await;
        let low_rep_agent = create_test_agent_with_reputation(&pool, 0.0).await;
        let owner_id = create_test_agent_with_reputation(&pool, 0.5).await;

        let repo_high = create_test_repo(&pool, &owner_id, Some("weight-test-high")).await;
        let repo_low = create_test_repo(&pool, &owner_id, Some("weight-test-low")).await;

        // Create stars (very recent to minimize age decay)
        let now = Utc::now();
        create_star(&pool, &repo_high, &high_rep_agent, now - Duration::seconds(10)).await;
        create_star(&pool, &repo_low, &low_rep_agent, now - Duration::seconds(10)).await;

        // Run aggregation
        let trending_service = TrendingService::new(pool.clone());
        trending_service
            .run_aggregation()
            .await
            .expect("Aggregation should succeed");

        // Get scores
        let high_score: Option<(f64,)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION) FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '1h'"#,
        )
        .bind(&repo_high)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        let low_score: Option<(f64,)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION) FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '1h'"#,
        )
        .bind(&repo_low)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        if let (Some((high,)), Some((low,))) = (high_score, low_score) {
            // High rep (1.0) should give weight ~1.0 (0.5 + 0.5 * 1.0)
            // Low rep (0.0) should give weight ~0.5 (0.5 + 0.5 * 0.0)
            // So high should be roughly 2x low (accounting for slight age decay differences)
            assert!(
                high > low,
                "High reputation star should have higher weight: high={}, low={}",
                high,
                low
            );
            // Allow some tolerance for age decay
            let ratio = high / low;
            assert!(
                ratio > 1.5 && ratio < 2.5,
                "Weight ratio should be approximately 2x: ratio={}",
                ratio
            );
        }

        cleanup_test_data(&pool, &[high_rep_agent, low_rep_agent, owner_id], &[repo_high, repo_low]).await;
    }

    // =========================================================================
    // Test: Age decay applied to older stars
    // Requirements: 17.3
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_age_decay_applied() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Create agents with same reputation
        let recent_agent = create_test_agent_with_reputation(&pool, 0.5).await;
        let old_agent = create_test_agent_with_reputation(&pool, 0.5).await;
        let owner_id = create_test_agent_with_reputation(&pool, 0.5).await;

        let repo_recent = create_test_repo(&pool, &owner_id, Some("age-test-recent")).await;
        let repo_old = create_test_repo(&pool, &owner_id, Some("age-test-old")).await;

        // Create stars at different times
        let now = Utc::now();
        create_star(&pool, &repo_recent, &recent_agent, now - Duration::minutes(5)).await;
        create_star(&pool, &repo_old, &old_agent, now - Duration::hours(23)).await; // Near end of 24h window

        // Run aggregation
        let trending_service = TrendingService::new(pool.clone());
        trending_service
            .run_aggregation()
            .await
            .expect("Aggregation should succeed");

        // Get scores for 24h window
        let recent_score: Option<(f64,)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION) FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '24h'"#,
        )
        .bind(&repo_recent)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        let old_score: Option<(f64,)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION) FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '24h'"#,
        )
        .bind(&repo_old)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        if let (Some((recent,)), Some((old,))) = (recent_score, old_score) {
            // Recent star should have higher weight due to age decay
            assert!(
                recent > old,
                "Recent star should have higher weight: recent={}, old={}",
                recent,
                old
            );
        }

        cleanup_test_data(&pool, &[recent_agent, old_agent, owner_id], &[repo_recent, repo_old]).await;
    }

    // =========================================================================
    // Test: Diversity penalty applied (first 3 from cluster = 1.0x, rest = 0.5x)
    // Requirements: 17.4
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_diversity_penalty_applied() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        // Create agents in the same cluster
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let mut cluster_agents = Vec::new();
        for _ in 0..5 {
            let agent_id = create_test_agent_with_reputation(&pool, 0.5).await;
            // Set cluster membership
            sqlx::query(
                r#"UPDATE reputation SET cluster_ids = $1 WHERE agent_id = $2"#,
            )
            .bind(serde_json::json!([&cluster_id]))
            .bind(&agent_id)
            .execute(&pool)
            .await
            .expect("Failed to set cluster");
            cluster_agents.push(agent_id);
        }

        // Create agent without cluster
        let no_cluster_agent = create_test_agent_with_reputation(&pool, 0.5).await;

        let owner_id = create_test_agent_with_reputation(&pool, 0.5).await;
        let repo_clustered = create_test_repo(&pool, &owner_id, Some("diversity-test-clustered")).await;
        let repo_diverse = create_test_repo(&pool, &owner_id, Some("diversity-test-diverse")).await;

        // Create stars from clustered agents on one repo
        let now = Utc::now();
        for (i, agent_id) in cluster_agents.iter().enumerate() {
            create_star(&pool, &repo_clustered, agent_id, now - Duration::minutes(i as i64)).await;
        }

        // Create stars from diverse agents on another repo (5 different agents, no cluster)
        for i in 0..5 {
            let diverse_agent = create_test_agent_with_reputation(&pool, 0.5).await;
            create_star(&pool, &repo_diverse, &diverse_agent, now - Duration::minutes(i as i64)).await;
            cluster_agents.push(diverse_agent); // Add to cleanup list
        }

        // Run aggregation
        let trending_service = TrendingService::new(pool.clone());
        trending_service
            .run_aggregation()
            .await
            .expect("Aggregation should succeed");

        // Get scores
        let clustered_score: Option<(f64, i32)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION), stars_delta FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '24h'"#,
        )
        .bind(&repo_clustered)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        let diverse_score: Option<(f64, i32)> = sqlx::query_as(
            r#"SELECT CAST(weighted_score AS DOUBLE PRECISION), stars_delta FROM repo_trending_scores WHERE repo_id = $1 AND "window" = '24h'"#,
        )
        .bind(&repo_diverse)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        if let (Some((clustered, clustered_delta)), Some((diverse, diverse_delta))) = (clustered_score, diverse_score) {
            assert_eq!(clustered_delta, 5, "Clustered repo should have 5 stars");
            assert_eq!(diverse_delta, 5, "Diverse repo should have 5 stars");
            // Diverse repo should have higher score due to no diversity penalty
            // Clustered: 3 * 1.0 + 2 * 0.5 = 4.0 (base, before reputation/age)
            // Diverse: 5 * 1.0 = 5.0 (base, before reputation/age)
            assert!(
                diverse > clustered,
                "Diverse stars should have higher total weight: diverse={}, clustered={}",
                diverse,
                clustered
            );
        }

        cluster_agents.push(no_cluster_agent);
        cluster_agents.push(owner_id);
        cleanup_test_data(&pool, &cluster_agents, &[repo_clustered, repo_diverse]).await;
    }

    // =========================================================================
    // Test: Scores written atomically to repo_trending_scores
    // Requirements: 17.2
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_scores_written_atomically() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let owner_id = create_test_agent_with_reputation(&pool, 0.5).await;
        let agent_id = create_test_agent_with_reputation(&pool, 0.5).await;
        let repo_id = create_test_repo(&pool, &owner_id, Some("atomic-test-repo")).await;

        // Create a star
        let now = Utc::now();
        create_star(&pool, &repo_id, &agent_id, now - Duration::minutes(5)).await;

        // Run aggregation multiple times
        let trending_service = TrendingService::new(pool.clone());
        for _ in 0..3 {
            trending_service
                .run_aggregation()
                .await
                .expect("Aggregation should succeed");
        }

        // Check that there's only one entry per window (atomic replacement)
        let count: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM repo_trending_scores WHERE repo_id = $1"#,
        )
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Should have exactly 4 entries (one per window: 1h, 24h, 7d, 30d)
        assert_eq!(count.0, 4, "Should have exactly 4 entries (one per window)");

        cleanup_test_data(&pool, &[owner_id, agent_id], &[repo_id]).await;
    }

    // =========================================================================
    // Test: Limit parameter works correctly
    // Requirements: 17.5
    // Design: DR-12.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_limit_parameter_works() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let app_state = create_test_app_state(pool.clone());

        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .configure(|cfg| {
                    cfg.service(web::scope("/v1").configure(configure_trending_routes));
                }),
        )
        .await;

        // Test with limit=5
        let req = test::TestRequest::get()
            .uri("/v1/repos/trending?window=24h&limit=5")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Request should succeed");

        let body: Value = test::read_body_json(resp).await;
        let repos = body["data"]["repos"].as_array().expect("repos should be array");
        assert!(repos.len() <= 5, "Should return at most 5 repos");
    }
}

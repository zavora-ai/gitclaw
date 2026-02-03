//! HTTP Integration Tests for Reputation Service
//!
//! These tests validate the Reputation Service end-to-end via HTTP endpoints.
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
//! Design: DR-13.1 (Reputation Service)

#[cfg(test)]
mod http_integration_tests {
    use actix_web::{App, test, web};
    use sqlx::PgPool;
    use uuid::Uuid;

    use crate::AppState;
    use crate::config::Config;
    use crate::handlers::configure_agent_routes;
    use crate::services::RateLimiterService;

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

        agent_id
    }

    /// Create a test agent with reputation initialized
    async fn create_test_agent_with_reputation(pool: &PgPool, score: f64) -> String {
        let agent_id = create_test_agent(pool).await;

        sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, $2, '[]', NOW())
            ON CONFLICT (agent_id) DO UPDATE SET score = $2, updated_at = NOW()
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

    // =========================================================================
    // Test: GET /v1/agents/{agentId}/reputation returns current score
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_reputation_returns_current_score() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let expected_score = 0.75;
        let agent_id = create_test_agent_with_reputation(&pool, expected_score).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}/reputation", agent_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            status, 200,
            "Expected 200 OK, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["agent_id"], agent_id);

        let returned_score = response["data"]["score"].as_f64().unwrap();
        assert!(
            (returned_score - expected_score).abs() < 0.001,
            "Expected score {}, got {}",
            expected_score,
            returned_score
        );
    }

    // =========================================================================
    // Test: GET /v1/agents/{agentId}/reputation for non-existent agent returns 404
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_reputation_nonexistent_agent_returns_404() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let fake_agent_id = Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}/reputation", fake_agent_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        assert_eq!(
            status, 404,
            "Expected 404 Not Found for non-existent agent, got {}",
            status
        );
    }

    // =========================================================================
    // Test: GET /v1/agents/{agentId}/reputation includes updated_at timestamp
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_reputation_includes_timestamp() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent_with_reputation(&pool, 0.5).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}/reputation", agent_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(status, 200, "Expected 200 OK, got {}", status);
        assert!(
            response["data"]["updated_at"].is_string(),
            "Response should include updated_at timestamp"
        );
    }

    // =========================================================================
    // Test: Reputation response has correct structure
    // Requirements: 10.4
    // Design: DR-13.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_reputation_has_correct_structure() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent_with_reputation(&pool, 0.65).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}/reputation", agent_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        // Verify response structure follows API standards
        assert!(
            response["data"].is_object(),
            "Response should have 'data' field"
        );
        assert!(
            response["meta"].is_object(),
            "Response should have 'meta' field"
        );
        assert!(
            response["meta"]["request_id"].is_string(),
            "Response should have 'meta.request_id'"
        );

        // Verify data fields
        let data = &response["data"];
        assert!(data["agent_id"].is_string(), "Data should have 'agent_id'");
        assert!(data["score"].is_number(), "Data should have 'score'");
        assert!(
            data["updated_at"].is_string(),
            "Data should have 'updated_at'"
        );
    }
}

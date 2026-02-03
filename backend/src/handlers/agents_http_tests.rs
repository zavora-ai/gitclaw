//! HTTP Integration Tests for Agent Registry Service
//!
//! These tests validate the Agent Registry Service end-to-end via HTTP endpoints.
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
//! Design: DR-1.1 (Agent Registry Service)
//!
//! Run with: `cargo test agents_http_tests -- --ignored`

#[cfg(test)]
mod http_integration_tests {
    use actix_web::{App, test, web};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sqlx::PgPool;

    use crate::AppState;
    use crate::config::Config;
    use crate::handlers::configure_agent_routes;
    use crate::services::RateLimiterService;

    /// Helper to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<PgPool> {
        // Try to load .env from backend directory (for running from workspace root)
        let _ = dotenvy::from_filename("backend/.env");
        // Also try current directory (for running from backend directory)
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

    /// Generate an Ed25519 keypair and return the base64-encoded public key
    fn generate_test_public_key() -> String {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        STANDARD.encode(verifying_key.as_bytes())
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

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        // Clean up in reverse order of dependencies
        let _ = sqlx::query("DELETE FROM repo_access WHERE agent_id = $1")
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

    /// Clean up test agent by name
    async fn cleanup_test_agent_by_name(pool: &PgPool, agent_name: &str) {
        // First get the agent_id
        let agent_id: Option<String> =
            sqlx::query_scalar("SELECT agent_id FROM agents WHERE agent_name = $1")
                .bind(agent_name)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

        if let Some(id) = agent_id {
            cleanup_test_agent(pool, &id).await;
        }
    }

    // =========================================================================
    // Test: Successful agent registration end-to-end via HTTP
    // Requirements: 1.1, 1.4, 1.5
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_agent_registration_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key,
            "capabilities": ["code", "review"]
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Extract agent_id for cleanup
        let agent_id = response["data"]["agentId"].as_str().unwrap_or("");

        // Cleanup
        if !agent_id.is_empty() {
            cleanup_test_agent(&pool, agent_id).await;
        }

        assert_eq!(
            status, 201,
            "Expected 201 Created, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["agentName"], agent_name);
        assert!(!response["data"]["agentId"].as_str().unwrap_or("").is_empty());
        assert!(response["data"]["createdAt"].as_str().is_some());
    }

    // =========================================================================
    // Test: Duplicate agent name rejection returns AGENT_NAME_EXISTS (409)
    // Requirements: 1.2
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_duplicate_agent_name_returns_409() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        let public_key1 = generate_test_public_key();
        let public_key2 = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        // First registration should succeed
        let request_body1 = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key1,
            "capabilities": ["code"]
        });

        let req1 = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body1)
            .to_request();

        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 201, "First registration should succeed");

        let body1_bytes = test::read_body(resp1).await;
        let response1: serde_json::Value = serde_json::from_slice(&body1_bytes).unwrap();
        let agent_id = response1["data"]["agentId"].as_str().unwrap();

        // Second registration with same name should fail with 409
        let request_body2 = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key2,
            "capabilities": ["review"]
        });

        let req2 = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body2)
            .to_request();

        let resp2 = test::call_service(&app, req2).await;
        let status2 = resp2.status();

        let body2_bytes = test::read_body(resp2).await;
        let response2: serde_json::Value = serde_json::from_slice(&body2_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_agent(&pool, agent_id).await;

        assert_eq!(
            status2, 409,
            "Second registration should return 409 Conflict: {:?}",
            response2
        );
        assert!(
            response2["error"]["code"]
                .as_str()
                .unwrap_or("")
                .contains("CONFLICT"),
            "Error code should indicate conflict: {:?}",
            response2
        );
    }

    // =========================================================================
    // Test: Invalid public key format returns INVALID_PUBLIC_KEY (400)
    // Requirements: 1.3
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_invalid_public_key_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        // Invalid public key - not valid base64 or wrong length
        let invalid_public_key = "not-a-valid-public-key!!!";

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": invalid_public_key,
            "capabilities": ["code"]
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup (in case it somehow succeeded)
        cleanup_test_agent_by_name(&pool, &agent_name).await;

        assert_eq!(
            status, 400,
            "Invalid public key should return 400 Bad Request: {:?}",
            response
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("public key")
                || response["error"]["code"]
                    .as_str()
                    .unwrap_or("")
                    .contains("VALIDATION"),
            "Error should mention public key validation: {:?}",
            response
        );
    }

    // =========================================================================
    // Test: Invalid public key - wrong length (valid base64 but wrong size)
    // Requirements: 1.3, 1.4
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_wrong_length_public_key_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        // Valid base64 but wrong length for Ed25519 (should be 32 bytes)
        let wrong_length_key = STANDARD.encode(b"too-short");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": wrong_length_key,
            "capabilities": []
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup (in case it somehow succeeded)
        cleanup_test_agent_by_name(&pool, &agent_name).await;

        assert_eq!(
            status, 400,
            "Wrong length public key should return 400 Bad Request: {:?}",
            response
        );
    }

    // =========================================================================
    // Test: Audit event is created on successful registration
    // Requirements: 1.1 (implied audit trail from DR-1.1)
    // Design: DR-1.1, DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_registration_creates_audit_event() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key,
            "capabilities": ["code", "review"]
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Registration should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let agent_id = response["data"]["agentId"].as_str().unwrap();

        // Check audit log for registration event
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'agent_register'"
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup
        cleanup_test_agent(&pool, agent_id).await;

        assert!(
            audit_count > 0,
            "Registration event should be recorded in audit_log"
        );
    }

    // =========================================================================
    // Test: Agent retrieval via GET /v1/agents/{agentId}
    // Requirements: 1.1, 1.5
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_agent_by_id_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        // First, register an agent
        let register_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key,
            "capabilities": ["code", "review"]
        });

        let register_req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&register_body)
            .to_request();

        let register_resp = test::call_service(&app, register_req).await;
        assert_eq!(register_resp.status(), 201, "Registration should succeed");

        let register_body_bytes = test::read_body(register_resp).await;
        let register_response: serde_json::Value =
            serde_json::from_slice(&register_body_bytes).unwrap();
        let agent_id = register_response["data"]["agentId"].as_str().unwrap();

        // Now retrieve the agent by ID
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}", agent_id))
            .to_request();

        let get_resp = test::call_service(&app, get_req).await;
        let get_status = get_resp.status();

        let get_body_bytes = test::read_body(get_resp).await;
        let get_response: serde_json::Value =
            serde_json::from_slice(&get_body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_agent(&pool, agent_id).await;

        assert_eq!(
            get_status, 200,
            "GET agent should succeed: {:?}",
            get_response
        );
        assert_eq!(get_response["data"]["agentId"], agent_id);
        assert_eq!(get_response["data"]["agentName"], agent_name);
        // Capabilities should be returned as an array
        assert!(get_response["data"]["capabilities"].is_array());
    }

    // =========================================================================
    // Test: GET non-existent agent returns 404
    // Requirements: 1.1
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_nonexistent_agent_returns_404() {
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
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        // Try to get a non-existent agent
        let fake_agent_id = uuid::Uuid::new_v4().to_string();
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/agents/{}", fake_agent_id))
            .to_request();

        let get_resp = test::call_service(&app, get_req).await;
        let get_status = get_resp.status();

        let get_body_bytes = test::read_body(get_resp).await;
        let get_response: serde_json::Value =
            serde_json::from_slice(&get_body_bytes).unwrap_or_default();

        assert_eq!(
            get_status, 404,
            "GET non-existent agent should return 404: {:?}",
            get_response
        );
        assert!(
            get_response["error"]["code"]
                .as_str()
                .unwrap_or("")
                .contains("NOT_FOUND"),
            "Error code should indicate not found: {:?}",
            get_response
        );
    }

    // =========================================================================
    // Test: Registration stores public key for signature verification
    // Requirements: 1.5
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_registration_stores_public_key() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());
        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": agent_name,
            "publicKey": public_key,
            "capabilities": []
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Registration should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let agent_id = response["data"]["agentId"].as_str().unwrap();

        // Verify public key is stored in database
        let stored_key: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM agents WHERE agent_id = $1")
                .bind(agent_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_agent(&pool, agent_id).await;

        assert_eq!(
            stored_key,
            Some(public_key),
            "Public key should be stored in database"
        );
    }

    // =========================================================================
    // Test: Invalid agent name format returns 400
    // Requirements: 1.1
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_invalid_agent_name_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        // Test with invalid agent name (starts with hyphen)
        let request_body = serde_json::json!({
            "agentName": "-invalid-name",
            "publicKey": public_key,
            "capabilities": []
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        assert_eq!(
            status, 400,
            "Invalid agent name should return 400 Bad Request: {:?}",
            response
        );
    }

    // =========================================================================
    // Test: Empty agent name returns 400
    // Requirements: 1.1
    // Design: DR-1.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_empty_agent_name_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let public_key = generate_test_public_key();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_agent_routes)),
        )
        .await;

        let request_body = serde_json::json!({
            "agentName": "",
            "publicKey": public_key,
            "capabilities": []
        });

        let req = test::TestRequest::post()
            .uri("/v1/agents/register")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        assert_eq!(
            status, 400,
            "Empty agent name should return 400 Bad Request: {:?}",
            response
        );
    }
}

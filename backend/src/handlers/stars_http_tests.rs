//! HTTP Integration Tests for Star Service
//!
//! These tests validate the Star Service end-to-end via HTTP endpoints.
//! Requirements: 14.1, 14.2, 14.5, 14.6, 14.7, 15.1, 15.2, 15.4, 16.1, 16.2, 16.3, 16.4
//! Design: DR-11.1 (Star Service)

#[cfg(test)]
mod http_integration_tests {
    use actix_web::{App, test, web};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;

    use crate::AppState;
    use crate::config::Config;
    use crate::handlers::configure_star_routes;
    use crate::services::signature::SignatureEnvelope;
    use crate::services::{RateLimiterService, SignatureValidator};

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

    /// Sign an envelope with Ed25519
    fn sign_envelope(signing_key: &SigningKey, envelope: &SignatureEnvelope) -> String {
        let validator = SignatureValidator::default();
        let canonical = validator
            .canonicalize(envelope)
            .expect("canonicalize failed");
        let message_hash = Sha256::digest(canonical.as_bytes());
        let signature = signing_key.sign(&message_hash);
        STANDARD.encode(signature.to_bytes())
    }

    /// Create a test agent in the database and return (agent_id, public_key, signing_key)
    async fn create_test_agent(pool: &PgPool) -> (String, String, SigningKey) {
        let (signing_key, public_key) = generate_test_keypair();
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

        // Initialize reputation
        let _ = sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, 0.500, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .execute(pool)
        .await;

        (agent_id, public_key, signing_key)
    }

    /// Create a test repository and return repo_id
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

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        let _ = sqlx::query("DELETE FROM repo_stars WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM star_events WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_access WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id IN (SELECT repo_id FROM repositories WHERE owner_id = $1)")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE owner_id = $1")
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

    /// Clean up test repository
    async fn cleanup_test_repo(pool: &PgPool, repo_id: &str) {
        let _ = sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM star_events WHERE repo_id = $1")
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

    /// Clean up idempotency result
    async fn cleanup_idempotency(pool: &PgPool, agent_id: &str, nonce: &str) {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
            .bind(&nonce_hash)
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
    // Test: Star creation end-to-end via HTTP
    // Requirements: 14.1
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_star_creation_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
            "reason": "Great project!",
            "reasonPublic": true,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&signing_key, &envelope);

        let request_body = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "reason": "Great project!",
            "reasonPublic": true,
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            status, 200,
            "Expected 200 OK, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["repoId"], repo_id);
        assert_eq!(response["data"]["agentId"], agent_id);
        assert_eq!(response["data"]["action"], "starred");
        assert_eq!(response["data"]["starCount"], 1);
    }

    // =========================================================================
    // Test: Star increments repo_star_counts atomically
    // Requirements: 14.5
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_star_increments_count_atomically() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create two agents to star
        let (agent1_id, _pk1, sk1) = create_test_agent(&pool).await;
        let (agent2_id, _pk2, sk2) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // First star
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let body1 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope1 = SignatureEnvelope {
            agent_id: agent1_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };
        let signature1 = sign_envelope(&sk1, &envelope1);

        let request1 = serde_json::json!({
            "agentId": agent1_id,
            "timestamp": envelope1.timestamp,
            "nonce": nonce1,
            "signature": signature1,
        });

        let req1 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request1)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200, "First star should succeed");

        // Second star
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let body2 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope2 = SignatureEnvelope {
            agent_id: agent2_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };
        let signature2 = sign_envelope(&sk2, &envelope2);

        let request2 = serde_json::json!({
            "agentId": agent2_id,
            "timestamp": envelope2.timestamp,
            "nonce": nonce2,
            "signature": signature2,
        });

        let req2 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request2)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        let body2_bytes = test::read_body(resp2).await;
        let response2: serde_json::Value = serde_json::from_slice(&body2_bytes).unwrap();

        // Verify count in database
        let db_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent1_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent2_id, &nonce2).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent1_id).await;
        cleanup_test_agent(&pool, &agent2_id).await;
        cleanup_test_agent(&pool, &owner_id).await;

        assert_eq!(
            response2["data"]["starCount"], 2,
            "Star count should be 2 after two stars"
        );
        assert_eq!(db_count, 2, "Database star count should be 2");
    }

    // =========================================================================
    // Test: Duplicate star returns DUPLICATE_STAR (409)
    // Requirements: 14.2
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_duplicate_star_returns_409() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // First star
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let body1 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope1 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };
        let signature1 = sign_envelope(&signing_key, &envelope1);

        let request1 = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope1.timestamp,
            "nonce": nonce1,
            "signature": signature1,
        });

        let req1 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request1)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200, "First star should succeed");

        // Second star with different nonce (duplicate attempt)
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let body2 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope2 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };
        let signature2 = sign_envelope(&signing_key, &envelope2);

        let request2 = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope2.timestamp,
            "nonce": nonce2,
            "signature": signature2,
        });

        let req2 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request2)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        let status2 = resp2.status();

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent_id, &nonce2).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(status2, 409, "Duplicate star should return 409 Conflict");
    }

    // =========================================================================
    // Test: Star on non-existent repo returns REPO_NOT_FOUND (404)
    // Requirements: 14.6
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_star_nonexistent_repo_returns_404() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let fake_repo_id = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": fake_repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };
        let signature = sign_envelope(&signing_key, &envelope);

        let request_body = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", fake_repo_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(status, 404, "Star on non-existent repo should return 404");
    }

    // =========================================================================
    // Test: Unstar decrements count (floor at 0)
    // Requirements: 15.4
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_unstar_decrements_count() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // First star
        let star_nonce = uuid::Uuid::new_v4().to_string();
        let star_body = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let star_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: star_nonce.clone(),
            body: star_body,
        };
        let star_signature = sign_envelope(&signing_key, &star_envelope);

        let star_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": star_envelope.timestamp,
            "nonce": star_nonce,
            "signature": star_signature,
        });

        let star_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&star_request)
            .to_request();
        let star_resp = test::call_service(&app, star_req).await;
        assert_eq!(star_resp.status(), 200, "Star should succeed");

        // Now unstar
        let unstar_nonce = uuid::Uuid::new_v4().to_string();
        let unstar_body = serde_json::json!({
            "repoId": repo_id,
        });
        let unstar_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "unstar".to_string(),
            timestamp: Utc::now(),
            nonce: unstar_nonce.clone(),
            body: unstar_body,
        };
        let unstar_signature = sign_envelope(&signing_key, &unstar_envelope);

        let unstar_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": unstar_envelope.timestamp,
            "nonce": unstar_nonce,
            "signature": unstar_signature,
        });

        let unstar_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:unstar", repo_id))
            .set_json(&unstar_request)
            .to_request();
        let unstar_resp = test::call_service(&app, unstar_req).await;
        let unstar_body_bytes = test::read_body(unstar_resp).await;
        let unstar_response: serde_json::Value =
            serde_json::from_slice(&unstar_body_bytes).unwrap();

        // Verify count in database
        let db_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &star_nonce).await;
        cleanup_idempotency(&pool, &agent_id, &unstar_nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            unstar_response["data"]["starCount"], 0,
            "Star count should be 0 after unstar"
        );
        assert_eq!(db_count, 0, "Database star count should be 0");
    }

    // =========================================================================
    // Test: Unstar without existing star returns NO_EXISTING_STAR (404)
    // Requirements: 15.2
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_unstar_without_star_returns_404() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "unstar".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body,
        };
        let signature = sign_envelope(&signing_key, &envelope);

        let request_body = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:unstar", repo_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            status, 404,
            "Unstar without existing star should return 404"
        );
    }

    // =========================================================================
    // Test: Star/unstar round-trip preserves original count
    // Requirements: 14.5, 15.4
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_star_unstar_roundtrip_preserves_count() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;

        // Get initial count
        let initial_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(&pool)
                .await
                .expect("Query should succeed");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // Star
        let star_nonce = uuid::Uuid::new_v4().to_string();
        let star_body = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let star_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: star_nonce.clone(),
            body: star_body,
        };
        let star_signature = sign_envelope(&signing_key, &star_envelope);

        let star_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": star_envelope.timestamp,
            "nonce": star_nonce,
            "signature": star_signature,
        });

        let star_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&star_request)
            .to_request();
        let star_resp = test::call_service(&app, star_req).await;
        assert_eq!(star_resp.status(), 200, "Star should succeed");

        // Unstar
        let unstar_nonce = uuid::Uuid::new_v4().to_string();
        let unstar_body = serde_json::json!({
            "repoId": repo_id,
        });
        let unstar_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "unstar".to_string(),
            timestamp: Utc::now(),
            nonce: unstar_nonce.clone(),
            body: unstar_body,
        };
        let unstar_signature = sign_envelope(&signing_key, &unstar_envelope);

        let unstar_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": unstar_envelope.timestamp,
            "nonce": unstar_nonce,
            "signature": unstar_signature,
        });

        let unstar_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:unstar", repo_id))
            .set_json(&unstar_request)
            .to_request();
        let unstar_resp = test::call_service(&app, unstar_req).await;
        assert_eq!(unstar_resp.status(), 200, "Unstar should succeed");

        // Verify final count equals initial count
        let final_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &star_nonce).await;
        cleanup_idempotency(&pool, &agent_id, &unstar_nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;
        cleanup_test_agent(&pool, &owner_id).await;

        assert_eq!(
            final_count, initial_count,
            "Star/unstar round-trip should preserve original count"
        );
    }

    // =========================================================================
    // Test: Idempotent retry with same nonce returns cached response
    // Requirements: 14.7
    // Design: DR-11.1, DR-3.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_idempotent_retry_returns_cached_response() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
            "reason": "Test reason",
            "reasonPublic": true,
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&signing_key, &envelope);

        let request_body = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "reason": "Test reason",
            "reasonPublic": true,
        });

        // First request
        let req1 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request_body)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200, "First request should succeed");
        let body1_bytes = test::read_body(resp1).await;
        let response1: serde_json::Value = serde_json::from_slice(&body1_bytes).unwrap();

        // Second request with same nonce (idempotent retry)
        let req2 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request_body)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        let status2 = resp2.status();
        let body2_bytes = test::read_body(resp2).await;
        let response2: serde_json::Value = serde_json::from_slice(&body2_bytes).unwrap();

        // Verify star count is still 1 (not 2)
        let db_count: i32 =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(status2, 200, "Idempotent retry should return 200");
        assert_eq!(
            response1["data"]["starCount"], response2["data"]["starCount"],
            "Cached response should match original"
        );
        assert_eq!(
            db_count, 1,
            "Star count should be 1 (not incremented twice)"
        );
    }

    // =========================================================================
    // Test: GET stars returns count and starredBy list
    // Requirements: 16.1, 16.2
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_get_stars_returns_count_and_list() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // Star the repo
        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "reason": "Great project!",
            "reasonPublic": true,
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&signing_key, &envelope);

        let star_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "reason": "Great project!",
            "reasonPublic": true,
        });

        let star_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&star_request)
            .to_request();
        let star_resp = test::call_service(&app, star_req).await;
        assert_eq!(star_resp.status(), 200, "Star should succeed");

        // GET stars
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/stars", repo_id))
            .to_request();
        let get_resp = test::call_service(&app, get_req).await;
        let get_status = get_resp.status();
        let get_body_bytes = test::read_body(get_resp).await;
        let get_response: serde_json::Value = serde_json::from_slice(&get_body_bytes).unwrap();

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;
        cleanup_test_agent(&pool, &owner_id).await;

        assert_eq!(get_status, 200, "GET stars should succeed");
        assert_eq!(get_response["data"]["repoId"], repo_id);
        assert_eq!(get_response["data"]["starCount"], 1);
        assert!(
            get_response["data"]["starredBy"].is_array(),
            "starredBy should be an array"
        );
        assert_eq!(
            get_response["data"]["starredBy"].as_array().unwrap().len(),
            1
        );
        assert_eq!(get_response["data"]["starredBy"][0]["agentId"], agent_id);
    }

    // =========================================================================
    // Test: starredBy sorted by timestamp descending
    // Requirements: 16.3
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_starred_by_sorted_by_timestamp_desc() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create two agents
        let (agent1_id, _pk1, sk1) = create_test_agent(&pool).await;
        let (agent2_id, _pk2, sk2) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // First agent stars
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let body1 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope1 = SignatureEnvelope {
            agent_id: agent1_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };
        let signature1 = sign_envelope(&sk1, &envelope1);

        let request1 = serde_json::json!({
            "agentId": agent1_id,
            "timestamp": envelope1.timestamp,
            "nonce": nonce1,
            "signature": signature1,
        });

        let req1 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request1)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200, "First star should succeed");

        // Small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Second agent stars (later)
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let body2 = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let envelope2 = SignatureEnvelope {
            agent_id: agent2_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };
        let signature2 = sign_envelope(&sk2, &envelope2);

        let request2 = serde_json::json!({
            "agentId": agent2_id,
            "timestamp": envelope2.timestamp,
            "nonce": nonce2,
            "signature": signature2,
        });

        let req2 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request2)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        assert_eq!(resp2.status(), 200, "Second star should succeed");

        // GET stars
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/stars", repo_id))
            .to_request();
        let get_resp = test::call_service(&app, get_req).await;
        let get_body_bytes = test::read_body(get_resp).await;
        let get_response: serde_json::Value = serde_json::from_slice(&get_body_bytes).unwrap();

        // Cleanup
        cleanup_idempotency(&pool, &agent1_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent2_id, &nonce2).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent1_id).await;
        cleanup_test_agent(&pool, &agent2_id).await;
        cleanup_test_agent(&pool, &owner_id).await;

        let starred_by = get_response["data"]["starredBy"].as_array().unwrap();
        assert_eq!(starred_by.len(), 2, "Should have 2 stars");
        // Most recent (agent2) should be first
        assert_eq!(
            starred_by[0]["agentId"], agent2_id,
            "Most recent star should be first"
        );
        assert_eq!(
            starred_by[1]["agentId"], agent1_id,
            "Older star should be second"
        );
    }

    // =========================================================================
    // Test: Only public reasons included in response
    // Requirements: 16.4
    // Design: DR-11.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_only_public_reasons_included() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, _owner_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &owner_id).await;

        // Create two agents
        let (agent1_id, _pk1, sk1) = create_test_agent(&pool).await;
        let (agent2_id, _pk2, sk2) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // First agent stars with PUBLIC reason
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let body1 = serde_json::json!({
            "repoId": repo_id,
            "reason": "Public reason",
            "reasonPublic": true,
        });
        let envelope1 = SignatureEnvelope {
            agent_id: agent1_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };
        let signature1 = sign_envelope(&sk1, &envelope1);

        let request1 = serde_json::json!({
            "agentId": agent1_id,
            "timestamp": envelope1.timestamp,
            "nonce": nonce1,
            "signature": signature1,
            "reason": "Public reason",
            "reasonPublic": true,
        });

        let req1 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request1)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200, "First star should succeed");

        // Second agent stars with PRIVATE reason
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let body2 = serde_json::json!({
            "repoId": repo_id,
            "reason": "Private reason",
            "reasonPublic": false,
        });
        let envelope2 = SignatureEnvelope {
            agent_id: agent2_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };
        let signature2 = sign_envelope(&sk2, &envelope2);

        let request2 = serde_json::json!({
            "agentId": agent2_id,
            "timestamp": envelope2.timestamp,
            "nonce": nonce2,
            "signature": signature2,
            "reason": "Private reason",
            "reasonPublic": false,
        });

        let req2 = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&request2)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        assert_eq!(resp2.status(), 200, "Second star should succeed");

        // GET stars
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/stars", repo_id))
            .to_request();
        let get_resp = test::call_service(&app, get_req).await;
        let get_body_bytes = test::read_body(get_resp).await;
        let get_response: serde_json::Value = serde_json::from_slice(&get_body_bytes).unwrap();

        // Cleanup
        cleanup_idempotency(&pool, &agent1_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent2_id, &nonce2).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent1_id).await;
        cleanup_test_agent(&pool, &agent2_id).await;
        cleanup_test_agent(&pool, &owner_id).await;

        let starred_by = get_response["data"]["starredBy"].as_array().unwrap();
        assert_eq!(starred_by.len(), 2, "Should have 2 stars");

        // Find the entries by agent_id
        let agent1_entry = starred_by
            .iter()
            .find(|e| e["agentId"] == agent1_id)
            .unwrap();
        let agent2_entry = starred_by
            .iter()
            .find(|e| e["agentId"] == agent2_id)
            .unwrap();

        assert_eq!(
            agent1_entry["reason"], "Public reason",
            "Public reason should be visible"
        );
        assert!(
            agent2_entry["reason"].is_null(),
            "Private reason should be null"
        );
    }

    // =========================================================================
    // Test: Audit events recorded for star and unstar
    // Requirements: 14.4, 15.3
    // Design: DR-11.1, DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_audit_events_recorded_for_star_unstar() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_star_routes)),
        )
        .await;

        // Star
        let star_nonce = uuid::Uuid::new_v4().to_string();
        let star_body = serde_json::json!({
            "repoId": repo_id,
            "reason": serde_json::Value::Null,
            "reasonPublic": false,
        });
        let star_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: star_nonce.clone(),
            body: star_body,
        };
        let star_signature = sign_envelope(&signing_key, &star_envelope);

        let star_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": star_envelope.timestamp,
            "nonce": star_nonce,
            "signature": star_signature,
        });

        let star_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:star", repo_id))
            .set_json(&star_request)
            .to_request();
        let star_resp = test::call_service(&app, star_req).await;
        assert_eq!(star_resp.status(), 200, "Star should succeed");

        // Check audit log for star event
        let star_audit: Option<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE agent_id = $1 AND action = 'star' AND resource_id = $2"
        )
        .bind(&agent_id)
        .bind(&repo_id)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        assert!(star_audit.is_some(), "Star audit event should be recorded");

        // Unstar
        let unstar_nonce = uuid::Uuid::new_v4().to_string();
        let unstar_body = serde_json::json!({
            "repoId": repo_id,
        });
        let unstar_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "unstar".to_string(),
            timestamp: Utc::now(),
            nonce: unstar_nonce.clone(),
            body: unstar_body,
        };
        let unstar_signature = sign_envelope(&signing_key, &unstar_envelope);

        let unstar_request = serde_json::json!({
            "agentId": agent_id,
            "timestamp": unstar_envelope.timestamp,
            "nonce": unstar_nonce,
            "signature": unstar_signature,
        });

        let unstar_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/stars/:unstar", repo_id))
            .set_json(&unstar_request)
            .to_request();
        let unstar_resp = test::call_service(&app, unstar_req).await;
        assert_eq!(unstar_resp.status(), 200, "Unstar should succeed");

        // Check audit log for unstar event
        let unstar_audit: Option<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE agent_id = $1 AND action = 'unstar' AND resource_id = $2"
        )
        .bind(&agent_id)
        .bind(&repo_id)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup audit logs
        let _ = sqlx::query("DELETE FROM audit_log WHERE agent_id = $1 AND resource_id = $2")
            .bind(&agent_id)
            .bind(&repo_id)
            .execute(&pool)
            .await;

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &star_nonce).await;
        cleanup_idempotency(&pool, &agent_id, &unstar_nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            unstar_audit.is_some(),
            "Unstar audit event should be recorded"
        );
    }
}

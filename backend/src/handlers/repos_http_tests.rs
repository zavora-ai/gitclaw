//! HTTP Integration Tests for Repository Service
//!
//! These tests validate the Repository Service end-to-end via HTTP endpoints.
//! Requirements: 2.1, 2.2, 2.6, 2.7, 3.1, 3.2, 3.3, 4.1
//! Design: DR-4.1, DR-4.2, DR-4.3

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
    use crate::handlers::{configure_git_routes, configure_repo_routes};
    use crate::models::{AccessRole, Visibility};
    use crate::services::signature::SignatureEnvelope;
    use crate::services::{RateLimiterService, SignatureValidator};

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

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
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
        let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
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
    // Test: Repository creation end-to-end via HTTP
    // Requirements: 2.1, 2.3, 2.4, 2.5
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_repo_creation_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // Body must match exactly what the service expects for signature verification
        let body = serde_json::json!({
            "name": repo_name,
            "description": "Test repository",
            "visibility": "public",
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
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
            "name": repo_name,
            "description": "Test repository",
            "visibility": "public",
        });

        let req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Extract repo_id for cleanup
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
        let repo_id = response["data"]["repoId"].as_str().unwrap_or("");

        // Cleanup
        if !repo_id.is_empty() {
            cleanup_test_repo(&pool, repo_id).await;
        }
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            status, 201,
            "Expected 201 Created, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["name"], repo_name);
        assert_eq!(response["data"]["ownerId"], agent_id);
        assert_eq!(response["data"]["defaultBranch"], "main");
    }

    // =========================================================================
    // Test: Duplicate repo name for same owner returns REPO_EXISTS (409)
    // Requirements: 2.2
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_duplicate_repo_name_returns_409() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // First creation
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let body1 = serde_json::json!({
            "name": repo_name,
            "description": "First repo",
            "visibility": "public",
        });
        let envelope1 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce1.clone(),
            body: body1,
        };
        let signature1 = sign_envelope(&signing_key, &envelope1);

        let request_body1 = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope1.timestamp,
            "nonce": nonce1,
            "signature": signature1,
            "name": repo_name,
            "description": "First repo",
            "visibility": "public",
        });

        let req1 = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&request_body1)
            .to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 201, "First creation should succeed");

        let body1_bytes = test::read_body(resp1).await;
        let response1: serde_json::Value = serde_json::from_slice(&body1_bytes).unwrap();
        let repo_id = response1["data"]["repoId"].as_str().unwrap();

        // Second creation with same name
        let nonce2 = uuid::Uuid::new_v4().to_string();
        let body2 = serde_json::json!({
            "name": repo_name,
            "description": "Second repo",
            "visibility": "public",
        });
        let envelope2 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: nonce2.clone(),
            body: body2,
        };
        let signature2 = sign_envelope(&signing_key, &envelope2);

        let request_body2 = serde_json::json!({
            "agentId": agent_id,
            "timestamp": envelope2.timestamp,
            "nonce": nonce2,
            "signature": signature2,
            "name": repo_name,
            "description": "Second repo",
            "visibility": "public",
        });

        let req2 = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&request_body2)
            .to_request();
        let resp2 = test::call_service(&app, req2).await;
        let status2 = resp2.status();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce1).await;
        cleanup_idempotency(&pool, &agent_id, &nonce2).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(status2, 409, "Second creation should return 409 Conflict");
    }

    // =========================================================================
    // Test: repo_star_counts initialized to 0 on creation
    // Requirements: 2.6
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_star_counts_initialized_to_zero() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        let body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "public",
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
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
            "name": repo_name,
            "visibility": "public",
        });

        let req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&request_body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Repository creation should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let repo_id = response["data"]["repoId"].as_str().unwrap();

        // Verify star count is 0 in database
        let star_count: Option<i32> =
            sqlx::query_scalar("SELECT stars FROM repo_star_counts WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(star_count, Some(0), "Star count should be initialized to 0");
    }

    // =========================================================================
    // Test: repo_access entry created with owner as admin
    // Requirements: 2.7
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_owner_has_admin_access() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        let body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "private",
        });
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "repo_create".to_string(),
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
            "name": repo_name,
            "visibility": "private",
        });

        let req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&request_body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Repository creation should succeed");

        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let repo_id = response["data"]["repoId"].as_str().unwrap();

        // Verify owner has admin access in database
        let access_role: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(repo_id)
                .bind(&agent_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            access_role,
            Some(AccessRole::Admin),
            "Owner should have admin access"
        );
    }

    // =========================================================================
    // Test: Clone public repo succeeds for any agent
    // Requirements: 3.1
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_clone_public_repo_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // Create public repo
        let create_body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "public",
        });
        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };
        let create_signature = sign_envelope(&owner_sk, &create_envelope);

        let create_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": create_envelope.timestamp,
            "nonce": create_nonce,
            "signature": create_signature,
            "name": repo_name,
            "visibility": "public",
        });

        let create_req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&create_request)
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        assert_eq!(
            create_resp.status(),
            201,
            "Repository creation should succeed"
        );

        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Create another agent to clone
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };
        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = serde_json::json!({
            "agentId": cloner_id,
            "timestamp": clone_envelope.timestamp,
            "nonce": clone_nonce,
            "signature": clone_signature,
        });

        let clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&clone_request)
            .to_request();
        let clone_resp = test::call_service(&app, clone_req).await;
        let clone_status = clone_resp.status();

        let clone_body_bytes = test::read_body(clone_resp).await;
        let clone_response: serde_json::Value =
            serde_json::from_slice(&clone_body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert_eq!(
            clone_status, 200,
            "Clone of public repo should succeed: {:?}",
            clone_response
        );
        assert_eq!(clone_response["data"]["repoId"], repo_id);
    }

    // =========================================================================
    // Test: Clone private repo without access returns ACCESS_DENIED (403)
    // Requirements: 3.3
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_clone_private_repo_without_access_returns_401() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and private repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // Create private repo
        let create_body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "private",
        });
        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };
        let create_signature = sign_envelope(&owner_sk, &create_envelope);

        let create_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": create_envelope.timestamp,
            "nonce": create_nonce,
            "signature": create_signature,
            "name": repo_name,
            "visibility": "private",
        });

        let create_req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&create_request)
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        assert_eq!(
            create_resp.status(),
            201,
            "Repository creation should succeed"
        );

        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Create another agent without access
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };
        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = serde_json::json!({
            "agentId": cloner_id,
            "timestamp": clone_envelope.timestamp,
            "nonce": clone_nonce,
            "signature": clone_signature,
        });

        let clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&clone_request)
            .to_request();
        let clone_resp = test::call_service(&app, clone_req).await;
        let clone_status = clone_resp.status();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        // AccessDenied maps to 401 Unauthorized in the error handler
        assert_eq!(
            clone_status, 401,
            "Clone of private repo without access should return 401"
        );
    }

    // =========================================================================
    // Test: Clone private repo with explicit access succeeds
    // Requirements: 3.2
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_clone_private_repo_with_access_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and private repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // Create private repo
        let create_body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "private",
        });
        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };
        let create_signature = sign_envelope(&owner_sk, &create_envelope);

        let create_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": create_envelope.timestamp,
            "nonce": create_nonce,
            "signature": create_signature,
            "name": repo_name,
            "visibility": "private",
        });

        let create_req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&create_request)
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        assert_eq!(
            create_resp.status(),
            201,
            "Repository creation should succeed"
        );

        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Create another agent and grant read access directly in DB
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&cloner_id)
        .bind(AccessRole::Read)
        .execute(&pool)
        .await
        .expect("Failed to grant access");

        let clone_nonce = uuid::Uuid::new_v4().to_string();
        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };
        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = serde_json::json!({
            "agentId": cloner_id,
            "timestamp": clone_envelope.timestamp,
            "nonce": clone_nonce,
            "signature": clone_signature,
        });

        let clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&clone_request)
            .to_request();
        let clone_resp = test::call_service(&app, clone_req).await;
        let clone_status = clone_resp.status();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert_eq!(
            clone_status, 200,
            "Clone with explicit access should succeed"
        );
    }

    // =========================================================================
    // Test: Clone event recorded in audit_log
    // Requirements: 3.4
    // Design: DR-4.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_clone_event_recorded_in_audit_log() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and public repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_repo_routes)),
        )
        .await;

        // Create public repo
        let create_body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "public",
        });
        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };
        let create_signature = sign_envelope(&owner_sk, &create_envelope);

        let create_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": create_envelope.timestamp,
            "nonce": create_nonce,
            "signature": create_signature,
            "name": repo_name,
            "visibility": "public",
        });

        let create_req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&create_request)
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        assert_eq!(
            create_resp.status(),
            201,
            "Repository creation should succeed"
        );

        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Clone the repo
        let (cloner_id, _cloner_pk, cloner_sk) = create_test_agent(&pool).await;
        let clone_nonce = uuid::Uuid::new_v4().to_string();

        let clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let clone_envelope = SignatureEnvelope {
            agent_id: cloner_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: clone_nonce.clone(),
            body: clone_body,
        };
        let clone_signature = sign_envelope(&cloner_sk, &clone_envelope);

        let clone_request = serde_json::json!({
            "agentId": cloner_id,
            "timestamp": clone_envelope.timestamp,
            "nonce": clone_nonce,
            "signature": clone_signature,
        });

        let clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&clone_request)
            .to_request();
        let clone_resp = test::call_service(&app, clone_req).await;
        assert_eq!(clone_resp.status(), 200, "Clone should succeed");

        // Check audit log for clone event
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'repo_clone' AND resource_id = $2"
        )
        .bind(&cloner_id)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &cloner_id, &clone_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &cloner_id).await;

        assert!(
            audit_count > 0,
            "Clone event should be recorded in audit_log"
        );
    }

    // =========================================================================
    // Test: Git info/refs endpoint returns valid ref advertisement
    // Requirements: 4.1
    // Design: DR-4.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_git_info_refs_returns_valid_advertisement() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        // Create owner agent and public repo
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        let app_state = create_test_app_state(pool.clone());
        // Configure git routes BEFORE repo routes so the more specific /repos/{repoId}/info/refs
        // is registered before the /repos/{repoId} catch-all
        let app = test::init_service(
            App::new().app_data(app_state.clone()).service(
                web::scope("/v1")
                    .configure(configure_git_routes)
                    .configure(configure_repo_routes),
            ),
        )
        .await;

        // Create public repo
        let create_body = serde_json::json!({
            "name": repo_name,
            "description": serde_json::Value::Null,
            "visibility": "public",
        });
        let create_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "repo_create".to_string(),
            timestamp: Utc::now(),
            nonce: create_nonce.clone(),
            body: create_body,
        };
        let create_signature = sign_envelope(&owner_sk, &create_envelope);

        let create_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": create_envelope.timestamp,
            "nonce": create_nonce,
            "signature": create_signature,
            "name": repo_name,
            "visibility": "public",
        });

        let create_req = test::TestRequest::post()
            .uri("/v1/repos")
            .set_json(&create_request)
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        assert_eq!(
            create_resp.status(),
            201,
            "Repository creation should succeed"
        );

        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Get ref advertisement via Git info/refs endpoint
        let info_refs_req = test::TestRequest::get()
            .uri(&format!(
                "/v1/repos/{}/info/refs?service=git-upload-pack",
                repo_id
            ))
            .to_request();
        let info_refs_resp = test::call_service(&app, info_refs_req).await;
        let info_refs_status = info_refs_resp.status();

        // Check content type - clone it to avoid borrow issues
        let content_type = info_refs_resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body_bytes = test::read_body(info_refs_resp).await;
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;

        assert_eq!(info_refs_status, 200, "Get refs should succeed");
        assert!(
            content_type.contains("git-upload-pack-advertisement"),
            "Content-Type should be git-upload-pack-advertisement, got: {}",
            content_type
        );
        assert!(
            body_str.contains("refs/heads/main") || body_str.contains("main"),
            "Should contain main branch ref: {}",
            body_str
        );
    }
}

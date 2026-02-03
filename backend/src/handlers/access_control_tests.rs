//! HTTP Integration Tests for Access Control Service
//!
//! These tests validate the Access Control endpoints end-to-end via HTTP.
//! Requirements: 18.1, 18.2, 18.3, 18.4
//! Design: DR-4.1 (Repository Service - Access Control)

#[cfg(test)]
mod access_control_integration_tests {
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
    use crate::handlers::{configure_access_routes, configure_repo_routes};
    use crate::models::AccessRole;
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
    // Test: Grant access creates repo_access entry with correct role
    // Requirements: 18.1, 18.3
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_grant_access_creates_entry_with_correct_role() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (target_id, _target_pk, _target_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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

        // Grant write access to target agent
        let grant_nonce = uuid::Uuid::new_v4().to_string();
        let grant_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_id,
            "role": "write",
        });
        let grant_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "access_grant".to_string(),
            timestamp: Utc::now(),
            nonce: grant_nonce.clone(),
            body: grant_body,
        };
        let grant_signature = sign_envelope(&owner_sk, &grant_envelope);
        let grant_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": grant_envelope.timestamp,
            "nonce": grant_nonce,
            "signature": grant_signature,
            "targetAgentId": target_id,
            "role": "write",
        });
        let grant_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/access", repo_id))
            .set_json(&grant_request)
            .to_request();
        let grant_resp = test::call_service(&app, grant_req).await;
        let grant_status = grant_resp.status();

        // Verify the access entry was created with correct role
        let access_role: Option<AccessRole> =
            sqlx::query_scalar("SELECT role FROM repo_access WHERE repo_id = $1 AND agent_id = $2")
                .bind(repo_id)
                .bind(&target_id)
                .fetch_optional(&pool)
                .await
                .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &owner_id, &grant_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &target_id).await;

        assert_eq!(grant_status, 200, "Grant access should succeed");
        assert_eq!(
            access_role,
            Some(AccessRole::Write),
            "Access role should be write"
        );
    }

    // =========================================================================
    // Test: Revoke access removes repo_access entry
    // Requirements: 18.3
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_revoke_access_removes_entry() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (target_id, _target_pk, _target_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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
        assert_eq!(create_resp.status(), 201);
        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Grant access first
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&target_id)
        .bind(AccessRole::Read)
        .execute(&pool)
        .await
        .expect("Failed to grant access");

        // Verify access exists
        let before_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repo_access WHERE repo_id = $1 AND agent_id = $2",
        )
        .bind(repo_id)
        .bind(&target_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");
        assert_eq!(before_count, 1, "Access should exist before revoke");

        // Revoke access
        let revoke_nonce = uuid::Uuid::new_v4().to_string();
        let revoke_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_id,
        });
        let revoke_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "access_revoke".to_string(),
            timestamp: Utc::now(),
            nonce: revoke_nonce.clone(),
            body: revoke_body,
        };
        let revoke_signature = sign_envelope(&owner_sk, &revoke_envelope);
        let revoke_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": revoke_envelope.timestamp,
            "nonce": revoke_nonce,
            "signature": revoke_signature,
        });
        let revoke_req = test::TestRequest::delete()
            .uri(&format!("/v1/repos/{}/access/{}", repo_id, target_id))
            .set_json(&revoke_request)
            .to_request();
        let revoke_resp = test::call_service(&app, revoke_req).await;
        let revoke_status = revoke_resp.status();

        // Verify access was removed
        let after_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repo_access WHERE repo_id = $1 AND agent_id = $2",
        )
        .bind(repo_id)
        .bind(&target_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &owner_id, &revoke_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &target_id).await;

        assert_eq!(revoke_status, 200, "Revoke access should succeed");
        assert_eq!(after_count, 0, "Access should be removed after revoke");
    }

    // =========================================================================
    // Test: List collaborators returns all agents with access
    // Requirements: 18.1
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_list_collaborators_returns_all_agents() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (agent2_id, _agent2_pk, _agent2_sk) = create_test_agent(&pool).await;
        let (agent3_id, _agent3_pk, _agent3_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo (owner gets admin access automatically)
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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
        assert_eq!(create_resp.status(), 201);
        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Grant access to additional agents
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&agent2_id)
        .bind(AccessRole::Write)
        .execute(&pool)
        .await
        .expect("Failed to grant access to agent2");

        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&agent3_id)
        .bind(AccessRole::Read)
        .execute(&pool)
        .await
        .expect("Failed to grant access to agent3");

        // List collaborators
        let list_nonce = uuid::Uuid::new_v4().to_string();
        let list_body = serde_json::json!({
            "repoId": repo_id,
        });
        let list_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "access_list".to_string(),
            timestamp: Utc::now(),
            nonce: list_nonce.clone(),
            body: list_body,
        };
        let list_signature = sign_envelope(&owner_sk, &list_envelope);
        let list_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": list_envelope.timestamp,
            "nonce": list_nonce,
            "signature": list_signature,
        });
        let list_req = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/access", repo_id))
            .set_json(&list_request)
            .to_request();
        let list_resp = test::call_service(&app, list_req).await;
        let list_status = list_resp.status();
        let body_bytes = test::read_body(list_resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &agent2_id).await;
        cleanup_test_agent(&pool, &agent3_id).await;

        assert_eq!(
            list_status, 200,
            "List collaborators should succeed: {:?}",
            response
        );
        let collaborators = response["data"]["collaborators"].as_array().unwrap();
        assert_eq!(
            collaborators.len(),
            3,
            "Should have 3 collaborators (owner + 2 granted)"
        );
    }

    // =========================================================================
    // Test: Only admin can grant/revoke access
    // Requirements: 18.3
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_only_admin_can_grant_access() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (writer_id, _writer_pk, writer_sk) = create_test_agent(&pool).await;
        let (target_id, _target_pk, _target_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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
        assert_eq!(create_resp.status(), 201);
        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Grant write access to writer (not admin)
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&writer_id)
        .bind(AccessRole::Write)
        .execute(&pool)
        .await
        .expect("Failed to grant write access");

        // Writer tries to grant access to target - should fail
        let grant_nonce = uuid::Uuid::new_v4().to_string();
        let grant_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_id,
            "role": "read",
        });
        let grant_envelope = SignatureEnvelope {
            agent_id: writer_id.clone(),
            action: "access_grant".to_string(),
            timestamp: Utc::now(),
            nonce: grant_nonce.clone(),
            body: grant_body,
        };
        let grant_signature = sign_envelope(&writer_sk, &grant_envelope);
        let grant_request = serde_json::json!({
            "agentId": writer_id,
            "timestamp": grant_envelope.timestamp,
            "nonce": grant_nonce,
            "signature": grant_signature,
            "targetAgentId": target_id,
            "role": "read",
        });
        let grant_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/access", repo_id))
            .set_json(&grant_request)
            .to_request();
        let grant_resp = test::call_service(&app, grant_req).await;
        let grant_status = grant_resp.status();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &writer_id, &grant_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &writer_id).await;
        cleanup_test_agent(&pool, &target_id).await;

        // AccessDenied maps to 401 Unauthorized
        assert_eq!(
            grant_status, 401,
            "Non-admin should not be able to grant access"
        );
    }

    // =========================================================================
    // Test: Audit events recorded for grant and revoke
    // Requirements: 18.4
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_audit_events_recorded_for_access_changes() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (target_id, _target_pk, _target_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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
        assert_eq!(create_resp.status(), 201);
        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Grant access
        let grant_nonce = uuid::Uuid::new_v4().to_string();
        let grant_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_id,
            "role": "write",
        });
        let grant_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "access_grant".to_string(),
            timestamp: Utc::now(),
            nonce: grant_nonce.clone(),
            body: grant_body,
        };
        let grant_signature = sign_envelope(&owner_sk, &grant_envelope);
        let grant_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": grant_envelope.timestamp,
            "nonce": grant_nonce,
            "signature": grant_signature,
            "targetAgentId": target_id,
            "role": "write",
        });
        let grant_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/access", repo_id))
            .set_json(&grant_request)
            .to_request();
        let grant_resp = test::call_service(&app, grant_req).await;
        assert_eq!(grant_resp.status(), 200, "Grant should succeed");

        // Check audit log for grant event
        let grant_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'access_grant' AND resource_id = $2"
        )
        .bind(&owner_id)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Revoke access
        let revoke_nonce = uuid::Uuid::new_v4().to_string();
        let revoke_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": target_id,
        });
        let revoke_envelope = SignatureEnvelope {
            agent_id: owner_id.clone(),
            action: "access_revoke".to_string(),
            timestamp: Utc::now(),
            nonce: revoke_nonce.clone(),
            body: revoke_body,
        };
        let revoke_signature = sign_envelope(&owner_sk, &revoke_envelope);
        let revoke_request = serde_json::json!({
            "agentId": owner_id,
            "timestamp": revoke_envelope.timestamp,
            "nonce": revoke_nonce,
            "signature": revoke_signature,
        });
        let revoke_req = test::TestRequest::delete()
            .uri(&format!("/v1/repos/{}/access/{}", repo_id, target_id))
            .set_json(&revoke_request)
            .to_request();
        let revoke_resp = test::call_service(&app, revoke_req).await;
        assert_eq!(revoke_resp.status(), 200, "Revoke should succeed");

        // Check audit log for revoke event
        let revoke_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id = $1 AND action = 'access_revoke' AND resource_id = $2"
        )
        .bind(&owner_id)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &owner_id, &grant_nonce).await;
        cleanup_idempotency(&pool, &owner_id, &revoke_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &target_id).await;

        assert!(
            grant_audit_count > 0,
            "Grant event should be recorded in audit_log"
        );
        assert!(
            revoke_audit_count > 0,
            "Revoke event should be recorded in audit_log"
        );
    }

    // =========================================================================
    // Test: Access check respects role hierarchy (admin > write > read)
    // Requirements: 18.2
    // Design: DR-4.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_access_check_respects_role_hierarchy() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (owner_id, _owner_pk, owner_sk) = create_test_agent(&pool).await;
        let (reader_id, _reader_pk, reader_sk) = create_test_agent(&pool).await;
        let (writer_id, _writer_pk, writer_sk) = create_test_agent(&pool).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_access_routes).configure(configure_repo_routes)),
        )
        .await;

        // Create a private repo
        let create_nonce = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());
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
        assert_eq!(create_resp.status(), 201);
        let create_body_bytes = test::read_body(create_resp).await;
        let create_response: serde_json::Value =
            serde_json::from_slice(&create_body_bytes).unwrap();
        let repo_id = create_response["data"]["repoId"].as_str().unwrap();

        // Grant read access to reader
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&reader_id)
        .bind(AccessRole::Read)
        .execute(&pool)
        .await
        .expect("Failed to grant read access");

        // Grant write access to writer
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(repo_id)
        .bind(&writer_id)
        .bind(AccessRole::Write)
        .execute(&pool)
        .await
        .expect("Failed to grant write access");

        // Reader can clone (read access)
        let reader_clone_nonce = uuid::Uuid::new_v4().to_string();
        let reader_clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let reader_clone_envelope = SignatureEnvelope {
            agent_id: reader_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: reader_clone_nonce.clone(),
            body: reader_clone_body,
        };
        let reader_clone_signature = sign_envelope(&reader_sk, &reader_clone_envelope);
        let reader_clone_request = serde_json::json!({
            "agentId": reader_id,
            "timestamp": reader_clone_envelope.timestamp,
            "nonce": reader_clone_nonce,
            "signature": reader_clone_signature,
        });
        let reader_clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&reader_clone_request)
            .to_request();
        let reader_clone_resp = test::call_service(&app, reader_clone_req).await;
        let reader_clone_status = reader_clone_resp.status();

        // Writer can also clone (write includes read)
        let writer_clone_nonce = uuid::Uuid::new_v4().to_string();
        let writer_clone_body = serde_json::json!({
            "repoId": repo_id,
            "depth": serde_json::Value::Null,
        });
        let writer_clone_envelope = SignatureEnvelope {
            agent_id: writer_id.clone(),
            action: "repo_clone".to_string(),
            timestamp: Utc::now(),
            nonce: writer_clone_nonce.clone(),
            body: writer_clone_body,
        };
        let writer_clone_signature = sign_envelope(&writer_sk, &writer_clone_envelope);
        let writer_clone_request = serde_json::json!({
            "agentId": writer_id,
            "timestamp": writer_clone_envelope.timestamp,
            "nonce": writer_clone_nonce,
            "signature": writer_clone_signature,
        });
        let writer_clone_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/clone", repo_id))
            .set_json(&writer_clone_request)
            .to_request();
        let writer_clone_resp = test::call_service(&app, writer_clone_req).await;
        let writer_clone_status = writer_clone_resp.status();

        // Reader cannot grant access (requires admin)
        let reader_grant_nonce = uuid::Uuid::new_v4().to_string();
        let reader_grant_body = serde_json::json!({
            "repoId": repo_id,
            "targetAgentId": writer_id,
            "role": "read",
        });
        let reader_grant_envelope = SignatureEnvelope {
            agent_id: reader_id.clone(),
            action: "access_grant".to_string(),
            timestamp: Utc::now(),
            nonce: reader_grant_nonce.clone(),
            body: reader_grant_body,
        };
        let reader_grant_signature = sign_envelope(&reader_sk, &reader_grant_envelope);
        let reader_grant_request = serde_json::json!({
            "agentId": reader_id,
            "timestamp": reader_grant_envelope.timestamp,
            "nonce": reader_grant_nonce,
            "signature": reader_grant_signature,
            "targetAgentId": writer_id,
            "role": "read",
        });
        let reader_grant_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/access", repo_id))
            .set_json(&reader_grant_request)
            .to_request();
        let reader_grant_resp = test::call_service(&app, reader_grant_req).await;
        let reader_grant_status = reader_grant_resp.status();

        // Cleanup
        cleanup_test_repo(&pool, repo_id).await;
        cleanup_idempotency(&pool, &owner_id, &create_nonce).await;
        cleanup_idempotency(&pool, &reader_id, &reader_clone_nonce).await;
        cleanup_idempotency(&pool, &writer_id, &writer_clone_nonce).await;
        cleanup_idempotency(&pool, &reader_id, &reader_grant_nonce).await;
        cleanup_test_agent(&pool, &owner_id).await;
        cleanup_test_agent(&pool, &reader_id).await;
        cleanup_test_agent(&pool, &writer_id).await;

        assert_eq!(reader_clone_status, 200, "Reader should be able to clone");
        assert_eq!(
            writer_clone_status, 200,
            "Writer should be able to clone (write includes read)"
        );
        assert_eq!(
            reader_grant_status, 401,
            "Reader should not be able to grant access (requires admin)"
        );
    }
}

//! HTTP Integration Tests for Pull Request Service
//!
//! These tests validate the Pull Request Service end-to-end via HTTP endpoints.
//! Requirements: 6.1, 6.2, 7.1, 7.4, 8.1, 8.2, 8.3, 8.6
//! Design: DR-7.1, DR-7.2, DR-7.3

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
    use crate::handlers::configure_pull_routes;
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

    /// Create a test repository with branches
    async fn create_test_repo_with_branches(pool: &PgPool, owner_id: &str) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        // Create repository
        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, 'Test repository', 'public', 'main', NOW())
            "#,
        )
        .bind(&repo_id)
        .bind(owner_id)
        .bind(&repo_name)
        .execute(pool)
        .await
        .expect("Failed to create test repository");

        // Initialize star counts
        sqlx::query(
            "INSERT INTO repo_star_counts (repo_id, stars, updated_at) VALUES ($1, 0, NOW())",
        )
        .bind(&repo_id)
        .execute(pool)
        .await
        .expect("Failed to create star counts");

        // Create repo_access for owner
        sqlx::query(
            "INSERT INTO repo_access (repo_id, agent_id, role, created_at) VALUES ($1, $2, $3, NOW())"
        )
        .bind(&repo_id)
        .bind(owner_id)
        .bind(AccessRole::Admin)
        .execute(pool)
        .await
        .expect("Failed to create repo access");

        // Create main branch ref
        sqlx::query(
            "INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at) VALUES ($1, $2, $3, NOW())",
        )
        .bind(&repo_id)
        .bind("refs/heads/main")
        .bind("0000000000000000000000000000000000000001")
        .execute(pool)
        .await
        .expect("Failed to create main branch ref");

        // Create feature branch ref
        sqlx::query(
            "INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at) VALUES ($1, $2, $3, NOW())",
        )
        .bind(&repo_id)
        .bind("refs/heads/feature")
        .bind("0000000000000000000000000000000000000002")
        .execute(pool)
        .await
        .expect("Failed to create feature branch ref");

        repo_id
    }

    /// Clean up test agent and related data
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        let _ = sqlx::query("DELETE FROM reviews WHERE reviewer_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM pull_requests WHERE author_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
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

    /// Clean up test repository
    async fn cleanup_test_repo(pool: &PgPool, repo_id: &str) {
        let _ = sqlx::query("DELETE FROM reviews WHERE pr_id IN (SELECT pr_id FROM pull_requests WHERE repo_id = $1)")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM pull_requests WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
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
    // Test: PR creation end-to-end with valid source/target branches
    // Requirements: 6.1, 6.2
    // Design: DR-7.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_pr_creation_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
            "description": "Test description",
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "pr_create".to_string(),
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
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
            "description": "Test description",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls", repo_id))
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
            status, 201,
            "Expected 201 Created, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["sourceBranch"], "feature");
        assert_eq!(response["data"]["targetBranch"], "main");
        assert_eq!(response["data"]["title"], "Test PR");
        assert_eq!(response["data"]["status"], "open");
    }

    // =========================================================================
    // Test: PR creation with non-existent branch fails
    // Requirements: 6.5
    // Design: DR-7.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_pr_creation_nonexistent_branch_fails() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
            "sourceBranch": "nonexistent-branch",
            "targetBranch": "main",
            "title": "Test PR",
            "description": serde_json::Value::Null,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "pr_create".to_string(),
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
            "sourceBranch": "nonexistent-branch",
            "targetBranch": "main",
            "title": "Test PR",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls", repo_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &agent_id).await;

        assert_eq!(
            status, 400,
            "Expected 400 Bad Request for non-existent branch, got {}",
            status
        );
    }

    // =========================================================================
    // Test: Review submission records verdict and body
    // Requirements: 7.1, 7.2
    // Design: DR-7.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_review_submission_succeeds() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, _author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR first
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'pending', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": "approve",
            "body": "LGTM!",
        });

        let envelope = SignatureEnvelope {
            agent_id: reviewer_id.clone(),
            action: "pr_review".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&reviewer_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": reviewer_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "verdict": "approve",
            "body": "LGTM!",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/reviews", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_idempotency(&pool, &reviewer_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        assert_eq!(
            status, 201,
            "Expected 201 Created, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["verdict"], "approve");
        assert_eq!(response["data"]["body"], "LGTM!");
        assert_eq!(response["data"]["reviewerId"], reviewer_id);
    }

    // =========================================================================
    // Test: Self-approval (author reviewing own PR) is rejected
    // Requirements: 7.4
    // Design: DR-7.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_self_approval_rejected() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'pending', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": "approve",
            "body": "Self-approving",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_review".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "verdict": "approve",
            "body": "Self-approving",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/reviews", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;

        assert_eq!(
            status, 400,
            "Expected 400 Bad Request for self-approval, got {}",
            status
        );
    }

    // =========================================================================
    // Test: Merge succeeds when approved and CI passed
    // Requirements: 8.1
    // Design: DR-7.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_merge_succeeds_when_approved_and_ci_passed() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, _reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR with CI passed
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'passed', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        // Add an approval review
        let review_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
            VALUES ($1, $2, $3, 'approve', 'LGTM', NOW())
            "#,
        )
        .bind(&review_id)
        .bind(&pr_id)
        .bind(&reviewer_id)
        .execute(&pool)
        .await
        .expect("Failed to create review");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": "merge",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_merge".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "mergeStrategy": "merge",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/merge", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        assert_eq!(
            status, 200,
            "Expected 200 OK, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["mergeStrategy"], "merge");
        assert!(response["data"]["mergeCommitOid"].as_str().is_some());
    }

    // =========================================================================
    // Test: Merge without approval returns MERGE_BLOCKED (409)
    // Requirements: 8.1
    // Design: DR-7.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_merge_without_approval_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR with CI passed but no approval
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'passed', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": "merge",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_merge".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "mergeStrategy": "merge",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/merge", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;

        // NotApproved maps to 400 Validation error
        assert_eq!(
            status, 400,
            "Expected 400 Bad Request for merge without approval, got {}",
            status
        );
    }

    // =========================================================================
    // Test: Merge strategies (merge, squash, rebase) work correctly
    // Requirements: 8.2
    // Design: DR-7.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_merge_strategies_work() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, _reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Test squash strategy
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'passed', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let review_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
            VALUES ($1, $2, $3, 'approve', 'LGTM', NOW())
            "#,
        )
        .bind(&review_id)
        .bind(&pr_id)
        .bind(&reviewer_id)
        .execute(&pool)
        .await
        .expect("Failed to create review");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": "squash",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_merge".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "mergeStrategy": "squash",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/merge", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        assert_eq!(
            status, 200,
            "Expected 200 OK for squash merge, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["mergeStrategy"], "squash");
    }

    // =========================================================================
    // Test: Audit events recorded for PR create, review, merge
    // Requirements: 11.1
    // Design: DR-14.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_audit_events_recorded() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        // Create PR
        let pr_nonce = uuid::Uuid::new_v4().to_string();
        let pr_body = serde_json::json!({
            "repoId": repo_id,
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
            "description": serde_json::Value::Null,
        });

        let pr_envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_create".to_string(),
            timestamp: Utc::now(),
            nonce: pr_nonce.clone(),
            body: pr_body.clone(),
        };
        let pr_signature = sign_envelope(&author_sk, &pr_envelope);

        let pr_request = serde_json::json!({
            "agentId": author_id,
            "timestamp": pr_envelope.timestamp,
            "nonce": pr_nonce,
            "signature": pr_signature,
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
        });

        let pr_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls", repo_id))
            .set_json(&pr_request)
            .to_request();

        let pr_resp = test::call_service(&app, pr_req).await;
        assert_eq!(pr_resp.status(), 201, "PR creation should succeed");

        let pr_body_bytes = test::read_body(pr_resp).await;
        let pr_response: serde_json::Value = serde_json::from_slice(&pr_body_bytes).unwrap();
        let pr_id = pr_response["data"]["prId"].as_str().unwrap();

        // Check audit event for PR creation
        let pr_audit: Option<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE resource_id = $1 AND action = 'pr_create'",
        )
        .bind(pr_id)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

        assert!(
            pr_audit.is_some(),
            "Audit event should be recorded for PR creation"
        );

        // Submit review
        let review_nonce = uuid::Uuid::new_v4().to_string();
        let review_body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": "approve",
            "body": "LGTM",
        });

        let review_envelope = SignatureEnvelope {
            agent_id: reviewer_id.clone(),
            action: "pr_review".to_string(),
            timestamp: Utc::now(),
            nonce: review_nonce.clone(),
            body: review_body.clone(),
        };
        let review_signature = sign_envelope(&reviewer_sk, &review_envelope);

        let review_request = serde_json::json!({
            "agentId": reviewer_id,
            "timestamp": review_envelope.timestamp,
            "nonce": review_nonce,
            "signature": review_signature,
            "verdict": "approve",
            "body": "LGTM",
        });

        let review_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/reviews", repo_id, pr_id))
            .set_json(&review_request)
            .to_request();

        let review_resp = test::call_service(&app, review_req).await;
        assert_eq!(
            review_resp.status(),
            201,
            "Review submission should succeed"
        );

        // Check audit event for review
        let review_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pr_review' AND agent_id = $1",
        )
        .bind(&reviewer_id)
        .fetch_one(&pool)
        .await
        .expect("Query should succeed");

        assert!(
            review_audit_count > 0,
            "Audit event should be recorded for review"
        );

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &pr_nonce).await;
        cleanup_idempotency(&pool, &reviewer_id, &review_nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;
    }

    // =========================================================================
    // Test: PR approval status updates after review
    // Requirements: 7.5
    // Design: DR-7.2
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_pr_approval_status_updates() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, _author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'pending', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        // Check PR info before review - should not be approved
        let get_req = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/pulls/{}", repo_id, pr_id))
            .to_request();
        let get_resp = test::call_service(&app, get_req).await;
        let get_body = test::read_body(get_resp).await;
        let pr_info: serde_json::Value = serde_json::from_slice(&get_body).unwrap();
        assert_eq!(
            pr_info["data"]["isApproved"], false,
            "PR should not be approved initially"
        );

        // Submit approval review
        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": "approve",
            "body": "LGTM",
        });

        let envelope = SignatureEnvelope {
            agent_id: reviewer_id.clone(),
            action: "pr_review".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&reviewer_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": reviewer_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "verdict": "approve",
            "body": "LGTM",
        });

        let review_req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/reviews", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();
        let review_resp = test::call_service(&app, review_req).await;
        assert_eq!(review_resp.status(), 201, "Review should succeed");

        // Check PR info after review - should be approved
        let get_req2 = test::TestRequest::get()
            .uri(&format!("/v1/repos/{}/pulls/{}", repo_id, pr_id))
            .to_request();
        let get_resp2 = test::call_service(&app, get_req2).await;
        let get_body2 = test::read_body(get_resp2).await;
        let pr_info2: serde_json::Value = serde_json::from_slice(&get_body2).unwrap();

        // Cleanup
        cleanup_idempotency(&pool, &reviewer_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        assert_eq!(
            pr_info2["data"]["isApproved"], true,
            "PR should be approved after review"
        );
    }

    // =========================================================================
    // Test: Diff statistics computed correctly on PR creation
    // Requirements: 6.2
    // Design: DR-7.1
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_diff_stats_computed_on_pr_creation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, signing_key) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &agent_id).await;
        let nonce = uuid::Uuid::new_v4().to_string();

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let body = serde_json::json!({
            "repoId": repo_id,
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
            "description": serde_json::Value::Null,
        });

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "pr_create".to_string(),
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
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls", repo_id))
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
            status, 201,
            "Expected 201 Created, got {}: {:?}",
            status, response
        );
        // Verify diffStats is present in response
        assert!(
            response["data"]["diffStats"].is_object(),
            "diffStats should be present"
        );
        assert!(
            response["data"]["diffStats"]["filesChanged"].is_number(),
            "filesChanged should be a number"
        );
        assert!(
            response["data"]["diffStats"]["insertions"].is_number(),
            "insertions should be a number"
        );
        assert!(
            response["data"]["diffStats"]["deletions"].is_number(),
            "deletions should be a number"
        );
    }

    // =========================================================================
    // Test: Merge with CI not passed returns error
    // Requirements: 8.1, 9.5
    // Design: DR-7.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_merge_ci_not_passed_returns_400() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, _reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        // Create a PR with CI pending (not passed)
        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'pending', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        // Add an approval review
        let review_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
            VALUES ($1, $2, $3, 'approve', 'LGTM', NOW())
            "#,
        )
        .bind(&review_id)
        .bind(&pr_id)
        .bind(&reviewer_id)
        .execute(&pool)
        .await
        .expect("Failed to create review");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": "merge",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_merge".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "mergeStrategy": "merge",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/merge", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        // CiNotPassed maps to 400 Validation error
        assert_eq!(
            status, 400,
            "Expected 400 Bad Request for merge with CI not passed, got {}",
            status
        );
    }

    // =========================================================================
    // Test: Rebase merge strategy works correctly
    // Requirements: 8.2
    // Design: DR-7.3
    // =========================================================================
    #[ignore]
    #[actix_rt::test]
    async fn http_rebase_merge_strategy_works() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (author_id, _author_pk, author_sk) = create_test_agent(&pool).await;
        let (reviewer_id, _reviewer_pk, _reviewer_sk) = create_test_agent(&pool).await;
        let repo_id = create_test_repo_with_branches(&pool, &author_id).await;

        let pr_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'open', 'passed', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(&repo_id)
        .bind(&author_id)
        .execute(&pool)
        .await
        .expect("Failed to create PR");

        let review_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO reviews (review_id, pr_id, reviewer_id, verdict, body, created_at)
            VALUES ($1, $2, $3, 'approve', 'LGTM', NOW())
            "#,
        )
        .bind(&review_id)
        .bind(&pr_id)
        .bind(&reviewer_id)
        .execute(&pool)
        .await
        .expect("Failed to create review");

        let app_state = create_test_app_state(pool.clone());
        let app = test::init_service(
            App::new()
                .app_data(app_state)
                .service(web::scope("/v1").configure(configure_pull_routes)),
        )
        .await;

        let nonce = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "repoId": repo_id,
            "prId": pr_id,
            "mergeStrategy": "rebase",
        });

        let envelope = SignatureEnvelope {
            agent_id: author_id.clone(),
            action: "pr_merge".to_string(),
            timestamp: Utc::now(),
            nonce: nonce.clone(),
            body: body.clone(),
        };
        let signature = sign_envelope(&author_sk, &envelope);

        let request_body = serde_json::json!({
            "agentId": author_id,
            "timestamp": envelope.timestamp,
            "nonce": nonce,
            "signature": signature,
            "mergeStrategy": "rebase",
        });

        let req = test::TestRequest::post()
            .uri(&format!("/v1/repos/{}/pulls/{}/merge", repo_id, pr_id))
            .set_json(&request_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body_bytes = test::read_body(resp).await;
        let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        // Cleanup
        cleanup_idempotency(&pool, &author_id, &nonce).await;
        cleanup_test_repo(&pool, &repo_id).await;
        cleanup_test_agent(&pool, &author_id).await;
        cleanup_test_agent(&pool, &reviewer_id).await;

        assert_eq!(
            status, 200,
            "Expected 200 OK for rebase merge, got {}: {:?}",
            status, response
        );
        assert_eq!(response["data"]["mergeStrategy"], "rebase");
    }
}

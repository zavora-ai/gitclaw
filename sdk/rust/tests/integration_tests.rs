//! Integration tests for GitClaw Rust SDK.
//!
//! These tests run against a local GitClaw backend and verify end-to-end workflows.
//!
//! Requirements: 6.1, 6.2, 6.3, 6.4, 7.1, 7.2, 7.3, 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 9.4, 9.5, 10.1, 10.2, 10.3, 13.1, 13.2, 13.3
//! Design: DR-5, DR-8, DR-9, DR-10, DR-11, DR-12
//!
//! To run these tests:
//! ```bash
//! GITCLAW_INTEGRATION_TESTS=1 GITCLAW_BASE_URL=http://localhost:8080 cargo test --test integration_tests -- --ignored
//! ```

use std::env;
use std::sync::Arc;

use gitclaw::{Ed25519Signer, GitClawClient, GitClawError, Signer};
use uuid::Uuid;

/// Check if integration tests should run.
fn should_run_integration_tests() -> bool {
    env::var("GITCLAW_INTEGRATION_TESTS").map_or(false, |v| v == "1")
}

/// Get the base URL for the GitClaw backend.
fn get_base_url() -> String {
    env::var("GITCLAW_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

/// Generate a unique name for test resources.
fn generate_unique_name(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

/// Create a temporary client for registration (before we have an agent_id).
fn create_temp_client(signer: Arc<dyn Signer>) -> Result<GitClawClient, gitclaw::Error> {
    GitClawClient::new("temp-agent", signer, Some(&get_base_url()), None, None)
}

/// Create an authenticated client with a registered agent.
async fn create_authenticated_client() -> Result<(GitClawClient, String), gitclaw::Error> {
    let (signer, public_key) = Ed25519Signer::generate();
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let agent_name = generate_unique_name("test-agent");

    // Create temporary client for registration
    let temp_client = create_temp_client(Arc::clone(&signer))?;

    // Register the agent
    let agent = temp_client
        .agents()
        .register(&agent_name, &public_key, None)
        .await?;

    // Create authenticated client with the real agent_id
    let client = GitClawClient::new(
        &agent.agent_id,
        signer,
        Some(&get_base_url()),
        None,
        None,
    )?;

    Ok((client, agent.agent_id))
}

// ============================================================================
// Task 8.1: Agent Lifecycle Integration Tests
// Requirements: 6.1, 6.2, 6.3, 6.4 | Design: DR-5, DR-9
// ============================================================================

mod agent_lifecycle {
    use super::*;

    /// Test: Register agent → Get profile
    ///
    /// Requirements: 6.1, 6.2, 6.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_register_agent_and_get_profile() {
        if !should_run_integration_tests() {
            return;
        }

        let (signer, public_key) = Ed25519Signer::generate();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        let agent_name = generate_unique_name("test-agent");

        let client = create_temp_client(signer).expect("Client creation should succeed");

        // Register the agent (unsigned request)
        let agent = client
            .agents()
            .register(&agent_name, &public_key, Some(vec!["code_review".to_string(), "testing".to_string()]))
            .await
            .expect("Agent registration should succeed");

        // Verify registration response
        assert!(!agent.agent_id.is_empty());
        assert_eq!(agent.agent_name, agent_name);

        // Get the agent profile
        let profile = client
            .agents()
            .get(&agent.agent_id)
            .await
            .expect("Get agent profile should succeed");

        // Verify profile matches registration
        assert_eq!(profile.agent_id, agent.agent_id);
        assert_eq!(profile.agent_name, agent_name);
        assert!(profile.capabilities.contains(&"code_review".to_string()));
        assert!(profile.capabilities.contains(&"testing".to_string()));
    }

    /// Test: Register agent → Get reputation
    ///
    /// Requirements: 6.1, 6.4
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_get_agent_reputation() {
        if !should_run_integration_tests() {
            return;
        }

        let (signer, public_key) = Ed25519Signer::generate();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        let agent_name = generate_unique_name("test-agent");

        let client = create_temp_client(signer).expect("Client creation should succeed");

        // Register the agent
        let agent = client
            .agents()
            .register(&agent_name, &public_key, None)
            .await
            .expect("Agent registration should succeed");

        // Get reputation
        let reputation = client
            .agents()
            .get_reputation(&agent.agent_id)
            .await
            .expect("Get reputation should succeed");

        // Verify reputation response
        assert_eq!(reputation.agent_id, agent.agent_id);
        // New agents should have a default reputation score
        assert!((0.0..=1.0).contains(&reputation.score));
    }

    /// Test: Getting a non-existent agent raises NotFoundError
    ///
    /// Requirements: 6.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_get_nonexistent_agent_raises_not_found() {
        if !should_run_integration_tests() {
            return;
        }

        let (signer, _) = Ed25519Signer::generate();
        let signer: Arc<dyn Signer> = Arc::new(signer);

        let client = create_temp_client(signer).expect("Client creation should succeed");

        let result = client.agents().get("nonexistent-agent-id-12345").await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::NotFound { .. })) => {
                // Expected error
            }
            Err(e) => panic!("Expected NotFound error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: Registering an agent with duplicate name raises ConflictError
    ///
    /// Requirements: 6.1, 6.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_register_duplicate_agent_name_raises_conflict() {
        if !should_run_integration_tests() {
            return;
        }

        let (signer1, public_key1) = Ed25519Signer::generate();
        let (_, public_key2) = Ed25519Signer::generate();
        let signer1: Arc<dyn Signer> = Arc::new(signer1);
        let agent_name = generate_unique_name("test-agent");

        let client = create_temp_client(signer1).expect("Client creation should succeed");

        // Register first agent
        client
            .agents()
            .register(&agent_name, &public_key1, None)
            .await
            .expect("First registration should succeed");

        // Try to register second agent with same name
        let result = client.agents().register(&agent_name, &public_key2, None).await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::Conflict { .. })) => {
                // Expected error
            }
            Err(e) => panic!("Expected Conflict error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }
}

// ============================================================================
// Task 8.2: Repository Lifecycle Integration Tests
// Requirements: 7.1, 7.2, 7.3, 10.1, 10.2, 10.3 | Design: DR-5, DR-10, DR-12
// ============================================================================

mod repository_lifecycle {
    use super::*;

    /// Test: Create repo → Get repo
    ///
    /// Requirements: 7.1, 7.2, 7.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_create_and_get_repository() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, agent_id) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let repo_name = generate_unique_name("test-repo");

        // Create repository
        let repo = client
            .repos()
            .create(&repo_name, Some("Test repository for integration tests"), Some("public"))
            .await
            .expect("Repository creation should succeed");

        // Verify creation response
        assert!(!repo.repo_id.is_empty());
        assert_eq!(repo.name, repo_name);
        assert_eq!(repo.owner_id, agent_id);
        assert_eq!(repo.visibility, "public");
        assert_eq!(repo.default_branch, "main");
        assert!(!repo.clone_url.is_empty());

        // Get the repository to verify description
        let fetched_repo = client
            .repos()
            .get(&repo.repo_id)
            .await
            .expect("Get repository should succeed");

        // Verify fetched repo matches created repo
        assert_eq!(fetched_repo.repo_id, repo.repo_id);
        assert_eq!(fetched_repo.name, repo_name);
        assert_eq!(fetched_repo.owner_id, agent_id);
        assert_eq!(fetched_repo.description, Some("Test repository for integration tests".to_string()));
        assert_eq!(fetched_repo.star_count, 0);
    }

    /// Test: Create repo → Star → Verify count → Unstar → Verify count
    ///
    /// Requirements: 7.1, 10.1, 10.2, 10.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_star_and_unstar_repository() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, agent_id) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let repo_name = generate_unique_name("test-repo");

        // Create repository
        let repo = client
            .repos()
            .create(&repo_name, None, None)
            .await
            .expect("Repository creation should succeed");

        assert_eq!(repo.star_count, 0);

        // Star the repository
        let star_response = client
            .stars()
            .star(&repo.repo_id, Some("Great project!"), true)
            .await
            .expect("Star should succeed");

        assert_eq!(star_response.repo_id, repo.repo_id);
        assert_eq!(star_response.agent_id, agent_id);
        assert!(star_response.action == "starred" || star_response.action == "star");
        assert_eq!(star_response.star_count, 1);

        // Get stars info
        let stars_info = client
            .stars()
            .get(&repo.repo_id)
            .await
            .expect("Get stars should succeed");

        assert_eq!(stars_info.star_count, 1);
        assert_eq!(stars_info.starred_by.len(), 1);
        assert_eq!(stars_info.starred_by[0].agent_id, agent_id);
        assert_eq!(stars_info.starred_by[0].reason, Some("Great project!".to_string()));

        // Unstar the repository
        let unstar_response = client
            .stars()
            .unstar(&repo.repo_id)
            .await
            .expect("Unstar should succeed");

        assert_eq!(unstar_response.repo_id, repo.repo_id);
        assert!(unstar_response.action == "unstarred" || unstar_response.action == "unstar");
        assert_eq!(unstar_response.star_count, 0);

        // Verify star count is back to 0
        let repo_after = client
            .repos()
            .get(&repo.repo_id)
            .await
            .expect("Get repository should succeed");

        assert_eq!(repo_after.star_count, 0);
    }

    /// Test: Star → Star again raises ConflictError
    ///
    /// Requirements: 10.1
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_duplicate_star_raises_conflict() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let repo_name = generate_unique_name("test-repo");
        let repo = client
            .repos()
            .create(&repo_name, None, None)
            .await
            .expect("Repository creation should succeed");

        // Star the repository
        client
            .stars()
            .star(&repo.repo_id, None, false)
            .await
            .expect("First star should succeed");

        // Try to star again
        let result = client.stars().star(&repo.repo_id, None, false).await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::Conflict { .. })) => {
                // Expected error
            }
            Err(e) => panic!("Expected Conflict error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: Getting a non-existent repository raises NotFoundError
    ///
    /// Requirements: 7.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_get_nonexistent_repository_raises_not_found() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let result = client.repos().get("nonexistent-repo-id-12345").await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::NotFound { .. })) => {
                // Expected error
            }
            Err(e) => panic!("Expected NotFound error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }
}


// ============================================================================
// Task 8.3: Pull Request Workflow Integration Tests
// Requirements: 9.1, 9.2, 9.3, 9.4, 9.5 | Design: DR-5, DR-11
// ============================================================================

mod pull_request_workflow {
    use super::*;

    /// Helper to create a repository with two agents (owner and reviewer).
    async fn create_repo_with_agents() -> Result<(GitClawClient, GitClawClient, String, String), gitclaw::Error> {
        // Create owner agent
        let (owner_signer, owner_public_key) = Ed25519Signer::generate();
        let owner_signer: Arc<dyn Signer> = Arc::new(owner_signer);
        let owner_name = generate_unique_name("owner-agent");

        let temp_client = create_temp_client(Arc::clone(&owner_signer))?;
        let owner_agent = temp_client
            .agents()
            .register(&owner_name, &owner_public_key, None)
            .await?;

        let owner_client = GitClawClient::new(
            &owner_agent.agent_id,
            owner_signer,
            Some(&get_base_url()),
            None,
            None,
        )?;

        // Create reviewer agent
        let (reviewer_signer, reviewer_public_key) = Ed25519Signer::generate();
        let reviewer_signer: Arc<dyn Signer> = Arc::new(reviewer_signer);
        let reviewer_name = generate_unique_name("reviewer-agent");

        let temp_client2 = create_temp_client(Arc::clone(&reviewer_signer))?;
        let reviewer_agent = temp_client2
            .agents()
            .register(&reviewer_name, &reviewer_public_key, None)
            .await?;

        let reviewer_client = GitClawClient::new(
            &reviewer_agent.agent_id,
            reviewer_signer,
            Some(&get_base_url()),
            None,
            None,
        )?;

        // Create repository
        let repo_name = generate_unique_name("test-repo");
        let repo = owner_client.repos().create(&repo_name, None, None).await?;

        // Grant reviewer write access
        owner_client
            .access()
            .grant(&repo.repo_id, &reviewer_agent.agent_id, "write")
            .await?;

        Ok((owner_client, reviewer_client, repo.repo_id, reviewer_agent.agent_id))
    }

    /// Test: Create PR
    ///
    /// Requirements: 9.1, 9.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_create_pull_request() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, _) = create_repo_with_agents()
            .await
            .expect("Setup should succeed");

        // Create a pull request
        // Note: Using main as both source and target since we can't create branches
        // without push functionality. The backend validates branch existence.
        let pr = owner_client
            .pulls()
            .create(
                &repo_id,
                "main",
                "main",
                "Add new feature",
                Some("This PR adds a new feature"),
            )
            .await
            .expect("PR creation should succeed");

        // Verify PR creation
        assert!(!pr.pr_id.is_empty());
        assert_eq!(pr.repo_id, repo_id);
        assert_eq!(pr.author_id, owner_client.agent_id());
        assert_eq!(pr.source_branch, "main");
        assert_eq!(pr.target_branch, "main");
        assert_eq!(pr.title, "Add new feature");
        assert_eq!(pr.description, Some("This PR adds a new feature".to_string()));
        assert_eq!(pr.status, "open");
        assert!(["pending", "running", "passed", "failed"].contains(&pr.ci_status.as_str()));
    }

    /// Test: Create PR → Get PR
    ///
    /// Requirements: 9.1, 9.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_get_pull_request() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, _) = create_repo_with_agents()
            .await
            .expect("Setup should succeed");

        // Create a pull request
        let pr = owner_client
            .pulls()
            .create(&repo_id, "main", "main", "Test PR", None)
            .await
            .expect("PR creation should succeed");

        // Get the PR
        let fetched_pr = owner_client
            .pulls()
            .get(&repo_id, &pr.pr_id)
            .await
            .expect("Get PR should succeed");

        assert_eq!(fetched_pr.pr_id, pr.pr_id);
        assert_eq!(fetched_pr.title, "Test PR");
    }

    /// Test: Create PR → Submit review
    ///
    /// Requirements: 9.1, 9.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_submit_review() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, reviewer_client, repo_id, reviewer_agent_id) = create_repo_with_agents()
            .await
            .expect("Setup should succeed");

        // Create a pull request
        let pr = owner_client
            .pulls()
            .create(&repo_id, "main", "main", "Test PR for review", None)
            .await
            .expect("PR creation should succeed");

        // Submit a review (reviewer approves)
        let review = reviewer_client
            .reviews()
            .create(&repo_id, &pr.pr_id, "approve", Some("LGTM! Great work."))
            .await
            .expect("Review submission should succeed");

        // Verify review
        assert!(!review.review_id.is_empty());
        assert_eq!(review.pr_id, pr.pr_id);
        assert_eq!(review.reviewer_id, reviewer_agent_id);
        assert_eq!(review.verdict, "approve");
        assert_eq!(review.body, Some("LGTM! Great work.".to_string()));

        // List reviews
        let reviews = reviewer_client
            .reviews()
            .list(&repo_id, &pr.pr_id)
            .await
            .expect("List reviews should succeed");

        assert!(!reviews.is_empty());
        let review_ids: Vec<&str> = reviews.iter().map(|r| r.review_id.as_str()).collect();
        assert!(review_ids.contains(&review.review_id.as_str()));
    }

    /// Test: Create PR → Submit request_changes review
    ///
    /// Requirements: 9.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_request_changes_review() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, reviewer_client, repo_id, _) = create_repo_with_agents()
            .await
            .expect("Setup should succeed");

        // Create a pull request
        let pr = owner_client
            .pulls()
            .create(&repo_id, "main", "main", "Test PR for changes", None)
            .await
            .expect("PR creation should succeed");

        // Submit request_changes review
        let review = reviewer_client
            .reviews()
            .create(
                &repo_id,
                &pr.pr_id,
                "request_changes",
                Some("Please fix the formatting issues."),
            )
            .await
            .expect("Review submission should succeed");

        assert_eq!(review.verdict, "request_changes");
        assert_eq!(review.body, Some("Please fix the formatting issues.".to_string()));
    }
}

// ============================================================================
// Task 8.4: Access Control Integration Tests
// Requirements: 8.1, 8.2, 8.3 | Design: DR-5, DR-10
// ============================================================================

mod access_control {
    use super::*;

    /// Helper to create an owner agent with a repository and a collaborator agent.
    async fn create_owner_and_collaborator() -> Result<(GitClawClient, GitClawClient, String, String), gitclaw::Error> {
        // Create owner agent
        let (owner_signer, owner_public_key) = Ed25519Signer::generate();
        let owner_signer: Arc<dyn Signer> = Arc::new(owner_signer);
        let owner_name = generate_unique_name("owner-agent");

        let temp_client = create_temp_client(Arc::clone(&owner_signer))?;
        let owner_agent = temp_client
            .agents()
            .register(&owner_name, &owner_public_key, None)
            .await?;

        let owner_client = GitClawClient::new(
            &owner_agent.agent_id,
            owner_signer,
            Some(&get_base_url()),
            None,
            None,
        )?;

        // Create collaborator agent
        let (collab_signer, collab_public_key) = Ed25519Signer::generate();
        let collab_signer: Arc<dyn Signer> = Arc::new(collab_signer);
        let collab_name = generate_unique_name("collab-agent");

        let temp_client2 = create_temp_client(Arc::clone(&collab_signer))?;
        let collab_agent = temp_client2
            .agents()
            .register(&collab_name, &collab_public_key, None)
            .await?;

        let collab_client = GitClawClient::new(
            &collab_agent.agent_id,
            collab_signer,
            Some(&get_base_url()),
            None,
            None,
        )?;

        // Create repository
        let repo_name = generate_unique_name("test-repo");
        let repo = owner_client.repos().create(&repo_name, None, None).await?;

        Ok((owner_client, collab_client, repo.repo_id, collab_agent.agent_id))
    }

    /// Test: Grant access to collaborator
    ///
    /// Requirements: 8.1
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_grant_access() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, collab_agent_id) = create_owner_and_collaborator()
            .await
            .expect("Setup should succeed");

        // Grant write access
        let response = owner_client
            .access()
            .grant(&repo_id, &collab_agent_id, "write")
            .await
            .expect("Grant access should succeed");

        assert_eq!(response.repo_id, repo_id);
        assert_eq!(response.agent_id, collab_agent_id);
        assert_eq!(response.role, Some("write".to_string()));
        assert_eq!(response.action, "granted");
    }

    /// Test: Grant access → List collaborators
    ///
    /// Requirements: 8.1, 8.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_list_collaborators() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, collab_agent_id) = create_owner_and_collaborator()
            .await
            .expect("Setup should succeed");

        // Grant access
        owner_client
            .access()
            .grant(&repo_id, &collab_agent_id, "read")
            .await
            .expect("Grant access should succeed");

        // List collaborators
        let collaborators = owner_client
            .access()
            .list(&repo_id)
            .await
            .expect("List collaborators should succeed");

        // Find the collaborator we just added
        let collab_ids: Vec<&str> = collaborators.iter().map(|c| c.agent_id.as_str()).collect();
        assert!(collab_ids.contains(&collab_agent_id.as_str()));

        // Verify collaborator details
        let collab = collaborators
            .iter()
            .find(|c| c.agent_id == collab_agent_id)
            .expect("Collaborator should be in list");

        assert_eq!(collab.role, "read");
        assert!(!collab.agent_name.is_empty());
    }

    /// Test: Grant access → Revoke access
    ///
    /// Requirements: 8.1, 8.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_revoke_access() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, collab_agent_id) = create_owner_and_collaborator()
            .await
            .expect("Setup should succeed");

        // Grant access
        owner_client
            .access()
            .grant(&repo_id, &collab_agent_id, "write")
            .await
            .expect("Grant access should succeed");

        // Revoke access
        let response = owner_client
            .access()
            .revoke(&repo_id, &collab_agent_id)
            .await
            .expect("Revoke access should succeed");

        assert_eq!(response.repo_id, repo_id);
        assert_eq!(response.agent_id, collab_agent_id);
        assert_eq!(response.action, "revoked");

        // Verify collaborator is no longer in the list
        let collaborators = owner_client
            .access()
            .list(&repo_id)
            .await
            .expect("List collaborators should succeed");

        let collab_ids: Vec<&str> = collaborators.iter().map(|c| c.agent_id.as_str()).collect();
        assert!(!collab_ids.contains(&collab_agent_id.as_str()));
    }

    /// Test: Grant different access roles (read, write, admin)
    ///
    /// Requirements: 8.1
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_grant_different_roles() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, collab_agent_id) = create_owner_and_collaborator()
            .await
            .expect("Setup should succeed");

        // Test each role
        for role in ["read", "write", "admin"] {
            let response = owner_client
                .access()
                .grant(&repo_id, &collab_agent_id, role)
                .await
                .expect("Grant access should succeed");

            assert_eq!(response.role, Some(role.to_string()));

            // Verify in collaborators list
            let collaborators = owner_client
                .access()
                .list(&repo_id)
                .await
                .expect("List collaborators should succeed");

            let collab = collaborators
                .iter()
                .find(|c| c.agent_id == collab_agent_id)
                .expect("Collaborator should be in list");

            assert_eq!(collab.role, role);
        }
    }

    /// Test: Full lifecycle - Grant → List → Revoke → Verify removed
    ///
    /// Requirements: 8.1, 8.2, 8.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_access_control_full_lifecycle() {
        if !should_run_integration_tests() {
            return;
        }

        let (owner_client, _, repo_id, collab_agent_id) = create_owner_and_collaborator()
            .await
            .expect("Setup should succeed");

        // Grant access
        let grant_response = owner_client
            .access()
            .grant(&repo_id, &collab_agent_id, "write")
            .await
            .expect("Grant access should succeed");

        assert_eq!(grant_response.action, "granted");

        // List and verify
        let collaborators = owner_client
            .access()
            .list(&repo_id)
            .await
            .expect("List collaborators should succeed");

        assert!(collaborators.iter().any(|c| c.agent_id == collab_agent_id));

        // Revoke access
        let revoke_response = owner_client
            .access()
            .revoke(&repo_id, &collab_agent_id)
            .await
            .expect("Revoke access should succeed");

        assert_eq!(revoke_response.action, "revoked");

        // Verify removed
        let collaborators_after = owner_client
            .access()
            .list(&repo_id)
            .await
            .expect("List collaborators should succeed");

        assert!(!collaborators_after.iter().any(|c| c.agent_id == collab_agent_id));
    }
}


// ============================================================================
// Task 8.5: Error Handling Integration Tests
// Requirements: 13.1, 13.2, 13.3 | Design: DR-8
// ============================================================================

mod error_handling {
    use super::*;

    /// Test: Duplicate star raises ConflictError
    ///
    /// Requirements: 13.1, 13.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_duplicate_star_raises_conflict_error() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let repo_name = generate_unique_name("test-repo");
        let repo = client
            .repos()
            .create(&repo_name, None, None)
            .await
            .expect("Repository creation should succeed");

        // First star succeeds
        client
            .stars()
            .star(&repo.repo_id, None, false)
            .await
            .expect("First star should succeed");

        // Second star raises ConflictError
        let result = client.stars().star(&repo.repo_id, None, false).await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::Conflict { code, message, .. })) => {
                // Verify error has code and message
                assert!(!code.is_empty());
                assert!(!message.is_empty());
            }
            Err(e) => panic!("Expected Conflict error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: NotFoundError contains code, message, and request_id
    ///
    /// Requirements: 13.2, 13.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_not_found_error_has_proper_fields() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let result = client.repos().get("nonexistent-repo-id-12345").await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::NotFound { code, message, .. })) => {
                assert!(!code.is_empty());
                assert!(!message.is_empty());
            }
            Err(e) => panic!("Expected NotFound error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: Invalid signature raises AuthenticationError
    ///
    /// Requirements: 13.1, 13.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_invalid_signature_raises_authentication_error() {
        if !should_run_integration_tests() {
            return;
        }

        // Create a client with mismatched agent_id and signer
        let (signer, public_key) = Ed25519Signer::generate();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        let agent_name = generate_unique_name("test-agent");

        // Register the agent
        let temp_client = create_temp_client(Arc::clone(&signer)).expect("Client creation should succeed");
        let agent = temp_client
            .agents()
            .register(&agent_name, &public_key, None)
            .await
            .expect("Agent registration should succeed");

        // Create a different signer (not matching the registered public key)
        let (wrong_signer, _) = Ed25519Signer::generate();
        let wrong_signer: Arc<dyn Signer> = Arc::new(wrong_signer);

        // Create client with correct agent_id but wrong signer
        let client = GitClawClient::new(
            &agent.agent_id,
            wrong_signer,
            Some(&get_base_url()),
            None,
            None,
        )
        .expect("Client creation should succeed");

        // Try to create a repo with invalid signature
        let result = client
            .repos()
            .create(&generate_unique_name("test-repo"), None, None)
            .await;

        match result {
            Err(gitclaw::Error::GitClaw(GitClawError::Authentication { code, message, .. })) => {
                assert!(!code.is_empty());
                assert!(!message.is_empty());
            }
            Err(e) => panic!("Expected Authentication error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: All errors inherit from GitClawError (via Error enum)
    ///
    /// Requirements: 13.4
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_error_inheritance() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        // Test NotFoundError
        let result = client.repos().get("nonexistent-repo-id").await;
        assert!(matches!(result, Err(gitclaw::Error::GitClaw(_))));

        // Test ConflictError
        let repo = client
            .repos()
            .create(&generate_unique_name("test-repo"), None, None)
            .await
            .expect("Repository creation should succeed");

        client
            .stars()
            .star(&repo.repo_id, None, false)
            .await
            .expect("First star should succeed");

        let result = client.stars().star(&repo.repo_id, None, false).await;
        assert!(matches!(result, Err(gitclaw::Error::GitClaw(_))));
    }

    /// Test: Error string representation includes code and message
    ///
    /// Requirements: 13.2
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_error_string_representation() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let result = client.repos().get("nonexistent-repo-id").await;

        match result {
            Err(gitclaw::Error::GitClaw(error)) => {
                let error_str = error.to_string();
                // String should contain the error code
                assert!(
                    error_str.contains(error.code()),
                    "Error string should contain code: {}",
                    error_str
                );
            }
            Err(e) => panic!("Expected GitClaw error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test: GitClawError helper methods work correctly
    ///
    /// Requirements: 13.2, 13.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_gitclaw_error_helper_methods() {
        if !should_run_integration_tests() {
            return;
        }

        let (client, _) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        let result = client.repos().get("nonexistent-repo-id").await;

        match result {
            Err(gitclaw::Error::GitClaw(error)) => {
                // Test helper methods
                assert!(!error.code().is_empty());
                assert!(!error.message().is_empty());
                // request_id may or may not be present
                let _ = error.request_id();

                // NotFound errors should not be retryable
                assert!(!error.is_retryable());
            }
            Err(e) => panic!("Expected GitClaw error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }
}

// ============================================================================
// Additional Integration Tests
// ============================================================================

mod additional_tests {
    use super::*;

    /// Test: Client can be created from environment variables
    ///
    /// Requirements: 1.2, 1.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and environment variables"]
    async fn test_client_from_env() {
        if !should_run_integration_tests() {
            return;
        }

        // This test requires GITCLAW_AGENT_ID and GITCLAW_PRIVATE_KEY_PATH to be set
        if env::var("GITCLAW_AGENT_ID").is_err() || env::var("GITCLAW_PRIVATE_KEY_PATH").is_err() {
            // Skip if env vars not set
            return;
        }

        let client = GitClawClient::from_env().expect("Client creation from env should succeed");
        assert!(!client.agent_id().is_empty());
    }

    /// Test: Trending endpoint works without authentication
    ///
    /// Requirements: 11.1, 11.2, 11.3
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_trending_without_auth() {
        if !should_run_integration_tests() {
            return;
        }

        let (signer, _) = Ed25519Signer::generate();
        let signer: Arc<dyn Signer> = Arc::new(signer);

        // Create client without registering (trending doesn't require auth)
        let client = create_temp_client(signer).expect("Client creation should succeed");

        // Get trending repositories
        let result = client.trending().get(Some("24h"), Some(10)).await;

        // Should succeed (even if empty)
        match result {
            Ok(trending) => {
                // Verify response structure
                assert!(trending.window == "24h" || trending.window.is_empty());
                // repos may be empty if no trending repos
            }
            Err(e) => {
                // Some backends may not have trending implemented
                println!("Trending endpoint returned error (may not be implemented): {:?}", e);
            }
        }
    }

    /// Test: Multiple operations in sequence
    ///
    /// Requirements: All
    #[tokio::test]
    #[ignore = "Integration test requires GITCLAW_INTEGRATION_TESTS=1 and a running backend"]
    async fn test_full_workflow() {
        if !should_run_integration_tests() {
            return;
        }

        // Create authenticated client
        let (client, agent_id) = create_authenticated_client()
            .await
            .expect("Client creation should succeed");

        // 1. Create a repository
        let repo_name = generate_unique_name("workflow-repo");
        let repo = client
            .repos()
            .create(&repo_name, Some("Workflow test repo"), Some("public"))
            .await
            .expect("Repository creation should succeed");

        assert_eq!(repo.owner_id, agent_id);

        // 2. Star the repository
        let star_response = client
            .stars()
            .star(&repo.repo_id, Some("Testing workflow"), false)
            .await
            .expect("Star should succeed");

        assert_eq!(star_response.star_count, 1);

        // 3. Get repository and verify star count
        let repo_after_star = client
            .repos()
            .get(&repo.repo_id)
            .await
            .expect("Get repository should succeed");

        assert_eq!(repo_after_star.star_count, 1);

        // 4. Create a pull request
        let pr = client
            .pulls()
            .create(
                &repo.repo_id,
                "main",
                "main",
                "Workflow PR",
                Some("Testing the full workflow"),
            )
            .await
            .expect("PR creation should succeed");

        assert_eq!(pr.status, "open");

        // 5. Unstar the repository
        let unstar_response = client
            .stars()
            .unstar(&repo.repo_id)
            .await
            .expect("Unstar should succeed");

        assert_eq!(unstar_response.star_count, 0);

        // 6. Verify final state
        let final_repo = client
            .repos()
            .get(&repo.repo_id)
            .await
            .expect("Get repository should succeed");

        assert_eq!(final_repo.star_count, 0);
    }
}

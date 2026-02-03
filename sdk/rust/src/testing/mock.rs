//! Mock GitClaw client for testing.
//!
//! Provides a `MockGitClawClient` that mimics the real client interface
//! without making actual API calls.
//!
//! Design Reference: DR-6
//! Requirements: 15.1, 15.2, 15.3

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::error::{Error, GitClawError};
use crate::types::{
    AccessResponse, Agent, AgentProfile, Collaborator, DiffStats, MergeResult, PullRequest,
    Reputation, Repository, Review, StarResponse, StarsInfo, TrendingResponse,
};

/// Record of a method call.
#[derive(Debug, Clone)]
pub struct MockCall {
    /// Method name (e.g., "repos.create", "stars.star")
    pub method: String,
    /// Arguments passed to the method
    pub args: Vec<String>,
    /// Timestamp of the call
    pub timestamp: DateTime<Utc>,
}

impl MockCall {
    /// Create a new mock call record.
    pub fn new(method: &str, args: Vec<String>) -> Self {
        Self {
            method: method.to_string(),
            args,
            timestamp: Utc::now(),
        }
    }
}

/// Configuration for a mock response.
#[derive(Debug, Clone)]
pub struct MockResponse<T: Clone> {
    /// The data to return
    pub data: Option<T>,
    /// Error code to return (will create a GitClawError::Validation)
    pub error_code: Option<String>,
    /// Error message to return
    pub error_message: Option<String>,
    /// Number of times this response has been used
    pub call_count: u32,
}

impl<T: Clone> Default for MockResponse<T> {
    fn default() -> Self {
        Self {
            data: None,
            error_code: None,
            error_message: None,
            call_count: 0,
        }
    }
}

impl<T: Clone> MockResponse<T> {
    /// Create a new mock response with data.
    pub fn with_data(data: T) -> Self {
        Self {
            data: Some(data),
            error_code: None,
            error_message: None,
            call_count: 0,
        }
    }

    /// Create a new mock response with an error.
    pub fn with_error(code: &str, message: &str) -> Self {
        Self {
            data: None,
            error_code: Some(code.to_string()),
            error_message: Some(message.to_string()),
            call_count: 0,
        }
    }

    /// Get the result, returning either the configured data or error.
    fn get_result(&mut self, default: T) -> Result<T, Error> {
        self.call_count += 1;
        if let (Some(code), Some(message)) = (&self.error_code, &self.error_message) {
            return Err(Error::GitClaw(GitClawError::Validation {
                code: code.clone(),
                message: message.clone(),
                request_id: None,
            }));
        }
        Ok(self.data.clone().unwrap_or(default))
    }
}

/// Internal state for the mock client.
struct MockClientState {
    agent_id: String,
    calls: Vec<MockCall>,
}

impl MockClientState {
    fn new(agent_id: String) -> Self {
        Self {
            agent_id,
            calls: Vec::new(),
        }
    }

    fn record_call(&mut self, method: &str, args: Vec<String>) {
        self.calls.push(MockCall::new(method, args));
    }
}

/// Mock agents client for testing.
pub struct MockAgentsClient {
    mock: Arc<Mutex<MockClientState>>,
    register_response: Arc<Mutex<MockResponse<Agent>>>,
    get_response: Arc<Mutex<MockResponse<AgentProfile>>>,
    get_reputation_response: Arc<Mutex<MockResponse<Reputation>>>,
}

impl MockAgentsClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            register_response: Arc::new(Mutex::new(MockResponse::default())),
            get_response: Arc::new(Mutex::new(MockResponse::default())),
            get_reputation_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for register() calls.
    pub fn configure_register(&self, response: MockResponse<Agent>) {
        *self.register_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for get() calls.
    pub fn configure_get(&self, response: MockResponse<AgentProfile>) {
        *self.get_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for get_reputation() calls.
    pub fn configure_get_reputation(&self, response: MockResponse<Reputation>) {
        *self.get_reputation_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock register method.
    pub fn register(
        &self,
        agent_name: &str,
        public_key: &str,
        capabilities: Option<Vec<String>>,
    ) -> Result<Agent, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("agents.register", vec![
                agent_name.to_string(),
                public_key.to_string(),
                format!("{capabilities:?}"),
            ]);

        let default = Agent {
            agent_id: "mock-agent-id".to_string(),
            agent_name: agent_name.to_string(),
            created_at: Utc::now(),
        };

        self.register_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock get method.
    pub fn get(&self, agent_id: &str) -> Result<AgentProfile, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("agents.get", vec![agent_id.to_string()]);

        let default = AgentProfile {
            agent_id: agent_id.to_string(),
            agent_name: "mock-agent".to_string(),
            capabilities: vec![],
            created_at: Utc::now(),
        };

        self.get_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock get_reputation method.
    pub fn get_reputation(&self, agent_id: &str) -> Result<Reputation, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("agents.get_reputation", vec![agent_id.to_string()]);

        let default = Reputation {
            agent_id: agent_id.to_string(),
            score: 0.5,
            updated_at: Utc::now(),
        };

        self.get_reputation_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }
}


/// Mock repos client for testing.
pub struct MockReposClient {
    mock: Arc<Mutex<MockClientState>>,
    create_response: Arc<Mutex<MockResponse<Repository>>>,
    get_response: Arc<Mutex<MockResponse<Repository>>>,
    list_response: Arc<Mutex<MockResponse<Vec<Repository>>>>,
}

impl MockReposClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            create_response: Arc::new(Mutex::new(MockResponse::default())),
            get_response: Arc::new(Mutex::new(MockResponse::default())),
            list_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for create() calls.
    pub fn configure_create(&self, response: MockResponse<Repository>) {
        *self.create_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for get() calls.
    pub fn configure_get(&self, response: MockResponse<Repository>) {
        *self.get_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for list() calls.
    pub fn configure_list(&self, response: MockResponse<Vec<Repository>>) {
        *self.list_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock create method.
    pub fn create(
        &self,
        name: &str,
        description: Option<&str>,
        visibility: Option<&str>,
    ) -> Result<Repository, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("repos.create", vec![
                name.to_string(),
                format!("{description:?}"),
                format!("{visibility:?}"),
            ]);

        let default = Repository {
            repo_id: "mock-repo-id".to_string(),
            name: name.to_string(),
            owner_id: agent_id.clone(),
            owner_name: Some("mock-owner".to_string()),
            description: description.map(String::from),
            visibility: visibility.unwrap_or("public").to_string(),
            default_branch: "main".to_string(),
            clone_url: format!("https://gitclaw.dev/{agent_id}/{name}.git"),
            star_count: 0,
            created_at: Utc::now(),
        };

        self.create_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock get method.
    pub fn get(&self, repo_id: &str) -> Result<Repository, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("repos.get", vec![repo_id.to_string()]);

        let default = Repository {
            repo_id: repo_id.to_string(),
            name: "mock-repo".to_string(),
            owner_id: agent_id.clone(),
            owner_name: Some("mock-owner".to_string()),
            description: None,
            visibility: "public".to_string(),
            default_branch: "main".to_string(),
            clone_url: format!("https://gitclaw.dev/{agent_id}/mock-repo.git"),
            star_count: 0,
            created_at: Utc::now(),
        };

        self.get_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock list method.
    pub fn list(&self) -> Result<Vec<Repository>, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("repos.list", vec![]);

        self.list_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(vec![])
    }
}

/// Mock stars client for testing.
pub struct MockStarsClient {
    mock: Arc<Mutex<MockClientState>>,
    star_response: Arc<Mutex<MockResponse<StarResponse>>>,
    unstar_response: Arc<Mutex<MockResponse<StarResponse>>>,
    get_response: Arc<Mutex<MockResponse<StarsInfo>>>,
}

impl MockStarsClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            star_response: Arc::new(Mutex::new(MockResponse::default())),
            unstar_response: Arc::new(Mutex::new(MockResponse::default())),
            get_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for star() calls.
    pub fn configure_star(&self, response: MockResponse<StarResponse>) {
        *self.star_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for unstar() calls.
    pub fn configure_unstar(&self, response: MockResponse<StarResponse>) {
        *self.unstar_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for get() calls.
    pub fn configure_get(&self, response: MockResponse<StarsInfo>) {
        *self.get_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock star method.
    pub fn star(
        &self,
        repo_id: &str,
        reason: Option<&str>,
        reason_public: bool,
    ) -> Result<StarResponse, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("stars.star", vec![
                repo_id.to_string(),
                format!("{reason:?}"),
                reason_public.to_string(),
            ]);

        let default = StarResponse {
            repo_id: repo_id.to_string(),
            agent_id,
            action: "star".to_string(),
            star_count: 1,
        };

        self.star_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock unstar method.
    pub fn unstar(&self, repo_id: &str) -> Result<StarResponse, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("stars.unstar", vec![repo_id.to_string()]);

        let default = StarResponse {
            repo_id: repo_id.to_string(),
            agent_id,
            action: "unstar".to_string(),
            star_count: 0,
        };

        self.unstar_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock get method.
    pub fn get(&self, repo_id: &str) -> Result<StarsInfo, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("stars.get", vec![repo_id.to_string()]);

        let default = StarsInfo {
            repo_id: repo_id.to_string(),
            star_count: 0,
            starred_by: vec![],
        };

        self.get_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }
}


/// Mock access client for testing.
pub struct MockAccessClient {
    mock: Arc<Mutex<MockClientState>>,
    grant_response: Arc<Mutex<MockResponse<AccessResponse>>>,
    revoke_response: Arc<Mutex<MockResponse<AccessResponse>>>,
    list_response: Arc<Mutex<MockResponse<Vec<Collaborator>>>>,
}

impl MockAccessClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            grant_response: Arc::new(Mutex::new(MockResponse::default())),
            revoke_response: Arc::new(Mutex::new(MockResponse::default())),
            list_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for grant() calls.
    pub fn configure_grant(&self, response: MockResponse<AccessResponse>) {
        *self.grant_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for revoke() calls.
    pub fn configure_revoke(&self, response: MockResponse<AccessResponse>) {
        *self.revoke_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for list() calls.
    pub fn configure_list(&self, response: MockResponse<Vec<Collaborator>>) {
        *self.list_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock grant method.
    pub fn grant(&self, repo_id: &str, agent_id: &str, role: &str) -> Result<AccessResponse, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("access.grant", vec![
                repo_id.to_string(),
                agent_id.to_string(),
                role.to_string(),
            ]);

        let default = AccessResponse {
            repo_id: repo_id.to_string(),
            agent_id: agent_id.to_string(),
            role: Some(role.to_string()),
            action: "granted".to_string(),
        };

        self.grant_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock revoke method.
    pub fn revoke(&self, repo_id: &str, agent_id: &str) -> Result<AccessResponse, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("access.revoke", vec![
                repo_id.to_string(),
                agent_id.to_string(),
            ]);

        let default = AccessResponse {
            repo_id: repo_id.to_string(),
            agent_id: agent_id.to_string(),
            role: None,
            action: "revoked".to_string(),
        };

        self.revoke_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock list method.
    pub fn list(&self, repo_id: &str) -> Result<Vec<Collaborator>, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("access.list", vec![repo_id.to_string()]);

        self.list_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(vec![])
    }
}

/// Mock pulls client for testing.
pub struct MockPullsClient {
    mock: Arc<Mutex<MockClientState>>,
    create_response: Arc<Mutex<MockResponse<PullRequest>>>,
    get_response: Arc<Mutex<MockResponse<PullRequest>>>,
    list_response: Arc<Mutex<MockResponse<Vec<PullRequest>>>>,
    merge_response: Arc<Mutex<MockResponse<MergeResult>>>,
}

impl MockPullsClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            create_response: Arc::new(Mutex::new(MockResponse::default())),
            get_response: Arc::new(Mutex::new(MockResponse::default())),
            list_response: Arc::new(Mutex::new(MockResponse::default())),
            merge_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for create() calls.
    pub fn configure_create(&self, response: MockResponse<PullRequest>) {
        *self.create_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for get() calls.
    pub fn configure_get(&self, response: MockResponse<PullRequest>) {
        *self.get_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for list() calls.
    pub fn configure_list(&self, response: MockResponse<Vec<PullRequest>>) {
        *self.list_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for merge() calls.
    pub fn configure_merge(&self, response: MockResponse<MergeResult>) {
        *self.merge_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock create method.
    pub fn create(
        &self,
        repo_id: &str,
        source_branch: &str,
        target_branch: &str,
        title: &str,
        description: Option<&str>,
    ) -> Result<PullRequest, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("pulls.create", vec![
                repo_id.to_string(),
                source_branch.to_string(),
                target_branch.to_string(),
                title.to_string(),
                format!("{description:?}"),
            ]);

        let default = PullRequest {
            pr_id: "mock-pr-id".to_string(),
            repo_id: repo_id.to_string(),
            author_id: agent_id,
            source_branch: source_branch.to_string(),
            target_branch: target_branch.to_string(),
            title: title.to_string(),
            description: description.map(String::from),
            status: "open".to_string(),
            ci_status: "pending".to_string(),
            diff_stats: DiffStats {
                files_changed: 0,
                insertions: 0,
                deletions: 0,
            },
            mergeable: true,
            is_approved: false,
            review_count: 0,
            created_at: Utc::now(),
            merged_at: None,
        };

        self.create_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock get method.
    pub fn get(&self, repo_id: &str, pr_id: &str) -> Result<PullRequest, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("pulls.get", vec![repo_id.to_string(), pr_id.to_string()]);

        let default = PullRequest {
            pr_id: pr_id.to_string(),
            repo_id: repo_id.to_string(),
            author_id: agent_id,
            source_branch: "feature".to_string(),
            target_branch: "main".to_string(),
            title: "Mock PR".to_string(),
            description: None,
            status: "open".to_string(),
            ci_status: "pending".to_string(),
            diff_stats: DiffStats {
                files_changed: 0,
                insertions: 0,
                deletions: 0,
            },
            mergeable: true,
            is_approved: false,
            review_count: 0,
            created_at: Utc::now(),
            merged_at: None,
        };

        self.get_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock list method.
    pub fn list(
        &self,
        repo_id: &str,
        status: Option<&str>,
        author_id: Option<&str>,
    ) -> Result<Vec<PullRequest>, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("pulls.list", vec![
                repo_id.to_string(),
                format!("{status:?}"),
                format!("{author_id:?}"),
            ]);

        self.list_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(vec![])
    }

    /// Mock merge method.
    pub fn merge(
        &self,
        repo_id: &str,
        pr_id: &str,
        merge_strategy: Option<&str>,
    ) -> Result<MergeResult, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("pulls.merge", vec![
                repo_id.to_string(),
                pr_id.to_string(),
                format!("{merge_strategy:?}"),
            ]);

        let default = MergeResult {
            pr_id: pr_id.to_string(),
            repo_id: repo_id.to_string(),
            merge_strategy: merge_strategy.unwrap_or("merge").to_string(),
            merged_at: Utc::now(),
            merge_commit_oid: "mock-commit-oid".to_string(),
        };

        self.merge_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }
}


/// Mock reviews client for testing.
pub struct MockReviewsClient {
    mock: Arc<Mutex<MockClientState>>,
    create_response: Arc<Mutex<MockResponse<Review>>>,
    list_response: Arc<Mutex<MockResponse<Vec<Review>>>>,
}

impl MockReviewsClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            create_response: Arc::new(Mutex::new(MockResponse::default())),
            list_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for create() calls.
    pub fn configure_create(&self, response: MockResponse<Review>) {
        *self.create_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Configure the response for list() calls.
    pub fn configure_list(&self, response: MockResponse<Vec<Review>>) {
        *self.list_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock create method.
    pub fn create(
        &self,
        repo_id: &str,
        pr_id: &str,
        verdict: &str,
        body: Option<&str>,
    ) -> Result<Review, Error> {
        let agent_id = self.mock.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone();
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("reviews.create", vec![
                repo_id.to_string(),
                pr_id.to_string(),
                verdict.to_string(),
                format!("{body:?}"),
            ]);

        let default = Review {
            review_id: "mock-review-id".to_string(),
            pr_id: pr_id.to_string(),
            reviewer_id: agent_id,
            verdict: verdict.to_string(),
            body: body.map(String::from),
            created_at: Utc::now(),
        };

        self.create_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }

    /// Mock list method.
    pub fn list(&self, repo_id: &str, pr_id: &str) -> Result<Vec<Review>, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("reviews.list", vec![repo_id.to_string(), pr_id.to_string()]);

        self.list_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(vec![])
    }
}

/// Mock trending client for testing.
pub struct MockTrendingClient {
    mock: Arc<Mutex<MockClientState>>,
    get_response: Arc<Mutex<MockResponse<TrendingResponse>>>,
}

impl MockTrendingClient {
    fn new(mock: Arc<Mutex<MockClientState>>) -> Self {
        Self {
            mock,
            get_response: Arc::new(Mutex::new(MockResponse::default())),
        }
    }

    /// Configure the response for get() calls.
    pub fn configure_get(&self, response: MockResponse<TrendingResponse>) {
        *self.get_response.lock().unwrap_or_else(|e| e.into_inner()) = response;
    }

    /// Mock get method.
    pub fn get(&self, window: Option<&str>, limit: Option<u32>) -> Result<TrendingResponse, Error> {
        self.mock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_call("trending.get", vec![
                format!("{window:?}"),
                format!("{limit:?}"),
            ]);

        let default = TrendingResponse {
            window: window.unwrap_or("24h").to_string(),
            repos: vec![],
            computed_at: Utc::now(),
        };

        self.get_response
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_result(default)
    }
}

/// Mock GitClaw client for testing.
///
/// Provides the same interface as `GitClawClient` but returns configurable
/// mock responses instead of making real API calls.
///
/// # Example
///
/// ```rust
/// use gitclaw::testing::{MockGitClawClient, MockResponse};
/// use gitclaw::types::Repository;
/// use chrono::Utc;
///
/// // Create mock client
/// let mock = MockGitClawClient::new("test-agent");
///
/// // Configure mock responses
/// mock.repos().configure_create(MockResponse::with_data(Repository {
///     repo_id: "custom-id".to_string(),
///     name: "my-repo".to_string(),
///     owner_id: "test-agent".to_string(),
///     owner_name: Some("test-owner".to_string()),
///     description: None,
///     visibility: "public".to_string(),
///     default_branch: "main".to_string(),
///     clone_url: "https://gitclaw.dev/test-agent/my-repo.git".to_string(),
///     star_count: 0,
///     created_at: Utc::now(),
/// }));
///
/// // Use in tests
/// let repo = mock.repos().create("my-repo", None, None).unwrap();
/// assert_eq!(repo.repo_id, "custom-id");
///
/// // Verify calls were made
/// assert!(mock.was_called("repos.create"));
/// assert_eq!(mock.call_count("repos.create"), 1);
/// ```
///
/// Requirements: 15.1, 15.2, 15.3
pub struct MockGitClawClient {
    state: Arc<Mutex<MockClientState>>,
    agents: MockAgentsClient,
    repos: MockReposClient,
    stars: MockStarsClient,
    access: MockAccessClient,
    pulls: MockPullsClient,
    reviews: MockReviewsClient,
    trending: MockTrendingClient,
}

impl MockGitClawClient {
    /// Create a new mock client.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent ID to use in mock responses
    pub fn new(agent_id: &str) -> Self {
        let state = Arc::new(Mutex::new(MockClientState::new(agent_id.to_string())));

        Self {
            agents: MockAgentsClient::new(Arc::clone(&state)),
            repos: MockReposClient::new(Arc::clone(&state)),
            stars: MockStarsClient::new(Arc::clone(&state)),
            access: MockAccessClient::new(Arc::clone(&state)),
            pulls: MockPullsClient::new(Arc::clone(&state)),
            reviews: MockReviewsClient::new(Arc::clone(&state)),
            trending: MockTrendingClient::new(Arc::clone(&state)),
            state,
        }
    }

    /// Get the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> String {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).agent_id.clone()
    }

    /// Get the agents client.
    #[must_use]
    pub fn agents(&self) -> &MockAgentsClient {
        &self.agents
    }

    /// Get the repos client.
    #[must_use]
    pub fn repos(&self) -> &MockReposClient {
        &self.repos
    }

    /// Get the stars client.
    #[must_use]
    pub fn stars(&self) -> &MockStarsClient {
        &self.stars
    }

    /// Get the access client.
    #[must_use]
    pub fn access(&self) -> &MockAccessClient {
        &self.access
    }

    /// Get the pulls client.
    #[must_use]
    pub fn pulls(&self) -> &MockPullsClient {
        &self.pulls
    }

    /// Get the reviews client.
    #[must_use]
    pub fn reviews(&self) -> &MockReviewsClient {
        &self.reviews
    }

    /// Get the trending client.
    #[must_use]
    pub fn trending(&self) -> &MockTrendingClient {
        &self.trending
    }

    /// Check if a method was called.
    ///
    /// # Arguments
    ///
    /// * `method` - Method name (e.g., "repos.create", "stars.star")
    ///
    /// # Returns
    ///
    /// `true` if the method was called at least once
    #[must_use]
    pub fn was_called(&self, method: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .calls
            .iter()
            .any(|call| call.method == method)
    }

    /// Get the number of times a method was called.
    ///
    /// # Arguments
    ///
    /// * `method` - Method name (e.g., "repos.create", "stars.star")
    ///
    /// # Returns
    ///
    /// Number of times the method was called
    #[must_use]
    pub fn call_count(&self, method: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .calls
            .iter()
            .filter(|call| call.method == method)
            .count()
    }

    /// Get recorded calls, optionally filtered by method.
    ///
    /// # Arguments
    ///
    /// * `method` - Optional method name to filter by
    ///
    /// # Returns
    ///
    /// List of `MockCall` objects
    #[must_use]
    pub fn get_calls(&self, method: Option<&str>) -> Vec<MockCall> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match method {
            Some(m) => state.calls.iter().filter(|call| call.method == m).cloned().collect(),
            None => state.calls.clone(),
        }
    }

    /// Reset all recorded calls.
    pub fn reset(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).calls.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client_creation() {
        let mock = MockGitClawClient::new("test-agent");
        assert_eq!(mock.agent_id(), "test-agent");
    }

    #[test]
    fn test_mock_repos_create() {
        let mock = MockGitClawClient::new("test-agent");
        let repo = mock.repos().create("my-repo", None, None).unwrap();

        assert_eq!(repo.name, "my-repo");
        assert_eq!(repo.owner_id, "test-agent");
        assert!(mock.was_called("repos.create"));
        assert_eq!(mock.call_count("repos.create"), 1);
    }

    #[test]
    fn test_mock_repos_create_with_configured_response() {
        let mock = MockGitClawClient::new("test-agent");

        mock.repos().configure_create(MockResponse::with_data(Repository {
            repo_id: "custom-id".to_string(),
            name: "custom-repo".to_string(),
            owner_id: "test-agent".to_string(),
            owner_name: Some("test-owner".to_string()),
            description: Some("Custom description".to_string()),
            visibility: "private".to_string(),
            default_branch: "main".to_string(),
            clone_url: "https://gitclaw.dev/test-agent/custom-repo.git".to_string(),
            star_count: 10,
            created_at: Utc::now(),
        }));

        let repo = mock.repos().create("my-repo", None, None).unwrap();

        assert_eq!(repo.repo_id, "custom-id");
        assert_eq!(repo.name, "custom-repo");
        assert_eq!(repo.star_count, 10);
    }

    #[test]
    fn test_mock_repos_create_with_error() {
        let mock = MockGitClawClient::new("test-agent");

        mock.repos().configure_create(MockResponse::with_error(
            "REPO_EXISTS",
            "Repository already exists",
        ));

        let result = mock.repos().create("my-repo", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_stars_star() {
        let mock = MockGitClawClient::new("test-agent");
        let response = mock.stars().star("repo-123", Some("Great project!"), true).unwrap();

        assert_eq!(response.repo_id, "repo-123");
        assert_eq!(response.action, "star");
        assert!(mock.was_called("stars.star"));
    }

    #[test]
    fn test_mock_stars_unstar() {
        let mock = MockGitClawClient::new("test-agent");
        let response = mock.stars().unstar("repo-123").unwrap();

        assert_eq!(response.repo_id, "repo-123");
        assert_eq!(response.action, "unstar");
        assert!(mock.was_called("stars.unstar"));
    }

    #[test]
    fn test_mock_pulls_create() {
        let mock = MockGitClawClient::new("test-agent");
        let pr = mock
            .pulls()
            .create("repo-123", "feature", "main", "Add feature", Some("Description"))
            .unwrap();

        assert_eq!(pr.repo_id, "repo-123");
        assert_eq!(pr.source_branch, "feature");
        assert_eq!(pr.target_branch, "main");
        assert_eq!(pr.title, "Add feature");
        assert!(mock.was_called("pulls.create"));
    }

    #[test]
    fn test_mock_reviews_create() {
        let mock = MockGitClawClient::new("test-agent");
        let review = mock
            .reviews()
            .create("repo-123", "pr-456", "approve", Some("LGTM!"))
            .unwrap();

        assert_eq!(review.pr_id, "pr-456");
        assert_eq!(review.verdict, "approve");
        assert!(mock.was_called("reviews.create"));
    }

    #[test]
    fn test_mock_access_grant() {
        let mock = MockGitClawClient::new("test-agent");
        let response = mock.access().grant("repo-123", "other-agent", "write").unwrap();

        assert_eq!(response.repo_id, "repo-123");
        assert_eq!(response.agent_id, "other-agent");
        assert_eq!(response.role, Some("write".to_string()));
        assert!(mock.was_called("access.grant"));
    }

    #[test]
    fn test_mock_trending_get() {
        let mock = MockGitClawClient::new("test-agent");
        let response = mock.trending().get(Some("7d"), Some(10)).unwrap();

        assert_eq!(response.window, "7d");
        assert!(mock.was_called("trending.get"));
    }

    #[test]
    fn test_mock_agents_register() {
        let mock = MockGitClawClient::new("test-agent");
        let agent = mock
            .agents()
            .register("new-agent", "public-key-123", Some(vec!["code".to_string()]))
            .unwrap();

        assert_eq!(agent.agent_name, "new-agent");
        assert!(mock.was_called("agents.register"));
    }

    #[test]
    fn test_mock_get_calls() {
        let mock = MockGitClawClient::new("test-agent");

        mock.repos().create("repo-1", None, None).unwrap();
        mock.repos().create("repo-2", None, None).unwrap();
        mock.stars().star("repo-1", None, false).unwrap();

        let all_calls = mock.get_calls(None);
        assert_eq!(all_calls.len(), 3);

        let repo_calls = mock.get_calls(Some("repos.create"));
        assert_eq!(repo_calls.len(), 2);

        let star_calls = mock.get_calls(Some("stars.star"));
        assert_eq!(star_calls.len(), 1);
    }

    #[test]
    fn test_mock_reset() {
        let mock = MockGitClawClient::new("test-agent");

        mock.repos().create("repo-1", None, None).unwrap();
        assert_eq!(mock.call_count("repos.create"), 1);

        mock.reset();
        assert_eq!(mock.call_count("repos.create"), 0);
        assert!(!mock.was_called("repos.create"));
    }
}

"""
Pytest fixtures for GitClaw SDK testing.

Provides common fixtures for testing applications that use the GitClaw SDK.

Design Reference: DR-6
Requirements: 15.2
"""

from datetime import datetime
from typing import Any, Generator

import pytest

from gitclaw.signers import Ed25519Signer
from gitclaw.testing.mock import MockGitClawClient
from gitclaw.types.agents import Agent, AgentProfile, Reputation
from gitclaw.types.pulls import DiffStats, MergeResult, PullRequest, Review
from gitclaw.types.repos import AccessResponse, Collaborator, Repository
from gitclaw.types.stars import StarredByAgent, StarResponse, StarsInfo
from gitclaw.types.trending import TrendingRepo, TrendingResponse


# ============================================================================
# Mock Client Fixtures
# ============================================================================


@pytest.fixture
def mock_client() -> Generator[MockGitClawClient, None, None]:
    """
    Provide a MockGitClawClient for testing.

    Example:
        ```python
        def test_my_feature(mock_client):
            mock_client.repos.configure_create(response=my_repo)
            result = my_function(mock_client)
            assert mock_client.was_called("repos.create")
        ```
    """
    client = MockGitClawClient(agent_id="test-agent-id")
    yield client
    client.reset()


@pytest.fixture
def mock_agent_id() -> str:
    """Provide a test agent ID."""
    return "test-agent-id"


@pytest.fixture
def mock_repo_id() -> str:
    """Provide a test repository ID."""
    return "test-repo-id"


@pytest.fixture
def mock_pr_id() -> str:
    """Provide a test pull request ID."""
    return "test-pr-id"


# ============================================================================
# Signer Fixtures
# ============================================================================


@pytest.fixture
def ed25519_signer() -> Ed25519Signer:
    """
    Provide a generated Ed25519 signer for testing.

    Example:
        ```python
        def test_signing(ed25519_signer):
            signature = ed25519_signer.sign(b"test message")
            assert len(signature) == 64
        ```
    """
    signer, _ = Ed25519Signer.generate()
    return signer


@pytest.fixture
def ed25519_keypair() -> tuple[Ed25519Signer, str]:
    """
    Provide a generated Ed25519 keypair (signer and public key).

    Example:
        ```python
        def test_registration(ed25519_keypair):
            signer, public_key = ed25519_keypair
            # Use public_key for registration
            # Use signer for signing requests
        ```
    """
    return Ed25519Signer.generate()


# ============================================================================
# Sample Data Fixtures
# ============================================================================


@pytest.fixture
def sample_agent() -> Agent:
    """Provide a sample Agent object."""
    return Agent(
        agent_id="sample-agent-id",
        agent_name="sample-agent",
        created_at=datetime(2024, 1, 15, 10, 30, 0),
    )


@pytest.fixture
def sample_agent_profile() -> AgentProfile:
    """Provide a sample AgentProfile object."""
    return AgentProfile(
        agent_id="sample-agent-id",
        agent_name="sample-agent",
        capabilities=["code_review", "testing"],
        created_at=datetime(2024, 1, 15, 10, 30, 0),
    )


@pytest.fixture
def sample_reputation() -> Reputation:
    """Provide a sample Reputation object."""
    return Reputation(
        agent_id="sample-agent-id",
        score=0.85,
        updated_at=datetime(2024, 1, 15, 12, 0, 0),
    )


@pytest.fixture
def sample_repository() -> Repository:
    """Provide a sample Repository object."""
    return Repository(
        repo_id="sample-repo-id",
        name="sample-repo",
        owner_id="sample-agent-id",
        owner_name="sample-agent",
        description="A sample repository for testing",
        visibility="public",
        default_branch="main",
        clone_url="https://gitclaw.dev/sample-agent/sample-repo.git",
        star_count=42,
        created_at=datetime(2024, 1, 15, 10, 30, 0),
    )


@pytest.fixture
def sample_collaborator() -> Collaborator:
    """Provide a sample Collaborator object."""
    return Collaborator(
        agent_id="collaborator-agent-id",
        agent_name="collaborator-agent",
        role="write",
        granted_at=datetime(2024, 1, 16, 9, 0, 0),
    )


@pytest.fixture
def sample_pull_request() -> PullRequest:
    """Provide a sample PullRequest object."""
    return PullRequest(
        pr_id="sample-pr-id",
        repo_id="sample-repo-id",
        author_id="sample-agent-id",
        source_branch="feature/new-feature",
        target_branch="main",
        title="Add new feature",
        description="This PR adds a new feature",
        status="open",
        ci_status="passed",
        diff_stats=DiffStats(files_changed=3, insertions=100, deletions=20),
        mergeable=True,
        is_approved=True,
        review_count=1,
        created_at=datetime(2024, 1, 15, 14, 0, 0),
        merged_at=None,
    )


@pytest.fixture
def sample_review() -> Review:
    """Provide a sample Review object."""
    return Review(
        review_id="sample-review-id",
        pr_id="sample-pr-id",
        reviewer_id="reviewer-agent-id",
        verdict="approve",
        body="LGTM! Great work.",
        created_at=datetime(2024, 1, 15, 15, 0, 0),
    )


@pytest.fixture
def sample_merge_result() -> MergeResult:
    """Provide a sample MergeResult object."""
    return MergeResult(
        pr_id="sample-pr-id",
        repo_id="sample-repo-id",
        merge_strategy="squash",
        merged_at=datetime(2024, 1, 15, 16, 0, 0),
        merge_commit_oid="abc123def456",
    )


@pytest.fixture
def sample_star_response() -> StarResponse:
    """Provide a sample StarResponse object."""
    return StarResponse(
        repo_id="sample-repo-id",
        agent_id="sample-agent-id",
        action="star",
        star_count=43,
    )


@pytest.fixture
def sample_stars_info() -> StarsInfo:
    """Provide a sample StarsInfo object."""
    return StarsInfo(
        repo_id="sample-repo-id",
        star_count=42,
        starred_by=[
            StarredByAgent(
                agent_id="starrer-1",
                agent_name="starrer-agent-1",
                reputation_score=0.9,
                reason="Great project!",
                starred_at=datetime(2024, 1, 14, 10, 0, 0),
            ),
            StarredByAgent(
                agent_id="starrer-2",
                agent_name="starrer-agent-2",
                reputation_score=0.75,
                reason=None,
                starred_at=datetime(2024, 1, 15, 8, 0, 0),
            ),
        ],
    )


@pytest.fixture
def sample_trending_response() -> TrendingResponse:
    """Provide a sample TrendingResponse object."""
    return TrendingResponse(
        window="24h",
        repos=[
            TrendingRepo(
                repo_id="trending-repo-1",
                name="hot-project",
                owner_id="popular-agent",
                owner_name="popular-agent",
                description="A trending project",
                stars=150,
                stars_delta=25,
                weighted_score=0.95,
                created_at=datetime(2024, 1, 10, 10, 0, 0),
            ),
            TrendingRepo(
                repo_id="trending-repo-2",
                name="rising-star",
                owner_id="new-agent",
                owner_name="new-agent",
                description="An up-and-coming project",
                stars=50,
                stars_delta=15,
                weighted_score=0.80,
                created_at=datetime(2024, 1, 12, 10, 0, 0),
            ),
        ],
        computed_at=datetime(2024, 1, 15, 12, 0, 0),
    )


@pytest.fixture
def sample_access_response() -> AccessResponse:
    """Provide a sample AccessResponse object."""
    return AccessResponse(
        repo_id="sample-repo-id",
        agent_id="collaborator-agent-id",
        role="write",
        action="granted",
    )


# ============================================================================
# Configured Mock Client Fixtures
# ============================================================================


@pytest.fixture
def mock_client_with_repo(
    mock_client: MockGitClawClient,
    sample_repository: Repository,
) -> MockGitClawClient:
    """
    Provide a MockGitClawClient pre-configured with a sample repository.

    Example:
        ```python
        def test_repo_operations(mock_client_with_repo):
            repo = mock_client_with_repo.repos.get("any-id")
            assert repo.name == "sample-repo"
        ```
    """
    mock_client.repos.configure_get(response=sample_repository)
    mock_client.repos.configure_create(response=sample_repository)
    return mock_client


@pytest.fixture
def mock_client_with_pr(
    mock_client: MockGitClawClient,
    sample_pull_request: PullRequest,
    sample_merge_result: MergeResult,
) -> MockGitClawClient:
    """
    Provide a MockGitClawClient pre-configured with PR operations.

    Example:
        ```python
        def test_pr_workflow(mock_client_with_pr):
            pr = mock_client_with_pr.pulls.create(...)
            result = mock_client_with_pr.pulls.merge(...)
        ```
    """
    mock_client.pulls.configure_create(response=sample_pull_request)
    mock_client.pulls.configure_get(response=sample_pull_request)
    mock_client.pulls.configure_merge(response=sample_merge_result)
    return mock_client


@pytest.fixture
def mock_client_with_stars(
    mock_client: MockGitClawClient,
    sample_star_response: StarResponse,
    sample_stars_info: StarsInfo,
) -> MockGitClawClient:
    """
    Provide a MockGitClawClient pre-configured with star operations.

    Example:
        ```python
        def test_star_workflow(mock_client_with_stars):
            result = mock_client_with_stars.stars.star("repo-id")
            info = mock_client_with_stars.stars.get("repo-id")
        ```
    """
    mock_client.stars.configure_star(response=sample_star_response)
    mock_client.stars.configure_get(response=sample_stars_info)
    return mock_client


# ============================================================================
# Helper Functions
# ============================================================================


def create_mock_repository(
    repo_id: str = "test-repo-id",
    name: str = "test-repo",
    owner_id: str = "test-agent-id",
    **kwargs: Any,
) -> Repository:
    """
    Create a Repository with customizable fields.

    Args:
        repo_id: Repository ID
        name: Repository name
        owner_id: Owner agent ID
        **kwargs: Additional fields to override

    Returns:
        Repository object
    """
    defaults = {
        "owner_name": owner_id,
        "description": None,
        "visibility": "public",
        "default_branch": "main",
        "clone_url": f"https://gitclaw.dev/{owner_id}/{name}.git",
        "star_count": 0,
        "created_at": datetime.utcnow(),
    }
    defaults.update(kwargs)
    return Repository(
        repo_id=repo_id,
        name=name,
        owner_id=owner_id,
        **defaults,
    )


def create_mock_pull_request(
    pr_id: str = "test-pr-id",
    repo_id: str = "test-repo-id",
    author_id: str = "test-agent-id",
    **kwargs: Any,
) -> PullRequest:
    """
    Create a PullRequest with customizable fields.

    Args:
        pr_id: Pull request ID
        repo_id: Repository ID
        author_id: Author agent ID
        **kwargs: Additional fields to override

    Returns:
        PullRequest object
    """
    defaults = {
        "source_branch": "feature",
        "target_branch": "main",
        "title": "Test PR",
        "description": None,
        "status": "open",
        "ci_status": "pending",
        "diff_stats": DiffStats(files_changed=1, insertions=10, deletions=5),
        "mergeable": True,
        "is_approved": False,
        "review_count": 0,
        "created_at": datetime.utcnow(),
        "merged_at": None,
    }
    defaults.update(kwargs)
    return PullRequest(
        pr_id=pr_id,
        repo_id=repo_id,
        author_id=author_id,
        **defaults,
    )


def create_mock_agent(
    agent_id: str = "test-agent-id",
    agent_name: str = "test-agent",
    **kwargs: Any,
) -> Agent:
    """
    Create an Agent with customizable fields.

    Args:
        agent_id: Agent ID
        agent_name: Agent name
        **kwargs: Additional fields to override

    Returns:
        Agent object
    """
    defaults = {
        "created_at": datetime.utcnow(),
    }
    defaults.update(kwargs)
    return Agent(
        agent_id=agent_id,
        agent_name=agent_name,
        **defaults,
    )


__all__ = [
    # Fixtures (exported for documentation, actual fixtures are auto-discovered)
    "mock_client",
    "mock_agent_id",
    "mock_repo_id",
    "mock_pr_id",
    "ed25519_signer",
    "ed25519_keypair",
    "sample_agent",
    "sample_agent_profile",
    "sample_reputation",
    "sample_repository",
    "sample_collaborator",
    "sample_pull_request",
    "sample_review",
    "sample_merge_result",
    "sample_star_response",
    "sample_stars_info",
    "sample_trending_response",
    "sample_access_response",
    "mock_client_with_repo",
    "mock_client_with_pr",
    "mock_client_with_stars",
    # Helper functions
    "create_mock_repository",
    "create_mock_pull_request",
    "create_mock_agent",
]

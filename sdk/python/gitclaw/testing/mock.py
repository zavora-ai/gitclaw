"""
Mock GitClaw client for testing.

Provides a MockGitClawClient that mimics the real client interface
without making actual API calls.

Design Reference: DR-6
Requirements: 15.1, 15.3
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from gitclaw.types.agents import Agent, AgentProfile, Reputation
from gitclaw.types.pulls import DiffStats, MergeResult, PullRequest, Review
from gitclaw.types.repos import AccessResponse, Collaborator, Repository
from gitclaw.types.stars import StarredByAgent, StarResponse, StarsInfo
from gitclaw.types.trending import TrendingRepo, TrendingResponse

T = TypeVar("T")


@dataclass
class MockResponse:
    """Configuration for a mock response."""

    data: Any
    error: Exception | None = None
    call_count: int = 0


@dataclass
class MockCall:
    """Record of a method call."""

    method: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


class MockAgentsClient:
    """Mock agents client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_register(
        self,
        response: Agent | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for register() calls."""
        self._responses["register"] = MockResponse(data=response, error=error)

    def configure_get(
        self,
        response: AgentProfile | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get() calls."""
        self._responses["get"] = MockResponse(data=response, error=error)

    def configure_get_reputation(
        self,
        response: Reputation | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get_reputation() calls."""
        self._responses["get_reputation"] = MockResponse(data=response, error=error)

    def register(
        self,
        agent_name: str,
        public_key: str,
        capabilities: list[str] | None = None,
    ) -> Agent:
        """Mock register method."""
        self._mock._record_call(
            "agents.register",
            (agent_name, public_key),
            {"capabilities": capabilities},
        )
        return self._get_response("register", Agent(
            agent_id="mock-agent-id",
            agent_name=agent_name,
            created_at=datetime.utcnow(),
        ))

    def get(self, agent_id: str) -> AgentProfile:
        """Mock get method."""
        self._mock._record_call("agents.get", (agent_id,), {})
        return self._get_response("get", AgentProfile(
            agent_id=agent_id,
            agent_name="mock-agent",
            capabilities=[],
            created_at=datetime.utcnow(),
        ))

    def get_reputation(self, agent_id: str) -> Reputation:
        """Mock get_reputation method."""
        self._mock._record_call("agents.get_reputation", (agent_id,), {})
        return self._get_response("get_reputation", Reputation(
            agent_id=agent_id,
            score=0.5,
            updated_at=datetime.utcnow(),
        ))

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockReposClient:
    """Mock repos client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_create(
        self,
        response: Repository | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for create() calls."""
        self._responses["create"] = MockResponse(data=response, error=error)

    def configure_get(
        self,
        response: Repository | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get() calls."""
        self._responses["get"] = MockResponse(data=response, error=error)

    def configure_list(
        self,
        response: list[Repository] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for list() calls."""
        self._responses["list"] = MockResponse(data=response, error=error)

    def create(
        self,
        name: str,
        description: str | None = None,
        visibility: str = "public",
    ) -> Repository:
        """Mock create method."""
        self._mock._record_call(
            "repos.create",
            (name,),
            {"description": description, "visibility": visibility},
        )
        return self._get_response("create", Repository(
            repo_id="mock-repo-id",
            name=name,
            owner_id=self._mock.agent_id,
            owner_name="mock-owner",
            description=description,
            visibility=visibility,
            default_branch="main",
            clone_url=f"https://gitclaw.dev/{self._mock.agent_id}/{name}.git",
            star_count=0,
            created_at=datetime.utcnow(),
        ))

    def get(self, repo_id: str) -> Repository:
        """Mock get method."""
        self._mock._record_call("repos.get", (repo_id,), {})
        return self._get_response("get", Repository(
            repo_id=repo_id,
            name="mock-repo",
            owner_id=self._mock.agent_id,
            owner_name="mock-owner",
            description=None,
            visibility="public",
            default_branch="main",
            clone_url=f"https://gitclaw.dev/{self._mock.agent_id}/mock-repo.git",
            star_count=0,
            created_at=datetime.utcnow(),
        ))

    def list(self) -> list[Repository]:
        """Mock list method."""
        self._mock._record_call("repos.list", (), {})
        return self._get_response("list", [])

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockStarsClient:
    """Mock stars client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_star(
        self,
        response: StarResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for star() calls."""
        self._responses["star"] = MockResponse(data=response, error=error)

    def configure_unstar(
        self,
        response: StarResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for unstar() calls."""
        self._responses["unstar"] = MockResponse(data=response, error=error)

    def configure_get(
        self,
        response: StarsInfo | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get() calls."""
        self._responses["get"] = MockResponse(data=response, error=error)

    def star(
        self,
        repo_id: str,
        reason: str | None = None,
        reason_public: bool = False,
    ) -> StarResponse:
        """Mock star method."""
        self._mock._record_call(
            "stars.star",
            (repo_id,),
            {"reason": reason, "reason_public": reason_public},
        )
        return self._get_response("star", StarResponse(
            repo_id=repo_id,
            agent_id=self._mock.agent_id,
            action="star",
            star_count=1,
        ))

    def unstar(self, repo_id: str) -> StarResponse:
        """Mock unstar method."""
        self._mock._record_call("stars.unstar", (repo_id,), {})
        return self._get_response("unstar", StarResponse(
            repo_id=repo_id,
            agent_id=self._mock.agent_id,
            action="unstar",
            star_count=0,
        ))

    def get(self, repo_id: str) -> StarsInfo:
        """Mock get method."""
        self._mock._record_call("stars.get", (repo_id,), {})
        return self._get_response("get", StarsInfo(
            repo_id=repo_id,
            star_count=0,
            starred_by=[],
        ))

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockAccessClient:
    """Mock access client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_grant(
        self,
        response: AccessResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for grant() calls."""
        self._responses["grant"] = MockResponse(data=response, error=error)

    def configure_revoke(
        self,
        response: AccessResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for revoke() calls."""
        self._responses["revoke"] = MockResponse(data=response, error=error)

    def configure_list(
        self,
        response: list[Collaborator] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for list() calls."""
        self._responses["list"] = MockResponse(data=response, error=error)

    def grant(self, repo_id: str, agent_id: str, role: str) -> AccessResponse:
        """Mock grant method."""
        self._mock._record_call(
            "access.grant",
            (repo_id, agent_id, role),
            {},
        )
        return self._get_response("grant", AccessResponse(
            repo_id=repo_id,
            agent_id=agent_id,
            role=role,
            action="granted",
        ))

    def revoke(self, repo_id: str, agent_id: str) -> AccessResponse:
        """Mock revoke method."""
        self._mock._record_call("access.revoke", (repo_id, agent_id), {})
        return self._get_response("revoke", AccessResponse(
            repo_id=repo_id,
            agent_id=agent_id,
            role=None,
            action="revoked",
        ))

    def list(self, repo_id: str) -> list[Collaborator]:
        """Mock list method."""
        self._mock._record_call("access.list", (repo_id,), {})
        return self._get_response("list", [])

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockPullsClient:
    """Mock pulls client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_create(
        self,
        response: PullRequest | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for create() calls."""
        self._responses["create"] = MockResponse(data=response, error=error)

    def configure_get(
        self,
        response: PullRequest | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get() calls."""
        self._responses["get"] = MockResponse(data=response, error=error)

    def configure_list(
        self,
        response: list[PullRequest] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for list() calls."""
        self._responses["list"] = MockResponse(data=response, error=error)

    def configure_merge(
        self,
        response: MergeResult | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for merge() calls."""
        self._responses["merge"] = MockResponse(data=response, error=error)

    def create(
        self,
        repo_id: str,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str | None = None,
    ) -> PullRequest:
        """Mock create method."""
        self._mock._record_call(
            "pulls.create",
            (repo_id, source_branch, target_branch, title),
            {"description": description},
        )
        return self._get_response("create", PullRequest(
            pr_id="mock-pr-id",
            repo_id=repo_id,
            author_id=self._mock.agent_id,
            source_branch=source_branch,
            target_branch=target_branch,
            title=title,
            description=description,
            status="open",
            ci_status="pending",
            diff_stats=DiffStats(files_changed=0, insertions=0, deletions=0),
            mergeable=True,
            is_approved=False,
            review_count=0,
            created_at=datetime.utcnow(),
            merged_at=None,
        ))

    def get(self, repo_id: str, pr_id: str) -> PullRequest:
        """Mock get method."""
        self._mock._record_call("pulls.get", (repo_id, pr_id), {})
        return self._get_response("get", PullRequest(
            pr_id=pr_id,
            repo_id=repo_id,
            author_id=self._mock.agent_id,
            source_branch="feature",
            target_branch="main",
            title="Mock PR",
            description=None,
            status="open",
            ci_status="pending",
            diff_stats=DiffStats(files_changed=0, insertions=0, deletions=0),
            mergeable=True,
            is_approved=False,
            review_count=0,
            created_at=datetime.utcnow(),
            merged_at=None,
        ))

    def list(
        self,
        repo_id: str,
        status: str | None = None,
        author_id: str | None = None,
    ) -> list[PullRequest]:
        """Mock list method."""
        self._mock._record_call(
            "pulls.list",
            (repo_id,),
            {"status": status, "author_id": author_id},
        )
        return self._get_response("list", [])

    def merge(
        self,
        repo_id: str,
        pr_id: str,
        merge_strategy: str = "merge",
    ) -> MergeResult:
        """Mock merge method."""
        self._mock._record_call(
            "pulls.merge",
            (repo_id, pr_id),
            {"merge_strategy": merge_strategy},
        )
        return self._get_response("merge", MergeResult(
            pr_id=pr_id,
            repo_id=repo_id,
            merge_strategy=merge_strategy,
            merged_at=datetime.utcnow(),
            merge_commit_oid="mock-commit-oid",
        ))

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockReviewsClient:
    """Mock reviews client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_create(
        self,
        response: Review | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for create() calls."""
        self._responses["create"] = MockResponse(data=response, error=error)

    def configure_list(
        self,
        response: list[Review] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for list() calls."""
        self._responses["list"] = MockResponse(data=response, error=error)

    def create(
        self,
        repo_id: str,
        pr_id: str,
        verdict: str,
        body: str | None = None,
    ) -> Review:
        """Mock create method."""
        self._mock._record_call(
            "reviews.create",
            (repo_id, pr_id, verdict),
            {"body": body},
        )
        return self._get_response("create", Review(
            review_id="mock-review-id",
            pr_id=pr_id,
            reviewer_id=self._mock.agent_id,
            verdict=verdict,
            body=body,
            created_at=datetime.utcnow(),
        ))

    def list(self, repo_id: str, pr_id: str) -> list[Review]:
        """Mock list method."""
        self._mock._record_call("reviews.list", (repo_id, pr_id), {})
        return self._get_response("list", [])

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockTrendingClient:
    """Mock trending client for testing."""

    def __init__(self, mock_client: "MockGitClawClient") -> None:
        self._mock = mock_client
        self._responses: dict[str, MockResponse] = {}

    def configure_get(
        self,
        response: TrendingResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        """Configure the response for get() calls."""
        self._responses["get"] = MockResponse(data=response, error=error)

    def get(self, window: str = "24h", limit: int = 50) -> TrendingResponse:
        """Mock get method."""
        self._mock._record_call(
            "trending.get",
            (),
            {"window": window, "limit": limit},
        )
        return self._get_response("get", TrendingResponse(
            window=window,
            repos=[],
            computed_at=datetime.utcnow(),
        ))

    def _get_response(self, method: str, default: T) -> T:
        """Get configured response or default."""
        if method in self._responses:
            resp = self._responses[method]
            resp.call_count += 1
            if resp.error:
                raise resp.error
            if resp.data is not None:
                return resp.data
        return default


class MockGitClawClient:
    """
    Mock GitClaw client for testing.

    Provides the same interface as GitClawClient but returns configurable
    mock responses instead of making real API calls.

    Example:
        ```python
        from gitclaw.testing import MockGitClawClient
        from gitclaw.types import Repository

        # Create mock client
        mock = MockGitClawClient(agent_id="test-agent")

        # Configure mock responses
        mock.repos.configure_create(
            response=Repository(
                repo_id="custom-id",
                name="my-repo",
                # ... other fields
            )
        )

        # Use in tests
        repo = mock.repos.create(name="my-repo")
        assert repo.repo_id == "custom-id"

        # Verify calls were made
        assert mock.was_called("repos.create")
        assert mock.call_count("repos.create") == 1
        ```

    Requirements: 15.1, 15.3
    """

    def __init__(self, agent_id: str = "mock-agent-id") -> None:
        """
        Initialize the mock client.

        Args:
            agent_id: Agent ID to use in mock responses
        """
        self.agent_id = agent_id
        self._calls: list[MockCall] = []

        # Initialize mock resource clients
        self.agents = MockAgentsClient(self)
        self.repos = MockReposClient(self)
        self.stars = MockStarsClient(self)
        self.access = MockAccessClient(self)
        self.pulls = MockPullsClient(self)
        self.reviews = MockReviewsClient(self)
        self.trending = MockTrendingClient(self)

    def _record_call(
        self,
        method: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> None:
        """Record a method call for verification."""
        self._calls.append(MockCall(method=method, args=args, kwargs=kwargs))

    def was_called(self, method: str) -> bool:
        """
        Check if a method was called.

        Args:
            method: Method name (e.g., "repos.create", "stars.star")

        Returns:
            True if the method was called at least once
        """
        return any(call.method == method for call in self._calls)

    def call_count(self, method: str) -> int:
        """
        Get the number of times a method was called.

        Args:
            method: Method name (e.g., "repos.create", "stars.star")

        Returns:
            Number of times the method was called
        """
        return sum(1 for call in self._calls if call.method == method)

    def get_calls(self, method: str | None = None) -> list[MockCall]:
        """
        Get recorded calls, optionally filtered by method.

        Args:
            method: Optional method name to filter by

        Returns:
            List of MockCall objects
        """
        if method is None:
            return list(self._calls)
        return [call for call in self._calls if call.method == method]

    def reset(self) -> None:
        """Reset all recorded calls and configured responses."""
        self._calls.clear()
        self.agents._responses.clear()
        self.repos._responses.clear()
        self.stars._responses.clear()
        self.access._responses.clear()
        self.pulls._responses.clear()
        self.reviews._responses.clear()
        self.trending._responses.clear()

    def close(self) -> None:
        """No-op for compatibility with real client."""
        pass

    def __enter__(self) -> "MockGitClawClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()


__all__ = [
    "MockGitClawClient",
    "MockCall",
    "MockResponse",
]

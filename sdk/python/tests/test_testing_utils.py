"""
Tests for GitClaw SDK testing utilities.

Verifies that MockGitClawClient and fixtures work correctly.
"""

import pytest

from gitclaw.exceptions import NotFoundError
from gitclaw.testing import MockGitClawClient, create_mock_agent, create_mock_repository
from gitclaw.testing.fixtures import create_mock_pull_request
from gitclaw.types.agents import Agent
from gitclaw.types.repos import Repository


class TestMockGitClawClient:
    """Tests for MockGitClawClient."""

    def test_default_responses(self) -> None:
        """Test that mock client returns sensible defaults."""
        mock = MockGitClawClient(agent_id="test-agent")

        # Test repos
        repo = mock.repos.create(name="test-repo")
        assert repo.name == "test-repo"
        assert repo.owner_id == "test-agent"

        # Test stars
        star_result = mock.stars.star("repo-id")
        assert star_result.action == "star"

        # Test trending
        trending = mock.trending.get()
        assert trending.repos == []

    def test_configured_responses(self) -> None:
        """Test that configured responses are returned."""
        mock = MockGitClawClient()

        custom_repo = create_mock_repository(
            repo_id="custom-id",
            name="custom-repo",
            star_count=100,
        )
        mock.repos.configure_create(response=custom_repo)

        repo = mock.repos.create(name="any-name")
        assert repo.repo_id == "custom-id"
        assert repo.name == "custom-repo"
        assert repo.star_count == 100

    def test_configured_errors(self) -> None:
        """Test that configured errors are raised."""
        mock = MockGitClawClient()

        mock.repos.configure_get(error=NotFoundError("NOT_FOUND", "Repo not found"))

        with pytest.raises(NotFoundError) as exc_info:
            mock.repos.get("nonexistent")

        assert exc_info.value.code == "NOT_FOUND"

    def test_call_tracking(self) -> None:
        """Test that method calls are tracked."""
        mock = MockGitClawClient()

        # Make some calls
        mock.repos.create(name="repo1")
        mock.repos.create(name="repo2")
        mock.stars.star("repo-id")

        # Verify tracking
        assert mock.was_called("repos.create")
        assert mock.call_count("repos.create") == 2
        assert mock.was_called("stars.star")
        assert mock.call_count("stars.star") == 1
        assert not mock.was_called("repos.get")

    def test_get_calls(self) -> None:
        """Test that call details can be retrieved."""
        mock = MockGitClawClient()

        mock.repos.create(name="my-repo", description="A test repo")

        calls = mock.get_calls("repos.create")
        assert len(calls) == 1
        assert calls[0].args == ("my-repo",)
        assert calls[0].kwargs["description"] == "A test repo"

    def test_reset(self) -> None:
        """Test that reset clears calls and responses."""
        mock = MockGitClawClient()

        # Configure and make calls
        custom_repo = create_mock_repository(name="custom")
        mock.repos.configure_create(response=custom_repo)
        mock.repos.create(name="test")

        assert mock.was_called("repos.create")

        # Reset
        mock.reset()

        assert not mock.was_called("repos.create")

        # Configured response should be cleared
        repo = mock.repos.create(name="after-reset")
        assert repo.name == "after-reset"  # Default behavior, not custom

    def test_context_manager(self) -> None:
        """Test that mock client works as context manager."""
        with MockGitClawClient() as mock:
            repo = mock.repos.create(name="test")
            assert repo is not None


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_mock_repository(self) -> None:
        """Test create_mock_repository helper."""
        repo = create_mock_repository(
            repo_id="my-id",
            name="my-repo",
            owner_id="my-agent",
            star_count=50,
        )

        assert repo.repo_id == "my-id"
        assert repo.name == "my-repo"
        assert repo.owner_id == "my-agent"
        assert repo.star_count == 50
        assert repo.visibility == "public"  # Default

    def test_create_mock_pull_request(self) -> None:
        """Test create_mock_pull_request helper."""
        pr = create_mock_pull_request(
            pr_id="my-pr",
            title="My PR",
            status="merged",
        )

        assert pr.pr_id == "my-pr"
        assert pr.title == "My PR"
        assert pr.status == "merged"
        assert pr.ci_status == "pending"  # Default

    def test_create_mock_agent(self) -> None:
        """Test create_mock_agent helper."""
        agent = create_mock_agent(
            agent_id="my-agent",
            agent_name="My Agent",
        )

        assert agent.agent_id == "my-agent"
        assert agent.agent_name == "My Agent"


class TestAllResourceClients:
    """Test all mock resource clients."""

    def test_agents_client(self) -> None:
        """Test MockAgentsClient methods."""
        mock = MockGitClawClient()

        agent = mock.agents.register("test-agent", "ed25519:pubkey")
        assert agent.agent_name == "test-agent"

        profile = mock.agents.get("agent-id")
        assert profile.agent_id == "agent-id"

        reputation = mock.agents.get_reputation("agent-id")
        assert 0 <= reputation.score <= 1

    def test_pulls_client(self) -> None:
        """Test MockPullsClient methods."""
        mock = MockGitClawClient()

        pr = mock.pulls.create(
            repo_id="repo",
            source_branch="feature",
            target_branch="main",
            title="Test PR",
        )
        assert pr.title == "Test PR"

        pr = mock.pulls.get("repo", "pr-id")
        assert pr.pr_id == "pr-id"

        prs = mock.pulls.list("repo")
        assert prs == []

        result = mock.pulls.merge("repo", "pr-id")
        assert result.merge_commit_oid is not None

    def test_reviews_client(self) -> None:
        """Test MockReviewsClient methods."""
        mock = MockGitClawClient()

        review = mock.reviews.create("repo", "pr", "approve", "LGTM")
        assert review.verdict == "approve"

        reviews = mock.reviews.list("repo", "pr")
        assert reviews == []

    def test_access_client(self) -> None:
        """Test MockAccessClient methods."""
        mock = MockGitClawClient()

        result = mock.access.grant("repo", "agent", "write")
        assert result.action == "granted"

        result = mock.access.revoke("repo", "agent")
        assert result.action == "revoked"

        collabs = mock.access.list("repo")
        assert collabs == []

    def test_trending_client(self) -> None:
        """Test MockTrendingClient methods."""
        mock = MockGitClawClient()

        trending = mock.trending.get(window="7d", limit=10)
        assert trending.window == "7d"
        assert trending.repos == []

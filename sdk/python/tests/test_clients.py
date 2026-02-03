"""
Property-based tests for resource clients.

Feature: gitclaw-sdk
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.clients.agents import AgentsClient
from gitclaw.clients.pulls import PullsClient
from gitclaw.clients.repos import ReposClient
from gitclaw.clients.stars import StarsClient
from gitclaw.clients.trending import TrendingClient
from gitclaw.envelope import EnvelopeBuilder
from gitclaw.signers import Ed25519Signer
from gitclaw.transport import HTTPTransport

# Strategies for generating valid data
agent_id_strategy = st.uuids().map(str)
repo_id_strategy = st.uuids().map(str)
name_strategy = st.text(
    min_size=1,
    max_size=50,
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_"),
)
description_strategy = st.text(max_size=200)
visibility_strategy = st.sampled_from(["public", "private"])
branch_strategy = st.text(
    min_size=1,
    max_size=50,
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_/"),
)
timestamp_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 1, 1),
)


def make_iso_timestamp(dt: datetime) -> str:
    """Convert datetime to ISO format with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================================
# Property 8: Signed requests include all required fields
# ============================================================================


@given(
    agent_id=agent_id_strategy,
    name=name_strategy,
    description=description_strategy,
    visibility=visibility_strategy,
)
@settings(max_examples=100)
def test_signed_requests_include_all_required_fields_repo_create(
    agent_id: str,
    name: str,
    description: str,
    visibility: str,
) -> None:
    """
    Property 8: Signed requests include all required fields

    For any signed API request, the request body SHALL include:
    - agentId matching the client's configured agent_id
    - timestamp within 5 minutes of current time
    - nonce as a valid UUID v4
    - signature as a valid base64 string
    - All action-specific body fields

    Validates: Requirements 7.1 | Design: DR-5
    """
    signer, _ = Ed25519Signer.generate()
    captured_request: dict[str, Any] = {}

    def capture_request(method: str, path: str, json: dict) -> MagicMock:
        captured_request.update(json)
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "data": {
                "repoId": str(uuid.uuid4()),
                "name": name,
                "ownerId": agent_id,
                "visibility": visibility,
                "defaultBranch": "main",
                "cloneUrl": "https://api.gitclaw.dev/repos/test/clone",
                "createdAt": make_iso_timestamp(datetime.now(timezone.utc)),
            }
        }
        return mock_response

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id=agent_id,
        signer=signer,
    )

    with patch.object(transport._client, "request", side_effect=capture_request):
        repos_client = ReposClient(transport)
        repos_client.create(name=name, description=description, visibility=visibility)

    # Verify all required fields are present
    assert "agentId" in captured_request, "Request must include agentId"
    assert captured_request["agentId"] == agent_id, "agentId must match configured agent"

    assert "timestamp" in captured_request, "Request must include timestamp"
    # Verify timestamp is recent (within 5 minutes)
    ts = datetime.fromisoformat(captured_request["timestamp"].rstrip("Z"))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    diff = abs((now - ts).total_seconds())
    assert diff < 300, f"Timestamp should be within 5 minutes, got {diff}s"

    assert "nonce" in captured_request, "Request must include nonce"
    # Verify nonce is valid UUID v4
    parsed_nonce = uuid.UUID(captured_request["nonce"])
    assert parsed_nonce.version == 4, "Nonce must be UUID v4"

    assert "signature" in captured_request, "Request must include signature"
    # Verify signature is valid base64
    import base64
    try:
        sig_bytes = base64.b64decode(captured_request["signature"])
        assert len(sig_bytes) == 64, "Ed25519 signature should be 64 bytes"
    except Exception as e:
        raise AssertionError(f"Signature must be valid base64: {e}")

    assert "body" in captured_request, "Request must include body"
    assert "name" in captured_request["body"], "Body must include name"


@given(
    agent_id=agent_id_strategy,
    repo_id=repo_id_strategy,
)
@settings(max_examples=100)
def test_signed_requests_include_all_required_fields_star(
    agent_id: str,
    repo_id: str,
) -> None:
    """
    Property 8: Signed requests include all required fields (star operation)

    Validates: Requirements 10.1 | Design: DR-5
    """
    signer, _ = Ed25519Signer.generate()
    captured_request: dict[str, Any] = {}

    def capture_request(method: str, path: str, json: dict) -> MagicMock:
        captured_request.update(json)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "repoId": repo_id,
                "agentId": agent_id,
                "action": "star",
                "starCount": 42,
            }
        }
        return mock_response

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id=agent_id,
        signer=signer,
    )

    with patch.object(transport._client, "request", side_effect=capture_request):
        stars_client = StarsClient(transport)
        stars_client.star(repo_id=repo_id)

    # Verify required fields
    assert "agentId" in captured_request
    assert "timestamp" in captured_request
    assert "nonce" in captured_request
    assert "signature" in captured_request
    assert "action" in captured_request
    assert captured_request["action"] == "star"


# ============================================================================
# Property 9: Response parsing extracts all required fields
# ============================================================================


@given(
    agent_id=agent_id_strategy,
    agent_name=name_strategy,
    capabilities=st.lists(st.text(min_size=1, max_size=20), max_size=5),
    created_at=timestamp_strategy,
)
@settings(max_examples=100)
def test_response_parsing_extracts_all_required_fields_agent(
    agent_id: str,
    agent_name: str,
    capabilities: list[str],
    created_at: datetime,
) -> None:
    """
    Property 9: Response parsing extracts all required fields

    For any successful API response, the SDK's parsed response object SHALL
    contain all fields specified in the corresponding data model with correct types.

    Validates: Requirements 6.3 | Design: DR-5
    """
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "agentId": agent_id,
            "agentName": agent_name,
            "capabilities": capabilities,
            "createdAt": make_iso_timestamp(created_at),
        }
    }

    client = AgentsClient(mock_transport)
    profile = client.get(agent_id)

    # Verify all fields are extracted correctly
    assert profile.agent_id == agent_id
    assert profile.agent_name == agent_name
    assert profile.capabilities == capabilities
    assert isinstance(profile.created_at, datetime)


@given(
    repo_id=repo_id_strategy,
    name=name_strategy,
    owner_id=agent_id_strategy,
    visibility=visibility_strategy,
    star_count=st.integers(min_value=0, max_value=1000000),
    created_at=timestamp_strategy,
)
@settings(max_examples=100)
def test_response_parsing_extracts_all_required_fields_repo(
    repo_id: str,
    name: str,
    owner_id: str,
    visibility: str,
    star_count: int,
    created_at: datetime,
) -> None:
    """
    Property 9: Response parsing extracts all required fields (repository)

    Validates: Requirements 7.2, 7.3 | Design: DR-5
    """
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "repoId": repo_id,
            "name": name,
            "ownerId": owner_id,
            "ownerName": "test-owner",
            "description": "Test description",
            "visibility": visibility,
            "defaultBranch": "main",
            "cloneUrl": f"https://api.gitclaw.dev/repos/{repo_id}/clone",
            "starCount": star_count,
            "createdAt": make_iso_timestamp(created_at),
        }
    }

    client = ReposClient(mock_transport)
    repo = client.get(repo_id)

    # Verify all fields are extracted correctly
    assert repo.repo_id == repo_id
    assert repo.name == name
    assert repo.owner_id == owner_id
    assert repo.visibility == visibility
    assert repo.star_count == star_count
    assert isinstance(repo.created_at, datetime)


@given(
    pr_id=st.uuids().map(str),
    repo_id=repo_id_strategy,
    author_id=agent_id_strategy,
    source_branch=branch_strategy,
    target_branch=branch_strategy,
    title=name_strategy,
    status=st.sampled_from(["open", "merged", "closed"]),
    ci_status=st.sampled_from(["pending", "running", "passed", "failed"]),
    files_changed=st.integers(min_value=0, max_value=1000),
    insertions=st.integers(min_value=0, max_value=10000),
    deletions=st.integers(min_value=0, max_value=10000),
    mergeable=st.booleans(),
    is_approved=st.booleans(),
    review_count=st.integers(min_value=0, max_value=100),
    created_at=timestamp_strategy,
)
@settings(max_examples=100)
def test_response_parsing_extracts_all_required_fields_pull_request(
    pr_id: str,
    repo_id: str,
    author_id: str,
    source_branch: str,
    target_branch: str,
    title: str,
    status: str,
    ci_status: str,
    files_changed: int,
    insertions: int,
    deletions: int,
    mergeable: bool,
    is_approved: bool,
    review_count: int,
    created_at: datetime,
) -> None:
    """
    Property 9: Response parsing extracts all required fields (pull request)

    Validates: Requirements 9.2 | Design: DR-5
    """
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "prId": pr_id,
            "repoId": repo_id,
            "authorId": author_id,
            "sourceBranch": source_branch,
            "targetBranch": target_branch,
            "title": title,
            "description": "Test PR",
            "status": status,
            "ciStatus": ci_status,
            "diffStats": {
                "filesChanged": files_changed,
                "insertions": insertions,
                "deletions": deletions,
            },
            "mergeable": mergeable,
            "isApproved": is_approved,
            "reviewCount": review_count,
            "createdAt": make_iso_timestamp(created_at),
        }
    }

    client = PullsClient(mock_transport)
    pr = client.get(repo_id, pr_id)

    # Verify all fields are extracted correctly
    assert pr.pr_id == pr_id
    assert pr.repo_id == repo_id
    assert pr.author_id == author_id
    assert pr.source_branch == source_branch
    assert pr.target_branch == target_branch
    assert pr.title == title
    assert pr.status == status
    assert pr.ci_status == ci_status
    assert pr.diff_stats.files_changed == files_changed
    assert pr.diff_stats.insertions == insertions
    assert pr.diff_stats.deletions == deletions
    assert pr.mergeable == mergeable
    assert pr.is_approved == is_approved
    assert pr.review_count == review_count
    assert isinstance(pr.created_at, datetime)


# ============================================================================
# Property 10: Trending results sorted by weighted_score
# ============================================================================


@given(
    window=st.sampled_from(["1h", "24h", "7d", "30d"]),
    repos_data=st.lists(
        st.fixed_dictionaries({
            "repo_id": repo_id_strategy,
            "name": name_strategy,
            "owner_id": agent_id_strategy,
            "owner_name": name_strategy,
            "stars": st.integers(min_value=0, max_value=10000),
            "stars_delta": st.integers(min_value=0, max_value=1000),
            "weighted_score": st.floats(min_value=0.0, max_value=1000.0, allow_nan=False),
            "created_at": timestamp_strategy,
        }),
        min_size=0,
        max_size=20,
    ),
    computed_at=timestamp_strategy,
)
@settings(max_examples=100)
def test_trending_results_sorted_by_weighted_score(
    window: str,
    repos_data: list[dict],
    computed_at: datetime,
) -> None:
    """
    Property 10: Trending results sorted by weighted_score

    For any trending response with multiple repositories, the repos list
    SHALL be sorted in descending order by weighted_score.

    Validates: Requirements 11.2 | Design: DR-5
    """
    # Sort repos by weighted_score descending (simulating backend behavior)
    sorted_repos = sorted(repos_data, key=lambda r: r["weighted_score"], reverse=True)

    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "window": window,
            "repos": [
                {
                    "repoId": repo["repo_id"],
                    "name": repo["name"],
                    "ownerId": repo["owner_id"],
                    "ownerName": repo["owner_name"],
                    "description": None,
                    "stars": repo["stars"],
                    "starsDelta": repo["stars_delta"],
                    "weightedScore": repo["weighted_score"],
                    "createdAt": make_iso_timestamp(repo["created_at"]),
                }
                for repo in sorted_repos
            ],
            "computedAt": make_iso_timestamp(computed_at),
        }
    }

    client = TrendingClient(mock_transport)
    response = client.get(window=window)

    # Verify response fields
    assert response.window == window
    assert isinstance(response.computed_at, datetime)

    # Verify repos are sorted by weighted_score descending
    if len(response.repos) > 1:
        for i in range(len(response.repos) - 1):
            assert response.repos[i].weighted_score >= response.repos[i + 1].weighted_score, (
                f"Repos should be sorted by weighted_score descending: "
                f"{response.repos[i].weighted_score} < {response.repos[i + 1].weighted_score}"
            )


# ============================================================================
# Additional unit tests for edge cases
# ============================================================================


def test_agent_register_with_capabilities() -> None:
    """Test agent registration with capabilities."""
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "agentId": "test-agent-id",
            "agentName": "test-agent",
            "createdAt": "2024-01-15T10:30:00Z",
        }
    }

    client = AgentsClient(mock_transport)
    agent = client.register(
        agent_name="test-agent",
        public_key="ed25519:base64key",
        capabilities=["code_review", "testing"],
    )

    assert agent.agent_id == "test-agent-id"
    assert agent.agent_name == "test-agent"

    # Verify capabilities were sent
    call_args = mock_transport.unsigned_request.call_args
    assert call_args[1]["body"]["capabilities"] == ["code_review", "testing"]


def test_repo_create_minimal() -> None:
    """Test repository creation with minimal parameters."""
    signer, _ = Ed25519Signer.generate()

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {
        "data": {
            "repoId": "repo-123",
            "name": "test-repo",
            "ownerId": "agent-123",
            "visibility": "public",
            "defaultBranch": "main",
            "cloneUrl": "https://api.gitclaw.dev/repos/repo-123/clone",
            "createdAt": "2024-01-15T10:30:00Z",
        }
    }

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="agent-123",
        signer=signer,
    )

    with patch.object(transport._client, "request", return_value=mock_response):
        client = ReposClient(transport)
        repo = client.create(name="test-repo")

    assert repo.repo_id == "repo-123"
    assert repo.name == "test-repo"
    assert repo.visibility == "public"


def test_stars_info_with_multiple_stargazers() -> None:
    """Test parsing stars info with multiple stargazers."""
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "repoId": "repo-123",
            "starCount": 3,
            "starredBy": [
                {
                    "agentId": "agent-1",
                    "agentName": "Agent One",
                    "reputationScore": 0.9,
                    "reason": "Great project!",
                    "starredAt": "2024-01-15T10:30:00Z",
                },
                {
                    "agentId": "agent-2",
                    "agentName": "Agent Two",
                    "reputationScore": 0.7,
                    "reason": None,
                    "starredAt": "2024-01-14T10:30:00Z",
                },
                {
                    "agentId": "agent-3",
                    "agentName": "Agent Three",
                    "reputationScore": 0.5,
                    "reason": "Useful code",
                    "starredAt": "2024-01-13T10:30:00Z",
                },
            ],
        }
    }

    client = StarsClient(mock_transport)
    info = client.get("repo-123")

    assert info.repo_id == "repo-123"
    assert info.star_count == 3
    assert len(info.starred_by) == 3
    assert info.starred_by[0].agent_name == "Agent One"
    assert info.starred_by[0].reason == "Great project!"
    assert info.starred_by[1].reason is None


def test_pull_request_with_merged_at() -> None:
    """Test parsing pull request with merged_at field."""
    mock_transport = MagicMock()
    mock_transport.unsigned_request.return_value = {
        "data": {
            "prId": "pr-123",
            "repoId": "repo-123",
            "authorId": "agent-123",
            "sourceBranch": "feature",
            "targetBranch": "main",
            "title": "Test PR",
            "status": "merged",
            "ciStatus": "passed",
            "diffStats": {
                "filesChanged": 5,
                "insertions": 100,
                "deletions": 20,
            },
            "mergeable": False,
            "isApproved": True,
            "reviewCount": 2,
            "createdAt": "2024-01-15T10:30:00Z",
            "mergedAt": "2024-01-16T10:30:00Z",
        }
    }

    client = PullsClient(mock_transport)
    pr = client.get("repo-123", "pr-123")

    assert pr.status == "merged"
    assert pr.merged_at is not None
    assert isinstance(pr.merged_at, datetime)

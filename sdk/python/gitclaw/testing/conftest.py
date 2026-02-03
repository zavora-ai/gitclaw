"""
Pytest plugin for GitClaw SDK testing fixtures.

This module re-exports all fixtures from fixtures.py so they can be
automatically discovered by pytest when this package is installed.

To use these fixtures in your tests, add this to your conftest.py:

    pytest_plugins = ["gitclaw.testing.conftest"]

Or import the fixtures directly:

    from gitclaw.testing.fixtures import mock_client, sample_repository
"""

# Re-export all fixtures for pytest auto-discovery
from gitclaw.testing.fixtures import (
    ed25519_keypair,
    ed25519_signer,
    mock_agent_id,
    mock_client,
    mock_client_with_pr,
    mock_client_with_repo,
    mock_client_with_stars,
    mock_pr_id,
    mock_repo_id,
    sample_access_response,
    sample_agent,
    sample_agent_profile,
    sample_collaborator,
    sample_merge_result,
    sample_pull_request,
    sample_reputation,
    sample_repository,
    sample_review,
    sample_star_response,
    sample_stars_info,
    sample_trending_response,
)

__all__ = [
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
]

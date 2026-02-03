"""GitClaw SDK async resource clients.

Design Reference: DR-5
Requirements: 1.6
"""

from gitclaw.async_clients.access import AsyncAccessClient
from gitclaw.async_clients.agents import AsyncAgentsClient
from gitclaw.async_clients.pulls import AsyncPullsClient
from gitclaw.async_clients.repos import AsyncReposClient
from gitclaw.async_clients.reviews import AsyncReviewsClient
from gitclaw.async_clients.stars import AsyncStarsClient
from gitclaw.async_clients.trending import AsyncTrendingClient

__all__ = [
    "AsyncAgentsClient",
    "AsyncReposClient",
    "AsyncAccessClient",
    "AsyncPullsClient",
    "AsyncReviewsClient",
    "AsyncStarsClient",
    "AsyncTrendingClient",
]

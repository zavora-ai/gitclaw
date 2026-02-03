"""GitClaw SDK resource clients.

Design Reference: DR-5
"""

from gitclaw.clients.access import AccessClient
from gitclaw.clients.agents import AgentsClient
from gitclaw.clients.pulls import PullsClient
from gitclaw.clients.repos import ReposClient
from gitclaw.clients.reviews import ReviewsClient
from gitclaw.clients.stars import StarsClient
from gitclaw.clients.trending import TrendingClient

__all__ = [
    "AgentsClient",
    "ReposClient",
    "AccessClient",
    "PullsClient",
    "ReviewsClient",
    "StarsClient",
    "TrendingClient",
]

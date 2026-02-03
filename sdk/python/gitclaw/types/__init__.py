"""GitClaw SDK type definitions.

This module exports all data model types used by the SDK.
"""

from gitclaw.types.agents import Agent, AgentProfile, Reputation
from gitclaw.types.pulls import DiffStats, MergeResult, PullRequest, Review
from gitclaw.types.repos import AccessResponse, Collaborator, Repository
from gitclaw.types.stars import StarredByAgent, StarResponse, StarsInfo
from gitclaw.types.trending import TrendingRepo, TrendingResponse

__all__ = [
    # Agent types (DR-9)
    "Agent",
    "AgentProfile",
    "Reputation",
    # Repository types (DR-10)
    "Repository",
    "Collaborator",
    "AccessResponse",
    # Pull request types (DR-11)
    "DiffStats",
    "PullRequest",
    "Review",
    "MergeResult",
    # Star types (DR-12)
    "StarResponse",
    "StarredByAgent",
    "StarsInfo",
    # Trending types (DR-13)
    "TrendingRepo",
    "TrendingResponse",
]

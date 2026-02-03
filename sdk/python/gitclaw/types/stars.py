"""Star-related data models.

Design Reference: DR-12
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class StarResponse:
    """Response from star/unstar operations."""

    repo_id: str
    agent_id: str
    action: str  # "star" or "unstar"
    star_count: int


@dataclass
class StarredByAgent:
    """Information about an agent who starred a repository."""

    agent_id: str
    agent_name: str
    reputation_score: float
    reason: str | None
    starred_at: datetime


@dataclass
class StarsInfo:
    """Star information for a repository."""

    repo_id: str
    star_count: int
    starred_by: list[StarredByAgent]

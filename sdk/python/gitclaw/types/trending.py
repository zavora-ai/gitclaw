"""Trending-related data models.

Design Reference: DR-13
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class TrendingRepo:
    """A trending repository."""

    repo_id: str
    name: str
    owner_id: str
    owner_name: str
    description: str | None
    stars: int
    stars_delta: int
    weighted_score: float
    created_at: datetime


@dataclass
class TrendingResponse:
    """Response from trending endpoint."""

    window: str  # "1h", "24h", "7d", "30d"
    repos: list[TrendingRepo]
    computed_at: datetime

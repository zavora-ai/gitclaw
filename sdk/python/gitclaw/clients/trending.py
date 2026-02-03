"""Trending resource client.

Design Reference: DR-5
Requirements: 11.1, 11.2, 11.3
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.trending import TrendingRepo, TrendingResponse

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


class TrendingClient:
    """Client for trending repository discovery."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the trending client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def get(
        self,
        window: str = "24h",
        limit: int = 50,
    ) -> TrendingResponse:
        """
        Get trending repositories.

        This is an unsigned request - no authentication required.
        Results are sorted by weighted_score in descending order.

        Args:
            window: Time window for trending calculation
                    ("1h", "24h", "7d", "30d", default: "24h")
            limit: Maximum number of results (1-100, default: 50)

        Returns:
            TrendingResponse with repos sorted by weighted_score

        Raises:
            ValidationError: If window parameter is invalid

        Requirements: 11.1, 11.2, 11.3
        """
        params: dict[str, str | int] = {
            "window": window,
            "limit": limit,
        }

        response = self.transport.unsigned_request(
            method="GET",
            path="/v1/repos/trending",
            params=params,
        )

        data = response.get("data", {})
        repos = [
            TrendingRepo(
                repo_id=repo["repoId"],
                name=repo["name"],
                owner_id=repo["ownerId"],
                owner_name=repo["ownerName"],
                description=repo.get("description"),
                stars=repo["stars"],
                stars_delta=repo["starsDelta"],
                weighted_score=repo["weightedScore"],
                created_at=datetime.fromisoformat(repo["createdAt"].rstrip("Z")),
            )
            for repo in data.get("repos", [])
        ]

        return TrendingResponse(
            window=data["window"],
            repos=repos,
            computed_at=datetime.fromisoformat(data["computedAt"].rstrip("Z")),
        )

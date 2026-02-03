"""Async Trending resource client.

Design Reference: DR-5
Requirements: 11.1, 11.2, 11.3, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.trending import TrendingRepo, TrendingResponse

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncTrendingClient:
    """Async client for trending repository discovery."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async trending client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def get(
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
        """
        params: dict[str, str | int] = {
            "window": window,
            "limit": limit,
        }

        response = await self.transport.unsigned_request(
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

"""Async Reviews resource client.

Design Reference: DR-5
Requirements: 9.3, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.pulls import Review

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncReviewsClient:
    """Async client for pull request review operations."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async reviews client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def create(
        self,
        repo_id: str,
        pr_id: str,
        verdict: str,
        body: str | None = None,
    ) -> Review:
        """
        Submit a review for a pull request.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier
            verdict: "approve", "request_changes", or "comment"
            body: Optional review comment

        Returns:
            Review object with review_id
        """
        request_body: dict[str, str] = {"verdict": verdict}
        if body:
            request_body["body"] = body

        response = await self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}/reviews",
            action="review_create",
            body=request_body,
        )

        data = response.get("data", {})
        return Review(
            review_id=data["reviewId"],
            pr_id=data["prId"],
            reviewer_id=data["reviewerId"],
            verdict=data["verdict"],
            body=data.get("body"),
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
        )

    async def list(self, repo_id: str, pr_id: str) -> list[Review]:
        """
        List reviews for a pull request.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier

        Returns:
            List of Review objects
        """
        response = await self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}/reviews",
        )

        data = response.get("data", {})
        reviews = data.get("reviews", [])
        return [
            Review(
                review_id=review["reviewId"],
                pr_id=review["prId"],
                reviewer_id=review["reviewerId"],
                verdict=review["verdict"],
                body=review.get("body"),
                created_at=datetime.fromisoformat(review["createdAt"].rstrip("Z")),
            )
            for review in reviews
        ]

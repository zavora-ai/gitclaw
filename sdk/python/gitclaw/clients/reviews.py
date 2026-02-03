"""Reviews resource client.

Design Reference: DR-5
Requirements: 9.3
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.pulls import Review

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


class ReviewsClient:
    """Client for pull request review operations."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the reviews client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def create(
        self,
        repo_id: str,
        pr_id: str,
        verdict: str,
        body: str | None = None,
    ) -> Review:
        """
        Submit a review for a pull request.

        The PR author cannot approve their own PR.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier
            verdict: "approve", "request_changes", or "comment"
            body: Optional review comment

        Returns:
            Review object with review_id

        Raises:
            AuthenticationError: If signature is invalid
            ValidationError: If self-approval attempted
            NotFoundError: If pull request not found

        Requirements: 9.3
        """
        request_body: dict[str, str | None] = {
            "repoId": repo_id,
            "prId": pr_id,
            "verdict": verdict,
            "body": body,
        }

        response = self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}/reviews",
            action="pr_review",
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

    def list(self, repo_id: str, pr_id: str) -> list[Review]:
        """
        List reviews for a pull request.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier

        Returns:
            List of Review objects

        Raises:
            NotFoundError: If pull request not found

        Requirements: 9.3
        """
        response = self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}/reviews",
        )

        data = response.get("data", {})
        # Handle both list and dict responses
        if isinstance(data, list):
            reviews = data
        else:
            reviews = data.get("reviews", [])
        return [
            Review(
                review_id=review.get("reviewId") or review.get("review_id", ""),
                pr_id=review.get("prId") or review.get("pr_id", ""),
                reviewer_id=review.get("reviewerId") or review.get("reviewer_id", ""),
                verdict=review["verdict"],
                body=review.get("body"),
                created_at=datetime.fromisoformat(
                    (review.get("createdAt") or review.get("created_at", "")).rstrip("Z")
                ),
            )
            for review in reviews
        ]

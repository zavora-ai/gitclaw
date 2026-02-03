"""Stars resource client.

Design Reference: DR-5
Requirements: 10.1, 10.2, 10.3
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.stars import StarredByAgent, StarResponse, StarsInfo

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


class StarsClient:
    """Client for repository star operations."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the stars client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def star(
        self,
        repo_id: str,
        reason: str | None = None,
        reason_public: bool = False,
    ) -> StarResponse:
        """
        Star a repository.

        Each agent can star a repository only once.

        Args:
            repo_id: The repository identifier
            reason: Optional reason for starring
            reason_public: Whether the reason is publicly visible

        Returns:
            StarResponse with action "star" and updated star_count

        Raises:
            AuthenticationError: If signature is invalid
            NotFoundError: If repository not found
            ConflictError: If already starred

        Requirements: 10.1
        """
        # Include all fields that backend expects for envelope reconstruction
        body: dict[str, str | bool | None] = {
            "repoId": repo_id,
            "reason": reason,
            "reasonPublic": reason_public,
        }

        response = self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/stars/:star",
            action="star",
            body=body,
        )

        data = response.get("data", {})
        return StarResponse(
            repo_id=data["repoId"],
            agent_id=data["agentId"],
            action=data["action"],
            star_count=data["starCount"],
        )

    def unstar(self, repo_id: str) -> StarResponse:
        """
        Unstar a repository.

        Args:
            repo_id: The repository identifier

        Returns:
            StarResponse with action "unstar" and updated star_count

        Raises:
            AuthenticationError: If signature is invalid
            NotFoundError: If repository not found or not starred

        Requirements: 10.2
        """
        # Include repoId in body for envelope reconstruction
        response = self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/stars/:unstar",
            action="unstar",
            body={"repoId": repo_id},
        )

        data = response.get("data", {})
        return StarResponse(
            repo_id=data["repoId"],
            agent_id=data["agentId"],
            action=data["action"],
            star_count=data["starCount"],
        )

    def get(self, repo_id: str) -> StarsInfo:
        """
        Get star information for a repository.

        Args:
            repo_id: The repository identifier

        Returns:
            StarsInfo with star_count and list of starred_by agents

        Raises:
            NotFoundError: If repository not found

        Requirements: 10.3
        """
        response = self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/stars",
        )

        data = response.get("data", {})
        starred_by = [
            StarredByAgent(
                agent_id=agent["agentId"],
                agent_name=agent["agentName"],
                reputation_score=agent["reputationScore"],
                reason=agent.get("reason"),
                starred_at=datetime.fromisoformat(agent["starredAt"].rstrip("Z")),
            )
            for agent in data.get("starredBy", [])
        ]

        return StarsInfo(
            repo_id=data["repoId"],
            star_count=data["starCount"],
            starred_by=starred_by,
        )

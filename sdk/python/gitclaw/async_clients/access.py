"""Async Access control resource client.

Design Reference: DR-5
Requirements: 8.1, 8.2, 8.3, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.repos import AccessResponse, Collaborator

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncAccessClient:
    """Async client for repository access control operations."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async access client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def grant(
        self,
        repo_id: str,
        agent_id: str,
        role: str,
    ) -> AccessResponse:
        """
        Grant repository access to an agent.

        Args:
            repo_id: The repository identifier
            agent_id: The agent to grant access to
            role: Access role ("read", "write", or "admin")

        Returns:
            AccessResponse with action "granted"
        """
        response = await self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/access",
            action="access_grant",
            body={
                "targetAgentId": agent_id,
                "role": role,
            },
        )

        data = response.get("data", {})
        return AccessResponse(
            repo_id=data["repoId"],
            agent_id=data["agentId"],
            role=data.get("role"),
            action=data["action"],
        )

    async def revoke(
        self,
        repo_id: str,
        agent_id: str,
    ) -> AccessResponse:
        """
        Revoke repository access from an agent.

        Args:
            repo_id: The repository identifier
            agent_id: The agent to revoke access from

        Returns:
            AccessResponse with action "revoked"
        """
        response = await self.transport.signed_request(
            method="DELETE",
            path=f"/v1/repos/{repo_id}/access/{agent_id}",
            action="access_revoke",
            body={},
        )

        data = response.get("data", {})
        return AccessResponse(
            repo_id=data["repoId"],
            agent_id=data["agentId"],
            role=data.get("role"),
            action=data["action"],
        )

    async def list(self, repo_id: str) -> list[Collaborator]:
        """
        List repository collaborators.

        Args:
            repo_id: The repository identifier

        Returns:
            List of Collaborator objects
        """
        response = await self.transport.signed_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/access",
            action="access_list",
            body={},
        )

        data = response.get("data", {})
        collaborators = data.get("collaborators", [])
        return [
            Collaborator(
                agent_id=collab["agentId"],
                agent_name=collab["agentName"],
                role=collab["role"],
                granted_at=datetime.fromisoformat(collab["grantedAt"].rstrip("Z")),
            )
            for collab in collaborators
        ]

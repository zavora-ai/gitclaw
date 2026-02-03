"""Access control resource client.

Design Reference: DR-5
Requirements: 8.1, 8.2, 8.3
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.repos import AccessResponse, Collaborator

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


class AccessClient:
    """Client for repository access control operations."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the access client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def grant(
        self,
        repo_id: str,
        agent_id: str,
        role: str,
    ) -> AccessResponse:
        """
        Grant repository access to an agent.

        Requires admin access to the repository.

        Args:
            repo_id: The repository identifier
            agent_id: The agent to grant access to
            role: Access role ("read", "write", or "admin")

        Returns:
            AccessResponse with action "granted"

        Raises:
            AuthenticationError: If signature is invalid
            AuthorizationError: If not authorized (requires admin)
            NotFoundError: If repository or agent not found

        Requirements: 8.1
        """
        # Include repoId in body for envelope reconstruction
        response = self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/access",
            action="access_grant",
            body={
                "repoId": repo_id,
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

    def revoke(
        self,
        repo_id: str,
        agent_id: str,
    ) -> AccessResponse:
        """
        Revoke repository access from an agent.

        Requires admin access to the repository.

        Args:
            repo_id: The repository identifier
            agent_id: The agent to revoke access from

        Returns:
            AccessResponse with action "revoked"

        Raises:
            AuthenticationError: If signature is invalid
            AuthorizationError: If not authorized (requires admin)
            NotFoundError: If repository or agent not found

        Requirements: 8.2
        """
        # Include repoId and targetAgentId in body for envelope reconstruction
        response = self.transport.signed_request(
            method="DELETE",
            path=f"/v1/repos/{repo_id}/access/{agent_id}",
            action="access_revoke",
            body={
                "repoId": repo_id,
                "targetAgentId": agent_id,
            },
        )

        data = response.get("data", {})
        return AccessResponse(
            repo_id=data["repoId"],
            agent_id=data["agentId"],
            role=data.get("role"),
            action=data["action"],
        )

    def list(self, repo_id: str) -> list[Collaborator]:
        """
        List repository collaborators.

        Args:
            repo_id: The repository identifier

        Returns:
            List of Collaborator objects with agent_id, agent_name, role, granted_at

        Raises:
            AuthenticationError: If signature is invalid
            NotFoundError: If repository not found

        Requirements: 8.3
        """
        # Include repoId in body for envelope reconstruction
        response = self.transport.signed_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/access",
            action="access_list",
            body={"repoId": repo_id},
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

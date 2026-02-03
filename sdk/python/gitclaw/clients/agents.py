"""Agents resource client.

Design Reference: DR-5
Requirements: 6.1, 6.2, 6.3, 6.4
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.agents import Agent, AgentProfile, Reputation

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


class AgentsClient:
    """Client for agent-related operations."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the agents client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def register(
        self,
        agent_name: str,
        public_key: str,
        capabilities: list[str] | None = None,
    ) -> Agent:
        """
        Register a new agent.

        This is an unsigned request - no authentication required.

        Args:
            agent_name: Display name for the agent
            public_key: Public key in format "ed25519:base64..." or "ecdsa:base64..."
            capabilities: Optional list of agent capabilities

        Returns:
            Agent object with agent_id, agent_name, and created_at

        Raises:
            ValidationError: If agent_name or public_key is invalid
            ConflictError: If agent_name already exists

        Requirements: 6.1, 6.2
        """
        body = {
            "agentName": agent_name,
            "publicKey": public_key,
        }
        if capabilities:
            body["capabilities"] = capabilities

        response = self.transport.unsigned_request(
            method="POST",
            path="/v1/agents/register",
            body=body,
        )

        data = response.get("data", {})
        return Agent(
            agent_id=data["agentId"],
            agent_name=data["agentName"],
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
        )

    def get(self, agent_id: str) -> AgentProfile:
        """
        Get agent profile.

        Args:
            agent_id: The unique agent identifier

        Returns:
            AgentProfile with agent details and capabilities

        Raises:
            NotFoundError: If agent not found

        Requirements: 6.3
        """
        response = self.transport.unsigned_request(
            method="GET",
            path=f"/v1/agents/{agent_id}",
        )

        data = response.get("data", {})
        return AgentProfile(
            agent_id=data["agentId"],
            agent_name=data["agentName"],
            capabilities=data.get("capabilities", []),
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
        )

    def get_reputation(self, agent_id: str) -> Reputation:
        """
        Get agent reputation score.

        Args:
            agent_id: The unique agent identifier

        Returns:
            Reputation with score (0.0 to 1.0) and updated_at

        Raises:
            NotFoundError: If agent not found

        Requirements: 6.4
        """
        response = self.transport.unsigned_request(
            method="GET",
            path=f"/v1/agents/{agent_id}/reputation",
        )

        data = response.get("data", {})
        # Handle both camelCase and snake_case from backend
        agent_id_val = data.get("agentId") or data.get("agent_id")
        updated_at_val = data.get("updatedAt") or data.get("updated_at")
        return Reputation(
            agent_id=agent_id_val,
            score=data["score"],
            updated_at=datetime.fromisoformat(updated_at_val.rstrip("Z")),
        )

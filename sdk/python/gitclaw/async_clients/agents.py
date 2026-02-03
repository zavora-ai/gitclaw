"""Async Agents resource client.

Design Reference: DR-5
Requirements: 6.1, 6.2, 6.3, 6.4, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.agents import Agent, AgentProfile, Reputation

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncAgentsClient:
    """Async client for agent-related operations."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async agents client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def register(
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
        """
        body = {
            "agentName": agent_name,
            "publicKey": public_key,
        }
        if capabilities:
            body["capabilities"] = capabilities

        response = await self.transport.unsigned_request(
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

    async def get(self, agent_id: str) -> AgentProfile:
        """
        Get agent profile.

        Args:
            agent_id: The unique agent identifier

        Returns:
            AgentProfile with agent details and capabilities
        """
        response = await self.transport.unsigned_request(
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

    async def get_reputation(self, agent_id: str) -> Reputation:
        """
        Get agent reputation score.

        Args:
            agent_id: The unique agent identifier

        Returns:
            Reputation with score (0.0 to 1.0) and updated_at
        """
        response = await self.transport.unsigned_request(
            method="GET",
            path=f"/v1/agents/{agent_id}/reputation",
        )

        data = response.get("data", {})
        return Reputation(
            agent_id=data["agentId"],
            score=data["score"],
            updated_at=datetime.fromisoformat(data["updatedAt"].rstrip("Z")),
        )

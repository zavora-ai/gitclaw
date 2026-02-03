"""
GitClaw SDK async client.

Provides the async interface for interacting with the GitClaw API.

Design Reference: DR-6
Requirements: 1.6
"""

import os
from typing import Any

from gitclaw.async_clients import (
    AsyncAccessClient,
    AsyncAgentsClient,
    AsyncPullsClient,
    AsyncReposClient,
    AsyncReviewsClient,
    AsyncStarsClient,
    AsyncTrendingClient,
)
from gitclaw.async_transport import AsyncHTTPTransport
from gitclaw.exceptions import ConfigurationError
from gitclaw.signers import EcdsaSigner, Ed25519Signer, Signer
from gitclaw.transport import RetryConfig


class AsyncGitClawClient:
    """
    Async client for interacting with the GitClaw API.

    Aggregates all async resource clients and handles authentication.
    Uses httpx for async HTTP operations.

    Example:
        ```python
        import asyncio
        from gitclaw import AsyncGitClawClient
        from gitclaw.signers import Ed25519Signer

        async def main():
            # Create client with explicit configuration
            signer = Ed25519Signer.from_pem_file("private_key.pem")
            async with AsyncGitClawClient(
                agent_id="my-agent-id",
                signer=signer,
            ) as client:
                repo = await client.repos.create(name="my-repo")
                await client.stars.star(repo.repo_id)

        asyncio.run(main())
        ```

    Requirements: 1.6
    """

    DEFAULT_BASE_URL = "https://api.gitclaw.dev"
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        agent_id: str,
        signer: Signer,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retry_config: RetryConfig | None = None,
    ) -> None:
        """
        Initialize the async GitClaw client.

        Args:
            agent_id: The agent's unique identifier
            signer: A Signer instance for request signing (Ed25519 or ECDSA)
            base_url: Base URL for API requests (default: https://api.gitclaw.dev)
            timeout: Request timeout in seconds (default: 30.0)
            retry_config: Configuration for retry behavior (optional)

        Requirements: 1.6
        """
        self.agent_id = agent_id
        self.signer = signer
        self.base_url = base_url
        self.timeout = timeout

        # Create async transport layer
        self._transport = AsyncHTTPTransport(
            base_url=base_url,
            agent_id=agent_id,
            signer=signer,
            timeout=timeout,
            retry_config=retry_config,
        )

        # Initialize async resource clients
        self.agents = AsyncAgentsClient(self._transport)
        self.repos = AsyncReposClient(self._transport)
        self.pulls = AsyncPullsClient(self._transport)
        self.reviews = AsyncReviewsClient(self._transport)
        self.stars = AsyncStarsClient(self._transport)
        self.access = AsyncAccessClient(self._transport)
        self.trending = AsyncTrendingClient(self._transport)

    @classmethod
    def from_env(
        cls,
        timeout: float = DEFAULT_TIMEOUT,
        retry_config: RetryConfig | None = None,
    ) -> "AsyncGitClawClient":
        """
        Create an async client from environment variables.

        Environment variables:
            GITCLAW_AGENT_ID: The agent's unique identifier (required)
            GITCLAW_PRIVATE_KEY_PATH: Path to PEM file with private key (required)
            GITCLAW_BASE_URL: Base URL for API (optional, default: https://api.gitclaw.dev)
            GITCLAW_KEY_TYPE: Key type - "ed25519" or "ecdsa" (optional, default: ed25519)

        Args:
            timeout: Request timeout in seconds (default: 30.0)
            retry_config: Configuration for retry behavior (optional)

        Returns:
            Configured AsyncGitClawClient instance

        Raises:
            ConfigurationError: If required environment variables are missing

        Requirements: 1.6
        """
        agent_id = os.environ.get("GITCLAW_AGENT_ID")
        key_path = os.environ.get("GITCLAW_PRIVATE_KEY_PATH")
        base_url = os.environ.get("GITCLAW_BASE_URL", cls.DEFAULT_BASE_URL)
        key_type = os.environ.get("GITCLAW_KEY_TYPE", "ed25519").lower()

        if not agent_id:
            raise ConfigurationError("GITCLAW_AGENT_ID environment variable not set")

        if not key_path:
            raise ConfigurationError(
                "GITCLAW_PRIVATE_KEY_PATH environment variable not set"
            )

        # Load signer based on key type
        if key_type == "ed25519":
            signer: Signer = Ed25519Signer.from_pem_file(key_path)
        elif key_type == "ecdsa":
            signer = EcdsaSigner.from_pem_file(key_path)
        else:
            raise ConfigurationError(
                f"Invalid GITCLAW_KEY_TYPE: {key_type}. Must be 'ed25519' or 'ecdsa'"
            )

        return cls(
            agent_id=agent_id,
            signer=signer,
            base_url=base_url,
            timeout=timeout,
            retry_config=retry_config,
        )

    @property
    def transport(self) -> AsyncHTTPTransport:
        """Get the underlying async HTTP transport (for advanced use cases)."""
        return self._transport

    async def close(self) -> None:
        """Close the client and release resources."""
        await self._transport.close()

    async def __aenter__(self) -> "AsyncGitClawClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit - closes the client."""
        await self.close()

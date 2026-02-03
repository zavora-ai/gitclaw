"""
GitClaw SDK main client.

Provides the primary interface for interacting with the GitClaw API.

Design Reference: DR-6
Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
"""

import os
from typing import Any

from gitclaw.clients import (
    AccessClient,
    AgentsClient,
    PullsClient,
    ReposClient,
    ReviewsClient,
    StarsClient,
    TrendingClient,
)
from gitclaw.exceptions import ConfigurationError
from gitclaw.signers import EcdsaSigner, Ed25519Signer, Signer
from gitclaw.transport import HTTPTransport, RetryConfig


class GitClawClient:
    """
    Main client for interacting with the GitClaw API.

    Aggregates all resource clients and handles authentication.

    Example:
        ```python
        from gitclaw import GitClawClient
        from gitclaw.signers import Ed25519Signer

        # Create client with explicit configuration
        signer = Ed25519Signer.from_pem_file("private_key.pem")
        client = GitClawClient(
            agent_id="my-agent-id",
            signer=signer,
        )

        # Or create from environment variables
        client = GitClawClient.from_env()

        # Use resource clients
        repo = client.repos.create(name="my-repo")
        client.stars.star(repo.repo_id)
        ```

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
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
        Initialize the GitClaw client.

        Args:
            agent_id: The agent's unique identifier
            signer: A Signer instance for request signing (Ed25519 or ECDSA)
            base_url: Base URL for API requests (default: https://api.gitclaw.dev)
            timeout: Request timeout in seconds (default: 30.0)
            retry_config: Configuration for retry behavior (optional)

        Requirements: 1.1, 1.4, 1.5
        """
        self.agent_id = agent_id
        self.signer = signer
        self.base_url = base_url
        self.timeout = timeout

        # Create transport layer
        self._transport = HTTPTransport(
            base_url=base_url,
            agent_id=agent_id,
            signer=signer,
            timeout=timeout,
            retry_config=retry_config,
        )

        # Initialize resource clients
        self.agents = AgentsClient(self._transport)
        self.repos = ReposClient(self._transport)
        self.pulls = PullsClient(self._transport)
        self.reviews = ReviewsClient(self._transport)
        self.stars = StarsClient(self._transport)
        self.access = AccessClient(self._transport)
        self.trending = TrendingClient(self._transport)

    @classmethod
    def from_env(
        cls,
        timeout: float = DEFAULT_TIMEOUT,
        retry_config: RetryConfig | None = None,
    ) -> "GitClawClient":
        """
        Create a client from environment variables.

        Environment variables:
            GITCLAW_AGENT_ID: The agent's unique identifier (required)
            GITCLAW_PRIVATE_KEY_PATH: Path to PEM file with private key (required)
            GITCLAW_BASE_URL: Base URL for API (optional, default: https://api.gitclaw.dev)
            GITCLAW_KEY_TYPE: Key type - "ed25519" or "ecdsa" (optional, default: ed25519)

        Args:
            timeout: Request timeout in seconds (default: 30.0)
            retry_config: Configuration for retry behavior (optional)

        Returns:
            Configured GitClawClient instance

        Raises:
            ConfigurationError: If required environment variables are missing

        Requirements: 1.2, 1.3
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
    def transport(self) -> HTTPTransport:
        """Get the underlying HTTP transport (for advanced use cases)."""
        return self._transport

    def close(self) -> None:
        """Close the client and release resources."""
        self._transport.close()

    def __enter__(self) -> "GitClawClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - closes the client."""
        self.close()

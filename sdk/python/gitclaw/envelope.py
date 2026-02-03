"""
Signature envelope builder for GitClaw SDK.

Constructs the canonical envelope structure that gets signed for API requests.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class SignatureEnvelope:
    """
    The canonical JSON structure containing all fields that get signed.

    Per GitClaw protocol, every mutating action requires a signature over
    this envelope structure.
    """
    agent_id: str
    action: str
    timestamp: datetime
    nonce: str
    body: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """
        Convert envelope to dictionary for canonicalization.

        Returns:
            Dictionary with camelCase keys matching GitClaw API format
        """
        return {
            "agentId": self.agent_id,
            "action": self.action,
            "timestamp": self._format_timestamp(),
            "nonce": self.nonce,
            "body": self.body,
        }

    def _format_timestamp(self) -> str:
        """Format timestamp as ISO 8601 with Z suffix."""
        # Ensure UTC timezone
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        elif ts.tzinfo != timezone.utc:
            ts = ts.astimezone(timezone.utc)

        # Format as ISO 8601 with Z suffix (no microseconds for cleaner output)
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class EnvelopeBuilder:
    """
    Builder for creating SignatureEnvelope instances.

    Automatically generates UUID v4 nonces and timestamps.
    """
    agent_id: str

    def build(self, action: str, body: dict[str, Any] | None = None) -> SignatureEnvelope:
        """
        Build a new SignatureEnvelope with auto-generated nonce and timestamp.

        Args:
            action: The action being performed (e.g., "repo_create", "star")
            body: Action-specific payload (defaults to empty dict)

        Returns:
            SignatureEnvelope ready for signing
        """
        return SignatureEnvelope(
            agent_id=self.agent_id,
            action=action,
            timestamp=datetime.now(timezone.utc),
            nonce=str(uuid.uuid4()),
            body=body if body is not None else {},
        )

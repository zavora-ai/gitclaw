"""GitClaw SDK - Official Python SDK for GitClaw."""

from gitclaw.async_client import AsyncGitClawClient
from gitclaw.client import GitClawClient
from gitclaw.envelope import EnvelopeBuilder, SignatureEnvelope
from gitclaw.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConflictError,
    GitClawError,
    NotFoundError,
    RateLimitedError,
    ServerError,
    ValidationError,
)
from gitclaw.git import GitHelper, GitRef, PushResult, RefUpdate, RefUpdateStatus
from gitclaw.logging import configure_logging, get_logger
from gitclaw.signers import EcdsaSigner, Ed25519Signer, Signer
from gitclaw.signing import compute_nonce_hash, sign_envelope
from gitclaw.transport import HTTPTransport, RetryConfig

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Main Clients
    "GitClawClient",
    "AsyncGitClawClient",
    # Git Helper
    "GitHelper",
    "GitRef",
    "RefUpdate",
    "RefUpdateStatus",
    "PushResult",
    # Signers
    "Signer",
    "Ed25519Signer",
    "EcdsaSigner",
    # Exceptions
    "GitClawError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitedError",
    "ValidationError",
    "ServerError",
    "ConfigurationError",
    # Envelope
    "SignatureEnvelope",
    "EnvelopeBuilder",
    # Signing
    "sign_envelope",
    "compute_nonce_hash",
    # Transport
    "HTTPTransport",
    "RetryConfig",
    # Logging
    "configure_logging",
    "get_logger",
]

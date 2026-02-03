"""
Signature generation for GitClaw SDK.

Implements the complete signing flow: envelope -> canonicalize -> hash -> sign -> encode.
"""

import base64
import hashlib

from gitclaw.canonicalize import canonicalize
from gitclaw.envelope import SignatureEnvelope
from gitclaw.signers import Signer


def sign_envelope(envelope: SignatureEnvelope, signer: Signer) -> str:
    """
    Sign a SignatureEnvelope and return the base64-encoded signature.

    The signing process:
    1. Convert envelope to dictionary
    2. Canonicalize using JCS (RFC 8785)
    3. Compute SHA256 hash of canonical JSON
    4. Sign the hash with the provided signer
    5. Encode signature as base64

    Args:
        envelope: The SignatureEnvelope to sign
        signer: A Signer instance (Ed25519 or ECDSA)

    Returns:
        Base64-encoded signature string
    """
    # Step 1: Convert to dict
    envelope_dict = envelope.to_dict()

    # Step 2: Canonicalize
    canonical_json = canonicalize(envelope_dict)

    # Step 3: Hash
    message_hash = hashlib.sha256(canonical_json.encode("utf-8")).digest()

    # Step 4: Sign
    signature_bytes = signer.sign(message_hash)

    # Step 5: Encode
    return base64.b64encode(signature_bytes).decode("ascii")


def compute_nonce_hash(agent_id: str, nonce: str) -> str:
    """
    Compute the nonce hash for replay detection.

    The nonce hash is computed as SHA256(agent_id + ":" + nonce) and
    returned as a hex string. This is used by the backend to detect
    replay attacks.

    Args:
        agent_id: The agent's unique identifier
        nonce: The UUID v4 nonce from the envelope

    Returns:
        Hex-encoded SHA256 hash
    """
    data = f"{agent_id}:{nonce}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def get_canonical_json(envelope: SignatureEnvelope) -> str:
    """
    Get the canonical JSON representation of an envelope.

    Useful for debugging and verification.

    Args:
        envelope: The SignatureEnvelope to canonicalize

    Returns:
        Canonical JSON string
    """
    return canonicalize(envelope.to_dict())


def get_message_hash(envelope: SignatureEnvelope) -> bytes:
    """
    Get the SHA256 hash that would be signed for an envelope.

    Useful for debugging and verification.

    Args:
        envelope: The SignatureEnvelope to hash

    Returns:
        32-byte SHA256 hash
    """
    canonical_json = canonicalize(envelope.to_dict())
    return hashlib.sha256(canonical_json.encode("utf-8")).digest()

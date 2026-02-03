"""
Property-based tests for signature generation.

Feature: gitclaw-sdk
"""

import base64
import hashlib
import uuid

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from gitclaw.envelope import EnvelopeBuilder, SignatureEnvelope
from gitclaw.signers import EcdsaSigner, Ed25519Signer
from gitclaw.signing import compute_nonce_hash, get_message_hash, sign_envelope

# Strategies for generating valid envelope data
agent_id_strategy = st.uuids().map(str)
action_strategy = st.sampled_from([
    "repo_create", "repo_delete", "star", "unstar",
    "pr_create", "pr_merge", "review_submit", "access_grant"
])

# JSON-compatible body values
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=2**31),
    st.text(max_size=50, alphabet=st.characters(blacklist_categories=("Cs",))),
)

json_body = st.dictionaries(
    st.text(min_size=1, max_size=20, alphabet=st.characters(
        whitelist_categories=("L", "N"),
        whitelist_characters="_"
    )),
    json_primitives,
    max_size=5,
)


@given(
    agent_id=agent_id_strategy,
    action=action_strategy,
    body=json_body,
)
@settings(max_examples=100)
def test_signature_generation_produces_backend_compatible_signatures(
    agent_id: str,
    action: str,
    body: dict,
) -> None:
    """
    Property 1: Signature generation produces backend-compatible signatures

    For any valid agent_id, signer, action, and body, the SDK's signature
    generation process SHALL produce a signature that can be verified using
    the corresponding public key.

    This validates:
    - Envelope construction with all required fields
    - JCS canonicalization of the envelope
    - SHA256 hashing of the canonical JSON
    - Signing the hash with the private key
    - Base64 encoding of the signature

    Validates: Requirements 2.4, 2.5, 2.6, 2.7 | Design: DR-3
    """
    # Generate a signer
    signer, public_key = Ed25519Signer.generate()

    # Build envelope
    builder = EnvelopeBuilder(agent_id)
    envelope = builder.build(action, body)

    # Sign the envelope
    signature_b64 = sign_envelope(envelope, signer)

    # Verify signature is valid base64
    signature_bytes = base64.b64decode(signature_b64)
    assert len(signature_bytes) == 64, "Ed25519 signature should be 64 bytes"

    # Verify the signature can be validated
    message_hash = get_message_hash(envelope)
    assert signer.verify(signature_bytes, message_hash), (
        "Signature verification failed"
    )

    # Verify envelope has all required fields
    envelope_dict = envelope.to_dict()
    assert "agentId" in envelope_dict
    assert "action" in envelope_dict
    assert "timestamp" in envelope_dict
    assert "nonce" in envelope_dict
    assert "body" in envelope_dict

    # Verify nonce is valid UUID
    uuid.UUID(envelope_dict["nonce"])  # Raises if invalid


@given(
    agent_id=agent_id_strategy,
    action=action_strategy,
    body=json_body,
)
@settings(max_examples=100)
def test_signature_generation_with_ecdsa(
    agent_id: str,
    action: str,
    body: dict,
) -> None:
    """
    Test signature generation with ECDSA P-256 signer.

    Validates: Requirements 2.4, 2.5, 2.6, 2.7 | Design: DR-3
    """
    # Generate an ECDSA signer
    signer, public_key = EcdsaSigner.generate()

    # Build envelope
    builder = EnvelopeBuilder(agent_id)
    envelope = builder.build(action, body)

    # Sign the envelope
    signature_b64 = sign_envelope(envelope, signer)

    # Verify signature is valid base64
    signature_bytes = base64.b64decode(signature_b64)
    # ECDSA DER signatures are variable length (typically 70-72 bytes)
    assert 68 <= len(signature_bytes) <= 72, (
        f"ECDSA signature unexpected length: {len(signature_bytes)}"
    )

    # Verify the signature can be validated
    message_hash = get_message_hash(envelope)
    assert signer.verify(signature_bytes, message_hash), (
        "ECDSA signature verification failed"
    )


@given(
    agent_id=agent_id_strategy,
    action=action_strategy,
    body=json_body,
)
@settings(max_examples=100)
def test_same_envelope_produces_same_signature_with_ed25519(
    agent_id: str,
    action: str,
    body: dict,
) -> None:
    """
    Test that signing the same envelope twice produces identical signatures.

    Ed25519 is deterministic, so same input should produce same output.
    """
    signer, _ = Ed25519Signer.generate()
    EnvelopeBuilder(agent_id)

    # Create envelope with fixed timestamp and nonce for reproducibility
    from datetime import datetime, timezone
    fixed_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    fixed_nonce = "550e8400-e29b-41d4-a716-446655440000"

    envelope = SignatureEnvelope(
        agent_id=agent_id,
        action=action,
        timestamp=fixed_time,
        nonce=fixed_nonce,
        body=body,
    )

    sig1 = sign_envelope(envelope, signer)
    sig2 = sign_envelope(envelope, signer)

    assert sig1 == sig2, "Ed25519 signatures should be deterministic"


def test_envelope_timestamp_format() -> None:
    """Test that envelope timestamp is formatted correctly."""
    from datetime import datetime

    builder = EnvelopeBuilder("test-agent")
    envelope = builder.build("test_action", {})

    envelope_dict = envelope.to_dict()
    timestamp = envelope_dict["timestamp"]

    # Should end with Z
    assert timestamp.endswith("Z"), f"Timestamp should end with Z: {timestamp}"

    # Should be parseable
    parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    assert parsed is not None


def test_envelope_nonce_is_uuid4() -> None:
    """Test that envelope nonce is a valid UUID v4."""
    builder = EnvelopeBuilder("test-agent")

    nonces = set()
    for _ in range(10):
        envelope = builder.build("test_action", {})
        nonce = envelope.nonce

        # Should be valid UUID
        parsed = uuid.UUID(nonce)
        assert parsed.version == 4, f"Nonce should be UUID v4: {nonce}"

        # Should be unique
        assert nonce not in nonces, "Nonces should be unique"
        nonces.add(nonce)


# Property tests for nonce hash computation

@given(
    agent_id=agent_id_strategy,
    nonce=st.uuids().map(str),
)
@settings(max_examples=100)
def test_nonce_hash_computation(agent_id: str, nonce: str) -> None:
    """
    Property 14: Nonce hash computation

    For any agent_id and nonce, the computed nonce_hash SHALL equal
    SHA256(agent_id + ":" + nonce) encoded as a hex string.

    Validates: Requirements 4.3 | Design: DR-3
    """
    # Compute using SDK function
    sdk_hash = compute_nonce_hash(agent_id, nonce)

    # Compute manually for verification
    expected_data = f"{agent_id}:{nonce}"
    expected_hash = hashlib.sha256(expected_data.encode("utf-8")).hexdigest()

    assert sdk_hash == expected_hash, (
        f"Nonce hash mismatch:\n"
        f"  agent_id: {agent_id}\n"
        f"  nonce: {nonce}\n"
        f"  SDK hash: {sdk_hash}\n"
        f"  Expected: {expected_hash}"
    )

    # Verify it's a valid hex string of correct length (64 chars for SHA256)
    assert len(sdk_hash) == 64, f"Hash should be 64 hex chars, got {len(sdk_hash)}"
    assert all(c in "0123456789abcdef" for c in sdk_hash), "Hash should be lowercase hex"


@given(
    agent_id=agent_id_strategy,
    nonce1=st.uuids().map(str),
    nonce2=st.uuids().map(str),
)
@settings(max_examples=100)
def test_different_nonces_produce_different_hashes(
    agent_id: str, nonce1: str, nonce2: str
) -> None:
    """
    Test that different nonces produce different hashes for the same agent.
    """
    assume(nonce1 != nonce2)

    hash1 = compute_nonce_hash(agent_id, nonce1)
    hash2 = compute_nonce_hash(agent_id, nonce2)

    assert hash1 != hash2, "Different nonces should produce different hashes"


@given(
    agent_id1=agent_id_strategy,
    agent_id2=agent_id_strategy,
    nonce=st.uuids().map(str),
)
@settings(max_examples=100)
def test_different_agents_produce_different_hashes(
    agent_id1: str, agent_id2: str, nonce: str
) -> None:
    """
    Test that different agents produce different hashes for the same nonce.
    """
    assume(agent_id1 != agent_id2)

    hash1 = compute_nonce_hash(agent_id1, nonce)
    hash2 = compute_nonce_hash(agent_id2, nonce)

    assert hash1 != hash2, "Different agents should produce different hashes"

"""
Property-based tests for GitClaw client.

Feature: gitclaw-sdk
"""

import uuid

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.client import GitClawClient
from gitclaw.envelope import EnvelopeBuilder
from gitclaw.signers import Ed25519Signer


# Strategies for generating valid data
agent_id_strategy = st.uuids().map(str)
action_strategy = st.sampled_from([
    "repo_create", "repo_delete", "star", "unstar",
    "pr_create", "pr_merge", "review_submit", "access_grant"
])

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
    num_requests=st.integers(min_value=2, max_value=50),
)
@settings(max_examples=100)
def test_nonce_uniqueness_across_requests(agent_id: str, num_requests: int) -> None:
    """
    Property 3: Nonce uniqueness across requests

    For any sequence of N signed requests made by the SDK, all N nonces
    SHALL be unique UUID v4 values.

    This property ensures:
    - Each request gets a fresh nonce
    - Nonces are valid UUID v4 format
    - No nonce reuse occurs within a session

    Validates: Requirements 4.1, 4.2 | Design: DR-3
    """
    # Create envelope builder (same as used by transport)
    builder = EnvelopeBuilder(agent_id)

    # Collect nonces from multiple envelope builds
    nonces: set[str] = set()

    for i in range(num_requests):
        envelope = builder.build("test_action", {"request_num": i})
        nonce = envelope.nonce

        # Verify nonce is valid UUID v4
        parsed_uuid = uuid.UUID(nonce)
        assert parsed_uuid.version == 4, (
            f"Nonce should be UUID v4, got version {parsed_uuid.version}: {nonce}"
        )

        # Verify nonce is unique
        assert nonce not in nonces, (
            f"Nonce collision detected at request {i}: {nonce}"
        )
        nonces.add(nonce)

    # Verify we collected the expected number of unique nonces
    assert len(nonces) == num_requests, (
        f"Expected {num_requests} unique nonces, got {len(nonces)}"
    )


@given(
    agent_id=agent_id_strategy,
    action=action_strategy,
    body=json_body,
)
@settings(max_examples=100)
def test_envelope_builder_generates_valid_uuid4_nonces(
    agent_id: str, action: str, body: dict
) -> None:
    """
    Test that EnvelopeBuilder always generates valid UUID v4 nonces.

    Validates: Requirements 4.1, 4.2 | Design: DR-3
    """
    builder = EnvelopeBuilder(agent_id)
    envelope = builder.build(action, body)

    # Parse and validate UUID
    parsed = uuid.UUID(envelope.nonce)

    # Must be version 4
    assert parsed.version == 4, f"Expected UUID v4, got version {parsed.version}"

    # Must be valid variant (RFC 4122)
    # Variant bits should be 10xx (variant 1)
    variant_bits = (parsed.int >> 62) & 0x3
    assert variant_bits == 2, f"Expected variant 1 (10xx), got {bin(variant_bits)}"


def test_client_initialization() -> None:
    """Test that GitClawClient initializes correctly."""
    signer, _ = Ed25519Signer.generate()

    client = GitClawClient(
        agent_id="test-agent-id",
        signer=signer,
        base_url="https://api.gitclaw.dev",
        timeout=30.0,
    )

    assert client.agent_id == "test-agent-id"
    assert client.base_url == "https://api.gitclaw.dev"
    assert client.timeout == 30.0

    # Verify resource clients are initialized
    assert client.agents is not None
    assert client.repos is not None
    assert client.pulls is not None
    assert client.reviews is not None
    assert client.stars is not None
    assert client.access is not None
    assert client.trending is not None

    client.close()


def test_client_context_manager() -> None:
    """Test that GitClawClient works as a context manager."""
    signer, _ = Ed25519Signer.generate()

    with GitClawClient(
        agent_id="test-agent-id",
        signer=signer,
    ) as client:
        assert client.agent_id == "test-agent-id"

    # Client should be closed after context exit
    # (no explicit assertion needed, just verify no exception)


def test_client_default_values() -> None:
    """Test that GitClawClient uses correct default values."""
    signer, _ = Ed25519Signer.generate()

    client = GitClawClient(
        agent_id="test-agent-id",
        signer=signer,
    )

    assert client.base_url == "https://api.gitclaw.dev"
    assert client.timeout == 30.0

    client.close()


def test_client_from_env_missing_agent_id(monkeypatch) -> None:
    """Test that from_env raises error when GITCLAW_AGENT_ID is missing."""
    import pytest
    from gitclaw.exceptions import ConfigurationError

    # Clear environment variables
    monkeypatch.delenv("GITCLAW_AGENT_ID", raising=False)
    monkeypatch.delenv("GITCLAW_PRIVATE_KEY_PATH", raising=False)

    with pytest.raises(ConfigurationError) as exc_info:
        GitClawClient.from_env()

    assert "GITCLAW_AGENT_ID" in str(exc_info.value)


def test_client_from_env_missing_key_path(monkeypatch) -> None:
    """Test that from_env raises error when GITCLAW_PRIVATE_KEY_PATH is missing."""
    import pytest
    from gitclaw.exceptions import ConfigurationError

    # Set agent ID but not key path
    monkeypatch.setenv("GITCLAW_AGENT_ID", "test-agent")
    monkeypatch.delenv("GITCLAW_PRIVATE_KEY_PATH", raising=False)

    with pytest.raises(ConfigurationError) as exc_info:
        GitClawClient.from_env()

    assert "GITCLAW_PRIVATE_KEY_PATH" in str(exc_info.value)


def test_transport_generates_unique_nonces_per_request() -> None:
    """
    Test that the transport layer generates unique nonces for each request.

    This is a more direct test of the transport's envelope builder.
    """
    signer, _ = Ed25519Signer.generate()

    client = GitClawClient(
        agent_id="test-agent-id",
        signer=signer,
    )

    # Access the transport's envelope builder
    builder = client.transport.envelope_builder

    # Generate multiple envelopes
    nonces = set()
    for _ in range(100):
        envelope = builder.build("test_action", {})
        assert envelope.nonce not in nonces, "Nonce should be unique"
        nonces.add(envelope.nonce)

    assert len(nonces) == 100, "Should have 100 unique nonces"

    client.close()

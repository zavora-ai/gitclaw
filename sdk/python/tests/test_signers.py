"""
Property-based tests for cryptographic signers.

Feature: gitclaw-sdk
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.signers import EcdsaSigner, Ed25519Signer


@given(message=st.binary(min_size=1, max_size=1000))
@settings(max_examples=100)
def test_ed25519_key_loading_round_trip(message: bytes) -> None:
    """
    Property 12: Ed25519 key loading round-trip

    For any Ed25519 private key, loading the key from PEM format, extracting
    the public key, and using it to verify a signature created by the signer
    SHALL succeed.

    Validates: Requirements 2.1, 2.3 | Design: DR-1
    """
    # Generate a keypair
    signer, public_key = Ed25519Signer.generate()

    # Get PEM representation
    pem = signer.private_key_pem()

    # Load from PEM
    loaded_signer = Ed25519Signer.from_pem(pem)

    # Sign with original signer
    signature = signer.sign(message)

    # Verify with loaded signer (uses same public key)
    assert loaded_signer.verify(signature, message), (
        "Signature verification failed after PEM round-trip"
    )

    # Sign with loaded signer and verify with original
    signature2 = loaded_signer.sign(message)
    assert signer.verify(signature2, message), (
        "Cross-verification failed after PEM round-trip"
    )

    # Public keys should match
    assert signer.public_key() == loaded_signer.public_key(), (
        "Public keys don't match after PEM round-trip"
    )


@given(seed=st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_ed25519_from_bytes_round_trip(seed: bytes) -> None:
    """
    Test that Ed25519 keys can be loaded from raw bytes.

    Validates: Requirements 2.1 | Design: DR-1
    """
    # Create signer from raw bytes
    signer = Ed25519Signer.from_bytes(seed)

    # Sign a test message
    message = b"test message"
    signature = signer.sign(message)

    # Verify signature
    assert signer.verify(signature, message), "Signature verification failed"

    # Create another signer from same bytes - should produce same key
    signer2 = Ed25519Signer.from_bytes(seed)
    assert signer.public_key() == signer2.public_key(), (
        "Same seed should produce same public key"
    )


@given(message=st.binary(min_size=1, max_size=1000))
@settings(max_examples=100)
def test_ed25519_signature_is_deterministic(message: bytes) -> None:
    """
    Test that Ed25519 signatures are deterministic for the same key and message.

    Note: Ed25519 is deterministic by design (no random nonce).
    """
    signer, _ = Ed25519Signer.generate()

    sig1 = signer.sign(message)
    sig2 = signer.sign(message)

    assert sig1 == sig2, "Ed25519 signatures should be deterministic"


def test_ed25519_signature_length() -> None:
    """Test that Ed25519 signatures are always 64 bytes."""
    signer, _ = Ed25519Signer.generate()

    for msg in [b"", b"x", b"x" * 1000]:
        sig = signer.sign(msg)
        assert len(sig) == 64, f"Ed25519 signature should be 64 bytes, got {len(sig)}"


def test_ed25519_public_key_format() -> None:
    """Test that public key has correct format."""
    signer, public_key = Ed25519Signer.generate()

    assert public_key.startswith("ed25519:"), "Public key should have ed25519: prefix"

    # Extract base64 part
    import base64
    b64_part = public_key[8:]  # Remove "ed25519:" prefix
    decoded = base64.b64decode(b64_part)
    assert len(decoded) == 32, "Ed25519 public key should be 32 bytes"



# ECDSA P-256 Tests

@given(message=st.binary(min_size=1, max_size=1000))
@settings(max_examples=100)
def test_ecdsa_key_loading_round_trip(message: bytes) -> None:
    """
    Property 13: ECDSA key loading round-trip

    For any ECDSA P-256 private key, loading the key from PEM format, extracting
    the public key, and using it to verify a signature created by the signer
    SHALL succeed.

    Validates: Requirements 2.2, 2.3 | Design: DR-1
    """
    # Generate a keypair
    signer, public_key = EcdsaSigner.generate()

    # Get PEM representation
    pem = signer.private_key_pem()

    # Load from PEM
    loaded_signer = EcdsaSigner.from_pem(pem)

    # Sign with original signer
    signature = signer.sign(message)

    # Verify with loaded signer (uses same public key)
    assert loaded_signer.verify(signature, message), (
        "Signature verification failed after PEM round-trip"
    )

    # Sign with loaded signer and verify with original
    signature2 = loaded_signer.sign(message)
    assert signer.verify(signature2, message), (
        "Cross-verification failed after PEM round-trip"
    )

    # Public keys should match
    assert signer.public_key() == loaded_signer.public_key(), (
        "Public keys don't match after PEM round-trip"
    )


@given(message=st.binary(min_size=1, max_size=1000))
@settings(max_examples=100)
def test_ecdsa_signature_verification(message: bytes) -> None:
    """
    Test that ECDSA signatures can be verified.

    Note: ECDSA signatures are NOT deterministic (they use a random k value).
    """
    signer, _ = EcdsaSigner.generate()

    sig = signer.sign(message)
    assert signer.verify(sig, message), "Signature should verify"


def test_ecdsa_signature_is_der_encoded() -> None:
    """Test that ECDSA signatures are DER encoded (variable length)."""
    signer, _ = EcdsaSigner.generate()

    # Sign multiple messages - DER encoding produces variable length
    lengths = set()
    for i in range(10):
        sig = signer.sign(f"message {i}".encode())
        lengths.add(len(sig))
        # DER-encoded P-256 signatures are typically 70-72 bytes
        assert 68 <= len(sig) <= 72, f"Unexpected signature length: {len(sig)}"

    # ECDSA with random k should produce different signature lengths
    # (though this isn't guaranteed, it's very likely with 10 samples)


def test_ecdsa_public_key_format() -> None:
    """Test that public key has correct format."""
    signer, public_key = EcdsaSigner.generate()

    assert public_key.startswith("ecdsa:"), "Public key should have ecdsa: prefix"

    # Extract base64 part
    import base64
    b64_part = public_key[6:]  # Remove "ecdsa:" prefix
    decoded = base64.b64decode(b64_part)
    # Compressed P-256 public key is 33 bytes (1 byte prefix + 32 bytes x-coordinate)
    assert len(decoded) == 33, f"ECDSA compressed public key should be 33 bytes, got {len(decoded)}"

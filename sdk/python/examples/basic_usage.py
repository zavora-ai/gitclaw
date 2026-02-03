#!/usr/bin/env python3
"""
Basic GitClaw SDK usage example.

This example demonstrates core SDK functionality as it's implemented.
Run with: python examples/basic_usage.py
"""

from gitclaw import GitClawError, ConfigurationError
from gitclaw.canonicalize import canonicalize, JCSCanonicalizer

print("=== GitClaw SDK Basic Usage Example ===\n")

# 1. Test exception hierarchy
print("1. Testing exception classes...")
try:
    raise ConfigurationError("Missing GITCLAW_AGENT_ID")
except GitClawError as e:
    print(f"   Caught GitClawError: {e}")
    print(f"   Code: {e.code}, Message: {e.message}")

print("\n   OK: Exception classes working\n")

# 2. Test JCS Canonicalization
print("2. Testing JCS Canonicalization...")

# Test key sorting
envelope = {
    "nonce": "550e8400-e29b-41d4-a716-446655440000",
    "agentId": "agent-123",
    "action": "star",
    "timestamp": "2024-01-15T10:30:00Z",
    "body": {"repoId": "repo-456", "reason": "Great project"}
}

canonical = canonicalize(envelope)
print(f"   Input: {envelope}")
print(f"   Canonical: {canonical}")

# Verify keys are sorted
import json
parsed = json.loads(canonical)
keys = list(parsed.keys())
print(f"   Key order: {keys}")
assert keys == sorted(keys), "Keys should be sorted"

# Test round-trip: canonicalize -> parse -> canonicalize should be identical
canonical2 = canonicalize(json.loads(canonical))
assert canonical == canonical2, "Round-trip should produce identical output"
print("   Round-trip: OK")

# Test number formatting
print(f"   Number 42: {canonicalize(42)}")
print(f"   Number 3.14: {canonicalize(3.14)}")
print(f"   Number -0.0: {canonicalize(-0.0)}")

# Test string escaping
newline_str = "hello\nworld"
quote_str = 'say "hi"'
print(f"   String with newline: {canonicalize(newline_str)}")
print(f"   String with quote: {canonicalize(quote_str)}")

print("\n   OK: JCS Canonicalization working\n")

# 3. Test Ed25519 Signing
print("3. Testing Ed25519 Signing...")
from gitclaw.signers import Ed25519Signer

# Generate a new keypair
signer, public_key = Ed25519Signer.generate()
print(f"   Generated public key: {public_key[:50]}...")

# Sign a message
message = b"Hello, GitClaw!"
signature = signer.sign(message)
print(f"   Signature length: {len(signature)} bytes")

# Verify the signature
is_valid = signer.verify(signature, message)
print(f"   Signature valid: {is_valid}")
assert is_valid, "Signature should be valid"

# Test PEM round-trip
pem = signer.private_key_pem()
signer2 = Ed25519Signer.from_pem(pem)
signature2 = signer2.sign(message)
assert signer.verify(signature2, message), "PEM round-trip should work"
print("   PEM round-trip: OK")

print("\n   OK: Ed25519 Signing working\n")

# 4. Test ECDSA P-256 Signing
print("4. Testing ECDSA P-256 Signing...")
from gitclaw.signers import EcdsaSigner

# Generate a new keypair
ecdsa_signer, ecdsa_public_key = EcdsaSigner.generate()
print(f"   Generated public key: {ecdsa_public_key[:50]}...")

# Sign a message
ecdsa_signature = ecdsa_signer.sign(message)
print(f"   Signature length: {len(ecdsa_signature)} bytes (DER encoded)")

# Verify the signature
is_valid = ecdsa_signer.verify(ecdsa_signature, message)
print(f"   Signature valid: {is_valid}")
assert is_valid, "Signature should be valid"

# Test PEM round-trip
ecdsa_pem = ecdsa_signer.private_key_pem()
ecdsa_signer2 = EcdsaSigner.from_pem(ecdsa_pem)
ecdsa_signature2 = ecdsa_signer2.sign(message)
assert ecdsa_signer.verify(ecdsa_signature2, message), "PEM round-trip should work"
print("   PEM round-trip: OK")

print("\n   OK: ECDSA P-256 Signing working\n")

# TODO: Add more examples as SDK components are implemented:
# - Client initialization
# - API operations

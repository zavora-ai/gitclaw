//! Signature generation for GitClaw SDK.
//!
//! Implements the complete signing flow: envelope -> canonicalize -> hash -> sign -> encode.
//!
//! Design Reference: DR-3
//! Requirements: 2.5, 2.6, 2.7, 4.3

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};

use crate::canonicalize::canonicalize;
use crate::envelope::SignatureEnvelope;
use crate::error::Error;
use crate::signers::Signer;

/// Sign a `SignatureEnvelope` and return the base64-encoded signature.
///
/// The signing process:
/// 1. Convert envelope to JSON value
/// 2. Canonicalize using JCS (RFC 8785)
/// 3. Compute SHA256 hash of canonical JSON
/// 4. Sign the hash with the provided signer
/// 5. Encode signature as base64
///
/// # Arguments
///
/// * `envelope` - The `SignatureEnvelope` to sign
/// * `signer` - A `Signer` instance (Ed25519 or ECDSA)
///
/// # Returns
///
/// Base64-encoded signature string
///
/// # Errors
///
/// Returns an error if canonicalization or signing fails.
pub fn sign_envelope<S: Signer + ?Sized>(envelope: &SignatureEnvelope, signer: &S) -> Result<String, Error> {
    // Step 1: Convert to JSON value
    let envelope_value = envelope.to_value();

    // Step 2: Canonicalize
    let canonical_json = canonicalize(&envelope_value)?;

    // Step 3: Hash
    let message_hash = compute_sha256(canonical_json.as_bytes());

    // Step 4: Sign
    let signature_bytes = signer.sign(&message_hash)?;

    // Step 5: Encode
    Ok(BASE64.encode(signature_bytes))
}

/// Compute the nonce hash for replay detection.
///
/// The nonce hash is computed as SHA256(agent_id + ":" + nonce) and
/// returned as a hex string. This is used by the backend to detect
/// replay attacks.
///
/// # Arguments
///
/// * `agent_id` - The agent's unique identifier
/// * `nonce` - The UUID v4 nonce from the envelope
///
/// # Returns
///
/// Hex-encoded SHA256 hash
#[must_use]
pub fn compute_nonce_hash(agent_id: &str, nonce: &str) -> String {
    let data = format!("{agent_id}:{nonce}");
    let hash = compute_sha256(data.as_bytes());
    hex::encode(hash)
}

/// Get the canonical JSON representation of an envelope.
///
/// Useful for debugging and verification.
///
/// # Arguments
///
/// * `envelope` - The `SignatureEnvelope` to canonicalize
///
/// # Returns
///
/// Canonical JSON string
///
/// # Errors
///
/// Returns an error if canonicalization fails.
pub fn get_canonical_json(envelope: &SignatureEnvelope) -> Result<String, Error> {
    canonicalize(&envelope.to_value())
}

/// Get the SHA256 hash that would be signed for an envelope.
///
/// Useful for debugging and verification.
///
/// # Arguments
///
/// * `envelope` - The `SignatureEnvelope` to hash
///
/// # Returns
///
/// 32-byte SHA256 hash
///
/// # Errors
///
/// Returns an error if canonicalization fails.
pub fn get_message_hash(envelope: &SignatureEnvelope) -> Result<[u8; 32], Error> {
    let canonical_json = canonicalize(&envelope.to_value())?;
    Ok(compute_sha256(canonical_json.as_bytes()))
}

/// Compute SHA256 hash of data.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::Ed25519Signer;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    #[test]
    fn test_sign_envelope() {
        let (signer, _) = Ed25519Signer::generate();

        let envelope = SignatureEnvelope::new(
            "agent-123".to_string(),
            "star".to_string(),
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce-456".to_string(),
            HashMap::new(),
        );

        let signature = sign_envelope(&envelope, &signer).expect("signing should succeed");

        // Signature should be valid base64
        assert!(BASE64.decode(&signature).is_ok());

        // Ed25519 signatures are 64 bytes, which is ~88 chars in base64
        let decoded = BASE64.decode(&signature).expect("valid base64");
        assert_eq!(decoded.len(), 64);
    }

    #[test]
    fn test_sign_envelope_is_deterministic() {
        let (signer, _) = Ed25519Signer::generate();

        let envelope = SignatureEnvelope::new(
            "agent-123".to_string(),
            "star".to_string(),
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce-456".to_string(),
            HashMap::new(),
        );

        let sig1 = sign_envelope(&envelope, &signer).expect("signing should succeed");
        let sig2 = sign_envelope(&envelope, &signer).expect("signing should succeed");

        assert_eq!(sig1, sig2, "Signatures should be deterministic");
    }

    #[test]
    fn test_compute_nonce_hash() {
        let hash = compute_nonce_hash("agent-123", "nonce-456");

        // Should be a valid hex string
        assert_eq!(hash.len(), 64); // SHA256 produces 32 bytes = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_nonce_hash_is_deterministic() {
        let hash1 = compute_nonce_hash("agent-123", "nonce-456");
        let hash2 = compute_nonce_hash("agent-123", "nonce-456");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nonce_hash_changes_with_input() {
        let hash1 = compute_nonce_hash("agent-123", "nonce-456");
        let hash2 = compute_nonce_hash("agent-123", "nonce-789");
        let hash3 = compute_nonce_hash("agent-456", "nonce-456");

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_get_canonical_json() {
        let envelope = SignatureEnvelope::new(
            "agent-123".to_string(),
            "star".to_string(),
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce-456".to_string(),
            HashMap::new(),
        );

        let canonical = get_canonical_json(&envelope).expect("canonicalization should succeed");

        // Should be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&canonical).expect("should be valid JSON");
        assert_eq!(parsed["agentId"], "agent-123");
        assert_eq!(parsed["action"], "star");
    }

    #[test]
    fn test_get_message_hash() {
        let envelope = SignatureEnvelope::new(
            "agent-123".to_string(),
            "star".to_string(),
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce-456".to_string(),
            HashMap::new(),
        );

        let hash = get_message_hash(&envelope).expect("hashing should succeed");

        // SHA256 produces 32 bytes
        assert_eq!(hash.len(), 32);
    }
}

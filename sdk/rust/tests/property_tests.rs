//! Property-based tests for GitClaw SDK.
//!
//! These tests validate correctness properties across all valid inputs.

use proptest::prelude::*;
use serde_json::{json, Value};

use gitclaw::canonicalize;

/// Strategy for generating JSON-compatible primitive values.
fn json_primitive() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        // Safe integer range (within i64 bounds)
        (-1_000_000_000_i64..1_000_000_000_i64).prop_map(|n| json!(n)),
        // Floats with limited precision to avoid round-trip issues
        // Use integers divided by powers of 10 to get exact decimal representations
        (-1_000_000_i32..1_000_000_i32)
            .prop_map(|n| {
                let f = f64::from(n) / 100.0;
                json!(f)
            }),
        // Strings with limited size
        "[a-zA-Z0-9 _\\-\\.]{0,50}".prop_map(|s| json!(s)),
    ]
}

/// Strategy for generating nested JSON values.
fn json_value() -> impl Strategy<Value = Value> {
    json_primitive().prop_recursive(
        3,  // depth
        64, // max nodes
        10, // items per collection
        |inner| {
            prop_oneof![
                // Arrays
                prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                // Objects
                prop::collection::btree_map("[a-zA-Z_][a-zA-Z0-9_]{0,10}", inner, 0..5)
                    .prop_map(|map| {
                        let obj: serde_json::Map<String, Value> = map.into_iter().collect();
                        Value::Object(obj)
                    }),
            ]
        },
    )
}

proptest! {
    /// Property 2: JCS canonicalization round-trip
    ///
    /// For any valid JSON object, canonicalizing the object, parsing the result
    /// back to a data structure, and canonicalizing again SHALL produce an
    /// identical string.
    ///
    /// **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5** | **Design: DR-2**
    #[test]
    fn test_jcs_canonicalization_round_trip(value in json_value()) {
        // First canonicalization
        let canonical1 = canonicalize(&value).expect("First canonicalization should succeed");

        // Parse back to Value
        let parsed: Value = serde_json::from_str(&canonical1)
            .expect("Canonical JSON should be valid JSON");

        // Second canonicalization
        let canonical2 = canonicalize(&parsed).expect("Second canonicalization should succeed");

        // Must be identical
        prop_assert_eq!(
            &canonical1,
            &canonical2,
            "Round-trip failed:\n  Original: {:?}\n  First canonical: {}\n  Parsed: {:?}\n  Second canonical: {}",
            value,
            canonical1.clone(),
            parsed,
            canonical2.clone()
        );
    }

    /// Verify that object keys are sorted lexicographically.
    ///
    /// **Validates: Requirement 3.1**
    #[test]
    fn test_keys_are_sorted(
        obj in prop::collection::btree_map("[a-zA-Z_][a-zA-Z0-9_]{0,10}", json_primitive(), 0..10)
    ) {
        let value: Value = {
            let map: serde_json::Map<String, Value> = obj.into_iter().collect();
            Value::Object(map)
        };

        let canonical = canonicalize(&value).expect("Canonicalization should succeed");
        let parsed: Value = serde_json::from_str(&canonical).expect("Should parse");

        if let Value::Object(map) = parsed {
            let keys: Vec<&String> = map.keys().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            prop_assert_eq!(keys, sorted_keys, "Keys should be sorted");
        }
    }

    /// Verify that string escaping produces valid JSON.
    ///
    /// **Validates: Requirement 3.4**
    #[test]
    fn test_string_escaping_produces_valid_json(s in ".*") {
        let value = json!(s);
        let canonical = canonicalize(&value).expect("Canonicalization should succeed");

        // Must be valid JSON
        let parsed: Value = serde_json::from_str(&canonical)
            .expect("Canonical string should be valid JSON");

        // Must round-trip correctly
        if let Value::String(parsed_str) = parsed {
            prop_assert_eq!(s, parsed_str, "String should round-trip correctly");
        } else {
            prop_assert!(false, "Parsed value should be a string");
        }
    }
}

#[test]
fn test_no_whitespace_between_tokens() {
    let obj = json!({"a": 1, "b": [1, 2, 3], "c": {"nested": true}});
    let canonical = canonicalize(&obj).expect("Canonicalization should succeed");

    // Should not contain spaces outside of strings
    // The canonical form should have no spaces at all for this input
    assert!(!canonical.contains(' '), "Should not contain spaces");
}

#[test]
fn test_negative_zero_becomes_zero() {
    let val: Value = serde_json::from_str("-0.0").expect("Should parse");
    let canonical = canonicalize(&val).expect("Canonicalization should succeed");
    assert_eq!(canonical, "0", "-0.0 should become \"0\"");
}

#[test]
fn test_integers_have_no_decimal() {
    assert_eq!(canonicalize(&json!(42)).unwrap(), "42");
    assert_eq!(canonicalize(&json!(-100)).unwrap(), "-100");
    assert_eq!(canonicalize(&json!(0)).unwrap(), "0");
}


// ============================================================================
// Signer Property Tests
// ============================================================================

use gitclaw::{Ed25519Signer, EcdsaSigner, Signer};

proptest! {
    /// Property 12: Ed25519 key loading round-trip
    ///
    /// For any Ed25519 private key, loading the key from PEM format, extracting
    /// the public key, and using it to verify a signature created by the signer
    /// SHALL succeed.
    ///
    /// **Validates: Requirements 2.1, 2.3** | **Design: DR-1**
    #[test]
    fn test_ed25519_key_loading_round_trip(message in prop::collection::vec(any::<u8>(), 1..1000)) {
        // Generate a keypair
        let (signer, public_key) = Ed25519Signer::generate();

        // Get PEM representation
        let pem = signer.private_key_pem();

        // Load from PEM
        let loaded_signer = Ed25519Signer::from_pem(&pem)
            .expect("Should load from PEM");

        // Sign with original signer
        let signature = signer.sign(&message).expect("Should sign");

        // Verify with loaded signer (uses same public key)
        prop_assert!(
            loaded_signer.verify(&signature, &message),
            "Signature verification failed after PEM round-trip"
        );

        // Sign with loaded signer and verify with original
        let signature2 = loaded_signer.sign(&message).expect("Should sign");
        prop_assert!(
            signer.verify(&signature2, &message),
            "Cross-verification failed after PEM round-trip"
        );

        // Public keys should match
        prop_assert_eq!(
            signer.public_key(),
            loaded_signer.public_key(),
            "Public keys don't match after PEM round-trip"
        );

        // Public key should have correct prefix
        prop_assert!(
            public_key.starts_with("ed25519:"),
            "Public key should have ed25519: prefix"
        );
    }

    /// Property 13: ECDSA key loading round-trip
    ///
    /// For any ECDSA P-256 private key, loading the key from PEM format, extracting
    /// the public key, and using it to verify a signature created by the signer
    /// SHALL succeed.
    ///
    /// **Validates: Requirements 2.2, 2.3** | **Design: DR-1**
    #[test]
    fn test_ecdsa_key_loading_round_trip(message in prop::collection::vec(any::<u8>(), 1..1000)) {
        // Generate a keypair
        let (signer, public_key) = EcdsaSigner::generate();

        // Get PEM representation
        let pem = signer.private_key_pem();

        // Load from PEM
        let loaded_signer = EcdsaSigner::from_pem(&pem)
            .expect("Should load from PEM");

        // Sign with original signer
        let signature = signer.sign(&message).expect("Should sign");

        // Verify with loaded signer (uses same public key)
        prop_assert!(
            loaded_signer.verify(&signature, &message),
            "Signature verification failed after PEM round-trip"
        );

        // Sign with loaded signer and verify with original
        let signature2 = loaded_signer.sign(&message).expect("Should sign");
        prop_assert!(
            signer.verify(&signature2, &message),
            "Cross-verification failed after PEM round-trip"
        );

        // Public keys should match
        prop_assert_eq!(
            signer.public_key(),
            loaded_signer.public_key(),
            "Public keys don't match after PEM round-trip"
        );

        // Public key should have correct prefix
        prop_assert!(
            public_key.starts_with("ecdsa:"),
            "Public key should have ecdsa: prefix"
        );
    }

    /// Test that Ed25519 keys can be loaded from raw bytes.
    ///
    /// **Validates: Requirements 2.1** | **Design: DR-1**
    #[test]
    fn test_ed25519_from_bytes_round_trip(seed in prop::array::uniform32(any::<u8>())) {
        // Create signer from raw bytes
        let signer = Ed25519Signer::from_bytes(&seed)
            .expect("Should create from bytes");

        // Sign a test message
        let message = b"test message";
        let signature = signer.sign(message).expect("Should sign");

        // Verify signature
        prop_assert!(
            signer.verify(&signature, message),
            "Signature verification failed"
        );

        // Create another signer from same bytes - should produce same key
        let signer2 = Ed25519Signer::from_bytes(&seed)
            .expect("Should create from bytes");
        prop_assert_eq!(
            signer.public_key(),
            signer2.public_key(),
            "Same seed should produce same public key"
        );
    }
}

#[test]
fn test_ed25519_signature_length() {
    let (signer, _) = Ed25519Signer::generate();

    for msg in [b"".as_slice(), b"x".as_slice(), &[b'x'; 1000]] {
        let sig = signer.sign(msg).expect("Should sign");
        assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");
    }
}

#[test]
fn test_ed25519_signature_is_deterministic() {
    let (signer, _) = Ed25519Signer::generate();
    let message = b"test message";

    let sig1 = signer.sign(message).expect("Should sign");
    let sig2 = signer.sign(message).expect("Should sign");

    assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
}

#[test]
fn test_ecdsa_signature_is_der_encoded() {
    let (signer, _) = EcdsaSigner::generate();

    // Sign multiple messages - DER encoding produces variable length
    for i in 0..10 {
        let sig = signer.sign(format!("message {i}").as_bytes()).expect("Should sign");
        // DER-encoded P-256 signatures are typically 70-72 bytes
        assert!(
            (68..=72).contains(&sig.len()),
            "Unexpected signature length: {}",
            sig.len()
        );
    }
}


// ============================================================================
// Signature Generation and Transport Property Tests
// ============================================================================

use gitclaw::{EnvelopeBuilder, SignatureEnvelope, sign_envelope, compute_nonce_hash};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::{HashMap, HashSet};

proptest! {
    /// Property 1: Signature generation produces backend-compatible signatures
    ///
    /// For any valid agent_id, signer, action, and body, the SDK's signature
    /// generation process SHALL produce a signature that can be verified.
    ///
    /// This property validates the complete signing flow:
    /// - Envelope construction with all required fields (agentId, action, timestamp, nonce, body)
    /// - JCS canonicalization of the envelope
    /// - SHA256 hashing of the canonical JSON
    /// - Signing the hash with the private key
    /// - Base64 encoding of the signature
    ///
    /// **Validates: Requirements 2.4, 2.5, 2.6, 2.7** | **Design: DR-3**
    #[test]
    fn test_signature_generation_produces_valid_signatures(
        agent_id in "[a-zA-Z0-9_-]{1,50}",
        action in "[a-zA-Z_][a-zA-Z0-9_]{0,30}",
        body_keys in prop::collection::vec("[a-zA-Z_][a-zA-Z0-9_]{0,20}", 0..5),
        body_values in prop::collection::vec("[a-zA-Z0-9 _-]{0,50}", 0..5)
    ) {
        // Generate a keypair
        let (signer, _) = Ed25519Signer::generate();

        // Build body from keys and values
        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        for (key, value) in body_keys.iter().zip(body_values.iter()) {
            body.insert(key.clone(), serde_json::json!(value));
        }

        // Build envelope
        let builder = EnvelopeBuilder::new(agent_id.clone());
        let envelope = builder.build(&action, body);

        // Sign the envelope
        let signature = sign_envelope(&envelope, &signer)
            .expect("Signing should succeed");

        // Signature should be valid base64
        let decoded = BASE64.decode(&signature)
            .expect("Signature should be valid base64");

        // Ed25519 signatures are 64 bytes
        prop_assert_eq!(
            decoded.len(),
            64,
            "Ed25519 signature should be 64 bytes, got {}",
            decoded.len()
        );

        // Verify the signature using the signer
        let message_hash = gitclaw::get_message_hash(&envelope)
            .expect("Hashing should succeed");
        prop_assert!(
            signer.verify(&decoded, &message_hash),
            "Signature verification failed"
        );

        // Envelope should have all required fields
        let envelope_value = envelope.to_value();
        prop_assert!(envelope_value.get("agentId").is_some(), "Missing agentId");
        prop_assert!(envelope_value.get("action").is_some(), "Missing action");
        prop_assert!(envelope_value.get("timestamp").is_some(), "Missing timestamp");
        prop_assert!(envelope_value.get("nonce").is_some(), "Missing nonce");
        prop_assert!(envelope_value.get("body").is_some(), "Missing body");

        // Verify field values
        prop_assert_eq!(
            envelope_value["agentId"].as_str(),
            Some(agent_id.as_str()),
            "agentId mismatch"
        );
        prop_assert_eq!(
            envelope_value["action"].as_str(),
            Some(action.as_str()),
            "action mismatch"
        );
    }

    /// Property 4: Retry generates new nonces
    ///
    /// For any request that is retried due to a retryable error, each retry
    /// attempt SHALL use a different nonce than all previous attempts for
    /// that request.
    ///
    /// This property ensures idempotency semantics are preserved across retries
    /// and prevents replay attack errors on retry.
    ///
    /// **Validates: Requirements 4.4, 5.4** | **Design: DR-4**
    #[test]
    fn test_retry_generates_new_nonces(
        agent_id in "[a-zA-Z0-9_-]{1,50}",
        action in "[a-zA-Z_][a-zA-Z0-9_]{0,30}",
        num_retries in 2..10usize
    ) {
        let builder = EnvelopeBuilder::new(agent_id);

        // Simulate multiple retry attempts by building multiple envelopes
        let mut nonces: HashSet<String> = HashSet::new();

        for _ in 0..num_retries {
            let envelope = builder.build_empty(&action);

            // Each nonce should be unique
            prop_assert!(
                nonces.insert(envelope.nonce.clone()),
                "Duplicate nonce detected: {}",
                envelope.nonce
            );

            // Nonce should be a valid UUID v4 format
            prop_assert!(
                uuid::Uuid::parse_str(&envelope.nonce).is_ok(),
                "Nonce is not a valid UUID: {}",
                envelope.nonce
            );
        }

        // All nonces should be unique
        prop_assert_eq!(
            nonces.len(),
            num_retries,
            "Expected {} unique nonces, got {}",
            num_retries,
            nonces.len()
        );
    }

    /// Property 14: Nonce hash computation
    ///
    /// For any agent_id and nonce, the computed nonce_hash SHALL equal
    /// SHA256(agent_id + ":" + nonce) encoded as a hex string.
    ///
    /// **Validates: Requirements 4.3** | **Design: DR-3**
    #[test]
    fn test_nonce_hash_computation(
        agent_id in "[a-zA-Z0-9_-]{1,50}",
        nonce in "[a-zA-Z0-9-]{36}"
    ) {
        let hash = compute_nonce_hash(&agent_id, &nonce);

        // Hash should be 64 hex characters (32 bytes)
        prop_assert_eq!(
            hash.len(),
            64,
            "Nonce hash should be 64 hex chars, got {}",
            hash.len()
        );

        // Hash should be valid hex
        prop_assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Nonce hash should be valid hex: {}",
            hash
        );

        // Verify the hash is computed correctly
        use sha2::{Sha256, Digest};
        let data = format!("{agent_id}:{nonce}");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let expected = hex::encode(hasher.finalize());

        prop_assert_eq!(
            hash,
            expected,
            "Nonce hash mismatch"
        );
    }

    /// Test that signature generation is deterministic for the same envelope.
    ///
    /// **Validates: Requirements 2.5, 2.6** | **Design: DR-3**
    #[test]
    fn test_signature_generation_is_deterministic(
        agent_id in "[a-zA-Z0-9_-]{1,50}",
        action in "[a-zA-Z_][a-zA-Z0-9_]{0,30}"
    ) {
        let (signer, _) = Ed25519Signer::generate();

        // Create a fixed envelope (same timestamp and nonce)
        let envelope = SignatureEnvelope::new(
            agent_id,
            action,
            chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&chrono::Utc),
            "fixed-nonce-12345".to_string(),
            HashMap::new(),
        );

        // Sign twice
        let sig1 = sign_envelope(&envelope, &signer).expect("Signing should succeed");
        let sig2 = sign_envelope(&envelope, &signer).expect("Signing should succeed");

        // Signatures should be identical
        prop_assert_eq!(
            sig1,
            sig2,
            "Signatures should be deterministic for the same envelope"
        );
    }
}

#[test]
fn test_envelope_contains_all_required_fields() {
    let builder = EnvelopeBuilder::new("test-agent".to_string());
    let envelope = builder.build_empty("test_action");

    let value = envelope.to_value();

    // Check all required fields exist
    assert!(value.get("agentId").is_some());
    assert!(value.get("action").is_some());
    assert!(value.get("timestamp").is_some());
    assert!(value.get("nonce").is_some());
    assert!(value.get("body").is_some());

    // Check field types
    assert!(value["agentId"].is_string());
    assert!(value["action"].is_string());
    assert!(value["timestamp"].is_string());
    assert!(value["nonce"].is_string());
    assert!(value["body"].is_object());
}

#[test]
fn test_nonce_is_uuid_v4() {
    let builder = EnvelopeBuilder::new("test-agent".to_string());

    for _ in 0..10 {
        let envelope = builder.build_empty("test_action");
        let uuid = uuid::Uuid::parse_str(&envelope.nonce)
            .expect("Nonce should be a valid UUID");

        // UUID v4 has version 4
        assert_eq!(uuid.get_version_num(), 4, "Nonce should be UUID v4");
    }
}

#[test]
fn test_timestamp_format_is_iso8601() {
    let builder = EnvelopeBuilder::new("test-agent".to_string());
    let envelope = builder.build_empty("test_action");

    let timestamp = envelope.format_timestamp();

    // Should end with Z
    assert!(timestamp.ends_with('Z'), "Timestamp should end with Z");

    // Should be parseable as ISO 8601
    chrono::DateTime::parse_from_rfc3339(&timestamp)
        .expect("Timestamp should be valid ISO 8601");
}

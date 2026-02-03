//! Signature Validator Service
//!
//! Implements cryptographic signature validation for all mutating actions.
//! Supports Ed25519 and ECDSA (P-256) signatures with JSON Canonicalization Scheme (JCS, RFC 8785).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::services::crypto::KeyType;

/// Errors that can occur during signature validation
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Invalid signature format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Timestamp expired: signature is older than {0} minutes")]
    TimestampExpired(i64),

    #[error("Timestamp in future: signature timestamp is {0} seconds in the future")]
    TimestampInFuture(i64),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    /// Agent is suspended and cannot perform mutating operations
    /// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
    #[error("Agent is suspended: {0}")]
    Suspended(String),
}

/// Signature envelope containing all signed data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEnvelope {
    pub agent_id: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub body: serde_json::Value,
}

/// Git-specific body for transport operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitTransportBody {
    pub packfile_hash: String,
    pub ref_updates: Vec<RefUpdate>,
}

/// Reference update for Git push operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefUpdate {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
    pub force: bool,
}

/// Configuration for signature validation
#[derive(Debug, Clone)]
pub struct SignatureValidatorConfig {
    /// Maximum age of a signature in minutes (default: 5)
    pub max_age_minutes: i64,
    /// Maximum future tolerance in seconds (default: 30)
    pub max_future_seconds: i64,
}

impl Default for SignatureValidatorConfig {
    fn default() -> Self {
        Self {
            max_age_minutes: 5,
            max_future_seconds: 30,
        }
    }
}

/// Service for validating cryptographic signatures
#[derive(Debug, Clone)]
pub struct SignatureValidator {
    config: SignatureValidatorConfig,
}

impl Default for SignatureValidator {
    fn default() -> Self {
        Self::new(SignatureValidatorConfig::default())
    }
}

impl SignatureValidator {
    pub fn new(config: SignatureValidatorConfig) -> Self {
        Self { config }
    }

    /// Validate a signature against the provided envelope and public key.
    ///
    /// # Arguments
    /// * `envelope` - The signature envelope containing the signed data
    /// * `signature` - Base64-encoded signature
    /// * `public_key` - The agent's public key (with optional type prefix)
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid
    /// * `Err(SignatureError)` if validation fails
    pub fn validate(
        &self,
        envelope: &SignatureEnvelope,
        signature: &str,
        public_key: &str,
    ) -> Result<(), SignatureError> {
        // 1. Validate timestamp
        self.validate_timestamp(&envelope.timestamp)?;

        // 2. Canonicalize the envelope using JCS
        let canonical = self.canonicalize(envelope)?;

        // 3. Compute SHA256 hash of canonical JSON
        let message_hash = Sha256::digest(canonical.as_bytes());

        // 4. Verify signature based on key type
        self.verify_signature(&message_hash, signature, public_key)
    }

    /// Validate that the timestamp is within acceptable bounds
    fn validate_timestamp(&self, timestamp: &DateTime<Utc>) -> Result<(), SignatureError> {
        let now = Utc::now();
        let age = now.signed_duration_since(*timestamp);

        // Check if timestamp is too old
        if age > Duration::minutes(self.config.max_age_minutes) {
            return Err(SignatureError::TimestampExpired(
                self.config.max_age_minutes,
            ));
        }

        // Check if timestamp is too far in the future
        if age < Duration::seconds(-self.config.max_future_seconds) {
            return Err(SignatureError::TimestampInFuture(-age.num_seconds()));
        }

        Ok(())
    }

    /// Canonicalize JSON using JCS (RFC 8785)
    ///
    /// JCS rules:
    /// 1. Object keys are sorted lexicographically by UTF-16 code units
    /// 2. No whitespace between tokens
    /// 3. Numbers use shortest representation without trailing zeros
    /// 4. Strings use minimal escaping
    pub fn canonicalize(&self, envelope: &SignatureEnvelope) -> Result<String, SignatureError> {
        // Serialize to serde_json::Value first
        let value = serde_json::to_value(envelope)
            .map_err(|e| SignatureError::InvalidJson(e.to_string()))?;

        // Recursively sort and serialize
        let canonical = self.canonicalize_value(&value)?;
        Ok(canonical)
    }

    /// Recursively canonicalize a JSON value
    fn canonicalize_value(&self, value: &serde_json::Value) -> Result<String, SignatureError> {
        match value {
            serde_json::Value::Null => Ok("null".to_string()),
            serde_json::Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
            serde_json::Value::Number(n) => {
                // JCS requires shortest representation
                Ok(n.to_string())
            }
            serde_json::Value::String(s) => {
                // Escape string according to JSON spec
                Ok(self.escape_string(s))
            }
            serde_json::Value::Array(arr) => {
                let elements: Result<Vec<String>, _> =
                    arr.iter().map(|v| self.canonicalize_value(v)).collect();
                Ok(format!("[{}]", elements?.join(",")))
            }
            serde_json::Value::Object(obj) => {
                // Sort keys lexicographically
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort();

                let pairs: Result<Vec<String>, _> = keys
                    .iter()
                    .map(|k| {
                        let v = obj.get(*k).ok_or_else(|| {
                            SignatureError::InvalidJson("Missing key".to_string())
                        })?;
                        let canonical_value = self.canonicalize_value(v)?;
                        Ok(format!("{}:{}", self.escape_string(k), canonical_value))
                    })
                    .collect();
                Ok(format!("{{{}}}", pairs?.join(",")))
            }
        }
    }

    /// Escape a string according to JSON spec
    fn escape_string(&self, s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 2);
        result.push('"');
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if c.is_control() => {
                    result.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => result.push(c),
            }
        }
        result.push('"');
        result
    }

    /// Verify the signature using the appropriate algorithm
    fn verify_signature(
        &self,
        message_hash: &[u8],
        signature: &str,
        public_key: &str,
    ) -> Result<(), SignatureError> {
        let (key_type, key_data) = self.parse_key_prefix(public_key)?;

        match key_type {
            KeyType::Ed25519 => self.verify_ed25519(message_hash, signature, &key_data),
            KeyType::Ecdsa => self.verify_ecdsa(message_hash, signature, &key_data),
        }
    }

    /// Parse the key type prefix from a public key string
    fn parse_key_prefix(&self, public_key: &str) -> Result<(KeyType, String), SignatureError> {
        if let Some(key_data) = public_key.strip_prefix("ed25519:") {
            Ok((KeyType::Ed25519, key_data.to_string()))
        } else if let Some(key_data) = public_key.strip_prefix("ecdsa:") {
            Ok((KeyType::Ecdsa, key_data.to_string()))
        } else {
            // Default to Ed25519 if no prefix
            Ok((KeyType::Ed25519, public_key.to_string()))
        }
    }

    /// Verify an Ed25519 signature
    fn verify_ed25519(
        &self,
        message_hash: &[u8],
        signature: &str,
        key_data: &str,
    ) -> Result<(), SignatureError> {
        // Decode the public key
        let key_bytes = STANDARD
            .decode(key_data)
            .map_err(|e| SignatureError::InvalidPublicKey(format!("Invalid base64: {e}")))?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidPublicKey("Invalid key length".to_string()))?;

        let verifying_key = Ed25519VerifyingKey::from_bytes(&key_array)
            .map_err(|e| SignatureError::InvalidPublicKey(format!("Invalid Ed25519 key: {e}")))?;

        // Decode the signature
        let sig_bytes = STANDARD
            .decode(signature)
            .map_err(|e| SignatureError::InvalidFormat(format!("Invalid signature base64: {e}")))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidFormat("Invalid signature length".to_string()))?;

        let sig = Ed25519Signature::from_bytes(&sig_array);

        // Verify the signature over the message hash
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(message_hash, &sig)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Verify an ECDSA P-256 signature
    fn verify_ecdsa(
        &self,
        message_hash: &[u8],
        signature: &str,
        key_data: &str,
    ) -> Result<(), SignatureError> {
        // Decode the public key
        let key_bytes = STANDARD
            .decode(key_data)
            .map_err(|e| SignatureError::InvalidPublicKey(format!("Invalid base64: {e}")))?;

        let verifying_key = P256VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|e| SignatureError::InvalidPublicKey(format!("Invalid ECDSA key: {e}")))?;

        // Decode the signature (DER or raw format)
        let sig_bytes = STANDARD
            .decode(signature)
            .map_err(|e| SignatureError::InvalidFormat(format!("Invalid signature base64: {e}")))?;

        // Try to parse as DER first, then as raw bytes
        let sig = P256Signature::from_der(&sig_bytes)
            .or_else(|_| P256Signature::from_slice(&sig_bytes))
            .map_err(|e| SignatureError::InvalidFormat(format!("Invalid ECDSA signature: {e}")))?;

        // Verify the signature
        verifying_key
            .verify(message_hash, &sig)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Compute the nonce hash for replay detection
    ///
    /// Formula: SHA256(agentId + ":" + nonce)
    pub fn compute_nonce_hash(agent_id: &str, nonce: &str) -> String {
        let input = format!("{agent_id}:{nonce}");
        let hash = Sha256::digest(input.as_bytes());
        hex::encode(hash)
    }

    /// Create a signature envelope for validation
    pub fn create_envelope(
        agent_id: String,
        action: String,
        timestamp: DateTime<Utc>,
        nonce: String,
        body: serde_json::Value,
    ) -> SignatureEnvelope {
        SignatureEnvelope {
            agent_id,
            action,
            timestamp,
            nonce,
            body,
        }
    }
}

/// Check if an agent is suspended
///
/// This function queries the database to check if an agent is suspended.
/// If the agent is suspended, it returns a `SignatureError::Suspended` error.
///
/// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `agent_id` - The agent ID to check
///
/// # Returns
/// * `Ok(())` if the agent is not suspended
/// * `Err(SignatureError::Suspended)` if the agent is suspended
/// * `Err(SignatureError::MissingField)` if the agent is not found
pub async fn check_agent_not_suspended(
    pool: &sqlx::PgPool,
    agent_id: &str,
) -> Result<(), SignatureError> {
    let result: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT suspended, suspended_reason FROM agents WHERE agent_id = $1",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| SignatureError::InvalidJson(format!("Database error: {e}")))?;

    match result {
        None => Err(SignatureError::MissingField(format!(
            "Agent not found: {agent_id}"
        ))),
        Some((true, reason)) => {
            let message = match reason {
                Some(r) => format!("{agent_id} - {r}"),
                None => agent_id.to_string(),
            };
            Err(SignatureError::Suspended(message))
        }
        Some((false, _)) => Ok(()),
    }
}

/// Get agent's public key and check suspension status in a single query
///
/// This is an optimized function that retrieves the agent's public key
/// while also checking if the agent is suspended. This reduces database
/// round-trips for mutating operations.
///
/// Requirements: 2.6 - Suspended agents must be rejected with SUSPENDED_AGENT error
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `agent_id` - The agent ID to check
///
/// # Returns
/// * `Ok(public_key)` if the agent exists and is not suspended
/// * `Err(SignatureError::Suspended)` if the agent is suspended
/// * `Err(SignatureError::MissingField)` if the agent is not found
pub async fn get_agent_public_key_if_not_suspended(
    pool: &sqlx::PgPool,
    agent_id: &str,
) -> Result<String, SignatureError> {
    let result: Option<(String, bool, Option<String>)> = sqlx::query_as(
        "SELECT public_key, suspended, suspended_reason FROM agents WHERE agent_id = $1",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| SignatureError::InvalidJson(format!("Database error: {e}")))?;

    match result {
        None => Err(SignatureError::MissingField(format!(
            "Agent not found: {agent_id}"
        ))),
        Some((_, true, reason)) => {
            let message = match reason {
                Some(r) => format!("{agent_id} - {r}"),
                None => agent_id.to_string(),
            };
            Err(SignatureError::Suspended(message))
        }
        Some((public_key, false, _)) => Ok(public_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer};
    use rand::rngs::OsRng;

    fn create_test_validator() -> SignatureValidator {
        SignatureValidator::default()
    }

    pub fn generate_ed25519_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        (signing_key, public_key)
    }

    pub fn generate_p256_keypair() -> (P256SigningKey, String) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = format!("ecdsa:{}", STANDARD.encode(verifying_key.to_sec1_bytes()));
        (signing_key, public_key)
    }

    pub fn sign_envelope_ed25519(signing_key: &SigningKey, envelope: &SignatureEnvelope) -> String {
        let validator = create_test_validator();
        let canonical = validator
            .canonicalize(envelope)
            .expect("canonicalize failed");
        let message_hash = Sha256::digest(canonical.as_bytes());

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&message_hash);
        STANDARD.encode(signature.to_bytes())
    }

    pub fn sign_envelope_p256(
        signing_key: &P256SigningKey,
        envelope: &SignatureEnvelope,
    ) -> String {
        let validator = create_test_validator();
        let canonical = validator
            .canonicalize(envelope)
            .expect("canonicalize failed");
        let message_hash = Sha256::digest(canonical.as_bytes());

        let signature: P256Signature = signing_key.sign(&message_hash);
        STANDARD.encode(signature.to_der())
    }

    #[test]
    fn test_valid_ed25519_signature() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_ed25519_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(result.is_ok(), "Expected valid signature: {:?}", result);
    }

    #[test]
    fn test_valid_ed25519_signature_with_prefix() {
        let validator = create_test_validator();
        let (signing_key, public_key_raw) = generate_ed25519_keypair();
        let public_key = format!("ed25519:{public_key_raw}");

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(result.is_ok(), "Expected valid signature: {:?}", result);
    }

    #[test]
    fn test_valid_ecdsa_signature() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_p256_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_p256(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(result.is_ok(), "Expected valid signature: {:?}", result);
    }

    #[test]
    fn test_invalid_signature() {
        let validator = create_test_validator();
        let (_, public_key) = generate_ed25519_keypair();
        let (other_signing_key, _) = generate_ed25519_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        // Sign with wrong key
        let signature = sign_envelope_ed25519(&other_signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn test_expired_timestamp() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_ed25519_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now() - Duration::minutes(10), // 10 minutes ago
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(matches!(result, Err(SignatureError::TimestampExpired(_))));
    }

    #[test]
    fn test_future_timestamp() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_ed25519_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now() + Duration::minutes(5), // 5 minutes in future
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(matches!(result, Err(SignatureError::TimestampInFuture(_))));
    }

    #[test]
    fn test_nonce_hash_computation() {
        let agent_id = "agent-123";
        let nonce = "550e8400-e29b-41d4-a716-446655440000";

        let hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);

        // Verify it's a valid hex string of correct length (SHA256 = 64 hex chars)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Same inputs should produce same hash
        let hash2 = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        assert_eq!(hash, hash2);

        // Different inputs should produce different hash
        let hash3 = SignatureValidator::compute_nonce_hash(agent_id, "different-nonce");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_canonicalization_key_ordering() {
        let validator = create_test_validator();

        // Create envelope with body that has keys in non-alphabetical order
        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("parse timestamp")
                .with_timezone(&Utc),
            nonce: "test-nonce".to_string(),
            body: serde_json::json!({
                "zebra": "last",
                "apple": "first",
                "middle": "middle"
            }),
        };

        let canonical = validator.canonicalize(&envelope).expect("canonicalize");

        // Verify keys are sorted
        assert!(canonical.contains("\"action\":"));
        assert!(canonical.contains("\"agentId\":"));

        // Body keys should be sorted: apple, middle, zebra
        let body_start = canonical.find("\"body\":").expect("find body");
        let body_section = &canonical[body_start..];
        let apple_pos = body_section.find("\"apple\"").expect("find apple");
        let middle_pos = body_section.find("\"middle\"").expect("find middle");
        let zebra_pos = body_section.find("\"zebra\"").expect("find zebra");

        assert!(apple_pos < middle_pos, "apple should come before middle");
        assert!(middle_pos < zebra_pos, "middle should come before zebra");
    }

    #[test]
    fn test_canonicalization_no_whitespace() {
        let validator = create_test_validator();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("parse timestamp")
                .with_timezone(&Utc),
            nonce: "test-nonce".to_string(),
            body: serde_json::json!({"key": "value"}),
        };

        let canonical = validator.canonicalize(&envelope).expect("canonicalize");

        // Should not contain any unnecessary whitespace
        assert!(!canonical.contains(" :"));
        assert!(!canonical.contains(": "));
        assert!(!canonical.contains("{ "));
        assert!(!canonical.contains(" }"));
        assert!(!canonical.contains("[ "));
        assert!(!canonical.contains(" ]"));
    }

    #[test]
    fn test_tampered_envelope_fails() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_ed25519_keypair();

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::json!({"repoId": "repo-456"}),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);

        // Tamper with the envelope
        let tampered_envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "star".to_string(),
            timestamp: envelope.timestamp,
            nonce: envelope.nonce.clone(),
            body: serde_json::json!({"repoId": "repo-TAMPERED"}), // Changed!
        };

        let result = validator.validate(&tampered_envelope, &signature, &public_key);
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn test_git_transport_body() {
        let validator = create_test_validator();
        let (signing_key, public_key) = generate_ed25519_keypair();

        let git_body = GitTransportBody {
            packfile_hash: "abc123def456".to_string(),
            ref_updates: vec![RefUpdate {
                ref_name: "refs/heads/main".to_string(),
                old_oid: "0000000000000000000000000000000000000000".to_string(),
                new_oid: "abc123def456789012345678901234567890abcd".to_string(),
                force: false,
            }],
        };

        let envelope = SignatureEnvelope {
            agent_id: "agent-123".to_string(),
            action: "git-receive-pack".to_string(),
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            body: serde_json::to_value(&git_body).expect("serialize git body"),
        };

        let signature = sign_envelope_ed25519(&signing_key, &envelope);
        let result = validator.validate(&envelope, &signature, &public_key);
        assert!(result.is_ok(), "Expected valid signature: {:?}", result);
    }

    /// **Property 15: Signature Validation**
    ///
    /// For any signed action with invalid signature, the action SHALL be rejected.
    ///
    /// **Validates: Requirements 12.1** | **Design: DR-3.1**
    ///
    /// This property test verifies that:
    /// 1. Valid signatures are accepted
    /// 2. Invalid signatures (wrong key, tampered data, malformed) are rejected
    /// 3. The signature validation is deterministic and consistent
    mod property_signature_validation {
        use super::*;
        use proptest::prelude::*;

        /// Strategy to generate valid agent IDs
        fn agent_id_strategy() -> impl Strategy<Value = String> {
            "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
        }

        /// Strategy to generate valid action names
        fn action_strategy() -> impl Strategy<Value = String> {
            prop::sample::select(vec![
                "star".to_string(),
                "unstar".to_string(),
                "repo_create".to_string(),
                "push".to_string(),
                "pr_create".to_string(),
                "review".to_string(),
                "merge".to_string(),
                "git-receive-pack".to_string(),
                "git-upload-pack".to_string(),
            ])
        }

        /// Strategy to generate valid nonces (UUID v4 format)
        fn nonce_strategy() -> impl Strategy<Value = String> {
            "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
        }

        /// Strategy to generate arbitrary JSON body values
        fn body_strategy() -> impl Strategy<Value = serde_json::Value> {
            prop_oneof![
                Just(serde_json::json!({})),
                Just(serde_json::json!({"repoId": "repo-123"})),
                Just(serde_json::json!({"repoId": "repo-456", "reason": "great code"})),
                Just(serde_json::json!({"prId": "pr-789", "verdict": "approve"})),
                Just(serde_json::json!({"name": "my-repo", "visibility": "public"})),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            /// Test that valid Ed25519 signatures are accepted
            ///
            /// This test validates that properly signed envelopes pass validation:
            /// 1. Generate a random keypair
            /// 2. Create an envelope with random valid data
            /// 3. Sign the envelope with the private key
            /// 4. Verify the signature is accepted
            #[test]
            fn valid_ed25519_signature_accepted(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy()
            ) {
                let validator = create_test_validator();
                let (signing_key, public_key) = generate_ed25519_keypair();

                let envelope = SignatureEnvelope {
                    agent_id,
                    action,
                    timestamp: Utc::now(),
                    nonce,
                    body,
                };

                let signature = sign_envelope_ed25519(&signing_key, &envelope);
                let result = validator.validate(&envelope, &signature, &public_key);

                prop_assert!(
                    result.is_ok(),
                    "Valid Ed25519 signature should be accepted: {:?}",
                    result
                );
            }

            /// Test that valid ECDSA signatures are accepted
            ///
            /// This test validates that properly signed envelopes with ECDSA pass validation
            #[test]
            fn valid_ecdsa_signature_accepted(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy()
            ) {
                let validator = create_test_validator();
                let (signing_key, public_key) = generate_p256_keypair();

                let envelope = SignatureEnvelope {
                    agent_id,
                    action,
                    timestamp: Utc::now(),
                    nonce,
                    body,
                };

                let signature = sign_envelope_p256(&signing_key, &envelope);
                let result = validator.validate(&envelope, &signature, &public_key);

                prop_assert!(
                    result.is_ok(),
                    "Valid ECDSA signature should be accepted: {:?}",
                    result
                );
            }

            /// Test that signatures with wrong key are rejected
            ///
            /// This test validates that signatures made with a different private key
            /// than the one corresponding to the public key are rejected.
            #[test]
            fn wrong_key_signature_rejected(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy()
            ) {
                let validator = create_test_validator();

                // Generate two different keypairs
                let (signing_key, _) = generate_ed25519_keypair();
                let (_, wrong_public_key) = generate_ed25519_keypair();

                let envelope = SignatureEnvelope {
                    agent_id,
                    action,
                    timestamp: Utc::now(),
                    nonce,
                    body,
                };

                // Sign with one key, verify with another
                let signature = sign_envelope_ed25519(&signing_key, &envelope);
                let result = validator.validate(&envelope, &signature, &wrong_public_key);

                prop_assert!(
                    matches!(result, Err(SignatureError::VerificationFailed)),
                    "Signature with wrong key should be rejected: {:?}",
                    result
                );
            }

            /// Test that tampered envelope data is rejected
            ///
            /// This test validates that any modification to the signed envelope
            /// after signing causes the signature to be rejected.
            #[test]
            fn tampered_envelope_rejected(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy(),
                tampered_action in action_strategy()
            ) {
                // Skip if actions happen to be the same
                prop_assume!(action != tampered_action);

                let validator = create_test_validator();
                let (signing_key, public_key) = generate_ed25519_keypair();

                let original_envelope = SignatureEnvelope {
                    agent_id: agent_id.clone(),
                    action: action.clone(),
                    timestamp: Utc::now(),
                    nonce: nonce.clone(),
                    body: body.clone(),
                };

                // Sign the original envelope
                let signature = sign_envelope_ed25519(&signing_key, &original_envelope);

                // Create a tampered envelope with different action
                let tampered_envelope = SignatureEnvelope {
                    agent_id,
                    action: tampered_action,
                    timestamp: original_envelope.timestamp,
                    nonce,
                    body,
                };

                // Verify tampered envelope is rejected
                let result = validator.validate(&tampered_envelope, &signature, &public_key);

                prop_assert!(
                    matches!(result, Err(SignatureError::VerificationFailed)),
                    "Tampered envelope should be rejected: {:?}",
                    result
                );
            }

            /// Test that malformed signatures are rejected
            ///
            /// This test validates that signatures that are not valid base64
            /// or have incorrect length are rejected.
            #[test]
            fn malformed_signature_rejected(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy(),
                garbage in "[a-zA-Z0-9]{10,100}"
            ) {
                let validator = create_test_validator();
                let (_, public_key) = generate_ed25519_keypair();

                let envelope = SignatureEnvelope {
                    agent_id,
                    action,
                    timestamp: Utc::now(),
                    nonce,
                    body,
                };

                // Use garbage as signature
                let result = validator.validate(&envelope, &garbage, &public_key);

                prop_assert!(
                    result.is_err(),
                    "Malformed signature should be rejected"
                );
            }

            /// Test signature validation is deterministic
            ///
            /// This test validates that the same envelope, signature, and key
            /// always produce the same validation result.
            #[test]
            fn signature_validation_is_deterministic(
                agent_id in agent_id_strategy(),
                action in action_strategy(),
                nonce in nonce_strategy(),
                body in body_strategy()
            ) {
                let validator = create_test_validator();
                let (signing_key, public_key) = generate_ed25519_keypair();

                let envelope = SignatureEnvelope {
                    agent_id,
                    action,
                    timestamp: Utc::now(),
                    nonce,
                    body,
                };

                let signature = sign_envelope_ed25519(&signing_key, &envelope);

                // Validate multiple times
                let result1 = validator.validate(&envelope, &signature, &public_key);
                let result2 = validator.validate(&envelope, &signature, &public_key);
                let result3 = validator.validate(&envelope, &signature, &public_key);

                prop_assert!(result1.is_ok());
                prop_assert!(result2.is_ok());
                prop_assert!(result3.is_ok());
            }
        }
    }
}

// Integration tests for Signature Validation
// These tests validate the full signature validation flow end-to-end
// Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
// Design: DR-3.1, DR-3.2
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::services::idempotency::{IdempotencyResult, IdempotencyService};
    use base64::engine::general_purpose::STANDARD;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;

    /// Helper to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };

        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()
    }

    /// Generate an Ed25519 keypair for testing
    fn generate_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        (signing_key, public_key)
    }

    /// Sign an envelope with Ed25519
    fn sign_envelope(signing_key: &SigningKey, envelope: &SignatureEnvelope) -> String {
        let validator = SignatureValidator::default();
        let canonical = validator
            .canonicalize(envelope)
            .expect("canonicalize failed");
        let message_hash = Sha256::digest(canonical.as_bytes());
        let signature = signing_key.sign(&message_hash);
        STANDARD.encode(signature.to_bytes())
    }

    /// Create a test agent in the database and return (agent_id, public_key, signing_key)
    async fn create_test_agent(pool: &PgPool) -> (String, String, SigningKey) {
        let (signing_key, public_key) = generate_test_keypair();
        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, $3, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .bind(&public_key)
        .execute(pool)
        .await
        .expect("Failed to create test agent");

        // Initialize reputation
        let _ = sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, 0.500, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .execute(pool)
        .await;

        (agent_id, public_key, signing_key)
    }

    /// Clean up test agent
    async fn cleanup_test_agent(pool: &PgPool, agent_id: &str) {
        let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    /// Clean up idempotency result
    async fn cleanup_idempotency(pool: &PgPool, agent_id: &str, nonce: &str) {
        let nonce_hash = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let _ = sqlx::query("DELETE FROM idempotency_results WHERE nonce_hash = $1")
            .bind(&nonce_hash)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: Valid signature passes verification end-to-end
    // Requirements: 12.1
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_valid_signature_passes_verification() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        let signature = sign_envelope(&signing_key, &envelope);

        // Validate signature
        let result = validator.validate(&envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            result.is_ok(),
            "Valid signature should pass verification: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Invalid signature returns INVALID_SIGNATURE (401)
    // Requirements: 12.1
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_invalid_signature_returns_verification_failed() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, _signing_key) = create_test_agent(&pool).await;
        let (other_signing_key, _) = generate_test_keypair();

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        // Sign with wrong key
        let signature = sign_envelope(&other_signing_key, &envelope);

        // Validate signature - should fail
        let result = validator.validate(&envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result, Err(SignatureError::VerificationFailed)),
            "Invalid signature should return VerificationFailed: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Expired signature (>5 min) returns SIGNATURE_EXPIRED (401)
    // Requirements: 12.3
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_expired_signature_returns_timestamp_expired() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create envelope with timestamp 10 minutes ago (expired)
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now() - Duration::minutes(10),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        let signature = sign_envelope(&signing_key, &envelope);

        // Validate signature - should fail due to expired timestamp
        let result = validator.validate(&envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result, Err(SignatureError::TimestampExpired(_))),
            "Expired signature should return TimestampExpired: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Nonce reuse for different action returns REPLAY_ATTACK (401)
    // Requirements: 12.4
    // Design: DR-3.1, DR-3.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_nonce_reuse_different_action_returns_replay_attack() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, _signing_key) = create_test_agent(&pool).await;

        let idempotency_service = IdempotencyService::new(pool.clone());
        let nonce = uuid::Uuid::new_v4().to_string();

        // Store a response for "star" action
        let response = serde_json::json!({"success": true, "action": "star"});
        idempotency_service
            .store(&agent_id, &nonce, "star", 200, &response)
            .await
            .expect("Failed to store idempotency result");

        // Try to use same nonce for "unstar" action
        let result = idempotency_service
            .check(&agent_id, &nonce, "unstar")
            .await
            .expect("Check should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        match result {
            IdempotencyResult::ReplayAttack { previous_action } => {
                assert_eq!(previous_action, "star", "Previous action should be 'star'");
            }
            _ => panic!("Expected ReplayAttack result, got {:?}", result),
        }
    }

    // =========================================================================
    // Test: Nonce reuse for same action returns cached response (idempotent)
    // Requirements: 12.5
    // Design: DR-3.2
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_nonce_reuse_same_action_returns_cached_response() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, _public_key, _signing_key) = create_test_agent(&pool).await;

        let idempotency_service = IdempotencyService::new(pool.clone());
        let nonce = uuid::Uuid::new_v4().to_string();

        // Store a response for "star" action
        let original_response = serde_json::json!({
            "success": true,
            "repoId": "test-repo-123",
            "starCount": 42
        });
        idempotency_service
            .store(&agent_id, &nonce, "star", 200, &original_response)
            .await
            .expect("Failed to store idempotency result");

        // Check with same nonce and same action
        let result = idempotency_service
            .check(&agent_id, &nonce, "star")
            .await
            .expect("Check should succeed");

        // Cleanup
        cleanup_idempotency(&pool, &agent_id, &nonce).await;
        cleanup_test_agent(&pool, &agent_id).await;

        match result {
            IdempotencyResult::Cached(cached) => {
                assert_eq!(cached.status_code, 200, "Status code should match");
                assert_eq!(
                    cached.response_json, original_response,
                    "Response JSON should match exactly"
                );
            }
            _ => panic!("Expected Cached result, got {:?}", result),
        }
    }

    // =========================================================================
    // Test: JCS canonical serialization produces consistent signatures
    // Requirements: 12.2
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_jcs_canonical_serialization_consistent() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Create envelope with body that has keys in non-alphabetical order
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp,
            nonce: nonce.clone(),
            body: serde_json::json!({
                "zebra": "last",
                "apple": "first",
                "middle": "middle"
            }),
        };

        // Sign the envelope
        let signature = sign_envelope(&signing_key, &envelope);

        // Validate - should succeed because JCS produces consistent canonical form
        let result1 = validator.validate(&envelope, &signature, &public_key);
        assert!(
            result1.is_ok(),
            "First validation should pass: {:?}",
            result1
        );

        // Create the same envelope again (keys might be in different order internally)
        let envelope2 = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp,
            nonce,
            body: serde_json::json!({
                "middle": "middle",
                "zebra": "last",
                "apple": "first"
            }),
        };

        // Validate with same signature - should still succeed due to JCS canonicalization
        let result2 = validator.validate(&envelope2, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            result2.is_ok(),
            "Second validation with reordered keys should pass due to JCS: {:?}",
            result2
        );
    }

    // =========================================================================
    // Test: Signature validation with Ed25519 prefix
    // Requirements: 12.6
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ed25519_prefix_signature_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (signing_key, public_key_raw) = generate_test_keypair();
        let public_key_with_prefix = format!("ed25519:{}", public_key_raw);

        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

        // Create agent with prefixed public key
        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, $3, '[]', NOW())
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .bind(&public_key_with_prefix)
        .execute(&pool)
        .await
        .expect("Failed to create test agent");

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        let signature = sign_envelope(&signing_key, &envelope);

        // Validate with prefixed public key
        let result = validator.validate(&envelope, &signature, &public_key_with_prefix);

        // Cleanup
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .execute(&pool)
            .await;

        assert!(
            result.is_ok(),
            "Signature validation with ed25519: prefix should pass: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Tampered envelope body fails signature validation
    // Requirements: 12.1
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_tampered_envelope_fails_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let original_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp,
            nonce: nonce.clone(),
            body: serde_json::json!({"repoId": "original-repo"}),
        };

        // Sign the original envelope
        let signature = sign_envelope(&signing_key, &original_envelope);

        // Create tampered envelope with different body
        let tampered_envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp,
            nonce,
            body: serde_json::json!({"repoId": "tampered-repo"}),
        };

        // Validate tampered envelope - should fail
        let result = validator.validate(&tampered_envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result, Err(SignatureError::VerificationFailed)),
            "Tampered envelope should fail validation: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Future timestamp (beyond tolerance) fails validation
    // Requirements: 12.3
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_future_timestamp_fails_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create envelope with timestamp 5 minutes in the future (beyond 30s tolerance)
        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now() + Duration::minutes(5),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        let signature = sign_envelope(&signing_key, &envelope);

        // Validate signature - should fail due to future timestamp
        let result = validator.validate(&envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result, Err(SignatureError::TimestampInFuture(_))),
            "Future timestamp should return TimestampInFuture: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Malformed signature base64 fails validation
    // Requirements: 12.1
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_malformed_signature_fails_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, _signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "star".to_string(),
            timestamp: Utc::now(),
            nonce,
            body: serde_json::json!({"repoId": "test-repo-123"}),
        };

        // Use invalid base64 as signature
        let malformed_signature = "not-valid-base64!!!";

        // Validate signature - should fail
        let result = validator.validate(&envelope, malformed_signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            matches!(result, Err(SignatureError::InvalidFormat(_))),
            "Malformed signature should return InvalidFormat: {:?}",
            result
        );
    }

    // =========================================================================
    // Test: Nonce hash computation is deterministic
    // Requirements: 12.2
    // Design: DR-3.1
    // =========================================================================
    #[test]
    fn integration_nonce_hash_deterministic() {
        let agent_id = "test-agent-123";
        let nonce = "550e8400-e29b-41d4-a716-446655440000";

        let hash1 = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let hash2 = SignatureValidator::compute_nonce_hash(agent_id, nonce);
        let hash3 = SignatureValidator::compute_nonce_hash(agent_id, nonce);

        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash2, hash3, "Hash should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA256 hash should be 64 hex chars");
    }

    // =========================================================================
    // Test: Different agent_id produces different nonce hash
    // Requirements: 12.2
    // Design: DR-3.1
    // =========================================================================
    #[test]
    fn integration_different_agent_produces_different_hash() {
        let nonce = "550e8400-e29b-41d4-a716-446655440000";

        let hash1 = SignatureValidator::compute_nonce_hash("agent-1", nonce);
        let hash2 = SignatureValidator::compute_nonce_hash("agent-2", nonce);

        assert_ne!(
            hash1, hash2,
            "Different agents should produce different hashes"
        );
    }

    // =========================================================================
    // Test: Git transport body signature validation
    // Requirements: 12.7
    // Design: DR-3.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_git_transport_body_signature_validation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };
        let (agent_id, public_key, signing_key) = create_test_agent(&pool).await;

        let validator = SignatureValidator::default();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Create Git transport body with packfile hash and ref updates
        let git_body = GitTransportBody {
            packfile_hash: "abc123def456789012345678901234567890abcd".to_string(),
            ref_updates: vec![
                RefUpdate {
                    ref_name: "refs/heads/main".to_string(),
                    old_oid: "0000000000000000000000000000000000000000".to_string(),
                    new_oid: "abc123def456789012345678901234567890abcd".to_string(),
                    force: false,
                },
                RefUpdate {
                    ref_name: "refs/heads/feature".to_string(),
                    old_oid: "1111111111111111111111111111111111111111".to_string(),
                    new_oid: "2222222222222222222222222222222222222222".to_string(),
                    force: true,
                },
            ],
        };

        let envelope = SignatureEnvelope {
            agent_id: agent_id.clone(),
            action: "git-receive-pack".to_string(),
            timestamp: Utc::now(),
            nonce,
            body: serde_json::to_value(&git_body).expect("serialize git body"),
        };

        let signature = sign_envelope(&signing_key, &envelope);

        // Validate signature
        let result = validator.validate(&envelope, &signature, &public_key);

        // Cleanup
        cleanup_test_agent(&pool, &agent_id).await;

        assert!(
            result.is_ok(),
            "Git transport body signature should be valid: {:?}",
            result
        );
    }
}

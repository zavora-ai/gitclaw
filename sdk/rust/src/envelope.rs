//! Signature envelope builder for GitClaw SDK.
//!
//! Constructs the canonical envelope structure that gets signed for API requests.
//!
//! Design Reference: DR-3
//! Requirements: 2.4, 4.1, 4.2

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// The canonical JSON structure containing all fields that get signed.
///
/// Per GitClaw protocol, every mutating action requires a signature over
/// this envelope structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEnvelope {
    /// The agent's unique identifier
    pub agent_id: String,
    /// The action being performed (e.g., "repo_create", "star")
    pub action: String,
    /// Timestamp of the request
    pub timestamp: DateTime<Utc>,
    /// Unique nonce (UUID v4) for idempotency
    pub nonce: String,
    /// Action-specific payload
    pub body: HashMap<String, Value>,
}

impl SignatureEnvelope {
    /// Create a new signature envelope.
    #[must_use]
    pub fn new(
        agent_id: String,
        action: String,
        timestamp: DateTime<Utc>,
        nonce: String,
        body: HashMap<String, Value>,
    ) -> Self {
        Self {
            agent_id,
            action,
            timestamp,
            nonce,
            body,
        }
    }

    /// Convert envelope to a serde_json::Value for canonicalization.
    #[must_use]
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "agentId": self.agent_id,
            "action": self.action,
            "timestamp": self.format_timestamp(),
            "nonce": self.nonce,
            "body": self.body,
        })
    }

    /// Format timestamp as ISO 8601 with Z suffix.
    #[must_use]
    pub fn format_timestamp(&self) -> String {
        self.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }
}

/// Builder for creating `SignatureEnvelope` instances.
///
/// Automatically generates UUID v4 nonces and timestamps.
#[derive(Debug, Clone)]
pub struct EnvelopeBuilder {
    agent_id: String,
}

impl EnvelopeBuilder {
    /// Create a new envelope builder for the given agent.
    #[must_use]
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Build a new `SignatureEnvelope` with auto-generated nonce and timestamp.
    ///
    /// # Arguments
    ///
    /// * `action` - The action being performed (e.g., "repo_create", "star")
    /// * `body` - Action-specific payload
    #[must_use]
    pub fn build(&self, action: &str, body: HashMap<String, Value>) -> SignatureEnvelope {
        SignatureEnvelope::new(
            self.agent_id.clone(),
            action.to_string(),
            Utc::now(),
            Uuid::new_v4().to_string(),
            body,
        )
    }

    /// Build a new `SignatureEnvelope` with an empty body.
    #[must_use]
    pub fn build_empty(&self, action: &str) -> SignatureEnvelope {
        self.build(action, HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_builder_generates_unique_nonces() {
        let builder = EnvelopeBuilder::new("test-agent".to_string());

        let env1 = builder.build_empty("test_action");
        let env2 = builder.build_empty("test_action");

        assert_ne!(env1.nonce, env2.nonce, "Nonces should be unique");
    }

    #[test]
    fn test_envelope_to_value() {
        let envelope = SignatureEnvelope::new(
            "agent-123".to_string(),
            "star".to_string(),
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce-456".to_string(),
            HashMap::new(),
        );

        let value = envelope.to_value();

        assert_eq!(value["agentId"], "agent-123");
        assert_eq!(value["action"], "star");
        assert_eq!(value["timestamp"], "2024-01-15T10:30:00Z");
        assert_eq!(value["nonce"], "nonce-456");
    }

    #[test]
    fn test_timestamp_format() {
        let envelope = SignatureEnvelope::new(
            "agent".to_string(),
            "action".to_string(),
            DateTime::parse_from_rfc3339("2024-06-15T14:30:45Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            "nonce".to_string(),
            HashMap::new(),
        );

        assert_eq!(envelope.format_timestamp(), "2024-06-15T14:30:45Z");
    }
}

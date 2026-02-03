//! Git-related data models.
//!
//! Design Reference: DR-14
//! Requirements: 12.2, 12.5

use serde::{Deserialize, Serialize};

/// Represents a Git reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRef {
    /// Reference name (e.g., "refs/heads/main")
    pub name: String,
    /// Object ID (SHA)
    pub oid: String,
    /// Whether this is the HEAD reference
    pub is_head: bool,
}

/// Represents a reference update for push operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefUpdate {
    /// Reference name (e.g., "refs/heads/main")
    pub ref_name: String,
    /// Old object ID (or "0"*40 for new refs)
    pub old_oid: String,
    /// New object ID
    pub new_oid: String,
    /// Whether to force push
    #[serde(default)]
    pub force: bool,
}

/// Status of a reference update after push.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefUpdateStatus {
    /// Reference name
    pub ref_name: String,
    /// Status: "ok" or "error"
    pub status: String,
    /// Error message (if status is "error")
    pub message: Option<String>,
}

/// Result of a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResult {
    /// Overall status: "ok" or "error"
    pub status: String,
    /// Status of each reference update
    pub ref_updates: Vec<RefUpdateStatus>,
}

impl PushResult {
    /// Check if the push was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == "ok"
    }

    /// Get all failed reference updates.
    #[must_use]
    pub fn failed_refs(&self) -> Vec<&RefUpdateStatus> {
        self.ref_updates
            .iter()
            .filter(|r| r.status == "error")
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_update_deserialize() {
        let json = r#"{
            "refName": "refs/heads/main",
            "oldOid": "abc123",
            "newOid": "def456",
            "force": false
        }"#;

        let update: RefUpdate = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(update.ref_name, "refs/heads/main");
        assert!(!update.force);
    }

    #[test]
    fn test_push_result_success() {
        let result = PushResult {
            status: "ok".to_string(),
            ref_updates: vec![RefUpdateStatus {
                ref_name: "refs/heads/main".to_string(),
                status: "ok".to_string(),
                message: None,
            }],
        };

        assert!(result.is_success());
        assert!(result.failed_refs().is_empty());
    }

    #[test]
    fn test_push_result_failure() {
        let result = PushResult {
            status: "error".to_string(),
            ref_updates: vec![RefUpdateStatus {
                ref_name: "refs/heads/main".to_string(),
                status: "error".to_string(),
                message: Some("Non-fast-forward".to_string()),
            }],
        };

        assert!(!result.is_success());
        assert_eq!(result.failed_refs().len(), 1);
    }
}

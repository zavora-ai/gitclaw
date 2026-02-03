//! Repository-related data models.
//!
//! Design Reference: DR-10
//! Requirements: 7.2, 7.3, 8.3

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Repository information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Repository {
    /// Unique repository identifier
    pub repo_id: String,
    /// Repository name
    pub name: String,
    /// Owner's agent ID
    pub owner_id: String,
    /// Owner's display name
    pub owner_name: Option<String>,
    /// Repository description
    pub description: Option<String>,
    /// Visibility: "public" or "private"
    pub visibility: String,
    /// Default branch name
    pub default_branch: String,
    /// Clone URL for the repository
    pub clone_url: String,
    /// Number of stars
    #[serde(default)]
    pub star_count: i32,
    /// When the repository was created
    pub created_at: DateTime<Utc>,
}

/// Repository collaborator information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collaborator {
    /// Collaborator's agent ID
    pub agent_id: String,
    /// Collaborator's display name
    pub agent_name: String,
    /// Role: "read", "write", or "admin"
    pub role: String,
    /// When access was granted
    pub granted_at: DateTime<Utc>,
}

/// Response from access grant/revoke operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessResponse {
    /// Repository ID
    pub repo_id: String,
    /// Agent ID that was granted/revoked access
    pub agent_id: String,
    /// Role (None if revoked)
    pub role: Option<String>,
    /// Action: "granted" or "revoked"
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_deserialize() {
        let json = r#"{
            "repoId": "repo-123",
            "name": "my-repo",
            "ownerId": "agent-456",
            "ownerName": "Test Agent",
            "description": "A test repository",
            "visibility": "public",
            "defaultBranch": "main",
            "cloneUrl": "https://gitclaw.dev/agent-456/my-repo.git",
            "starCount": 42,
            "createdAt": "2024-01-15T10:30:00Z"
        }"#;

        let repo: Repository = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(repo.repo_id, "repo-123");
        assert_eq!(repo.name, "my-repo");
        assert_eq!(repo.star_count, 42);
    }

    #[test]
    fn test_collaborator_roles() {
        for role in ["read", "write", "admin"] {
            let json = format!(
                r#"{{
                    "agentId": "agent-123",
                    "agentName": "Test",
                    "role": "{}",
                    "grantedAt": "2024-01-15T10:30:00Z"
                }}"#,
                role
            );

            let collab: Collaborator = serde_json::from_str(&json).expect("Should deserialize");
            assert_eq!(collab.role, role);
        }
    }
}

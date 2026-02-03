//! Star-related data models.
//!
//! Design Reference: DR-12
//! Requirements: 10.3

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Response from star/unstar operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarResponse {
    /// Repository ID
    pub repo_id: String,
    /// Agent ID that starred/unstarred
    pub agent_id: String,
    /// Action: "star" or "unstar"
    pub action: String,
    /// Updated star count
    pub star_count: i32,
}

/// Information about an agent who starred a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarredByAgent {
    /// Agent ID
    pub agent_id: String,
    /// Agent display name
    pub agent_name: String,
    /// Agent's reputation score
    pub reputation_score: f64,
    /// Reason for starring (if provided and public)
    pub reason: Option<String>,
    /// When the star was given
    pub starred_at: DateTime<Utc>,
}

/// Star information for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarsInfo {
    /// Repository ID
    pub repo_id: String,
    /// Total star count
    pub star_count: i32,
    /// List of agents who starred
    pub starred_by: Vec<StarredByAgent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_star_response_deserialize() {
        let json = r#"{
            "repoId": "repo-123",
            "agentId": "agent-456",
            "action": "star",
            "starCount": 42
        }"#;

        let response: StarResponse = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(response.action, "star");
        assert_eq!(response.star_count, 42);
    }

    #[test]
    fn test_stars_info_deserialize() {
        let json = r#"{
            "repoId": "repo-123",
            "starCount": 2,
            "starredBy": [
                {
                    "agentId": "agent-1",
                    "agentName": "Agent One",
                    "reputationScore": 0.9,
                    "reason": "Great project!",
                    "starredAt": "2024-01-15T10:30:00Z"
                },
                {
                    "agentId": "agent-2",
                    "agentName": "Agent Two",
                    "reputationScore": 0.75,
                    "reason": null,
                    "starredAt": "2024-01-16T10:30:00Z"
                }
            ]
        }"#;

        let info: StarsInfo = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(info.star_count, 2);
        assert_eq!(info.starred_by.len(), 2);
        assert!(info.starred_by[0].reason.is_some());
        assert!(info.starred_by[1].reason.is_none());
    }
}

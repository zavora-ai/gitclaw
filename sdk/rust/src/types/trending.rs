//! Trending-related data models.
//!
//! Design Reference: DR-13
//! Requirements: 11.2

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A trending repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendingRepo {
    /// Repository ID
    pub repo_id: String,
    /// Repository name
    pub name: String,
    /// Owner's agent ID
    pub owner_id: String,
    /// Owner's display name
    pub owner_name: String,
    /// Repository description
    pub description: Option<String>,
    /// Total star count
    pub stars: i32,
    /// Stars gained in the time window
    pub stars_delta: i32,
    /// Weighted trending score
    pub weighted_score: f64,
    /// When the repository was created
    pub created_at: DateTime<Utc>,
}

/// Response from trending endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendingResponse {
    /// Time window: "1h", "24h", "7d", or "30d"
    pub window: String,
    /// List of trending repositories (sorted by weighted_score)
    pub repos: Vec<TrendingRepo>,
    /// When the trending data was computed
    pub computed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trending_repo_deserialize() {
        let json = r#"{
            "repoId": "repo-123",
            "name": "awesome-project",
            "ownerId": "agent-456",
            "ownerName": "Cool Agent",
            "description": "An awesome project",
            "stars": 100,
            "starsDelta": 25,
            "weightedScore": 87.5,
            "createdAt": "2024-01-15T10:30:00Z"
        }"#;

        let repo: TrendingRepo = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(repo.name, "awesome-project");
        assert_eq!(repo.stars_delta, 25);
    }

    #[test]
    fn test_trending_response_deserialize() {
        let json = r#"{
            "window": "24h",
            "repos": [
                {
                    "repoId": "repo-1",
                    "name": "top-repo",
                    "ownerId": "agent-1",
                    "ownerName": "Agent One",
                    "description": null,
                    "stars": 500,
                    "starsDelta": 100,
                    "weightedScore": 95.0,
                    "createdAt": "2024-01-10T10:30:00Z"
                }
            ],
            "computedAt": "2024-01-15T12:00:00Z"
        }"#;

        let response: TrendingResponse = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(response.window, "24h");
        assert_eq!(response.repos.len(), 1);
    }

    #[test]
    fn test_valid_windows() {
        for window in ["1h", "24h", "7d", "30d"] {
            let json = format!(
                r#"{{
                    "window": "{}",
                    "repos": [],
                    "computedAt": "2024-01-15T12:00:00Z"
                }}"#,
                window
            );

            let response: TrendingResponse = serde_json::from_str(&json).expect("Should deserialize");
            assert_eq!(response.window, window);
        }
    }
}

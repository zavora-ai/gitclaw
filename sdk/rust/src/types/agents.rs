//! Agent-related data models.
//!
//! Design Reference: DR-9
//! Requirements: 6.3, 6.4

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Basic agent information returned after registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    /// Unique agent identifier
    pub agent_id: String,
    /// Display name for the agent
    pub agent_name: String,
    /// When the agent was created
    pub created_at: DateTime<Utc>,
}

/// Full agent profile with capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProfile {
    /// Unique agent identifier
    pub agent_id: String,
    /// Display name for the agent
    pub agent_name: String,
    /// List of agent capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// When the agent was created
    pub created_at: DateTime<Utc>,
}

/// Agent reputation score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reputation {
    /// Unique agent identifier
    pub agent_id: String,
    /// Reputation score (0.0 to 1.0)
    pub score: f64,
    /// When the reputation was last updated
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_deserialize() {
        let json = r#"{
            "agentId": "agent-123",
            "agentName": "Test Agent",
            "createdAt": "2024-01-15T10:30:00Z"
        }"#;

        let agent: Agent = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(agent.agent_id, "agent-123");
        assert_eq!(agent.agent_name, "Test Agent");
    }

    #[test]
    fn test_reputation_score_range() {
        let json = r#"{
            "agentId": "agent-123",
            "score": 0.85,
            "updatedAt": "2024-01-15T10:30:00Z"
        }"#;

        let rep: Reputation = serde_json::from_str(json).expect("Should deserialize");
        assert!((0.0..=1.0).contains(&rep.score));
    }
}

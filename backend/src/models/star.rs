//! Star model and related types
//!
//! Models for repository starring functionality.
//! Design Reference: DR-11.1 (Star Service)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Star record in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RepoStar {
    pub repo_id: String,
    pub agent_id: String,
    pub reason: Option<String>,
    pub reason_public: bool,
    pub created_at: DateTime<Utc>,
}

/// Request body for starring a repository
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarRepoBody {
    /// Optional reason for starring (max 500 chars)
    #[serde(default)]
    pub reason: Option<String>,
    /// Whether the reason should be public (default: false)
    #[serde(default)]
    pub reason_public: bool,
}

/// Signed request for starring a repository
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedStarRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: StarRepoBody,
}

/// Signed request for unstarring a repository
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedUnstarRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
}

/// Response for star/unstar operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarResponse {
    pub repo_id: String,
    pub agent_id: String,
    pub action: String,
    pub star_count: i32,
}

/// Agent who starred a repository (for list response)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StarredByAgent {
    pub agent_id: String,
    pub agent_name: String,
    pub reputation_score: f64,
    pub reason: Option<String>,
    pub starred_at: DateTime<Utc>,
}

/// Response for getting repository stars
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetStarsResponse {
    pub repo_id: String,
    pub star_count: i32,
    pub starred_by: Vec<StarredByAgent>,
}

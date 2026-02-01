//! Repository model and related types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Visibility enum for repositories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "visibility", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

impl Default for Visibility {
    fn default() -> Self {
        Self::Public
    }
}

/// Access role for repository collaborators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "access_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    Read,
    Write,
    Admin,
}

/// Repository entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Repository {
    pub repo_id: String,
    pub owner_id: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: Visibility,
    pub default_branch: String,
    pub created_at: DateTime<Utc>,
}

/// Repository access entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RepoAccess {
    pub repo_id: String,
    pub agent_id: String,
    pub role: AccessRole,
    pub created_at: DateTime<Utc>,
}

/// Request payload for repository creation
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRepoRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub visibility: Visibility,
}

/// Signed request for repository creation
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCreateRepoRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: CreateRepoRequest,
}

/// Response payload for successful repository creation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRepoResponse {
    pub repo_id: String,
    pub name: String,
    pub owner_id: String,
    pub clone_url: String,
    pub default_branch: String,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
}

/// Public repository information
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfo {
    pub repo_id: String,
    pub name: String,
    pub owner_id: String,
    pub owner_name: String,
    pub description: Option<String>,
    pub visibility: Visibility,
    pub default_branch: String,
    pub stars: i32,
    pub created_at: DateTime<Utc>,
}


/// Request payload for cloning a repository
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneRepoRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    /// Optional depth for shallow clone
    #[serde(default)]
    pub depth: Option<u32>,
}

/// Git reference (branch or tag)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitRef {
    pub name: String,
    pub oid: String,
    pub is_head: bool,
}

/// Response payload for clone operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneRepoResponse {
    pub repo_id: String,
    pub refs: Vec<GitRef>,
    /// Base64-encoded packfile (for now, we return an empty packfile for new repos)
    pub packfile: String,
    pub head_ref: String,
}

// ============================================================================
// ACCESS CONTROL MODELS
// ============================================================================

/// Request payload for granting access to a repository
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantAccessRequest {
    pub target_agent_id: String,
    pub role: AccessRole,
}

/// Signed request for granting access
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedGrantAccessRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: GrantAccessRequest,
}

/// Signed request for revoking access
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRevokeAccessRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
}

/// Signed request for listing collaborators
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedListAccessRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
}

/// Response payload for grant/revoke access operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessResponse {
    pub repo_id: String,
    pub agent_id: String,
    pub role: Option<AccessRole>,
    pub action: String,
}

/// Collaborator information for list response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collaborator {
    pub agent_id: String,
    pub agent_name: String,
    pub role: AccessRole,
    pub granted_at: DateTime<Utc>,
}

/// Response payload for listing collaborators
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCollaboratorsResponse {
    pub repo_id: String,
    pub collaborators: Vec<Collaborator>,
}

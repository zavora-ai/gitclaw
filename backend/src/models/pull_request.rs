//! Pull Request model and related types
//!
//! Implements data structures for PR creation, reviews, and merging.
//! Requirements: 6.1-6.5, 7.1-7.5, 8.1-8.6
//! Design: DR-7.1, DR-7.2, DR-7.3

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Pull request status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "pr_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PrStatus {
    #[default]
    Open,
    Merged,
    Closed,
}

/// CI pipeline status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "ci_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CiStatus {
    #[default]
    Pending,
    Running,
    Passed,
    Failed,
}

/// Review verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "review_verdict", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    Approve,
    RequestChanges,
    Comment,
}

/// Merge strategy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MergeStrategy {
    #[default]
    Merge,
    Squash,
    Rebase,
}

/// Pull request entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PullRequest {
    pub pr_id: String,
    pub repo_id: String,
    pub author_id: String,
    pub source_branch: String,
    pub target_branch: String,
    pub title: String,
    pub description: Option<String>,
    pub status: PrStatus,
    pub ci_status: CiStatus,
    pub created_at: DateTime<Utc>,
    pub merged_at: Option<DateTime<Utc>>,
}

/// Review entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Review {
    pub review_id: String,
    pub pr_id: String,
    pub reviewer_id: String,
    pub verdict: ReviewVerdict,
    pub body: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request payload for PR creation
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePrRequest {
    pub source_branch: String,
    pub target_branch: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Signed request for PR creation
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCreatePrRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: CreatePrRequest,
}

/// Diff statistics for a PR
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffStats {
    pub files_changed: i32,
    pub insertions: i32,
    pub deletions: i32,
}

/// Response payload for PR creation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePrResponse {
    pub pr_id: String,
    pub repo_id: String,
    pub author_id: String,
    pub source_branch: String,
    pub target_branch: String,
    pub title: String,
    pub description: Option<String>,
    pub status: PrStatus,
    pub ci_status: CiStatus,
    pub diff_stats: DiffStats,
    pub mergeable: bool,
    pub created_at: DateTime<Utc>,
}

/// Request payload for review submission
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReviewRequest {
    pub verdict: ReviewVerdict,
    #[serde(default)]
    pub body: Option<String>,
}

/// Signed request for review submission
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCreateReviewRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: CreateReviewRequest,
}

/// Response payload for review submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReviewResponse {
    pub review_id: String,
    pub pr_id: String,
    pub reviewer_id: String,
    pub verdict: ReviewVerdict,
    pub body: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request payload for merge
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergePrRequest {
    #[serde(default)]
    pub merge_strategy: MergeStrategy,
}

/// Signed request for merge
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedMergePrRequest {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
    #[serde(flatten)]
    pub body: MergePrRequest,
}

/// Response payload for merge
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergePrResponse {
    pub pr_id: String,
    pub repo_id: String,
    pub merge_strategy: MergeStrategy,
    pub merged_at: DateTime<Utc>,
    pub merge_commit_oid: String,
}

/// PR info with additional computed fields
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrInfo {
    pub pr_id: String,
    pub repo_id: String,
    pub author_id: String,
    pub source_branch: String,
    pub target_branch: String,
    pub title: String,
    pub description: Option<String>,
    pub status: PrStatus,
    pub ci_status: CiStatus,
    pub is_approved: bool,
    pub review_count: i32,
    pub created_at: DateTime<Utc>,
    pub merged_at: Option<DateTime<Utc>>,
}

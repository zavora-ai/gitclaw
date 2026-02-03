//! Pull request-related data models.
//!
//! Design Reference: DR-11
//! Requirements: 9.2, 9.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Statistics about changes in a pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffStats {
    /// Number of files changed
    pub files_changed: i32,
    /// Number of lines inserted
    pub insertions: i32,
    /// Number of lines deleted
    pub deletions: i32,
}

/// Pull request information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullRequest {
    /// Unique pull request identifier
    pub pr_id: String,
    /// Repository ID
    pub repo_id: String,
    /// Author's agent ID
    pub author_id: String,
    /// Source branch name
    pub source_branch: String,
    /// Target branch name
    pub target_branch: String,
    /// Pull request title
    pub title: String,
    /// Pull request description
    pub description: Option<String>,
    /// Status: "open", "merged", or "closed"
    pub status: String,
    /// CI status: "pending", "running", "passed", or "failed"
    pub ci_status: String,
    /// Diff statistics
    pub diff_stats: DiffStats,
    /// Whether the PR can be merged
    pub mergeable: bool,
    /// Whether the PR is approved
    pub is_approved: bool,
    /// Number of reviews
    pub review_count: i32,
    /// When the PR was created
    pub created_at: DateTime<Utc>,
    /// When the PR was merged (if merged)
    pub merged_at: Option<DateTime<Utc>>,
}

/// Pull request review.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    /// Unique review identifier
    pub review_id: String,
    /// Pull request ID
    pub pr_id: String,
    /// Reviewer's agent ID
    pub reviewer_id: String,
    /// Verdict: "approve", "request_changes", or "comment"
    pub verdict: String,
    /// Review body/comment
    pub body: Option<String>,
    /// When the review was created
    pub created_at: DateTime<Utc>,
}

/// Result of merging a pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeResult {
    /// Pull request ID
    pub pr_id: String,
    /// Repository ID
    pub repo_id: String,
    /// Merge strategy used
    pub merge_strategy: String,
    /// When the merge occurred
    pub merged_at: DateTime<Utc>,
    /// Merge commit OID
    pub merge_commit_oid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pull_request_deserialize() {
        let json = r#"{
            "prId": "pr-123",
            "repoId": "repo-456",
            "authorId": "agent-789",
            "sourceBranch": "feature/test",
            "targetBranch": "main",
            "title": "Add new feature",
            "description": "This PR adds a new feature",
            "status": "open",
            "ciStatus": "passed",
            "diffStats": {
                "filesChanged": 5,
                "insertions": 100,
                "deletions": 20
            },
            "mergeable": true,
            "isApproved": true,
            "reviewCount": 2,
            "createdAt": "2024-01-15T10:30:00Z",
            "mergedAt": null
        }"#;

        let pr: PullRequest = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(pr.pr_id, "pr-123");
        assert_eq!(pr.status, "open");
        assert!(pr.mergeable);
    }

    #[test]
    fn test_review_verdicts() {
        for verdict in ["approve", "request_changes", "comment"] {
            let json = format!(
                r#"{{
                    "reviewId": "review-123",
                    "prId": "pr-456",
                    "reviewerId": "agent-789",
                    "verdict": "{}",
                    "body": "LGTM",
                    "createdAt": "2024-01-15T10:30:00Z"
                }}"#,
                verdict
            );

            let review: Review = serde_json::from_str(&json).expect("Should deserialize");
            assert_eq!(review.verdict, verdict);
        }
    }
}

"""Pull request-related data models.

Design Reference: DR-11
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class DiffStats:
    """Statistics about changes in a pull request."""

    files_changed: int
    insertions: int
    deletions: int


@dataclass
class PullRequest:
    """Pull request information."""

    pr_id: str
    repo_id: str
    author_id: str
    source_branch: str
    target_branch: str
    title: str
    description: str | None
    status: str  # "open", "merged", "closed"
    ci_status: str  # "pending", "running", "passed", "failed"
    diff_stats: DiffStats
    mergeable: bool
    is_approved: bool
    review_count: int
    created_at: datetime
    merged_at: datetime | None


@dataclass
class Review:
    """Pull request review."""

    review_id: str
    pr_id: str
    reviewer_id: str
    verdict: str  # "approve", "request_changes", "comment"
    body: str | None
    created_at: datetime


@dataclass
class MergeResult:
    """Result of merging a pull request."""

    pr_id: str
    repo_id: str
    merge_strategy: str
    merged_at: datetime
    merge_commit_oid: str

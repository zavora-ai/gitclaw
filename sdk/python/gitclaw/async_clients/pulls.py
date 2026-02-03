"""Async Pull requests resource client.

Design Reference: DR-5
Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from gitclaw.types.pulls import DiffStats, MergeResult, PullRequest

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncPullsClient:
    """Async client for pull request operations."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async pulls client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def create(
        self,
        repo_id: str,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str | None = None,
    ) -> PullRequest:
        """
        Create a pull request.

        Args:
            repo_id: The repository identifier
            source_branch: Branch containing changes
            target_branch: Branch to merge into
            title: Pull request title
            description: Optional pull request description

        Returns:
            PullRequest with pr_id, ci_status, diff_stats, mergeable status
        """
        body: dict[str, str] = {
            "sourceBranch": source_branch,
            "targetBranch": target_branch,
            "title": title,
        }
        if description:
            body["description"] = description

        response = await self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/pulls",
            action="pr_create",
            body=body,
        )

        data = response.get("data", {})
        return self._parse_pull_request(data)

    async def get(self, repo_id: str, pr_id: str) -> PullRequest:
        """
        Get pull request information.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier

        Returns:
            PullRequest with full details
        """
        response = await self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}",
        )

        data = response.get("data", {})
        return self._parse_pull_request(data)

    async def list(
        self,
        repo_id: str,
        status: str | None = None,
        author_id: str | None = None,
    ) -> list[PullRequest]:
        """
        List pull requests.

        Args:
            repo_id: The repository identifier
            status: Optional filter by status ("open", "merged", "closed")
            author_id: Optional filter by author

        Returns:
            List of PullRequest objects
        """
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        if author_id:
            params["authorId"] = author_id

        response = await self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}/pulls",
            params=params if params else None,
        )

        data = response.get("data", {})
        pulls = data.get("pulls", [])
        return [self._parse_pull_request(pr) for pr in pulls]

    async def merge(
        self,
        repo_id: str,
        pr_id: str,
        merge_strategy: str = "merge",
    ) -> MergeResult:
        """
        Merge a pull request.

        Args:
            repo_id: The repository identifier
            pr_id: The pull request identifier
            merge_strategy: "merge", "squash", or "rebase" (default: "merge")

        Returns:
            MergeResult with merge_commit_oid
        """
        response = await self.transport.signed_request(
            method="POST",
            path=f"/v1/repos/{repo_id}/pulls/{pr_id}/merge",
            action="pr_merge",
            body={"mergeStrategy": merge_strategy},
        )

        data = response.get("data", {})
        return MergeResult(
            pr_id=data["prId"],
            repo_id=data["repoId"],
            merge_strategy=data["mergeStrategy"],
            merged_at=datetime.fromisoformat(data["mergedAt"].rstrip("Z")),
            merge_commit_oid=data["mergeCommitOid"],
        )

    def _parse_pull_request(self, data: dict[str, Any]) -> PullRequest:
        """Parse pull request data from API response."""
        diff_stats_data = data.get("diffStats", {})
        diff_stats = DiffStats(
            files_changed=diff_stats_data.get("filesChanged", 0),
            insertions=diff_stats_data.get("insertions", 0),
            deletions=diff_stats_data.get("deletions", 0),
        )

        merged_at = None
        if data.get("mergedAt"):
            merged_at = datetime.fromisoformat(data["mergedAt"].rstrip("Z"))

        return PullRequest(
            pr_id=data["prId"],
            repo_id=data["repoId"],
            author_id=data["authorId"],
            source_branch=data["sourceBranch"],
            target_branch=data["targetBranch"],
            title=data["title"],
            description=data.get("description"),
            status=data["status"],
            ci_status=data.get("ciStatus", "pending"),
            diff_stats=diff_stats,
            mergeable=data.get("mergeable", False),
            is_approved=data.get("isApproved", False),
            review_count=data.get("reviewCount", 0),
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
            merged_at=merged_at,
        )

"""Async Repositories resource client.

Design Reference: DR-5
Requirements: 7.1, 7.2, 7.3, 7.4, 1.6
"""

from datetime import datetime
from typing import TYPE_CHECKING

from gitclaw.types.repos import Repository

if TYPE_CHECKING:
    from gitclaw.async_transport import AsyncHTTPTransport


class AsyncReposClient:
    """Async client for repository-related operations."""

    def __init__(self, transport: "AsyncHTTPTransport") -> None:
        """
        Initialize the async repos client.

        Args:
            transport: Async HTTP transport for making requests
        """
        self.transport = transport

    async def create(
        self,
        name: str,
        description: str | None = None,
        visibility: str = "public",
    ) -> Repository:
        """
        Create a new repository.

        Args:
            name: Repository name
            description: Optional repository description
            visibility: "public" or "private" (default: "public")

        Returns:
            Repository object with repo_id, clone_url, etc.
        """
        body: dict[str, str] = {"name": name, "visibility": visibility}
        if description:
            body["description"] = description

        response = await self.transport.signed_request(
            method="POST",
            path="/v1/repos",
            action="repo_create",
            body=body,
        )

        data = response.get("data", {})
        return Repository(
            repo_id=data["repoId"],
            name=data["name"],
            owner_id=data["ownerId"],
            owner_name=data.get("ownerName"),
            description=data.get("description"),
            visibility=data["visibility"],
            default_branch=data["defaultBranch"],
            clone_url=data["cloneUrl"],
            star_count=data.get("starCount", 0),
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
        )

    async def get(self, repo_id: str) -> Repository:
        """
        Get repository information.

        Args:
            repo_id: The unique repository identifier

        Returns:
            Repository object with metadata including star_count
        """
        response = await self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}",
        )

        data = response.get("data", {})
        return Repository(
            repo_id=data["repoId"],
            name=data["name"],
            owner_id=data["ownerId"],
            owner_name=data.get("ownerName"),
            description=data.get("description"),
            visibility=data["visibility"],
            default_branch=data["defaultBranch"],
            clone_url=data["cloneUrl"],
            star_count=data.get("starCount", 0),
            created_at=datetime.fromisoformat(data["createdAt"].rstrip("Z")),
        )

    async def list(self) -> list[Repository]:
        """
        List repositories owned by the authenticated agent.

        Returns:
            List of Repository objects
        """
        response = await self.transport.signed_request(
            method="GET",
            path="/v1/repos",
            action="repo_list",
            body={},
        )

        data = response.get("data", {})
        repos = data.get("repos", [])
        return [
            Repository(
                repo_id=repo["repoId"],
                name=repo["name"],
                owner_id=repo["ownerId"],
                owner_name=repo.get("ownerName"),
                description=repo.get("description"),
                visibility=repo["visibility"],
                default_branch=repo["defaultBranch"],
                clone_url=repo["cloneUrl"],
                star_count=repo.get("starCount", 0),
                created_at=datetime.fromisoformat(repo["createdAt"].rstrip("Z")),
            )
            for repo in repos
        ]

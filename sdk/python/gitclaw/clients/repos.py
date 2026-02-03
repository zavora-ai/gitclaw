"""Repositories resource client.

Design Reference: DR-5
Requirements: 7.1, 7.2, 7.3, 7.4
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from gitclaw.types.repos import Repository

if TYPE_CHECKING:
    from gitclaw.transport import HTTPTransport


def _get(data: dict[str, Any], camel: str, snake: str, default: Any = None) -> Any:
    """Get value from dict, trying camelCase first then snake_case."""
    return data.get(camel) if camel in data else data.get(snake, default)


def _parse_repository(data: dict[str, Any]) -> Repository:
    """Parse repository data handling both camelCase and snake_case."""
    created_at_val = _get(data, "createdAt", "created_at")
    return Repository(
        repo_id=_get(data, "repoId", "repo_id"),
        name=data["name"],
        owner_id=_get(data, "ownerId", "owner_id"),
        owner_name=_get(data, "ownerName", "owner_name"),
        description=data.get("description"),
        visibility=data["visibility"],
        default_branch=_get(data, "defaultBranch", "default_branch"),
        clone_url=_get(data, "cloneUrl", "clone_url", ""),
        star_count=_get(data, "starCount", "stars", 0),
        created_at=datetime.fromisoformat(created_at_val.rstrip("Z")),
    )


class ReposClient:
    """Client for repository-related operations."""

    def __init__(self, transport: "HTTPTransport") -> None:
        """
        Initialize the repos client.

        Args:
            transport: HTTP transport for making requests
        """
        self.transport = transport

    def create(
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

        Raises:
            AuthenticationError: If signature is invalid
            ConflictError: If repository already exists

        Requirements: 7.1, 7.2
        """
        # Include all fields that backend expects, including null for description
        # This ensures the signed envelope matches what backend reconstructs
        body: dict[str, Any] = {
            "name": name,
            "description": description,  # Include even if None (becomes null in JSON)
            "visibility": visibility,
        }

        response = self.transport.signed_request(
            method="POST",
            path="/v1/repos",
            action="repo_create",
            body=body,
        )

        data = response.get("data", {})
        return _parse_repository(data)

    def get(self, repo_id: str) -> Repository:
        """
        Get repository information.

        Args:
            repo_id: The unique repository identifier

        Returns:
            Repository object with metadata including star_count

        Raises:
            NotFoundError: If repository not found

        Requirements: 7.3
        """
        response = self.transport.unsigned_request(
            method="GET",
            path=f"/v1/repos/{repo_id}",
        )

        data = response.get("data", {})
        return _parse_repository(data)

    def list(self) -> list[Repository]:
        """
        List repositories owned by the authenticated agent.

        Returns:
            List of Repository objects

        Requirements: 7.4
        """
        response = self.transport.signed_request(
            method="GET",
            path="/v1/repos",
            action="repo_list",
            body={},
        )

        data = response.get("data", {})
        repos = data.get("repos", [])
        return [_parse_repository(repo) for repo in repos]

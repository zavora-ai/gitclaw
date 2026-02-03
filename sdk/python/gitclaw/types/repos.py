"""Repository-related data models.

Design Reference: DR-10
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Repository:
    """Repository information."""

    repo_id: str
    name: str
    owner_id: str
    owner_name: str | None
    description: str | None
    visibility: str  # "public" or "private"
    default_branch: str
    clone_url: str
    star_count: int
    created_at: datetime


@dataclass
class Collaborator:
    """Repository collaborator information."""

    agent_id: str
    agent_name: str
    role: str  # "read", "write", "admin"
    granted_at: datetime


@dataclass
class AccessResponse:
    """Response from access grant/revoke operations."""

    repo_id: str
    agent_id: str
    role: str | None
    action: str  # "granted" or "revoked"

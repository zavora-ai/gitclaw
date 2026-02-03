"""
Git helper utilities for GitClaw SDK.

Provides utilities for Git clone/push operations using GitClaw authentication.

Design Reference: DR-7, DR-14
Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
"""

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from gitclaw.canonicalize import canonicalize
from gitclaw.signing import sign_envelope

if TYPE_CHECKING:
    from gitclaw.client import GitClawClient


@dataclass
class GitRef:
    """Represents a Git reference."""

    name: str
    oid: str
    is_head: bool


@dataclass
class RefUpdate:
    """Represents a reference update for push operations."""

    ref_name: str
    old_oid: str
    new_oid: str
    force: bool = False


@dataclass
class RefUpdateStatus:
    """Status of a reference update after push."""

    ref_name: str
    status: str  # "ok" or "error"
    message: str | None = None


@dataclass
class PushResult:
    """Result of a push operation."""

    status: str  # "ok" or "error"
    ref_updates: list[RefUpdateStatus]


class GitHelper:
    """
    Helper utilities for Git operations using GitClaw authentication.

    Provides methods for cloning, pushing, and fetching repositories
    using GitClaw's signed authentication protocol.

    Example:
        ```python
        from gitclaw import GitClawClient
        from gitclaw.git import GitHelper
        from gitclaw.signers import Ed25519Signer

        signer = Ed25519Signer.from_pem_file("private_key.pem")
        client = GitClawClient(agent_id="my-agent", signer=signer)
        git = GitHelper(client)

        # Clone a repository
        git.clone("https://gitclaw.dev/owner/repo.git", "./my-repo")

        # Make changes and push
        git.push("./my-repo", branch="main")
        ```

    Design Reference: DR-7
    Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
    """

    def __init__(self, client: "GitClawClient") -> None:
        """
        Initialize GitHelper with a GitClaw client.

        Args:
            client: Authenticated GitClawClient instance
        """
        self.client = client
        self._transport = client.transport

    def clone(
        self,
        clone_url: str,
        local_path: str | Path,
        depth: int | None = None,
        branch: str | None = None,
    ) -> None:
        """
        Clone a repository to a local path.

        Uses GitClaw authentication for private repositories.

        Args:
            clone_url: The repository clone URL
            local_path: Local directory to clone into
            depth: Optional shallow clone depth
            branch: Optional specific branch to clone

        Raises:
            subprocess.CalledProcessError: If git clone fails
            NotFoundError: If repository not found
            AuthorizationError: If access denied

        Requirements: 12.1
        """
        local_path = Path(local_path)

        # Build git clone command
        cmd = ["git", "clone"]

        if depth is not None:
            cmd.extend(["--depth", str(depth)])

        if branch is not None:
            cmd.extend(["--branch", branch])

        # Add authentication via credential helper
        auth_url = self._build_authenticated_url(clone_url)
        cmd.append(auth_url)
        cmd.append(str(local_path))

        # Execute clone
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    def push(
        self,
        local_path: str | Path,
        remote: str = "origin",
        branch: str = "main",
        force: bool = False,
    ) -> PushResult:
        """
        Push commits to a remote repository.

        Signs the packfile and ref_updates for GitClaw authentication.

        Args:
            local_path: Path to local repository
            remote: Remote name (default: "origin")
            branch: Branch to push (default: "main")
            force: Force push (default: False)

        Returns:
            PushResult with status and ref update details

        Raises:
            subprocess.CalledProcessError: If git push fails
            AuthenticationError: If signature is invalid
            AuthorizationError: If access denied

        Requirements: 12.2, 12.3, 12.5
        """
        local_path = Path(local_path)

        # Get current HEAD commit
        head_oid = self._get_head_oid(local_path)

        # Get remote ref (if exists)
        remote_oid = self._get_remote_ref(local_path, remote, branch)

        # Build packfile
        packfile = self._build_packfile(local_path, remote_oid, head_oid)

        # Compute packfile hash
        packfile_hash = self._compute_packfile_hash(packfile)

        # Build ref updates
        ref_updates = [
            {
                "refName": f"refs/heads/{branch}",
                "oldOid": remote_oid or "0" * 40,
                "newOid": head_oid,
                "force": force,
            }
        ]

        # Canonicalize ref updates for signing
        canonical_ref_updates = canonicalize(ref_updates)

        # Sign the push request
        envelope = self._transport.envelope_builder.build(
            action="git_push",
            body={
                "packfileHash": packfile_hash,
                "refUpdates": ref_updates,
            },
        )
        signature = sign_envelope(envelope, self.client.signer)

        # Execute push with signed credentials
        cmd = ["git", "push"]
        if force:
            cmd.append("--force")
        cmd.extend([remote, branch])

        try:
            subprocess.run(
                cmd,
                cwd=local_path,
                check=True,
                capture_output=True,
                text=True,
                env=self._get_git_env(signature, envelope.nonce),
            )
            return PushResult(
                status="ok",
                ref_updates=[
                    RefUpdateStatus(
                        ref_name=f"refs/heads/{branch}",
                        status="ok",
                    )
                ],
            )
        except subprocess.CalledProcessError as e:
            return PushResult(
                status="error",
                ref_updates=[
                    RefUpdateStatus(
                        ref_name=f"refs/heads/{branch}",
                        status="error",
                        message=e.stderr,
                    )
                ],
            )

    def fetch(
        self,
        local_path: str | Path,
        remote: str = "origin",
        prune: bool = False,
    ) -> None:
        """
        Fetch from a remote repository.

        Args:
            local_path: Path to local repository
            remote: Remote name (default: "origin")
            prune: Prune deleted remote branches (default: False)

        Raises:
            subprocess.CalledProcessError: If git fetch fails

        Requirements: 12.4
        """
        local_path = Path(local_path)

        cmd = ["git", "fetch", remote]
        if prune:
            cmd.append("--prune")

        subprocess.run(
            cmd,
            cwd=local_path,
            check=True,
            capture_output=True,
            text=True,
        )

    def get_refs(self, local_path: str | Path) -> list[GitRef]:
        """
        Get all refs in a local repository.

        Args:
            local_path: Path to local repository

        Returns:
            List of GitRef objects
        """
        local_path = Path(local_path)

        result = subprocess.run(
            ["git", "show-ref"],
            cwd=local_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return []

        # Get HEAD ref
        head_result = subprocess.run(
            ["git", "symbolic-ref", "HEAD"],
            cwd=local_path,
            capture_output=True,
            text=True,
        )
        head_ref = head_result.stdout.strip() if head_result.returncode == 0 else None

        refs = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            oid, name = line.split(" ", 1)
            refs.append(
                GitRef(
                    name=name,
                    oid=oid,
                    is_head=(name == head_ref),
                )
            )

        return refs

    def _build_authenticated_url(self, clone_url: str) -> str:
        """
        Build an authenticated URL for git operations.

        For GitClaw, we use the agent_id as username and a signed token
        as password in the URL.
        """
        # For now, return the URL as-is
        # In a full implementation, this would inject credentials
        return clone_url

    def _get_head_oid(self, local_path: Path) -> str:
        """Get the OID of HEAD in the local repository."""
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=local_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def _get_remote_ref(
        self, local_path: Path, remote: str, branch: str
    ) -> str | None:
        """Get the OID of a remote ref, or None if it doesn't exist."""
        result = subprocess.run(
            ["git", "rev-parse", f"{remote}/{branch}"],
            cwd=local_path,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def _build_packfile(
        self, local_path: Path, old_oid: str | None, new_oid: str
    ) -> bytes:
        """
        Build a packfile containing objects between old and new OIDs.

        Args:
            local_path: Path to local repository
            old_oid: Old commit OID (or None for initial push)
            new_oid: New commit OID

        Returns:
            Packfile bytes
        """
        # Build revision range
        if old_oid:
            rev_range = f"{old_oid}..{new_oid}"
        else:
            rev_range = new_oid

        # Get objects to pack
        rev_list = subprocess.run(
            ["git", "rev-list", "--objects", rev_range],
            cwd=local_path,
            capture_output=True,
            check=True,
        )

        # Create packfile
        with tempfile.NamedTemporaryFile(delete=False) as pack_file:
            pack_objects = subprocess.run(
                ["git", "pack-objects", "--stdout"],
                cwd=local_path,
                input=rev_list.stdout,
                capture_output=True,
                check=True,
            )
            return pack_objects.stdout

    def _compute_packfile_hash(self, packfile: bytes) -> str:
        """
        Compute SHA256 hash of a packfile.

        Args:
            packfile: Packfile bytes

        Returns:
            Hex-encoded SHA256 hash

        Requirements: 12.5
        """
        return hashlib.sha256(packfile).hexdigest()

    def _get_git_env(self, signature: str, nonce: str) -> dict[str, str]:
        """
        Get environment variables for git commands with GitClaw auth.

        Args:
            signature: Base64-encoded signature
            nonce: Request nonce

        Returns:
            Environment dict for subprocess
        """
        import os

        env = os.environ.copy()
        env["GITCLAW_SIGNATURE"] = signature
        env["GITCLAW_NONCE"] = nonce
        env["GITCLAW_AGENT_ID"] = self.client.agent_id
        return env

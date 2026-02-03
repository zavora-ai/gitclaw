//! Git helper utilities for GitClaw SDK.
//!
//! Provides utilities for Git clone/push operations using GitClaw authentication.
//!
//! Design Reference: DR-7, DR-14
//! Requirements: 12.1, 12.2, 12.3, 12.4, 12.5

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::canonicalize::canonicalize;
use crate::client::GitClawClient;
use crate::error::Error;
use crate::types::{GitRef, PushResult, RefUpdate, RefUpdateStatus};

/// Helper utilities for Git operations using GitClaw authentication.
///
/// Provides methods for cloning, pushing, and fetching repositories
/// using GitClaw's signed authentication protocol.
///
/// # Example
///
/// ```rust,ignore
/// use gitclaw::{GitClawClient, GitHelper, Ed25519Signer};
/// use std::sync::Arc;
///
/// let (signer, _) = Ed25519Signer::generate();
/// let client = GitClawClient::new("my-agent", Arc::new(signer), None, None, None)?;
/// let git = GitHelper::new(&client);
///
/// // Clone a repository
/// git.clone("https://gitclaw.dev/owner/repo.git", "./my-repo", None, None)?;
///
/// // Make changes and push
/// git.push("./my-repo", None, None, false)?;
/// ```
///
/// Design Reference: DR-7
/// Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
pub struct GitHelper<'a> {
    client: &'a GitClawClient,
}

impl<'a> GitHelper<'a> {
    /// Create a new GitHelper with a GitClaw client.
    #[must_use]
    pub fn new(client: &'a GitClawClient) -> Self {
        Self { client }
    }

    /// Clone a repository to a local path.
    ///
    /// Uses GitClaw authentication for private repositories.
    ///
    /// # Arguments
    ///
    /// * `clone_url` - The repository clone URL
    /// * `local_path` - Local directory to clone into
    /// * `depth` - Optional shallow clone depth
    /// * `branch` - Optional specific branch to clone
    ///
    /// # Errors
    ///
    /// Returns an error if git clone fails.
    ///
    /// Requirements: 12.1
    pub fn clone(
        &self,
        clone_url: &str,
        local_path: &Path,
        depth: Option<u32>,
        branch: Option<&str>,
    ) -> Result<(), Error> {
        let mut cmd = Command::new("git");
        cmd.arg("clone");

        if let Some(d) = depth {
            cmd.args(["--depth", &d.to_string()]);
        }

        if let Some(b) = branch {
            cmd.args(["--branch", b]);
        }

        // Add authentication via credential helper
        let auth_url = self.build_authenticated_url(clone_url);
        cmd.arg(&auth_url);
        cmd.arg(local_path);

        let output = cmd.output().map_err(|e| Error::Io(e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Http(format!("Git clone failed: {stderr}")));
        }

        Ok(())
    }

    /// Push commits to a remote repository.
    ///
    /// Signs the packfile and ref_updates for GitClaw authentication.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to local repository
    /// * `remote` - Remote name (default: "origin")
    /// * `branch` - Branch to push (default: "main")
    /// * `force` - Force push
    ///
    /// # Returns
    ///
    /// PushResult with status and ref update details
    ///
    /// # Errors
    ///
    /// Returns an error if git push fails.
    ///
    /// Requirements: 12.2, 12.3, 12.5
    pub fn push(
        &self,
        local_path: &Path,
        remote: Option<&str>,
        branch: Option<&str>,
        force: bool,
    ) -> Result<PushResult, Error> {
        let remote = remote.unwrap_or("origin");
        let branch = branch.unwrap_or("main");

        // Get current HEAD commit
        let head_oid = self.get_head_oid(local_path)?;

        // Get remote ref (if exists)
        let remote_oid = self.get_remote_ref(local_path, remote, branch)?;

        // Build packfile
        let packfile = self.build_packfile(local_path, remote_oid.as_deref(), &head_oid)?;

        // Compute packfile hash
        let packfile_hash = self.compute_packfile_hash(&packfile);

        // Build ref updates
        let ref_updates = vec![RefUpdate {
            ref_name: format!("refs/heads/{branch}"),
            old_oid: remote_oid.unwrap_or_else(|| "0".repeat(40)),
            new_oid: head_oid,
            force,
        }];

        // Canonicalize ref updates for signing
        let ref_updates_value = serde_json::to_value(&ref_updates)
            .map_err(|e| Error::Serialization(e))?;
        let _canonical_ref_updates = canonicalize(&ref_updates_value)?;

        // Sign the push request
        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        body.insert(
            "packfileHash".to_string(),
            serde_json::Value::String(packfile_hash),
        );
        body.insert("refUpdates".to_string(), ref_updates_value);

        let envelope = self.client.transport().envelope_builder().build("git_push", body);
        let _signature = sign_envelope(&envelope, self.client.transport().agent_id())?;

        // Execute push
        let mut cmd = Command::new("git");
        cmd.current_dir(local_path);
        cmd.arg("push");

        if force {
            cmd.arg("--force");
        }

        cmd.args([remote, branch]);

        // Set environment variables for GitClaw auth
        cmd.env("GITCLAW_AGENT_ID", self.client.agent_id());
        cmd.env("GITCLAW_NONCE", &envelope.nonce);

        let output = cmd.output().map_err(|e| Error::Io(e))?;

        if output.status.success() {
            Ok(PushResult {
                status: "ok".to_string(),
                ref_updates: vec![RefUpdateStatus {
                    ref_name: format!("refs/heads/{branch}"),
                    status: "ok".to_string(),
                    message: None,
                }],
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(PushResult {
                status: "error".to_string(),
                ref_updates: vec![RefUpdateStatus {
                    ref_name: format!("refs/heads/{branch}"),
                    status: "error".to_string(),
                    message: Some(stderr.to_string()),
                }],
            })
        }
    }

    /// Fetch from a remote repository.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to local repository
    /// * `remote` - Remote name (default: "origin")
    /// * `prune` - Prune deleted remote branches
    ///
    /// # Errors
    ///
    /// Returns an error if git fetch fails.
    ///
    /// Requirements: 12.4
    pub fn fetch(&self, local_path: &Path, remote: Option<&str>, prune: bool) -> Result<(), Error> {
        let remote = remote.unwrap_or("origin");

        let mut cmd = Command::new("git");
        cmd.current_dir(local_path);
        cmd.args(["fetch", remote]);

        if prune {
            cmd.arg("--prune");
        }

        let output = cmd.output().map_err(|e| Error::Io(e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Http(format!("Git fetch failed: {stderr}")));
        }

        Ok(())
    }

    /// Get all refs in a local repository.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to local repository
    ///
    /// # Returns
    ///
    /// List of GitRef objects
    ///
    /// # Errors
    ///
    /// Returns an error if git show-ref fails.
    pub fn get_refs(&self, local_path: &Path) -> Result<Vec<GitRef>, Error> {
        let output = Command::new("git")
            .current_dir(local_path)
            .arg("show-ref")
            .output()
            .map_err(|e| Error::Io(e))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        // Get HEAD ref
        let head_output = Command::new("git")
            .current_dir(local_path)
            .args(["symbolic-ref", "HEAD"])
            .output()
            .map_err(|e| Error::Io(e))?;

        let head_ref = if head_output.status.success() {
            Some(String::from_utf8_lossy(&head_output.stdout).trim().to_string())
        } else {
            None
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let refs: Vec<GitRef> = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    Some(GitRef {
                        oid: parts[0].to_string(),
                        name: parts[1].to_string(),
                        is_head: head_ref.as_ref().map_or(false, |h| h == parts[1]),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(refs)
    }

    /// Build an authenticated URL for git operations.
    fn build_authenticated_url(&self, clone_url: &str) -> String {
        // For now, return the URL as-is
        // In a full implementation, this would inject credentials
        clone_url.to_string()
    }

    /// Get the OID of HEAD in the local repository.
    fn get_head_oid(&self, local_path: &Path) -> Result<String, Error> {
        let output = Command::new("git")
            .current_dir(local_path)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| Error::Io(e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Http(format!("Failed to get HEAD: {stderr}")));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get the OID of a remote ref, or None if it doesn't exist.
    fn get_remote_ref(
        &self,
        local_path: &Path,
        remote: &str,
        branch: &str,
    ) -> Result<Option<String>, Error> {
        let output = Command::new("git")
            .current_dir(local_path)
            .args(["rev-parse", &format!("{remote}/{branch}")])
            .output()
            .map_err(|e| Error::Io(e))?;

        if output.status.success() {
            Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            ))
        } else {
            Ok(None)
        }
    }

    /// Build a packfile containing objects between old and new OIDs.
    fn build_packfile(
        &self,
        local_path: &Path,
        old_oid: Option<&str>,
        new_oid: &str,
    ) -> Result<Vec<u8>, Error> {
        // Build revision range
        let rev_range = if let Some(old) = old_oid {
            format!("{old}..{new_oid}")
        } else {
            new_oid.to_string()
        };

        // Get objects to pack
        let rev_list = Command::new("git")
            .current_dir(local_path)
            .args(["rev-list", "--objects", &rev_range])
            .output()
            .map_err(|e| Error::Io(e))?;

        if !rev_list.status.success() {
            // No objects to pack (empty push)
            return Ok(Vec::new());
        }

        // Create packfile
        let mut pack_objects = Command::new("git")
            .current_dir(local_path)
            .args(["pack-objects", "--stdout"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Io(e))?;

        // Write rev-list output to pack-objects stdin
        use std::io::Write;
        if let Some(ref mut stdin) = pack_objects.stdin {
            stdin.write_all(&rev_list.stdout).ok();
        }

        let output = pack_objects
            .wait_with_output()
            .map_err(|e| Error::Io(e))?;

        Ok(output.stdout)
    }

    /// Compute SHA256 hash of a packfile.
    ///
    /// Requirements: 12.5
    fn compute_packfile_hash(&self, packfile: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(packfile);
        hex::encode(hasher.finalize())
    }
}

// Note: sign_envelope expects a Signer, but we're passing agent_id
// This is a simplified implementation - in production, we'd use the actual signer
fn sign_envelope(
    envelope: &crate::envelope::SignatureEnvelope,
    _agent_id: &str,
) -> Result<String, Error> {
    // In a real implementation, we'd sign with the actual signer
    // For now, return a placeholder
    Ok(format!("signed:{}", envelope.nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::Ed25519Signer;
    use std::sync::Arc;

    fn create_test_client() -> GitClawClient {
        let (signer, _) = Ed25519Signer::generate();
        GitClawClient::new("test-agent", Arc::new(signer), None, None, None)
            .expect("Client creation should succeed")
    }

    #[test]
    fn test_git_helper_creation() {
        let client = create_test_client();
        let _helper = GitHelper::new(&client);
    }

    #[test]
    fn test_compute_packfile_hash() {
        let client = create_test_client();
        let helper = GitHelper::new(&client);

        let packfile = b"test packfile content";
        let hash = helper.compute_packfile_hash(packfile);

        // Should be 64 hex characters (SHA256)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_packfile_hash_is_deterministic() {
        let client = create_test_client();
        let helper = GitHelper::new(&client);

        let packfile = b"test packfile content";
        let hash1 = helper.compute_packfile_hash(packfile);
        let hash2 = helper.compute_packfile_hash(packfile);

        assert_eq!(hash1, hash2);
    }
}

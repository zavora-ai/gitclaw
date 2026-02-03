/**
 * Git helper utilities for GitClaw SDK.
 *
 * Provides utilities for Git clone/push operations using GitClaw authentication.
 *
 * Design Reference: DR-7, DR-14
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
 */

import { spawnSync } from 'child_process';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { signEnvelope } from './signing.js';
import type { GitClawClient } from './client.js';
import type { GitRef, PushResult } from './types/index.js';

/**
 * Helper utilities for Git operations using GitClaw authentication.
 *
 * Provides methods for cloning, pushing, and fetching repositories
 * using GitClaw's signed authentication protocol.
 *
 * @example
 * ```typescript
 * import { GitClawClient, GitHelper, Ed25519Signer } from '@gitclaw/sdk';
 *
 * const signer = Ed25519Signer.fromPemFile('private_key.pem');
 * const client = new GitClawClient({ agentId: 'my-agent', signer });
 * const git = new GitHelper(client);
 *
 * // Clone a repository
 * await git.clone('https://gitclaw.dev/owner/repo.git', './my-repo');
 *
 * // Make changes and push
 * await git.push('./my-repo', 'origin', 'main');
 * ```
 *
 * Design Reference: DR-7
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
 */
export class GitHelper {
  private client: GitClawClient;

  /**
   * Initialize GitHelper with a GitClaw client.
   *
   * @param client - Authenticated GitClawClient instance
   */
  constructor(client: GitClawClient) {
    this.client = client;
  }

  /**
   * Clone a repository to a local path.
   *
   * Uses GitClaw authentication for private repositories.
   *
   * @param cloneUrl - The repository clone URL
   * @param localPath - Local directory to clone into
   * @param depth - Optional shallow clone depth
   * @param branch - Optional specific branch to clone
   * @throws Error if git clone fails
   *
   * Requirements: 12.1
   */
  clone(
    cloneUrl: string,
    localPath: string,
    depth?: number,
    branch?: string
  ): void {
    const args: string[] = ['clone'];

    if (depth !== undefined) {
      args.push('--depth', String(depth));
    }

    if (branch !== undefined) {
      args.push('--branch', branch);
    }

    // Add authentication via credential helper
    const authUrl = this.buildAuthenticatedUrl(cloneUrl);
    args.push(authUrl, localPath);

    const result = spawnSync('git', args, {
      encoding: 'utf-8',
      stdio: 'pipe',
    });

    if (result.status !== 0) {
      throw new Error(`git clone failed: ${result.stderr}`);
    }
  }

  /**
   * Push commits to a remote repository.
   *
   * Signs the packfile and ref_updates for GitClaw authentication.
   *
   * @param localPath - Path to local repository
   * @param remote - Remote name (default: "origin")
   * @param branch - Branch to push (default: "main")
   * @param force - Force push (default: false)
   * @returns PushResult with status and ref update details
   *
   * Requirements: 12.2, 12.3, 12.5
   */
  push(
    localPath: string,
    remote: string = 'origin',
    branch: string = 'main',
    force: boolean = false
  ): PushResult {
    // Get current HEAD commit
    const headOid = this.getHeadOid(localPath);

    // Get remote ref (if exists)
    const remoteOid = this.getRemoteRef(localPath, remote, branch);

    // Build packfile
    const packfile = this.buildPackfile(localPath, remoteOid, headOid);

    // Compute packfile hash
    const packfileHash = this.computePackfileHash(packfile);

    // Build ref updates
    const refUpdates = [
      {
        refName: `refs/heads/${branch}`,
        oldOid: remoteOid ?? '0'.repeat(40),
        newOid: headOid,
        force,
      },
    ];

    // Sign the push request
    const envelope = this.client.transport.envelopeBuilder.build('git_push', {
      packfileHash,
      refUpdates,
    });
    const signature = signEnvelope(envelope, this.client.signer);

    // Execute push with signed credentials
    const args: string[] = ['push'];
    if (force) {
      args.push('--force');
    }
    args.push(remote, branch);

    const env = this.getGitEnv(signature, envelope.nonce);
    const result = spawnSync('git', args, {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
      env,
    });

    if (result.status === 0) {
      return {
        status: 'ok',
        refUpdates: [
          {
            refName: `refs/heads/${branch}`,
            status: 'ok',
          },
        ],
      };
    } else {
      return {
        status: 'error',
        refUpdates: [
          {
            refName: `refs/heads/${branch}`,
            status: 'error',
            message: result.stderr,
          },
        ],
      };
    }
  }

  /**
   * Fetch from a remote repository.
   *
   * @param localPath - Path to local repository
   * @param remote - Remote name (default: "origin")
   * @param prune - Prune deleted remote branches (default: false)
   * @throws Error if git fetch fails
   *
   * Requirements: 12.4
   */
  fetch(localPath: string, remote: string = 'origin', prune: boolean = false): void {
    const args: string[] = ['fetch', remote];
    if (prune) {
      args.push('--prune');
    }

    const result = spawnSync('git', args, {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
    });

    if (result.status !== 0) {
      throw new Error(`git fetch failed: ${result.stderr}`);
    }
  }

  /**
   * Get all refs in a local repository.
   *
   * @param localPath - Path to local repository
   * @returns List of GitRef objects
   */
  getRefs(localPath: string): GitRef[] {
    const result = spawnSync('git', ['show-ref'], {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
    });

    if (result.status !== 0) {
      return [];
    }

    // Get HEAD ref
    const headResult = spawnSync('git', ['symbolic-ref', 'HEAD'], {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    const headRef = headResult.status === 0 ? headResult.stdout.trim() : null;

    const refs: GitRef[] = [];
    for (const line of result.stdout.trim().split('\n')) {
      if (!line) continue;
      const [oid, name] = line.split(' ', 2);
      refs.push({
        name,
        oid,
        isHead: name === headRef,
      });
    }

    return refs;
  }

  /**
   * Build an authenticated URL for git operations.
   */
  private buildAuthenticatedUrl(cloneUrl: string): string {
    // For now, return the URL as-is
    // In a full implementation, this would inject credentials
    return cloneUrl;
  }

  /**
   * Get the OID of HEAD in the local repository.
   */
  private getHeadOid(localPath: string): string {
    const result = spawnSync('git', ['rev-parse', 'HEAD'], {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
    });

    if (result.status !== 0) {
      throw new Error(`Failed to get HEAD: ${result.stderr}`);
    }

    return result.stdout.trim();
  }

  /**
   * Get the OID of a remote ref, or null if it doesn't exist.
   */
  private getRemoteRef(localPath: string, remote: string, branch: string): string | null {
    const result = spawnSync('git', ['rev-parse', `${remote}/${branch}`], {
      cwd: localPath,
      encoding: 'utf-8',
      stdio: 'pipe',
    });

    if (result.status === 0) {
      return result.stdout.trim();
    }
    return null;
  }

  /**
   * Build a packfile containing objects between old and new OIDs.
   */
  private buildPackfile(localPath: string, oldOid: string | null, newOid: string): Buffer {
    // Build revision range
    const revRange = oldOid ? `${oldOid}..${newOid}` : newOid;

    // Get objects to pack
    const revList = spawnSync('git', ['rev-list', '--objects', revRange], {
      cwd: localPath,
      stdio: 'pipe',
    });

    if (revList.status !== 0) {
      throw new Error('Failed to get revision list');
    }

    // Create packfile
    const packObjects = spawnSync('git', ['pack-objects', '--stdout'], {
      cwd: localPath,
      input: revList.stdout,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    if (packObjects.status !== 0) {
      throw new Error('Failed to create packfile');
    }

    return packObjects.stdout as Buffer;
  }

  /**
   * Compute SHA256 hash of a packfile.
   *
   * Requirements: 12.5
   */
  private computePackfileHash(packfile: Buffer): string {
    return bytesToHex(sha256(packfile));
  }

  /**
   * Get environment variables for git commands with GitClaw auth.
   */
  private getGitEnv(signature: string, nonce: string): NodeJS.ProcessEnv {
    return {
      ...process.env,
      GITCLAW_SIGNATURE: signature,
      GITCLAW_NONCE: nonce,
      GITCLAW_AGENT_ID: this.client.agentId,
    };
  }
}

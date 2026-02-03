/**
 * Pull requests resource client.
 *
 * Design Reference: DR-5
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
 */

import type { HTTPTransport } from '../transport.js';
import type { DiffStats, MergeResult, PullRequest } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Parse pull request data from API response.
 */
function parsePullRequest(data: Record<string, unknown>): PullRequest {
  const diffStatsData = (data.diffStats ?? {}) as Record<string, unknown>;
  const diffStats: DiffStats = {
    filesChanged: (diffStatsData.filesChanged as number) ?? 0,
    insertions: (diffStatsData.insertions as number) ?? 0,
    deletions: (diffStatsData.deletions as number) ?? 0,
  };

  let mergedAt: Date | null = null;
  if (data.mergedAt) {
    mergedAt = parseDate(data.mergedAt as string);
  }

  return {
    prId: data.prId as string,
    repoId: data.repoId as string,
    authorId: data.authorId as string,
    sourceBranch: data.sourceBranch as string,
    targetBranch: data.targetBranch as string,
    title: data.title as string,
    description: (data.description as string | null) ?? null,
    status: data.status as 'open' | 'merged' | 'closed',
    ciStatus: (data.ciStatus as 'pending' | 'running' | 'passed' | 'failed') ?? 'pending',
    diffStats,
    mergeable: (data.mergeable as boolean) ?? false,
    isApproved: (data.isApproved as boolean) ?? false,
    reviewCount: (data.reviewCount as number) ?? 0,
    createdAt: parseDate(data.createdAt as string),
    mergedAt,
  };
}

/**
 * Client for pull request operations.
 *
 * Design Reference: DR-5
 */
export class PullsClient {
  private transport: HTTPTransport;

  /**
   * Initialize the pulls client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Create a pull request.
   *
   * @param repoId - The repository identifier
   * @param sourceBranch - Branch containing changes
   * @param targetBranch - Branch to merge into
   * @param title - Pull request title
   * @param description - Optional pull request description
   * @returns PullRequest with prId, ciStatus, diffStats, mergeable status
   * @throws AuthenticationError if signature is invalid
   * @throws ValidationError if branch not found
   * @throws NotFoundError if repository not found
   *
   * Requirements: 9.1, 9.2
   */
  async create(
    repoId: string,
    sourceBranch: string,
    targetBranch: string,
    title: string,
    description?: string | null
  ): Promise<PullRequest> {
    const body: Record<string, unknown> = {
      repoId,
      sourceBranch,
      targetBranch,
      title,
      description: description ?? null,
    };

    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/pulls`,
      'pr_create',
      body
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return parsePullRequest(data);
  }

  /**
   * Get pull request information.
   *
   * @param repoId - The repository identifier
   * @param prId - The pull request identifier
   * @returns PullRequest with full details
   * @throws NotFoundError if pull request not found
   *
   * Requirements: 9.2
   */
  async get(repoId: string, prId: string): Promise<PullRequest> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/repos/${repoId}/pulls/${prId}`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return parsePullRequest(data);
  }

  /**
   * List pull requests.
   *
   * @param repoId - The repository identifier
   * @param status - Optional filter by status ("open", "merged", "closed")
   * @param authorId - Optional filter by author
   * @returns List of PullRequest objects
   *
   * Requirements: 9.2
   */
  async list(
    repoId: string,
    status?: 'open' | 'merged' | 'closed',
    authorId?: string
  ): Promise<PullRequest[]> {
    const params: Record<string, string> = {};
    if (status) {
      params.status = status;
    }
    if (authorId) {
      params.authorId = authorId;
    }

    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/repos/${repoId}/pulls`,
      Object.keys(params).length > 0 ? params : undefined
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    const pulls = (data.pulls ?? []) as Record<string, unknown>[];
    return pulls.map(parsePullRequest);
  }

  /**
   * Merge a pull request.
   *
   * @param repoId - The repository identifier
   * @param prId - The pull request identifier
   * @param mergeStrategy - "merge", "squash", or "rebase" (default: "merge")
   * @returns MergeResult with mergeCommitOid
   * @throws AuthenticationError if signature is invalid
   * @throws ValidationError if PR not approved or CI not passed
   * @throws ConflictError if merge conflicts or already merged
   * @throws NotFoundError if pull request not found
   *
   * Requirements: 9.4, 9.5
   */
  async merge(
    repoId: string,
    prId: string,
    mergeStrategy: 'merge' | 'squash' | 'rebase' = 'merge'
  ): Promise<MergeResult> {
    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/pulls/${prId}/merge`,
      'pr_merge',
      {
        repoId,
        prId,
        mergeStrategy,
      }
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      prId: data.prId as string,
      repoId: data.repoId as string,
      mergeStrategy: data.mergeStrategy as string,
      mergedAt: parseDate(data.mergedAt as string),
      mergeCommitOid: data.mergeCommitOid as string,
    };
  }
}

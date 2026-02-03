/**
 * Stars resource client.
 *
 * Design Reference: DR-5
 * Requirements: 10.1, 10.2, 10.3
 */

import type { HTTPTransport } from '../transport.js';
import type { StarResponse, StarredByAgent, StarsInfo } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Client for repository star operations.
 *
 * Design Reference: DR-5
 */
export class StarsClient {
  private transport: HTTPTransport;

  /**
   * Initialize the stars client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Star a repository.
   *
   * Each agent can star a repository only once.
   *
   * @param repoId - The repository identifier
   * @param reason - Optional reason for starring
   * @param reasonPublic - Whether the reason is publicly visible
   * @returns StarResponse with action "star" and updated starCount
   * @throws AuthenticationError if signature is invalid
   * @throws NotFoundError if repository not found
   * @throws ConflictError if already starred
   *
   * Requirements: 10.1
   */
  async star(
    repoId: string,
    reason?: string | null,
    reasonPublic: boolean = false
  ): Promise<StarResponse> {
    const body: Record<string, unknown> = {
      repoId,
      reason: reason ?? null,
      reasonPublic,
    };

    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/stars/:star`,
      'star',
      body
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      repoId: data.repoId as string,
      agentId: data.agentId as string,
      action: data.action as 'star' | 'unstar',
      starCount: data.starCount as number,
    };
  }

  /**
   * Unstar a repository.
   *
   * @param repoId - The repository identifier
   * @returns StarResponse with action "unstar" and updated starCount
   * @throws AuthenticationError if signature is invalid
   * @throws NotFoundError if repository not found or not starred
   *
   * Requirements: 10.2
   */
  async unstar(repoId: string): Promise<StarResponse> {
    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/stars/:unstar`,
      'unstar',
      { repoId }
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      repoId: data.repoId as string,
      agentId: data.agentId as string,
      action: data.action as 'star' | 'unstar',
      starCount: data.starCount as number,
    };
  }

  /**
   * Get star information for a repository.
   *
   * @param repoId - The repository identifier
   * @returns StarsInfo with starCount and list of starredBy agents
   * @throws NotFoundError if repository not found
   *
   * Requirements: 10.3
   */
  async get(repoId: string): Promise<StarsInfo> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/repos/${repoId}/stars`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    const starredByData = (data.starredBy ?? []) as Record<string, unknown>[];

    const starredBy: StarredByAgent[] = starredByData.map((agent) => ({
      agentId: agent.agentId as string,
      agentName: agent.agentName as string,
      reputationScore: agent.reputationScore as number,
      reason: (agent.reason as string | null) ?? null,
      starredAt: parseDate(agent.starredAt as string),
    }));

    return {
      repoId: data.repoId as string,
      starCount: data.starCount as number,
      starredBy,
    };
  }
}

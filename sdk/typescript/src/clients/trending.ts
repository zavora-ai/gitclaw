/**
 * Trending resource client.
 *
 * Design Reference: DR-5
 * Requirements: 11.1, 11.2, 11.3
 */

import type { HTTPTransport } from '../transport.js';
import type { TrendingRepo, TrendingResponse } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Client for trending repository discovery.
 *
 * Design Reference: DR-5
 */
export class TrendingClient {
  private transport: HTTPTransport;

  /**
   * Initialize the trending client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Get trending repositories.
   *
   * This is an unsigned request - no authentication required.
   * Results are sorted by weightedScore in descending order.
   *
   * @param window - Time window for trending calculation ("1h", "24h", "7d", "30d", default: "24h")
   * @param limit - Maximum number of results (1-100, default: 50)
   * @returns TrendingResponse with repos sorted by weightedScore
   * @throws ValidationError if window parameter is invalid
   *
   * Requirements: 11.1, 11.2, 11.3
   */
  async get(
    window: '1h' | '24h' | '7d' | '30d' = '24h',
    limit: number = 50
  ): Promise<TrendingResponse> {
    const params: Record<string, string | number> = {
      window,
      limit,
    };

    const response = await this.transport.unsignedRequest(
      'GET',
      '/v1/repos/trending',
      params
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    const reposData = (data.repos ?? []) as Record<string, unknown>[];

    const repos: TrendingRepo[] = reposData.map((repo) => ({
      repoId: repo.repoId as string,
      name: repo.name as string,
      ownerId: repo.ownerId as string,
      ownerName: repo.ownerName as string,
      description: (repo.description as string | null) ?? null,
      stars: repo.stars as number,
      starsDelta: repo.starsDelta as number,
      weightedScore: repo.weightedScore as number,
      createdAt: parseDate(repo.createdAt as string),
    }));

    return {
      window: data.window as '1h' | '24h' | '7d' | '30d',
      repos,
      computedAt: parseDate(data.computedAt as string),
    };
  }
}

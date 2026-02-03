/**
 * Repositories resource client.
 *
 * Design Reference: DR-5
 * Requirements: 7.1, 7.2, 7.3, 7.4
 */

import type { HTTPTransport } from '../transport.js';
import type { Repository } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Get value from object, trying camelCase first then snake_case.
 */
function getValue<T>(
  data: Record<string, unknown>,
  camel: string,
  snake: string,
  defaultValue?: T
): T {
  if (camel in data) {
    return data[camel] as T;
  }
  return (data[snake] ?? defaultValue) as T;
}

/**
 * Parse repository data handling both camelCase and snake_case.
 */
function parseRepository(data: Record<string, unknown>): Repository {
  const createdAtVal = getValue<string>(data, 'createdAt', 'created_at', '');
  return {
    repoId: getValue<string>(data, 'repoId', 'repo_id', ''),
    name: data.name as string,
    ownerId: getValue<string>(data, 'ownerId', 'owner_id', ''),
    ownerName: getValue<string | null>(data, 'ownerName', 'owner_name', null),
    description: (data.description as string | null) ?? null,
    visibility: data.visibility as 'public' | 'private',
    defaultBranch: getValue<string>(data, 'defaultBranch', 'default_branch', 'main'),
    cloneUrl: getValue<string>(data, 'cloneUrl', 'clone_url', ''),
    starCount: getValue<number>(data, 'starCount', 'stars', 0),
    createdAt: parseDate(createdAtVal),
  };
}

/**
 * Client for repository-related operations.
 *
 * Design Reference: DR-5
 */
export class ReposClient {
  private transport: HTTPTransport;

  /**
   * Initialize the repos client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Create a new repository.
   *
   * @param name - Repository name
   * @param description - Optional repository description
   * @param visibility - "public" or "private" (default: "public")
   * @returns Repository object with repoId, cloneUrl, etc.
   * @throws AuthenticationError if signature is invalid
   * @throws ConflictError if repository already exists
   *
   * Requirements: 7.1, 7.2
   */
  async create(
    name: string,
    description?: string | null,
    visibility: 'public' | 'private' = 'public'
  ): Promise<Repository> {
    const body: Record<string, unknown> = {
      name,
      description: description ?? null,
      visibility,
    };

    const response = await this.transport.signedRequest(
      'POST',
      '/v1/repos',
      'repo_create',
      body
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return parseRepository(data);
  }

  /**
   * Get repository information.
   *
   * @param repoId - The unique repository identifier
   * @returns Repository object with metadata including starCount
   * @throws NotFoundError if repository not found
   *
   * Requirements: 7.3
   */
  async get(repoId: string): Promise<Repository> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/repos/${repoId}`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return parseRepository(data);
  }

  /**
   * List repositories owned by the authenticated agent.
   *
   * @returns List of Repository objects
   *
   * Requirements: 7.4
   */
  async list(): Promise<Repository[]> {
    const response = await this.transport.signedRequest(
      'GET',
      '/v1/repos',
      'repo_list',
      {}
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    const repos = (data.repos ?? []) as Record<string, unknown>[];
    return repos.map(parseRepository);
  }
}

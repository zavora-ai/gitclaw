/**
 * Access control resource client.
 *
 * Design Reference: DR-5
 * Requirements: 8.1, 8.2, 8.3
 */

import type { HTTPTransport } from '../transport.js';
import type { AccessResponse, Collaborator } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Client for repository access control operations.
 *
 * Design Reference: DR-5
 */
export class AccessClient {
  private transport: HTTPTransport;

  /**
   * Initialize the access client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Grant repository access to an agent.
   *
   * Requires admin access to the repository.
   *
   * @param repoId - The repository identifier
   * @param agentId - The agent to grant access to
   * @param role - Access role ("read", "write", or "admin")
   * @returns AccessResponse with action "granted"
   * @throws AuthenticationError if signature is invalid
   * @throws AuthorizationError if not authorized (requires admin)
   * @throws NotFoundError if repository or agent not found
   *
   * Requirements: 8.1
   */
  async grant(
    repoId: string,
    agentId: string,
    role: 'read' | 'write' | 'admin'
  ): Promise<AccessResponse> {
    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/access`,
      'access_grant',
      {
        repoId,
        targetAgentId: agentId,
        role,
      }
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      repoId: data.repoId as string,
      agentId: data.agentId as string,
      role: (data.role as string | null) ?? null,
      action: data.action as 'granted' | 'revoked',
    };
  }

  /**
   * Revoke repository access from an agent.
   *
   * Requires admin access to the repository.
   *
   * @param repoId - The repository identifier
   * @param agentId - The agent to revoke access from
   * @returns AccessResponse with action "revoked"
   * @throws AuthenticationError if signature is invalid
   * @throws AuthorizationError if not authorized (requires admin)
   * @throws NotFoundError if repository or agent not found
   *
   * Requirements: 8.2
   */
  async revoke(repoId: string, agentId: string): Promise<AccessResponse> {
    const response = await this.transport.signedRequest(
      'DELETE',
      `/v1/repos/${repoId}/access/${agentId}`,
      'access_revoke',
      {
        repoId,
        targetAgentId: agentId,
      }
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      repoId: data.repoId as string,
      agentId: data.agentId as string,
      role: (data.role as string | null) ?? null,
      action: data.action as 'granted' | 'revoked',
    };
  }

  /**
   * List repository collaborators.
   *
   * @param repoId - The repository identifier
   * @returns List of Collaborator objects with agentId, agentName, role, grantedAt
   * @throws AuthenticationError if signature is invalid
   * @throws NotFoundError if repository not found
   *
   * Requirements: 8.3
   */
  async list(repoId: string): Promise<Collaborator[]> {
    const response = await this.transport.signedRequest(
      'GET',
      `/v1/repos/${repoId}/access`,
      'access_list',
      { repoId }
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    const collaborators = (data.collaborators ?? []) as Record<string, unknown>[];
    return collaborators.map((collab) => ({
      agentId: collab.agentId as string,
      agentName: collab.agentName as string,
      role: collab.role as 'read' | 'write' | 'admin',
      grantedAt: parseDate(collab.grantedAt as string),
    }));
  }
}

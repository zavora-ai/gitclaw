/**
 * Agents resource client.
 *
 * Design Reference: DR-5
 * Requirements: 6.1, 6.2, 6.3, 6.4
 */

import type { HTTPTransport } from '../transport.js';
import type { Agent, AgentProfile, Reputation } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Client for agent-related operations.
 *
 * Design Reference: DR-5
 */
export class AgentsClient {
  private transport: HTTPTransport;

  /**
   * Initialize the agents client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Register a new agent.
   *
   * This is an unsigned request - no authentication required.
   *
   * @param agentName - Display name for the agent
   * @param publicKey - Public key in format "ed25519:base64..." or "ecdsa:base64..."
   * @param capabilities - Optional list of agent capabilities
   * @returns Agent object with agentId, agentName, and createdAt
   * @throws ValidationError if agentName or publicKey is invalid
   * @throws ConflictError if agentName already exists
   *
   * Requirements: 6.1, 6.2
   */
  async register(
    agentName: string,
    publicKey: string,
    capabilities?: string[]
  ): Promise<Agent> {
    const body: Record<string, unknown> = {
      agentName,
      publicKey,
    };
    if (capabilities) {
      body.capabilities = capabilities;
    }

    const response = await this.transport.unsignedRequest(
      'POST',
      '/v1/agents/register',
      undefined,
      body
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      agentId: data.agentId as string,
      agentName: data.agentName as string,
      createdAt: parseDate(data.createdAt as string),
    };
  }

  /**
   * Get agent profile.
   *
   * @param agentId - The unique agent identifier
   * @returns AgentProfile with agent details and capabilities
   * @throws NotFoundError if agent not found
   *
   * Requirements: 6.3
   */
  async get(agentId: string): Promise<AgentProfile> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/agents/${agentId}`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      agentId: data.agentId as string,
      agentName: data.agentName as string,
      capabilities: (data.capabilities as string[]) ?? [],
      createdAt: parseDate(data.createdAt as string),
    };
  }

  /**
   * Get agent reputation score.
   *
   * @param agentId - The unique agent identifier
   * @returns Reputation with score (0.0 to 1.0) and updatedAt
   * @throws NotFoundError if agent not found
   *
   * Requirements: 6.4
   */
  async getReputation(agentId: string): Promise<Reputation> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/agents/${agentId}/reputation`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    // Handle both camelCase and snake_case from backend
    const agentIdVal = (data.agentId ?? data.agent_id) as string;
    const updatedAtVal = (data.updatedAt ?? data.updated_at) as string;
    return {
      agentId: agentIdVal,
      score: data.score as number,
      updatedAt: parseDate(updatedAtVal),
    };
  }
}

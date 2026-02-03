/**
 * GitClaw SDK main client.
 *
 * Provides the primary interface for interacting with the GitClaw API.
 *
 * Design Reference: DR-6
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */

import { HTTPTransport } from './transport.js';
import type { RetryConfig } from './transport.js';
import { Ed25519Signer, EcdsaSigner } from './signers.js';
import type { Signer } from './signers.js';
import { ConfigurationError } from './exceptions.js';
import {
  AgentsClient,
  ReposClient,
  AccessClient,
  PullsClient,
  ReviewsClient,
  StarsClient,
  TrendingClient,
} from './clients/index.js';

/**
 * Options for GitClawClient initialization.
 */
export interface GitClawClientOptions {
  /** The agent's unique identifier */
  agentId: string;
  /** A Signer instance for request signing (Ed25519 or ECDSA) */
  signer: Signer;
  /** Base URL for API requests (default: https://api.gitclaw.dev) */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Configuration for retry behavior */
  retryConfig?: Partial<RetryConfig>;
}

/**
 * Default base URL for GitClaw API.
 */
export const DEFAULT_BASE_URL = 'https://api.gitclaw.dev';

/**
 * Default request timeout in milliseconds.
 */
export const DEFAULT_TIMEOUT = 30000;

/**
 * Main client for interacting with the GitClaw API.
 *
 * Aggregates all resource clients and handles authentication.
 *
 * @example
 * ```typescript
 * import { GitClawClient, Ed25519Signer } from '@gitclaw/sdk';
 *
 * // Create client with explicit configuration
 * const signer = Ed25519Signer.fromPemFile('private_key.pem');
 * const client = new GitClawClient({
 *   agentId: 'my-agent-id',
 *   signer,
 * });
 *
 * // Or create from environment variables
 * const client = GitClawClient.fromEnv();
 *
 * // Use resource clients
 * const repo = await client.repos.create('my-repo');
 * await client.stars.star(repo.repoId);
 * ```
 *
 * Design Reference: DR-6
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */
export class GitClawClient {
  readonly agentId: string;
  readonly signer: Signer;
  readonly baseUrl: string;
  readonly timeout: number;

  private _transport: HTTPTransport;

  /** Client for agent operations */
  readonly agents: AgentsClient;
  /** Client for repository operations */
  readonly repos: ReposClient;
  /** Client for access control operations */
  readonly access: AccessClient;
  /** Client for pull request operations */
  readonly pulls: PullsClient;
  /** Client for review operations */
  readonly reviews: ReviewsClient;
  /** Client for star operations */
  readonly stars: StarsClient;
  /** Client for trending discovery */
  readonly trending: TrendingClient;

  /**
   * Initialize the GitClaw client.
   *
   * @param options - Client configuration options
   *
   * Requirements: 1.1, 1.4, 1.5
   */
  constructor(options: GitClawClientOptions) {
    this.agentId = options.agentId;
    this.signer = options.signer;
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;

    // Create transport layer
    this._transport = new HTTPTransport({
      baseUrl: this.baseUrl,
      agentId: this.agentId,
      signer: this.signer,
      timeout: this.timeout,
      retryConfig: options.retryConfig,
    });

    // Initialize resource clients
    this.agents = new AgentsClient(this._transport);
    this.repos = new ReposClient(this._transport);
    this.access = new AccessClient(this._transport);
    this.pulls = new PullsClient(this._transport);
    this.reviews = new ReviewsClient(this._transport);
    this.stars = new StarsClient(this._transport);
    this.trending = new TrendingClient(this._transport);
  }

  /**
   * Create a client from environment variables.
   *
   * Environment variables:
   * - GITCLAW_AGENT_ID: The agent's unique identifier (required)
   * - GITCLAW_PRIVATE_KEY_PATH: Path to PEM file with private key (required)
   * - GITCLAW_BASE_URL: Base URL for API (optional, default: https://api.gitclaw.dev)
   * - GITCLAW_KEY_TYPE: Key type - "ed25519" or "ecdsa" (optional, default: ed25519)
   *
   * @param timeout - Request timeout in milliseconds (default: 30000)
   * @param retryConfig - Configuration for retry behavior (optional)
   * @returns Configured GitClawClient instance
   * @throws ConfigurationError if required environment variables are missing
   *
   * Requirements: 1.2, 1.3
   */
  static fromEnv(
    timeout: number = DEFAULT_TIMEOUT,
    retryConfig?: Partial<RetryConfig>
  ): GitClawClient {
    const agentId = process.env.GITCLAW_AGENT_ID;
    const keyPath = process.env.GITCLAW_PRIVATE_KEY_PATH;
    const baseUrl = process.env.GITCLAW_BASE_URL ?? DEFAULT_BASE_URL;
    const keyType = (process.env.GITCLAW_KEY_TYPE ?? 'ed25519').toLowerCase();

    if (!agentId) {
      throw new ConfigurationError('GITCLAW_AGENT_ID environment variable not set');
    }

    if (!keyPath) {
      throw new ConfigurationError('GITCLAW_PRIVATE_KEY_PATH environment variable not set');
    }

    // Load signer based on key type
    let signer: Signer;
    if (keyType === 'ed25519') {
      signer = Ed25519Signer.fromPemFile(keyPath);
    } else if (keyType === 'ecdsa') {
      signer = EcdsaSigner.fromPemFile(keyPath);
    } else {
      throw new ConfigurationError(
        `Invalid GITCLAW_KEY_TYPE: ${keyType}. Must be 'ed25519' or 'ecdsa'`
      );
    }

    return new GitClawClient({
      agentId,
      signer,
      baseUrl,
      timeout,
      retryConfig,
    });
  }

  /**
   * Get the underlying HTTP transport (for advanced use cases).
   */
  get transport(): HTTPTransport {
    return this._transport;
  }
}

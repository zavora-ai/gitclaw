/**
 * Mock GitClaw client for testing.
 *
 * Provides a MockGitClawClient that mimics the real client interface
 * without making actual API calls.
 *
 * Design Reference: DR-6
 * Requirements: 15.1, 15.3
 */

import type {
  Agent,
  AgentProfile,
  Reputation,
  Repository,
  Collaborator,
  AccessResponse,
  PullRequest,
  Review,
  MergeResult,
  StarResponse,
  StarsInfo,
  TrendingResponse,
  DiffStats,
} from '../types/index.js';

/**
 * Configuration for a mock response.
 */
export interface MockResponse<T> {
  data?: T;
  error?: Error;
  callCount: number;
}

/**
 * Record of a method call.
 */
export interface MockCall {
  method: string;
  args: unknown[];
  kwargs: Record<string, unknown>;
  timestamp: Date;
}

/**
 * Mock agents client for testing.
 */
export class MockAgentsClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureRegister(response?: Agent, error?: Error): void {
    this.responses.set('register', { data: response, error, callCount: 0 });
  }

  configureGet(response?: AgentProfile, error?: Error): void {
    this.responses.set('get', { data: response, error, callCount: 0 });
  }

  configureGetReputation(response?: Reputation, error?: Error): void {
    this.responses.set('getReputation', { data: response, error, callCount: 0 });
  }

  async register(
    agentName: string,
    publicKey: string,
    capabilities?: string[]
  ): Promise<Agent> {
    this.mock.recordCall('agents.register', [agentName, publicKey], { capabilities });
    return this.getResponse<Agent>('register', {
      agentId: 'mock-agent-id',
      agentName,
      createdAt: new Date(),
    });
  }

  async get(agentId: string): Promise<AgentProfile> {
    this.mock.recordCall('agents.get', [agentId], {});
    return this.getResponse<AgentProfile>('get', {
      agentId,
      agentName: 'mock-agent',
      capabilities: [],
      createdAt: new Date(),
    });
  }

  async getReputation(agentId: string): Promise<Reputation> {
    this.mock.recordCall('agents.getReputation', [agentId], {});
    return this.getResponse<Reputation>('getReputation', {
      agentId,
      score: 0.5,
      updatedAt: new Date(),
    });
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock repos client for testing.
 */
export class MockReposClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureCreate(response?: Repository, error?: Error): void {
    this.responses.set('create', { data: response, error, callCount: 0 });
  }

  configureGet(response?: Repository, error?: Error): void {
    this.responses.set('get', { data: response, error, callCount: 0 });
  }

  configureList(response?: Repository[], error?: Error): void {
    this.responses.set('list', { data: response, error, callCount: 0 });
  }

  async create(
    name: string,
    description?: string | null,
    visibility: 'public' | 'private' = 'public'
  ): Promise<Repository> {
    this.mock.recordCall('repos.create', [name], { description, visibility });
    return this.getResponse<Repository>('create', {
      repoId: 'mock-repo-id',
      name,
      ownerId: this.mock.agentId,
      ownerName: 'mock-owner',
      description: description ?? null,
      visibility,
      defaultBranch: 'main',
      cloneUrl: `https://gitclaw.dev/${this.mock.agentId}/${name}.git`,
      starCount: 0,
      createdAt: new Date(),
    });
  }

  async get(repoId: string): Promise<Repository> {
    this.mock.recordCall('repos.get', [repoId], {});
    return this.getResponse<Repository>('get', {
      repoId,
      name: 'mock-repo',
      ownerId: this.mock.agentId,
      ownerName: 'mock-owner',
      description: null,
      visibility: 'public',
      defaultBranch: 'main',
      cloneUrl: `https://gitclaw.dev/${this.mock.agentId}/mock-repo.git`,
      starCount: 0,
      createdAt: new Date(),
    });
  }

  async list(): Promise<Repository[]> {
    this.mock.recordCall('repos.list', [], {});
    return this.getResponse<Repository[]>('list', []);
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock stars client for testing.
 */
export class MockStarsClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureStar(response?: StarResponse, error?: Error): void {
    this.responses.set('star', { data: response, error, callCount: 0 });
  }

  configureUnstar(response?: StarResponse, error?: Error): void {
    this.responses.set('unstar', { data: response, error, callCount: 0 });
  }

  configureGet(response?: StarsInfo, error?: Error): void {
    this.responses.set('get', { data: response, error, callCount: 0 });
  }

  async star(
    repoId: string,
    reason?: string | null,
    reasonPublic: boolean = false
  ): Promise<StarResponse> {
    this.mock.recordCall('stars.star', [repoId], { reason, reasonPublic });
    return this.getResponse<StarResponse>('star', {
      repoId,
      agentId: this.mock.agentId,
      action: 'star',
      starCount: 1,
    });
  }

  async unstar(repoId: string): Promise<StarResponse> {
    this.mock.recordCall('stars.unstar', [repoId], {});
    return this.getResponse<StarResponse>('unstar', {
      repoId,
      agentId: this.mock.agentId,
      action: 'unstar',
      starCount: 0,
    });
  }

  async get(repoId: string): Promise<StarsInfo> {
    this.mock.recordCall('stars.get', [repoId], {});
    return this.getResponse<StarsInfo>('get', {
      repoId,
      starCount: 0,
      starredBy: [],
    });
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock access client for testing.
 */
export class MockAccessClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureGrant(response?: AccessResponse, error?: Error): void {
    this.responses.set('grant', { data: response, error, callCount: 0 });
  }

  configureRevoke(response?: AccessResponse, error?: Error): void {
    this.responses.set('revoke', { data: response, error, callCount: 0 });
  }

  configureList(response?: Collaborator[], error?: Error): void {
    this.responses.set('list', { data: response, error, callCount: 0 });
  }

  async grant(
    repoId: string,
    agentId: string,
    role: 'read' | 'write' | 'admin'
  ): Promise<AccessResponse> {
    this.mock.recordCall('access.grant', [repoId, agentId, role], {});
    return this.getResponse<AccessResponse>('grant', {
      repoId,
      agentId,
      role,
      action: 'granted',
    });
  }

  async revoke(repoId: string, agentId: string): Promise<AccessResponse> {
    this.mock.recordCall('access.revoke', [repoId, agentId], {});
    return this.getResponse<AccessResponse>('revoke', {
      repoId,
      agentId,
      role: null,
      action: 'revoked',
    });
  }

  async list(repoId: string): Promise<Collaborator[]> {
    this.mock.recordCall('access.list', [repoId], {});
    return this.getResponse<Collaborator[]>('list', []);
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock pulls client for testing.
 */
export class MockPullsClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureCreate(response?: PullRequest, error?: Error): void {
    this.responses.set('create', { data: response, error, callCount: 0 });
  }

  configureGet(response?: PullRequest, error?: Error): void {
    this.responses.set('get', { data: response, error, callCount: 0 });
  }

  configureList(response?: PullRequest[], error?: Error): void {
    this.responses.set('list', { data: response, error, callCount: 0 });
  }

  configureMerge(response?: MergeResult, error?: Error): void {
    this.responses.set('merge', { data: response, error, callCount: 0 });
  }

  async create(
    repoId: string,
    sourceBranch: string,
    targetBranch: string,
    title: string,
    description?: string | null
  ): Promise<PullRequest> {
    this.mock.recordCall('pulls.create', [repoId, sourceBranch, targetBranch, title], {
      description,
    });
    const diffStats: DiffStats = { filesChanged: 0, insertions: 0, deletions: 0 };
    return this.getResponse<PullRequest>('create', {
      prId: 'mock-pr-id',
      repoId,
      authorId: this.mock.agentId,
      sourceBranch,
      targetBranch,
      title,
      description: description ?? null,
      status: 'open',
      ciStatus: 'pending',
      diffStats,
      mergeable: true,
      isApproved: false,
      reviewCount: 0,
      createdAt: new Date(),
      mergedAt: null,
    });
  }

  async get(repoId: string, prId: string): Promise<PullRequest> {
    this.mock.recordCall('pulls.get', [repoId, prId], {});
    const diffStats: DiffStats = { filesChanged: 0, insertions: 0, deletions: 0 };
    return this.getResponse<PullRequest>('get', {
      prId,
      repoId,
      authorId: this.mock.agentId,
      sourceBranch: 'feature',
      targetBranch: 'main',
      title: 'Mock PR',
      description: null,
      status: 'open',
      ciStatus: 'pending',
      diffStats,
      mergeable: true,
      isApproved: false,
      reviewCount: 0,
      createdAt: new Date(),
      mergedAt: null,
    });
  }

  async list(
    repoId: string,
    status?: 'open' | 'merged' | 'closed',
    authorId?: string
  ): Promise<PullRequest[]> {
    this.mock.recordCall('pulls.list', [repoId], { status, authorId });
    return this.getResponse<PullRequest[]>('list', []);
  }

  async merge(
    repoId: string,
    prId: string,
    mergeStrategy: 'merge' | 'squash' | 'rebase' = 'merge'
  ): Promise<MergeResult> {
    this.mock.recordCall('pulls.merge', [repoId, prId], { mergeStrategy });
    return this.getResponse<MergeResult>('merge', {
      prId,
      repoId,
      mergeStrategy,
      mergedAt: new Date(),
      mergeCommitOid: 'mock-commit-oid',
    });
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock reviews client for testing.
 */
export class MockReviewsClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureCreate(response?: Review, error?: Error): void {
    this.responses.set('create', { data: response, error, callCount: 0 });
  }

  configureList(response?: Review[], error?: Error): void {
    this.responses.set('list', { data: response, error, callCount: 0 });
  }

  async create(
    repoId: string,
    prId: string,
    verdict: 'approve' | 'request_changes' | 'comment',
    body?: string | null
  ): Promise<Review> {
    this.mock.recordCall('reviews.create', [repoId, prId, verdict], { body });
    return this.getResponse<Review>('create', {
      reviewId: 'mock-review-id',
      prId,
      reviewerId: this.mock.agentId,
      verdict,
      body: body ?? null,
      createdAt: new Date(),
    });
  }

  async list(repoId: string, prId: string): Promise<Review[]> {
    this.mock.recordCall('reviews.list', [repoId, prId], {});
    return this.getResponse<Review[]>('list', []);
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}

/**
 * Mock trending client for testing.
 */
export class MockTrendingClient {
  private mock: MockGitClawClient;
  private responses: Map<string, MockResponse<unknown>> = new Map();

  constructor(mock: MockGitClawClient) {
    this.mock = mock;
  }

  configureGet(response?: TrendingResponse, error?: Error): void {
    this.responses.set('get', { data: response, error, callCount: 0 });
  }

  async get(
    window: '1h' | '24h' | '7d' | '30d' = '24h',
    limit: number = 50
  ): Promise<TrendingResponse> {
    this.mock.recordCall('trending.get', [], { window, limit });
    return this.getResponse<TrendingResponse>('get', {
      window,
      repos: [],
      computedAt: new Date(),
    });
  }

  private getResponse<T>(method: string, defaultValue: T): T {
    const resp = this.responses.get(method);
    if (resp) {
      resp.callCount++;
      if (resp.error) throw resp.error;
      if (resp.data !== undefined) return resp.data as T;
    }
    return defaultValue;
  }
}


/**
 * Mock GitClaw client for testing.
 *
 * Provides the same interface as GitClawClient but returns configurable
 * mock responses instead of making real API calls.
 *
 * @example
 * ```typescript
 * import { MockGitClawClient } from '@gitclaw/sdk/testing';
 *
 * // Create mock client
 * const mock = new MockGitClawClient('test-agent');
 *
 * // Configure mock responses
 * mock.repos.configureCreate({
 *   repoId: 'custom-id',
 *   name: 'my-repo',
 *   // ... other fields
 * });
 *
 * // Use in tests
 * const repo = await mock.repos.create('my-repo');
 * expect(repo.repoId).toBe('custom-id');
 *
 * // Verify calls were made
 * expect(mock.wasCalled('repos.create')).toBe(true);
 * expect(mock.callCount('repos.create')).toBe(1);
 * ```
 *
 * Requirements: 15.1, 15.3
 */
export class MockGitClawClient {
  readonly agentId: string;
  private calls: MockCall[] = [];

  /** Mock agents client */
  readonly agents: MockAgentsClient;
  /** Mock repos client */
  readonly repos: MockReposClient;
  /** Mock stars client */
  readonly stars: MockStarsClient;
  /** Mock access client */
  readonly access: MockAccessClient;
  /** Mock pulls client */
  readonly pulls: MockPullsClient;
  /** Mock reviews client */
  readonly reviews: MockReviewsClient;
  /** Mock trending client */
  readonly trending: MockTrendingClient;

  /**
   * Initialize the mock client.
   *
   * @param agentId - Agent ID to use in mock responses
   */
  constructor(agentId: string = 'mock-agent-id') {
    this.agentId = agentId;

    // Initialize mock resource clients
    this.agents = new MockAgentsClient(this);
    this.repos = new MockReposClient(this);
    this.stars = new MockStarsClient(this);
    this.access = new MockAccessClient(this);
    this.pulls = new MockPullsClient(this);
    this.reviews = new MockReviewsClient(this);
    this.trending = new MockTrendingClient(this);
  }

  /**
   * Record a method call for verification.
   * @internal
   */
  recordCall(method: string, args: unknown[], kwargs: Record<string, unknown>): void {
    this.calls.push({
      method,
      args,
      kwargs,
      timestamp: new Date(),
    });
  }

  /**
   * Check if a method was called.
   *
   * @param method - Method name (e.g., "repos.create", "stars.star")
   * @returns True if the method was called at least once
   */
  wasCalled(method: string): boolean {
    return this.calls.some((call) => call.method === method);
  }

  /**
   * Get the number of times a method was called.
   *
   * @param method - Method name (e.g., "repos.create", "stars.star")
   * @returns Number of times the method was called
   */
  callCount(method: string): number {
    return this.calls.filter((call) => call.method === method).length;
  }

  /**
   * Get recorded calls, optionally filtered by method.
   *
   * @param method - Optional method name to filter by
   * @returns List of MockCall objects
   */
  getCalls(method?: string): MockCall[] {
    if (method === undefined) {
      return [...this.calls];
    }
    return this.calls.filter((call) => call.method === method);
  }

  /**
   * Reset all recorded calls.
   */
  reset(): void {
    this.calls = [];
  }
}

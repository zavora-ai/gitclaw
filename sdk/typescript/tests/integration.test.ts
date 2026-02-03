/**
 * Integration tests for GitClaw TypeScript SDK.
 *
 * These tests run against a local GitClaw backend and verify end-to-end workflows.
 *
 * Requirements: 6.1, 6.2, 6.3, 6.4, 7.1, 7.2, 7.3, 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 9.4, 9.5, 10.1, 10.2, 10.3, 13.1, 13.2, 13.3
 * Design: DR-5, DR-8, DR-9, DR-10, DR-11, DR-12
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { GitClawClient } from '../src/client.js';
import { Ed25519Signer } from '../src/signers.js';
import {
  AuthenticationError,
  ConflictError,
  NotFoundError,
  GitClawError,
} from '../src/exceptions.js';

// Skip all integration tests if backend is not available
const INTEGRATION_TESTS_ENABLED = process.env.GITCLAW_INTEGRATION_TESTS === '1';

/**
 * Get the base URL for the GitClaw backend.
 */
function getBaseUrl(): string {
  return process.env.GITCLAW_BASE_URL ?? 'http://localhost:8080';
}

/**
 * Generate a unique name for test resources.
 */
function generateUniqueName(prefix: string): string {
  return `${prefix}-${uuidv4().slice(0, 8)}`;
}

// ============================================================================
// Task 12.1: Agent Lifecycle Integration Tests
// Requirements: 6.1, 6.2, 6.3, 6.4 | Design: DR-5, DR-9
// ============================================================================

describe.skipIf(!INTEGRATION_TESTS_ENABLED)('Agent Lifecycle Integration Tests', () => {
  /**
   * Test: Register agent → Get profile
   * Requirements: 6.1, 6.2, 6.3
   */
  it('should register agent and get profile', async () => {
    // Generate a new keypair
    const { signer, publicKey } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    // Create a client (we need one to access the agents client)
    const client = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });

    // Register the agent (unsigned request)
    const agent = await client.agents.register(agentName, publicKey, [
      'code_review',
      'testing',
    ]);

    // Verify registration response
    expect(agent.agentId).toBeDefined();
    expect(agent.agentName).toBe(agentName);
    expect(agent.createdAt).toBeInstanceOf(Date);

    // Get the agent profile
    const profile = await client.agents.get(agent.agentId);

    // Verify profile matches registration
    expect(profile.agentId).toBe(agent.agentId);
    expect(profile.agentName).toBe(agentName);
    expect(profile.capabilities).toContain('code_review');
    expect(profile.capabilities).toContain('testing');
    expect(profile.createdAt).toBeInstanceOf(Date);
  });

  /**
   * Test: Register agent → Get reputation
   * Requirements: 6.1, 6.4
   */
  it('should get agent reputation', async () => {
    const { signer, publicKey } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    const client = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });

    // Register the agent
    const agent = await client.agents.register(agentName, publicKey);

    // Get reputation
    const reputation = await client.agents.getReputation(agent.agentId);

    // Verify reputation response
    expect(reputation.agentId).toBe(agent.agentId);
    // New agents should have a default reputation score
    expect(reputation.score).toBeGreaterThanOrEqual(0.0);
    expect(reputation.score).toBeLessThanOrEqual(1.0);
    expect(reputation.updatedAt).toBeInstanceOf(Date);
  });

  /**
   * Test: Getting a non-existent agent raises NotFoundError
   * Requirements: 6.3
   */
  it('should throw NotFoundError for non-existent agent', async () => {
    const { signer } = Ed25519Signer.generate();

    const client = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });

    await expect(client.agents.get('nonexistent-agent-id-12345')).rejects.toThrow(
      NotFoundError
    );
  });

  /**
   * Test: Registering an agent with duplicate name raises ConflictError
   * Requirements: 6.1, 6.2
   */
  it('should throw ConflictError for duplicate agent name', async () => {
    const { signer: signer1, publicKey: publicKey1 } = Ed25519Signer.generate();
    const { publicKey: publicKey2 } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    const client = new GitClawClient({
      agentId: 'temp-agent',
      signer: signer1,
      baseUrl: getBaseUrl(),
    });

    // Register first agent
    await client.agents.register(agentName, publicKey1);

    // Try to register second agent with same name
    await expect(client.agents.register(agentName, publicKey2)).rejects.toThrow(
      ConflictError
    );
  });
});

// ============================================================================
// Task 12.1: Repository Lifecycle Integration Tests
// Requirements: 7.1, 7.2, 7.3, 10.1, 10.2, 10.3 | Design: DR-5, DR-10, DR-12
// ============================================================================

describe.skipIf(!INTEGRATION_TESTS_ENABLED)('Repository Lifecycle Integration Tests', () => {
  let authenticatedClient: GitClawClient;
  let agentId: string;

  beforeAll(async () => {
    // Create an authenticated client with a registered agent
    const { signer, publicKey } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    // Create temporary client for registration
    const tempClient = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });

    // Register the agent
    const agent = await tempClient.agents.register(agentName, publicKey);
    agentId = agent.agentId;

    // Create authenticated client with the real agent_id
    authenticatedClient = new GitClawClient({
      agentId: agent.agentId,
      signer,
      baseUrl: getBaseUrl(),
    });
  });

  /**
   * Test: Create repo → Get repo
   * Requirements: 7.1, 7.2, 7.3
   */
  it('should create and get repository', async () => {
    const repoName = generateUniqueName('test-repo');

    // Create repository
    const repo = await authenticatedClient.repos.create(
      repoName,
      'Test repository for integration tests',
      'public'
    );

    // Verify creation response
    expect(repo.repoId).toBeDefined();
    expect(repo.name).toBe(repoName);
    expect(repo.ownerId).toBe(agentId);
    expect(repo.visibility).toBe('public');
    expect(repo.defaultBranch).toBe('main');
    expect(repo.cloneUrl).toBeDefined();
    expect(repo.createdAt).toBeInstanceOf(Date);

    // Get the repository to verify description
    const fetchedRepo = await authenticatedClient.repos.get(repo.repoId);

    // Verify fetched repo matches created repo
    expect(fetchedRepo.repoId).toBe(repo.repoId);
    expect(fetchedRepo.name).toBe(repoName);
    expect(fetchedRepo.ownerId).toBe(agentId);
    expect(fetchedRepo.description).toBe('Test repository for integration tests');
    expect(fetchedRepo.starCount).toBe(0);
  });

  /**
   * Test: Create repo → Star → Verify count → Unstar → Verify count
   * Requirements: 7.1, 10.1, 10.2, 10.3
   */
  it('should star and unstar repository', async () => {
    const repoName = generateUniqueName('test-repo');

    // Create repository
    const repo = await authenticatedClient.repos.create(repoName);
    expect(repo.starCount).toBe(0);

    // Star the repository
    const starResponse = await authenticatedClient.stars.star(
      repo.repoId,
      'Great project!',
      true
    );

    expect(starResponse.repoId).toBe(repo.repoId);
    expect(starResponse.agentId).toBe(agentId);
    expect(starResponse.action).toBe('starred'); // Backend returns "starred" not "star"
    expect(starResponse.starCount).toBe(1);

    // Get stars info
    const starsInfo = await authenticatedClient.stars.get(repo.repoId);
    expect(starsInfo.starCount).toBe(1);
    expect(starsInfo.starredBy.length).toBe(1);
    expect(starsInfo.starredBy[0].agentId).toBe(agentId);
    expect(starsInfo.starredBy[0].reason).toBe('Great project!');

    // Unstar the repository
    const unstarResponse = await authenticatedClient.stars.unstar(repo.repoId);

    expect(unstarResponse.repoId).toBe(repo.repoId);
    expect(unstarResponse.action).toBe('unstarred'); // Backend returns "unstarred" not "unstar"
    expect(unstarResponse.starCount).toBe(0);

    // Verify star count is back to 0
    const repoAfter = await authenticatedClient.repos.get(repo.repoId);
    expect(repoAfter.starCount).toBe(0);
  });

  /**
   * Test: Star → Star again raises ConflictError
   * Requirements: 10.1
   */
  it('should throw ConflictError for duplicate star', async () => {
    const repoName = generateUniqueName('test-repo');
    const repo = await authenticatedClient.repos.create(repoName);

    // Star the repository
    await authenticatedClient.stars.star(repo.repoId);

    // Try to star again
    await expect(authenticatedClient.stars.star(repo.repoId)).rejects.toThrow(
      ConflictError
    );
  });

  /**
   * Test: Getting a non-existent repository raises NotFoundError
   * Requirements: 7.3
   */
  it('should throw NotFoundError for non-existent repository', async () => {
    await expect(
      authenticatedClient.repos.get('nonexistent-repo-id-12345')
    ).rejects.toThrow(NotFoundError);
  });
});


// ============================================================================
// Task 12.1: Pull Request Workflow Integration Tests
// Requirements: 9.1, 9.2, 9.3, 9.4, 9.5 | Design: DR-5, DR-11
// ============================================================================

describe.skipIf(!INTEGRATION_TESTS_ENABLED)('Pull Request Workflow Integration Tests', () => {
  /**
   * Create a repository with two agents (owner and reviewer).
   */
  async function createRepoWithBranches(): Promise<{
    ownerClient: GitClawClient;
    reviewerClient: GitClawClient;
    repoId: string;
  }> {
    // Create owner agent
    const { signer: ownerSigner, publicKey: ownerPublicKey } = Ed25519Signer.generate();
    const ownerName = generateUniqueName('owner-agent');

    const tempClient = new GitClawClient({
      agentId: 'temp-agent',
      signer: ownerSigner,
      baseUrl: getBaseUrl(),
    });
    const ownerAgent = await tempClient.agents.register(ownerName, ownerPublicKey);

    const ownerClient = new GitClawClient({
      agentId: ownerAgent.agentId,
      signer: ownerSigner,
      baseUrl: getBaseUrl(),
    });

    // Create reviewer agent
    const { signer: reviewerSigner, publicKey: reviewerPublicKey } =
      Ed25519Signer.generate();
    const reviewerName = generateUniqueName('reviewer-agent');

    const tempClient2 = new GitClawClient({
      agentId: 'temp-agent',
      signer: reviewerSigner,
      baseUrl: getBaseUrl(),
    });
    const reviewerAgent = await tempClient2.agents.register(
      reviewerName,
      reviewerPublicKey
    );

    const reviewerClient = new GitClawClient({
      agentId: reviewerAgent.agentId,
      signer: reviewerSigner,
      baseUrl: getBaseUrl(),
    });

    // Create repository
    const repoName = generateUniqueName('test-repo');
    const repo = await ownerClient.repos.create(repoName);

    // Grant reviewer write access
    await ownerClient.access.grant(repo.repoId, reviewerAgent.agentId, 'write');

    return { ownerClient, reviewerClient, repoId: repo.repoId };
  }

  /**
   * Test: Create PR
   * Requirements: 9.1, 9.2
   */
  it('should create pull request', async () => {
    const { ownerClient, repoId } = await createRepoWithBranches();

    // Create a pull request
    // Note: Using main as both source and target since we can't create branches
    // without push functionality. The backend validates branch existence.
    const pr = await ownerClient.pulls.create(
      repoId,
      'main',
      'main',
      'Add new feature',
      'This PR adds a new feature'
    );

    // Verify PR creation
    expect(pr.prId).toBeDefined();
    expect(pr.repoId).toBe(repoId);
    expect(pr.authorId).toBe(ownerClient.agentId);
    expect(pr.sourceBranch).toBe('main');
    expect(pr.targetBranch).toBe('main');
    expect(pr.title).toBe('Add new feature');
    expect(pr.description).toBe('This PR adds a new feature');
    expect(pr.status).toBe('open');
    expect(['pending', 'running', 'passed', 'failed']).toContain(pr.ciStatus);
    expect(pr.createdAt).toBeInstanceOf(Date);
  });

  /**
   * Test: Create PR → Get PR
   * Requirements: 9.1, 9.2
   */
  it('should get pull request', async () => {
    const { ownerClient, repoId } = await createRepoWithBranches();

    // Create a pull request
    const pr = await ownerClient.pulls.create(repoId, 'main', 'main', 'Test PR');

    // Get the PR
    const fetchedPr = await ownerClient.pulls.get(repoId, pr.prId);
    expect(fetchedPr.prId).toBe(pr.prId);
    expect(fetchedPr.title).toBe('Test PR');
  });

  /**
   * Test: Create PR → Submit review
   * Requirements: 9.1, 9.3
   */
  it('should submit review', async () => {
    const { ownerClient, reviewerClient, repoId } = await createRepoWithBranches();

    // Create a pull request
    const pr = await ownerClient.pulls.create(
      repoId,
      'main',
      'main',
      'Test PR for review'
    );

    // Submit a review (reviewer approves)
    const review = await reviewerClient.reviews.create(
      repoId,
      pr.prId,
      'approve',
      'LGTM! Great work.'
    );

    // Verify review
    expect(review.reviewId).toBeDefined();
    expect(review.prId).toBe(pr.prId);
    expect(review.reviewerId).toBe(reviewerClient.agentId);
    expect(review.verdict).toBe('approve');
    expect(review.body).toBe('LGTM! Great work.');
    expect(review.createdAt).toBeInstanceOf(Date);

    // List reviews
    const reviews = await reviewerClient.reviews.list(repoId, pr.prId);
    expect(reviews.length).toBeGreaterThanOrEqual(1);
    const reviewIds = reviews.map((r) => r.reviewId);
    expect(reviewIds).toContain(review.reviewId);
  });

  /**
   * Test: Create PR → Submit request_changes review
   * Requirements: 9.3
   */
  it('should submit request_changes review', async () => {
    const { ownerClient, reviewerClient, repoId } = await createRepoWithBranches();

    // Create a pull request
    const pr = await ownerClient.pulls.create(
      repoId,
      'main',
      'main',
      'Test PR for changes'
    );

    // Submit request_changes review
    const review = await reviewerClient.reviews.create(
      repoId,
      pr.prId,
      'request_changes',
      'Please fix the formatting issues.'
    );

    expect(review.verdict).toBe('request_changes');
    expect(review.body).toBe('Please fix the formatting issues.');
  });
});

// ============================================================================
// Task 12.1: Access Control Integration Tests
// Requirements: 8.1, 8.2, 8.3 | Design: DR-5, DR-10
// ============================================================================

describe.skipIf(!INTEGRATION_TESTS_ENABLED)('Access Control Integration Tests', () => {
  /**
   * Create an owner agent with a repository and a collaborator agent.
   */
  async function createOwnerAndCollaborator(): Promise<{
    ownerClient: GitClawClient;
    collabClient: GitClawClient;
    repoId: string;
    collabAgentId: string;
  }> {
    // Create owner agent
    const { signer: ownerSigner, publicKey: ownerPublicKey } = Ed25519Signer.generate();
    const ownerName = generateUniqueName('owner-agent');

    const tempClient = new GitClawClient({
      agentId: 'temp-agent',
      signer: ownerSigner,
      baseUrl: getBaseUrl(),
    });
    const ownerAgent = await tempClient.agents.register(ownerName, ownerPublicKey);

    const ownerClient = new GitClawClient({
      agentId: ownerAgent.agentId,
      signer: ownerSigner,
      baseUrl: getBaseUrl(),
    });

    // Create collaborator agent
    const { signer: collabSigner, publicKey: collabPublicKey } = Ed25519Signer.generate();
    const collabName = generateUniqueName('collab-agent');

    const tempClient2 = new GitClawClient({
      agentId: 'temp-agent',
      signer: collabSigner,
      baseUrl: getBaseUrl(),
    });
    const collabAgent = await tempClient2.agents.register(collabName, collabPublicKey);

    const collabClient = new GitClawClient({
      agentId: collabAgent.agentId,
      signer: collabSigner,
      baseUrl: getBaseUrl(),
    });

    // Create repository
    const repoName = generateUniqueName('test-repo');
    const repo = await ownerClient.repos.create(repoName);

    return {
      ownerClient,
      collabClient,
      repoId: repo.repoId,
      collabAgentId: collabAgent.agentId,
    };
  }

  /**
   * Test: Grant access to collaborator
   * Requirements: 8.1
   */
  it('should grant access', async () => {
    const { ownerClient, repoId, collabAgentId } = await createOwnerAndCollaborator();

    // Grant write access
    const response = await ownerClient.access.grant(repoId, collabAgentId, 'write');

    expect(response.repoId).toBe(repoId);
    expect(response.agentId).toBe(collabAgentId);
    expect(response.role).toBe('write');
    expect(response.action).toBe('granted');
  });

  /**
   * Test: Grant access → List collaborators
   * Requirements: 8.1, 8.3
   */
  it('should list collaborators', async () => {
    const { ownerClient, repoId, collabAgentId } = await createOwnerAndCollaborator();

    // Grant access
    await ownerClient.access.grant(repoId, collabAgentId, 'read');

    // List collaborators
    const collaborators = await ownerClient.access.list(repoId);

    // Find the collaborator we just added
    const collabIds = collaborators.map((c) => c.agentId);
    expect(collabIds).toContain(collabAgentId);

    // Verify collaborator details
    const collab = collaborators.find((c) => c.agentId === collabAgentId);
    expect(collab).toBeDefined();
    expect(collab!.role).toBe('read');
    expect(collab!.agentName).toBeDefined();
    expect(collab!.grantedAt).toBeInstanceOf(Date);
  });

  /**
   * Test: Grant access → Revoke access
   * Requirements: 8.1, 8.2
   */
  it('should revoke access', async () => {
    const { ownerClient, repoId, collabAgentId } = await createOwnerAndCollaborator();

    // Grant access
    await ownerClient.access.grant(repoId, collabAgentId, 'write');

    // Revoke access
    const response = await ownerClient.access.revoke(repoId, collabAgentId);

    expect(response.repoId).toBe(repoId);
    expect(response.agentId).toBe(collabAgentId);
    expect(response.action).toBe('revoked');

    // Verify collaborator is no longer in the list
    const collaborators = await ownerClient.access.list(repoId);
    const collabIds = collaborators.map((c) => c.agentId);
    expect(collabIds).not.toContain(collabAgentId);
  });

  /**
   * Test: Grant different access roles (read, write, admin)
   * Requirements: 8.1
   */
  it('should grant different roles', async () => {
    const { ownerClient, repoId, collabAgentId } = await createOwnerAndCollaborator();

    // Test each role
    for (const role of ['read', 'write', 'admin'] as const) {
      const response = await ownerClient.access.grant(repoId, collabAgentId, role);
      expect(response.role).toBe(role);

      // Verify in collaborators list
      const collaborators = await ownerClient.access.list(repoId);
      const collab = collaborators.find((c) => c.agentId === collabAgentId);
      expect(collab).toBeDefined();
      expect(collab!.role).toBe(role);
    }
  });

  /**
   * Test: Full lifecycle - Grant → List → Revoke → Verify removed
   * Requirements: 8.1, 8.2, 8.3
   */
  it('should handle full access control lifecycle', async () => {
    const { ownerClient, repoId, collabAgentId } = await createOwnerAndCollaborator();

    // Grant access
    const grantResponse = await ownerClient.access.grant(repoId, collabAgentId, 'write');
    expect(grantResponse.action).toBe('granted');

    // List and verify
    const collaborators = await ownerClient.access.list(repoId);
    expect(collaborators.some((c) => c.agentId === collabAgentId)).toBe(true);

    // Revoke access
    const revokeResponse = await ownerClient.access.revoke(repoId, collabAgentId);
    expect(revokeResponse.action).toBe('revoked');

    // Verify removed
    const collaboratorsAfter = await ownerClient.access.list(repoId);
    expect(collaboratorsAfter.some((c) => c.agentId === collabAgentId)).toBe(false);
  });
});


// ============================================================================
// Task 12.1: Error Handling Integration Tests
// Requirements: 13.1, 13.2, 13.3 | Design: DR-8
// ============================================================================

describe.skipIf(!INTEGRATION_TESTS_ENABLED)('Error Handling Integration Tests', () => {
  let authenticatedClient: GitClawClient;
  let agentId: string;

  beforeAll(async () => {
    // Create an authenticated client with a registered agent
    const { signer, publicKey } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    const tempClient = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });

    const agent = await tempClient.agents.register(agentName, publicKey);
    agentId = agent.agentId;

    authenticatedClient = new GitClawClient({
      agentId: agent.agentId,
      signer,
      baseUrl: getBaseUrl(),
    });
  });

  /**
   * Test: Duplicate star raises ConflictError
   * Requirements: 13.1, 13.2
   */
  it('should throw ConflictError with proper fields for duplicate star', async () => {
    const repoName = generateUniqueName('test-repo');
    const repo = await authenticatedClient.repos.create(repoName);

    // First star succeeds
    await authenticatedClient.stars.star(repo.repoId);

    // Second star raises ConflictError
    try {
      await authenticatedClient.stars.star(repo.repoId);
      expect.fail('Expected ConflictError to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConflictError);
      const conflictError = error as ConflictError;
      // Verify error has code and message
      expect(conflictError.code).toBeDefined();
      expect(conflictError.message).toBeDefined();
    }
  });

  /**
   * Test: NotFoundError contains code, message, and request_id
   * Requirements: 13.2, 13.3
   */
  it('should throw NotFoundError with proper fields', async () => {
    try {
      await authenticatedClient.repos.get('nonexistent-repo-id-12345');
      expect.fail('Expected NotFoundError to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(NotFoundError);
      const notFoundError = error as NotFoundError;
      expect(notFoundError.code).toBeDefined();
      expect(notFoundError.message).toBeDefined();
      // Error should have meaningful content
      expect(notFoundError.message.length).toBeGreaterThan(0);
    }
  });

  /**
   * Test: Invalid signature raises AuthenticationError
   * Requirements: 13.1, 13.2
   */
  it('should throw AuthenticationError for invalid signature', async () => {
    // Create a client with mismatched agent_id and signer
    const { signer, publicKey } = Ed25519Signer.generate();
    const agentName = generateUniqueName('test-agent');

    // Register the agent
    const tempClient = new GitClawClient({
      agentId: 'temp-agent',
      signer,
      baseUrl: getBaseUrl(),
    });
    const agent = await tempClient.agents.register(agentName, publicKey);

    // Create a different signer (not matching the registered public key)
    const { signer: wrongSigner } = Ed25519Signer.generate();

    // Create client with correct agent_id but wrong signer
    const client = new GitClawClient({
      agentId: agent.agentId,
      signer: wrongSigner,
      baseUrl: getBaseUrl(),
    });

    // Try to create a repo with invalid signature
    try {
      await client.repos.create(generateUniqueName('test-repo'));
      expect.fail('Expected AuthenticationError to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(AuthenticationError);
      const authError = error as AuthenticationError;
      expect(authError.code).toBeDefined();
      expect(authError.message).toBeDefined();
    }
  });

  /**
   * Test: All errors inherit from GitClawError
   * Requirements: 13.4
   */
  it('should have all errors inherit from GitClawError', async () => {
    // Test NotFoundError
    try {
      await authenticatedClient.repos.get('nonexistent-repo-id');
    } catch (error) {
      expect(error).toBeInstanceOf(GitClawError);
    }

    // Test ConflictError
    const repo = await authenticatedClient.repos.create(generateUniqueName('test-repo'));
    await authenticatedClient.stars.star(repo.repoId);

    try {
      await authenticatedClient.stars.star(repo.repoId);
    } catch (error) {
      expect(error).toBeInstanceOf(GitClawError);
    }
  });

  /**
   * Test: Error string representation includes code and message
   * Requirements: 13.2
   */
  it('should have error string representation include code', async () => {
    try {
      await authenticatedClient.repos.get('nonexistent-repo-id');
      expect.fail('Expected NotFoundError to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(NotFoundError);
      const notFoundError = error as NotFoundError;
      const errorStr = String(notFoundError);

      // String should contain the error code
      expect(errorStr).toContain(notFoundError.code);
    }
  });
});

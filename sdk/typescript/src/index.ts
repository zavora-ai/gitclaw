/**
 * GitClaw TypeScript SDK
 *
 * Official SDK for interacting with the GitClaw platform - The Git Platform for AI Agents.
 *
 * @packageDocumentation
 */

// Core exports
export { canonicalize, JCSCanonicalizer } from './canonicalize.js';
export { Ed25519Signer, EcdsaSigner } from './signers.js';
export type { Signer } from './signers.js';

// Envelope and signing
export type { SignatureEnvelope } from './envelope.js';
export { EnvelopeBuilder, envelopeToDict, formatTimestamp } from './envelope.js';
export { signEnvelope, computeNonceHash, getCanonicalJson, getMessageHash } from './signing.js';

// Transport
export { HTTPTransport, DEFAULT_RETRY_CONFIG } from './transport.js';
export type { RetryConfig, HTTPTransportOptions } from './transport.js';

// Exceptions
export {
  GitClawError,
  ConfigurationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitedError,
  ValidationError,
  ServerError,
} from './exceptions.js';

// Main client
export { GitClawClient, DEFAULT_BASE_URL, DEFAULT_TIMEOUT } from './client.js';
export type { GitClawClientOptions } from './client.js';

// Resource clients
export {
  AgentsClient,
  ReposClient,
  AccessClient,
  PullsClient,
  ReviewsClient,
  StarsClient,
  TrendingClient,
} from './clients/index.js';

// Git helper
export { GitHelper } from './git.js';

// Testing utilities
export { MockGitClawClient } from './testing/index.js';
export type { MockResponse, MockCall } from './testing/index.js';

// Re-export types
export type * from './types/index.js';

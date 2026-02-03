/**
 * HTTP Transport for GitClaw SDK.
 *
 * Handles HTTP communication with automatic retry logic, signature generation,
 * and error handling.
 *
 * Design Reference: DR-4
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
 */

import { EnvelopeBuilder } from './envelope.js';
import { signEnvelope, computeNonceHash } from './signing.js';
import type { Signer } from './signers.js';
import {
  GitClawError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitedError,
  ValidationError,
  ServerError,
} from './exceptions.js';

/**
 * Configuration for automatic retry behavior.
 *
 * Requirements: 5.1, 5.6
 */
export interface RetryConfig {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries: number;
  /** Backoff multiplier for exponential backoff (default: 2.0) */
  backoffFactor: number;
  /** HTTP status codes that trigger retry (default: [429, 500, 502, 503]) */
  retryOn: number[];
  /** Whether to respect Retry-After header (default: true) */
  respectRetryAfter: boolean;
  /** Maximum backoff time in seconds (default: 60) */
  maxBackoff: number;
  /** Jitter factor for randomization (default: 0.1 = ±10%) */
  jitter: number;
}

/**
 * Default retry configuration.
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  backoffFactor: 2.0,
  retryOn: [429, 500, 502, 503],
  respectRetryAfter: true,
  maxBackoff: 60.0,
  jitter: 0.1,
};

/**
 * Options for HTTPTransport initialization.
 */
export interface HTTPTransportOptions {
  /** Base URL for API requests */
  baseUrl: string;
  /** Agent's unique identifier */
  agentId: string;
  /** Signer instance for request signing */
  signer: Signer;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Retry configuration */
  retryConfig?: Partial<RetryConfig>;
}

/**
 * HTTP response structure from fetch.
 */
interface FetchResponse {
  ok: boolean;
  status: number;
  headers: Headers;
  json(): Promise<unknown>;
}


/**
 * HTTP transport layer with automatic signing and retry logic.
 *
 * Handles:
 * - Automatic signature generation for signed requests
 * - Exponential backoff with jitter for retries
 * - Retry-After header respect for rate limiting
 * - Error response parsing into typed exceptions
 *
 * Design Reference: DR-4
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
 */
export class HTTPTransport {
  readonly baseUrl: string;
  readonly agentId: string;
  readonly signer: Signer;
  readonly timeout: number;
  readonly retryConfig: RetryConfig;
  readonly envelopeBuilder: EnvelopeBuilder;

  /**
   * Initialize HTTP transport.
   *
   * @param options - Transport configuration options
   */
  constructor(options: HTTPTransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.agentId = options.agentId;
    this.signer = options.signer;
    this.timeout = options.timeout ?? 30000;
    this.retryConfig = { ...DEFAULT_RETRY_CONFIG, ...options.retryConfig };
    this.envelopeBuilder = new EnvelopeBuilder(options.agentId);
  }

  /**
   * Make a signed request with automatic retry.
   *
   * @param method - HTTP method (POST, PUT, DELETE, etc.)
   * @param path - API path (e.g., "/v1/repos")
   * @param action - Action name for the signature envelope
   * @param body - Request body (action-specific payload)
   * @returns Parsed JSON response
   * @throws GitClawError on API errors
   *
   * Requirements: 5.4
   */
  async signedRequest(
    method: string,
    path: string,
    action: string,
    body: Record<string, unknown> = {}
  ): Promise<Record<string, unknown>> {
    const makeRequest = async (): Promise<FetchResponse> => {
      // Build envelope with fresh nonce (Requirements: 4.4, 5.4)
      const envelope = this.envelopeBuilder.build(action, body);

      // Sign the envelope
      const signature = signEnvelope(envelope, this.signer);

      // Compute nonce hash
      const nonceHash = computeNonceHash(this.agentId, envelope.nonce);

      // Build request body with nested body field (per design DR-3)
      const requestBody = {
        agentId: envelope.agentId,
        action: envelope.action,
        timestamp: envelope.timestamp,
        nonce: envelope.nonce,
        signature,
        nonceHash,
        body,
      };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      try {
        const response = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        });
        return response;
      } finally {
        clearTimeout(timeoutId);
      }
    };

    return this.executeWithRetry(makeRequest);
  }

  /**
   * Make an unsigned request (for registration, trending, etc.).
   *
   * @param method - HTTP method
   * @param path - API path
   * @param params - Query parameters
   * @param body - Request body (for POST/PUT)
   * @returns Parsed JSON response
   * @throws GitClawError on API errors
   */
  async unsignedRequest(
    method: string,
    path: string,
    params?: Record<string, string | number>,
    body?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const makeRequest = async (): Promise<FetchResponse> => {
      let url = `${this.baseUrl}${path}`;

      // Add query parameters
      if (params && Object.keys(params).length > 0) {
        const searchParams = new URLSearchParams();
        for (const [key, value] of Object.entries(params)) {
          searchParams.append(key, String(value));
        }
        url += `?${searchParams.toString()}`;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      try {
        const options: RequestInit = {
          method,
          headers: {
            'Content-Type': 'application/json',
          },
          signal: controller.signal,
        };

        if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
          options.body = JSON.stringify(body);
        }

        const response = await fetch(url, options);
        return response;
      } finally {
        clearTimeout(timeoutId);
      }
    };

    return this.executeWithRetry(makeRequest);
  }

  /**
   * Execute a request with automatic retry on retryable errors.
   *
   * @param requestFn - Function that makes the HTTP request
   * @returns Parsed JSON response
   * @throws GitClawError on non-retryable errors or after max retries
   *
   * Requirements: 5.2, 5.3, 5.5
   */
  private async executeWithRetry(
    requestFn: () => Promise<FetchResponse>
  ): Promise<Record<string, unknown>> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retryConfig.maxRetries; attempt++) {
      try {
        const response = await requestFn();

        if (response.ok) {
          return (await response.json()) as Record<string, unknown>;
        }

        // Parse error response
        const error = await this.parseErrorResponse(response);

        // Check if we should retry (Requirements: 5.5)
        if (!this.shouldRetry(response.status, attempt)) {
          throw error;
        }

        lastError = error;

        // Calculate backoff time (Requirements: 5.2, 5.3)
        const retryAfter = response.headers.get('Retry-After');
        const waitTime = this.getBackoffTime(attempt, retryAfter);
        await this.sleep(waitTime * 1000);
      } catch (e) {
        if (e instanceof GitClawError) {
          throw e;
        }

        // Network errors are retryable
        if (attempt >= this.retryConfig.maxRetries) {
          throw new ServerError('CONNECTION_ERROR', String(e));
        }

        lastError = e instanceof Error ? e : new Error(String(e));
        const waitTime = this.getBackoffTime(attempt, null);
        await this.sleep(waitTime * 1000);
      }
    }

    // Should not reach here, but just in case
    if (lastError) {
      if (lastError instanceof GitClawError) {
        throw lastError;
      }
      throw new ServerError('MAX_RETRIES_EXCEEDED', lastError.message);
    }

    throw new ServerError('UNKNOWN_ERROR', 'Request failed with no error details');
  }

  /**
   * Determine if a request should be retried.
   *
   * @param statusCode - HTTP status code
   * @param attempt - Current attempt number (0-indexed)
   * @returns True if the request should be retried
   *
   * Requirements: 5.5
   */
  private shouldRetry(statusCode: number, attempt: number): boolean {
    if (attempt >= this.retryConfig.maxRetries) {
      return false;
    }

    return this.retryConfig.retryOn.includes(statusCode);
  }

  /**
   * Calculate backoff time for retry.
   *
   * Uses exponential backoff with jitter, respecting Retry-After header
   * if present.
   *
   * @param attempt - Current attempt number (0-indexed)
   * @param retryAfter - Value of Retry-After header (if present)
   * @returns Time to wait in seconds
   *
   * Requirements: 5.2, 5.3
   */
  getBackoffTime(attempt: number, retryAfter: string | null): number {
    // If Retry-After header is present and we should respect it (Requirements: 5.3)
    if (retryAfter && this.retryConfig.respectRetryAfter) {
      const parsed = parseFloat(retryAfter);
      if (!isNaN(parsed)) {
        return parsed;
      }
    }

    // Exponential backoff: backoff_factor ^ attempt (Requirements: 5.2)
    const baseWait = Math.pow(this.retryConfig.backoffFactor, attempt);

    // Apply jitter (±jitter%)
    const jitterRange = baseWait * this.retryConfig.jitter;
    const jitter = (Math.random() * 2 - 1) * jitterRange;
    const waitTime = baseWait + jitter;

    // Cap at max_backoff
    return Math.min(waitTime, this.retryConfig.maxBackoff);
  }

  /**
   * Parse an error response into a typed exception.
   *
   * @param response - HTTP response with error status
   * @returns Appropriate GitClawError subclass
   */
  private async parseErrorResponse(response: FetchResponse): Promise<GitClawError> {
    let data: Record<string, unknown> = {};
    try {
      data = (await response.json()) as Record<string, unknown>;
    } catch {
      // Ignore JSON parse errors
    }

    const error = (data.error ?? {}) as Record<string, unknown>;
    const code = (error.code as string) ?? 'UNKNOWN_ERROR';
    const message = (error.message as string) ?? `HTTP ${response.status}`;
    const meta = (data.meta ?? {}) as Record<string, unknown>;
    const requestId = meta.requestId as string | undefined;

    const statusCode = response.status;

    if (statusCode === 401) {
      return new AuthenticationError(code, message, requestId);
    } else if (statusCode === 403) {
      return new AuthorizationError(code, message, requestId);
    } else if (statusCode === 404) {
      return new NotFoundError(code, message, requestId);
    } else if (statusCode === 409) {
      return new ConflictError(code, message, requestId);
    } else if (statusCode === 429) {
      const retryAfterStr = response.headers.get('Retry-After') ?? '60';
      const retryAfter = parseInt(retryAfterStr, 10) || 60;
      return new RateLimitedError(code, message, retryAfter, requestId);
    } else if (statusCode >= 500) {
      return new ServerError(code, message, requestId);
    } else {
      return new ValidationError(code, message, requestId);
    }
  }

  /**
   * Sleep for a specified duration.
   *
   * @param ms - Duration in milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

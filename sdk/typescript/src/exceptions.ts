/**
 * GitClaw SDK exception classes.
 *
 * Design Reference: DR-8
 * Requirements: 13.1, 13.2, 13.3, 13.4
 */

/**
 * Base exception for all GitClaw SDK errors.
 *
 * Requirements: 13.4
 */
export class GitClawError extends Error {
  readonly code: string;
  readonly requestId?: string;

  constructor(code: string, message: string, requestId?: string) {
    super(`[${code}] ${message}`);
    this.name = 'GitClawError';
    this.code = code;
    this.requestId = requestId;

    // Maintain proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when SDK configuration is invalid or missing.
 */
export class ConfigurationError extends GitClawError {
  constructor(message: string) {
    super('CONFIGURATION_ERROR', message);
    this.name = 'ConfigurationError';
  }
}

/**
 * Raised when signature validation fails.
 *
 * Requirements: 13.1
 */
export class AuthenticationError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'AuthenticationError';
  }
}

/**
 * Raised when access is denied.
 *
 * Requirements: 13.1
 */
export class AuthorizationError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'AuthorizationError';
  }
}

/**
 * Raised when a resource is not found.
 *
 * Requirements: 13.1
 */
export class NotFoundError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'NotFoundError';
  }
}

/**
 * Raised on conflicts (duplicate star, merge conflicts, etc.).
 *
 * Requirements: 13.1
 */
export class ConflictError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'ConflictError';
  }
}

/**
 * Raised when rate limited.
 *
 * Requirements: 13.1, 13.3
 */
export class RateLimitedError extends GitClawError {
  readonly retryAfter: number;

  constructor(code: string, message: string, retryAfter: number, requestId?: string) {
    super(code, message, requestId);
    this.name = 'RateLimitedError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Raised on validation errors.
 *
 * Requirements: 13.1
 */
export class ValidationError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'ValidationError';
  }
}

/**
 * Raised on server errors (5xx).
 *
 * Requirements: 13.1
 */
export class ServerError extends GitClawError {
  constructor(code: string, message: string, requestId?: string) {
    super(code, message, requestId);
    this.name = 'ServerError';
  }
}

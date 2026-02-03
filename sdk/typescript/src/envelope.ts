/**
 * Signature envelope builder for GitClaw SDK.
 *
 * Constructs the canonical envelope structure that gets signed for API requests.
 *
 * Design Reference: DR-3
 * Requirements: 2.4, 4.1, 4.2
 */

import { v4 as uuidv4 } from 'uuid';

/**
 * The canonical JSON structure containing all fields that get signed.
 *
 * Per GitClaw protocol, every mutating action requires a signature over
 * this envelope structure.
 */
export interface SignatureEnvelope {
  agentId: string;
  action: string;
  timestamp: string;
  nonce: string;
  body: Record<string, unknown>;
}

/**
 * Convert a SignatureEnvelope to a dictionary for canonicalization.
 *
 * @param envelope - The envelope to convert
 * @returns Object with camelCase keys matching GitClaw API format
 */
export function envelopeToDict(envelope: SignatureEnvelope): Record<string, unknown> {
  return {
    agentId: envelope.agentId,
    action: envelope.action,
    timestamp: envelope.timestamp,
    nonce: envelope.nonce,
    body: envelope.body,
  };
}

/**
 * Format a Date as ISO 8601 with Z suffix (no milliseconds).
 *
 * @param date - Date to format
 * @returns ISO 8601 formatted string with Z suffix
 */
export function formatTimestamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Builder for creating SignatureEnvelope instances.
 *
 * Automatically generates UUID v4 nonces and timestamps.
 */
export class EnvelopeBuilder {
  private agentId: string;

  /**
   * Create an EnvelopeBuilder for a specific agent.
   *
   * @param agentId - The agent's unique identifier
   */
  constructor(agentId: string) {
    this.agentId = agentId;
  }

  /**
   * Build a new SignatureEnvelope with auto-generated nonce and timestamp.
   *
   * @param action - The action being performed (e.g., "repo_create", "star")
   * @param body - Action-specific payload (defaults to empty object)
   * @returns SignatureEnvelope ready for signing
   *
   * Requirements: 4.1, 4.2
   */
  build(action: string, body: Record<string, unknown> = {}): SignatureEnvelope {
    return {
      agentId: this.agentId,
      action,
      timestamp: formatTimestamp(new Date()),
      nonce: uuidv4(),
      body,
    };
  }
}

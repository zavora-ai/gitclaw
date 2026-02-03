/**
 * Signature generation for GitClaw SDK.
 *
 * Implements the complete signing flow: envelope -> canonicalize -> hash -> sign -> encode.
 *
 * Design Reference: DR-3
 * Requirements: 2.5, 2.6, 2.7, 4.3
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonicalize.js';
import { SignatureEnvelope, envelopeToDict } from './envelope.js';
import type { Signer } from './signers.js';

/**
 * Sign a SignatureEnvelope and return the base64-encoded signature.
 *
 * The signing process:
 * 1. Convert envelope to dictionary
 * 2. Canonicalize using JCS (RFC 8785)
 * 3. Compute SHA256 hash of canonical JSON
 * 4. Sign the hash with the provided signer
 * 5. Encode signature as base64
 *
 * @param envelope - The SignatureEnvelope to sign
 * @param signer - A Signer instance (Ed25519 or ECDSA)
 * @returns Base64-encoded signature string
 *
 * Requirements: 2.5, 2.6, 2.7
 */
export function signEnvelope(envelope: SignatureEnvelope, signer: Signer): string {
  // Step 1: Convert to dict
  const envelopeDict = envelopeToDict(envelope);

  // Step 2: Canonicalize
  const canonicalJson = canonicalize(envelopeDict);

  // Step 3: Hash
  const messageHash = sha256(new TextEncoder().encode(canonicalJson));

  // Step 4: Sign
  const signatureBytes = signer.sign(messageHash);

  // Step 5: Encode
  return Buffer.from(signatureBytes).toString('base64');
}

/**
 * Compute the nonce hash for replay detection.
 *
 * The nonce hash is computed as SHA256(agent_id + ":" + nonce) and
 * returned as a hex string. This is used by the backend to detect
 * replay attacks.
 *
 * @param agentId - The agent's unique identifier
 * @param nonce - The UUID v4 nonce from the envelope
 * @returns Hex-encoded SHA256 hash
 *
 * Requirements: 4.3
 */
export function computeNonceHash(agentId: string, nonce: string): string {
  const data = `${agentId}:${nonce}`;
  const hash = sha256(new TextEncoder().encode(data));
  return bytesToHex(hash);
}

/**
 * Get the canonical JSON representation of an envelope.
 *
 * Useful for debugging and verification.
 *
 * @param envelope - The SignatureEnvelope to canonicalize
 * @returns Canonical JSON string
 */
export function getCanonicalJson(envelope: SignatureEnvelope): string {
  return canonicalize(envelopeToDict(envelope));
}

/**
 * Get the SHA256 hash that would be signed for an envelope.
 *
 * Useful for debugging and verification.
 *
 * @param envelope - The SignatureEnvelope to hash
 * @returns 32-byte SHA256 hash as Uint8Array
 */
export function getMessageHash(envelope: SignatureEnvelope): Uint8Array {
  const canonicalJson = canonicalize(envelopeToDict(envelope));
  return sha256(new TextEncoder().encode(canonicalJson));
}

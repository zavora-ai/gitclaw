/**
 * Property-based tests for signature generation and transport.
 *
 * Feature: gitclaw-sdk
 * Property 1: Signature generation produces backend-compatible signatures
 * Property 4: Retry generates new nonces
 * Validates: Requirements 2.4, 2.5, 2.6, 2.7, 4.4, 5.4 | Design: DR-3, DR-4
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { Ed25519Signer, EcdsaSigner } from '../src/signers.js';
import { EnvelopeBuilder } from '../src/envelope.js';
import { signEnvelope, computeNonceHash, getCanonicalJson, getMessageHash } from '../src/signing.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

describe('Signature Generation', () => {
  /**
   * Property 1: Signature generation produces backend-compatible signatures
   *
   * For any valid agent_id, signer, action, and body, the SDK's signature
   * generation process SHALL produce a signature that can be verified.
   *
   * This property validates the complete signing flow:
   * - Envelope construction with all required fields
   * - JCS canonicalization of the envelope
   * - SHA256 hashing of the canonical JSON
   * - Signing the hash with the private key
   * - Base64 encoding of the signature
   *
   * **Validates: Requirements 2.4, 2.5, 2.6, 2.7** | **Design: DR-3**
   */
  it('Ed25519 signature generation produces verifiable signatures', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }), // agentId
        fc.string({ minLength: 1, maxLength: 50 }),  // action
        fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ maxLength: 100 }), { maxKeys: 10 }), // body
        (agentId, action, body) => {
          // Generate a keypair
          const { signer } = Ed25519Signer.generate();

          // Build envelope
          const builder = new EnvelopeBuilder(agentId);
          const envelope = builder.build(action, body);

          // Verify envelope has all required fields (Requirement 2.4)
          expect(envelope.agentId).toBe(agentId);
          expect(envelope.action).toBe(action);
          expect(envelope.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
          expect(envelope.nonce).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
          expect(envelope.body).toEqual(body);

          // Sign the envelope (Requirements 2.5, 2.6, 2.7)
          const signature = signEnvelope(envelope, signer);

          // Verify signature is base64 encoded
          expect(() => Buffer.from(signature, 'base64')).not.toThrow();
          const sigBytes = Buffer.from(signature, 'base64');
          expect(sigBytes.length).toBe(64); // Ed25519 signatures are 64 bytes

          // Verify the signature can be verified
          const messageHash = getMessageHash(envelope);
          expect(signer.verify(sigBytes, messageHash)).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * Property 1 (ECDSA variant): Signature generation produces verifiable signatures
   *
   * **Validates: Requirements 2.4, 2.5, 2.6, 2.7** | **Design: DR-3**
   */
  it('ECDSA signature generation produces verifiable signatures', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }), // agentId
        fc.string({ minLength: 1, maxLength: 50 }),  // action
        fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ maxLength: 100 }), { maxKeys: 10 }), // body
        (agentId, action, body) => {
          // Generate a keypair
          const { signer } = EcdsaSigner.generate();

          // Build envelope
          const builder = new EnvelopeBuilder(agentId);
          const envelope = builder.build(action, body);

          // Sign the envelope
          const signature = signEnvelope(envelope, signer);

          // Verify signature is base64 encoded
          expect(() => Buffer.from(signature, 'base64')).not.toThrow();
          const sigBytes = Buffer.from(signature, 'base64');
          // ECDSA DER signatures are typically 68-72 bytes
          expect(sigBytes.length).toBeGreaterThanOrEqual(68);
          expect(sigBytes.length).toBeLessThanOrEqual(72);

          // Verify the signature can be verified
          const messageHash = getMessageHash(envelope);
          expect(signer.verify(sigBytes, messageHash)).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * Test that canonical JSON is deterministic.
   *
   * The same envelope should always produce the same canonical JSON.
   */
  it('canonical JSON is deterministic', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 50 }),
        fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ maxLength: 100 }), { maxKeys: 10 }),
        (agentId, action, body) => {
          const builder = new EnvelopeBuilder(agentId);
          const envelope = builder.build(action, body);

          // Get canonical JSON twice
          const canonical1 = getCanonicalJson(envelope);
          const canonical2 = getCanonicalJson(envelope);

          expect(canonical1).toBe(canonical2);
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * Test that message hash is deterministic.
   */
  it('message hash is deterministic', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 50 }),
        fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ maxLength: 100 }), { maxKeys: 10 }),
        (agentId, action, body) => {
          const builder = new EnvelopeBuilder(agentId);
          const envelope = builder.build(action, body);

          const hash1 = getMessageHash(envelope);
          const hash2 = getMessageHash(envelope);

          expect(hash1).toEqual(hash2);
          expect(hash1.length).toBe(32); // SHA256 produces 32 bytes
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('Nonce Hash Computation', () => {
  /**
   * Property 14: Nonce hash computation
   *
   * For any agent_id and nonce, the computed nonce_hash SHALL equal
   * SHA256(agent_id + ":" + nonce) encoded as a hex string.
   *
   * **Validates: Requirements 4.3** | **Design: DR-3**
   */
  it('nonce hash equals SHA256(agentId:nonce) as hex', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.uuid(),
        (agentId, nonce) => {
          const computed = computeNonceHash(agentId, nonce);

          // Manually compute expected hash
          const data = `${agentId}:${nonce}`;
          const expected = bytesToHex(sha256(new TextEncoder().encode(data)));

          expect(computed).toBe(expected);
          expect(computed.length).toBe(64); // SHA256 hex is 64 chars
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('Nonce Uniqueness', () => {
  /**
   * Property 3: Nonce uniqueness across requests
   *
   * For any sequence of N signed requests made by the SDK, all N nonces
   * SHALL be unique UUID v4 values.
   *
   * **Validates: Requirements 4.1, 4.2** | **Design: DR-3**
   */
  it('each envelope build generates a unique nonce', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.integer({ min: 2, max: 50 }),
        (agentId, count) => {
          const builder = new EnvelopeBuilder(agentId);
          const nonces = new Set<string>();

          for (let i = 0; i < count; i++) {
            const envelope = builder.build('test_action', {});
            // Verify UUID v4 format
            expect(envelope.nonce).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
            nonces.add(envelope.nonce);
          }

          // All nonces should be unique
          expect(nonces.size).toBe(count);
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('Retry Behavior', () => {
  /**
   * Property 4: Retry generates new nonces
   *
   * For any request that is retried due to a retryable error, each retry
   * attempt SHALL use a different nonce than all previous attempts.
   *
   * This test simulates the retry behavior by building multiple envelopes
   * (as would happen during retries) and verifying nonce uniqueness.
   *
   * **Validates: Requirements 4.4, 5.4** | **Design: DR-4**
   */
  it('simulated retries generate unique nonces', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 50 }),
        fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ maxLength: 100 }), { maxKeys: 5 }),
        fc.integer({ min: 1, max: 5 }), // number of retries
        (agentId, action, body, retryCount) => {
          const builder = new EnvelopeBuilder(agentId);
          const nonces: string[] = [];

          // Simulate initial request + retries
          for (let attempt = 0; attempt <= retryCount; attempt++) {
            const envelope = builder.build(action, body);
            nonces.push(envelope.nonce);
          }

          // All nonces should be unique
          const uniqueNonces = new Set(nonces);
          expect(uniqueNonces.size).toBe(nonces.length);
        }
      ),
      { numRuns: 100 }
    );
  });
});

/**
 * Property-based tests for cryptographic signers.
 *
 * Feature: gitclaw-sdk
 * Property 12: Ed25519 key loading round-trip
 * Property 13: ECDSA key loading round-trip
 * Validates: Requirements 2.1, 2.2, 2.3 | Design: DR-1
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { Ed25519Signer, EcdsaSigner } from '../src/signers.js';

describe('Ed25519 Signer', () => {
  /**
   * Property 12: Ed25519 key loading round-trip
   *
   * For any Ed25519 private key, loading the key from PEM format, extracting
   * the public key, and using it to verify a signature created by the signer
   * SHALL succeed.
   *
   * **Validates: Requirements 2.1, 2.3** | **Design: DR-1**
   */
  it('key loading round-trip: generate -> PEM -> load -> sign/verify', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 1000 }), (message) => {
        // Generate a keypair
        const { signer } = Ed25519Signer.generate();

        // Get PEM representation
        const pem = signer.privateKeyPem();

        // Load from PEM
        const loadedSigner = Ed25519Signer.fromPem(pem);

        // Sign with original signer
        const signature = signer.sign(message);

        // Verify with loaded signer (uses same public key)
        expect(loadedSigner.verify(signature, message)).toBe(true);

        // Sign with loaded signer and verify with original
        const signature2 = loadedSigner.sign(message);
        expect(signer.verify(signature2, message)).toBe(true);

        // Public keys should match
        expect(signer.publicKey()).toBe(loadedSigner.publicKey());
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Test that Ed25519 keys can be loaded from raw bytes.
   *
   * Validates: Requirements 2.1 | Design: DR-1
   */
  it('from bytes round-trip: same seed produces same key', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
        // Create signer from raw bytes
        const signer = Ed25519Signer.fromBytes(seed);

        // Sign a test message
        const message = new TextEncoder().encode('test message');
        const signature = signer.sign(message);

        // Verify signature
        expect(signer.verify(signature, message)).toBe(true);

        // Create another signer from same bytes - should produce same key
        const signer2 = Ed25519Signer.fromBytes(seed);
        expect(signer.publicKey()).toBe(signer2.publicKey());
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Test that Ed25519 signatures are deterministic for the same key and message.
   *
   * Note: Ed25519 is deterministic by design (no random nonce).
   */
  it('signatures are deterministic', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 1000 }), (message) => {
        const { signer } = Ed25519Signer.generate();

        const sig1 = signer.sign(message);
        const sig2 = signer.sign(message);

        expect(sig1).toEqual(sig2);
      }),
      { numRuns: 100 }
    );
  });

  it('signature length is always 64 bytes', () => {
    const { signer } = Ed25519Signer.generate();

    const messages = [
      new Uint8Array(0),
      new Uint8Array([0x78]),
      new Uint8Array(1000).fill(0x78),
    ];

    for (const msg of messages) {
      const sig = signer.sign(msg);
      expect(sig.length).toBe(64);
    }
  });

  it('public key has correct format', () => {
    const { publicKey } = Ed25519Signer.generate();

    expect(publicKey.startsWith('ed25519:')).toBe(true);

    // Extract base64 part
    const b64Part = publicKey.slice(8); // Remove "ed25519:" prefix
    const decoded = Buffer.from(b64Part, 'base64');
    expect(decoded.length).toBe(32);
  });
});

describe('ECDSA P-256 Signer', () => {
  /**
   * Property 13: ECDSA key loading round-trip
   *
   * For any ECDSA P-256 private key, loading the key from PEM format, extracting
   * the public key, and using it to verify a signature created by the signer
   * SHALL succeed.
   *
   * **Validates: Requirements 2.2, 2.3** | **Design: DR-1**
   */
  it('key loading round-trip: generate -> PEM -> load -> sign/verify', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 1000 }), (message) => {
        // Generate a keypair
        const { signer } = EcdsaSigner.generate();

        // Get PEM representation
        const pem = signer.privateKeyPem();

        // Load from PEM
        const loadedSigner = EcdsaSigner.fromPem(pem);

        // Sign with original signer
        const signature = signer.sign(message);

        // Verify with loaded signer (uses same public key)
        expect(loadedSigner.verify(signature, message)).toBe(true);

        // Sign with loaded signer and verify with original
        const signature2 = loadedSigner.sign(message);
        expect(signer.verify(signature2, message)).toBe(true);

        // Public keys should match
        expect(signer.publicKey()).toBe(loadedSigner.publicKey());
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Test that ECDSA signatures can be verified.
   *
   * Note: ECDSA signatures are NOT deterministic (they use a random k value).
   */
  it('signature verification works', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 1000 }), (message) => {
        const { signer } = EcdsaSigner.generate();

        const sig = signer.sign(message);
        expect(signer.verify(sig, message)).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it('signatures are DER encoded with expected length', () => {
    const { signer } = EcdsaSigner.generate();

    // Sign multiple messages - DER encoding produces variable length
    for (let i = 0; i < 10; i++) {
      const sig = signer.sign(new TextEncoder().encode(`message ${i}`));
      // DER-encoded P-256 signatures are typically 68-72 bytes
      expect(sig.length).toBeGreaterThanOrEqual(68);
      expect(sig.length).toBeLessThanOrEqual(72);
    }
  });

  it('public key has correct format', () => {
    const { publicKey } = EcdsaSigner.generate();

    expect(publicKey.startsWith('ecdsa:')).toBe(true);

    // Extract base64 part
    const b64Part = publicKey.slice(6); // Remove "ecdsa:" prefix
    const decoded = Buffer.from(b64Part, 'base64');
    // Compressed P-256 public key is 33 bytes (1 byte prefix + 32 bytes x-coordinate)
    expect(decoded.length).toBe(33);
  });
});

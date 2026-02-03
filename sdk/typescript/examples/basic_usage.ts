#!/usr/bin/env npx ts-node
/**
 * Basic GitClaw SDK usage example.
 *
 * This example demonstrates core SDK functionality as it's implemented.
 * Run with: npx ts-node examples/basic_usage.ts
 * Or: npm run example
 */

import { GitClawError, ConfigurationError } from '../src/exceptions.js';
import { canonicalize } from '../src/canonicalize.js';
import { Ed25519Signer, EcdsaSigner } from '../src/signers.js';

console.log('=== GitClaw SDK Basic Usage Example ===\n');

// 1. Test exception hierarchy
console.log('1. Testing exception classes...');
try {
  throw new ConfigurationError('Missing GITCLAW_AGENT_ID');
} catch (e) {
  if (e instanceof GitClawError) {
    console.log(`   Caught GitClawError: ${e.message}`);
    console.log(`   Code: ${e.code}`);
  }
}

console.log('\n   OK: Exception classes working\n');

// 2. Test JCS Canonicalization
console.log('2. Testing JCS Canonicalization...');

// Test key sorting
const envelope = {
  nonce: '550e8400-e29b-41d4-a716-446655440000',
  agentId: 'agent-123',
  action: 'star',
  timestamp: '2024-01-15T10:30:00Z',
  body: { repoId: 'repo-456', reason: 'Great project' },
};

const canonical = canonicalize(envelope);
console.log(`   Input: ${JSON.stringify(envelope)}`);
console.log(`   Canonical: ${canonical}`);

// Verify keys are sorted
const parsed = JSON.parse(canonical);
const keys = Object.keys(parsed);
console.log(`   Key order: ${JSON.stringify(keys)}`);
const sortedKeys = [...keys].sort();
if (JSON.stringify(keys) !== JSON.stringify(sortedKeys)) {
  throw new Error('Keys should be sorted');
}

// Test round-trip: canonicalize -> parse -> canonicalize should be identical
const canonical2 = canonicalize(JSON.parse(canonical));
if (canonical !== canonical2) {
  throw new Error('Round-trip should produce identical output');
}
console.log('   Round-trip: OK');

// Test number formatting
console.log(`   Number 42: ${canonicalize(42)}`);
console.log(`   Number 3.14: ${canonicalize(3.14)}`);
console.log(`   Number -0.0: ${canonicalize(-0.0)}`);

// Test string escaping
const newlineStr = 'hello\nworld';
const quoteStr = 'say "hi"';
console.log(`   String with newline: ${canonicalize(newlineStr)}`);
console.log(`   String with quote: ${canonicalize(quoteStr)}`);

console.log('\n   OK: JCS Canonicalization working\n');

// 3. Test Ed25519 Signing
console.log('3. Testing Ed25519 Signing...');

// Generate a new keypair
const { signer: ed25519Signer, publicKey: ed25519PublicKey } = Ed25519Signer.generate();
console.log(`   Generated public key: ${ed25519PublicKey.slice(0, 50)}...`);

// Sign a message
const message = new TextEncoder().encode('Hello, GitClaw!');
const signature = ed25519Signer.sign(message);
console.log(`   Signature length: ${signature.length} bytes`);

// Verify the signature
const isValid = ed25519Signer.verify(signature, message);
console.log(`   Signature valid: ${isValid}`);
if (!isValid) {
  throw new Error('Signature should be valid');
}

// Test PEM round-trip
const pem = ed25519Signer.privateKeyPem();
const signer2 = Ed25519Signer.fromPem(pem);
const signature2 = signer2.sign(message);
if (!ed25519Signer.verify(signature2, message)) {
  throw new Error('PEM round-trip should work');
}
console.log('   PEM round-trip: OK');

console.log('\n   OK: Ed25519 Signing working\n');

// 4. Test ECDSA P-256 Signing
console.log('4. Testing ECDSA P-256 Signing...');

// Generate a new keypair
const { signer: ecdsaSigner, publicKey: ecdsaPublicKey } = EcdsaSigner.generate();
console.log(`   Generated public key: ${ecdsaPublicKey.slice(0, 50)}...`);

// Sign a message
const ecdsaSignature = ecdsaSigner.sign(message);
console.log(`   Signature length: ${ecdsaSignature.length} bytes (DER encoded)`);

// Verify the signature
const ecdsaIsValid = ecdsaSigner.verify(ecdsaSignature, message);
console.log(`   Signature valid: ${ecdsaIsValid}`);
if (!ecdsaIsValid) {
  throw new Error('Signature should be valid');
}

// Test PEM round-trip
const ecdsaPem = ecdsaSigner.privateKeyPem();
const ecdsaSigner2 = EcdsaSigner.fromPem(ecdsaPem);
const ecdsaSignature2 = ecdsaSigner2.sign(message);
if (!ecdsaSigner.verify(ecdsaSignature2, message)) {
  throw new Error('PEM round-trip should work');
}
console.log('   PEM round-trip: OK');

console.log('\n   OK: ECDSA P-256 Signing working\n');

// 5. Test Signature Envelope Building
console.log('5. Testing Signature Envelope Building...');

import { EnvelopeBuilder } from '../src/envelope.js';
import { signEnvelope, computeNonceHash } from '../src/signing.js';

const agentId = 'agent-123';
const builder = new EnvelopeBuilder(agentId);

const testEnvelope = builder.build('star', { repoId: 'repo-456' });
console.log(`   Agent ID: ${testEnvelope.agentId}`);
console.log(`   Action: ${testEnvelope.action}`);
console.log(`   Nonce: ${testEnvelope.nonce}`);
console.log(`   Timestamp: ${testEnvelope.timestamp}`);

// Sign the envelope
const envelopeSignature = signEnvelope(testEnvelope, ed25519Signer);
console.log(`   Signature: ${envelopeSignature.slice(0, 30)}...`);

// Compute nonce hash
const nonceHash = computeNonceHash(agentId, testEnvelope.nonce);
console.log(`   Nonce hash: ${nonceHash.slice(0, 30)}...`);

console.log('\n   OK: Signature Envelope Building working\n');

// 6. Test Client Initialization (without making actual API calls)
console.log('6. Testing Client Initialization...');

import { GitClawClient } from '../src/client.js';

const client = new GitClawClient({
  agentId: 'test-agent-id',
  signer: ed25519Signer,
  baseUrl: 'https://api.gitclaw.dev',
  timeout: 30000,
});

console.log(`   Agent ID: ${client.agentId}`);
console.log(`   Base URL: ${client.baseUrl}`);
console.log(`   Timeout: ${client.timeout}ms`);
console.log(`   Has agents client: ${!!client.agents}`);
console.log(`   Has repos client: ${!!client.repos}`);
console.log(`   Has stars client: ${!!client.stars}`);
console.log(`   Has pulls client: ${!!client.pulls}`);
console.log(`   Has reviews client: ${!!client.reviews}`);
console.log(`   Has access client: ${!!client.access}`);
console.log(`   Has trending client: ${!!client.trending}`);

console.log('\n   OK: Client Initialization working\n');

console.log('=== All examples completed successfully! ===');

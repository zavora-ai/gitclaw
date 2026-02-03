/**
 * Cryptographic signers for GitClaw SDK.
 *
 * Supports Ed25519 and ECDSA P-256 signing algorithms.
 */

import * as ed from '@noble/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as fs from 'fs';

// Configure ed25519 to use sha512
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * Abstract interface for cryptographic signers.
 */
export interface Signer {
  /**
   * Sign a message and return the signature bytes.
   */
  sign(message: Uint8Array): Uint8Array;

  /**
   * Return the public key in base64 format with type prefix.
   */
  publicKey(): string;

  /**
   * Verify a signature (for testing purposes).
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean;
}

/**
 * Ed25519 digital signature implementation.
 */
export class Ed25519Signer implements Signer {
  private privateKey: Uint8Array;
  private pubKey: Uint8Array;

  /**
   * Initialize with an Ed25519 private key.
   *
   * @param privateKey - 32-byte Ed25519 private key seed
   */
  private constructor(privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error(`Ed25519 private key must be 32 bytes, got ${privateKey.length}`);
    }
    this.privateKey = privateKey;
    this.pubKey = ed.getPublicKey(privateKey);
  }

  /**
   * Sign a message using Ed25519.
   *
   * @param message - The message bytes to sign
   * @returns 64-byte Ed25519 signature
   */
  sign(message: Uint8Array): Uint8Array {
    return ed.sign(message, this.privateKey);
  }

  /**
   * Return the public key as base64 with ed25519: prefix.
   *
   * @returns String in format "ed25519:<base64_public_key>"
   */
  publicKey(): string {
    return `ed25519:${Buffer.from(this.pubKey).toString('base64')}`;
  }

  /**
   * Return the raw 32-byte public key.
   */
  publicKeyBytes(): Uint8Array {
    return this.pubKey;
  }

  /**
   * Return the public key in PEM format.
   */
  publicKeyPem(): string {
    // Ed25519 public key in SubjectPublicKeyInfo format
    // OID for Ed25519: 1.3.101.112
    const oid = new Uint8Array([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    const bitString = new Uint8Array([0x03, 0x21, 0x00, ...this.pubKey]);
    const spki = new Uint8Array([0x30, oid.length + bitString.length, ...oid, ...bitString]);

    const b64 = Buffer.from(spki).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
  }

  /**
   * Return the private key in PEM format (for storage).
   */
  privateKeyPem(): string {
    // Ed25519 private key in PKCS#8 format
    // OID for Ed25519: 1.3.101.112
    const oid = new Uint8Array([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    const privateKeyOctet = new Uint8Array([0x04, 0x20, ...this.privateKey]);
    const privateKeyInfo = new Uint8Array([0x04, privateKeyOctet.length, ...privateKeyOctet]);
    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const pkcs8 = new Uint8Array([
      0x30,
      version.length + oid.length + privateKeyInfo.length,
      ...version,
      ...oid,
      ...privateKeyInfo,
    ]);

    const b64 = Buffer.from(pkcs8).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
  }

  /**
   * Verify a signature (for testing purposes).
   *
   * @param signature - The signature to verify
   * @param message - The original message
   * @returns True if valid, false otherwise
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    try {
      return ed.verify(signature, message, this.pubKey);
    } catch {
      return false;
    }
  }

  /**
   * Load an Ed25519 signer from a PEM file.
   *
   * @param path - Path to PEM file containing Ed25519 private key
   * @returns Ed25519Signer instance
   */
  static fromPemFile(path: string): Ed25519Signer {
    const pemData = fs.readFileSync(path, 'utf-8');
    return Ed25519Signer.fromPem(pemData);
  }

  /**
   * Load an Ed25519 signer from a PEM string.
   *
   * @param pemString - PEM-encoded Ed25519 private key
   * @returns Ed25519Signer instance
   */
  static fromPem(pemString: string): Ed25519Signer {
    // Extract base64 content from PEM
    const lines = pemString.split('\n');
    const b64Lines = lines.filter(
      (line) => !line.startsWith('-----') && line.trim().length > 0
    );
    const b64 = b64Lines.join('');
    const der = Buffer.from(b64, 'base64');

    // Parse PKCS#8 structure to extract the 32-byte private key
    // PKCS#8 for Ed25519: SEQUENCE { version, algorithm, privateKey }
    // The privateKey is an OCTET STRING containing another OCTET STRING with the 32-byte key
    const privateKey = extractEd25519PrivateKey(der);
    return new Ed25519Signer(privateKey);
  }

  /**
   * Load an Ed25519 signer from raw 32-byte private key.
   *
   * @param keyBytes - 32-byte Ed25519 private key seed
   * @returns Ed25519Signer instance
   */
  static fromBytes(keyBytes: Uint8Array): Ed25519Signer {
    return new Ed25519Signer(keyBytes);
  }

  /**
   * Generate a new Ed25519 keypair.
   *
   * @returns Object with signer and publicKey string
   */
  static generate(): { signer: Ed25519Signer; publicKey: string } {
    const privateKey = ed.utils.randomPrivateKey();
    const signer = new Ed25519Signer(privateKey);
    return { signer, publicKey: signer.publicKey() };
  }
}

/**
 * ECDSA P-256 digital signature implementation.
 */
export class EcdsaSigner implements Signer {
  private privateKey: Uint8Array;
  private pubKey: Uint8Array;

  /**
   * Initialize with an ECDSA P-256 private key.
   *
   * @param privateKey - 32-byte ECDSA P-256 private key
   */
  private constructor(privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error(`ECDSA P-256 private key must be 32 bytes, got ${privateKey.length}`);
    }
    this.privateKey = privateKey;
    // Get compressed public key (33 bytes)
    this.pubKey = p256.getPublicKey(privateKey, true);
  }

  /**
   * Sign a message using ECDSA P-256 with SHA-256.
   *
   * @param message - The message bytes to sign
   * @returns DER-encoded ECDSA signature
   */
  sign(message: Uint8Array): Uint8Array {
    const sig = p256.sign(message, this.privateKey);
    return sig.toDERRawBytes();
  }

  /**
   * Return the public key as base64 with ecdsa: prefix.
   *
   * @returns String in format "ecdsa:<base64_compressed_public_key>"
   */
  publicKey(): string {
    return `ecdsa:${Buffer.from(this.pubKey).toString('base64')}`;
  }

  /**
   * Return the compressed public key bytes.
   */
  publicKeyBytes(): Uint8Array {
    return this.pubKey;
  }

  /**
   * Return the public key in PEM format.
   */
  publicKeyPem(): string {
    // P-256 public key in SubjectPublicKeyInfo format
    // OID for P-256: 1.2.840.10045.3.1.7
    // OID for EC public key: 1.2.840.10045.2.1
    const uncompressedPubKey = p256.getPublicKey(this.privateKey, false);
    const algorithm = new Uint8Array([
      0x30,
      0x13,
      0x06,
      0x07,
      0x2a,
      0x86,
      0x48,
      0xce,
      0x3d,
      0x02,
      0x01, // ecPublicKey OID
      0x06,
      0x08,
      0x2a,
      0x86,
      0x48,
      0xce,
      0x3d,
      0x03,
      0x01,
      0x07, // P-256 OID
    ]);
    const bitString = new Uint8Array([0x03, uncompressedPubKey.length + 1, 0x00, ...uncompressedPubKey]);
    const spki = new Uint8Array([0x30, algorithm.length + bitString.length, ...algorithm, ...bitString]);

    const b64 = Buffer.from(spki).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
  }

  /**
   * Return the private key in PEM format (for storage).
   */
  privateKeyPem(): string {
    // ECDSA private key in PKCS#8 format
    // Structure: SEQUENCE { version, algorithm, privateKey }
    // where privateKey is OCTET STRING containing EC private key

    // Build the inner EC private key (SEC1 format)
    const ecVersion = new Uint8Array([0x02, 0x01, 0x01]); // version 1
    const privateKeyOctet = new Uint8Array([0x04, 0x20, ...this.privateKey]);

    // EC private key without optional parameters (simpler format)
    const ecPrivateKeyLen = ecVersion.length + privateKeyOctet.length;
    const ecPrivateKey = new Uint8Array([0x30, ecPrivateKeyLen, ...ecVersion, ...privateKeyOctet]);

    // PKCS#8 wrapper
    const pkcs8Version = new Uint8Array([0x02, 0x01, 0x00]); // version 0
    const algorithm = new Uint8Array([
      0x30,
      0x13,
      0x06,
      0x07,
      0x2a,
      0x86,
      0x48,
      0xce,
      0x3d,
      0x02,
      0x01, // ecPublicKey OID
      0x06,
      0x08,
      0x2a,
      0x86,
      0x48,
      0xce,
      0x3d,
      0x03,
      0x01,
      0x07, // P-256 OID
    ]);
    const privateKeyInfo = new Uint8Array([0x04, ecPrivateKey.length, ...ecPrivateKey]);

    const totalLen = pkcs8Version.length + algorithm.length + privateKeyInfo.length;
    const pkcs8 = new Uint8Array([0x30, totalLen, ...pkcs8Version, ...algorithm, ...privateKeyInfo]);

    const b64 = Buffer.from(pkcs8).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
  }

  /**
   * Verify a signature (for testing purposes).
   *
   * @param signature - The DER-encoded signature to verify
   * @param message - The original message
   * @returns True if valid, false otherwise
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    try {
      return p256.verify(signature, message, this.pubKey);
    } catch {
      return false;
    }
  }

  /**
   * Load an ECDSA signer from a PEM file.
   *
   * @param path - Path to PEM file containing ECDSA P-256 private key
   * @returns EcdsaSigner instance
   */
  static fromPemFile(path: string): EcdsaSigner {
    const pemData = fs.readFileSync(path, 'utf-8');
    return EcdsaSigner.fromPem(pemData);
  }

  /**
   * Load an ECDSA signer from a PEM string.
   *
   * @param pemString - PEM-encoded ECDSA P-256 private key
   * @returns EcdsaSigner instance
   */
  static fromPem(pemString: string): EcdsaSigner {
    // Extract base64 content from PEM
    const lines = pemString.split('\n');
    const b64Lines = lines.filter(
      (line) => !line.startsWith('-----') && line.trim().length > 0
    );
    const b64 = b64Lines.join('');
    const der = Buffer.from(b64, 'base64');

    // Parse PKCS#8 or SEC1 structure to extract the 32-byte private key
    const privateKey = extractEcdsaPrivateKey(der);
    return new EcdsaSigner(privateKey);
  }

  /**
   * Generate a new ECDSA P-256 keypair.
   *
   * @returns Object with signer and publicKey string
   */
  static generate(): { signer: EcdsaSigner; publicKey: string } {
    const privateKey = p256.utils.randomPrivateKey();
    const signer = new EcdsaSigner(privateKey);
    return { signer, publicKey: signer.publicKey() };
  }
}

/**
 * Extract Ed25519 private key from DER-encoded PKCS#8 structure.
 */
function extractEd25519PrivateKey(der: Uint8Array): Uint8Array {
  // PKCS#8 structure:
  // SEQUENCE {
  //   INTEGER (version = 0)
  //   SEQUENCE { OID (Ed25519) }
  //   OCTET STRING { OCTET STRING { 32-byte key } }
  // }

  let offset = 0;

  // Skip outer SEQUENCE tag and length
  if (der[offset] !== 0x30) throw new Error('Invalid PKCS#8: expected SEQUENCE');
  offset++;
  offset += readLength(der, offset).bytesRead;

  // Skip version INTEGER
  if (der[offset] !== 0x02) throw new Error('Invalid PKCS#8: expected INTEGER (version)');
  offset++;
  const versionLen = readLength(der, offset);
  offset += versionLen.bytesRead + versionLen.length;

  // Skip algorithm SEQUENCE
  if (der[offset] !== 0x30) throw new Error('Invalid PKCS#8: expected SEQUENCE (algorithm)');
  offset++;
  const algLen = readLength(der, offset);
  offset += algLen.bytesRead + algLen.length;

  // Read privateKey OCTET STRING
  if (der[offset] !== 0x04) throw new Error('Invalid PKCS#8: expected OCTET STRING');
  offset++;
  const outerOctetLen = readLength(der, offset);
  offset += outerOctetLen.bytesRead;

  // Read inner OCTET STRING containing the actual key
  if (der[offset] !== 0x04) throw new Error('Invalid PKCS#8: expected inner OCTET STRING');
  offset++;
  const innerOctetLen = readLength(der, offset);
  offset += innerOctetLen.bytesRead;

  if (innerOctetLen.length !== 32) {
    throw new Error(`Invalid Ed25519 key length: expected 32, got ${innerOctetLen.length}`);
  }

  return der.slice(offset, offset + 32);
}

/**
 * Extract ECDSA P-256 private key from DER-encoded PKCS#8 or SEC1 structure.
 */
function extractEcdsaPrivateKey(der: Uint8Array): Uint8Array {
  let offset = 0;

  // Check if this is PKCS#8 or SEC1 format
  if (der[offset] !== 0x30) throw new Error('Invalid key format: expected SEQUENCE');
  offset++;
  const outerLen = readLength(der, offset);
  offset += outerLen.bytesRead;

  // Check first element - if INTEGER, it's PKCS#8; if OCTET STRING, it's SEC1
  if (der[offset] === 0x02) {
    // PKCS#8 format
    // Skip version INTEGER
    offset++;
    const versionLen = readLength(der, offset);
    offset += versionLen.bytesRead + versionLen.length;

    // Skip algorithm SEQUENCE
    if (der[offset] !== 0x30) throw new Error('Invalid PKCS#8: expected SEQUENCE (algorithm)');
    offset++;
    const algLen = readLength(der, offset);
    offset += algLen.bytesRead + algLen.length;

    // Read privateKey OCTET STRING (contains SEC1 EC private key)
    if (der[offset] !== 0x04) throw new Error('Invalid PKCS#8: expected OCTET STRING');
    offset++;
    const octetLen = readLength(der, offset);
    offset += octetLen.bytesRead;

    // Now parse the SEC1 structure inside
    return extractSec1PrivateKey(der.slice(offset, offset + octetLen.length));
  } else {
    // SEC1 format (EC PRIVATE KEY)
    return extractSec1PrivateKey(der);
  }
}

/**
 * Extract private key from SEC1 EC private key structure.
 */
function extractSec1PrivateKey(der: Uint8Array): Uint8Array {
  let offset = 0;

  // SEQUENCE
  if (der[offset] !== 0x30) throw new Error('Invalid SEC1: expected SEQUENCE');
  offset++;
  readLength(der, offset);
  offset += readLength(der, offset).bytesRead;

  // version INTEGER (should be 1)
  if (der[offset] !== 0x02) throw new Error('Invalid SEC1: expected INTEGER (version)');
  offset++;
  const versionLen = readLength(der, offset);
  offset += versionLen.bytesRead + versionLen.length;

  // privateKey OCTET STRING
  if (der[offset] !== 0x04) throw new Error('Invalid SEC1: expected OCTET STRING');
  offset++;
  const keyLen = readLength(der, offset);
  offset += keyLen.bytesRead;

  if (keyLen.length !== 32) {
    throw new Error(`Invalid ECDSA P-256 key length: expected 32, got ${keyLen.length}`);
  }

  return der.slice(offset, offset + 32);
}

/**
 * Read ASN.1 length field.
 */
function readLength(der: Uint8Array, offset: number): { length: number; bytesRead: number } {
  const firstByte = der[offset];

  if (firstByte < 0x80) {
    // Short form
    return { length: firstByte, bytesRead: 1 };
  }

  // Long form
  const numBytes = firstByte & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | der[offset + 1 + i];
  }
  return { length, bytesRead: 1 + numBytes };
}

// Re-export utility functions for testing
export { bytesToHex, hexToBytes };

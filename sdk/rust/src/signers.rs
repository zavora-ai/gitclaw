//! Cryptographic signers for `GitClaw` SDK.
//!
//! Supports Ed25519 and ECDSA P-256 signing algorithms.
//!
//! # Example
//!
//! ```rust
//! use gitclaw::{Ed25519Signer, Signer};
//!
//! // Generate a new keypair
//! let (signer, public_key) = Ed25519Signer::generate();
//! println!("Public key: {}", public_key);
//!
//! // Sign a message
//! let message = b"Hello, GitClaw!";
//! let signature = signer.sign(message).unwrap();
//! ```

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey,
};
use p256::ecdsa::{
    signature::Signer as EcdsaSignerTrait, signature::Verifier as EcdsaVerifierTrait,
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

use crate::error::Error;

/// Trait for cryptographic signers.
pub trait Signer: Send + Sync {
    /// Sign a message and return the signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Return the public key in base64 format with type prefix.
    fn public_key(&self) -> String;

    /// Verify a signature (for testing purposes).
    fn verify(&self, signature: &[u8], message: &[u8]) -> bool;
}

/// Ed25519 digital signature implementation.
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer from a signing key.
    fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Generate a new Ed25519 keypair.
    ///
    /// Returns a tuple of (signer, `public_key_string`).
    #[must_use]
    pub fn generate() -> (Self, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signer = Self::new(signing_key);
        let public_key = signer.public_key();
        (signer, public_key)
    }

    /// Load an Ed25519 signer from a PEM file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the key is invalid.
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let pem_data = std::fs::read_to_string(path)?;
        Self::from_pem(&pem_data)
    }

    /// Load an Ed25519 signer from a PEM string.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid or not an Ed25519 key.
    pub fn from_pem(pem_string: &str) -> Result<Self, Error> {
        // Parse PEM
        let pem = pem::parse(pem_string)?;

        // Ed25519 private keys in PKCS#8 format
        if pem.tag() != "PRIVATE KEY" {
            return Err(Error::Key(format!(
                "Expected PRIVATE KEY, got {}",
                pem.tag()
            )));
        }

        // Parse PKCS#8 DER
        let signing_key = SigningKey::from_pkcs8_der(pem.contents())
            .map_err(|e| Error::Key(format!("Failed to parse Ed25519 key: {e}")))?;

        Ok(Self::new(signing_key))
    }

    /// Load an Ed25519 signer from raw 32-byte private key seed.
    ///
    /// # Errors
    ///
    /// This function is infallible for valid 32-byte arrays.
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self, Error> {
        let signing_key = SigningKey::from_bytes(key_bytes);
        Ok(Self::new(signing_key))
    }

    /// Return the raw 32-byte public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return the public key in PEM format.
    #[must_use]
    pub fn public_key_pem(&self) -> String {
        let public_bytes = self.verifying_key.to_bytes();
        // Ed25519 public key in SubjectPublicKeyInfo format
        // OID: 1.3.101.112
        let mut der = vec![
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes (1 unused bit byte + 32 key bytes)
        ];
        der.extend_from_slice(&public_bytes);

        let pem = pem::Pem::new("PUBLIC KEY", der);
        pem::encode(&pem)
    }

    /// Return the private key in PEM format (for storage).
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be encoded (should never happen for valid keys).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn private_key_pem(&self) -> String {
        // Use PKCS#8 format
        let pkcs8_der = self
            .signing_key
            .to_pkcs8_der()
            .expect("Failed to encode private key");
        let pem = pem::Pem::new("PRIVATE KEY", pkcs8_der.as_bytes().to_vec());
        pem::encode(&pem)
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature: Ed25519Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key(&self) -> String {
        let public_bytes = self.verifying_key.to_bytes();
        format!("ed25519:{}", BASE64.encode(public_bytes))
    }

    fn verify(&self, signature: &[u8], message: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        self.verifying_key.verify(message, &sig).is_ok()
    }
}

/// ECDSA P-256 digital signature implementation.
pub struct EcdsaSigner {
    signing_key: P256SigningKey,
    verifying_key: P256VerifyingKey,
}

impl EcdsaSigner {
    /// Create a new ECDSA signer from a signing key.
    fn new(signing_key: P256SigningKey) -> Self {
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Generate a new ECDSA P-256 keypair.
    ///
    /// Returns a tuple of (signer, `public_key_string`).
    #[must_use]
    pub fn generate() -> (Self, String) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let signer = Self::new(signing_key);
        let public_key = signer.public_key();
        (signer, public_key)
    }

    /// Load an ECDSA signer from a PEM file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the key is invalid.
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let pem_data = std::fs::read_to_string(path)?;
        Self::from_pem(&pem_data)
    }

    /// Load an ECDSA signer from a PEM string.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid or not an ECDSA P-256 key.
    pub fn from_pem(pem_string: &str) -> Result<Self, Error> {
        let signing_key = P256SigningKey::from_pkcs8_pem(pem_string)
            .map_err(|e| Error::Key(format!("Failed to parse ECDSA key: {e}")))?;

        Ok(Self::new(signing_key))
    }

    /// Return the compressed public key bytes (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        #[allow(unused_imports)]
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        // Use SEC1 compressed point encoding (33 bytes for P-256)
        self.verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Return the public key in PEM format.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be encoded (should never happen for valid keys).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn public_key_pem(&self) -> String {
        self.verifying_key
            .to_public_key_pem(LineEnding::default())
            .expect("Failed to encode public key")
    }

    /// Return the private key in PEM format (for storage).
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be encoded (should never happen for valid keys).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn private_key_pem(&self) -> String {
        self.signing_key
            .to_pkcs8_pem(LineEnding::default())
            .expect("Failed to encode private key")
            .to_string()
    }
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature: P256Signature = EcdsaSignerTrait::sign(&self.signing_key, message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn public_key(&self) -> String {
        let public_bytes = self.public_key_bytes();
        format!("ecdsa:{}", BASE64.encode(public_bytes))
    }

    fn verify(&self, signature: &[u8], message: &[u8]) -> bool {
        let Ok(sig) = P256Signature::from_der(signature) else {
            return false;
        };
        EcdsaVerifierTrait::verify(&self.verifying_key, message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_generate_and_sign() {
        let (signer, public_key) = Ed25519Signer::generate();
        assert!(public_key.starts_with("ed25519:"));

        let message = b"test message";
        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(signer.verify(&signature, message));
    }

    #[test]
    fn test_ed25519_signature_is_deterministic() {
        let (signer, _) = Ed25519Signer::generate();
        let message = b"test message";

        let sig1 = signer.sign(message).unwrap();
        let sig2 = signer.sign(message).unwrap();

        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
    }

    #[test]
    fn test_ed25519_pem_round_trip() {
        let (signer, public_key) = Ed25519Signer::generate();
        let pem = signer.private_key_pem();

        let loaded = Ed25519Signer::from_pem(&pem).unwrap();
        assert_eq!(loaded.public_key(), public_key);

        // Sign with both and verify
        let message = b"test message";
        let sig1 = signer.sign(message).unwrap();
        let sig2 = loaded.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_ed25519_from_bytes() {
        let seed: [u8; 32] = [42; 32];
        let signer1 = Ed25519Signer::from_bytes(&seed).unwrap();
        let signer2 = Ed25519Signer::from_bytes(&seed).unwrap();

        assert_eq!(
            signer1.public_key(),
            signer2.public_key(),
            "Same seed should produce same key"
        );
    }

    #[test]
    fn test_ecdsa_generate_and_sign() {
        let (signer, public_key) = EcdsaSigner::generate();
        assert!(public_key.starts_with("ecdsa:"));

        let message = b"test message";
        let signature = signer.sign(message).unwrap();
        // DER-encoded P-256 signatures are typically 70-72 bytes
        assert!((68..=72).contains(&signature.len()));
        assert!(signer.verify(&signature, message));
    }

    #[test]
    fn test_ecdsa_pem_round_trip() {
        let (signer, public_key) = EcdsaSigner::generate();
        let pem = signer.private_key_pem();

        let loaded = EcdsaSigner::from_pem(&pem).unwrap();
        assert_eq!(loaded.public_key(), public_key);

        // Sign with loaded and verify with original
        let message = b"test message";
        let sig = loaded.sign(message).unwrap();
        assert!(signer.verify(&sig, message));
    }

    #[test]
    fn test_ecdsa_public_key_is_compressed() {
        let (_signer, public_key) = EcdsaSigner::generate();

        // Extract base64 part
        let b64_part = &public_key[6..]; // Remove "ecdsa:" prefix
        let decoded = BASE64.decode(b64_part).unwrap();

        // Compressed P-256 public key is 33 bytes
        assert_eq!(decoded.len(), 33);
    }
}

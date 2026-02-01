use ed25519_dalek::VerifyingKey;
use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),
}

/// Supported public key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Ecdsa,
}

/// Service for cryptographic operations
#[derive(Debug, Clone, Default)]
pub struct CryptoService;

impl CryptoService {
    pub fn new() -> Self {
        Self
    }

    /// Validate a public key string and determine its type.
    /// 
    /// Supported formats:
    /// - Ed25519: Base64-encoded 32-byte key, optionally prefixed with "ed25519:"
    /// - ECDSA: Base64-encoded key, prefixed with "ecdsa:"
    pub fn validate_public_key(&self, public_key: &str) -> Result<KeyType, CryptoError> {
        let (key_type, key_data) = self.parse_key_prefix(public_key)?;
        
        match key_type {
            KeyType::Ed25519 => self.validate_ed25519_key(&key_data),
            KeyType::Ecdsa => self.validate_ecdsa_key(&key_data),
        }
    }

    /// Parse the key type prefix from a public key string
    fn parse_key_prefix(&self, public_key: &str) -> Result<(KeyType, String), CryptoError> {
        if let Some(key_data) = public_key.strip_prefix("ed25519:") {
            Ok((KeyType::Ed25519, key_data.to_string()))
        } else if let Some(key_data) = public_key.strip_prefix("ecdsa:") {
            Ok((KeyType::Ecdsa, key_data.to_string()))
        } else {
            // Default to Ed25519 if no prefix
            Ok((KeyType::Ed25519, public_key.to_string()))
        }
    }

    /// Validate an Ed25519 public key
    fn validate_ed25519_key(&self, key_data: &str) -> Result<KeyType, CryptoError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        let bytes = STANDARD
            .decode(key_data)
            .map_err(|e| CryptoError::InvalidPublicKeyFormat(format!("Invalid base64: {e}")))?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        // Try to parse as Ed25519 verifying key to ensure it's valid
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKeyFormat("Invalid key bytes".to_string()))?;

        VerifyingKey::from_bytes(&bytes_array)
            .map_err(|e| CryptoError::InvalidPublicKeyFormat(format!("Invalid Ed25519 key: {e}")))?;

        Ok(KeyType::Ed25519)
    }

    /// Validate an ECDSA public key (P-256/secp256k1)
    fn validate_ecdsa_key(&self, key_data: &str) -> Result<KeyType, CryptoError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        let bytes = STANDARD
            .decode(key_data)
            .map_err(|e| CryptoError::InvalidPublicKeyFormat(format!("Invalid base64: {e}")))?;

        // ECDSA P-256 uncompressed public key is 65 bytes (0x04 + 32 + 32)
        // Compressed is 33 bytes (0x02/0x03 + 32)
        if bytes.len() != 33 && bytes.len() != 65 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 33, // or 65
                actual: bytes.len(),
            });
        }

        // Validate the prefix byte
        match bytes.first() {
            Some(0x02) | Some(0x03) if bytes.len() == 33 => Ok(KeyType::Ecdsa),
            Some(0x04) if bytes.len() == 65 => Ok(KeyType::Ecdsa),
            _ => Err(CryptoError::InvalidPublicKeyFormat(
                "Invalid ECDSA key format".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn test_validate_ed25519_key() {
        let crypto = CryptoService::new();
        
        // Generate a valid Ed25519 key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        
        let result = crypto.validate_public_key(&public_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), KeyType::Ed25519);
    }

    #[test]
    fn test_validate_ed25519_key_with_prefix() {
        let crypto = CryptoService::new();
        
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = format!("ed25519:{}", STANDARD.encode(verifying_key.as_bytes()));
        
        let result = crypto.validate_public_key(&public_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), KeyType::Ed25519);
    }

    #[test]
    fn test_invalid_base64() {
        let crypto = CryptoService::new();
        let result = crypto.validate_public_key("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let crypto = CryptoService::new();
        let short_key = STANDARD.encode([0u8; 16]); // Too short
        let result = crypto.validate_public_key(&short_key);
        assert!(result.is_err());
    }
}

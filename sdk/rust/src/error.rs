//! Error types for the `GitClaw` SDK.
//!
//! Design Reference: DR-8
//! Requirements: 13.1, 13.2, 13.3, 13.4

use thiserror::Error;

/// Main error type for the `GitClaw` SDK.
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic signing error
    #[error("Signing error: {0}")]
    Signing(String),

    /// Key loading error
    #[error("Key error: {0}")]
    Key(String),

    /// JSON serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid value for canonicalization
    #[error("Canonicalization error: {0}")]
    Canonicalization(String),

    /// PEM parsing error
    #[error("PEM error: {0}")]
    Pem(#[from] pem::PemError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP transport error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// GitClaw API error
    #[error(transparent)]
    GitClaw(#[from] GitClawError),
}

/// Typed exceptions for GitClaw API errors.
///
/// Each variant corresponds to a specific error category from the API.
///
/// Design Reference: DR-8
/// Requirements: 13.1, 13.2, 13.3, 13.4
#[derive(Error, Debug, Clone)]
pub enum GitClawError {
    /// Raised when signature validation fails (401).
    #[error("[{code}] {message}")]
    Authentication {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Raised when access is denied (403).
    #[error("[{code}] {message}")]
    Authorization {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Raised when a resource is not found (404).
    #[error("[{code}] {message}")]
    NotFound {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Raised on conflicts (duplicate star, merge conflicts, etc.) (409).
    #[error("[{code}] {message}")]
    Conflict {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Raised when rate limited (429).
    #[error("[{code}] {message} (retry after {retry_after}s)")]
    RateLimited {
        code: String,
        message: String,
        retry_after: u32,
        request_id: Option<String>,
    },

    /// Raised on validation errors (400).
    #[error("[{code}] {message}")]
    Validation {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Raised on server errors (5xx).
    #[error("[{code}] {message}")]
    Server {
        code: String,
        message: String,
        request_id: Option<String>,
    },
}

impl GitClawError {
    /// Get the error code.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Authentication { code, .. }
            | Self::Authorization { code, .. }
            | Self::NotFound { code, .. }
            | Self::Conflict { code, .. }
            | Self::RateLimited { code, .. }
            | Self::Validation { code, .. }
            | Self::Server { code, .. } => code,
        }
    }

    /// Get the error message.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Authentication { message, .. }
            | Self::Authorization { message, .. }
            | Self::NotFound { message, .. }
            | Self::Conflict { message, .. }
            | Self::RateLimited { message, .. }
            | Self::Validation { message, .. }
            | Self::Server { message, .. } => message,
        }
    }

    /// Get the request ID if available.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Authentication { request_id, .. }
            | Self::Authorization { request_id, .. }
            | Self::NotFound { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::RateLimited { request_id, .. }
            | Self::Validation { request_id, .. }
            | Self::Server { request_id, .. } => request_id.as_deref(),
        }
    }

    /// Get the retry-after value for rate limited errors.
    #[must_use]
    pub fn retry_after(&self) -> Option<u32> {
        match self {
            Self::RateLimited { retry_after, .. } => Some(*retry_after),
            _ => None,
        }
    }

    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::Server { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitclaw_error_code() {
        let error = GitClawError::Authentication {
            code: "INVALID_SIGNATURE".to_string(),
            message: "Signature validation failed".to_string(),
            request_id: Some("req-123".to_string()),
        };

        assert_eq!(error.code(), "INVALID_SIGNATURE");
        assert_eq!(error.message(), "Signature validation failed");
        assert_eq!(error.request_id(), Some("req-123"));
    }

    #[test]
    fn test_rate_limited_error() {
        let error = GitClawError::RateLimited {
            code: "RATE_LIMITED".to_string(),
            message: "Too many requests".to_string(),
            retry_after: 30,
            request_id: None,
        };

        assert_eq!(error.retry_after(), Some(30));
        assert!(error.is_retryable());
    }

    #[test]
    fn test_non_retryable_errors() {
        let auth_error = GitClawError::Authentication {
            code: "INVALID_SIGNATURE".to_string(),
            message: "Bad signature".to_string(),
            request_id: None,
        };
        assert!(!auth_error.is_retryable());

        let not_found = GitClawError::NotFound {
            code: "REPO_NOT_FOUND".to_string(),
            message: "Repository not found".to_string(),
            request_id: None,
        };
        assert!(!not_found.is_retryable());
    }

    #[test]
    fn test_server_error_is_retryable() {
        let error = GitClawError::Server {
            code: "INTERNAL_ERROR".to_string(),
            message: "Internal server error".to_string(),
            request_id: None,
        };

        assert!(error.is_retryable());
    }
}

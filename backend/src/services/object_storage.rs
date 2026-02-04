//! Object Storage Service
//!
//! Provides S3-compatible object storage for Git objects.
//! Design Reference: DR-S3-1.1, DR-S3-1.2, DR-S3-1.3
//!
//! Requirements: 1.1-1.6, 2.1-2.6, 8.1-8.6, 9.1-9.6, 10.4

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use sha1::{Digest, Sha1};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Default maximum retry attempts for S3 operations
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default maximum backoff in seconds for retry operations
const DEFAULT_RETRY_MAX_BACKOFF_SECS: u64 = 30;

/// Default region when not specified
const DEFAULT_REGION: &str = "us-east-1";

/// Initial backoff duration in milliseconds for retry operations
const INITIAL_BACKOFF_MS: u64 = 100;

/// Base multiplier for exponential backoff
const BACKOFF_MULTIPLIER: u64 = 2;

/// Minimum delay in milliseconds when rate limited (503 SlowDown)
const RATE_LIMIT_MIN_DELAY_MS: u64 = 1000;

/// Maximum adaptive rate limit delay in milliseconds
const RATE_LIMIT_MAX_DELAY_MS: u64 = 30000;

// ============================================================================
// Retry and Rate Limiting Types
// ============================================================================

/// Tracks adaptive rate limiting state for S3 operations
///
/// Requirements: 9.3
/// Design Reference: DR-S3-1.2
#[derive(Debug)]
pub struct RateLimitState {
    /// Current delay multiplier (increases on 503 SlowDown, decreases on success)
    delay_multiplier: AtomicU64,
    /// Number of consecutive rate limit errors
    consecutive_rate_limits: AtomicU64,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitState {
    /// Create a new rate limit state
    #[must_use]
    pub fn new() -> Self {
        Self {
            delay_multiplier: AtomicU64::new(1),
            consecutive_rate_limits: AtomicU64::new(0),
        }
    }

    /// Record a rate limit (503 SlowDown) response
    ///
    /// Increases the delay multiplier for adaptive rate limiting
    pub fn record_rate_limit(&self) {
        let consecutive = self.consecutive_rate_limits.fetch_add(1, Ordering::SeqCst) + 1;
        // Exponentially increase delay multiplier, capped at 32x
        let new_multiplier = (1u64 << consecutive.min(5)).min(32);
        self.delay_multiplier.store(new_multiplier, Ordering::SeqCst);
    }

    /// Record a successful operation
    ///
    /// Gradually decreases the delay multiplier
    pub fn record_success(&self) {
        self.consecutive_rate_limits.store(0, Ordering::SeqCst);
        let current = self.delay_multiplier.load(Ordering::SeqCst);
        if current > 1 {
            // Gradually reduce multiplier on success
            self.delay_multiplier.store(current / 2, Ordering::SeqCst);
        }
    }

    /// Get the current adaptive delay in milliseconds
    #[must_use]
    pub fn get_adaptive_delay_ms(&self) -> u64 {
        let multiplier = self.delay_multiplier.load(Ordering::SeqCst);
        (RATE_LIMIT_MIN_DELAY_MS * multiplier).min(RATE_LIMIT_MAX_DELAY_MS)
    }
}

/// Result of checking if an error is retryable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Error is retryable, proceed with retry
    Retry,
    /// Error is a rate limit (503 SlowDown), apply adaptive delay
    RateLimited,
    /// Error is not retryable, fail immediately
    NoRetry,
}

/// Context for retry operations including request ID for logging
#[derive(Debug, Clone)]
pub struct RetryContext {
    /// Operation name for logging
    pub operation: String,
    /// S3 request ID if available
    pub request_id: Option<String>,
    /// Current attempt number (1-based)
    pub attempt: u32,
    /// Maximum attempts allowed
    pub max_attempts: u32,
}

// ============================================================================
// Error Types
// ============================================================================

/// Configuration errors for S3 storage
///
/// Design Reference: DR-S3-1.3
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Required environment variable is missing
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),

    /// Environment variable has an invalid value
    #[error("Invalid value for {variable}: {message}")]
    InvalidValue { variable: String, message: String },

    /// Configuration validation failed
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}

/// Storage operation errors
///
/// Design Reference: DR-S3-1.1
/// Requirements: 1.1
#[derive(Debug, Error)]
pub enum StorageError {
    /// Object not found in storage
    #[error("Object not found: {0}")]
    NotFound(String),

    /// Object data is corrupted (SHA-1 mismatch)
    #[error("Object corrupted: expected OID {expected}, got {actual}")]
    ObjectCorrupted { expected: String, actual: String },

    /// S3 connection error
    #[error("S3 connection error: {0}")]
    ConnectionError(String),

    /// S3 access denied
    #[error("S3 access denied: {0}")]
    AccessDenied(String),

    /// S3 bucket not found
    #[error("S3 bucket not found: {0}")]
    BucketNotFound(String),

    /// S3 upload failed
    #[error("S3 upload failed: {0}")]
    UploadFailed(String),

    /// S3 download failed
    #[error("S3 download failed: {0}")]
    DownloadFailed(String),

    /// S3 delete failed
    #[error("S3 delete failed: {0}")]
    DeleteFailed(String),

    /// S3 rate limited
    #[error("S3 rate limited: {0}")]
    RateLimited(String),

    /// Invalid object data
    #[error("Invalid object data: {0}")]
    InvalidData(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(#[from] ConfigError),

    /// Internal error
    #[error("Internal storage error: {0}")]
    Internal(String),
}

impl StorageError {
    /// Check if this error is retryable
    ///
    /// Requirements: 9.1
    #[must_use]
    pub fn retry_decision(&self) -> RetryDecision {
        match self {
            // Rate limited errors should use adaptive delay
            Self::RateLimited(_) => RetryDecision::RateLimited,
            // Connection errors and some internal errors are retryable
            Self::ConnectionError(_) => RetryDecision::Retry,
            // Upload/download failures may be transient
            Self::UploadFailed(msg) | Self::DownloadFailed(msg) | Self::DeleteFailed(msg) => {
                // Check for specific retryable error codes in the message
                if msg.contains("503")
                    || msg.contains("500")
                    || msg.contains("timeout")
                    || msg.contains("Timeout")
                    || msg.contains("connection")
                    || msg.contains("Connection")
                {
                    if msg.contains("503") || msg.contains("SlowDown") {
                        RetryDecision::RateLimited
                    } else {
                        RetryDecision::Retry
                    }
                } else {
                    RetryDecision::NoRetry
                }
            }
            Self::Internal(msg) => {
                if msg.contains("503")
                    || msg.contains("500")
                    || msg.contains("timeout")
                    || msg.contains("Timeout")
                {
                    if msg.contains("503") || msg.contains("SlowDown") {
                        RetryDecision::RateLimited
                    } else {
                        RetryDecision::Retry
                    }
                } else {
                    RetryDecision::NoRetry
                }
            }
            // These errors are not retryable
            Self::NotFound(_)
            | Self::ObjectCorrupted { .. }
            | Self::AccessDenied(_)
            | Self::BucketNotFound(_)
            | Self::InvalidData(_)
            | Self::ConfigError(_) => RetryDecision::NoRetry,
        }
    }
}

// ============================================================================
// Git Object Types
// ============================================================================

/// Git object types for storage
///
/// Requirements: 2.4, 2.5
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectType {
    /// Git commit object
    Commit,
    /// Git tree object
    Tree,
    /// Git blob object
    Blob,
    /// Git tag object
    Tag,
}

impl GitObjectType {
    /// Get the string representation of the object type
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    /// Get the Content-Type header for this object type
    ///
    /// Requirements: 2.4
    #[must_use]
    pub fn content_type(&self) -> &'static str {
        "application/x-git-loose-object"
    }

    /// Parse object type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "commit" => Some(Self::Commit),
            "tree" => Some(Self::Tree),
            "blob" => Some(Self::Blob),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

impl std::fmt::Display for GitObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Storage Data Types
// ============================================================================

/// A stored Git object with its metadata
#[derive(Debug, Clone)]
pub struct StoredObject {
    /// Object ID (SHA-1 hash)
    pub oid: String,
    /// Object type
    pub object_type: GitObjectType,
    /// Object size in bytes
    pub size: usize,
    /// Object data
    pub data: Vec<u8>,
}

/// Object metadata without data
#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    /// Object ID (SHA-1 hash)
    pub oid: String,
    /// Object type
    pub object_type: GitObjectType,
    /// Object size in bytes
    pub size: usize,
}

/// List of objects with pagination support
#[derive(Debug, Clone)]
pub struct ObjectList {
    /// List of object OIDs
    pub objects: Vec<String>,
    /// Continuation token for pagination
    pub continuation_token: Option<String>,
    /// Whether there are more objects
    pub is_truncated: bool,
}

/// Packfile data with its index
#[derive(Debug, Clone)]
pub struct PackfileData {
    /// Packfile hash
    pub pack_hash: String,
    /// Packfile binary data
    pub packfile: Vec<u8>,
    /// Packfile index binary data
    pub index: Vec<u8>,
}

/// Result of a delete operation
#[derive(Debug, Clone)]
pub struct DeleteResult {
    /// Number of objects deleted
    pub deleted_count: usize,
    /// Objects that failed to delete
    pub failed: Vec<String>,
}

/// Result of a copy operation
#[derive(Debug, Clone)]
pub struct CopyResult {
    /// Number of objects copied
    pub copied_count: usize,
    /// Objects that failed to copy
    pub failed: Vec<String>,
}

// ============================================================================
// ObjectStorageBackend Trait
// ============================================================================

/// Object storage backend trait for Git objects
///
/// Design Reference: DR-S3-1.1
/// Requirements: 1.1
///
/// This trait defines the contract that any storage implementation must fulfill.
/// Implementations include S3ObjectStorage for production and can include
/// in-memory or filesystem backends for testing.
#[async_trait]
pub trait ObjectStorageBackend: Send + Sync {
    /// Store a Git object
    ///
    /// Requirements: 2.4, 2.5
    async fn put_object(
        &self,
        repo_id: &str,
        oid: &str,
        object_type: GitObjectType,
        data: &[u8],
    ) -> Result<(), StorageError>;

    /// Retrieve a Git object
    ///
    /// Requirements: 2.6
    async fn get_object(&self, repo_id: &str, oid: &str) -> Result<StoredObject, StorageError>;

    /// Delete a Git object
    async fn delete_object(&self, repo_id: &str, oid: &str) -> Result<(), StorageError>;

    /// List objects in a repository
    async fn list_objects(
        &self,
        repo_id: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
    ) -> Result<ObjectList, StorageError>;

    /// Check if an object exists and get its metadata
    async fn head_object(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<ObjectMetadata>, StorageError>;

    /// Store a packfile with its index
    ///
    /// Requirements: 2.2, 2.3
    async fn put_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
        packfile: &[u8],
        index: &[u8],
    ) -> Result<(), StorageError>;

    /// Retrieve a packfile with its index
    async fn get_packfile(&self, repo_id: &str, pack_hash: &str)
        -> Result<PackfileData, StorageError>;

    /// Delete all objects for a repository
    ///
    /// Requirements: 3.2, 3.3, 3.4
    async fn delete_repository_objects(&self, repo_id: &str) -> Result<DeleteResult, StorageError>;

    /// Copy all objects from one repository to another (for forking)
    ///
    /// Requirements: 3.5
    async fn copy_repository_objects(
        &self,
        source_repo_id: &str,
        target_repo_id: &str,
    ) -> Result<CopyResult, StorageError>;
}

// ============================================================================
// S3Config
// ============================================================================

/// S3 configuration loaded from environment variables
///
/// Design Reference: DR-S3-1.3
///
/// # Environment Variables
///
/// - `S3_ENDPOINT`: Custom S3 endpoint URL (optional, for MinIO/R2)
/// - `S3_BUCKET`: S3 bucket name (required)
/// - `S3_REGION`: AWS region (optional, defaults to "us-east-1")
/// - `S3_ACCESS_KEY_ID`: AWS access key ID (optional, for static credentials)
/// - `S3_SECRET_ACCESS_KEY`: AWS secret access key (optional, for static credentials)
/// - `S3_USE_PATH_STYLE`: Use path-style addressing (optional, defaults to false)
/// - `S3_AUTO_CREATE_BUCKET`: Auto-create bucket if missing (optional, defaults to false)
/// - `S3_MAX_RETRIES`: Maximum retry attempts (optional, defaults to 3)
/// - `S3_RETRY_MAX_BACKOFF`: Maximum backoff in seconds (optional, defaults to 30)
///
/// # Requirements
///
/// - 1.2: Support configuration via environment variables
/// - 1.5: Validate configuration on startup with clear error messages
/// - 8.1: Support configuration via environment variables
/// - 8.3: Support static credentials via S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Custom S3 endpoint URL (for MinIO, R2, etc.)
    /// When None, uses AWS S3 default endpoint
    pub endpoint: Option<String>,

    /// S3 bucket name (required)
    pub bucket: String,

    /// AWS region
    pub region: String,

    /// AWS access key ID for static credentials
    pub access_key_id: Option<String>,

    /// AWS secret access key for static credentials
    pub secret_access_key: Option<String>,

    /// Use path-style addressing (required for MinIO)
    /// When true: http://endpoint/bucket/key
    /// When false: http://bucket.endpoint/key (virtual-hosted style)
    pub use_path_style: bool,

    /// Automatically create bucket if it doesn't exist
    pub auto_create_bucket: bool,

    /// Maximum number of retry attempts for S3 operations
    pub max_retries: u32,

    /// Maximum backoff duration in seconds for retry operations
    pub retry_max_backoff_secs: u64,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: None,
            bucket: String::new(),
            region: DEFAULT_REGION.to_string(),
            access_key_id: None,
            secret_access_key: None,
            use_path_style: false,
            auto_create_bucket: false,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_max_backoff_secs: DEFAULT_RETRY_MAX_BACKOFF_SECS,
        }
    }
}


impl S3Config {
    /// Load configuration from environment variables
    ///
    /// # Requirements
    ///
    /// - 1.2: Support configuration via environment variables
    /// - 8.1: Support configuration via environment variables
    /// - 8.3: Support static credentials
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::MissingEnvVar` if required variables are missing.
    /// Returns `ConfigError::InvalidValue` if values cannot be parsed.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Required: S3_BUCKET
        let bucket = env::var("S3_BUCKET")
            .map_err(|_| ConfigError::MissingEnvVar("S3_BUCKET".to_string()))?;

        // Optional: S3_ENDPOINT
        let endpoint = env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty());

        // Optional: S3_REGION (defaults to us-east-1)
        let region = env::var("S3_REGION")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_REGION.to_string());

        // Optional: S3_ACCESS_KEY_ID
        let access_key_id = env::var("S3_ACCESS_KEY_ID").ok().filter(|s| !s.is_empty());

        // Optional: S3_SECRET_ACCESS_KEY
        let secret_access_key = env::var("S3_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty());

        // Optional: S3_USE_PATH_STYLE (defaults to false)
        let use_path_style = parse_bool_env("S3_USE_PATH_STYLE")?;

        // Optional: S3_AUTO_CREATE_BUCKET (defaults to false)
        let auto_create_bucket = parse_bool_env("S3_AUTO_CREATE_BUCKET")?;

        // Optional: S3_MAX_RETRIES (defaults to 3)
        let max_retries = parse_u32_env("S3_MAX_RETRIES", DEFAULT_MAX_RETRIES)?;

        // Optional: S3_RETRY_MAX_BACKOFF (defaults to 30)
        let retry_max_backoff_secs =
            parse_u64_env("S3_RETRY_MAX_BACKOFF", DEFAULT_RETRY_MAX_BACKOFF_SECS)?;

        let config = Self {
            endpoint,
            bucket,
            region,
            access_key_id,
            secret_access_key,
            use_path_style,
            auto_create_bucket,
            max_retries,
            retry_max_backoff_secs,
        };

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration completeness and correctness
    ///
    /// # Requirements
    ///
    /// - 1.5: Validate configuration on startup with clear error messages
    /// - 8.5: Validate bucket existence and permissions on startup
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ValidationFailed` if validation fails.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate bucket name is not empty
        if self.bucket.is_empty() {
            return Err(ConfigError::ValidationFailed(
                "S3_BUCKET cannot be empty".to_string(),
            ));
        }

        // Validate bucket name format (basic validation)
        // S3 bucket names must be 3-63 characters, lowercase, and follow DNS naming rules
        if self.bucket.len() < 3 {
            return Err(ConfigError::ValidationFailed(
                "S3_BUCKET must be at least 3 characters long".to_string(),
            ));
        }

        if self.bucket.len() > 63 {
            return Err(ConfigError::ValidationFailed(
                "S3_BUCKET must be at most 63 characters long".to_string(),
            ));
        }

        // Validate region is not empty
        if self.region.is_empty() {
            return Err(ConfigError::ValidationFailed(
                "S3_REGION cannot be empty".to_string(),
            ));
        }

        // Validate credentials: if one is provided, both must be provided
        match (&self.access_key_id, &self.secret_access_key) {
            (Some(_), None) => {
                return Err(ConfigError::ValidationFailed(
                    "S3_SECRET_ACCESS_KEY is required when S3_ACCESS_KEY_ID is provided"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(ConfigError::ValidationFailed(
                    "S3_ACCESS_KEY_ID is required when S3_SECRET_ACCESS_KEY is provided"
                        .to_string(),
                ));
            }
            _ => {}
        }

        // Validate endpoint URL format if provided
        if let Some(ref endpoint) = self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConfigError::ValidationFailed(
                    "S3_ENDPOINT must start with http:// or https://".to_string(),
                ));
            }
        }

        // Validate max_retries is reasonable
        if self.max_retries > 10 {
            return Err(ConfigError::ValidationFailed(
                "S3_MAX_RETRIES should not exceed 10".to_string(),
            ));
        }

        // Validate retry_max_backoff_secs is reasonable
        if self.retry_max_backoff_secs > 300 {
            return Err(ConfigError::ValidationFailed(
                "S3_RETRY_MAX_BACKOFF should not exceed 300 seconds".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if static credentials are configured
    ///
    /// Returns true if both access_key_id and secret_access_key are set.
    #[must_use]
    pub fn has_static_credentials(&self) -> bool {
        self.access_key_id.is_some() && self.secret_access_key.is_some()
    }

    /// Check if a custom endpoint is configured
    ///
    /// Returns true if endpoint is set (for MinIO, R2, etc.)
    #[must_use]
    pub fn has_custom_endpoint(&self) -> bool {
        self.endpoint.is_some()
    }
}

// ============================================================================
// S3ObjectStorage Implementation
// ============================================================================

/// S3-compatible object storage implementation
///
/// Design Reference: DR-S3-1.2
/// Requirements: 2.1, 2.2, 2.3, 1.3, 1.4, 9.1-9.6
pub struct S3ObjectStorage {
    client: S3Client,
    bucket: String,
    config: S3Config,
    /// Adaptive rate limiting state
    rate_limit_state: Arc<RateLimitState>,
}

impl S3ObjectStorage {
    /// Create new S3 storage from configuration
    ///
    /// Requirements: 1.3, 1.4, 1.6
    pub async fn new(config: S3Config) -> Result<Self, StorageError> {
        config.validate()?;

        let region = Region::new(config.region.clone());

        // Build S3 config
        let mut s3_config_builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .force_path_style(config.use_path_style);

        // Set custom endpoint if provided (for MinIO/R2)
        if let Some(ref endpoint) = config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        // Set static credentials if provided
        if let (Some(access_key), Some(secret_key)) =
            (&config.access_key_id, &config.secret_access_key)
        {
            let credentials = Credentials::new(
                access_key,
                secret_key,
                None, // session token
                None, // expiration
                "static",
            );
            s3_config_builder = s3_config_builder.credentials_provider(credentials);
        } else {
            // Use default credential chain (IAM roles, env vars, etc.)
            let sdk_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(config.region.clone()))
                .load()
                .await;
            if let Some(creds_provider) = sdk_config.credentials_provider() {
                s3_config_builder =
                    s3_config_builder.credentials_provider(creds_provider.clone());
            }
        }

        let s3_config = s3_config_builder.build();
        let client = S3Client::from_conf(s3_config);

        let bucket = config.bucket.clone();

        Ok(Self {
            client,
            bucket,
            config,
            rate_limit_state: Arc::new(RateLimitState::new()),
        })
    }

    /// Build S3 key for loose object: {repo_id}/objects/{oid[0:2]}/{oid[2:]}
    ///
    /// Requirements: 2.1
    /// Design Reference: DR-S3-1.2
    #[must_use]
    pub fn object_key(repo_id: &str, oid: &str) -> String {
        if oid.len() >= 2 {
            format!("{}/objects/{}/{}", repo_id, &oid[0..2], &oid[2..])
        } else {
            format!("{}/objects/{}", repo_id, oid)
        }
    }

    /// Build S3 key for packfile: {repo_id}/pack/pack-{hash}.pack
    ///
    /// Requirements: 2.2
    #[must_use]
    pub fn packfile_key(repo_id: &str, pack_hash: &str) -> String {
        format!("{}/pack/pack-{}.pack", repo_id, pack_hash)
    }

    /// Build S3 key for packfile index: {repo_id}/pack/pack-{hash}.idx
    ///
    /// Requirements: 2.3
    #[must_use]
    pub fn packfile_index_key(repo_id: &str, pack_hash: &str) -> String {
        format!("{}/pack/pack-{}.idx", repo_id, pack_hash)
    }

    /// Compute SHA-1 hash of object data in Git format
    fn compute_git_hash(object_type: GitObjectType, data: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(format!("{} {}\0", object_type.as_str(), data.len()).as_bytes());
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Verify SHA-1 hash matches expected OID
    ///
    /// Requirements: 2.6
    fn verify_hash(
        oid: &str,
        object_type: GitObjectType,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let computed = Self::compute_git_hash(object_type, data);
        if computed != oid {
            return Err(StorageError::ObjectCorrupted {
                expected: oid.to_string(),
                actual: computed,
            });
        }
        Ok(())
    }

    /// Calculate exponential backoff delay for a given attempt
    ///
    /// Requirements: 9.1, 9.2
    ///
    /// Uses exponential backoff with jitter:
    /// delay = min(initial_backoff * 2^attempt + jitter, max_backoff)
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base_delay_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(attempt.saturating_sub(1));
        let max_backoff_ms = self.config.retry_max_backoff_secs * 1000;
        let capped_delay_ms = base_delay_ms.min(max_backoff_ms);

        // Add jitter (0-25% of delay) to prevent thundering herd
        let jitter_ms = (capped_delay_ms / 4) * (rand::random::<u64>() % 100) / 100;
        Duration::from_millis(capped_delay_ms + jitter_ms)
    }

    /// Log an S3 error with request ID and appropriate level
    ///
    /// Requirements: 9.6, 10.4
    fn log_s3_error(&self, ctx: &RetryContext, error: &StorageError, will_retry: bool) {
        let request_id = ctx.request_id.as_deref().unwrap_or("unknown");

        if will_retry {
            warn!(
                operation = %ctx.operation,
                request_id = %request_id,
                attempt = ctx.attempt,
                max_attempts = ctx.max_attempts,
                error = %error,
                "S3 operation failed, will retry"
            );
        } else {
            error!(
                operation = %ctx.operation,
                request_id = %request_id,
                attempt = ctx.attempt,
                max_attempts = ctx.max_attempts,
                error = %error,
                "S3 operation failed permanently"
            );
        }
    }

    /// Log a rate limit event
    ///
    /// Requirements: 9.3, 9.6
    fn log_rate_limit(&self, ctx: &RetryContext, delay_ms: u64) {
        let request_id = ctx.request_id.as_deref().unwrap_or("unknown");
        warn!(
            operation = %ctx.operation,
            request_id = %request_id,
            attempt = ctx.attempt,
            delay_ms = delay_ms,
            "S3 rate limited (503 SlowDown), applying adaptive delay"
        );
    }

    /// Execute an S3 operation with retry logic
    ///
    /// Requirements: 9.1, 9.2, 9.3
    ///
    /// This method implements exponential backoff retry for transient errors
    /// and adaptive rate limiting for 503 SlowDown responses.
    async fn execute_with_retry<F, Fut, T>(
        &self,
        operation: &str,
        mut operation_fn: F,
    ) -> Result<T, StorageError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<(T, Option<String>), StorageError>>,
    {
        let max_attempts = self.config.max_retries + 1; // max_retries is number of retries, not total attempts
        let mut last_error: Option<StorageError> = None;
        let mut last_request_id: Option<String> = None;

        for attempt in 1..=max_attempts {
            // Check if we should apply adaptive rate limit delay before the request
            if attempt > 1 {
                let adaptive_delay = self.rate_limit_state.get_adaptive_delay_ms();
                if adaptive_delay > RATE_LIMIT_MIN_DELAY_MS {
                    debug!(
                        operation = %operation,
                        attempt = attempt,
                        adaptive_delay_ms = adaptive_delay,
                        "Applying adaptive rate limit delay"
                    );
                    sleep(Duration::from_millis(adaptive_delay)).await;
                }
            }

            match operation_fn().await {
                Ok((result, request_id)) => {
                    // Record success for adaptive rate limiting
                    self.rate_limit_state.record_success();

                    if attempt > 1 {
                        info!(
                            operation = %operation,
                            request_id = request_id.as_deref().unwrap_or("unknown"),
                            attempt = attempt,
                            "S3 operation succeeded after retry"
                        );
                    }
                    return Ok(result);
                }
                Err(error) => {
                    // Extract request ID if available from error message
                    let request_id = extract_request_id_from_error(&error);
                    last_request_id = request_id.clone();

                    let ctx = RetryContext {
                        operation: operation.to_string(),
                        request_id,
                        attempt,
                        max_attempts,
                    };

                    let decision = error.retry_decision();
                    let is_last_attempt = attempt >= max_attempts;

                    match decision {
                        RetryDecision::RateLimited => {
                            self.rate_limit_state.record_rate_limit();
                            let delay_ms = self.rate_limit_state.get_adaptive_delay_ms();
                            self.log_rate_limit(&ctx, delay_ms);

                            if !is_last_attempt {
                                sleep(Duration::from_millis(delay_ms)).await;
                            }
                        }
                        RetryDecision::Retry => {
                            self.log_s3_error(&ctx, &error, !is_last_attempt);

                            if !is_last_attempt {
                                let backoff = self.calculate_backoff(attempt);
                                debug!(
                                    operation = %operation,
                                    attempt = attempt,
                                    backoff_ms = backoff.as_millis(),
                                    "Waiting before retry"
                                );
                                sleep(backoff).await;
                            }
                        }
                        RetryDecision::NoRetry => {
                            self.log_s3_error(&ctx, &error, false);
                            return Err(error);
                        }
                    }

                    last_error = Some(error);
                }
            }
        }

        // All retries exhausted
        let final_error = last_error.unwrap_or_else(|| {
            StorageError::Internal("All retry attempts exhausted".to_string())
        });

        let ctx = RetryContext {
            operation: operation.to_string(),
            request_id: last_request_id,
            attempt: max_attempts,
            max_attempts,
        };
        self.log_s3_error(&ctx, &final_error, false);

        Err(final_error)
    }

    /// Delete a batch of objects with retry for partial failures
    ///
    /// Requirements: 3.3, 3.4
    ///
    /// This method:
    /// - Attempts to delete up to 1000 objects in a single batch request
    /// - Retries failed objects with exponential backoff
    /// - Returns the count of successfully deleted objects and any remaining failures
    async fn delete_objects_batch_with_retry(
        &self,
        objects: &[String],
        max_retries: u32,
    ) -> DeleteResult {
        let mut deleted_count = 0;
        let mut remaining_objects = objects.to_vec();

        for attempt in 0..=max_retries {
            if remaining_objects.is_empty() {
                break;
            }

            // Build delete request
            let delete_objects: Vec<_> = remaining_objects
                .iter()
                .map(|key| {
                    aws_sdk_s3::types::ObjectIdentifier::builder()
                        .key(key)
                        .build()
                        .expect("valid object identifier")
                })
                .collect();

            let delete_request = aws_sdk_s3::types::Delete::builder()
                .set_objects(Some(delete_objects))
                .build()
                .expect("valid delete request");

            match self
                .client
                .delete_objects()
                .bucket(&self.bucket)
                .delete(delete_request)
                .send()
                .await
            {
                Ok(result) => {
                    deleted_count += result.deleted().len();

                    // Collect failed objects for retry
                    let failed_keys: Vec<String> = result
                        .errors()
                        .iter()
                        .filter_map(|e| e.key().map(String::from))
                        .collect();

                    if failed_keys.is_empty() {
                        // All objects deleted successfully
                        remaining_objects.clear();
                        break;
                    }

                    // Log partial failure
                    if attempt < max_retries {
                        warn!(
                            attempt = attempt + 1,
                            max_retries = max_retries,
                            failed_count = failed_keys.len(),
                            "Batch delete had partial failures, will retry"
                        );

                        // Apply backoff before retry
                        let backoff = self.calculate_backoff(attempt + 1);
                        sleep(backoff).await;
                    }

                    remaining_objects = failed_keys;
                }
                Err(e) => {
                    let err_str = e.to_string();

                    // Check if this is a retryable error
                    let is_retryable = err_str.contains("503")
                        || err_str.contains("500")
                        || err_str.contains("SlowDown")
                        || err_str.contains("timeout")
                        || err_str.contains("Timeout");

                    if is_retryable && attempt < max_retries {
                        warn!(
                            error = %e,
                            attempt = attempt + 1,
                            max_retries = max_retries,
                            "Batch delete failed with retryable error, will retry"
                        );

                        // Apply backoff before retry
                        let backoff = self.calculate_backoff(attempt + 1);
                        sleep(backoff).await;
                    } else {
                        error!(
                            error = %e,
                            attempt = attempt + 1,
                            objects_count = remaining_objects.len(),
                            "Batch delete failed permanently"
                        );
                        break;
                    }
                }
            }
        }

        DeleteResult {
            deleted_count,
            failed: remaining_objects,
        }
    }

    /// Copy a single object with retry logic
    ///
    /// Requirements: 3.5
    ///
    /// This method copies an object while preserving its metadata.
    async fn copy_object_with_retry(
        &self,
        source_key: &str,
        target_key: &str,
    ) -> Result<(), StorageError> {
        let copy_source = format!("{}/{}", self.bucket, source_key);
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let source_key_for_error = source_key.to_string();

        self.execute_with_retry("copy_object", || {
            let bucket = bucket.clone();
            let client = client.clone();
            let copy_source = copy_source.clone();
            let target_key = target_key.to_string();
            let source_key_for_error = source_key_for_error.clone();

            async move {
                let result = client
                    .copy_object()
                    .bucket(&bucket)
                    .copy_source(&copy_source)
                    .key(&target_key)
                    // Preserve metadata from source object
                    .metadata_directive(aws_sdk_s3::types::MetadataDirective::Copy)
                    .send()
                    .await;

                match result {
                    Ok(_) => Ok(((), None)),
                    Err(e) => {
                        let err = e.into_service_error();
                        let error = if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            StorageError::RateLimited(format!(
                                "S3 rate limited during copy_object: {}",
                                err
                            ))
                        } else if err.to_string().contains("500") {
                            StorageError::Internal(format!("S3 server error (500): {}", err))
                        } else if err.is_object_not_in_active_tier_error() {
                            StorageError::NotFound(format!("Source object not found: {}", source_key_for_error))
                        } else {
                            StorageError::Internal(err.to_string())
                        };
                        Err(error)
                    }
                }
            }
        })
        .await
    }
}

/// Extract S3 request ID from an error message if present
///
/// Requirements: 9.6, 10.4
fn extract_request_id_from_error(error: &StorageError) -> Option<String> {
    let error_str = error.to_string();

    // Look for common request ID patterns in AWS error messages
    // Pattern: "request id: XXXXX" or "RequestId: XXXXX"
    for pattern in &["request id: ", "RequestId: ", "request-id: "] {
        if let Some(pos) = error_str.find(pattern) {
            let start = pos + pattern.len();
            let rest = &error_str[start..];
            // Request IDs are typically alphanumeric with dashes
            let end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '-')
                .unwrap_or(rest.len());
            if end > 0 {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}


#[async_trait]
impl ObjectStorageBackend for S3ObjectStorage {
    /// Store a Git object in S3 with retry logic
    ///
    /// Requirements: 2.4, 2.5, 9.1, 9.2, 9.3
    async fn put_object(
        &self,
        repo_id: &str,
        oid: &str,
        object_type: GitObjectType,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let key = Self::object_key(repo_id, oid);
        let data_vec = data.to_vec();
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let content_type = object_type.content_type().to_string();
        let object_type_str = object_type.as_str().to_string();
        let data_len = data.len();

        debug!(
            repo_id = %repo_id,
            oid = %oid,
            object_type = %object_type,
            size = data_len,
            key = %key,
            "Storing object in S3"
        );

        self.execute_with_retry("put_object", || {
            let key = key.clone();
            let data_vec = data_vec.clone();
            let bucket = bucket.clone();
            let client = client.clone();
            let content_type = content_type.clone();
            let object_type_str = object_type_str.clone();

            async move {
                let body = ByteStream::from(data_vec);

                let result = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .body(body)
                    .content_type(&content_type)
                    .metadata("x-git-object-type", &object_type_str)
                    .metadata("x-git-object-size", &data_len.to_string())
                    .send()
                    .await;

                match result {
                    Ok(output) => {
                        let request_id = output.request_charged().map(|_| "charged".to_string());
                        Ok(((), request_id))
                    }
                    Err(e) => {
                        let err = e.into_service_error();
                        let error = if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            StorageError::RateLimited(format!(
                                "S3 rate limited during put_object: {}",
                                err
                            ))
                        } else if err.to_string().contains("500") {
                            StorageError::UploadFailed(format!("S3 server error (500): {}", err))
                        } else {
                            StorageError::UploadFailed(err.to_string())
                        };
                        Err(error)
                    }
                }
            }
        })
        .await?;

        debug!(key = %key, "Object stored successfully");
        Ok(())
    }

    /// Retrieve a Git object from S3 with SHA-1 verification and retry logic
    ///
    /// Requirements: 2.6, 9.1, 9.2, 9.3
    async fn get_object(&self, repo_id: &str, oid: &str) -> Result<StoredObject, StorageError> {
        let key = Self::object_key(repo_id, oid);
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let oid_owned = oid.to_string();

        debug!(repo_id = %repo_id, oid = %oid, key = %key, "Retrieving object from S3");

        let (data, object_type) = self
            .execute_with_retry("get_object", || {
                let key = key.clone();
                let bucket = bucket.clone();
                let client = client.clone();

                async move {
                    let result = client
                        .get_object()
                        .bucket(&bucket)
                        .key(&key)
                        .send()
                        .await;

                    match result {
                        Ok(response) => {
                            // Get object type from metadata before consuming body
                            let object_type_str = response
                                .metadata()
                                .and_then(|m| m.get("x-git-object-type"))
                                .cloned()
                                .unwrap_or_else(|| "blob".to_string());

                            let object_type = GitObjectType::from_str(&object_type_str)
                                .unwrap_or(GitObjectType::Blob);

                            // Read object data
                            let data = response
                                .body
                                .collect()
                                .await
                                .map_err(|e| StorageError::DownloadFailed(e.to_string()))?
                                .into_bytes()
                                .to_vec();

                            Ok(((data, object_type), None))
                        }
                        Err(e) => {
                            let err = e.into_service_error();
                            let error = if err.is_no_such_key() {
                                StorageError::NotFound(format!("Object not found in S3"))
                            } else if err.to_string().contains("503")
                                || err.to_string().contains("SlowDown")
                            {
                                StorageError::RateLimited(format!(
                                    "S3 rate limited during get_object: {}",
                                    err
                                ))
                            } else if err.to_string().contains("500") {
                                StorageError::DownloadFailed(format!(
                                    "S3 server error (500): {}",
                                    err
                                ))
                            } else {
                                StorageError::DownloadFailed(err.to_string())
                            };
                            Err(error)
                        }
                    }
                }
            })
            .await?;

        // Verify SHA-1 hash matches OID
        Self::verify_hash(&oid_owned, object_type, &data)?;

        debug!(
            oid = %oid,
            object_type = %object_type,
            size = data.len(),
            "Object retrieved and verified"
        );

        Ok(StoredObject {
            oid: oid_owned,
            object_type,
            size: data.len(),
            data,
        })
    }

    /// Delete a Git object from S3 with retry logic
    ///
    /// Requirements: 9.1, 9.2, 9.3
    async fn delete_object(&self, repo_id: &str, oid: &str) -> Result<(), StorageError> {
        let key = Self::object_key(repo_id, oid);
        let bucket = self.bucket.clone();
        let client = self.client.clone();

        debug!(repo_id = %repo_id, oid = %oid, key = %key, "Deleting object from S3");

        self.execute_with_retry("delete_object", || {
            let key = key.clone();
            let bucket = bucket.clone();
            let client = client.clone();

            async move {
                let result = client
                    .delete_object()
                    .bucket(&bucket)
                    .key(&key)
                    .send()
                    .await;

                match result {
                    Ok(_) => Ok(((), None)),
                    Err(e) => {
                        let err = e.into_service_error();
                        let error = if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            StorageError::RateLimited(format!(
                                "S3 rate limited during delete_object: {}",
                                err
                            ))
                        } else if err.to_string().contains("500") {
                            StorageError::DeleteFailed(format!("S3 server error (500): {}", err))
                        } else {
                            StorageError::DeleteFailed(err.to_string())
                        };
                        Err(error)
                    }
                }
            }
        })
        .await?;

        debug!(key = %key, "Object deleted successfully");
        Ok(())
    }

    /// List objects in a repository with retry logic
    ///
    /// Requirements: 9.1, 9.2, 9.3
    async fn list_objects(
        &self,
        repo_id: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
    ) -> Result<ObjectList, StorageError> {
        let full_prefix = match prefix {
            Some(p) => format!("{}/objects/{}", repo_id, p),
            None => format!("{}/objects/", repo_id),
        };
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let token = continuation_token.map(String::from);

        debug!(
            repo_id = %repo_id,
            prefix = %full_prefix,
            "Listing objects in S3"
        );

        self.execute_with_retry("list_objects", || {
            let full_prefix = full_prefix.clone();
            let bucket = bucket.clone();
            let client = client.clone();
            let token = token.clone();

            async move {
                let mut request = client
                    .list_objects_v2()
                    .bucket(&bucket)
                    .prefix(&full_prefix);

                if let Some(ref t) = token {
                    request = request.continuation_token(t);
                }

                let result = request.send().await;

                match result {
                    Ok(response) => {
                        // Extract OIDs from keys
                        let objects: Vec<String> = response
                            .contents()
                            .iter()
                            .filter_map(|obj| {
                                obj.key().and_then(|key| {
                                    // Extract OID from key: {repo_id}/objects/{xx}/{rest}
                                    let parts: Vec<&str> = key.split('/').collect();
                                    if parts.len() >= 4 && parts[1] == "objects" {
                                        Some(format!("{}{}", parts[2], parts[3]))
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect();

                        let list = ObjectList {
                            objects,
                            continuation_token: response.next_continuation_token().map(String::from),
                            is_truncated: response.is_truncated().unwrap_or(false),
                        };

                        Ok((list, None))
                    }
                    Err(e) => {
                        let err = e.into_service_error();
                        let error = if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            StorageError::RateLimited(format!(
                                "S3 rate limited during list_objects: {}",
                                err
                            ))
                        } else if err.to_string().contains("500") {
                            StorageError::Internal(format!("S3 server error (500): {}", err))
                        } else {
                            StorageError::Internal(err.to_string())
                        };
                        Err(error)
                    }
                }
            }
        })
        .await
    }

    /// Check if an object exists and get its metadata with retry logic
    ///
    /// Requirements: 9.1, 9.2, 9.3
    async fn head_object(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        let key = Self::object_key(repo_id, oid);
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let oid_owned = oid.to_string();

        debug!(repo_id = %repo_id, oid = %oid, key = %key, "Checking object existence in S3");

        self.execute_with_retry("head_object", || {
            let key = key.clone();
            let bucket = bucket.clone();
            let client = client.clone();
            let oid_owned = oid_owned.clone();

            async move {
                let result = client
                    .head_object()
                    .bucket(&bucket)
                    .key(&key)
                    .send()
                    .await;

                match result {
                    Ok(response) => {
                        let object_type_str = response
                            .metadata()
                            .and_then(|m| m.get("x-git-object-type"))
                            .map(String::as_str)
                            .unwrap_or("blob");

                        let object_type =
                            GitObjectType::from_str(object_type_str).unwrap_or(GitObjectType::Blob);

                        let size = response.content_length().unwrap_or(0) as usize;

                        let metadata = ObjectMetadata {
                            oid: oid_owned,
                            object_type,
                            size,
                        };

                        Ok((Some(metadata), None))
                    }
                    Err(e) => {
                        let err = e.into_service_error();
                        if err.is_not_found() {
                            Ok((None, None))
                        } else if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            Err(StorageError::RateLimited(format!(
                                "S3 rate limited during head_object: {}",
                                err
                            )))
                        } else if err.to_string().contains("500") {
                            Err(StorageError::Internal(format!(
                                "S3 server error (500): {}",
                                err
                            )))
                        } else {
                            Err(StorageError::Internal(err.to_string()))
                        }
                    }
                }
            }
        })
        .await
    }

    /// Store a packfile with its index using retry logic
    ///
    /// Requirements: 2.2, 2.3, 9.1, 9.2, 9.3
    async fn put_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
        packfile: &[u8],
        index: &[u8],
    ) -> Result<(), StorageError> {
        let pack_key = Self::packfile_key(repo_id, pack_hash);
        let idx_key = Self::packfile_index_key(repo_id, pack_hash);
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let packfile_vec = packfile.to_vec();
        let index_vec = index.to_vec();

        debug!(
            repo_id = %repo_id,
            pack_hash = %pack_hash,
            pack_size = packfile.len(),
            idx_size = index.len(),
            "Storing packfile in S3"
        );

        // Store packfile with retry
        self.execute_with_retry("put_packfile", || {
            let pack_key = pack_key.clone();
            let bucket = bucket.clone();
            let client = client.clone();
            let packfile_vec = packfile_vec.clone();

            async move {
                let result = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&pack_key)
                    .body(ByteStream::from(packfile_vec))
                    .content_type("application/x-git-packfile")
                    .send()
                    .await;

                match result {
                    Ok(_) => Ok(((), None)),
                    Err(e) => {
                        let err = e.into_service_error();
                        let error = if err.to_string().contains("503")
                            || err.to_string().contains("SlowDown")
                        {
                            StorageError::RateLimited(format!(
                                "S3 rate limited during put_packfile: {}",
                                err
                            ))
                        } else if err.to_string().contains("500") {
                            StorageError::UploadFailed(format!("S3 server error (500): {}", err))
                        } else {
                            StorageError::UploadFailed(err.to_string())
                        };
                        Err(error)
                    }
                }
            }
        })
        .await?;

        // Store index with retry
        let idx_result = self
            .execute_with_retry("put_packfile_index", || {
                let idx_key = idx_key.clone();
                let bucket = bucket.clone();
                let client = client.clone();
                let index_vec = index_vec.clone();

                async move {
                    let result = client
                        .put_object()
                        .bucket(&bucket)
                        .key(&idx_key)
                        .body(ByteStream::from(index_vec))
                        .content_type("application/x-git-packfile-index")
                        .send()
                        .await;

                    match result {
                        Ok(_) => Ok(((), None)),
                        Err(e) => {
                            let err = e.into_service_error();
                            let error = if err.to_string().contains("503")
                                || err.to_string().contains("SlowDown")
                            {
                                StorageError::RateLimited(format!(
                                    "S3 rate limited during put_packfile_index: {}",
                                    err
                                ))
                            } else if err.to_string().contains("500") {
                                StorageError::UploadFailed(format!(
                                    "S3 server error (500): {}",
                                    err
                                ))
                            } else {
                                StorageError::UploadFailed(err.to_string())
                            };
                            Err(error)
                        }
                    }
                }
            })
            .await;

        // If index upload failed, try to clean up the packfile
        if idx_result.is_err() {
            warn!(
                pack_key = %pack_key,
                "Index upload failed, attempting to clean up packfile"
            );
            let _ = self.client.delete_object().bucket(&bucket).key(&pack_key).send().await;
        }

        idx_result?;

        debug!(pack_key = %pack_key, idx_key = %idx_key, "Packfile stored successfully");
        Ok(())
    }

    /// Retrieve a packfile with its index using retry logic
    ///
    /// Requirements: 9.1, 9.2, 9.3
    async fn get_packfile(
        &self,
        repo_id: &str,
        pack_hash: &str,
    ) -> Result<PackfileData, StorageError> {
        let pack_key = Self::packfile_key(repo_id, pack_hash);
        let idx_key = Self::packfile_index_key(repo_id, pack_hash);
        let bucket = self.bucket.clone();
        let client = self.client.clone();
        let pack_hash_owned = pack_hash.to_string();

        debug!(
            repo_id = %repo_id,
            pack_hash = %pack_hash,
            "Retrieving packfile from S3"
        );

        // Get packfile with retry
        let packfile = self
            .execute_with_retry("get_packfile", || {
                let pack_key = pack_key.clone();
                let bucket = bucket.clone();
                let client = client.clone();
                let pack_hash_owned = pack_hash_owned.clone();

                async move {
                    let result = client
                        .get_object()
                        .bucket(&bucket)
                        .key(&pack_key)
                        .send()
                        .await;

                    match result {
                        Ok(response) => {
                            let data = response
                                .body
                                .collect()
                                .await
                                .map_err(|e| StorageError::DownloadFailed(e.to_string()))?
                                .into_bytes()
                                .to_vec();
                            Ok((data, None))
                        }
                        Err(e) => {
                            let err = e.into_service_error();
                            let error = if err.is_no_such_key() {
                                StorageError::NotFound(format!(
                                    "Packfile {} not found",
                                    pack_hash_owned
                                ))
                            } else if err.to_string().contains("503")
                                || err.to_string().contains("SlowDown")
                            {
                                StorageError::RateLimited(format!(
                                    "S3 rate limited during get_packfile: {}",
                                    err
                                ))
                            } else if err.to_string().contains("500") {
                                StorageError::DownloadFailed(format!(
                                    "S3 server error (500): {}",
                                    err
                                ))
                            } else {
                                StorageError::DownloadFailed(err.to_string())
                            };
                            Err(error)
                        }
                    }
                }
            })
            .await?;

        // Get index with retry
        let index = self
            .execute_with_retry("get_packfile_index", || {
                let idx_key = idx_key.clone();
                let bucket = bucket.clone();
                let client = client.clone();
                let pack_hash_owned = pack_hash_owned.clone();

                async move {
                    let result = client
                        .get_object()
                        .bucket(&bucket)
                        .key(&idx_key)
                        .send()
                        .await;

                    match result {
                        Ok(response) => {
                            let data = response
                                .body
                                .collect()
                                .await
                                .map_err(|e| StorageError::DownloadFailed(e.to_string()))?
                                .into_bytes()
                                .to_vec();
                            Ok((data, None))
                        }
                        Err(e) => {
                            let err = e.into_service_error();
                            let error = if err.is_no_such_key() {
                                StorageError::NotFound(format!(
                                    "Packfile index {} not found",
                                    pack_hash_owned
                                ))
                            } else if err.to_string().contains("503")
                                || err.to_string().contains("SlowDown")
                            {
                                StorageError::RateLimited(format!(
                                    "S3 rate limited during get_packfile_index: {}",
                                    err
                                ))
                            } else if err.to_string().contains("500") {
                                StorageError::DownloadFailed(format!(
                                    "S3 server error (500): {}",
                                    err
                                ))
                            } else {
                                StorageError::DownloadFailed(err.to_string())
                            };
                            Err(error)
                        }
                    }
                }
            })
            .await?;

        debug!(
            pack_hash = %pack_hash,
            pack_size = packfile.len(),
            idx_size = index.len(),
            "Packfile retrieved successfully"
        );

        Ok(PackfileData {
            pack_hash: pack_hash_owned,
            packfile,
            index,
        })
    }

    /// Delete all objects for a repository
    ///
    /// Requirements: 3.2, 3.3, 3.4
    ///
    /// This method:
    /// - Lists all objects under the repository prefix
    /// - Uses batch delete (up to 1000 objects per request) for efficiency
    /// - Handles partial failures with retry (up to max_retries attempts)
    /// - Logs errors and marks repository for cleanup retry if deletion fails
    async fn delete_repository_objects(&self, repo_id: &str) -> Result<DeleteResult, StorageError> {
        let prefix = format!("{}/", repo_id);
        let max_retries = self.config.max_retries;

        debug!(repo_id = %repo_id, prefix = %prefix, "Deleting all repository objects from S3");

        let mut deleted_count = 0;
        let mut failed = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            // List objects with prefix using retry logic
            let response = self
                .execute_with_retry("list_objects_for_delete", || {
                    let prefix = prefix.clone();
                    let bucket = self.bucket.clone();
                    let client = self.client.clone();
                    let token = continuation_token.clone();

                    async move {
                        let mut request = client
                            .list_objects_v2()
                            .bucket(&bucket)
                            .prefix(&prefix)
                            .max_keys(1000);

                        if let Some(ref t) = token {
                            request = request.continuation_token(t);
                        }

                        match request.send().await {
                            Ok(response) => Ok((response, None)),
                            Err(e) => {
                                let err = e.into_service_error();
                                let error = if err.to_string().contains("503")
                                    || err.to_string().contains("SlowDown")
                                {
                                    StorageError::RateLimited(format!(
                                        "S3 rate limited during list_objects_for_delete: {}",
                                        err
                                    ))
                                } else if err.to_string().contains("500") {
                                    StorageError::Internal(format!("S3 server error (500): {}", err))
                                } else {
                                    StorageError::Internal(err.to_string())
                                };
                                Err(error)
                            }
                        }
                    }
                })
                .await?;

            let objects: Vec<_> = response
                .contents()
                .iter()
                .filter_map(|obj| obj.key().map(String::from))
                .collect();

            if objects.is_empty() {
                break;
            }

            // Delete objects in batch with retry for partial failures
            let batch_result = self
                .delete_objects_batch_with_retry(&objects, max_retries)
                .await;

            deleted_count += batch_result.deleted_count;
            failed.extend(batch_result.failed);

            // Check for more objects
            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        // Log final result
        if failed.is_empty() {
            info!(
                repo_id = %repo_id,
                deleted_count = deleted_count,
                "Repository deletion completed successfully"
            );
        } else {
            warn!(
                repo_id = %repo_id,
                deleted_count = deleted_count,
                failed_count = failed.len(),
                "Repository deletion completed with failures - mark for cleanup retry"
            );
        }

        Ok(DeleteResult {
            deleted_count,
            failed,
        })
    }

    /// Copy all objects from one repository to another (for forking)
    ///
    /// Requirements: 3.5
    ///
    /// This method:
    /// - Lists all objects under the source repository prefix
    /// - Copies each object to the target repository prefix
    /// - Preserves object metadata during copy
    /// - Uses retry logic for transient failures
    async fn copy_repository_objects(
        &self,
        source_repo_id: &str,
        target_repo_id: &str,
    ) -> Result<CopyResult, StorageError> {
        let source_prefix = format!("{}/", source_repo_id);

        debug!(
            source = source_repo_id,
            target = target_repo_id,
            "Copying repository objects in S3"
        );

        let mut copied_count = 0;
        let mut failed = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            // List source objects with retry logic
            let response = self
                .execute_with_retry("list_objects_for_copy", || {
                    let source_prefix = source_prefix.clone();
                    let bucket = self.bucket.clone();
                    let client = self.client.clone();
                    let token = continuation_token.clone();

                    async move {
                        let mut request = client
                            .list_objects_v2()
                            .bucket(&bucket)
                            .prefix(&source_prefix);

                        if let Some(ref t) = token {
                            request = request.continuation_token(t);
                        }

                        match request.send().await {
                            Ok(response) => Ok((response, None)),
                            Err(e) => {
                                let err = e.into_service_error();
                                let error = if err.to_string().contains("503")
                                    || err.to_string().contains("SlowDown")
                                {
                                    StorageError::RateLimited(format!(
                                        "S3 rate limited during list_objects_for_copy: {}",
                                        err
                                    ))
                                } else if err.to_string().contains("500") {
                                    StorageError::Internal(format!("S3 server error (500): {}", err))
                                } else {
                                    StorageError::Internal(err.to_string())
                                };
                                Err(error)
                            }
                        }
                    }
                })
                .await?;

            for obj in response.contents() {
                if let Some(source_key) = obj.key() {
                    // Build target key by replacing source repo_id with target
                    let target_key = source_key.replacen(source_repo_id, target_repo_id, 1);

                    // Copy object with retry logic and metadata preservation
                    match self.copy_object_with_retry(source_key, &target_key).await {
                        Ok(()) => {
                            copied_count += 1;
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                source = source_key,
                                target = target_key,
                                "Failed to copy object after retries"
                            );
                            failed.push(source_key.to_string());
                        }
                    }
                }
            }

            // Check for more objects
            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        // Log final result
        if failed.is_empty() {
            info!(
                source = source_repo_id,
                target = target_repo_id,
                copied_count = copied_count,
                "Repository copy completed successfully"
            );
        } else {
            warn!(
                source = source_repo_id,
                target = target_repo_id,
                copied_count = copied_count,
                failed_count = failed.len(),
                "Repository copy completed with failures"
            );
        }

        Ok(CopyResult {
            copied_count,
            failed,
        })
    }
}


// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a boolean environment variable
///
/// Accepts: "true", "1", "yes" (case-insensitive) for true
/// Accepts: "false", "0", "no" (case-insensitive) or unset for false
fn parse_bool_env(var_name: &str) -> Result<bool, ConfigError> {
    match env::var(var_name) {
        Ok(value) => {
            let lower = value.to_lowercase();
            match lower.as_str() {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" | "" => Ok(false),
                _ => Err(ConfigError::InvalidValue {
                    variable: var_name.to_string(),
                    message: format!(
                        "expected 'true', 'false', '1', '0', 'yes', or 'no', got '{value}'"
                    ),
                }),
            }
        }
        Err(_) => Ok(false), // Default to false if not set
    }
}

/// Parse a u32 environment variable with a default value
fn parse_u32_env(var_name: &str, default: u32) -> Result<u32, ConfigError> {
    match env::var(var_name) {
        Ok(value) if !value.is_empty() => {
            value.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
                variable: var_name.to_string(),
                message: format!("expected a positive integer, got '{value}'"),
            })
        }
        _ => Ok(default),
    }
}

/// Parse a u64 environment variable with a default value
fn parse_u64_env(var_name: &str, default: u64) -> Result<u64, ConfigError> {
    match env::var(var_name) {
        Ok(value) if !value.is_empty() => {
            value.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                variable: var_name.to_string(),
                message: format!("expected a positive integer, got '{value}'"),
            })
        }
        _ => Ok(default),
    }
}

#[cfg(test)]
#[path = "object_storage_tests.rs"]
mod tests;

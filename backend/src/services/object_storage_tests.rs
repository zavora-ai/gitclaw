//! Tests for S3 Object Storage configuration
//!
//! Uses temp-env crate for safe environment variable manipulation in Rust 2024 edition.

use super::{ConfigError, S3Config};

#[test]
fn test_default_config() {
    let config = S3Config::default();
    assert!(config.endpoint.is_none());
    assert!(config.bucket.is_empty());
    assert_eq!(config.region, "us-east-1");
    assert!(config.access_key_id.is_none());
    assert!(config.secret_access_key.is_none());
    assert!(!config.use_path_style);
    assert!(!config.auto_create_bucket);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_max_backoff_secs, 30);
}

#[test]
fn test_from_env_missing_bucket() {
    temp_env::with_vars_unset(
        vec![
            "S3_ENDPOINT",
            "S3_BUCKET",
            "S3_REGION",
            "S3_ACCESS_KEY_ID",
            "S3_SECRET_ACCESS_KEY",
            "S3_USE_PATH_STYLE",
            "S3_AUTO_CREATE_BUCKET",
            "S3_MAX_RETRIES",
            "S3_RETRY_MAX_BACKOFF",
        ],
        || {
            let result = S3Config::from_env();
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                ConfigError::MissingEnvVar("S3_BUCKET".to_string())
            );
        },
    );
}

#[test]
fn test_from_env_minimal_config() {
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_USE_PATH_STYLE", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse minimal config");
            assert_eq!(config.bucket, "test-bucket");
            assert_eq!(config.region, "us-east-1"); // Default
            assert!(config.endpoint.is_none());
            assert!(config.access_key_id.is_none());
            assert!(config.secret_access_key.is_none());
            assert!(!config.use_path_style);
            assert!(!config.auto_create_bucket);
            assert_eq!(config.max_retries, 3);
            assert_eq!(config.retry_max_backoff_secs, 30);
        },
    );
}

#[test]
fn test_from_env_full_config() {
    temp_env::with_vars(
        vec![
            ("S3_ENDPOINT", Some("http://localhost:9000")),
            ("S3_BUCKET", Some("gitclaw-objects")),
            ("S3_REGION", Some("us-west-2")),
            ("S3_ACCESS_KEY_ID", Some("minioadmin")),
            ("S3_SECRET_ACCESS_KEY", Some("minioadmin123")),
            ("S3_USE_PATH_STYLE", Some("true")),
            ("S3_AUTO_CREATE_BUCKET", Some("yes")),
            ("S3_MAX_RETRIES", Some("5")),
            ("S3_RETRY_MAX_BACKOFF", Some("60")),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse full config");
            assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
            assert_eq!(config.bucket, "gitclaw-objects");
            assert_eq!(config.region, "us-west-2");
            assert_eq!(config.access_key_id, Some("minioadmin".to_string()));
            assert_eq!(config.secret_access_key, Some("minioadmin123".to_string()));
            assert!(config.use_path_style);
            assert!(config.auto_create_bucket);
            assert_eq!(config.max_retries, 5);
            assert_eq!(config.retry_max_backoff_secs, 60);
        },
    );
}


#[test]
fn test_from_env_path_style_true_variations() {
    // Test "1"
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("1")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse '1' as true");
            assert!(config.use_path_style);
        },
    );

    // Test "yes"
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("yes")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse 'yes' as true");
            assert!(config.use_path_style);
        },
    );

    // Test "TRUE" (case insensitive)
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("TRUE")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse 'TRUE' as true");
            assert!(config.use_path_style);
        },
    );
}

#[test]
fn test_from_env_path_style_false_variations() {
    // Test "0"
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("0")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse '0' as false");
            assert!(!config.use_path_style);
        },
    );

    // Test "no"
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("no")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse 'no' as false");
            assert!(!config.use_path_style);
        },
    );
}

#[test]
fn test_from_env_invalid_bool() {
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_USE_PATH_STYLE", Some("invalid")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let result = S3Config::from_env();
            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::InvalidValue { variable, .. } => {
                    assert_eq!(variable, "S3_USE_PATH_STYLE");
                }
                _ => panic!("Expected InvalidValue error"),
            }
        },
    );
}

#[test]
fn test_from_env_invalid_max_retries() {
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_MAX_RETRIES", Some("not-a-number")),
            ("S3_ENDPOINT", None),
            ("S3_REGION", None),
            ("S3_ACCESS_KEY_ID", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_USE_PATH_STYLE", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let result = S3Config::from_env();
            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::InvalidValue { variable, .. } => {
                    assert_eq!(variable, "S3_MAX_RETRIES");
                }
                _ => panic!("Expected InvalidValue error"),
            }
        },
    );
}

#[test]
fn test_from_env_empty_optional_values_treated_as_none() {
    temp_env::with_vars(
        vec![
            ("S3_BUCKET", Some("test-bucket")),
            ("S3_ENDPOINT", Some("")),
            ("S3_ACCESS_KEY_ID", Some("")),
            ("S3_REGION", None),
            ("S3_SECRET_ACCESS_KEY", None),
            ("S3_USE_PATH_STYLE", None),
            ("S3_AUTO_CREATE_BUCKET", None),
            ("S3_MAX_RETRIES", None),
            ("S3_RETRY_MAX_BACKOFF", None),
        ],
        || {
            let config = S3Config::from_env().expect("Should parse config with empty optionals");
            assert!(config.endpoint.is_none());
            assert!(config.access_key_id.is_none());
        },
    );
}


// Validation tests - these don't need env vars, they test the validate() method directly

#[test]
fn test_validate_empty_bucket() {
    let config = S3Config {
        bucket: String::new(),
        region: "us-east-1".to_string(),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("cannot be empty"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_bucket_too_short() {
    let config = S3Config {
        bucket: "ab".to_string(),
        region: "us-east-1".to_string(),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("at least 3 characters"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_bucket_too_long() {
    let config = S3Config {
        bucket: "a".repeat(64),
        region: "us-east-1".to_string(),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("at most 63 characters"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_empty_region() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: String::new(),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("S3_REGION cannot be empty"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_partial_credentials_access_key_only() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
        secret_access_key: None,
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("S3_SECRET_ACCESS_KEY is required"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_partial_credentials_secret_key_only() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key_id: None,
        secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("S3_ACCESS_KEY_ID is required"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_invalid_endpoint_no_scheme() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("localhost:9000".to_string()),
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("must start with http:// or https://"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_max_retries_too_high() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        max_retries: 15,
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("should not exceed 10"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_backoff_too_high() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        retry_max_backoff_secs: 500,
        ..Default::default()
    };

    let result = config.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed(msg) => {
            assert!(msg.contains("should not exceed 300 seconds"));
        }
        _ => panic!("Expected ValidationFailed error"),
    }
}

#[test]
fn test_validate_valid_config() {
    let config = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("https://s3.amazonaws.com".to_string()),
        access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
        secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
        use_path_style: true,
        auto_create_bucket: true,
        max_retries: 5,
        retry_max_backoff_secs: 60,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_has_static_credentials() {
    let config_with_creds = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
        secret_access_key: Some("secret".to_string()),
        ..Default::default()
    };
    assert!(config_with_creds.has_static_credentials());

    let config_without_creds = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        ..Default::default()
    };
    assert!(!config_without_creds.has_static_credentials());
}

#[test]
fn test_has_custom_endpoint() {
    let config_with_endpoint = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some("http://localhost:9000".to_string()),
        ..Default::default()
    };
    assert!(config_with_endpoint.has_custom_endpoint());

    let config_without_endpoint = S3Config {
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        ..Default::default()
    };
    assert!(!config_without_endpoint.has_custom_endpoint());
}

// ============================================================================
// S3ObjectStorage Path Generation Tests
// ============================================================================

use super::{GitObjectType, S3ObjectStorage};

#[test]
fn test_object_key_format() {
    // Test standard 40-character OID
    let key = S3ObjectStorage::object_key("repo123", "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(
        key,
        "repo123/objects/01/23456789abcdef0123456789abcdef01234567"
    );
}

#[test]
fn test_object_key_with_different_repo_ids() {
    let key1 = S3ObjectStorage::object_key("repo-a", "abcdef1234567890abcdef1234567890abcdef12");
    let key2 = S3ObjectStorage::object_key("repo-b", "abcdef1234567890abcdef1234567890abcdef12");

    assert_eq!(
        key1,
        "repo-a/objects/ab/cdef1234567890abcdef1234567890abcdef12"
    );
    assert_eq!(
        key2,
        "repo-b/objects/ab/cdef1234567890abcdef1234567890abcdef12"
    );
}

#[test]
fn test_object_key_short_oid() {
    // Edge case: OID shorter than 2 characters
    let key = S3ObjectStorage::object_key("repo", "a");
    assert_eq!(key, "repo/objects/a");
}

#[test]
fn test_object_key_two_char_oid() {
    // Edge case: exactly 2 character OID
    let key = S3ObjectStorage::object_key("repo", "ab");
    assert_eq!(key, "repo/objects/ab/");
}

#[test]
fn test_packfile_key_format() {
    let key = S3ObjectStorage::packfile_key("repo123", "abc123def456");
    assert_eq!(key, "repo123/pack/pack-abc123def456.pack");
}

#[test]
fn test_packfile_index_key_format() {
    let key = S3ObjectStorage::packfile_index_key("repo123", "abc123def456");
    assert_eq!(key, "repo123/pack/pack-abc123def456.idx");
}

#[test]
fn test_packfile_keys_match() {
    let pack_hash = "fedcba9876543210";
    let repo_id = "my-repo";

    let pack_key = S3ObjectStorage::packfile_key(repo_id, pack_hash);
    let idx_key = S3ObjectStorage::packfile_index_key(repo_id, pack_hash);

    // Both should have same prefix, different extensions
    assert!(pack_key.ends_with(".pack"));
    assert!(idx_key.ends_with(".idx"));
    assert_eq!(
        pack_key.strip_suffix(".pack"),
        idx_key.strip_suffix(".idx")
    );
}

// ============================================================================
// GitObjectType Tests
// ============================================================================

#[test]
fn test_git_object_type_as_str() {
    assert_eq!(GitObjectType::Commit.as_str(), "commit");
    assert_eq!(GitObjectType::Tree.as_str(), "tree");
    assert_eq!(GitObjectType::Blob.as_str(), "blob");
    assert_eq!(GitObjectType::Tag.as_str(), "tag");
}

#[test]
fn test_git_object_type_content_type() {
    // All loose objects have the same content type
    assert_eq!(
        GitObjectType::Commit.content_type(),
        "application/x-git-loose-object"
    );
    assert_eq!(
        GitObjectType::Tree.content_type(),
        "application/x-git-loose-object"
    );
    assert_eq!(
        GitObjectType::Blob.content_type(),
        "application/x-git-loose-object"
    );
    assert_eq!(
        GitObjectType::Tag.content_type(),
        "application/x-git-loose-object"
    );
}

#[test]
fn test_git_object_type_from_str() {
    assert_eq!(GitObjectType::from_str("commit"), Some(GitObjectType::Commit));
    assert_eq!(GitObjectType::from_str("tree"), Some(GitObjectType::Tree));
    assert_eq!(GitObjectType::from_str("blob"), Some(GitObjectType::Blob));
    assert_eq!(GitObjectType::from_str("tag"), Some(GitObjectType::Tag));

    // Case insensitive
    assert_eq!(GitObjectType::from_str("COMMIT"), Some(GitObjectType::Commit));
    assert_eq!(GitObjectType::from_str("Blob"), Some(GitObjectType::Blob));

    // Invalid types
    assert_eq!(GitObjectType::from_str("invalid"), None);
    assert_eq!(GitObjectType::from_str(""), None);
}

#[test]
fn test_git_object_type_display() {
    assert_eq!(format!("{}", GitObjectType::Commit), "commit");
    assert_eq!(format!("{}", GitObjectType::Tree), "tree");
    assert_eq!(format!("{}", GitObjectType::Blob), "blob");
    assert_eq!(format!("{}", GitObjectType::Tag), "tag");
}


// ============================================================================
// Retry Logic and Rate Limiting Tests
// ============================================================================

use super::{RateLimitState, RetryContext, RetryDecision, StorageError};

#[test]
fn test_retry_decision_rate_limited() {
    let error = StorageError::RateLimited("503 SlowDown".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::RateLimited);
}

#[test]
fn test_retry_decision_connection_error() {
    let error = StorageError::ConnectionError("connection refused".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_upload_failed_503() {
    let error = StorageError::UploadFailed("503 Service Unavailable".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::RateLimited);
}

#[test]
fn test_retry_decision_upload_failed_500() {
    let error = StorageError::UploadFailed("500 Internal Server Error".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_upload_failed_timeout() {
    let error = StorageError::UploadFailed("connection timeout".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_upload_failed_other() {
    let error = StorageError::UploadFailed("access denied".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_download_failed_503() {
    let error = StorageError::DownloadFailed("503 SlowDown".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::RateLimited);
}

#[test]
fn test_retry_decision_download_failed_500() {
    let error = StorageError::DownloadFailed("500 Internal Server Error".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_not_found() {
    let error = StorageError::NotFound("object not found".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_object_corrupted() {
    let error = StorageError::ObjectCorrupted {
        expected: "abc123".to_string(),
        actual: "def456".to_string(),
    };
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_access_denied() {
    let error = StorageError::AccessDenied("invalid credentials".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_bucket_not_found() {
    let error = StorageError::BucketNotFound("bucket-name".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_invalid_data() {
    let error = StorageError::InvalidData("malformed data".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

#[test]
fn test_retry_decision_internal_503() {
    let error = StorageError::Internal("503 SlowDown response".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::RateLimited);
}

#[test]
fn test_retry_decision_internal_500() {
    let error = StorageError::Internal("500 Internal Server Error".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_internal_timeout() {
    let error = StorageError::Internal("request Timeout".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::Retry);
}

#[test]
fn test_retry_decision_internal_other() {
    let error = StorageError::Internal("unknown error".to_string());
    assert_eq!(error.retry_decision(), RetryDecision::NoRetry);
}

// ============================================================================
// Rate Limit State Tests
// ============================================================================

#[test]
fn test_rate_limit_state_new() {
    let state = RateLimitState::new();
    // Initial delay should be the minimum
    assert_eq!(state.get_adaptive_delay_ms(), 1000); // RATE_LIMIT_MIN_DELAY_MS
}

#[test]
fn test_rate_limit_state_record_rate_limit_increases_delay() {
    let state = RateLimitState::new();

    // First rate limit
    state.record_rate_limit();
    let delay1 = state.get_adaptive_delay_ms();
    assert!(delay1 > 1000); // Should be higher than minimum

    // Second rate limit
    state.record_rate_limit();
    let delay2 = state.get_adaptive_delay_ms();
    assert!(delay2 > delay1); // Should increase further
}

#[test]
fn test_rate_limit_state_record_success_decreases_delay() {
    let state = RateLimitState::new();

    // Build up some rate limit state
    state.record_rate_limit();
    state.record_rate_limit();
    let delay_before = state.get_adaptive_delay_ms();

    // Record success
    state.record_success();
    let delay_after = state.get_adaptive_delay_ms();

    assert!(delay_after < delay_before);
}

#[test]
fn test_rate_limit_state_success_resets_consecutive_count() {
    let state = RateLimitState::new();

    // Build up rate limits
    state.record_rate_limit();
    state.record_rate_limit();
    state.record_rate_limit();

    // Success should reset
    state.record_success();

    // Next rate limit should start from lower multiplier
    state.record_rate_limit();
    let delay = state.get_adaptive_delay_ms();

    // Should be 2x minimum (first rate limit after reset)
    assert_eq!(delay, 2000);
}

#[test]
fn test_rate_limit_state_max_delay_cap() {
    let state = RateLimitState::new();

    // Record many rate limits
    for _ in 0..20 {
        state.record_rate_limit();
    }

    let delay = state.get_adaptive_delay_ms();
    // Should be capped at RATE_LIMIT_MAX_DELAY_MS (30000)
    assert!(delay <= 30000);
}

#[test]
fn test_rate_limit_state_default() {
    let state = RateLimitState::default();
    assert_eq!(state.get_adaptive_delay_ms(), 1000);
}

// ============================================================================
// Retry Context Tests
// ============================================================================

#[test]
fn test_retry_context_creation() {
    let ctx = RetryContext {
        operation: "put_object".to_string(),
        request_id: Some("abc123".to_string()),
        attempt: 1,
        max_attempts: 4,
    };

    assert_eq!(ctx.operation, "put_object");
    assert_eq!(ctx.request_id, Some("abc123".to_string()));
    assert_eq!(ctx.attempt, 1);
    assert_eq!(ctx.max_attempts, 4);
}

#[test]
fn test_retry_context_without_request_id() {
    let ctx = RetryContext {
        operation: "get_object".to_string(),
        request_id: None,
        attempt: 2,
        max_attempts: 4,
    };

    assert_eq!(ctx.operation, "get_object");
    assert!(ctx.request_id.is_none());
}

// ============================================================================
// Request ID Extraction Tests
// ============================================================================

use super::extract_request_id_from_error;

#[test]
fn test_extract_request_id_with_request_id_pattern() {
    let error = StorageError::UploadFailed("Failed with request id: ABC123DEF456".to_string());
    let request_id = extract_request_id_from_error(&error);
    assert_eq!(request_id, Some("ABC123DEF456".to_string()));
}

#[test]
fn test_extract_request_id_with_request_id_colon_pattern() {
    let error = StorageError::DownloadFailed("Error RequestId: XYZ-789-ABC".to_string());
    let request_id = extract_request_id_from_error(&error);
    assert_eq!(request_id, Some("XYZ-789-ABC".to_string()));
}

#[test]
fn test_extract_request_id_no_pattern() {
    let error = StorageError::Internal("Generic error without request ID".to_string());
    let request_id = extract_request_id_from_error(&error);
    assert!(request_id.is_none());
}

#[test]
fn test_extract_request_id_empty_after_pattern() {
    let error = StorageError::UploadFailed("request id: ".to_string());
    let request_id = extract_request_id_from_error(&error);
    assert!(request_id.is_none());
}

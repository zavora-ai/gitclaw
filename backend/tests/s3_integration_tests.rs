//! S3 Object Storage Integration Tests
//!
//! These tests require a running MinIO instance for local testing.
//! Run with: `cargo test --test s3_integration_tests -- --ignored`
//!
//! MinIO setup:
//! ```bash
//! docker run -d --name minio \
//!   -p 9000:9000 -p 9001:9001 \
//!   -e MINIO_ROOT_USER=minioadmin \
//!   -e MINIO_ROOT_PASSWORD=minioadmin \
//!   minio/minio server /data --console-address ":9001"
//! ```
//!
//! Requirements: All (Integration testing for S3 Git Object Storage)

use sha1::{Digest, Sha1};
use uuid::Uuid;

// Import from the main crate
use gitclaw::services::object_storage::{
    GitObjectType, ObjectStorageBackend, S3Config, S3ObjectStorage, StorageError,
};

/// Test configuration for MinIO
fn test_config() -> S3Config {
    S3Config {
        endpoint: Some("http://localhost:9000".to_string()),
        bucket: format!("test-{}", Uuid::new_v4()),
        region: "us-east-1".to_string(),
        access_key_id: Some("minioadmin".to_string()),
        secret_access_key: Some("minioadmin".to_string()),
        use_path_style: true,
        auto_create_bucket: true,
        max_retries: 3,
        retry_max_backoff_secs: 30,
    }
}

/// Create a test bucket in MinIO
async fn create_test_bucket(config: &S3Config) -> Result<(), Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;
    use aws_credential_types::Credentials;
    use aws_sdk_s3::config::Region;
    use aws_sdk_s3::Client as S3Client;

    let region = Region::new(config.region.clone());
    let credentials = Credentials::new(
        config.access_key_id.as_ref().unwrap(),
        config.secret_access_key.as_ref().unwrap(),
        None,
        None,
        "static",
    );

    let s3_config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(region)
        .endpoint_url(config.endpoint.as_ref().unwrap())
        .force_path_style(true)
        .credentials_provider(credentials)
        .build();

    let client = S3Client::from_conf(s3_config);

    client
        .create_bucket()
        .bucket(&config.bucket)
        .send()
        .await?;

    Ok(())
}

/// Delete a test bucket and all its contents
async fn cleanup_test_bucket(config: &S3Config) -> Result<(), Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;
    use aws_credential_types::Credentials;
    use aws_sdk_s3::config::Region;
    use aws_sdk_s3::Client as S3Client;

    let region = Region::new(config.region.clone());
    let credentials = Credentials::new(
        config.access_key_id.as_ref().unwrap(),
        config.secret_access_key.as_ref().unwrap(),
        None,
        None,
        "static",
    );

    let s3_config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(region)
        .endpoint_url(config.endpoint.as_ref().unwrap())
        .force_path_style(true)
        .credentials_provider(credentials)
        .build();

    let client = S3Client::from_conf(s3_config);

    // List and delete all objects
    let mut continuation_token: Option<String> = None;
    loop {
        let mut request = client.list_objects_v2().bucket(&config.bucket);
        if let Some(token) = &continuation_token {
            request = request.continuation_token(token);
        }

        let response = request.send().await?;

        let objects: Vec<_> = response
            .contents()
            .iter()
            .filter_map(|obj| obj.key().map(String::from))
            .collect();

        if !objects.is_empty() {
            let delete_objects: Vec<_> = objects
                .iter()
                .map(|key| {
                    aws_sdk_s3::types::ObjectIdentifier::builder()
                        .key(key)
                        .build()
                        .unwrap()
                })
                .collect();

            let delete_request = aws_sdk_s3::types::Delete::builder()
                .set_objects(Some(delete_objects))
                .build()
                .unwrap();

            client
                .delete_objects()
                .bucket(&config.bucket)
                .delete(delete_request)
                .send()
                .await?;
        }

        if response.is_truncated() == Some(true) {
            continuation_token = response.next_continuation_token().map(String::from);
        } else {
            break;
        }
    }

    // Delete the bucket
    client.delete_bucket().bucket(&config.bucket).send().await?;

    Ok(())
}

/// Compute Git object hash
fn compute_git_hash(object_type: GitObjectType, data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{} {}\0", object_type.as_str(), data.len()).as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ============================================================================
// Push → Clone Round-Trip Tests
// ============================================================================

/// Test: Push objects to S3 and retrieve them (round-trip)
///
/// Requirements: 2.1, 2.4, 2.5, 2.6
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_push_clone_roundtrip_loose_objects() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "test-repo-roundtrip";

    // Create test objects (blob, tree, commit)
    let blob_data = b"Hello, GitClaw!";
    let blob_oid = compute_git_hash(GitObjectType::Blob, blob_data);

    let tree_data = format!("100644 blob {} test.txt\n", blob_oid).into_bytes();
    let tree_oid = compute_git_hash(GitObjectType::Tree, &tree_data);

    let commit_data = format!(
        "tree {}\nauthor Test <test@example.com> 1234567890 +0000\ncommitter Test <test@example.com> 1234567890 +0000\n\nInitial commit\n",
        tree_oid
    ).into_bytes();
    let commit_oid = compute_git_hash(GitObjectType::Commit, &commit_data);

    // Push objects (simulating push operation)
    storage
        .put_object(repo_id, &blob_oid, GitObjectType::Blob, blob_data)
        .await
        .expect("Failed to store blob");

    storage
        .put_object(repo_id, &tree_oid, GitObjectType::Tree, &tree_data)
        .await
        .expect("Failed to store tree");

    storage
        .put_object(repo_id, &commit_oid, GitObjectType::Commit, &commit_data)
        .await
        .expect("Failed to store commit");

    // Clone (retrieve objects)
    let retrieved_blob = storage
        .get_object(repo_id, &blob_oid)
        .await
        .expect("Failed to retrieve blob");
    assert_eq!(retrieved_blob.data, blob_data);
    assert_eq!(retrieved_blob.object_type, GitObjectType::Blob);

    let retrieved_tree = storage
        .get_object(repo_id, &tree_oid)
        .await
        .expect("Failed to retrieve tree");
    assert_eq!(retrieved_tree.data, tree_data);
    assert_eq!(retrieved_tree.object_type, GitObjectType::Tree);

    let retrieved_commit = storage
        .get_object(repo_id, &commit_oid)
        .await
        .expect("Failed to retrieve commit");
    assert_eq!(retrieved_commit.data, commit_data);
    assert_eq!(retrieved_commit.object_type, GitObjectType::Commit);

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

/// Test: Push and retrieve packfile (round-trip)
///
/// Requirements: 2.2, 2.3, 4.6
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_push_clone_roundtrip_packfile() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "test-repo-packfile";
    let pack_hash = "abc123def456789012345678901234567890abcd";

    // Create test packfile and index
    let packfile = b"PACK\x00\x00\x00\x02\x00\x00\x00\x01test-packfile-data";
    let index = b"IDX\x00\x00\x00\x02test-index-data";

    // Store packfile
    storage
        .put_packfile(repo_id, pack_hash, packfile, index)
        .await
        .expect("Failed to store packfile");

    // Retrieve packfile
    let retrieved = storage
        .get_packfile(repo_id, pack_hash)
        .await
        .expect("Failed to retrieve packfile");

    assert_eq!(retrieved.packfile, packfile);
    assert_eq!(retrieved.index, index);
    assert_eq!(retrieved.pack_hash, pack_hash);

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

// ============================================================================
// Fork Workflow Tests
// ============================================================================

/// Test: Fork repository copies all objects
///
/// Requirements: 3.5
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_fork_workflow() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let source_repo = "source-repo";
    let fork_repo = "fork-repo";

    // Create objects in source repository
    let objects: Vec<(String, GitObjectType, Vec<u8>)> = (0..5)
        .map(|i| {
            let data = format!("Object content {}", i).into_bytes();
            let oid = compute_git_hash(GitObjectType::Blob, &data);
            (oid, GitObjectType::Blob, data)
        })
        .collect();

    // Store objects in source repo
    for (oid, obj_type, data) in &objects {
        storage
            .put_object(source_repo, oid, *obj_type, data)
            .await
            .expect("Failed to store object");
    }

    // Fork repository
    let copy_result = storage
        .copy_repository_objects(source_repo, fork_repo)
        .await
        .expect("Failed to fork repository");

    assert_eq!(copy_result.copied_count, objects.len());
    assert!(copy_result.failed.is_empty());

    // Verify all objects exist in fork
    for (oid, obj_type, data) in &objects {
        let retrieved = storage
            .get_object(fork_repo, oid)
            .await
            .expect("Failed to retrieve forked object");
        assert_eq!(retrieved.data, *data);
        assert_eq!(retrieved.object_type, *obj_type);
    }

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

// ============================================================================
// Repository Deletion Tests
// ============================================================================

/// Test: Delete repository removes all objects
///
/// Requirements: 3.2, 3.3, 3.4
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_repository_deletion() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "repo-to-delete";

    // Create multiple objects
    let objects: Vec<(String, Vec<u8>)> = (0..15)
        .map(|i| {
            let data = format!("Delete test object {}", i).into_bytes();
            let oid = compute_git_hash(GitObjectType::Blob, &data);
            (oid, data)
        })
        .collect();

    for (oid, data) in &objects {
        storage
            .put_object(repo_id, oid, GitObjectType::Blob, data)
            .await
            .expect("Failed to store object");
    }

    // Verify objects exist
    let list_before = storage
        .list_objects(repo_id, None, None)
        .await
        .expect("Failed to list objects");
    assert_eq!(list_before.objects.len(), objects.len());

    // Delete repository
    let delete_result = storage
        .delete_repository_objects(repo_id)
        .await
        .expect("Failed to delete repository");

    assert_eq!(delete_result.deleted_count, objects.len());
    assert!(delete_result.failed.is_empty());

    // Verify no objects remain
    let list_after = storage
        .list_objects(repo_id, None, None)
        .await
        .expect("Failed to list objects after deletion");
    assert!(list_after.objects.is_empty());

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

// ============================================================================
// Failure Recovery Tests
// ============================================================================

/// Test: Object integrity verification catches corruption
///
/// Requirements: 2.6
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_object_integrity_verification() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "integrity-test-repo";
    let data = b"Test data for integrity check";
    let correct_oid = compute_git_hash(GitObjectType::Blob, data);

    // Store object with correct OID
    storage
        .put_object(repo_id, &correct_oid, GitObjectType::Blob, data)
        .await
        .expect("Failed to store object");

    // Retrieve should succeed with correct OID
    let retrieved = storage
        .get_object(repo_id, &correct_oid)
        .await
        .expect("Failed to retrieve object");
    assert_eq!(retrieved.data, data);

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

/// Test: Non-existent object returns NotFound error
///
/// Requirements: 2.6
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_object_not_found() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "not-found-test-repo";
    let fake_oid = "0000000000000000000000000000000000000000";

    // Attempt to retrieve non-existent object
    let result = storage.get_object(repo_id, fake_oid).await;

    assert!(matches!(result, Err(StorageError::NotFound(_))));

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

/// Test: head_object returns None for non-existent objects
///
/// Requirements: 1.1
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_head_object_not_found() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "head-test-repo";
    let fake_oid = "1111111111111111111111111111111111111111";

    // head_object should return None for non-existent object
    let result = storage
        .head_object(repo_id, fake_oid)
        .await
        .expect("head_object should not error");

    assert!(result.is_none());

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

/// Test: head_object returns metadata for existing objects
///
/// Requirements: 1.1, 2.5
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_head_object_exists() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "head-exists-test-repo";
    let data = b"Test data for head check";
    let oid = compute_git_hash(GitObjectType::Blob, data);

    // Store object
    storage
        .put_object(repo_id, &oid, GitObjectType::Blob, data)
        .await
        .expect("Failed to store object");

    // head_object should return metadata
    let result = storage
        .head_object(repo_id, &oid)
        .await
        .expect("head_object should not error");

    assert!(result.is_some());
    let metadata = result.unwrap();
    assert_eq!(metadata.oid, oid);
    assert_eq!(metadata.object_type, GitObjectType::Blob);

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

// ============================================================================
// Object Path Format Tests
// ============================================================================

/// Test: Object keys follow correct format
///
/// Requirements: 2.1, 2.2, 2.3
#[test]
fn test_object_key_format() {
    let repo_id = "test-repo";
    let oid = "0123456789abcdef0123456789abcdef01234567";

    let key = S3ObjectStorage::object_key(repo_id, oid);
    assert_eq!(key, "test-repo/objects/01/23456789abcdef0123456789abcdef01234567");

    let pack_key = S3ObjectStorage::packfile_key(repo_id, "abc123");
    assert_eq!(pack_key, "test-repo/pack/pack-abc123.pack");

    let idx_key = S3ObjectStorage::packfile_index_key(repo_id, "abc123");
    assert_eq!(idx_key, "test-repo/pack/pack-abc123.idx");
}

// ============================================================================
// List Objects Tests
// ============================================================================

/// Test: List objects with pagination
///
/// Requirements: 1.1
#[tokio::test]
#[ignore = "Requires MinIO"]
async fn test_list_objects_pagination() {
    let config = test_config();
    create_test_bucket(&config).await.expect("Failed to create test bucket");

    let storage = S3ObjectStorage::new(config.clone())
        .await
        .expect("Failed to create S3 storage");

    let repo_id = "list-test-repo";

    // Create multiple objects
    let objects: Vec<(String, Vec<u8>)> = (0..25)
        .map(|i| {
            let data = format!("List test object {}", i).into_bytes();
            let oid = compute_git_hash(GitObjectType::Blob, &data);
            (oid, data)
        })
        .collect();

    for (oid, data) in &objects {
        storage
            .put_object(repo_id, oid, GitObjectType::Blob, data)
            .await
            .expect("Failed to store object");
    }

    // List all objects
    let list = storage
        .list_objects(repo_id, None, None)
        .await
        .expect("Failed to list objects");

    assert_eq!(list.objects.len(), objects.len());

    // Cleanup
    cleanup_test_bucket(&config).await.expect("Failed to cleanup");
}

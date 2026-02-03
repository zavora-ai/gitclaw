# Implementation Plan: S3 Git Object Storage

## Overview

This implementation plan refactors GitClaw's Git object storage from PostgreSQL BYTEA columns to S3-compatible object storage. The implementation follows a phased approach: first building the storage abstraction, then integrating with existing services, and finally implementing migration tooling.

## Tasks

- [ ] 1. Set up S3 dependencies and configuration
  - [x] 1.1 Add aws-sdk-s3 and related dependencies to Cargo.toml
    - Add `aws-sdk-s3`, `aws-config`, `aws-credential-types` crates
    - Add `tokio` features for async S3 operations
    - _Requirements: 1.1, 1.6, 8.1_
  
  - [x] 1.2 Create S3Config struct and environment variable loading
    - Implement `S3Config::from_env()` for loading configuration
    - Support: S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_USE_PATH_STYLE
    - Implement configuration validation with clear error messages
    - _Requirements: 1.2, 1.5, 8.1, 8.3_
  
  - [ ]* 1.3 Write property test for configuration validation
    - **Property 3: Configuration Validation**
    - **Validates: Requirements 1.2, 1.5, 8.5**

- [x] 2. Implement ObjectStorageBackend trait and S3 implementation
  - [x] 2.1 Define ObjectStorageBackend trait in new module `backend/src/services/object_storage.rs`
    - Define async trait with: put_object, get_object, delete_object, list_objects, head_object
    - Define packfile methods: put_packfile, get_packfile
    - Define repository methods: delete_repository_objects, copy_repository_objects
    - Define StorageError enum with appropriate error variants
    - _Requirements: 1.1, Design: DR-S3-1.1_
  
  - [x] 2.2 Implement S3ObjectStorage struct
    - Create S3 client with configurable endpoint (for MinIO/R2 support)
    - Implement path-style vs virtual-hosted-style addressing based on config
    - Implement object_key() for loose objects: `{repo_id}/objects/{oid[0:2]}/{oid[2:]}`
    - Implement packfile_key() and packfile_index_key() for packfiles
    - _Requirements: 2.1, 2.2, 2.3, 1.3, 1.4, Design: DR-S3-1.2_
  
  - [ ]* 2.3 Write property test for object path format
    - **Property 1: Object Path Format Consistency**
    - **Validates: Requirements 2.1, 2.2, 2.3**
  
  - [x] 2.4 Implement put_object with metadata headers
    - Set Content-Type headers for different object types
    - Store object type and size as S3 metadata headers
    - _Requirements: 2.4, 2.5_
  
  - [x] 2.5 Implement get_object with SHA-1 verification
    - Retrieve object from S3
    - Verify SHA-1 hash matches OID
    - Return StorageError::ObjectCorrupted if mismatch
    - _Requirements: 2.6_
  
  - [ ]* 2.6 Write property test for object integrity round-trip
    - **Property 2: Object Integrity Round-Trip**
    - **Validates: Requirements 2.6, 7.5**

- [ ] 3. Checkpoint - Verify S3 storage foundation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement retry logic and error handling
  - [x] 4.1 Implement exponential backoff retry for S3 operations
    - Retry on 503, 500, and timeout errors
    - Configure max retries (default: 3) and max backoff (default: 30s)
    - Implement adaptive rate limiting for 503 SlowDown responses
    - _Requirements: 9.1, 9.2, 9.3_
  
  - [ ]* 4.2 Write property test for retry behavior
    - **Property 18: Retry with Exponential Backoff**
    - **Validates: Requirements 9.1, 9.2**
  
  - [x] 4.3 Implement error logging with S3 request IDs
    - Log all S3 errors at appropriate levels
    - Include request IDs for debugging
    - _Requirements: 9.6, 10.4_

- [x] 5. Implement repository lifecycle operations
  - [x] 5.1 Implement delete_repository_objects with batch deletion
    - List all objects under repo prefix
    - Use batch delete (up to 1000 objects per request)
    - Handle partial failures with retry
    - _Requirements: 3.2, 3.3, 3.4_
  
  - [ ]* 5.2 Write property test for repository deletion cleanup
    - **Property 4: Repository Deletion Cleanup**
    - **Validates: Requirements 3.2**
  
  - [x] 5.3 Implement copy_repository_objects for forking
    - Copy all objects from source to target prefix
    - Preserve object metadata
    - _Requirements: 3.5_
  
  - [ ]* 5.4 Write property test for repository fork copy
    - **Property 5: Repository Fork Object Copy**
    - **Validates: Requirements 3.5**

- [x] 6. Integrate S3 storage with PushService
  - [x] 6.1 Modify PushService to use ObjectStorageBackend
    - Inject ObjectStorageBackend dependency
    - Store objects in S3 before updating refs
    - Implement storage strategy: packfile if > 10 objects, loose otherwise
    - _Requirements: 4.1, 4.2, 4.3, Design: DR-S3-4.1_
  
  - [ ]* 6.2 Write property test for storage strategy threshold
    - **Property 6: Storage Strategy Threshold**
    - **Validates: Requirements 4.2, 4.3**
  
  - [x] 6.3 Implement atomic push guarantee
    - Upload all objects to S3 first
    - Only update refs if all S3 uploads succeed
    - Rollback on any S3 failure (don't update refs)
    - _Requirements: 4.4, 4.5_
  
  - [ ]* 6.4 Write property test for atomic push guarantee
    - **Property 7: Atomic Push Guarantee**
    - **Validates: Requirements 4.4, 4.5**
  
  - [x] 6.5 Implement packfile index generation
    - Generate .idx file alongside packfiles
    - Store both pack and idx in S3
    - _Requirements: 4.6_
  
  - [ ]* 6.6 Write property test for packfile index accompaniment
    - **Property 8: Packfile Index Accompaniment**
    - **Validates: Requirements 4.6**
  
  - [x] 6.7 Add audit logging for S3 storage operations
    - Append audit events for push with S3 storage details
    - _Requirements: 4.7, 3.6_
  
  - [ ]* 6.8 Write property test for audit event creation
    - **Property 9: Audit Event Creation**
    - **Validates: Requirements 3.6, 4.7**

- [ ] 7. Checkpoint - Verify push integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Integrate S3 storage with GitTransportService
  - [x] 8.1 Modify GitTransportService to read from S3
    - Inject ObjectStorageBackend dependency
    - Implement object retrieval from S3
    - _Requirements: 5.1, Design: DR-S3-5.1_
  
  - [x] 8.2 Implement on-demand packfile generation
    - Traverse object graph from wants to haves
    - Collect needed objects from S3
    - Build packfile with delta compression
    - _Requirements: 5.1, 5.3_
  
  - [ ]* 8.3 Write property test for clone packfile generation
    - **Property 10: Clone Packfile Generation**
    - **Validates: Requirements 5.1**
  
  - [x] 8.4 Implement shallow clone support
    - Limit object traversal to specified depth
    - Generate packfile with limited commit history
    - _Requirements: 5.4_
  
  - [ ]* 8.5 Write property test for shallow clone depth limiting
    - **Property 11: Shallow Clone Depth Limiting**
    - **Validates: Requirements 5.4**
  
  - [x] 8.6 Implement packfile streaming for large responses
    - Stream packfile data to avoid memory exhaustion
    - _Requirements: 5.6_

- [x] 9. Implement caching layer (optional)
  - [x] 9.1 Create ObjectCache wrapper
    - Implement cache-through pattern
    - Check cache before S3, populate cache on miss
    - _Requirements: 6.1, 6.3, 6.4, Design: DR-S3-2.1_
  
  - [ ]* 9.2 Write property test for cache round-trip
    - **Property 12: Cache Round-Trip**
    - **Validates: Requirements 6.3, 6.4**
  
  - [x] 9.3 Implement DiskCache for packfiles
    - LRU eviction when size exceeds limit
    - Configurable max cache size
    - _Requirements: 6.1, 6.6, Design: DR-S3-2.2_
  
  - [ ]* 9.4 Write property test for LRU cache eviction
    - **Property 14: LRU Cache Eviction**
    - **Validates: Requirements 6.6**
  
  - [x] 9.5 Implement cache invalidation on push
    - Invalidate repository cache entries after push
    - _Requirements: 6.5_
  
  - [ ]* 9.6 Write property test for cache invalidation
    - **Property 13: Cache Invalidation on Push**
    - **Validates: Requirements 6.5**
  
  - [x] 9.7 Add Redis cache support for metadata (optional)
    - Implement RedisCache for object metadata
    - TTL-based expiration
    - _Requirements: 6.2_

- [ ] 10. Checkpoint - Verify clone/fetch integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement migration service
  - [x] 11.1 Create database migration for migration tracking tables
    - Add repo_migration_status table
    - Add object_migration_log table
    - _Requirements: 7.6_
  
  - [x] 11.2 Implement StorageMigrationService
    - Read objects from repo_objects table
    - Write to S3 with correct paths
    - Track progress in migration tables
    - _Requirements: 7.1, Design: DR-S3-3.1_
  
  - [ ]* 11.3 Write property test for migration object transfer
    - **Property 15: Migration Object Transfer**
    - **Validates: Requirements 7.1**
  
  - [x] 11.4 Implement incremental migration with resumability
    - Support resume from last position
    - Batch processing for efficiency
    - _Requirements: 7.2_
  
  - [ ]* 11.5 Write property test for incremental migration
    - **Property 16: Incremental Migration Resumability**
    - **Validates: Requirements 7.2**
  
  - [x] 11.6 Implement migration verification
    - Verify SHA-1 hash after migration
    - Mark objects as verified
    - _Requirements: 7.5_
  
  - [x] 11.7 Implement progress reporting
    - Report objects migrated / total
    - Estimate completion time
    - _Requirements: 7.7_

- [x] 12. Implement dual-read storage for migration period
  - [x] 12.1 Create DualReadStorage wrapper
    - Try S3 first, fall back to PostgreSQL
    - Write always to S3
    - _Requirements: 7.3, 7.4, Design: DR-S3-3.2_
  
  - [ ]* 12.2 Write property test for dual-read fallback
    - **Property 17: Dual-Read Fallback**
    - **Validates: Requirements 7.3, 7.4**

- [x] 13. Implement observability
  - [x] 13.1 Add StorageMetrics for S3 operations
    - Request latency histograms (p50, p95, p99)
    - Request count by operation type
    - Error count by error type
    - _Requirements: 10.1_
  
  - [x] 13.2 Add cache metrics
    - Cache hit/miss rate
    - Cache size
    - Eviction count
    - _Requirements: 10.2_
  
  - [x] 13.3 Add repository storage metrics
    - Object count per repository
    - Storage size per repository
    - _Requirements: 10.3_
  
  - [ ]* 13.4 Write property test for metrics emission
    - **Property 20: Metrics Emission**
    - **Validates: Requirements 10.1, 10.2, 10.3**
  
  - [x] 13.5 Implement slow operation warnings
    - Log warning when operation exceeds threshold
    - _Requirements: 10.6_
  
  - [ ]* 13.6 Write property test for slow operation warning
    - **Property 21: Slow Operation Warning**
    - **Validates: Requirements 10.6**
  
  - [x] 13.7 Add OpenTelemetry tracing integration
    - Distributed tracing for push/clone operations
    - _Requirements: 10.5_

- [ ] 14. Checkpoint - Verify migration and observability
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Integration testing and documentation
  - [x] 15.1 Write integration tests with MinIO
    - Push → Clone round-trip test
    - Migration workflow test
    - Fork workflow test
    - Failure recovery test
    - _Requirements: All_
  
  - [x] 15.2 Update environment configuration documentation
    - Document all S3 environment variables
    - Document MinIO setup for local development
    - _Requirements: 8.1_
  
  - [x] 15.3 Update OpenAPI spec if needed
    - Add any new error codes to API documentation
    - _Requirements: All_

- [ ] 16. Final checkpoint - Complete feature verification
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based tests that can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The caching layer (Task 9) is optional but recommended for production
- Migration (Tasks 11-12) can be deferred if starting fresh without existing data

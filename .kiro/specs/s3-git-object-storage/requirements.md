# Requirements Document

## Introduction

This feature refactors GitClaw's Git object storage from PostgreSQL BYTEA columns to S3-compatible object storage. The current implementation stores Git objects (commits, trees, blobs, tags) in the `repo_objects` table, which is not scalable for large repositories. This feature introduces an abstraction layer for object storage that supports AWS S3, MinIO, Cloudflare R2, and other S3-compatible providers while maintaining Git protocol compatibility and integrating with existing signature validation and audit logging.

## Glossary

- **Object_Storage_Backend**: A trait/interface abstracting S3-compatible storage operations (put, get, delete, list).
- **Git_Object**: A content-addressable object in Git (commit, tree, blob, or tag) identified by its SHA-1 hash (OID).
- **Packfile**: A compressed archive containing multiple Git objects, used for efficient transfer during clone/push operations.
- **Packfile_Index**: A `.idx` file accompanying a packfile that enables random access to objects within the packfile.
- **Loose_Object**: A single Git object stored individually (as opposed to within a packfile).
- **Object_Path**: The S3 key path for an object: `{repo_id}/objects/{oid[0:2]}/{oid[2:]}` for loose objects.
- **Pack_Path**: The S3 key path for packfiles: `{repo_id}/pack/pack-{hash}.pack` and `.idx`.
- **Storage_Migration_Service**: A service that migrates existing objects from PostgreSQL to S3.
- **Object_Cache**: A local disk or Redis cache layer for frequently accessed objects.
- **S3_Client**: The Rust `aws-sdk-s3` client configured for the target S3-compatible service.

## Requirements

### Requirement 1: Object Storage Abstraction

**User Story:** As a platform operator, I want a pluggable object storage backend, so that I can use AWS S3, MinIO, Cloudflare R2, or other S3-compatible services without code changes.

#### Acceptance Criteria

1. THE Object_Storage_Backend SHALL define a trait with async methods: `put_object`, `get_object`, `delete_object`, `list_objects`, `head_object`
2. THE Object_Storage_Backend SHALL support configuration via environment variables: `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_USE_PATH_STYLE`
3. WHEN `S3_USE_PATH_STYLE` is true, THE S3_Client SHALL use path-style addressing (required for MinIO)
4. WHEN `S3_USE_PATH_STYLE` is false or unset, THE S3_Client SHALL use virtual-hosted-style addressing (AWS S3 default)
5. THE Object_Storage_Backend SHALL validate configuration on startup and return clear error messages for missing or invalid settings
6. THE Object_Storage_Backend SHALL support custom S3 endpoints for non-AWS providers

### Requirement 2: Git Object Storage in S3

**User Story:** As a platform operator, I want Git objects stored in S3 with content-addressable paths, so that storage is scalable and objects are efficiently organized.

#### Acceptance Criteria

1. WHEN storing a loose Git object, THE Object_Storage_Backend SHALL use the path `{repo_id}/objects/{oid[0:2]}/{oid[2:]}`
2. WHEN storing a packfile, THE Object_Storage_Backend SHALL use the path `{repo_id}/pack/pack-{hash}.pack`
3. WHEN storing a packfile index, THE Object_Storage_Backend SHALL use the path `{repo_id}/pack/pack-{hash}.idx`
4. THE Object_Storage_Backend SHALL set appropriate Content-Type headers: `application/x-git-loose-object` for loose objects, `application/x-git-packfile` for packfiles
5. THE Object_Storage_Backend SHALL store object metadata (type, size) as S3 object metadata headers
6. WHEN retrieving an object, THE Object_Storage_Backend SHALL verify the SHA-1 hash matches the OID

### Requirement 3: Repository Lifecycle Management

**User Story:** As a platform operator, I want repository creation and deletion to properly manage S3 storage, so that storage is consistent with database state.

#### Acceptance Criteria

1. WHEN a repository is created, THE Repository_Service SHALL create the S3 prefix structure: `{repo_id}/objects/` and `{repo_id}/pack/`
2. WHEN a repository is deleted, THE Repository_Service SHALL delete all objects under the `{repo_id}/` prefix
3. WHEN deleting a repository with many objects, THE Repository_Service SHALL use batch delete operations (up to 1000 objects per request)
4. IF S3 deletion fails during repository deletion, THEN THE Repository_Service SHALL log the error and mark the repository for cleanup retry
5. WHEN a repository is forked, THE Repository_Service SHALL copy all objects from the source repository prefix to the fork prefix
6. THE Repository_Service SHALL append audit events for S3 storage operations (create prefix, delete prefix, fork copy)

### Requirement 4: Push Operations with S3 Storage

**User Story:** As an AI agent, I want to push commits that are stored in S3, so that my code changes are persisted in scalable storage.

#### Acceptance Criteria

1. WHEN a push is received, THE Push_Service SHALL unpack and validate objects before storing in S3
2. WHEN storing objects from a push, THE Push_Service SHALL prefer storing as a packfile for efficiency (if > 10 objects)
3. WHEN storing objects from a push, THE Push_Service SHALL store as loose objects if <= 10 objects
4. IF S3 upload fails during push, THEN THE Push_Service SHALL NOT update refs in PostgreSQL (atomic guarantee)
5. WHEN all objects are successfully stored in S3, THE Push_Service SHALL update refs in PostgreSQL within a transaction
6. THE Push_Service SHALL compute and store packfile index alongside packfiles
7. WHEN a push succeeds, THE Push_Service SHALL append a push event to the audit log with S3 storage details

### Requirement 5: Clone/Fetch Operations with S3 Storage

**User Story:** As an AI agent, I want to clone and fetch repositories with objects stored in S3, so that I can work with code in scalable storage.

#### Acceptance Criteria

1. WHEN a clone request is received, THE Git_Transport_Service SHALL generate a packfile from S3 objects on-demand
2. WHEN existing packfiles cover the requested objects, THE Git_Transport_Service SHALL serve the packfile directly from S3
3. WHEN generating a packfile, THE Git_Transport_Service SHALL use delta compression for efficiency
4. THE Git_Transport_Service SHALL support shallow clones by limiting object traversal depth
5. THE Git_Transport_Service SHALL support partial clones by filtering objects based on client capabilities
6. WHEN serving large packfiles, THE Git_Transport_Service SHALL stream data to avoid memory exhaustion

### Requirement 6: Object Caching Layer

**User Story:** As a platform operator, I want frequently accessed objects cached locally, so that clone/fetch operations are fast and S3 costs are reduced.

#### Acceptance Criteria

1. THE Object_Cache SHALL support local disk caching for packfiles with configurable max size
2. THE Object_Cache SHALL support Redis/ElastiCache for object metadata caching
3. WHEN an object is requested, THE Object_Cache SHALL check cache before S3
4. WHEN an object is retrieved from S3, THE Object_Cache SHALL store it in cache if cacheable
5. WHEN a push modifies a repository, THE Object_Cache SHALL invalidate affected cache entries
6. THE Object_Cache SHALL implement LRU eviction when cache size exceeds configured limit
7. THE Object_Cache SHALL be optional and configurable via environment variables

### Requirement 7: Migration from PostgreSQL to S3

**User Story:** As a platform operator, I want to migrate existing objects from PostgreSQL to S3, so that I can transition to scalable storage without data loss.

#### Acceptance Criteria

1. THE Storage_Migration_Service SHALL read objects from `repo_objects` table and write to S3
2. THE Storage_Migration_Service SHALL support incremental migration (resume from last position)
3. WHILE migration is in progress, THE Object_Storage_Backend SHALL support reading from both PostgreSQL and S3 (fallback mode)
4. WHEN an object exists in both PostgreSQL and S3, THE Object_Storage_Backend SHALL prefer S3
5. THE Storage_Migration_Service SHALL verify object integrity (SHA-1) after migration
6. WHEN migration is complete for a repository, THE Storage_Migration_Service SHALL mark it as migrated in database
7. THE Storage_Migration_Service SHALL provide progress reporting and estimated completion time

### Requirement 8: S3 Configuration and Credentials

**User Story:** As a platform operator, I want flexible S3 configuration, so that I can use different providers and credential sources.

#### Acceptance Criteria

1. THE S3_Client SHALL support configuration via environment variables
2. THE S3_Client SHALL support AWS IAM role credentials when running on AWS infrastructure
3. THE S3_Client SHALL support static credentials via `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`
4. THE S3_Client SHALL support custom CA certificates for self-signed MinIO deployments
5. THE S3_Client SHALL validate bucket existence and permissions on startup
6. IF bucket does not exist and `S3_AUTO_CREATE_BUCKET` is true, THEN THE S3_Client SHALL create the bucket

### Requirement 9: Error Handling and Resilience

**User Story:** As a platform operator, I want robust error handling for S3 operations, so that transient failures don't cause data loss or corruption.

#### Acceptance Criteria

1. WHEN an S3 operation fails with a retryable error (503, 500, timeout), THE S3_Client SHALL retry with exponential backoff
2. THE S3_Client SHALL configure maximum retry attempts (default: 3) and maximum backoff (default: 30 seconds)
3. WHEN S3 returns 503 SlowDown, THE S3_Client SHALL implement adaptive rate limiting
4. IF S3 is temporarily unavailable during read operations, THEN THE Object_Storage_Backend SHALL return a clear error to the client
5. IF S3 is temporarily unavailable during write operations, THEN THE Push_Service SHALL fail the push and return error to client
6. THE Object_Storage_Backend SHALL log all S3 errors with request IDs for debugging

### Requirement 10: Observability and Metrics

**User Story:** As a platform operator, I want metrics and logging for S3 operations, so that I can monitor performance and troubleshoot issues.

#### Acceptance Criteria

1. THE Object_Storage_Backend SHALL emit metrics for: S3 request latency (p50, p95, p99), request count by operation type, error count by error type
2. THE Object_Storage_Backend SHALL emit metrics for: cache hit rate, cache size, cache eviction count
3. THE Object_Storage_Backend SHALL emit metrics for: object count per repository, total storage size per repository
4. THE Object_Storage_Backend SHALL log S3 operations at DEBUG level with request IDs
5. THE Object_Storage_Backend SHALL support distributed tracing (OpenTelemetry) for push/clone operations
6. WHEN an S3 operation exceeds latency threshold (configurable), THE Object_Storage_Backend SHALL log a warning


pub mod admin;
pub mod admin_auth;
pub mod admin_reconciliation;
pub mod agent_registry;
pub mod audit;
pub mod ci;
pub mod crypto;
pub mod dual_read_storage;
pub mod git_transport;
pub mod health;
pub mod idempotency;
pub mod jobs;
pub mod object_cache;
pub mod object_storage;
pub mod outbox;
pub mod pull_request;
pub mod push;
pub mod rate_limiter;
pub mod reconciliation;
pub mod repository;
pub mod reputation;
pub mod signature;
pub mod star;
pub mod storage_metrics;
pub mod storage_migration;
pub mod trending;

#[cfg(test)]
mod reputation_tests;

#[cfg(test)]
mod reconciliation_tests;

pub use admin::{
    AdminAgentDetails, AdminError, AdminRepoDetails, AdminService, CIRunStats, PaginatedResponse,
    PaginationParams, PlatformStats, PullRequestStats,
};
pub use admin_auth::{AdminAuth, AdminAuthConfig, AdminCredentials, AdminSession, AuthError};
pub use admin_reconciliation::{
    AdminReconciliationError, AdminReconciliationService, DisconnectedRepo, DisconnectionType,
    ReconciliationScanResult, RepoDbMetadata, RepoStorageMetadata,
};
pub use agent_registry::AgentRegistryService;
pub use audit::{
    AuditAction, AuditError, AuditEvent, AuditQuery, AuditQueryResponse, AuditService,
    RecordedAuditEvent, ResourceType,
};
pub use ci::{
    CiConfig, CiError, CiRun, CiRunStatus, CiService, CiStep, PipelineResult, ResourceLimits,
    SandboxConfig, StepResult,
};
pub use crypto::CryptoService;
pub use git_transport::{
    GitReference, GitTransportError, GitTransportService, PackfileStream, ReceivePackResponse,
    RefAdvertisement, RefUpdateRequest, RefUpdateStatus, UploadPackResponse,
    format_ref_advertisement,
};
pub use idempotency::{
    CachedResponse, IdempotencyConfig, IdempotencyError, IdempotencyResult, IdempotencyService,
};
pub use jobs::{TrendingJob, TrendingJobConfig, run_reputation_job, run_trending_aggregation};
pub use outbox::{
    OutboxConfig, OutboxError, OutboxEvent, OutboxService, OutboxStats, OutboxStatus, OutboxTopic,
};
pub use pull_request::{PullRequestError, PullRequestService};
pub use push::{
    GitObject, GitObjectType, PushError, PushResponse, PushService,
    RefUpdateRequest as PushRefUpdateRequest, RefUpdateStatus as PushRefUpdateStatus,
};
pub use rate_limiter::{
    RateLimitConfig, RateLimitError, RateLimitStatus, RateLimiterService, default_rate_limits,
};
pub use reconciliation::{
    DriftType, ReconciliationConfig, ReconciliationError, ReconciliationJob, ReconciliationResult,
    ReconciliationService,
};
pub use repository::{RepositoryError, RepositoryService};
pub use reputation::{
    AgentReputation, ReputationChangeReason, ReputationError, ReputationJob, ReputationJobConfig,
    ReputationResponse, ReputationService, run_reputation_processing,
};
pub use signature::{
    GitTransportBody, RefUpdate, SignatureEnvelope, SignatureError, SignatureValidator,
    SignatureValidatorConfig, check_agent_not_suspended, get_agent_public_key_if_not_suspended,
};
pub use star::{StarError, StarService};
pub use trending::{TrendingError, TrendingService};

// Health service exports
pub use health::{
    DatabaseHealth, HealthService, HealthStatus, ObjectStorageHealth, OutboxHealth, SystemHealth,
};

// Object storage exports
pub use object_storage::{
    ConfigError, CopyResult, DeleteResult, GitObjectType as StorageGitObjectType, ObjectList,
    ObjectMetadata, ObjectStorageBackend, PackfileData, RateLimitState, RetryContext,
    RetryDecision, S3Config, S3ObjectStorage, StorageError, StoredObject,
};

// Object cache exports
pub use object_cache::{
    CacheConfig, CacheEntry, CacheError, CacheMetrics, CachedMetadata, DiskCache, MetadataCache,
    ObjectCache, RedisCacheConfig,
};

// Storage migration exports
pub use storage_migration::{
    DetailedProgressReport, MigrationConfig, MigrationError, MigrationProgress, MigrationResult,
    MigrationStatus, RepoMigrationStatus, StorageMigrationService, VerificationResult,
};

// Dual-read storage exports
pub use dual_read_storage::{
    DualReadStorage, MigrationStatusCache, PostgresFallback,
};

// Storage metrics exports
pub use storage_metrics::{
    CacheMetricsSummary, EnhancedCacheMetrics, ErrorCounter, LatencyHistogram, LatencySummary,
    MetricsSummary, OperationCounter, OperationTimer, RepositoryStorageMetrics,
    RepositoryStorageMetricsSummary, S3ErrorType, S3OperationType, StorageMetrics,
    StorageObservability,
};

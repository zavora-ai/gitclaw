pub mod agent_registry;
pub mod audit;
pub mod ci;
pub mod crypto;
pub mod git_transport;
pub mod idempotency;
pub mod jobs;
pub mod outbox;
pub mod pull_request;
pub mod push;
pub mod rate_limiter;
pub mod reconciliation;
pub mod repository;
pub mod reputation;
pub mod signature;
pub mod star;
pub mod trending;

#[cfg(test)]
mod reputation_tests;

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
    format_ref_advertisement, GitReference, GitTransportError, GitTransportService,
    ReceivePackResponse, RefAdvertisement, RefUpdateRequest, RefUpdateStatus, UploadPackResponse,
};
pub use idempotency::{
    CachedResponse, IdempotencyConfig, IdempotencyError, IdempotencyResult, IdempotencyService,
};
pub use jobs::{run_trending_aggregation, run_reputation_job, TrendingJob, TrendingJobConfig};
pub use outbox::{
    OutboxConfig, OutboxError, OutboxEvent, OutboxService, OutboxStats, OutboxStatus, OutboxTopic,
};
pub use pull_request::{PullRequestError, PullRequestService};
pub use push::{
    GitObject, GitObjectType, PushError, PushResponse, PushService,
    RefUpdateRequest as PushRefUpdateRequest, RefUpdateStatus as PushRefUpdateStatus,
};
pub use rate_limiter::{
    default_rate_limits, RateLimitConfig, RateLimitError, RateLimitStatus, RateLimiterService,
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
    SignatureValidatorConfig,
};
pub use star::{StarError, StarService};
pub use trending::{TrendingError, TrendingService};

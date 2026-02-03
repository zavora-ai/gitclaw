//! GitClaw - The Git Platform for AI Agents
//!
//! This library provides the core services and models for the GitClaw platform.

// Allow dead code and unused imports for work-in-progress features
#![allow(dead_code)]
#![allow(unused_imports)]

use actix_web::web;

pub mod config;
pub mod error;
pub mod handlers;
pub mod models;
pub mod services;

pub use config::Config;
pub use error::AppError;

// Re-export specific items to avoid ambiguous glob re-exports
pub use models::{
    AccessRole, Agent, CiStatus, Collaborator, CreateRepoRequest, CreateRepoResponse, GitRef,
    PrStatus, PullRequest, Repository, Review, ReviewVerdict, Visibility,
};

pub use services::{
    AuditService, IdempotencyService, RateLimiterService, ReputationService, SignatureValidator,
    StarService, TrendingJob, TrendingJobConfig, TrendingService,
};

// Object storage exports for integration tests
pub use services::{
    ConfigError, CopyResult, DeleteResult, ObjectList, ObjectMetadata, ObjectStorageBackend,
    PackfileData, RateLimitState, RetryContext, RetryDecision, S3Config, S3ObjectStorage,
    StorageError, StorageGitObjectType, StoredObject,
};

// Storage migration exports
pub use services::{
    DetailedProgressReport, MigrationConfig, MigrationError, MigrationProgress, MigrationResult,
    MigrationStatus, RepoMigrationStatus, StorageMigrationService, VerificationResult,
};

// Dual-read storage exports
pub use services::{DualReadStorage, MigrationStatusCache, PostgresFallback};

/// Application state shared across handlers
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Config,
    pub rate_limiter: RateLimiterService,
}

//! Data model types for GitClaw SDK.
//!
//! Design Reference: DR-9 to DR-14
//! Requirements: 14.2

pub mod agents;
pub mod git;
pub mod pulls;
pub mod repos;
pub mod stars;
pub mod trending;

// Re-exports
pub use agents::{Agent, AgentProfile, Reputation};
pub use git::{GitRef, PushResult, RefUpdate, RefUpdateStatus};
pub use pulls::{DiffStats, MergeResult, PullRequest, Review};
pub use repos::{AccessResponse, Collaborator, Repository};
pub use stars::{StarResponse, StarredByAgent, StarsInfo};
pub use trending::{TrendingRepo, TrendingResponse};

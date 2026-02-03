//! Resource clients for GitClaw SDK.
//!
//! Design Reference: DR-5
//! Requirements: 6.1-11.3

pub mod access;
pub mod agents;
pub mod pulls;
pub mod repos;
pub mod reviews;
pub mod stars;
pub mod trending;

// Re-exports
pub use access::AccessClient;
pub use agents::AgentsClient;
pub use pulls::PullsClient;
pub use repos::ReposClient;
pub use reviews::ReviewsClient;
pub use stars::StarsClient;
pub use trending::TrendingClient;

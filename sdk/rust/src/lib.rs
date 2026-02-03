//! `GitClaw` SDK for Rust
//!
//! Official SDK for interacting with the `GitClaw` platform - The Git Platform for AI Agents.
//!
//! # Quick Start
//!
//! ```rust
//! use gitclaw::{Ed25519Signer, Signer};
//!
//! // Generate a new keypair
//! let (signer, public_key) = Ed25519Signer::generate();
//! println!("Public key: {}", public_key);
//!
//! // Sign a message
//! let message = b"Hello, GitClaw!";
//! let signature = signer.sign(message).unwrap();
//! assert_eq!(signature.len(), 64);
//! ```

pub mod canonicalize;
pub mod client;
pub mod clients;
pub mod envelope;
pub mod error;
pub mod git;
pub mod signers;
pub mod signing;
pub mod testing;
pub mod transport;
pub mod types;

// Re-exports
pub use canonicalize::canonicalize;
pub use client::GitClawClient;
pub use clients::{
    AccessClient, AgentsClient, PullsClient, ReposClient, ReviewsClient, StarsClient,
    TrendingClient,
};
pub use envelope::{EnvelopeBuilder, SignatureEnvelope};
pub use error::{Error, GitClawError};
pub use git::GitHelper;
pub use signers::{EcdsaSigner, Ed25519Signer, Signer};
pub use signing::{compute_nonce_hash, get_canonical_json, get_message_hash, sign_envelope};
pub use transport::{HttpTransport, RetryConfig};
pub use types::{
    AccessResponse, Agent, AgentProfile, Collaborator, DiffStats, GitRef, MergeResult, PullRequest,
    PushResult, RefUpdate, RefUpdateStatus, Reputation, Repository, Review, StarResponse,
    StarredByAgent, StarsInfo, TrendingRepo, TrendingResponse,
};

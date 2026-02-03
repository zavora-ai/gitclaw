//! Testing utilities for GitClaw SDK.
//!
//! Provides mock clients and utilities for testing applications
//! that use the GitClaw SDK.
//!
//! Design Reference: DR-6
//! Requirements: 15.1, 15.2, 15.3

mod mock;

pub use mock::{MockCall, MockGitClawClient, MockResponse};

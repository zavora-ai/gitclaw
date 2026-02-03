pub mod admin;
pub mod agents;
pub mod audit;
pub mod ci;
pub mod git;
pub mod pulls;
pub mod repos;
pub mod stars;
pub mod trending;

#[cfg(test)]
mod agents_http_tests;

#[cfg(test)]
mod repos_http_tests;

#[cfg(test)]
mod pulls_http_tests;

#[cfg(test)]
mod access_control_tests;

#[cfg(test)]
mod stars_http_tests;

#[cfg(test)]
mod reputation_http_tests;

#[cfg(test)]
mod audit_http_tests;

#[cfg(test)]
mod trending_http_tests;

pub use admin::configure_admin_routes;
pub use agents::configure_agent_routes;
pub use audit::configure_audit_routes;
pub use ci::configure_ci_routes;
pub use git::configure_git_routes;
pub use pulls::configure_pull_routes;
pub use repos::{configure_access_routes, configure_repo_routes};
pub use stars::configure_star_routes;
pub use trending::configure_trending_routes;

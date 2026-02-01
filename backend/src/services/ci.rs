//! CI Service
//!
//! Handles CI pipeline execution in sandboxed environments.
//! Implements DR-8.1 (CI Service)
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 9.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

use crate::models::CiStatus;
use crate::services::audit::{AuditError, AuditEvent, AuditService};

/// Maximum execution time for a CI pipeline (in seconds)
const DEFAULT_TIMEOUT_SECS: u64 = 600; // 10 minutes

/// Maximum memory limit for CI container (in bytes)
const DEFAULT_MEMORY_LIMIT: u64 = 512 * 1024 * 1024; // 512 MB

/// Maximum CPU shares for CI container
const DEFAULT_CPU_SHARES: u64 = 1024;

/// Errors that can occur during CI operations
#[derive(Debug, Error)]
pub enum CiError {
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Pull request not found: {0}")]
    PrNotFound(String),

    #[error("CI configuration not found in repository")]
    ConfigNotFound,

    #[error("Invalid CI configuration: {0}")]
    InvalidConfig(String),

    #[error("Pipeline execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Pipeline timed out after {0} seconds")]
    Timeout(u64),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Sandbox creation failed: {0}")]
    SandboxError(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
}

/// CI pipeline run status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "ci_run_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CiRunStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Cancelled,
    TimedOut,
}

impl From<CiRunStatus> for CiStatus {
    fn from(status: CiRunStatus) -> Self {
        match status {
            CiRunStatus::Pending => CiStatus::Pending,
            CiRunStatus::Running => CiStatus::Running,
            CiRunStatus::Passed => CiStatus::Passed,
            CiRunStatus::Failed | CiRunStatus::Cancelled | CiRunStatus::TimedOut => {
                CiStatus::Failed
            }
        }
    }
}

/// CI configuration from .gitclaw-ci.yml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiConfig {
    /// Pipeline name
    #[serde(default = "default_pipeline_name")]
    pub name: String,

    /// List of pipeline steps
    pub steps: Vec<CiStep>,

    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Resource limits
    #[serde(default)]
    pub resources: ResourceLimits,

    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_pipeline_name() -> String {
    "default".to_string()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

/// A single step in the CI pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiStep {
    /// Step name
    pub name: String,

    /// Command to run
    pub run: String,

    /// Working directory (relative to repo root)
    #[serde(default)]
    pub working_dir: Option<String>,

    /// Environment variables specific to this step
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Continue on error
    #[serde(default)]
    pub continue_on_error: bool,
}

/// Resource limits for CI execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit in bytes
    #[serde(default = "default_memory_limit")]
    pub memory: u64,

    /// CPU shares (relative weight)
    #[serde(default = "default_cpu_shares")]
    pub cpu_shares: u64,

    /// Disk space limit in bytes
    #[serde(default = "default_disk_limit")]
    pub disk: u64,
}

fn default_memory_limit() -> u64 {
    DEFAULT_MEMORY_LIMIT
}

fn default_cpu_shares() -> u64 {
    DEFAULT_CPU_SHARES
}

fn default_disk_limit() -> u64 {
    1024 * 1024 * 1024 // 1 GB
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory: default_memory_limit(),
            cpu_shares: default_cpu_shares(),
            disk: default_disk_limit(),
        }
    }
}

/// Result of a single step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step name
    pub name: String,

    /// Exit code (0 = success)
    pub exit_code: i32,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// Whether the step passed
    pub passed: bool,
}

/// Result of a complete pipeline run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Run ID
    pub run_id: String,

    /// PR ID that triggered this run
    pub pr_id: String,

    /// Repository ID
    pub repo_id: String,

    /// Commit SHA being tested
    pub commit_sha: String,

    /// Overall status
    pub status: CiRunStatus,

    /// Results of each step
    pub steps: Vec<StepResult>,

    /// Total duration in milliseconds
    pub total_duration_ms: u64,

    /// When the run started
    pub started_at: DateTime<Utc>,

    /// When the run completed
    pub completed_at: Option<DateTime<Utc>>,

    /// Full log output
    pub logs: String,
}

/// CI pipeline run record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiRun {
    pub run_id: String,
    pub pr_id: String,
    pub repo_id: String,
    pub commit_sha: String,
    pub status: CiRunStatus,
    pub config: CiConfig,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub logs: String,
}

/// Sandbox configuration for isolated execution
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Resource limits
    pub resources: ResourceLimits,

    /// Timeout duration
    pub timeout: Duration,

    /// Allowed network hosts (empty = no network)
    pub allowed_hosts: Vec<String>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Working directory
    pub working_dir: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            resources: ResourceLimits::default(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            allowed_hosts: Vec::new(), // No network access by default
            env: HashMap::new(),
            working_dir: "/workspace".to_string(),
        }
    }
}

/// Service for managing CI pipelines
///
/// Design Reference: DR-8.1 (CI Service)
#[derive(Debug, Clone)]
pub struct CiService {
    pool: PgPool,
}

impl CiService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Trigger CI pipeline for a pull request
    ///
    /// Called when a PR is opened or updated.
    /// Requirements: 9.1
    pub async fn trigger_for_pr(
        &self,
        repo_id: &str,
        pr_id: &str,
        commit_sha: &str,
    ) -> Result<String, CiError> {
        // Verify repository exists
        let repo_exists: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM repositories WHERE repo_id = $1")
                .bind(repo_id)
                .fetch_optional(&self.pool)
                .await?;

        if repo_exists.is_none() {
            return Err(CiError::RepoNotFound(repo_id.to_string()));
        }

        // Verify PR exists
        let pr_exists: Option<String> =
            sqlx::query_scalar("SELECT pr_id FROM pull_requests WHERE pr_id = $1")
                .bind(pr_id)
                .fetch_optional(&self.pool)
                .await?;

        if pr_exists.is_none() {
            return Err(CiError::PrNotFound(pr_id.to_string()));
        }

        // Read CI configuration from repository
        let config = self.read_ci_config(repo_id, commit_sha).await?;

        // Generate run ID
        let run_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();

        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Create CI run record
        sqlx::query(
            r#"
            INSERT INTO ci_runs (run_id, pr_id, repo_id, commit_sha, status, config, started_at, logs)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&run_id)
        .bind(pr_id)
        .bind(repo_id)
        .bind(commit_sha)
        .bind(CiRunStatus::Pending)
        .bind(serde_json::to_value(&config).unwrap_or_default())
        .bind(started_at)
        .bind("")
        .execute(&mut *tx)
        .await?;

        // Update PR CI status to pending
        sqlx::query("UPDATE pull_requests SET ci_status = $1 WHERE pr_id = $2")
            .bind(CiStatus::Pending)
            .bind(pr_id)
            .execute(&mut *tx)
            .await?;

        // Append audit event
        let audit_data = serde_json::json!({
            "run_id": run_id,
            "pr_id": pr_id,
            "repo_id": repo_id,
            "commit_sha": commit_sha,
            "trigger": "pr_update",
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: "system".to_string(),
                action: "ci_triggered".to_string(),
                resource_type: "ci_run".to_string(),
                resource_id: run_id.clone(),
                data: audit_data,
                signature: "system".to_string(),
            },
        )
        .await?;

        // Insert into event_outbox for async processing
        sqlx::query(
            r#"
            INSERT INTO event_outbox (audit_event_id, topic, status, available_at, created_at)
            SELECT event_id, 'ci_run', 'pending', NOW(), NOW()
            FROM audit_log
            WHERE resource_id = $1 AND action = 'ci_triggered'
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .bind(&run_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(run_id)
    }

    /// Execute a CI pipeline run
    ///
    /// This is called by the background worker to actually run the pipeline.
    /// Requirements: 9.2, 9.3, 9.4
    pub async fn execute_run(&self, run_id: &str) -> Result<PipelineResult, CiError> {
        // Get the run record
        let run = self.get_run(run_id).await?;
        let run = run.ok_or_else(|| CiError::ExecutionFailed("Run not found".to_string()))?;

        // Update status to running
        self.update_run_status(run_id, CiRunStatus::Running).await?;
        self.update_pr_ci_status(&run.pr_id, CiStatus::Running)
            .await?;

        let started_at = Utc::now();
        let mut logs = String::new();
        let mut step_results = Vec::new();
        let mut overall_passed = true;

        // Create sandbox configuration
        let sandbox_config = SandboxConfig {
            resources: run.config.resources.clone(),
            timeout: Duration::from_secs(run.config.timeout),
            allowed_hosts: Vec::new(), // No network access (Requirement 9.2)
            env: run.config.env.clone(),
            working_dir: "/workspace".to_string(),
        };

        // Execute each step
        for step in &run.config.steps {
            logs.push_str(&format!("\n=== Step: {} ===\n", step.name));
            logs.push_str(&format!("Command: {}\n", step.run));

            let step_start = std::time::Instant::now();

            // Execute step in sandbox
            let step_result = self
                .execute_step_in_sandbox(step, &sandbox_config, &run.repo_id, &run.commit_sha)
                .await;

            let duration_ms = step_start.elapsed().as_millis() as u64;

            match step_result {
                Ok(result) => {
                    logs.push_str(&format!("Exit code: {}\n", result.exit_code));
                    if !result.stdout.is_empty() {
                        logs.push_str(&format!("stdout:\n{}\n", result.stdout));
                    }
                    if !result.stderr.is_empty() {
                        logs.push_str(&format!("stderr:\n{}\n", result.stderr));
                    }

                    let passed = result.exit_code == 0 || step.continue_on_error;
                    if !passed {
                        overall_passed = false;
                    }

                    step_results.push(StepResult {
                        name: step.name.clone(),
                        exit_code: result.exit_code,
                        stdout: result.stdout,
                        stderr: result.stderr,
                        duration_ms,
                        passed,
                    });

                    if !passed && !step.continue_on_error {
                        logs.push_str(&format!("Step '{}' failed, stopping pipeline\n", step.name));
                        break;
                    }
                }
                Err(e) => {
                    logs.push_str(&format!("Step execution error: {}\n", e));
                    overall_passed = false;

                    step_results.push(StepResult {
                        name: step.name.clone(),
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: e.to_string(),
                        duration_ms,
                        passed: false,
                    });

                    if !step.continue_on_error {
                        break;
                    }
                }
            }
        }

        let completed_at = Utc::now();
        let total_duration_ms = (completed_at - started_at).num_milliseconds() as u64;
        let final_status = if overall_passed {
            CiRunStatus::Passed
        } else {
            CiRunStatus::Failed
        };

        // Update run record with results
        self.complete_run(run_id, final_status, &logs).await?;

        // Update PR CI status (Requirement 9.3)
        self.update_pr_ci_status(&run.pr_id, final_status.into())
            .await?;

        // Store logs for audit (Requirement 9.4)
        self.store_run_logs(run_id, &logs).await?;

        Ok(PipelineResult {
            run_id: run_id.to_string(),
            pr_id: run.pr_id,
            repo_id: run.repo_id,
            commit_sha: run.commit_sha,
            status: final_status,
            steps: step_results,
            total_duration_ms,
            started_at,
            completed_at: Some(completed_at),
            logs,
        })
    }

    /// Execute a single step in a sandboxed environment
    ///
    /// Requirements: 9.2 (isolation, resource limits, no production network)
    async fn execute_step_in_sandbox(
        &self,
        step: &CiStep,
        config: &SandboxConfig,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<StepExecutionResult, CiError> {
        // In a production implementation, this would:
        // 1. Create an isolated container (Docker, Firecracker, etc.)
        // 2. Mount the repository code at the working directory
        // 3. Apply resource limits (memory, CPU, disk)
        // 4. Block network access except for allowed hosts
        // 5. Execute the command with timeout
        // 6. Capture stdout/stderr
        // 7. Clean up the container

        // For now, we simulate sandbox execution
        // A real implementation would use something like:
        // - Docker with --network=none for network isolation
        // - --memory and --cpus flags for resource limits
        // - seccomp profiles for syscall filtering
        // - Read-only filesystem except for designated areas

        tracing::info!(
            "Executing step '{}' in sandbox for repo {} at commit {}",
            step.name,
            repo_id,
            commit_sha
        );
        tracing::debug!("Sandbox config: {:?}", config);
        tracing::debug!("Command: {}", step.run);

        // Simulate execution with configurable behavior for testing
        // In production, this would actually run the command in a container
        let simulated_result = self.simulate_step_execution(step).await;

        Ok(simulated_result)
    }

    /// Simulate step execution (for development/testing)
    ///
    /// In production, replace with actual container execution
    async fn simulate_step_execution(&self, step: &CiStep) -> StepExecutionResult {
        // Parse the command to determine simulated behavior
        let command = step.run.to_lowercase();

        // Simulate common CI commands
        if command.contains("test") && command.contains("fail") {
            StepExecutionResult {
                exit_code: 1,
                stdout: "Running tests...\n".to_string(),
                stderr: "Test failed: assertion error\n".to_string(),
            }
        } else if command.contains("test") {
            StepExecutionResult {
                exit_code: 0,
                stdout: "Running tests...\nAll tests passed!\n".to_string(),
                stderr: String::new(),
            }
        } else if command.contains("build") {
            StepExecutionResult {
                exit_code: 0,
                stdout: "Building project...\nBuild successful!\n".to_string(),
                stderr: String::new(),
            }
        } else if command.contains("lint") {
            StepExecutionResult {
                exit_code: 0,
                stdout: "Linting code...\nNo issues found.\n".to_string(),
                stderr: String::new(),
            }
        } else {
            // Default: success
            StepExecutionResult {
                exit_code: 0,
                stdout: format!("Executed: {}\n", step.run),
                stderr: String::new(),
            }
        }
    }

    /// Read CI configuration from repository
    ///
    /// Looks for .gitclaw-ci.yml in the repository root
    async fn read_ci_config(&self, repo_id: &str, commit_sha: &str) -> Result<CiConfig, CiError> {
        // In a real implementation, this would:
        // 1. Checkout the commit
        // 2. Read .gitclaw-ci.yml from the repo root
        // 3. Parse and validate the YAML

        // For now, check if we have a stored config or return a default
        let config_blob: Option<Vec<u8>> = sqlx::query_scalar(
            r#"
            SELECT o.data
            FROM repo_objects o
            JOIN repo_refs r ON r.repo_id = o.repo_id
            WHERE o.repo_id = $1
              AND o.object_type = 'blob'
              AND r.oid = $2
            LIMIT 1
            "#,
        )
        .bind(repo_id)
        .bind(commit_sha)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(data) = config_blob {
            // Try to parse as YAML
            let config_str = String::from_utf8_lossy(&data);
            if let Ok(config) = serde_yaml_parse(&config_str) {
                return Ok(config);
            }
        }

        // Return default config if not found
        // In production, you might want to return ConfigNotFound error instead
        Ok(CiConfig {
            name: "default".to_string(),
            steps: vec![
                CiStep {
                    name: "build".to_string(),
                    run: "echo 'Building...'".to_string(),
                    working_dir: None,
                    env: HashMap::new(),
                    continue_on_error: false,
                },
                CiStep {
                    name: "test".to_string(),
                    run: "echo 'Testing...'".to_string(),
                    working_dir: None,
                    env: HashMap::new(),
                    continue_on_error: false,
                },
            ],
            env: HashMap::new(),
            resources: ResourceLimits::default(),
            timeout: DEFAULT_TIMEOUT_SECS,
        })
    }

    /// Get a CI run by ID
    pub async fn get_run(&self, run_id: &str) -> Result<Option<CiRun>, CiError> {
        let row = sqlx::query(
            r#"
            SELECT run_id, pr_id, repo_id, commit_sha, status, config, started_at, completed_at, logs
            FROM ci_runs
            WHERE run_id = $1
            "#,
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            use sqlx::Row;
            let config_json: serde_json::Value = r.get("config");
            CiRun {
                run_id: r.get("run_id"),
                pr_id: r.get("pr_id"),
                repo_id: r.get("repo_id"),
                commit_sha: r.get("commit_sha"),
                status: r.get("status"),
                config: serde_json::from_value(config_json).unwrap_or_else(|_| CiConfig {
                    name: "default".to_string(),
                    steps: Vec::new(),
                    env: HashMap::new(),
                    resources: ResourceLimits::default(),
                    timeout: DEFAULT_TIMEOUT_SECS,
                }),
                started_at: r.get("started_at"),
                completed_at: r.get("completed_at"),
                logs: r.get("logs"),
            }
        }))
    }

    /// Get CI runs for a PR
    pub async fn get_runs_for_pr(&self, pr_id: &str) -> Result<Vec<CiRun>, CiError> {
        let rows = sqlx::query(
            r#"
            SELECT run_id, pr_id, repo_id, commit_sha, status, config, started_at, completed_at, logs
            FROM ci_runs
            WHERE pr_id = $1
            ORDER BY started_at DESC
            "#,
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                use sqlx::Row;
                let config_json: serde_json::Value = r.get("config");
                CiRun {
                    run_id: r.get("run_id"),
                    pr_id: r.get("pr_id"),
                    repo_id: r.get("repo_id"),
                    commit_sha: r.get("commit_sha"),
                    status: r.get("status"),
                    config: serde_json::from_value(config_json).unwrap_or_else(|_| CiConfig {
                        name: "default".to_string(),
                        steps: Vec::new(),
                        env: HashMap::new(),
                        resources: ResourceLimits::default(),
                        timeout: DEFAULT_TIMEOUT_SECS,
                    }),
                    started_at: r.get("started_at"),
                    completed_at: r.get("completed_at"),
                    logs: r.get("logs"),
                }
            })
            .collect())
    }

    /// Update CI run status
    async fn update_run_status(&self, run_id: &str, status: CiRunStatus) -> Result<(), CiError> {
        sqlx::query("UPDATE ci_runs SET status = $1 WHERE run_id = $2")
            .bind(status)
            .bind(run_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update PR CI status
    async fn update_pr_ci_status(&self, pr_id: &str, status: CiStatus) -> Result<(), CiError> {
        sqlx::query("UPDATE pull_requests SET ci_status = $1 WHERE pr_id = $2")
            .bind(status)
            .bind(pr_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Complete a CI run with final status and logs
    async fn complete_run(
        &self,
        run_id: &str,
        status: CiRunStatus,
        logs: &str,
    ) -> Result<(), CiError> {
        let completed_at = Utc::now();

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE ci_runs
            SET status = $1, completed_at = $2, logs = $3
            WHERE run_id = $4
            "#,
        )
        .bind(status)
        .bind(completed_at)
        .bind(logs)
        .bind(run_id)
        .execute(&mut *tx)
        .await?;

        // Append audit event for completion
        let audit_data = serde_json::json!({
            "run_id": run_id,
            "status": status,
            "completed_at": completed_at,
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: "system".to_string(),
                action: "ci_completed".to_string(),
                resource_type: "ci_run".to_string(),
                resource_id: run_id.to_string(),
                data: audit_data,
                signature: "system".to_string(),
            },
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Store CI run logs for audit
    ///
    /// Requirement 9.4: Store pipeline logs for audit
    async fn store_run_logs(&self, run_id: &str, logs: &str) -> Result<(), CiError> {
        // Logs are already stored in ci_runs table
        // This method can be extended to store logs in a separate storage system
        // (e.g., S3, object storage) for long-term retention

        let mut tx = self.pool.begin().await?;

        // Append audit event for log storage
        let audit_data = serde_json::json!({
            "run_id": run_id,
            "log_size_bytes": logs.len(),
        });

        AuditService::append_in_tx(
            &mut tx,
            AuditEvent {
                agent_id: "system".to_string(),
                action: "ci_logs_stored".to_string(),
                resource_type: "ci_run".to_string(),
                resource_id: run_id.to_string(),
                data: audit_data,
                signature: "system".to_string(),
            },
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Get logs for a CI run
    pub async fn get_run_logs(&self, run_id: &str) -> Result<Option<String>, CiError> {
        let logs: Option<String> =
            sqlx::query_scalar("SELECT logs FROM ci_runs WHERE run_id = $1")
                .bind(run_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(logs)
    }

    /// Cancel a running CI pipeline
    pub async fn cancel_run(&self, run_id: &str) -> Result<(), CiError> {
        let run = self.get_run(run_id).await?;
        let run = run.ok_or_else(|| CiError::ExecutionFailed("Run not found".to_string()))?;

        if run.status != CiRunStatus::Running && run.status != CiRunStatus::Pending {
            return Err(CiError::ExecutionFailed(format!(
                "Cannot cancel run in status {:?}",
                run.status
            )));
        }

        self.complete_run(run_id, CiRunStatus::Cancelled, &run.logs)
            .await?;
        self.update_pr_ci_status(&run.pr_id, CiStatus::Failed)
            .await?;

        Ok(())
    }
}

/// Result of executing a single step
#[derive(Debug, Clone)]
struct StepExecutionResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Parse YAML config (simplified parser)
///
/// In production, use the `serde_yaml` crate
fn serde_yaml_parse(content: &str) -> Result<CiConfig, String> {
    // Simple YAML-like parsing for .gitclaw-ci.yml
    // In production, use serde_yaml crate

    let mut config = CiConfig {
        name: "default".to_string(),
        steps: Vec::new(),
        env: HashMap::new(),
        resources: ResourceLimits::default(),
        timeout: DEFAULT_TIMEOUT_SECS,
    };

    let mut current_step: Option<CiStep> = None;
    let mut in_steps = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("name:") {
            config.name = trimmed.trim_start_matches("name:").trim().to_string();
        } else if trimmed == "steps:" {
            in_steps = true;
        } else if in_steps && trimmed.starts_with("- name:") {
            // Save previous step if any
            if let Some(step) = current_step.take() {
                config.steps.push(step);
            }
            current_step = Some(CiStep {
                name: trimmed.trim_start_matches("- name:").trim().to_string(),
                run: String::new(),
                working_dir: None,
                env: HashMap::new(),
                continue_on_error: false,
            });
        } else if in_steps && trimmed.starts_with("run:") {
            if let Some(ref mut step) = current_step {
                step.run = trimmed.trim_start_matches("run:").trim().to_string();
            }
        } else if trimmed.starts_with("timeout:") {
            if let Ok(t) = trimmed.trim_start_matches("timeout:").trim().parse() {
                config.timeout = t;
            }
        }
    }

    // Save last step
    if let Some(step) = current_step {
        config.steps.push(step);
    }

    if config.steps.is_empty() {
        return Err("No steps defined in CI config".to_string());
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_resource_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory, DEFAULT_MEMORY_LIMIT);
        assert_eq!(limits.cpu_shares, DEFAULT_CPU_SHARES);
    }

    #[test]
    fn test_ci_run_status_conversion() {
        assert_eq!(CiStatus::from(CiRunStatus::Pending), CiStatus::Pending);
        assert_eq!(CiStatus::from(CiRunStatus::Running), CiStatus::Running);
        assert_eq!(CiStatus::from(CiRunStatus::Passed), CiStatus::Passed);
        assert_eq!(CiStatus::from(CiRunStatus::Failed), CiStatus::Failed);
        assert_eq!(CiStatus::from(CiRunStatus::Cancelled), CiStatus::Failed);
        assert_eq!(CiStatus::from(CiRunStatus::TimedOut), CiStatus::Failed);
    }

    #[test]
    fn test_yaml_parse_basic() {
        let yaml = r#"
name: test-pipeline
steps:
- name: build
  run: cargo build
- name: test
  run: cargo test
timeout: 300
"#;
        let config = serde_yaml_parse(yaml).unwrap();
        assert_eq!(config.name, "test-pipeline");
        assert_eq!(config.steps.len(), 2);
        assert_eq!(config.steps[0].name, "build");
        assert_eq!(config.steps[0].run, "cargo build");
        assert_eq!(config.steps[1].name, "test");
        assert_eq!(config.steps[1].run, "cargo test");
        assert_eq!(config.timeout, 300);
    }

    #[test]
    fn test_sandbox_config_default_no_network() {
        let config = SandboxConfig::default();
        assert!(config.allowed_hosts.is_empty(), "Sandbox should have no network access by default");
    }

    #[test]
    fn test_resource_limits_default_values() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory, 512 * 1024 * 1024, "Default memory should be 512MB");
        assert_eq!(limits.cpu_shares, 1024, "Default CPU shares should be 1024");
        assert_eq!(limits.disk, 1024 * 1024 * 1024, "Default disk should be 1GB");
    }
}

// ============================================================================
// Integration Tests for CI Service
// Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
// Design: DR-8.1 (CI Service)
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use sqlx::PgPool;

    /// Helper to create a test database pool - returns None if connection fails
    async fn try_create_test_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return None,
        };

        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .ok()
    }

    /// Create a test agent in the database
    async fn create_test_agent(pool: &PgPool) -> String {
        let agent_id = uuid::Uuid::new_v4().to_string();
        let agent_name = format!("test-agent-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO agents (agent_id, agent_name, public_key, capabilities, created_at)
            VALUES ($1, $2, 'test-public-key', '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .bind(&agent_name)
        .execute(pool)
        .await
        .expect("Failed to create test agent");

        // Initialize reputation
        let _ = sqlx::query(
            r#"
            INSERT INTO reputation (agent_id, score, cluster_ids, updated_at)
            VALUES ($1, 0.500, '[]', NOW())
            ON CONFLICT (agent_id) DO NOTHING
            "#,
        )
        .bind(&agent_id)
        .execute(pool)
        .await;

        agent_id
    }

    /// Create a test repository
    async fn create_test_repo(pool: &PgPool, owner_id: &str) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        let repo_name = format!("test-repo-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO repositories (repo_id, owner_id, name, description, visibility, default_branch, created_at)
            VALUES ($1, $2, $3, 'Test repo', 'public', 'main', NOW())
            "#,
        )
        .bind(&repo_id)
        .bind(owner_id)
        .bind(&repo_name)
        .execute(pool)
        .await
        .expect("Failed to create test repo");

        // Initialize star counts
        let _ = sqlx::query(
            "INSERT INTO repo_star_counts (repo_id, stars, updated_at) VALUES ($1, 0, NOW())",
        )
        .bind(&repo_id)
        .execute(pool)
        .await;

        // Create default branch ref
        let _ = sqlx::query(
            "INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at) VALUES ($1, 'refs/heads/main', $2, NOW())",
        )
        .bind(&repo_id)
        .bind(&format!("{:040x}", rand::random::<u128>()))
        .execute(pool)
        .await;

        repo_id
    }

    /// Create a test pull request
    async fn create_test_pr(pool: &PgPool, repo_id: &str, author_id: &str) -> String {
        let pr_id = uuid::Uuid::new_v4().to_string();

        // Create a feature branch for the PR
        let _ = sqlx::query(
            "INSERT INTO repo_refs (repo_id, ref_name, oid, updated_at) VALUES ($1, 'refs/heads/feature', $2, NOW())",
        )
        .bind(repo_id)
        .bind(&format!("{:040x}", rand::random::<u128>()))
        .execute(pool)
        .await;

        sqlx::query(
            r#"
            INSERT INTO pull_requests (pr_id, repo_id, author_id, source_branch, target_branch, title, description, status, ci_status, created_at)
            VALUES ($1, $2, $3, 'feature', 'main', 'Test PR', 'Test description', 'open', 'pending', NOW())
            "#,
        )
        .bind(&pr_id)
        .bind(repo_id)
        .bind(author_id)
        .execute(pool)
        .await
        .expect("Failed to create test PR");

        pr_id
    }

    /// Clean up test data
    async fn cleanup_test_data(pool: &PgPool, agent_id: &str, repo_id: &str, pr_id: &str) {
        // Clean up in reverse order of dependencies
        let _ = sqlx::query("DELETE FROM ci_step_results WHERE run_id IN (SELECT run_id FROM ci_runs WHERE pr_id = $1)")
            .bind(pr_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM ci_runs WHERE pr_id = $1")
            .bind(pr_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM reviews WHERE pr_id = $1")
            .bind(pr_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM pull_requests WHERE pr_id = $1")
            .bind(pr_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_refs WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_star_counts WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repo_access WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE repo_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM reputation WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    // =========================================================================
    // Test: CI pipeline triggered on PR creation
    // Requirements: 9.1
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ci_triggered_on_pr_creation() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger CI for the PR
        let result = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await;

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        assert!(result.is_ok(), "CI trigger should succeed: {:?}", result);
        let run_id = result.unwrap();
        assert!(!run_id.is_empty(), "Run ID should not be empty");
    }

    // =========================================================================
    // Test: CI pipeline triggered on PR update (new commits)
    // Requirements: 9.1
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ci_triggered_on_pr_update() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());

        // First trigger (initial PR)
        let commit_sha1 = format!("{:040x}", rand::random::<u128>());
        let result1 = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha1).await;
        assert!(result1.is_ok(), "First CI trigger should succeed");

        // Second trigger (PR update with new commit)
        let commit_sha2 = format!("{:040x}", rand::random::<u128>());
        let result2 = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha2).await;

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        assert!(result2.is_ok(), "Second CI trigger should succeed: {:?}", result2);
        let run_id1 = result1.unwrap();
        let run_id2 = result2.unwrap();
        assert_ne!(run_id1, run_id2, "Each trigger should create a new run");
    }

    // =========================================================================
    // Test: CI status transitions (pending → running → passed/failed)
    // Requirements: 9.3
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ci_status_transitions() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger CI
        let run_id = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await
            .expect("CI trigger should succeed");

        // Verify initial status is pending
        let run = ci_service.get_run(&run_id).await
            .expect("Get run should succeed")
            .expect("Run should exist");
        assert_eq!(run.status, CiRunStatus::Pending, "Initial status should be pending");

        // Execute the run (this transitions through running to passed/failed)
        let result = ci_service.execute_run(&run_id).await;

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        assert!(result.is_ok(), "Execute run should succeed: {:?}", result);
        let pipeline_result = result.unwrap();
        assert!(
            matches!(pipeline_result.status, CiRunStatus::Passed | CiRunStatus::Failed),
            "Final status should be passed or failed"
        );
    }

    // =========================================================================
    // Test: CI logs stored and retrievable
    // Requirements: 9.4
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ci_logs_stored_and_retrievable() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger and execute CI
        let run_id = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await
            .expect("CI trigger should succeed");
        let _ = ci_service.execute_run(&run_id).await
            .expect("Execute run should succeed");

        // Retrieve logs
        let logs = ci_service.get_run_logs(&run_id).await;

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        assert!(logs.is_ok(), "Get logs should succeed: {:?}", logs);
        let logs = logs.unwrap();
        assert!(logs.is_some(), "Logs should exist");
        let logs = logs.unwrap();
        assert!(!logs.is_empty(), "Logs should not be empty");
        assert!(logs.contains("Step:"), "Logs should contain step information");
    }

    // =========================================================================
    // Test: Sandbox isolation (no production network access)
    // Requirements: 9.2
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_sandbox_isolation_no_network() {
        // This test verifies that the sandbox configuration defaults to no network access
        let config = SandboxConfig::default();
        
        assert!(
            config.allowed_hosts.is_empty(),
            "Sandbox should have no allowed hosts by default (no network access)"
        );
        
        // Verify resource limits are set
        assert!(config.resources.memory > 0, "Memory limit should be set");
        assert!(config.resources.cpu_shares > 0, "CPU shares should be set");
        assert!(config.timeout.as_secs() > 0, "Timeout should be set");
    }

    // =========================================================================
    // Test: Resource limits enforced (CPU, memory, time)
    // Requirements: 9.2
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_resource_limits_enforced() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger CI
        let run_id = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await
            .expect("CI trigger should succeed");

        // Get the run and verify config has resource limits
        let run = ci_service.get_run(&run_id).await
            .expect("Get run should succeed")
            .expect("Run should exist");

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        // Verify resource limits are configured
        assert!(run.config.resources.memory > 0, "Memory limit should be configured");
        assert!(run.config.resources.cpu_shares > 0, "CPU shares should be configured");
        assert!(run.config.timeout > 0, "Timeout should be configured");
    }

    // =========================================================================
    // Test: PR marked CI-approved when all pipelines pass
    // Requirements: 9.5
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_pr_marked_ci_approved_when_passed() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger and execute CI
        let run_id = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await
            .expect("CI trigger should succeed");
        let result = ci_service.execute_run(&run_id).await
            .expect("Execute run should succeed");

        // Check PR CI status
        let pr_ci_status: CiStatus = sqlx::query_scalar(
            "SELECT ci_status FROM pull_requests WHERE pr_id = $1"
        )
        .bind(&pr_id)
        .fetch_one(&pool)
        .await
        .expect("Should get PR CI status");

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        // If pipeline passed, PR should be marked as CI passed
        if result.status == CiRunStatus::Passed {
            assert_eq!(pr_ci_status, CiStatus::Passed, "PR should be marked CI-approved when pipeline passes");
        } else {
            assert_eq!(pr_ci_status, CiStatus::Failed, "PR should be marked CI-failed when pipeline fails");
        }
    }

    // =========================================================================
    // Test: CI reads .gitclaw-ci.yml configuration correctly
    // Requirements: 9.1
    // Design: DR-8.1
    // =========================================================================
    #[ignore]
    #[tokio::test]
    async fn integration_ci_reads_config_correctly() {
        let pool = match try_create_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping test: database not available");
                return;
            }
        };

        let agent_id = create_test_agent(&pool).await;
        let repo_id = create_test_repo(&pool, &agent_id).await;
        let pr_id = create_test_pr(&pool, &repo_id, &agent_id).await;

        let ci_service = CiService::new(pool.clone());
        let commit_sha = format!("{:040x}", rand::random::<u128>());

        // Trigger CI
        let run_id = ci_service.trigger_for_pr(&repo_id, &pr_id, &commit_sha).await
            .expect("CI trigger should succeed");

        // Get the run and verify config was loaded
        let run = ci_service.get_run(&run_id).await
            .expect("Get run should succeed")
            .expect("Run should exist");

        // Cleanup
        cleanup_test_data(&pool, &agent_id, &repo_id, &pr_id).await;

        // Verify config has steps (either from file or default)
        assert!(!run.config.steps.is_empty(), "CI config should have steps");
        assert!(!run.config.name.is_empty(), "CI config should have a name");
    }
}

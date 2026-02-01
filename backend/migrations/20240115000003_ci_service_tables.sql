-- CI Service Tables
-- This migration adds tables for CI pipeline execution

-- ============================================================================
-- CI RUN STATUS ENUM
-- ============================================================================

CREATE TYPE ci_run_status AS ENUM ('pending', 'running', 'passed', 'failed', 'cancelled', 'timed_out');

-- ============================================================================
-- CI RUNS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS ci_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    pr_id VARCHAR(64) NOT NULL REFERENCES pull_requests(pr_id) ON DELETE CASCADE,
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    commit_sha VARCHAR(40) NOT NULL,
    status ci_run_status NOT NULL DEFAULT 'pending',
    config JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    logs TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ci_runs_pr ON ci_runs(pr_id);
CREATE INDEX IF NOT EXISTS idx_ci_runs_repo ON ci_runs(repo_id);
CREATE INDEX IF NOT EXISTS idx_ci_runs_status ON ci_runs(status);
CREATE INDEX IF NOT EXISTS idx_ci_runs_started ON ci_runs(started_at DESC);

-- ============================================================================
-- CI STEP RESULTS TABLE (optional, for detailed step tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS ci_step_results (
    step_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id VARCHAR(64) NOT NULL REFERENCES ci_runs(run_id) ON DELETE CASCADE,
    step_name VARCHAR(256) NOT NULL,
    step_order INTEGER NOT NULL,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    duration_ms BIGINT,
    passed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ci_step_results_run ON ci_step_results(run_id);

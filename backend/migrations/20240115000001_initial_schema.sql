-- GitClaw Initial Database Schema
-- This migration creates all core tables for the GitClaw platform

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

CREATE TYPE visibility AS ENUM ('public', 'private');
CREATE TYPE access_role AS ENUM ('read', 'write', 'admin');
CREATE TYPE pr_status AS ENUM ('open', 'merged', 'closed');
CREATE TYPE ci_status AS ENUM ('pending', 'running', 'passed', 'failed');
CREATE TYPE review_verdict AS ENUM ('approve', 'request_changes', 'comment');
CREATE TYPE star_action AS ENUM ('star', 'unstar');
CREATE TYPE trending_window AS ENUM ('1h', '24h', '7d', '30d');
CREATE TYPE outbox_status AS ENUM ('pending', 'processing', 'processed', 'dead');

-- ============================================================================
-- AGENTS TABLE
-- ============================================================================

CREATE TABLE agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    agent_name VARCHAR(128) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_name ON agents(agent_name);

-- ============================================================================
-- REPOSITORIES TABLE
-- ============================================================================

CREATE TABLE repositories (
    repo_id VARCHAR(64) PRIMARY KEY,
    owner_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id),
    name VARCHAR(256) NOT NULL,
    description TEXT,
    visibility visibility NOT NULL DEFAULT 'public',
    default_branch VARCHAR(128) NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner_id, name)
);

CREATE INDEX idx_repositories_owner ON repositories(owner_id);
CREATE INDEX idx_repositories_visibility ON repositories(visibility);


-- ============================================================================
-- REPO ACCESS TABLE (for private repo permissions)
-- ============================================================================

CREATE TABLE repo_access (
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    role access_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, agent_id)
);

CREATE INDEX idx_repo_access_agent ON repo_access(agent_id);

-- ============================================================================
-- PULL REQUESTS TABLE
-- ============================================================================

CREATE TABLE pull_requests (
    pr_id VARCHAR(64) PRIMARY KEY,
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    author_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id),
    source_branch VARCHAR(128) NOT NULL,
    target_branch VARCHAR(128) NOT NULL,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    status pr_status NOT NULL DEFAULT 'open',
    ci_status ci_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    merged_at TIMESTAMPTZ
);

CREATE INDEX idx_pull_requests_repo ON pull_requests(repo_id);
CREATE INDEX idx_pull_requests_author ON pull_requests(author_id);
CREATE INDEX idx_pull_requests_status ON pull_requests(status);

-- ============================================================================
-- REVIEWS TABLE
-- ============================================================================

CREATE TABLE reviews (
    review_id VARCHAR(64) PRIMARY KEY,
    pr_id VARCHAR(64) NOT NULL REFERENCES pull_requests(pr_id) ON DELETE CASCADE,
    reviewer_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id),
    verdict review_verdict NOT NULL,
    body TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reviews_pr ON reviews(pr_id);
CREATE INDEX idx_reviews_reviewer ON reviews(reviewer_id);

-- ============================================================================
-- REPO STARS TABLE
-- ============================================================================

CREATE TABLE repo_stars (
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    reason TEXT CHECK (reason IS NULL OR LENGTH(reason) <= 500),
    reason_public BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, agent_id)
);

CREATE INDEX idx_repo_stars_agent ON repo_stars(agent_id);
CREATE INDEX idx_repo_stars_created ON repo_stars(created_at DESC);

-- ============================================================================
-- REPO STAR COUNTS TABLE (denormalized for performance)
-- ============================================================================

CREATE TABLE repo_star_counts (
    repo_id VARCHAR(64) PRIMARY KEY REFERENCES repositories(repo_id) ON DELETE CASCADE,
    stars INTEGER NOT NULL DEFAULT 0 CHECK (stars >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- REPUTATION TABLE
-- ============================================================================

CREATE TABLE reputation (
    agent_id VARCHAR(64) PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    score DECIMAL(4,3) NOT NULL DEFAULT 0.500 CHECK (score >= 0.000 AND score <= 1.000),
    cluster_ids JSONB NOT NULL DEFAULT '[]',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================================
-- AUDIT LOG TABLE (authoritative, append-only)
-- ============================================================================

CREATE TABLE audit_log (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature VARCHAR(256) NOT NULL
);

CREATE INDEX idx_audit_log_agent ON audit_log(agent_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);

-- ============================================================================
-- REPO TRENDING SCORES TABLE (async projection)
-- ============================================================================

CREATE TABLE repo_trending_scores (
    "window" trending_window NOT NULL,
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    weighted_score DECIMAL(10,4) NOT NULL DEFAULT 0,
    stars_delta INTEGER NOT NULL DEFAULT 0,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY ("window", repo_id)
);

CREATE INDEX idx_trending_scores_window_score ON repo_trending_scores("window", weighted_score DESC);

-- ============================================================================
-- IDEMPOTENCY RESULTS TABLE
-- ============================================================================

CREATE TABLE idempotency_results (
    nonce_hash VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    status_code INTEGER NOT NULL,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_idempotency_expires ON idempotency_results(expires_at);
CREATE INDEX idx_idempotency_agent_action ON idempotency_results(agent_id, action);

-- ============================================================================
-- EVENT OUTBOX TABLE (for async job delivery)
-- ============================================================================

CREATE TABLE event_outbox (
    outbox_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_event_id UUID NOT NULL REFERENCES audit_log(event_id),
    topic VARCHAR(64) NOT NULL,
    status outbox_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(64),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX idx_outbox_status_available ON event_outbox(status, available_at);
CREATE INDEX idx_outbox_topic_status ON event_outbox(topic, status, available_at);


-- ============================================================================
-- STAR EVENTS TABLE (append-only projection for analytics)
-- ============================================================================

CREATE TABLE star_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    action star_action NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    nonce VARCHAR(36) NOT NULL,
    signature VARCHAR(256) NOT NULL
);

CREATE INDEX idx_star_events_repo ON star_events(repo_id);
CREATE INDEX idx_star_events_agent ON star_events(agent_id);
CREATE INDEX idx_star_events_timestamp ON star_events(timestamp DESC);

-- ============================================================================
-- HELPER TRIGGERS (using simple SQL instead of plpgsql functions)
-- ============================================================================

-- Note: The following triggers should be created after the application
-- handles the initialization logic. For now, the application code will
-- handle creating repo_star_counts and reputation entries when creating
-- agents and repositories respectively.

-- Cleanup function for expired idempotency results (run periodically)
-- DELETE FROM idempotency_results WHERE expires_at < NOW();

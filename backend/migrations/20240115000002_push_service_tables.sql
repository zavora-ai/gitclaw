-- Push Service Tables
-- This migration adds tables for Git refs and objects storage

-- ============================================================================
-- REPO REFS TABLE (stores branch/tag references)
-- ============================================================================

CREATE TABLE IF NOT EXISTS repo_refs (
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    ref_name VARCHAR(256) NOT NULL,
    oid VARCHAR(40) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, ref_name)
);

CREATE INDEX IF NOT EXISTS idx_repo_refs_repo ON repo_refs(repo_id);
CREATE INDEX IF NOT EXISTS idx_repo_refs_oid ON repo_refs(oid);

-- ============================================================================
-- REPO OBJECTS TABLE (stores Git objects: commits, trees, blobs, tags)
-- ============================================================================

CREATE TABLE IF NOT EXISTS repo_objects (
    repo_id VARCHAR(64) NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
    oid VARCHAR(40) NOT NULL,
    object_type VARCHAR(10) NOT NULL CHECK (object_type IN ('commit', 'tree', 'blob', 'tag')),
    size BIGINT NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, oid)
);

CREATE INDEX IF NOT EXISTS idx_repo_objects_repo ON repo_objects(repo_id);
CREATE INDEX IF NOT EXISTS idx_repo_objects_type ON repo_objects(repo_id, object_type);

-- ============================================================================
-- PUSH EVENTS TABLE (append-only projection for analytics)
-- ============================================================================

CREATE TABLE IF NOT EXISTS push_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    ref_updates JSONB NOT NULL DEFAULT '[]',
    packfile_hash VARCHAR(64) NOT NULL,
    objects_count INTEGER NOT NULL DEFAULT 0,
    force_push BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    nonce VARCHAR(36) NOT NULL,
    signature VARCHAR(256) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_events_repo ON push_events(repo_id);
CREATE INDEX IF NOT EXISTS idx_push_events_agent ON push_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_push_events_timestamp ON push_events(timestamp DESC);

-- Migration Tracking Tables
-- This migration adds tables for tracking PostgreSQL to S3 object migration
-- Design Reference: DR-S3-3.1

-- ============================================================================
-- MIGRATION STATUS ENUM
-- ============================================================================

CREATE TYPE migration_status AS ENUM ('pending', 'in_progress', 'completed', 'failed');

-- ============================================================================
-- REPO MIGRATION STATUS TABLE
-- Tracks migration progress per repository
-- ============================================================================

CREATE TABLE IF NOT EXISTS repo_migration_status (
    repo_id VARCHAR(64) PRIMARY KEY REFERENCES repositories(repo_id) ON DELETE CASCADE,
    status migration_status NOT NULL DEFAULT 'pending',
    objects_total INTEGER NOT NULL DEFAULT 0,
    objects_migrated INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_repo_migration_status_status ON repo_migration_status(status);
CREATE INDEX IF NOT EXISTS idx_repo_migration_status_updated ON repo_migration_status(updated_at);

-- ============================================================================
-- OBJECT MIGRATION LOG TABLE
-- Tracks individual object migrations for resumability
-- ============================================================================

CREATE TABLE IF NOT EXISTS object_migration_log (
    repo_id VARCHAR(64) NOT NULL,
    oid VARCHAR(40) NOT NULL,
    migrated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    s3_key VARCHAR(512) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (repo_id, oid)
);

CREATE INDEX IF NOT EXISTS idx_object_migration_log_repo ON object_migration_log(repo_id);
CREATE INDEX IF NOT EXISTS idx_object_migration_log_verified ON object_migration_log(repo_id, verified);
CREATE INDEX IF NOT EXISTS idx_object_migration_log_migrated ON object_migration_log(migrated_at);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE repo_migration_status IS 'Tracks PostgreSQL to S3 migration progress per repository';
COMMENT ON TABLE object_migration_log IS 'Tracks individual object migrations for resumability and verification';

COMMENT ON COLUMN repo_migration_status.objects_total IS 'Total number of objects to migrate for this repository';
COMMENT ON COLUMN repo_migration_status.objects_migrated IS 'Number of objects successfully migrated to S3';
COMMENT ON COLUMN repo_migration_status.last_error IS 'Last error message if migration failed';

COMMENT ON COLUMN object_migration_log.s3_key IS 'Full S3 key path where the object was stored';
COMMENT ON COLUMN object_migration_log.verified IS 'Whether SHA-1 hash was verified after migration';

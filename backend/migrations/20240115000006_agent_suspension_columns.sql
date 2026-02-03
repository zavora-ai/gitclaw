-- Add agent suspension columns for Admin Dashboard feature
-- Requirements: 2.4, 2.5, 2.6 - Agent suspension management

-- ============================================================================
-- AGENT SUSPENSION COLUMNS
-- ============================================================================

-- Add suspended flag (defaults to FALSE for existing agents)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT FALSE;

-- Add timestamp when agent was suspended
ALTER TABLE agents ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;

-- Add reason for suspension (optional, provided by admin)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS suspended_reason TEXT;

-- Add admin identifier who performed the suspension
ALTER TABLE agents ADD COLUMN IF NOT EXISTS suspended_by VARCHAR(64);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Partial index for efficiently filtering suspended agents
-- Only indexes rows where suspended = TRUE to minimize index size
CREATE INDEX IF NOT EXISTS idx_agents_suspended ON agents(suspended) WHERE suspended = TRUE;

-- Audit Log Immutability
-- This migration enforces append-only semantics on the audit_log table
-- by revoking UPDATE and DELETE permissions.
--
-- Requirements: 11.4 (Audit Trail Immutability)
-- Design: DR-14.1 (Audit Service)

-- Create a trigger function that prevents updates and deletes
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to prevent updates
DROP TRIGGER IF EXISTS prevent_audit_log_update ON audit_log;
CREATE TRIGGER prevent_audit_log_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Create trigger to prevent deletes
DROP TRIGGER IF EXISTS prevent_audit_log_delete ON audit_log;
CREATE TRIGGER prevent_audit_log_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Add a comment documenting the immutability constraint
COMMENT ON TABLE audit_log IS 'Authoritative append-only audit log. UPDATE and DELETE operations are blocked by triggers.';

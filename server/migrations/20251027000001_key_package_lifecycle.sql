-- Migration: Enforce key package lifecycle management
-- This migration adds constraints and triggers for proper key package lifecycle.

-- Add key_package_ref column for faster lookups
ALTER TABLE key_packages ADD COLUMN IF NOT EXISTS key_package_ref BYTEA;

-- Create index on key_package_ref
CREATE INDEX IF NOT EXISTS idx_key_packages_ref ON key_packages(key_package_ref);

-- Add constraint to limit key packages per user (enforced in application)
-- Maximum: 100 key packages per DID
-- Note: This is a soft limit enforced by the application, not a database constraint

-- Add trigger to automatically set expires_at to 30 days if not specified
-- This ensures all key packages have an expiration date

-- Create function to set default expiry
CREATE OR REPLACE FUNCTION set_default_key_package_expiry()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.expires_at IS NULL THEN
        NEW.expires_at := NOW() + INTERVAL '30 days';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for key package expiry
DROP TRIGGER IF EXISTS trigger_set_key_package_expiry ON key_packages;
CREATE TRIGGER trigger_set_key_package_expiry
    BEFORE INSERT ON key_packages
    FOR EACH ROW
    EXECUTE FUNCTION set_default_key_package_expiry();

-- Add comments for documentation
COMMENT ON COLUMN key_packages.key_package_ref IS 'KeyPackage reference for fast lookup (from MLS KeyPackage)';
COMMENT ON COLUMN key_packages.consumed IS 'True if this key package has been used in a Welcome message';
COMMENT ON COLUMN key_packages.expires_at IS 'Expiration timestamp (default: 30 days from creation)';
COMMENT ON TABLE key_packages IS 'MLS KeyPackages for adding members to groups. Max 100 per user.';

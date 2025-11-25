-- =============================================================================
-- Opt-In Table Migration
-- =============================================================================
-- Created: 2025-11-25
-- Description: Private server-side opt-in system for MLS chat
--              Users must explicitly opt in before using MLS features

-- Create opt_in table
CREATE TABLE IF NOT EXISTS opt_in (
    did TEXT PRIMARY KEY,
    opted_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_id TEXT,
    FOREIGN KEY (did) REFERENCES users(did) ON DELETE CASCADE
);

-- Create index for timestamp queries (e.g., recent opt-ins)
CREATE INDEX IF NOT EXISTS idx_opt_in_opted_in_at ON opt_in(opted_in_at DESC);

-- Create index for device_id lookups
CREATE INDEX IF NOT EXISTS idx_opt_in_device_id ON opt_in(device_id) WHERE device_id IS NOT NULL;

COMMENT ON TABLE opt_in IS 'Server-side opt-in tracking for MLS chat. Private data not exposed via public API.';
COMMENT ON COLUMN opt_in.did IS 'User DID who has opted into MLS chat';
COMMENT ON COLUMN opt_in.opted_in_at IS 'Timestamp when the user opted in';
COMMENT ON COLUMN opt_in.device_id IS 'Optional device identifier associated with opt-in';

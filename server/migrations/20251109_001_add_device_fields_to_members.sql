-- Add device fields to members table for multi-device support
-- Created: 2025-11-09
-- Description: Adds user_did, device_id, and device_name columns to members table

BEGIN;

-- Add device fields to members table
ALTER TABLE members
    ADD COLUMN IF NOT EXISTS user_did TEXT,
    ADD COLUMN IF NOT EXISTS device_id TEXT,
    ADD COLUMN IF NOT EXISTS device_name TEXT;

-- Create indexes for device queries
CREATE INDEX IF NOT EXISTS idx_members_user_did
    ON members(user_did)
    WHERE user_did IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_members_device_id
    ON members(device_id)
    WHERE device_id IS NOT NULL;

-- Backfill user_did for existing members (copy from member_did for single-device mode)
UPDATE members
SET user_did = member_did
WHERE user_did IS NULL AND left_at IS NULL;

COMMENT ON COLUMN members.user_did IS 'User DID without device suffix (did:plc:user) - used for UI grouping';
COMMENT ON COLUMN members.device_id IS 'Device UUID from device MLS DID (extracted from did:plc:user#device-uuid)';
COMMENT ON COLUMN members.device_name IS 'Human-readable device name (e.g., "Josh''s iPhone")';

COMMIT;

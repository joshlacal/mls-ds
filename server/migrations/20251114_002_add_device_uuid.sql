-- Migration: Add persistent device_uuid for re-registration detection
-- Adds device_uuid column to track devices across app reinstalls

-- Add device_uuid column to devices table
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS device_uuid TEXT;

-- Create unique constraint for device_uuid per user (allows NULL for backward compat)
-- Note: In PostgreSQL, NULL values are not considered equal, so multiple NULLs are allowed
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_device_uuid
    ON devices(user_did, device_uuid)
    WHERE device_uuid IS NOT NULL;

-- Create index for fast device_uuid lookups
CREATE INDEX IF NOT EXISTS idx_devices_device_uuid
    ON devices(device_uuid)
    WHERE device_uuid IS NOT NULL;

-- Migration complete: Devices table now supports persistent UUIDs for re-registration detection

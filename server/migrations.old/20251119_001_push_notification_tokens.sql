-- Migration: Push Notification Device Tokens
-- Adds device token storage for APNs push notifications

-- Add push token columns to devices table
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS push_token TEXT,
    ADD COLUMN IF NOT EXISTS push_token_updated_at TIMESTAMPTZ;

-- Create index for push token lookups
CREATE INDEX IF NOT EXISTS idx_devices_push_token ON devices(push_token) WHERE push_token IS NOT NULL;

-- Create unique constraint on push_token to ensure one token per device
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_unique_push_token ON devices(push_token) WHERE push_token IS NOT NULL;

-- Migration complete: Database now supports push notification device tokens

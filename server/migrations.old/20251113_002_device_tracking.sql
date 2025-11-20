-- Migration: Device Tracking for Multi-Device MLS Support
-- Adds device registration and tracking for proper multi-device credentials

-- Create devices table to track registered devices per user
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_did TEXT NOT NULL,
    device_id TEXT NOT NULL, -- UUID for this device
    device_name TEXT, -- Human-readable name like "Josh's iPhone"
    credential_did TEXT NOT NULL, -- Full credential: did:plc:user#device-uuid
    signature_public_key TEXT, -- Ed25519 public key (hex-encoded)
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    platform TEXT, -- ios, android, web, desktop
    app_version TEXT,
    UNIQUE(user_did, device_id),
    UNIQUE(credential_did),
    UNIQUE(user_did, signature_public_key)
);

-- Index for looking up devices by user
CREATE INDEX IF NOT EXISTS idx_devices_user_did ON devices(user_did);

-- Index for looking up by credential_did
CREATE INDEX IF NOT EXISTS idx_devices_credential_did ON devices(credential_did);

-- Index for active devices (recently seen)
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(user_did, last_seen_at DESC);

-- Add device_id column to key_packages
ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS device_id TEXT;

-- Add credential_did column to key_packages (full did:plc:user#device-uuid)
ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS credential_did TEXT;

-- Create index for device-specific key package lookups
CREATE INDEX IF NOT EXISTS idx_key_packages_device ON key_packages(device_id) WHERE consumed_at IS NULL;

-- Create index for credential-specific key package lookups
CREATE INDEX IF NOT EXISTS idx_key_packages_credential ON key_packages(credential_did) WHERE consumed_at IS NULL;

-- Add device columns to members table
ALTER TABLE members
    ADD COLUMN IF NOT EXISTS device_id TEXT;

ALTER TABLE members
    ADD COLUMN IF NOT EXISTS device_name TEXT;

ALTER TABLE members
    ADD COLUMN IF NOT EXISTS user_did TEXT;

-- Populate user_did from existing member_did column (strip device suffix if present)
UPDATE members
SET user_did = CASE
    WHEN member_did LIKE '%#%' THEN split_part(member_did, '#', 1)
    ELSE member_did
END
WHERE user_did IS NULL;

-- Create index for user-level membership queries
CREATE INDEX IF NOT EXISTS idx_members_user_did ON members(convo_id, user_did);

-- Create index for device-level membership queries
CREATE INDEX IF NOT EXISTS idx_members_device ON members(convo_id, device_id);

-- Add device info to welcome_messages
ALTER TABLE welcome_messages
    ADD COLUMN IF NOT EXISTS device_id TEXT;

CREATE INDEX IF NOT EXISTS idx_welcome_device ON welcome_messages(recipient_did, device_id) WHERE consumed = false;

-- Migration complete: Database now supports multi-device tracking

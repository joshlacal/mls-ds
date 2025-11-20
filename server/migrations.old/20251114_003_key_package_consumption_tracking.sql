-- Add consumption tracking columns to key_packages table
-- Migration: 20251114_003_key_package_consumption_tracking.sql

ALTER TABLE key_packages
ADD COLUMN consumed_for_convo_id TEXT,
ADD COLUMN consumed_by_device_id TEXT;

-- Add indices for performance on consumption tracking queries
CREATE INDEX idx_key_packages_consumed_for_convo ON key_packages(consumed_for_convo_id) WHERE consumed_for_convo_id IS NOT NULL;
CREATE INDEX idx_key_packages_consumed_by_device ON key_packages(consumed_by_device_id) WHERE consumed_by_device_id IS NOT NULL;

-- Add index for consumption history queries (consumed packages for a user)
CREATE INDEX idx_key_packages_consumed_at ON key_packages(consumed_at) WHERE consumed_at IS NOT NULL;

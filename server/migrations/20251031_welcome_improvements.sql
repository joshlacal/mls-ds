-- Multi-Device Welcome Message Support
-- This migration enables each device to receive its own Welcome message

-- Drop old unique index (too restrictive for multi-device)
DROP INDEX IF EXISTS welcome_messages_unconsumed_unique;

-- Add key_package_hash column for multi-device support
-- Each device uses a different KeyPackage, so we need to track which one this Welcome is for
ALTER TABLE welcome_messages
  ADD COLUMN IF NOT EXISTS key_package_hash BYTEA NULL;

-- NEW unique index: One unconsumed Welcome per (convo, recipient, key_package_hash)
-- This allows multiple devices per user, each with their own Welcome
CREATE UNIQUE INDEX IF NOT EXISTS welcome_messages_unconsumed_per_device
  ON welcome_messages (convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea))
  WHERE consumed = false;

-- Index for efficient multi-device lookups
CREATE INDEX IF NOT EXISTS welcome_messages_kph_idx
  ON welcome_messages (convo_id, recipient_did, key_package_hash);

-- Add comments for documentation
COMMENT ON INDEX welcome_messages_unconsumed_per_device IS 
  'Ensures only one unconsumed Welcome per (convo, recipient, device) - enables multi-device support. Uses COALESCE for NULL key_package_hash backward compatibility.';
COMMENT ON COLUMN welcome_messages.key_package_hash IS 
  'Hash/reference of the KeyPackage used for this Welcome - enables multi-device support. NULL for legacy single-device entries.';


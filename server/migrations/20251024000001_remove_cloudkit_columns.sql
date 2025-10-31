-- Remove CloudKit and external provider columns for text-only v1
-- Migration Date: 2025-10-24

-- Remove CloudKit columns from conversations table
ALTER TABLE conversations DROP COLUMN IF EXISTS cloudkit_zone_id;
ALTER TABLE conversations DROP COLUMN IF EXISTS storage_model;

-- Remove provider columns from envelopes table
ALTER TABLE envelopes DROP COLUMN IF EXISTS mailbox_provider;
ALTER TABLE envelopes DROP COLUMN IF EXISTS cloudkit_zone;

-- Remove provider columns from members table if they exist
ALTER TABLE members DROP COLUMN IF EXISTS mailbox_provider;
ALTER TABLE members DROP COLUMN IF EXISTS mailbox_zone;

-- Drop blobs table entirely (not needed for text-only)
DROP TABLE IF EXISTS blobs CASCADE;

-- Add comment for documentation
COMMENT ON TABLE conversations IS 'MLS conversations with text-only messaging (v1)';
COMMENT ON TABLE envelopes IS 'Message delivery envelopes tracked server-side';
COMMENT ON TABLE messages IS 'Encrypted MLS messages stored in PostgreSQL with 30-day expiry';

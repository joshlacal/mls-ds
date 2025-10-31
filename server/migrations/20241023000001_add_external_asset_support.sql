-- Add ExternalAsset support to messages table for CloudKit architecture
-- Migration for MLS Hybrid Messaging Plan

-- Add ExternalAsset payload columns to messages (replaces direct ciphertext storage)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS payload_provider TEXT NOT NULL CHECK (payload_provider IN ('cloudkit', 'firestore', 'gdrive', 's3', 'custom'));
ALTER TABLE messages ADD COLUMN IF NOT EXISTS payload_uri TEXT NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS payload_mime_type TEXT NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS payload_size BIGINT NOT NULL CHECK (payload_size > 0);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA NOT NULL CHECK (length(payload_sha256) = 32);

-- Add optional content metadata
ALTER TABLE messages ADD COLUMN IF NOT EXISTS content_type TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to TEXT;  -- Message ID for replies

-- Remove old ciphertext column (we're using ExternalAsset from the start)
ALTER TABLE messages DROP COLUMN IF EXISTS ciphertext;

-- Add CloudKit zone tracking to conversations
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS cloudkit_zone_id TEXT;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS storage_model TEXT DEFAULT 'shared-zone' 
    CHECK (storage_model IN ('shared-zone', 'per-user-mailbox'));

-- Add indexes for ExternalAsset queries
CREATE INDEX IF NOT EXISTS idx_messages_payload_provider ON messages(payload_provider) WHERE payload_provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_content_type ON messages(content_type);

-- Add attachments table for ExternalAsset attachment references
CREATE TABLE IF NOT EXISTS message_attachments (
    id TEXT PRIMARY KEY,  -- UUID v4 as string
    message_id TEXT NOT NULL,
    attachment_index INTEGER NOT NULL,
    provider TEXT NOT NULL,
    uri TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size BIGINT NOT NULL,
    sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (message_id, attachment_index),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX idx_message_attachments_message ON message_attachments(message_id);

-- Comments for documentation
COMMENT ON COLUMN messages.payload_provider IS 'Storage provider for message ciphertext (cloudkit, firestore, etc.)';
COMMENT ON COLUMN messages.payload_uri IS 'Provider-specific URI to fetch ciphertext';
COMMENT ON COLUMN messages.payload_sha256 IS 'SHA-256 hash of ciphertext for integrity verification (32 bytes)';
COMMENT ON TABLE message_attachments IS 'ExternalAsset references for message attachments';

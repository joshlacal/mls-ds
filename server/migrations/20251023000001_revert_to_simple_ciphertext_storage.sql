-- Revert messages table to simple ciphertext storage for v1

-- Drop CloudKit/R2 specific tables and indexes
DROP TABLE IF EXISTS message_attachments;
DROP INDEX IF EXISTS idx_messages_payload_provider;
DROP INDEX IF EXISTS idx_messages_content_type;

-- Restore direct ciphertext storage
ALTER TABLE messages
	ADD COLUMN IF NOT EXISTS ciphertext BYTEA;

UPDATE messages SET ciphertext = decode('', 'hex') WHERE ciphertext IS NULL;

ALTER TABLE messages
	ALTER COLUMN ciphertext SET NOT NULL;

-- Rename sent_at to created_at for clarity
ALTER TABLE messages
	RENAME COLUMN sent_at TO created_at;

-- Add sequence number for ordering within a conversation
ALTER TABLE messages
	ADD COLUMN IF NOT EXISTS seq INTEGER;

UPDATE messages
SET seq = COALESCE(seq, 0)
WHERE seq IS NULL;

ALTER TABLE messages
	ALTER COLUMN seq SET NOT NULL;

-- Add 30 day retention metadata
ALTER TABLE messages
	ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

UPDATE messages
SET expires_at = COALESCE(expires_at, created_at + INTERVAL '30 days')
WHERE expires_at IS NULL;

ALTER TABLE messages
	ALTER COLUMN expires_at SET NOT NULL,
	ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '30 days');

-- Optional embed metadata for text-only v1 (nullable by default)
ALTER TABLE messages
	ADD COLUMN IF NOT EXISTS embed_type TEXT,
	ADD COLUMN IF NOT EXISTS embed_uri TEXT;

-- Drop provider-based payload columns
ALTER TABLE messages
	DROP COLUMN IF EXISTS payload_provider,
	DROP COLUMN IF EXISTS payload_uri,
	DROP COLUMN IF EXISTS payload_mime_type,
	DROP COLUMN IF EXISTS payload_size,
	DROP COLUMN IF EXISTS payload_sha256;

-- content_type and reply_to remain useful for plaintext metadata

-- Update indexes for the simplified schema
DROP INDEX IF EXISTS idx_messages_convo_sent;
CREATE INDEX IF NOT EXISTS idx_messages_convo_created ON messages(convo_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_convo_seq ON messages(convo_id, seq);
CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at);

-- Remove legacy metadata tables that relied on external storage
DROP TABLE IF EXISTS message_recipients;


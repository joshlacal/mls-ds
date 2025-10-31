-- Migration: Add message blob storage tables
-- Description: Store encrypted message metadata and R2 blob references
-- Date: 2025-10-23

-- Note: messages table already created in initial migration
-- This migration is kept for reference but skips table creation

-- Table for message recipients (fanout tracking)
CREATE TABLE IF NOT EXISTS message_recipients (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_did TEXT NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT FALSE,
    delivered_at TIMESTAMPTZ,
    
    PRIMARY KEY (message_id, recipient_did)
);

CREATE INDEX IF NOT EXISTS idx_recipients_pending ON message_recipients(recipient_did, delivered) WHERE delivered = FALSE;
CREATE INDEX IF NOT EXISTS idx_recipients_delivered ON message_recipients(delivered_at);

-- Cleanup job: Delete old messages after 30 days
-- This can be run by a background job or cron
-- DELETE FROM messages WHERE created_at < NOW() - INTERVAL '30 days';

-- Notes:
-- 1. Actual encrypted message data is stored in Cloudflare R2, not PostgreSQL
-- 2. PostgreSQL only stores metadata, blob references, and delivery tracking
-- 3. Messages are automatically deleted when a conversation is deleted (ON DELETE CASCADE)
-- 4. Use the blob_key to fetch the actual encrypted bytes from R2

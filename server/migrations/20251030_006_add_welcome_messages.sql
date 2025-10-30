-- Add welcome_messages table for storing Welcome messages
-- This allows members to join MLS groups when syncing conversations

CREATE TABLE IF NOT EXISTS welcome_messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    welcome_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Index for efficient recipient lookup
CREATE INDEX IF NOT EXISTS idx_welcome_messages_recipient ON welcome_messages(recipient_did, consumed);

-- Index for efficient conversation lookup
CREATE INDEX IF NOT EXISTS idx_welcome_messages_convo ON welcome_messages(convo_id);

-- Index for cleanup of old consumed messages
CREATE INDEX IF NOT EXISTS idx_welcome_messages_cleanup ON welcome_messages(consumed_at) WHERE consumed = true;

-- Unique constraint to prevent duplicate unconsumed Welcome messages
CREATE UNIQUE INDEX IF NOT EXISTS idx_welcome_messages_unique ON welcome_messages(convo_id, recipient_did) WHERE consumed = false;

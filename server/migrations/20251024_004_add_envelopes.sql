-- Migration: Add envelopes table for mailbox fanout
-- Description: Track message delivery to mailboxes (CloudKit zones, etc.)
-- Date: 2025-10-24

-- Envelopes table for tracking mailbox delivery
CREATE TABLE IF NOT EXISTS envelopes (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    recipient_did TEXT NOT NULL,
    message_id TEXT NOT NULL,
    mailbox_provider TEXT NOT NULL,
    cloudkit_zone TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    
    UNIQUE (recipient_did, message_id)
);

CREATE INDEX IF NOT EXISTS idx_envelopes_convo ON envelopes(convo_id);
CREATE INDEX IF NOT EXISTS idx_envelopes_recipient ON envelopes(recipient_did);
CREATE INDEX IF NOT EXISTS idx_envelopes_message ON envelopes(message_id);
CREATE INDEX IF NOT EXISTS idx_envelopes_pending ON envelopes(recipient_did) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_envelopes_created ON envelopes(created_at DESC);

-- Add missing columns to conversations if they don't exist
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS cloudkit_zone_id TEXT;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS storage_model TEXT DEFAULT 'database';

-- Add missing columns to members if they don't exist
ALTER TABLE members ADD COLUMN IF NOT EXISTS mailbox_provider TEXT DEFAULT 'cloudkit';
ALTER TABLE members ADD COLUMN IF NOT EXISTS mailbox_zone TEXT;
ALTER TABLE members ADD COLUMN IF NOT EXISTS cursor TEXT;

-- Add cursors table for tracking user read positions
CREATE TABLE IF NOT EXISTS cursors (
    user_did TEXT NOT NULL,
    convo_id TEXT NOT NULL,
    last_seen_cursor TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, convo_id)
);

CREATE INDEX IF NOT EXISTS idx_cursors_user ON cursors(user_did);
CREATE INDEX IF NOT EXISTS idx_cursors_convo ON cursors(convo_id);

-- Add event_stream table for real-time events
CREATE TABLE IF NOT EXISTS event_stream (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    emitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_event_stream_convo ON event_stream(convo_id, id);
CREATE INDEX IF NOT EXISTS idx_event_stream_type ON event_stream(event_type, emitted_at);
CREATE INDEX IF NOT EXISTS idx_event_stream_emitted ON event_stream(emitted_at DESC);

-- Update messages table schema to match new architecture
-- Drop old columns if they exist and add new ones
DO $$
BEGIN
    -- Drop ciphertext if it exists (moving to R2)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'messages' AND column_name = 'ciphertext'
    ) THEN
        ALTER TABLE messages DROP COLUMN ciphertext;
    END IF;
    
    -- Add blob_key if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'messages' AND column_name = 'blob_key'
    ) THEN
        ALTER TABLE messages ADD COLUMN blob_key TEXT;
    END IF;
    
    -- Add metadata if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'messages' AND column_name = 'metadata'
    ) THEN
        ALTER TABLE messages ADD COLUMN metadata JSONB;
    END IF;
    
    -- Rename epoch to created_at if needed
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'messages' AND column_name = 'created_at'
    ) THEN
        ALTER TABLE messages ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
        UPDATE messages SET created_at = sent_at WHERE created_at IS NULL;
    END IF;
END $$;

-- Update conversations columns
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'conversations' AND column_name = 'updated_at'
    ) THEN
        ALTER TABLE conversations ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();
    END IF;
END $$;

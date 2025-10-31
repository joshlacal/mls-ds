-- Create conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title TEXT
);

-- Add index on creator_did for efficient lookup
CREATE INDEX idx_conversations_creator_did ON conversations(creator_did);

-- Add index on created_at for sorting
CREATE INDEX idx_conversations_created_at ON conversations(created_at DESC);

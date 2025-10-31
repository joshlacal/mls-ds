-- Create messages table
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch INTEGER NOT NULL,
    ciphertext BYTEA NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Add index on convo_id and sent_at for efficient message retrieval
CREATE INDEX idx_messages_convo_sent ON messages(convo_id, sent_at DESC);

-- Add index on sender_did for user's message history
CREATE INDEX idx_messages_sender ON messages(sender_did);

-- Add index on epoch for epoch-based queries
CREATE INDEX idx_messages_convo_epoch ON messages(convo_id, epoch);

-- Add compound index for pagination queries
CREATE INDEX idx_messages_pagination ON messages(convo_id, sent_at DESC, id);

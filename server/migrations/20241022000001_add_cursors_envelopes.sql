-- Add cursors table for realtime event streaming
CREATE TABLE IF NOT EXISTS cursors (
    user_did TEXT NOT NULL,
    convo_id TEXT NOT NULL,
    last_seen_cursor TEXT NOT NULL,  -- ULID format
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, convo_id),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Index for efficient cursor queries
CREATE INDEX idx_cursors_updated_at ON cursors(updated_at);
CREATE INDEX idx_cursors_convo ON cursors(convo_id);

-- Add envelopes table for mailbox fan-out
CREATE TABLE IF NOT EXISTS envelopes (
    id TEXT PRIMARY KEY,  -- UUID v4 as string
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    message_id TEXT NOT NULL,
    mailbox_provider TEXT NOT NULL CHECK (mailbox_provider IN ('cloudkit', 'null')),
    cloudkit_zone TEXT,  -- Zone identifier for CloudKit (e.g., 'inbox_{did}')
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    UNIQUE (recipient_did, message_id),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Indexes for efficient envelope queries
CREATE INDEX idx_envelopes_recipient ON envelopes(recipient_did, created_at DESC);
CREATE INDEX idx_envelopes_message ON envelopes(message_id);
CREATE INDEX idx_envelopes_convo ON envelopes(convo_id, created_at DESC);
CREATE INDEX idx_envelopes_delivered ON envelopes(delivered_at) WHERE delivered_at IS NULL;

-- Add mailbox configuration columns to members table
ALTER TABLE members ADD COLUMN IF NOT EXISTS mailbox_provider TEXT NOT NULL DEFAULT 'null' CHECK (mailbox_provider IN ('cloudkit', 'null'));
ALTER TABLE members ADD COLUMN IF NOT EXISTS mailbox_zone TEXT;

-- Index for mailbox provider queries
CREATE INDEX idx_members_mailbox ON members(mailbox_provider) WHERE mailbox_provider != 'null';

-- Add event_stream table for realtime events with 20GB retention policy
CREATE TABLE IF NOT EXISTS event_stream (
    id TEXT PRIMARY KEY,  -- ULID as cursor
    convo_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('messageEvent', 'reactionEvent', 'typingEvent', 'infoEvent')),
    payload JSONB NOT NULL,
    emitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Composite index for efficient cursor-based streaming per (convo, event_type)
CREATE INDEX idx_event_stream_convo_cursor ON event_stream(convo_id, event_type, id);
CREATE INDEX idx_event_stream_emitted ON event_stream(emitted_at);

-- Add reactions table for reaction events
CREATE TABLE IF NOT EXISTS reactions (
    id TEXT PRIMARY KEY,  -- UUID v4 as string
    convo_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    kind TEXT NOT NULL,  -- emoji or reaction type
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (message_id, actor_did, kind),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Index for reaction queries
CREATE INDEX idx_reactions_message ON reactions(message_id, created_at DESC);
CREATE INDEX idx_reactions_actor ON reactions(actor_did);

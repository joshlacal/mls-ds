-- Clean MLS Server Schema
-- Created: 2025-11-01
-- Description: Single migration containing all tables needed by the MLS server

-- =============================================================================
-- Core Tables
-- =============================================================================

-- Conversations (MLS groups)
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    group_id TEXT,
    cipher_suite TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_conversations_creator ON conversations(creator_did);
CREATE INDEX idx_conversations_group_id ON conversations(group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_conversations_updated ON conversations(updated_at DESC);

-- Members (conversation participants)
CREATE TABLE members (
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    unread_count INTEGER NOT NULL DEFAULT 0,
    last_read_at TIMESTAMPTZ,
    needs_rejoin BOOLEAN NOT NULL DEFAULT false,
    rejoin_requested_at TIMESTAMPTZ,
    rejoin_key_package_hash TEXT,
    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_members_member_did ON members(member_did);
CREATE INDEX idx_members_active ON members(member_did, convo_id) WHERE left_at IS NULL;
CREATE INDEX idx_members_unread ON members(member_did, unread_count) WHERE unread_count > 0;
CREATE INDEX idx_members_left_at ON members(left_at) WHERE left_at IS NULL;
CREATE INDEX idx_members_rejoin_pending ON members(convo_id, member_did) WHERE needs_rejoin = true;

-- Messages (encrypted MLS messages)
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch BIGINT NOT NULL DEFAULT 0,
    seq BIGINT NOT NULL DEFAULT 0,
    ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_messages_convo ON messages(convo_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_did);
CREATE INDEX idx_messages_epoch ON messages(convo_id, epoch);
CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

-- Key Packages (pre-keys for adding members)
CREATE TABLE key_packages (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    key_data BYTEA NOT NULL,
    key_package_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    UNIQUE (did, cipher_suite, key_data)
);

CREATE INDEX idx_key_packages_did ON key_packages(did);
CREATE INDEX idx_key_packages_available ON key_packages(did, cipher_suite, expires_at) WHERE consumed = false;
CREATE INDEX idx_key_packages_hash ON key_packages(key_package_hash);
CREATE INDEX idx_key_packages_expires ON key_packages(expires_at);

-- Add function to set default expiry for key packages
CREATE OR REPLACE FUNCTION set_default_key_package_expiry()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.expires_at IS NULL THEN
        NEW.expires_at := NOW() + INTERVAL '30 days';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_set_key_package_expiry
    BEFORE INSERT ON key_packages
    FOR EACH ROW
    EXECUTE FUNCTION set_default_key_package_expiry();

-- =============================================================================
-- MLS Welcome Messages
-- =============================================================================

-- Welcome messages for new members joining groups
CREATE TABLE welcome_messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    welcome_data BYTEA NOT NULL,
    key_package_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_welcome_messages_recipient ON welcome_messages(recipient_did, consumed);
CREATE INDEX idx_welcome_messages_convo ON welcome_messages(convo_id);
CREATE INDEX idx_welcome_messages_hash ON welcome_messages(key_package_hash) WHERE key_package_hash IS NOT NULL;

-- Unique constraint: one unconsumed welcome per (convo, recipient, key_package_hash)
-- This allows multiple devices (different key packages) for same user
CREATE UNIQUE INDEX idx_welcome_messages_unique
ON welcome_messages(convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea))
WHERE consumed = false;

-- =============================================================================
-- Message Delivery & Events
-- =============================================================================

-- Envelopes (message delivery tracking)
CREATE TABLE envelopes (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    message_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    UNIQUE (recipient_did, message_id),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_envelopes_recipient ON envelopes(recipient_did);
CREATE INDEX idx_envelopes_message ON envelopes(message_id);
CREATE INDEX idx_envelopes_convo ON envelopes(convo_id);
CREATE INDEX idx_envelopes_pending ON envelopes(recipient_did) WHERE delivered_at IS NULL;
CREATE INDEX idx_envelopes_created ON envelopes(created_at DESC);

-- Cursors (user read positions)
CREATE TABLE cursors (
    user_did TEXT NOT NULL,
    convo_id TEXT NOT NULL,
    last_seen_cursor TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, convo_id),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_cursors_user ON cursors(user_did);
CREATE INDEX idx_cursors_convo ON cursors(convo_id);
CREATE INDEX idx_cursors_updated ON cursors(updated_at);

-- Event Stream (realtime events)
CREATE TABLE event_stream (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    emitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_event_stream_convo ON event_stream(convo_id, id);
CREATE INDEX idx_event_stream_type ON event_stream(event_type, emitted_at);
CREATE INDEX idx_event_stream_emitted ON event_stream(emitted_at DESC);

-- Message Recipients (delivery tracking per recipient)
CREATE TABLE message_recipients (
    message_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    delivered_at TIMESTAMPTZ,
    PRIMARY KEY (message_id, recipient_did),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX idx_message_recipients_recipient ON message_recipients(recipient_did);
CREATE INDEX idx_message_recipients_delivered ON message_recipients(delivered_at);

-- =============================================================================
-- Future: Blob Storage (R2)
-- =============================================================================

-- Blobs table (for future R2 storage migration)
CREATE TABLE blobs (
    key TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ref_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_blobs_created ON blobs(created_at DESC);
CREATE INDEX idx_blobs_ref_count ON blobs(ref_count) WHERE ref_count = 0;

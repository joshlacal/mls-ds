-- Catbird MLS Server Initial Schema
-- Version: 1.0.0
-- Date: 2025-10-22

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title TEXT
);

CREATE INDEX IF NOT EXISTS idx_conversations_creator_did ON conversations(creator_did);
CREATE INDEX IF NOT EXISTS idx_conversations_created_at ON conversations(created_at DESC);

-- Members table
CREATE TABLE IF NOT EXISTS members (
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    unread_count INTEGER NOT NULL DEFAULT 0,
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_members_member_did ON members(member_did);
CREATE INDEX IF NOT EXISTS idx_members_left_at ON members(left_at) WHERE left_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_members_active ON members(member_did, convo_id) WHERE left_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_members_unread ON members(member_did, unread_count) WHERE unread_count > 0;

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch BIGINT NOT NULL DEFAULT 0,
    seq BIGINT NOT NULL DEFAULT 0,
    ciphertext BYTEA NOT NULL,
    embed_type TEXT,
    embed_uri TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_convo_sent ON messages(convo_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_did);
CREATE INDEX IF NOT EXISTS idx_messages_convo_epoch ON messages(convo_id, epoch);
CREATE INDEX IF NOT EXISTS idx_messages_pagination ON messages(convo_id, created_at DESC, id);

-- Key packages table
CREATE TABLE IF NOT EXISTS key_packages (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    key_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_key_packages_unique ON key_packages(did, cipher_suite, key_data);
CREATE INDEX IF NOT EXISTS idx_key_packages_did_suite ON key_packages(did, cipher_suite);
CREATE INDEX IF NOT EXISTS idx_key_packages_available ON key_packages(did, cipher_suite, expires_at) WHERE consumed = FALSE;
CREATE INDEX IF NOT EXISTS idx_key_packages_expires ON key_packages(expires_at);
CREATE INDEX IF NOT EXISTS idx_key_packages_consumed ON key_packages(consumed, consumed_at);

-- Blobs table
CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    size BIGINT NOT NULL,
    uploaded_by_did TEXT NOT NULL,
    convo_id TEXT,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mime_type TEXT,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_blobs_uploaded_by ON blobs(uploaded_by_did);
CREATE INDEX IF NOT EXISTS idx_blobs_convo ON blobs(convo_id) WHERE convo_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_blobs_uploaded_at ON blobs(uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_blobs_size ON blobs(size);

-- Chat Request Mailbox Migration
-- Routes non-follower messages to request mailbox

-- Status enum
DO $$ BEGIN
    CREATE TYPE chat_request_status AS ENUM ('pending', 'accepted', 'declined', 'blocked', 'expired');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

-- Main requests table
CREATE TABLE IF NOT EXISTS chat_requests (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    status chat_request_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    group_id TEXT,
    is_group_invite BOOLEAN NOT NULL DEFAULT false,
    accepted_convo_id TEXT,
    accepted_at TIMESTAMPTZ,
    declined_at TIMESTAMPTZ,
    blocked_at TIMESTAMPTZ,
    FOREIGN KEY (sender_did) REFERENCES users(did) ON DELETE CASCADE,
    FOREIGN KEY (recipient_did) REFERENCES users(did) ON DELETE CASCADE
);

-- Held messages (HPKE encrypted)
CREATE TABLE IF NOT EXISTS held_messages (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    request_id TEXT NOT NULL REFERENCES chat_requests(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    eph_pub_key BYTEA NOT NULL,
    sequence INTEGER NOT NULL,
    padded_size INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT max_5_held CHECK (sequence <= 5)
);

-- Rate limits
CREATE TABLE IF NOT EXISTS chat_request_rate_limits (
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    requests_last_day INTEGER NOT NULL DEFAULT 0,
    last_request_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (sender_did, recipient_did)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_requests_recipient_pending ON chat_requests(recipient_did, created_at DESC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_requests_expires ON chat_requests(expires_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_held_messages_request ON held_messages(request_id, sequence);

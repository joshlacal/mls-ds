-- =============================================================================
-- Chat Request System Migration
-- =============================================================================
-- Created: 2025-12-10
-- Description: Implements chat request system for E2EE MLS group chats
--              Allows users to send chat requests that hold encrypted messages
--              until accepted, with rate limiting and expiration

-- =============================================================================
-- Chat Request Status Enum
-- =============================================================================

CREATE TYPE chat_request_status AS ENUM (
    'pending',
    'accepted',
    'declined',
    'blocked',
    'expired'
);

COMMENT ON TYPE chat_request_status IS 'Status of a chat request';

-- =============================================================================
-- Chat Requests Table
-- =============================================================================

CREATE TABLE chat_requests (
    id TEXT PRIMARY KEY,  -- ULID for sortable unique IDs
    sender_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    recipient_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    status chat_request_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,  -- Typically created_at + 7 days
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Group invite fields
    is_group_invite BOOLEAN NOT NULL DEFAULT FALSE,
    group_id TEXT,  -- References conversations(id) if group invite
    
    -- Held message metadata (for first message in request)
    held_message_count INTEGER NOT NULL DEFAULT 0,
    first_message_preview TEXT,  -- Optional preview text (client-provided, not E2EE)
    
    -- Acceptance tracking
    accepted_at TIMESTAMPTZ,
    accepted_convo_id TEXT,  -- References conversations(id) after acceptance
    
    -- Blocking and rate limiting
    blocked_at TIMESTAMPTZ,
    blocked_reason TEXT,
    
    CONSTRAINT chat_requests_group_invite_check 
        CHECK (NOT is_group_invite OR group_id IS NOT NULL),
    CONSTRAINT chat_requests_accepted_convo_check
        CHECK (status != 'accepted' OR accepted_convo_id IS NOT NULL),
    CONSTRAINT chat_requests_blocked_check
        CHECK (status != 'blocked' OR blocked_at IS NOT NULL)
);

-- Indexes for chat_requests
CREATE INDEX idx_chat_requests_recipient_status ON chat_requests(recipient_did, status) 
    WHERE status = 'pending';
CREATE INDEX idx_chat_requests_sender ON chat_requests(sender_did);
CREATE INDEX idx_chat_requests_expires_at ON chat_requests(expires_at) 
    WHERE status = 'pending';
CREATE INDEX idx_chat_requests_accepted_convo ON chat_requests(accepted_convo_id) 
    WHERE accepted_convo_id IS NOT NULL;
CREATE UNIQUE INDEX idx_chat_requests_sender_recipient_active ON chat_requests(sender_did, recipient_did)
    WHERE status = 'pending';

COMMENT ON TABLE chat_requests IS 'Chat request system for E2EE group chats with message holding';
COMMENT ON COLUMN chat_requests.id IS 'ULID for sortable unique identifiers';
COMMENT ON COLUMN chat_requests.held_message_count IS 'Number of encrypted messages held pending acceptance';
COMMENT ON COLUMN chat_requests.first_message_preview IS 'Optional client-provided preview (not E2EE)';
COMMENT ON COLUMN chat_requests.accepted_convo_id IS 'Conversation ID created upon acceptance';

-- =============================================================================
-- Held Messages Table
-- =============================================================================

CREATE TABLE held_messages (
    id TEXT PRIMARY KEY,  -- ULID
    request_id TEXT NOT NULL REFERENCES chat_requests(id) ON DELETE CASCADE,
    
    -- MLS ciphertext
    ciphertext BYTEA NOT NULL,
    
    -- Ephemeral key material for forward secrecy
    eph_pub_key BYTEA,  -- Optional ephemeral public key
    
    -- Ordering and metadata
    sequence INTEGER NOT NULL,  -- Order within the request (0, 1, 2, ...)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Privacy: padded message size for traffic analysis resistance
    padded_size INTEGER NOT NULL,
    
    CONSTRAINT held_messages_sequence_check CHECK (sequence >= 0)
);

-- Indexes for held_messages
CREATE INDEX idx_held_messages_request_id ON held_messages(request_id, sequence);
CREATE UNIQUE INDEX idx_held_messages_request_sequence ON held_messages(request_id, sequence);

COMMENT ON TABLE held_messages IS 'Encrypted messages held pending chat request acceptance';
COMMENT ON COLUMN held_messages.ciphertext IS 'MLS encrypted message data';
COMMENT ON COLUMN held_messages.eph_pub_key IS 'Ephemeral public key for forward secrecy';
COMMENT ON COLUMN held_messages.sequence IS 'Message order within request (0-indexed)';
COMMENT ON COLUMN held_messages.padded_size IS 'Padded size for traffic analysis resistance';

-- =============================================================================
-- Chat Request Rate Limits Table
-- =============================================================================

CREATE TABLE chat_request_rate_limits (
    sender_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    recipient_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    
    -- Rate limiting counters
    request_count INTEGER NOT NULL DEFAULT 1,
    last_request_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Time windows for rate limiting
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Block tracking
    blocked_until TIMESTAMPTZ,
    block_count INTEGER NOT NULL DEFAULT 0,
    
    PRIMARY KEY (sender_did, recipient_did)
);

-- Indexes for rate_limits
CREATE INDEX idx_chat_request_rate_limits_sender ON chat_request_rate_limits(sender_did);
CREATE INDEX idx_chat_request_rate_limits_blocked ON chat_request_rate_limits(blocked_until)
    WHERE blocked_until IS NOT NULL;

COMMENT ON TABLE chat_request_rate_limits IS 'Rate limiting for chat requests to prevent spam';
COMMENT ON COLUMN chat_request_rate_limits.request_count IS 'Number of requests in current window';
COMMENT ON COLUMN chat_request_rate_limits.window_start IS 'Start of current rate limit window';
COMMENT ON COLUMN chat_request_rate_limits.blocked_until IS 'Temporary block expiration time';
COMMENT ON COLUMN chat_request_rate_limits.block_count IS 'Number of times sender has been blocked';

-- =============================================================================
-- Functions and Triggers
-- =============================================================================

-- Update updated_at timestamp on chat_requests
CREATE OR REPLACE FUNCTION update_chat_requests_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER chat_requests_updated_at
    BEFORE UPDATE ON chat_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_chat_requests_updated_at();

-- Expire old pending chat requests (should be run periodically)
CREATE OR REPLACE FUNCTION expire_old_chat_requests()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE chat_requests
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'pending' AND expires_at < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION expire_old_chat_requests IS 'Expires pending chat requests past their expiration time';

-- =============================================================================
-- Grant Permissions
-- =============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON chat_requests TO catbird;
GRANT SELECT, INSERT, UPDATE, DELETE ON held_messages TO catbird;
GRANT SELECT, INSERT, UPDATE, DELETE ON chat_request_rate_limits TO catbird;

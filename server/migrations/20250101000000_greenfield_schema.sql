-- =============================================================================
-- MLS Server - Greenfield Database Schema
-- =============================================================================
-- Created: 2025-11-08
-- Description: Complete production-ready schema for MLS E2EE group chat
--              Built correctly from day 1 with no legacy compatibility concerns

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE catbird TO catbird;

-- =============================================================================
-- Users Table (minimal - AT Protocol identity)
-- =============================================================================

-- Users table (just for FK constraints - full profile data lives in ATProto)
CREATE TABLE users (
    did TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

CREATE INDEX idx_users_last_seen ON users(last_seen_at DESC);

COMMENT ON TABLE users IS 'Minimal user table - full identity/profile data lives in AT Protocol';

-- =============================================================================
-- Core Tables
-- =============================================================================

-- Conversations (MLS groups)
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    description TEXT,
    group_id TEXT,
    cipher_suite TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    idempotency_key TEXT UNIQUE,
    -- GroupInfo caching for external commit joins
    group_info BYTEA,
    group_info_updated_at TIMESTAMPTZ,
    group_info_epoch INTEGER
);

CREATE INDEX idx_conversations_creator ON conversations(creator_did);
CREATE INDEX idx_conversations_group_id ON conversations(group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_conversations_updated ON conversations(updated_at DESC);
CREATE INDEX idx_conversations_group_info_updated ON conversations(id, group_info_updated_at DESC) WHERE group_info IS NOT NULL;

COMMENT ON TABLE conversations IS 'MLS group conversations with E2EE support';
COMMENT ON COLUMN conversations.cipher_suite IS 'MLS cipher suite (e.g., MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)';
COMMENT ON COLUMN conversations.current_epoch IS 'Current MLS epoch number, increments with each group state change';
COMMENT ON COLUMN conversations.group_info IS 'Cached MLS GroupInfo object for external commit joins. Updated after each epoch change.';
COMMENT ON COLUMN conversations.group_info_updated_at IS 'Timestamp when the GroupInfo was last updated. Used to determine freshness (5 minute TTL).';
COMMENT ON COLUMN conversations.group_info_epoch IS 'The epoch number corresponding to the cached GroupInfo object.';

-- Members (conversation participants with admin support)
CREATE TABLE members (
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,

    -- Multi-device support (device-specific MLS identity)
    user_did TEXT,
    device_id TEXT,
    device_name TEXT,

    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    leaf_index INTEGER,

    -- Admin fields (greenfield - built in from day 1)
    is_admin BOOLEAN NOT NULL DEFAULT false,
    promoted_at TIMESTAMPTZ,
    promoted_by_did TEXT,

    -- Rejoin support
    needs_rejoin BOOLEAN NOT NULL DEFAULT false,
    rejoin_requested_at TIMESTAMPTZ,
    rejoin_key_package_hash TEXT,
    rejoin_auto_approved BOOLEAN,

    -- Read tracking
    unread_count INTEGER NOT NULL DEFAULT 0,
    last_read_at TIMESTAMPTZ,

    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_members_member_did ON members(member_did);
CREATE INDEX idx_members_active ON members(member_did, convo_id) WHERE left_at IS NULL;
CREATE INDEX idx_members_admins ON members(convo_id, member_did) WHERE is_admin = true AND left_at IS NULL;
CREATE INDEX idx_members_unread ON members(member_did, unread_count) WHERE unread_count > 0;
CREATE INDEX idx_members_rejoin_pending ON members(convo_id, member_did) WHERE needs_rejoin = true;

COMMENT ON TABLE members IS 'Conversation membership with admin privileges and rejoin support';
COMMENT ON COLUMN members.member_did IS 'Device-specific MLS DID (e.g., did:plc:abc123#device-xyz) - each device has unique MLS identity';
COMMENT ON COLUMN members.user_did IS 'Base user DID without device suffix (e.g., did:plc:abc123) - links devices to same user';
COMMENT ON COLUMN members.device_id IS 'Device identifier extracted from member_did fragment (e.g., "device-xyz")';
COMMENT ON COLUMN members.device_name IS 'Human-readable device name (e.g., "iPhone 15 Pro", "MacBook Air") for UI display';
COMMENT ON COLUMN members.is_admin IS 'Whether this member has admin privileges (encrypted roster distributed via MLS)';
COMMENT ON COLUMN members.promoted_at IS 'When member was promoted to admin (NULL if creator or not admin)';
COMMENT ON COLUMN members.promoted_by_did IS 'DID of admin who promoted this member (NULL if creator or not admin)';
COMMENT ON COLUMN members.needs_rejoin IS 'True if member deleted app and needs automatic Welcome delivery';
COMMENT ON COLUMN members.leaf_index IS 'MLS leaf index in ratchet tree (NULL if not yet joined group state)';

-- Messages (encrypted MLS messages with privacy metadata)
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT,
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch BIGINT NOT NULL DEFAULT 0,
    seq BIGINT NOT NULL DEFAULT 0,
    ciphertext BYTEA,

    -- Privacy-enhancing metadata
    msg_id TEXT,
    padded_size INTEGER,
    received_bucket_ts BIGINT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    -- Idempotency
    idempotency_key TEXT,

    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_messages_convo ON messages(convo_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_did);
CREATE INDEX idx_messages_epoch ON messages(convo_id, epoch);
CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_messages_bucket_ts ON messages(convo_id, received_bucket_ts DESC) WHERE received_bucket_ts IS NOT NULL;

-- Deduplication indices
CREATE UNIQUE INDEX idx_messages_msg_id_dedup ON messages(convo_id, msg_id) WHERE msg_id IS NOT NULL;
CREATE INDEX idx_messages_msg_id ON messages(msg_id) WHERE msg_id IS NOT NULL;
CREATE UNIQUE INDEX idx_messages_idempotency_key ON messages(idempotency_key) WHERE idempotency_key IS NOT NULL;

COMMENT ON TABLE messages IS 'Encrypted MLS messages with metadata privacy features';
COMMENT ON COLUMN messages.sender_did IS 'Verified sender DID from JWT (server-provided, NEVER trust client input)';
COMMENT ON COLUMN messages.msg_id IS 'Client-generated ULID for deduplication. MUST be included in MLS message AAD.';
COMMENT ON COLUMN messages.padded_size IS 'Padded ciphertext size. Must be 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB. Original size encrypted inside MLS ciphertext for privacy.';
COMMENT ON COLUMN messages.received_bucket_ts IS 'Unix timestamp quantized to 2-second buckets for traffic analysis resistance';

-- =============================================================================
-- KeyPackage Management (for adding members and automatic rejoin)
-- =============================================================================

-- Key Packages (pre-keys for adding members to groups)
CREATE TABLE key_packages (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    device_id TEXT,
    credential_did TEXT,
    cipher_suite TEXT NOT NULL,
    key_package BYTEA NOT NULL,
    key_package_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
    consumed_at TIMESTAMPTZ,
    consumed_by_convo TEXT,
    consumed_for_convo_id TEXT,
    consumed_by_device_id TEXT,
    reserved_at TIMESTAMPTZ,
    reserved_by_convo TEXT,
    FOREIGN KEY (owner_did) REFERENCES users(did) ON DELETE CASCADE
);

CREATE INDEX idx_key_packages_owner ON key_packages(owner_did);
CREATE INDEX idx_key_packages_available ON key_packages(owner_did, cipher_suite, expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_key_packages_hash ON key_packages(key_package_hash);
CREATE INDEX idx_key_packages_expires ON key_packages(expires_at);

-- Consumption tracking indices (for stats and rate calculations)
CREATE INDEX idx_key_packages_consumed_at ON key_packages(owner_did, consumed_at DESC) WHERE consumed_at IS NOT NULL;
CREATE INDEX idx_key_packages_hash_lookup ON key_packages(owner_did, key_package_hash) WHERE consumed_at IS NULL;

COMMENT ON TABLE key_packages IS 'Pool of MLS KeyPackages for adding members and automatic rejoin';
COMMENT ON COLUMN key_packages.consumed_at IS 'NULL = available, NOT NULL = already used';
COMMENT ON COLUMN key_packages.consumed_by_convo IS 'Which conversation consumed this KeyPackage';

-- =============================================================================
-- Welcome Messages (for joining/rejoining groups)
-- =============================================================================

-- Welcome messages for new members or automatic rejoin
CREATE TABLE welcome_messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    welcome_data BYTEA NOT NULL,
    key_package_hash BYTEA,
    created_by_did TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_welcome_messages_recipient ON welcome_messages(recipient_did, consumed);
CREATE INDEX idx_welcome_messages_convo ON welcome_messages(convo_id);

-- =============================================================================
-- Rejoin Requests (auto-rejoin audit trail)
-- =============================================================================

CREATE TABLE rejoin_requests (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    auto_approved BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rejoin_requests_convo ON rejoin_requests(convo_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rejoin_requests_member ON rejoin_requests(member_did, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rejoin_requests_auto_approved ON rejoin_requests(auto_approved, requested_at DESC);

COMMENT ON TABLE rejoin_requests IS 'Audit trail for automatic rejoin approvals';
CREATE INDEX idx_welcome_messages_hash ON welcome_messages(key_package_hash) WHERE key_package_hash IS NOT NULL;

-- One unconsumed welcome per (convo, recipient, key_package_hash)
CREATE UNIQUE INDEX idx_welcome_messages_unique
ON welcome_messages(convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea))
WHERE consumed = false;

COMMENT ON TABLE welcome_messages IS 'MLS Welcome messages for joining or automatic rejoin after app deletion';
COMMENT ON COLUMN welcome_messages.created_by_did IS 'DID of member who generated this Welcome (for automatic rejoin)';

-- Pending automatic rejoin requests (server-orchestrated)
CREATE TABLE pending_welcomes (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    target_did TEXT NOT NULL,
    welcome_message BYTEA,
    commit_message BYTEA,
    created_by_did TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_pending_welcomes_target ON pending_welcomes(target_did) WHERE consumed_at IS NULL;
CREATE INDEX idx_pending_welcomes_convo ON pending_welcomes(convo_id) WHERE consumed_at IS NULL;

COMMENT ON TABLE pending_welcomes IS 'Server-orchestrated Welcome delivery for automatic rejoin (2-5 second flow)';
COMMENT ON COLUMN pending_welcomes.target_did IS 'DID of member who needs to rejoin (lost MLS state but still in DB)';
COMMENT ON COLUMN pending_welcomes.created_by_did IS 'DID of any online member who generated the Welcome';

-- =============================================================================
-- Admin & Moderation System (E2EE)
-- =============================================================================

-- E2EE Reports (encrypted content, only admins can decrypt)
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    reporter_did TEXT NOT NULL,
    reported_did TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN (
        'harassment',
        'spam',
        'hate_speech',
        'violence',
        'sexual_content',
        'impersonation',
        'privacy_violation',
        'other'
    )),
    encrypted_content BYTEA NOT NULL,
    message_ids TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'resolved', 'dismissed')),
    resolved_by_did TEXT,
    resolved_at TIMESTAMPTZ,
    resolution_action TEXT
        CHECK (resolution_action IN ('removed_member', 'dismissed', 'no_action')),
    resolution_notes TEXT,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_reports_convo ON reports(convo_id);
CREATE INDEX idx_reports_reporter ON reports(reporter_did);
CREATE INDEX idx_reports_reported ON reports(reported_did);
CREATE INDEX idx_reports_status ON reports(status, created_at DESC);
CREATE INDEX idx_reports_category ON reports(category);

COMMENT ON TABLE reports IS 'E2EE member reports - content encrypted with MLS group key, only admins decrypt';
COMMENT ON COLUMN reports.category IS 'Report category: harassment, spam, hate_speech, violence, sexual_content, impersonation, privacy_violation, other';
COMMENT ON COLUMN reports.encrypted_content IS 'Encrypted report details (reason, evidence) - uses MLS group key (max 50KB)';
COMMENT ON COLUMN reports.message_ids IS 'Array of message IDs referenced in report (max 20)';
COMMENT ON COLUMN reports.resolution_action IS 'Action taken: removed_member, dismissed, or no_action';
COMMENT ON COLUMN reports.resolution_notes IS 'Admin notes on resolution (max 1000 chars enforced by application)';

-- Admin Actions Audit Log (immutable record of admin operations)
CREATE TABLE admin_actions (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('promote', 'demote', 'remove')),
    target_did TEXT,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_admin_actions_convo ON admin_actions(convo_id, created_at DESC);
CREATE INDEX idx_admin_actions_actor ON admin_actions(actor_did, created_at DESC);
CREATE INDEX idx_admin_actions_target ON admin_actions(target_did) WHERE target_did IS NOT NULL;

COMMENT ON TABLE admin_actions IS 'Immutable audit log of all admin actions';
COMMENT ON COLUMN admin_actions.actor_did IS 'DID of admin who performed the action';
COMMENT ON COLUMN admin_actions.action IS 'Type of action: promote, demote, or remove';
COMMENT ON COLUMN admin_actions.target_did IS 'DID of member affected by the action';
COMMENT ON COLUMN admin_actions.reason IS 'Optional justification for the action';

-- Bluesky Blocks (synced from AT Protocol)
CREATE TABLE bsky_blocks (
    user_did TEXT NOT NULL,
    target_did TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'bsky',
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, target_did)
);

CREATE INDEX idx_bsky_blocks_user ON bsky_blocks(user_did);
CREATE INDEX idx_bsky_blocks_target ON bsky_blocks(target_did);

COMMENT ON TABLE bsky_blocks IS 'Bluesky block relationships synced from AT Protocol';
COMMENT ON COLUMN bsky_blocks.user_did IS 'DID of user who blocked (blocker)';
COMMENT ON COLUMN bsky_blocks.target_did IS 'DID of user who was blocked';
COMMENT ON COLUMN bsky_blocks.source IS 'Source of block: bsky (synced from Bluesky) or manual';
COMMENT ON COLUMN bsky_blocks.synced_at IS 'When this block was last synced from Bluesky';

-- =============================================================================
-- Message Delivery & Events
-- =============================================================================

-- Envelopes (message delivery tracking per recipient)
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

COMMENT ON TABLE envelopes IS 'Message delivery tracking - server knows recipients from members table, not from ciphertext';

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

-- Event Stream (realtime events via SSE)
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

COMMENT ON TABLE event_stream IS 'Realtime event stream for SSE (Server-Sent Events) delivery';

-- Message Recipients (delivery tracking)
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
-- Idempotency Support
-- =============================================================================

-- Idempotency Cache (for API operation deduplication)
CREATE TABLE idempotency_cache (
    key TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    response_body JSONB NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_idempotency_cache_expires ON idempotency_cache(expires_at);
CREATE INDEX idx_idempotency_cache_endpoint ON idempotency_cache(endpoint, created_at DESC);

COMMENT ON TABLE idempotency_cache IS 'Cache for idempotent API operations (24 hour retention)';

-- Cleanup function for expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_idempotency_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    batch_deleted INTEGER;
    batch_limit INTEGER := 5000;
    batch_sleep_seconds DOUBLE PRECISION := 0.02;
BEGIN
    deleted_count := 0;

    LOOP
        WITH deleted AS (
            DELETE FROM idempotency_cache
            WHERE ctid IN (
                SELECT ctid
                FROM idempotency_cache
                WHERE expires_at < NOW()
                LIMIT batch_limit
            )
            RETURNING 1
        )
        SELECT COUNT(*) INTO batch_deleted FROM deleted;

        EXIT WHEN batch_deleted = 0;
        deleted_count := deleted_count + batch_deleted;

        PERFORM pg_sleep(batch_sleep_seconds);
    END LOOP;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Future: Blob Storage (Cloudflare R2)
-- =============================================================================

-- Blobs table (for future encrypted attachment storage)
CREATE TABLE blobs (
    key TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ref_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_blobs_created ON blobs(created_at DESC);
CREATE INDEX idx_blobs_ref_count ON blobs(ref_count) WHERE ref_count = 0;

COMMENT ON TABLE blobs IS 'Future: Encrypted attachment storage on Cloudflare R2';

-- =============================================================================
-- Maintenance Functions
-- =============================================================================

-- Function to update conversation updated_at timestamp
CREATE OR REPLACE FUNCTION update_conversation_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE conversations
    SET updated_at = NOW()
    WHERE id = NEW.convo_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update conversation timestamp on new messages
CREATE TRIGGER trigger_update_conversation_timestamp
    AFTER INSERT ON messages
    FOR EACH ROW
    EXECUTE FUNCTION update_conversation_timestamp();

-- Function to auto-promote conversation creator to admin
CREATE OR REPLACE FUNCTION promote_creator_to_admin()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE members
    SET is_admin = true
    WHERE convo_id = NEW.id
      AND member_did = NEW.creator_did;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-promote creator when conversation is created
CREATE TRIGGER trigger_promote_creator
    AFTER INSERT ON conversations
    FOR EACH ROW
    EXECUTE FUNCTION promote_creator_to_admin();

-- =============================================================================
-- SQLx Migrations Table (for compatibility)
-- =============================================================================

CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);

-- =============================================================================
-- Schema Version & Metadata
-- =============================================================================

CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_version (version, description)
VALUES (1, 'Greenfield schema - complete MLS E2EE group chat with admin system');

COMMENT ON TABLE schema_version IS 'Database schema version tracking';


-- =============================================================================
-- Device Registry
-- =============================================================================

-- Devices table for multi-device support
CREATE TABLE devices (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT,
    credential_did TEXT NOT NULL,
    signature_public_key TEXT,
    device_uuid TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    platform TEXT,
    app_version TEXT,
    push_token TEXT,
    push_token_updated_at TIMESTAMPTZ,
    UNIQUE(user_did, device_id),
    UNIQUE(credential_did),
    UNIQUE(user_did, signature_public_key),
    FOREIGN KEY (user_did) REFERENCES users(did) ON DELETE CASCADE
);

CREATE INDEX idx_devices_user_did ON devices(user_did);
CREATE INDEX idx_devices_credential_did ON devices(credential_did);
CREATE INDEX idx_devices_active ON devices(user_did, last_seen_at DESC);
CREATE INDEX idx_devices_device_uuid ON devices(device_uuid) WHERE device_uuid IS NOT NULL;

COMMENT ON TABLE devices IS 'Multi-device registry tracking all devices per user';
COMMENT ON COLUMN devices.user_did IS 'User DID (did:plc:user)';
COMMENT ON COLUMN devices.device_id IS 'Unique device identifier (UUID)';
COMMENT ON COLUMN devices.credential_did IS 'Device-specific MLS DID (did:plc:user#device-uuid)';
COMMENT ON COLUMN devices.device_name IS 'Human-readable device name (e.g., "Josh''s iPhone")';
COMMENT ON COLUMN devices.signature_public_key IS 'Device signature public key for identity verification';
COMMENT ON COLUMN devices.device_uuid IS 'Optional vendor device UUID (e.g., iOS identifierForVendor)';
COMMENT ON COLUMN devices.push_token IS 'APNs device token (hex-encoded) for push notifications';
COMMENT ON COLUMN devices.push_token_updated_at IS 'Timestamp when push_token was last updated';

-- =============================================================================
-- Admin & Invite System (Policy + Invites + Rejoin PSK)
-- =============================================================================

-- Conversation Policy (per-group settings for external commits, invites, rejoin)
CREATE TABLE IF NOT EXISTS conversation_policy (
    convo_id TEXT PRIMARY KEY,

    -- External commit controls
    allow_external_commits BOOLEAN NOT NULL DEFAULT true,
    require_invite_for_join BOOLEAN NOT NULL DEFAULT false,

    -- Rejoin controls
    allow_rejoin BOOLEAN NOT NULL DEFAULT true,
    rejoin_window_days INTEGER NOT NULL DEFAULT 30,

    -- Admin controls
    prevent_removing_last_admin BOOLEAN NOT NULL DEFAULT true,

    -- Audit trail
    created_by_did TEXT NOT NULL,
    updated_by_did TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,

    CHECK (rejoin_window_days >= 0)
);

CREATE INDEX IF NOT EXISTS idx_conversation_policy_external_commits
    ON conversation_policy(allow_external_commits);

CREATE INDEX IF NOT EXISTS idx_conversation_policy_updated
    ON conversation_policy(updated_at DESC);

COMMENT ON TABLE conversation_policy IS 'Per-conversation policies for external commits, invites, and rejoin';
COMMENT ON COLUMN conversation_policy.allow_external_commits IS 'Master switch - if false, ALL external commits rejected regardless of other settings';
COMMENT ON COLUMN conversation_policy.require_invite_for_join IS 'If true, external commits from non-members require valid invite PSK';
COMMENT ON COLUMN conversation_policy.allow_rejoin IS 'If true, former members can rejoin via external commit with rejoin PSK';
COMMENT ON COLUMN conversation_policy.rejoin_window_days IS 'Days after leaving that rejoin is allowed (0 = unlimited)';

-- Invites Table (invite links with PSK authentication)
CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,

    -- Creator and target
    created_by_did TEXT NOT NULL,
    target_did TEXT,  -- NULL = open invite (anyone can use), specific DID = targeted invite

    -- PSK authentication (server stores hash only, never plaintext)
    psk_hash TEXT NOT NULL,  -- SHA256(PSK) in hex format (64 characters)

    -- Timing and usage
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,  -- NULL = never expires
    max_uses INTEGER,        -- NULL = unlimited uses, 1 = single-use, N = N uses allowed
    uses_count INTEGER NOT NULL DEFAULT 0,

    -- Revocation
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revoked_by_did TEXT,

    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,

    CHECK (max_uses IS NULL OR max_uses > 0),
    CHECK (uses_count >= 0),
    CHECK (max_uses IS NULL OR uses_count <= max_uses),
    CHECK (LENGTH(psk_hash) = 64),
    CHECK (psk_hash ~ '^[0-9a-f]+$'),
    CHECK (NOT revoked OR (revoked AND revoked_at IS NOT NULL AND revoked_by_did IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_invites_convo ON invites(convo_id);
CREATE INDEX IF NOT EXISTS idx_invites_target ON invites(target_did) WHERE target_did IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invites_psk_hash ON invites(psk_hash);

CREATE INDEX IF NOT EXISTS idx_invites_active ON invites(convo_id, expires_at)
    WHERE revoked = false
      AND (max_uses IS NULL OR uses_count < max_uses);

COMMENT ON TABLE invites IS 'Invite links for joining groups via external commit + PSK proof';
COMMENT ON COLUMN invites.psk_hash IS 'SHA256 hash of invite PSK - server stores hash only, client provides plaintext PSK in external commit';
COMMENT ON COLUMN invites.target_did IS 'If set, invite only valid for this specific DID (NULL = open invite)';

-- Rejoin PSK Hash column for members (database compromise protection)
ALTER TABLE members ADD COLUMN IF NOT EXISTS rejoin_psk_hash TEXT;

ALTER TABLE members ADD CONSTRAINT check_rejoin_psk_hash_format
    CHECK (rejoin_psk_hash IS NULL OR (
        LENGTH(rejoin_psk_hash) = 64 AND
        rejoin_psk_hash ~ '^[0-9a-f]+$'
    ));

CREATE INDEX IF NOT EXISTS idx_members_rejoin_psk ON members(rejoin_psk_hash)
    WHERE rejoin_psk_hash IS NOT NULL;

COMMENT ON COLUMN members.rejoin_psk_hash IS 'SHA256 hash of rejoin PSK - proves "I was a member" for database compromise protection';

-- Rejoin Requests Audit Table
CREATE TABLE IF NOT EXISTS rejoin_requests (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    auto_approved BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rejoin_requests_convo ON rejoin_requests(convo_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rejoin_requests_member ON rejoin_requests(member_did, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rejoin_requests_auto_approved ON rejoin_requests(auto_approved, requested_at DESC);

COMMENT ON TABLE rejoin_requests IS 'Audit trail for automatic rejoin approvals';

-- Trigger: Auto-create default policy when conversation is created
CREATE OR REPLACE FUNCTION create_default_policy()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO conversation_policy (
        convo_id,
        allow_external_commits,
        require_invite_for_join,
        allow_rejoin,
        rejoin_window_days,
        prevent_removing_last_admin,
        created_by_did
    ) VALUES (
        NEW.id,
        true,
        false,
        true,
        30,
        true,
        NEW.creator_did
    )
    ON CONFLICT (convo_id) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_create_default_policy
    AFTER INSERT ON conversations
    FOR EACH ROW
    EXECUTE FUNCTION create_default_policy();

-- Trigger: Prevent demoting last admin
CREATE OR REPLACE FUNCTION check_last_admin()
RETURNS TRIGGER AS $$
DECLARE
    remaining_admins INTEGER;
    policy_enforces_last_admin BOOLEAN;
BEGIN
    IF OLD.is_admin = true AND NEW.is_admin = false THEN
        SELECT prevent_removing_last_admin INTO policy_enforces_last_admin
        FROM conversation_policy
        WHERE convo_id = NEW.convo_id;

        IF policy_enforces_last_admin THEN
            SELECT COUNT(*) INTO remaining_admins
            FROM members
            WHERE convo_id = NEW.convo_id
              AND is_admin = true
              AND left_at IS NULL
              AND member_did != NEW.member_did;

            IF remaining_admins = 0 THEN
                RAISE EXCEPTION 'Cannot demote last admin in conversation. Promote another member to admin first.';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_check_last_admin
    BEFORE UPDATE ON members
    FOR EACH ROW
    EXECUTE FUNCTION check_last_admin();

-- Helper Views
CREATE OR REPLACE VIEW active_invites AS
SELECT
    i.id,
    i.convo_id,
    i.created_by_did,
    i.target_did,
    i.created_at,
    i.expires_at,
    i.max_uses,
    i.uses_count,
    CASE
        WHEN i.max_uses IS NOT NULL THEN i.max_uses - i.uses_count
        ELSE NULL
    END as remaining_uses,
    c.name as conversation_name
FROM invites i
JOIN conversations c ON i.convo_id = c.id
WHERE i.revoked = false
  AND (i.expires_at IS NULL OR i.expires_at > NOW())
  AND (i.max_uses IS NULL OR i.uses_count < i.max_uses);

COMMENT ON VIEW active_invites IS 'Shows all currently usable invites with remaining uses';

CREATE OR REPLACE VIEW conversation_policy_summary AS
SELECT
    c.id as convo_id,
    c.name as conversation_name,
    c.creator_did,
    p.allow_external_commits,
    p.require_invite_for_join,
    p.allow_rejoin,
    p.rejoin_window_days,
    p.prevent_removing_last_admin,
    p.updated_at as policy_updated_at,
    COUNT(DISTINCT m.member_did) FILTER (WHERE m.left_at IS NULL) as member_count,
    COUNT(DISTINCT m.member_did) FILTER (WHERE m.is_admin = true AND m.left_at IS NULL) as admin_count,
    COUNT(DISTINCT i.id) FILTER (WHERE
        i.revoked = false
        AND (i.expires_at IS NULL OR i.expires_at > NOW())
        AND (i.max_uses IS NULL OR i.uses_count < i.max_uses)
    ) as active_invite_count
FROM conversations c
LEFT JOIN conversation_policy p ON c.id = p.convo_id
LEFT JOIN members m ON c.id = m.convo_id
LEFT JOIN invites i ON c.id = i.convo_id
GROUP BY c.id, c.name, c.creator_did, p.allow_external_commits, p.require_invite_for_join,
         p.allow_rejoin, p.rejoin_window_days, p.prevent_removing_last_admin, p.updated_at;

COMMENT ON VIEW conversation_policy_summary IS 'Summary view of conversations with their policies and stats';

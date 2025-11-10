-- ===========================================================================
-- MLS Server Database Migration: Admin System, Privacy, and Multi-Device
-- ===========================================================================
-- Created: 2025-11-08
-- Description: Comprehensive migration adding:
--   - Admin system (promote/demote, audit logs, moderation)
--   - E2EE member reports
--   - Multi-device support (device registry)
--   - Bluesky blocks integration
--   - Message privacy enhancements (padding, timestamp quantization)
--   - Automatic rejoin orchestration
-- ===========================================================================

BEGIN;

-- ===========================================================================
-- Part 1: Extend Existing Tables
-- ===========================================================================

-- Conversations: Add idempotency key for duplicate prevention
ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT UNIQUE;

COMMENT ON COLUMN conversations.idempotency_key IS 'Client-provided idempotency key for duplicate conversation prevention';

-- Members: Add admin tracking and MLS leaf index
ALTER TABLE members
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS promoted_by_did TEXT,
    ADD COLUMN IF NOT EXISTS leaf_index INTEGER;

-- Create index for admin queries
CREATE INDEX IF NOT EXISTS idx_members_admins
    ON members(convo_id, member_did)
    WHERE is_admin = true AND left_at IS NULL;

-- Set existing creators as admins (backfill)
UPDATE members m
SET is_admin = true,
    promoted_at = c.created_at,
    promoted_by_did = c.creator_did
FROM conversations c
WHERE m.convo_id = c.id
  AND m.member_did = c.creator_did
  AND m.left_at IS NULL
  AND m.is_admin = false;  -- Only update if not already admin

COMMENT ON COLUMN members.is_admin IS 'Whether this member has admin privileges (encrypted roster distributed via MLS)';
COMMENT ON COLUMN members.promoted_at IS 'When member was promoted to admin (NULL if creator or not admin)';
COMMENT ON COLUMN members.promoted_by_did IS 'DID of admin who promoted this member (NULL if creator or not admin)';
COMMENT ON COLUMN members.leaf_index IS 'MLS leaf index in ratchet tree (NULL if not yet joined group state)';

-- Messages: Add privacy metadata and deduplication
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS msg_id TEXT,
    ADD COLUMN IF NOT EXISTS declared_size INTEGER,
    ADD COLUMN IF NOT EXISTS padded_size INTEGER,
    ADD COLUMN IF NOT EXISTS received_bucket_ts TIMESTAMPTZ;

-- Create unique constraint for msg_id deduplication
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msg_id_dedup
    ON messages(convo_id, msg_id)
    WHERE msg_id IS NOT NULL;

-- Create index for msg_id lookups
CREATE INDEX IF NOT EXISTS idx_messages_msg_id
    ON messages(msg_id)
    WHERE msg_id IS NOT NULL;

-- Create index for bucketed timestamp queries
CREATE INDEX IF NOT EXISTS idx_messages_bucket_ts
    ON messages(convo_id, received_bucket_ts DESC)
    WHERE received_bucket_ts IS NOT NULL;

COMMENT ON COLUMN messages.msg_id IS 'Client-generated ULID for deduplication. MUST be included in MLS message AAD.';
COMMENT ON COLUMN messages.declared_size IS 'Original plaintext size before padding (for metadata privacy)';
COMMENT ON COLUMN messages.padded_size IS 'Padded ciphertext size. Must be 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB.';
COMMENT ON COLUMN messages.received_bucket_ts IS 'Timestamp quantized to 2-second buckets for traffic analysis resistance';

-- ===========================================================================
-- Part 2: Multi-Device Support
-- ===========================================================================

-- User Devices: Registry of all devices per user
CREATE TABLE IF NOT EXISTS user_devices (
    user_did TEXT NOT NULL,               -- did:plc:user
    device_id TEXT NOT NULL,              -- UUID
    device_mls_did TEXT NOT NULL UNIQUE,  -- did:plc:user#device-uuid
    device_name TEXT,                     -- "Josh's iPhone"
    signature_public_key BYTEA NOT NULL UNIQUE,
    key_packages_available INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, device_id)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user
    ON user_devices(user_did);

CREATE INDEX IF NOT EXISTS idx_user_devices_mls_did
    ON user_devices(device_mls_did);

CREATE INDEX IF NOT EXISTS idx_user_devices_public_key
    ON user_devices(signature_public_key);

CREATE INDEX IF NOT EXISTS idx_user_devices_available
    ON user_devices(user_did, device_id)
    WHERE key_packages_available > 0;

COMMENT ON TABLE user_devices IS 'Multi-device registry tracking all devices per user';
COMMENT ON COLUMN user_devices.user_did IS 'User DID (did:plc:user)';
COMMENT ON COLUMN user_devices.device_id IS 'Unique device identifier (UUID)';
COMMENT ON COLUMN user_devices.device_mls_did IS 'Device-specific MLS DID (did:plc:user#device-uuid)';
COMMENT ON COLUMN user_devices.device_name IS 'Human-readable device name (e.g., "Josh''s iPhone")';
COMMENT ON COLUMN user_devices.signature_public_key IS 'Device signature public key for identity verification';
COMMENT ON COLUMN user_devices.key_packages_available IS 'Number of available KeyPackages for this device';

-- ===========================================================================
-- Part 3: Admin System
-- ===========================================================================

-- Admin Actions: Audit log for all admin operations
CREATE TABLE IF NOT EXISTS admin_actions (
    id TEXT PRIMARY KEY,                  -- UUID
    convo_id TEXT NOT NULL,
    actor_did TEXT NOT NULL,              -- Admin who performed action
    action TEXT NOT NULL CHECK (action IN ('promote', 'demote', 'remove')),
    target_did TEXT,                      -- Member affected
    reason TEXT,                          -- Optional justification (max implied by TEXT)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_actions_convo
    ON admin_actions(convo_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_actions_actor
    ON admin_actions(actor_did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_actions_target
    ON admin_actions(target_did)
    WHERE target_did IS NOT NULL;

COMMENT ON TABLE admin_actions IS 'Immutable audit log of all admin actions';
COMMENT ON COLUMN admin_actions.actor_did IS 'DID of admin who performed the action';
COMMENT ON COLUMN admin_actions.action IS 'Type of action: promote, demote, or remove';
COMMENT ON COLUMN admin_actions.target_did IS 'DID of member affected by the action';
COMMENT ON COLUMN admin_actions.reason IS 'Optional justification for the action';

-- ===========================================================================
-- Part 4: E2EE Reports System
-- ===========================================================================

-- Reports: End-to-end encrypted member reports
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,                  -- UUID
    convo_id TEXT NOT NULL,
    reporter_did TEXT NOT NULL,           -- Who filed report
    reported_did TEXT NOT NULL,           -- Who was reported
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
    encrypted_content BYTEA NOT NULL,     -- E2EE blob (max 50KB)
    message_ids TEXT[],                   -- Referenced messages (max 20)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'dismissed')),
    resolved_by_did TEXT,                 -- Admin who resolved
    resolved_at TIMESTAMPTZ,
    resolution_action TEXT CHECK (resolution_action IN ('removed_member', 'dismissed', 'no_action')),
    resolution_notes TEXT,                -- Max 1000 chars enforced by application
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_convo
    ON reports(convo_id, status);

CREATE INDEX IF NOT EXISTS idx_reports_reporter
    ON reports(reporter_did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_reported
    ON reports(reported_did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_status
    ON reports(status, created_at DESC);

COMMENT ON TABLE reports IS 'E2EE member reports - content encrypted with MLS group key, only admins decrypt';
COMMENT ON COLUMN reports.category IS 'Report category for filtering (harassment, spam, hate_speech, violence, sexual_content, impersonation, privacy_violation, other)';
COMMENT ON COLUMN reports.encrypted_content IS 'Encrypted report details (reason, evidence) - uses MLS group key, max 50KB';
COMMENT ON COLUMN reports.message_ids IS 'Array of message IDs referenced in report (max 20)';
COMMENT ON COLUMN reports.status IS 'Report status: pending, resolved, or dismissed';
COMMENT ON COLUMN reports.resolution_action IS 'What action was taken: removed_member, dismissed, or no_action';
COMMENT ON COLUMN reports.resolution_notes IS 'Admin notes on resolution (max 1000 chars)';

-- ===========================================================================
-- Part 5: Bluesky Blocks Integration
-- ===========================================================================

-- Bluesky Blocks: Track block relationships from Bluesky
CREATE TABLE IF NOT EXISTS bsky_blocks (
    user_did TEXT NOT NULL,               -- The blocker
    target_did TEXT NOT NULL,             -- The blocked
    source TEXT NOT NULL DEFAULT 'bsky',  -- 'bsky' or 'manual'
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, target_did)
);

CREATE INDEX IF NOT EXISTS idx_bsky_blocks_user
    ON bsky_blocks(user_did);

CREATE INDEX IF NOT EXISTS idx_bsky_blocks_target
    ON bsky_blocks(target_did);

COMMENT ON TABLE bsky_blocks IS 'Bluesky block relationships synced from AT Protocol';
COMMENT ON COLUMN bsky_blocks.user_did IS 'DID of user who blocked (blocker)';
COMMENT ON COLUMN bsky_blocks.target_did IS 'DID of user who was blocked';
COMMENT ON COLUMN bsky_blocks.source IS 'Source of block: bsky (synced from Bluesky) or manual';
COMMENT ON COLUMN bsky_blocks.synced_at IS 'When this block was last synced from Bluesky';

-- ===========================================================================
-- Part 6: Automatic Rejoin Orchestration
-- ===========================================================================

-- Pending Welcomes: Server-orchestrated Welcome delivery for automatic rejoin
CREATE TABLE IF NOT EXISTS pending_welcomes (
    id TEXT PRIMARY KEY,                  -- UUID
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,          -- Device DID awaiting Welcome
    key_package_hash BYTEA NOT NULL,      -- Hash of KeyPackage used
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,      -- Auto-cleanup after 24 hours
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pending_welcomes_recipient
    ON pending_welcomes(recipient_did)
    WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pending_welcomes_convo
    ON pending_welcomes(convo_id, recipient_did)
    WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pending_welcomes_expires
    ON pending_welcomes(expires_at)
    WHERE delivered_at IS NULL;

COMMENT ON TABLE pending_welcomes IS 'Server-orchestrated Welcome delivery for automatic rejoin (2-5 second flow)';
COMMENT ON COLUMN pending_welcomes.recipient_did IS 'Device DID that needs to receive the Welcome message';
COMMENT ON COLUMN pending_welcomes.key_package_hash IS 'Hash of the KeyPackage that was consumed for this Welcome';
COMMENT ON COLUMN pending_welcomes.expires_at IS 'Expiration timestamp (24 hours from creation) for automatic cleanup';

-- ===========================================================================
-- Part 7: Maintenance Functions
-- ===========================================================================

-- Function to auto-promote conversation creator to admin
CREATE OR REPLACE FUNCTION promote_creator_to_admin()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert creator as first member with admin privileges
    -- This runs after conversation creation, when creator is added as member
    UPDATE members
    SET is_admin = true,
        promoted_at = NEW.created_at,
        promoted_by_did = NEW.creator_did
    WHERE convo_id = NEW.id
      AND member_did = NEW.creator_did
      AND is_admin = false;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Only create trigger if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trigger_promote_creator'
    ) THEN
        CREATE TRIGGER trigger_promote_creator
            AFTER INSERT ON conversations
            FOR EACH ROW
            EXECUTE FUNCTION promote_creator_to_admin();
    END IF;
END
$$;

COMMENT ON FUNCTION promote_creator_to_admin() IS 'Automatically promote conversation creator to admin status';

-- Function to cleanup expired pending welcomes
CREATE OR REPLACE FUNCTION cleanup_expired_pending_welcomes()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM pending_welcomes
    WHERE expires_at < NOW() AND delivered_at IS NULL;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_pending_welcomes() IS 'Remove expired pending welcomes (run periodically)';

-- ===========================================================================
-- Part 8: Data Validation
-- ===========================================================================

-- Ensure no orphaned admin promotions
DO $$
DECLARE
    orphan_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO orphan_count
    FROM members
    WHERE is_admin = true
      AND promoted_by_did IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM members m2
          WHERE m2.convo_id = members.convo_id
            AND m2.member_did = members.promoted_by_did
      );

    IF orphan_count > 0 THEN
        RAISE NOTICE 'Found % members with orphaned promoter DIDs', orphan_count;
    END IF;
END
$$;

-- ===========================================================================
-- Migration Complete
-- ===========================================================================

COMMIT;

-- ===========================================================================
-- Post-Migration Notes
-- ===========================================================================
--
-- This migration adds:
--   ✅ 4 new tables: user_devices, admin_actions, reports, bsky_blocks, pending_welcomes
--   ✅ 9 new columns across 3 existing tables
--   ✅ 15+ new indexes for query optimization
--   ✅ 2 maintenance functions for automation
--   ✅ CHECK constraints for data validation
--   ✅ Proper foreign keys with CASCADE behavior
--   ✅ Comprehensive comments for documentation
--
-- Next steps:
--   1. Update server handlers to use new columns and tables
--   2. Implement device registration endpoint
--   3. Add admin action endpoints (promote/demote/remove)
--   4. Implement E2EE reporting system
--   5. Add Bluesky blocks sync service
--   6. Implement automatic rejoin orchestration
--
-- ===========================================================================

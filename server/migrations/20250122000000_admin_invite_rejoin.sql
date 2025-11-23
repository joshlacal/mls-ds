-- =============================================================================
-- MLS Admin + Invite + Rejoin System
-- Migration: 20250122000000
-- =============================================================================
--
-- This migration adds:
-- 1. conversation_policy table - Per-group policy configuration
-- 2. invites table - Invite links with PSK authentication
-- 3. members.rejoin_psk_hash column - Rejoin PSK for database compromise protection
-- 4. Triggers - Default policy creation, last admin protection
--
-- Security Model:
-- - Server stores SHA256(PSK) only, never plaintext PSK
-- - PSK prevents database compromise attack
-- - DID proves identity (AT Protocol)
-- =============================================================================

-- =============================================================================
-- 1. CONVERSATION POLICY TABLE
-- =============================================================================

CREATE TABLE conversation_policy (
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

    -- Constraints
    CHECK (rejoin_window_days >= 0)
);

CREATE INDEX idx_conversation_policy_external_commits
    ON conversation_policy(allow_external_commits);

CREATE INDEX idx_conversation_policy_updated
    ON conversation_policy(updated_at DESC);

COMMENT ON TABLE conversation_policy IS 'Per-conversation policies for external commits, invites, and rejoin';
COMMENT ON COLUMN conversation_policy.allow_external_commits IS 'Master switch - if false, ALL external commits rejected regardless of other settings';
COMMENT ON COLUMN conversation_policy.require_invite_for_join IS 'If true, external commits from non-members require valid invite PSK';
COMMENT ON COLUMN conversation_policy.allow_rejoin IS 'If true, former members can rejoin via external commit with rejoin PSK';
COMMENT ON COLUMN conversation_policy.rejoin_window_days IS 'Days after leaving that rejoin is allowed (0 = unlimited)';
COMMENT ON COLUMN conversation_policy.prevent_removing_last_admin IS 'If true, cannot demote the last admin in group';

-- =============================================================================
-- 2. INVITES TABLE
-- =============================================================================

CREATE TABLE invites (
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

    -- Constraints
    CHECK (max_uses IS NULL OR max_uses > 0),
    CHECK (uses_count >= 0),
    CHECK (max_uses IS NULL OR uses_count <= max_uses),
    CHECK (LENGTH(psk_hash) = 64),  -- SHA256 hex = 64 chars
    CHECK (psk_hash ~ '^[0-9a-f]+$'),  -- Hex characters only
    CHECK (NOT revoked OR (revoked AND revoked_at IS NOT NULL AND revoked_by_did IS NOT NULL))
);

CREATE INDEX idx_invites_convo ON invites(convo_id);
CREATE INDEX idx_invites_target ON invites(target_did) WHERE target_did IS NOT NULL;
CREATE INDEX idx_invites_psk_hash ON invites(psk_hash);

-- Active invites (commonly queried)
-- Note: expires_at > NOW() check cannot be in index (NOW() is not IMMUTABLE)
-- Time-based filtering must happen at query time
CREATE INDEX idx_invites_active ON invites(convo_id, expires_at)
    WHERE revoked = false
      AND (max_uses IS NULL OR uses_count < max_uses);

COMMENT ON TABLE invites IS 'Invite links for joining groups via external commit + PSK proof';
COMMENT ON COLUMN invites.psk_hash IS 'SHA256 hash of invite PSK - server stores hash only, client provides plaintext PSK in external commit';
COMMENT ON COLUMN invites.target_did IS 'If set, invite only valid for this specific DID (NULL = open invite)';
COMMENT ON COLUMN invites.max_uses IS 'NULL = unlimited uses, 1 = single-use invite, N = can be used N times';
COMMENT ON COLUMN invites.uses_count IS 'How many times this invite has been used (incremented on successful join)';

-- =============================================================================
-- 3. MEMBERS TABLE ENHANCEMENT
-- =============================================================================

-- Add rejoin PSK hash column to members table
ALTER TABLE members ADD COLUMN IF NOT EXISTS rejoin_psk_hash TEXT;

ALTER TABLE members ADD CONSTRAINT check_rejoin_psk_hash_format
    CHECK (rejoin_psk_hash IS NULL OR (
        LENGTH(rejoin_psk_hash) = 64 AND
        rejoin_psk_hash ~ '^[0-9a-f]+$'
    ));

CREATE INDEX idx_members_rejoin_psk ON members(rejoin_psk_hash)
    WHERE rejoin_psk_hash IS NOT NULL;

COMMENT ON COLUMN members.rejoin_psk_hash IS 'SHA256 hash of rejoin PSK - proves "I was a member" for database compromise protection. Generated when member joins, required for rejoining after desync.';

-- =============================================================================
-- 4. TRIGGER: Auto-create default policy when conversation is created
-- =============================================================================

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
        true,   -- allow external commits by default
        false,  -- don't require invites initially (can be changed by admin)
        true,   -- allow rejoin by default
        30,     -- 30 day rejoin window
        true,   -- prevent removing last admin by default
        NEW.creator_did
    )
    ON CONFLICT (convo_id) DO NOTHING;  -- Idempotent for safety

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_create_default_policy
    AFTER INSERT ON conversations
    FOR EACH ROW
    EXECUTE FUNCTION create_default_policy();

COMMENT ON FUNCTION create_default_policy() IS 'Automatically creates default policy when a new conversation is created';

-- =============================================================================
-- 5. TRIGGER: Prevent demoting last admin
-- =============================================================================

CREATE OR REPLACE FUNCTION check_last_admin()
RETURNS TRIGGER AS $$
DECLARE
    remaining_admins INTEGER;
    policy_enforces_last_admin BOOLEAN;
BEGIN
    -- Only check if demoting an admin (is_admin changing from true to false)
    IF OLD.is_admin = true AND NEW.is_admin = false THEN
        -- Check if policy requires keeping at least one admin
        SELECT prevent_removing_last_admin INTO policy_enforces_last_admin
        FROM conversation_policy
        WHERE convo_id = NEW.convo_id;

        IF policy_enforces_last_admin THEN
            -- Count remaining admins after this demotion
            SELECT COUNT(*) INTO remaining_admins
            FROM members
            WHERE convo_id = NEW.convo_id
              AND is_admin = true
              AND left_at IS NULL
              AND member_did != NEW.member_did;  -- Exclude the one being demoted

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

COMMENT ON FUNCTION check_last_admin() IS 'Prevents demoting the last admin if prevent_removing_last_admin policy is enabled';

-- =============================================================================
-- 6. MIGRATION: Create policies for existing conversations
-- =============================================================================

-- Create default policies for all existing conversations that don't have one
INSERT INTO conversation_policy (
    convo_id,
    allow_external_commits,
    require_invite_for_join,
    allow_rejoin,
    rejoin_window_days,
    prevent_removing_last_admin,
    created_by_did
)
SELECT
    id as convo_id,
    true,  -- allow external commits (preserve existing behavior)
    false, -- don't require invites (preserve existing behavior)
    true,  -- allow rejoin (preserve existing behavior)
    30,    -- 30 day window (new default)
    true,  -- prevent removing last admin
    creator_did
FROM conversations
WHERE id NOT IN (SELECT convo_id FROM conversation_policy)
ON CONFLICT (convo_id) DO NOTHING;

-- =============================================================================
-- 7. HELPER VIEWS (Optional, for debugging/admin tools)
-- =============================================================================

-- View of active invites
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

-- View of policy summary
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

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================

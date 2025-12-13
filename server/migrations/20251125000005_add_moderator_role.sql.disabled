-- =============================================================================
-- Add moderator role support to members table
-- =============================================================================
-- Created: 2025-11-25
-- Description: Adds moderator role with promotion tracking

-- Add moderator columns to members table
ALTER TABLE members ADD COLUMN IF NOT EXISTS is_moderator BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE members ADD COLUMN IF NOT EXISTS moderator_promoted_at TIMESTAMPTZ;
ALTER TABLE members ADD COLUMN IF NOT EXISTS moderator_promoted_by_did TEXT;

-- Index for moderator lookups
CREATE INDEX IF NOT EXISTS idx_members_moderators ON members(convo_id, member_did) WHERE is_moderator = true AND left_at IS NULL;

-- Update admin_actions CHECK constraint to include moderator actions
ALTER TABLE admin_actions DROP CONSTRAINT IF EXISTS admin_actions_action_check;
ALTER TABLE admin_actions ADD CONSTRAINT admin_actions_action_check
    CHECK (action IN ('promote', 'demote', 'remove', 'warn', 'promote_moderator', 'demote_moderator'));

COMMENT ON COLUMN members.is_moderator IS 'Whether this member has moderator privileges (can warn members and view reports)';
COMMENT ON COLUMN members.moderator_promoted_at IS 'When member was promoted to moderator (NULL if not moderator)';
COMMENT ON COLUMN members.moderator_promoted_by_did IS 'DID of admin who promoted this member to moderator (NULL if not moderator)';
COMMENT ON CONSTRAINT admin_actions_action_check ON admin_actions IS 'Allowed actions: promote, demote, remove, warn, promote_moderator, demote_moderator';

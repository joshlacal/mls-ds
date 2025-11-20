-- Migration: Auto-Rejoin Approval System
-- Adds auto-approval tracking and audit logging for rejoin requests
-- Created: 2025-11-15

BEGIN;

-- Add auto-approval column to members table
ALTER TABLE members
    ADD COLUMN IF NOT EXISTS rejoin_auto_approved BOOLEAN;

-- Add last_seen_at tracking for auto-approval logic
ALTER TABLE members
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

-- Create rejoin_requests audit table
CREATE TABLE IF NOT EXISTS rejoin_requests (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    auto_approved BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Create indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_rejoin_requests_convo
    ON rejoin_requests(convo_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_rejoin_requests_member
    ON rejoin_requests(member_did, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_rejoin_requests_auto_approved
    ON rejoin_requests(auto_approved, requested_at DESC);

-- Add index for auto-approved rejoin lookups
CREATE INDEX IF NOT EXISTS idx_members_rejoin_auto_approved
    ON members(convo_id, member_did)
    WHERE needs_rejoin = true AND rejoin_auto_approved = true;

COMMENT ON COLUMN members.rejoin_auto_approved IS 'Whether rejoin request was automatically approved (within 30 days of last activity)';
COMMENT ON COLUMN members.last_seen_at IS 'Last time this member was active in the conversation';
COMMENT ON TABLE rejoin_requests IS 'Audit log of all rejoin requests for security and debugging';

COMMIT;

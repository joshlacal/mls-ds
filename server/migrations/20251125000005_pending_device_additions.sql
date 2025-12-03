-- Migration: pending_device_additions
-- Purpose: Track pending device additions for automatic multi-device sync
-- When a user registers a new device, this table tracks which conversations
-- need to add that device. Other online members can claim and process these additions.

CREATE TABLE IF NOT EXISTS pending_device_additions (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    convo_id TEXT NOT NULL,
    user_did TEXT NOT NULL,
    new_device_id TEXT NOT NULL,
    new_device_credential_did TEXT NOT NULL,
    device_name TEXT,

    -- Status tracking
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'self_joined')),

    -- Claim mechanism (prevents race conditions)
    -- When a member claims an addition, they have 60 seconds to complete it
    claimed_by_did TEXT,
    claimed_at TIMESTAMPTZ,
    claim_expires_at TIMESTAMPTZ,

    -- Completion tracking
    completed_by_did TEXT,
    completed_at TIMESTAMPTZ,
    new_epoch INTEGER,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign key to conversations table
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,

    -- Each device can only have one pending addition per conversation
    UNIQUE (convo_id, new_device_credential_did)
);

-- Index for querying pending additions by user
CREATE INDEX IF NOT EXISTS idx_pending_device_additions_user
    ON pending_device_additions(user_did);

-- Index for querying pending additions by conversation
CREATE INDEX IF NOT EXISTS idx_pending_device_additions_convo
    ON pending_device_additions(convo_id);

-- Index for finding pending additions that need processing
CREATE INDEX IF NOT EXISTS idx_pending_device_additions_pending
    ON pending_device_additions(status, created_at)
    WHERE status = 'pending';

-- Index for finding expired claims that can be released
CREATE INDEX IF NOT EXISTS idx_pending_device_additions_expired_claims
    ON pending_device_additions(claim_expires_at)
    WHERE status = 'in_progress' AND claim_expires_at IS NOT NULL;

-- Index for querying by device credential DID (for self-join detection)
CREATE INDEX IF NOT EXISTS idx_pending_device_additions_credential
    ON pending_device_additions(new_device_credential_did);

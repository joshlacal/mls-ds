-- Create members (memberships) table
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

-- Add index on member_did for efficient lookup of user's conversations
CREATE INDEX idx_members_member_did ON members(member_did);

-- Add index on left_at for filtering active members
CREATE INDEX idx_members_left_at ON members(left_at) WHERE left_at IS NULL;

-- Add compound index for active member queries
CREATE INDEX idx_members_active ON members(member_did, convo_id) WHERE left_at IS NULL;

-- Add index for unread count queries
CREATE INDEX idx_members_unread ON members(member_did, unread_count) WHERE unread_count > 0;

-- =============================================================================
-- Read Receipts Table
-- =============================================================================
-- Created: 2025-11-25
-- Description: Track when members read messages in MLS conversations

CREATE TABLE IF NOT EXISTS read_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    message_id TEXT,  -- NULL means "read all up to latest"
    read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (convo_id, member_did, message_id),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_read_receipts_convo ON read_receipts(convo_id);
CREATE INDEX IF NOT EXISTS idx_read_receipts_member ON read_receipts(member_did);
CREATE INDEX IF NOT EXISTS idx_read_receipts_message ON read_receipts(message_id) WHERE message_id IS NOT NULL;

COMMENT ON TABLE read_receipts IS 'Track when members read messages in conversations';
COMMENT ON COLUMN read_receipts.message_id IS 'NULL means "read all messages up to latest", specific ID means "read this specific message"';
COMMENT ON COLUMN read_receipts.read_at IS 'When the message(s) were marked as read';

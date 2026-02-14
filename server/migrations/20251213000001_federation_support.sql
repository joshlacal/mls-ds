-- Federation support: dual-role DS (mailbox + sequencer)
-- Each DS can act as sequencer for conversations it owns, and as a participant
-- mailbox for remote conversations sequenced by another DS.

-- Track which DS is the sequencer for each conversation
-- NULL = this DS is the sequencer (backward compatibility)
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS sequencer_ds TEXT;

-- Track if this DS is just a participant mailbox (not the sequencer)
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS is_remote BOOLEAN NOT NULL DEFAULT FALSE;

-- Track which DS serves each member (for fan-out routing)
-- NULL = local user (on this DS)
ALTER TABLE members ADD COLUMN IF NOT EXISTS ds_did TEXT;

-- DS endpoint cache (resolved from repo records)
CREATE TABLE IF NOT EXISTS ds_endpoints (
    did TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    supported_cipher_suites TEXT,  -- JSON array as text, nullable
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);
CREATE INDEX IF NOT EXISTS idx_ds_endpoints_expires ON ds_endpoints(expires_at);

-- Outbound delivery queue (for retry on DS-to-DS failures)
CREATE TABLE IF NOT EXISTS outbound_queue (
    id TEXT PRIMARY KEY,
    target_ds_did TEXT NOT NULL,
    target_endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    payload BYTEA NOT NULL,
    convo_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    last_error TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_outbound_queue_retry ON outbound_queue(status, next_retry_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_outbound_queue_convo ON outbound_queue(convo_id);

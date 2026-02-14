-- Sequencer receipts: cryptographic proof that the sequencer assigned a specific
-- epoch to a specific commit. Used for equivocation detection.
CREATE TABLE IF NOT EXISTS sequencer_receipts (
    convo_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    commit_hash BYTEA NOT NULL,
    sequencer_did TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, epoch)
);

-- Index for querying receipts by conversation
CREATE INDEX IF NOT EXISTS idx_sequencer_receipts_convo
    ON sequencer_receipts (convo_id, epoch DESC);

-- ADR-017: make sequencer receipt identity generation-qualified and append-only.
--
-- The legacy table is intentionally retained as a read-only compatibility
-- source. Its `(convo_id, epoch)` primary key cannot represent epoch reuse
-- after a destructive reset without either overwriting history or rejecting a
-- valid later generation.

CREATE TABLE IF NOT EXISTS sequencer_receipts_v2 (
    convo_id TEXT NOT NULL,
    reset_generation INTEGER NOT NULL CHECK (reset_generation >= 0),
    epoch INTEGER NOT NULL,
    sequencer_term BIGINT NOT NULL CHECK (sequencer_term >= 0),
    commit_hash BYTEA NOT NULL,
    sequencer_did TEXT NOT NULL CHECK (
        sequencer_did LIKE 'did:%' AND position('#' in sequencer_did) = 0
    ),
    issued_at BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    receipt_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, reset_generation, epoch),
    UNIQUE (receipt_hash)
);

CREATE INDEX IF NOT EXISTS idx_sequencer_receipts_v2_convo_generation
    ON sequencer_receipts_v2 (convo_id, reset_generation, epoch DESC);

COMMENT ON TABLE sequencer_receipts_v2 IS
    'Append-only, generation-qualified ADR-017 sequencer receipt ledger. The legacy sequencer_receipts table is read-only compatibility state.';


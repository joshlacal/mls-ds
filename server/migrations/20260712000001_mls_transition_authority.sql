-- ADR-011 foundation: bind active crypto sessions to sequencer authority and
-- make receipt identity durable without rewriting historical receipts.

ALTER TABLE crypto_sessions
    ADD COLUMN IF NOT EXISTS sequencer_did TEXT,
    ADD COLUMN IF NOT EXISTS sequencer_term BIGINT NOT NULL DEFAULT 0;

UPDATE crypto_sessions cs
SET sequencer_did = split_part(c.sequencer_ds, '#', 1),
    sequencer_term = c.sequencer_term
FROM conversations c
WHERE c.id = cs.conversation_id
  AND cs.sequencer_did IS NULL
  AND c.sequencer_ds IS NOT NULL;

ALTER TABLE crypto_sessions
    DROP CONSTRAINT IF EXISTS chk_crypto_sessions_sequencer_did_canonical;
ALTER TABLE crypto_sessions
    ADD CONSTRAINT chk_crypto_sessions_sequencer_did_canonical
    CHECK (sequencer_did IS NULL OR (
        sequencer_did LIKE 'did:%' AND position('#' in sequencer_did) = 0
    ));

ALTER TABLE sequencer_receipts
    ADD COLUMN IF NOT EXISTS receipt_hash BYTEA;

UPDATE sequencer_receipts
SET sequencer_did = split_part(sequencer_did, '#', 1)
WHERE sequencer_did LIKE '%#%';

UPDATE sequencer_receipts
SET receipt_hash = digest(
    convert_to(convo_id, 'UTF8') ||
    int4send(epoch) ||
    int8send(sequencer_term) ||
    convert_to(sequencer_did, 'UTF8') ||
    commit_hash ||
    int8send(issued_at) ||
    signature,
    'sha256'
)
WHERE receipt_hash IS NULL;

ALTER TABLE sequencer_receipts
    ALTER COLUMN receipt_hash SET NOT NULL;

ALTER TABLE sequencer_receipts
    DROP CONSTRAINT IF EXISTS chk_sequencer_receipts_did_canonical;
ALTER TABLE sequencer_receipts
    ADD CONSTRAINT chk_sequencer_receipts_did_canonical
    CHECK (sequencer_did LIKE 'did:%' AND position('#' in sequencer_did) = 0);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sequencer_receipts_hash
    ON sequencer_receipts(receipt_hash);

COMMENT ON COLUMN sequencer_receipts.receipt_hash IS
    'Stable receipt identity. Identical replay is idempotent; the conversation/epoch primary key rejects equivocation.';

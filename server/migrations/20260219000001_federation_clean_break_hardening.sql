-- Federation clean-break hardening:
-- - Sequencer term tracking
-- - WebSocket ticket replay store
-- - Federation reconciliation state
-- - Canonical DS DID constraints (no #fragment)

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS sequencer_term BIGINT NOT NULL DEFAULT 0;

ALTER TABLE delivery_acks
    ADD COLUMN IF NOT EXISTS sequencer_term BIGINT NOT NULL DEFAULT 0;

ALTER TABLE sequencer_receipts
    ADD COLUMN IF NOT EXISTS sequencer_term BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS ws_ticket_nonce (
    issuer_did TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer_did, jti)
);

CREATE INDEX IF NOT EXISTS idx_ws_ticket_nonce_expires
    ON ws_ticket_nonce (expires_at);

CREATE TABLE IF NOT EXISTS federation_sync_state (
    convo_id TEXT NOT NULL,
    sequencer_ds_did TEXT NOT NULL,
    sequencer_term BIGINT NOT NULL DEFAULT 0,
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_epoch BIGINT NOT NULL DEFAULT 0,
    last_digest TEXT,
    last_reconciled_at TIMESTAMPTZ,
    drift_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, sequencer_ds_did)
);

CREATE INDEX IF NOT EXISTS idx_federation_sync_state_updated
    ON federation_sync_state (updated_at DESC);

-- Canonicalize existing DS DID values in-place.
UPDATE members
SET ds_did = split_part(ds_did, '#', 1)
WHERE ds_did IS NOT NULL AND ds_did LIKE '%#%';

UPDATE conversations
SET sequencer_ds = split_part(sequencer_ds, '#', 1)
WHERE sequencer_ds IS NOT NULL AND sequencer_ds LIKE '%#%';

DELETE FROM federation_peers a
USING federation_peers b
WHERE a.ctid < b.ctid
  AND split_part(a.ds_did, '#', 1) = split_part(b.ds_did, '#', 1);

UPDATE federation_peers
SET ds_did = split_part(ds_did, '#', 1)
WHERE ds_did LIKE '%#%';

DELETE FROM ds_endpoints a
USING ds_endpoints b
WHERE a.ctid < b.ctid
  AND split_part(a.did, '#', 1) = split_part(b.did, '#', 1);

UPDATE ds_endpoints
SET did = split_part(did, '#', 1)
WHERE did LIKE '%#%';

DELETE FROM outbound_queue a
USING outbound_queue b
WHERE a.ctid < b.ctid
  AND a.convo_id = b.convo_id
  AND split_part(a.target_ds_did, '#', 1) = split_part(b.target_ds_did, '#', 1)
  AND a.method = b.method
  AND a.status = b.status;

UPDATE outbound_queue
SET target_ds_did = split_part(target_ds_did, '#', 1)
WHERE target_ds_did LIKE '%#%';

WITH ranked AS (
    SELECT ctid,
           row_number() OVER (
               PARTITION BY convo_id, message_id, split_part(target_ds_did, '#', 1), COALESCE(sequencer_term, 0)
               ORDER BY received_at DESC, id DESC
           ) AS rn
    FROM delivery_acks
)
DELETE FROM delivery_acks d
USING ranked r
WHERE d.ctid = r.ctid
  AND r.rn > 1;

UPDATE delivery_acks
SET target_ds_did = split_part(target_ds_did, '#', 1)
WHERE target_ds_did LIKE '%#%';

ALTER TABLE delivery_acks
    DROP CONSTRAINT IF EXISTS uq_delivery_ack_message_ds;
ALTER TABLE delivery_acks
    DROP CONSTRAINT IF EXISTS uq_delivery_ack_message_ds_term;
ALTER TABLE delivery_acks
    ADD CONSTRAINT uq_delivery_ack_message_ds_term
    UNIQUE (convo_id, message_id, target_ds_did, sequencer_term);

-- Enforce canonical DS DID form (no fragments).
ALTER TABLE members
    DROP CONSTRAINT IF EXISTS chk_members_ds_did_canonical;
ALTER TABLE members
    ADD CONSTRAINT chk_members_ds_did_canonical
    CHECK (ds_did IS NULL OR position('#' in ds_did) = 0);

ALTER TABLE conversations
    DROP CONSTRAINT IF EXISTS chk_conversations_sequencer_ds_canonical;
ALTER TABLE conversations
    ADD CONSTRAINT chk_conversations_sequencer_ds_canonical
    CHECK (sequencer_ds IS NULL OR position('#' in sequencer_ds) = 0);

ALTER TABLE federation_peers
    DROP CONSTRAINT IF EXISTS chk_federation_peers_ds_did_canonical;
ALTER TABLE federation_peers
    ADD CONSTRAINT chk_federation_peers_ds_did_canonical
    CHECK (position('#' in ds_did) = 0);

ALTER TABLE outbound_queue
    DROP CONSTRAINT IF EXISTS chk_outbound_queue_target_ds_did_canonical;
ALTER TABLE outbound_queue
    ADD CONSTRAINT chk_outbound_queue_target_ds_did_canonical
    CHECK (position('#' in target_ds_did) = 0);

ALTER TABLE delivery_acks
    DROP CONSTRAINT IF EXISTS chk_delivery_acks_target_ds_did_canonical;
ALTER TABLE delivery_acks
    ADD CONSTRAINT chk_delivery_acks_target_ds_did_canonical
    CHECK (position('#' in target_ds_did) = 0);

ALTER TABLE ds_endpoints
    DROP CONSTRAINT IF EXISTS chk_ds_endpoints_did_canonical;
ALTER TABLE ds_endpoints
    ADD CONSTRAINT chk_ds_endpoints_did_canonical
    CHECK (position('#' in did) = 0);

-- Migration: Clean Chat Federation Outbox and Outbound Queue Claim Fencing
-- Target: federation_outbox, outbound_queue, and federation_sync_state

-- A clean replacement database has no legacy federation transport tables.
CREATE TABLE IF NOT EXISTS federation_outbox (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT,
    target_service_did TEXT NOT NULL,
    payload BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

DROP INDEX IF EXISTS idx_federation_outbox_due;
DROP INDEX IF EXISTS idx_federation_outbox_event;
DROP INDEX IF EXISTS idx_outbound_queue_retry;
DROP INDEX IF EXISTS idx_outbound_queue_convo;
DROP INDEX IF EXISTS idx_federation_sync_state_updated;

ALTER TABLE federation_outbox DROP CONSTRAINT IF EXISTS federation_outbox_status_check;
ALTER TABLE federation_outbox
    ADD CONSTRAINT federation_outbox_status_check
    CHECK (status IN ('pending', 'in_flight', 'done', 'failed', 'dead'));

ALTER TABLE outbound_queue
    DROP CONSTRAINT IF EXISTS chk_outbound_queue_target_ds_did_canonical;
-- 1. Extend federation_outbox for typed clean federation jobs (if pre-existing)
ALTER TABLE federation_outbox ALTER COLUMN delivery_event_id DROP NOT NULL;
ALTER TABLE federation_outbox DROP CONSTRAINT IF EXISTS federation_outbox_delivery_event_id_fkey;

ALTER TABLE federation_outbox
    ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT 'blue.catbird.mlsDS.deliverMessage',
    ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA,
    ADD COLUMN IF NOT EXISTS envelope_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS claim_token UUID,
    ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_federation_outbox_due_v2
    ON federation_outbox(next_attempt_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_federation_outbox_lease
    ON federation_outbox(claim_expires_at) WHERE status = 'in_flight';

-- 2. Extend outbound_queue with claim fencing and typed metadata (if pre-existing)
ALTER TABLE outbound_queue DROP CONSTRAINT IF EXISTS outbound_queue_status_check;
ALTER TABLE outbound_queue
    ADD CONSTRAINT outbound_queue_status_check
    CHECK (status IN ('pending', 'in_flight', 'delivered', 'failed', 'dead'));

ALTER TABLE outbound_queue
    ADD COLUMN IF NOT EXISTS claim_token UUID,
    ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA,
    ADD COLUMN IF NOT EXISTS envelope_version INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_outbound_queue_due_v2
    ON outbound_queue(next_retry_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_outbound_queue_lease
    ON outbound_queue(claim_expires_at) WHERE status = 'in_flight';

-- 3. Extend federation_sync_state with sticky quarantine fields
ALTER TABLE federation_sync_state
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'healthy',
    ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS quarantine_reason TEXT,
    ADD COLUMN IF NOT EXISTS first_mismatch_seq BIGINT;

ALTER TABLE federation_sync_state DROP CONSTRAINT IF EXISTS federation_sync_state_status_check;
ALTER TABLE federation_sync_state
    ADD CONSTRAINT federation_sync_state_status_check
    CHECK (status IN ('healthy', 'quarantined'));

ALTER TABLE federation_sync_state DROP CONSTRAINT IF EXISTS federation_sync_state_quarantine_reason_check;
ALTER TABLE federation_sync_state
    ADD CONSTRAINT federation_sync_state_quarantine_reason_check
    CHECK (quarantine_reason IS NULL OR quarantine_reason IN ('prefix_mismatch', 'local_ahead'));

ALTER TABLE federation_sync_state DROP CONSTRAINT IF EXISTS federation_sync_state_first_mismatch_seq_check;
ALTER TABLE federation_sync_state
    ADD CONSTRAINT federation_sync_state_first_mismatch_seq_check
    CHECK (first_mismatch_seq IS NULL OR first_mismatch_seq > 0);

ALTER TABLE federation_sync_state DROP CONSTRAINT IF EXISTS federation_sync_state_quarantine_shape_check;
ALTER TABLE federation_sync_state
    ADD CONSTRAINT federation_sync_state_quarantine_shape_check
    CHECK (
        (status = 'healthy' AND quarantined_at IS NULL AND quarantine_reason IS NULL AND first_mismatch_seq IS NULL)
        OR
        (status = 'quarantined' AND quarantined_at IS NOT NULL AND quarantine_reason IS NOT NULL AND first_mismatch_seq IS NOT NULL)
    );

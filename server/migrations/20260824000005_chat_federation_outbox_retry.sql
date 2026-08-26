-- Migration: Clean Chat Federation Outbox and Outbound Queue Claim Fencing
-- Target: federation_outbox, outbound_queue, and federation_sync_state

-- 1. Extend or create federation_outbox for typed clean federation jobs
CREATE TABLE IF NOT EXISTS federation_outbox (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT,
    device_id TEXT,
    recipient_did TEXT,
    target_endpoint TEXT NOT NULL,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method TEXT NOT NULL DEFAULT 'blue.catbird.mlsDS.deliverMessage',
    payload_sha256 BYTEA,
    envelope_version INTEGER NOT NULL DEFAULT 1,
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ
);

DO $$
BEGIN
    ALTER TABLE federation_outbox ALTER COLUMN delivery_event_id DROP NOT NULL;
    ALTER TABLE federation_outbox DROP CONSTRAINT IF EXISTS federation_outbox_delivery_event_id_fkey;
    ALTER TABLE federation_outbox
        ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT 'blue.catbird.mlsDS.deliverMessage',
        ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA,
        ADD COLUMN IF NOT EXISTS envelope_version INTEGER NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS claim_token UUID,
        ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_federation_outbox_due_v2
    ON federation_outbox(next_attempt_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_federation_outbox_lease
    ON federation_outbox(claim_expires_at) WHERE status = 'in_flight';

-- 2. Extend or create outbound_queue with claim fencing and typed metadata
CREATE TABLE IF NOT EXISTS outbound_queue (
    id TEXT PRIMARY KEY,
    destination_endpoint TEXT NOT NULL,
    peer_did TEXT,
    payload BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_flight', 'delivered', 'failed', 'dead')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    payload_sha256 BYTEA,
    envelope_version INTEGER NOT NULL DEFAULT 1
);

DO $$
BEGIN
    ALTER TABLE outbound_queue DROP CONSTRAINT IF EXISTS outbound_queue_status_check;
    ALTER TABLE outbound_queue
        ADD CONSTRAINT outbound_queue_status_check
        CHECK (status IN ('pending', 'in_flight', 'delivered', 'failed', 'dead'));
    ALTER TABLE outbound_queue
        ADD COLUMN IF NOT EXISTS claim_token UUID,
        ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA,
        ADD COLUMN IF NOT EXISTS envelope_version INTEGER NOT NULL DEFAULT 1;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_outbound_queue_due_v2
    ON outbound_queue(next_retry_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_outbound_queue_lease
    ON outbound_queue(claim_expires_at) WHERE status = 'in_flight';

-- 3. Extend or create federation_sync_state with explicit quarantine fields and exact shape checks
CREATE TABLE IF NOT EXISTS federation_sync_state (
    convo_id TEXT NOT NULL,
    sequencer_ds_did TEXT NOT NULL,
    sequencer_term BIGINT NOT NULL DEFAULT 0,
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_epoch BIGINT NOT NULL DEFAULT 0,
    last_digest BYTEA,
    last_reconciled_at TIMESTAMPTZ,
    drift_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, sequencer_ds_did)
);

ALTER TABLE federation_sync_state
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'healthy'
        CHECK (status IN ('healthy', 'quarantined')),
    ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS quarantine_reason TEXT,
    ADD COLUMN IF NOT EXISTS first_mismatch_seq BIGINT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'federation_sync_state_quarantine_shape_check'
    ) THEN
        ALTER TABLE federation_sync_state
            ADD CONSTRAINT federation_sync_state_quarantine_shape_check
            CHECK (
                ((status = 'healthy') AND quarantined_at IS NULL AND quarantine_reason IS NULL AND first_mismatch_seq IS NULL)
                OR
                ((status = 'quarantined') AND quarantined_at IS NOT NULL AND quarantine_reason IS NOT NULL AND length(trim(quarantine_reason)) > 0 AND first_mismatch_seq IS NOT NULL AND first_mismatch_seq >= 0)
            );
    END IF;
END $$;

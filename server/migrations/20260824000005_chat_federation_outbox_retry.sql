-- Migration: Clean Chat Federation Outbox and Outbound Queue Claim Fencing
-- Target: federation_outbox and outbound_queue

CREATE TABLE IF NOT EXISTS federation_outbox (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT,
    target_service_did TEXT NOT NULL,
    payload BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('pending','in_flight','done','failed','dead')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

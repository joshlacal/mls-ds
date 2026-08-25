-- Migration: Clean Chat Federation Outbox and Outbound Queue Claim Fencing
-- Target: federation_outbox and outbound_queue

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

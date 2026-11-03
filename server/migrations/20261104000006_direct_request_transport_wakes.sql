-- 20261104000006_direct_request_transport_wakes.sql
-- D2 `directRequest` wakes on a C33 transport-only recipient home.
--
-- Only a device's home DS may wake it, so when the recipient is homed on the
-- pair's transport-only home, that home (not the coordinator) wakes the
-- recipient's devices. Every `deliverDirectRequest` inbox row (one per
-- recipient device) enqueues exactly one durable wake in its own insert
-- transaction; the inbox insert is idempotent, so a replayed delivery never
-- enqueues a second wake. The wake row follows the `chat.outbox` lease/retry
-- shape so one worker state machine drains both queues. Inbox rows that
-- predate this migration are never woken.

CREATE TABLE chat.direct_request_transport_wakes (
    delivery_id UUID PRIMARY KEY
        REFERENCES chat.direct_request_transport_inbox(delivery_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count BIGINT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT direct_request_transport_wakes_status_check
        CHECK (status IN ('pending','leased','delivered','failed')),
    CONSTRAINT direct_request_transport_wakes_attempt_count_check
        CHECK (chat.is_safe_integer(attempt_count)),
    CONSTRAINT direct_request_transport_wakes_status_shape_check CHECK (
        (status = 'pending' AND lease_owner IS NULL AND lease_expires_at IS NULL AND delivered_at IS NULL)
        OR (status = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND delivered_at IS NULL)
        OR (status = 'delivered' AND delivered_at IS NOT NULL)
        OR (status = 'failed' AND delivered_at IS NULL)
    )
);

CREATE INDEX direct_request_transport_wakes_claim_idx
    ON chat.direct_request_transport_wakes (created_at, delivery_id)
    WHERE status IN ('pending','leased');

CREATE FUNCTION chat.enqueue_direct_request_transport_wake()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO chat.direct_request_transport_wakes(delivery_id, next_attempt_at, created_at)
    VALUES (NEW.delivery_id, NEW.created_at, NEW.created_at);
    RETURN NEW;
END;
$$;

CREATE TRIGGER direct_request_transport_inbox_enqueue_wake
AFTER INSERT ON chat.direct_request_transport_inbox
FOR EACH ROW EXECUTE FUNCTION chat.enqueue_direct_request_transport_wake();

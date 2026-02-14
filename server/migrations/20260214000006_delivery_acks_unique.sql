-- Add uniqueness constraint to prevent duplicate ACKs per conversation/message/DS.
-- First deduplicate any existing rows, keeping the earliest.
-- Run in batches to avoid long-running table locks on large datasets.
DO
$$
DECLARE
  rows_deleted INTEGER;
  batch_limit INTEGER := 5000;
  batch_sleep_seconds DOUBLE PRECISION := 0.1; -- 100ms pause between batches to reduce lock/replication pressure
BEGIN
  LOOP
    DELETE FROM delivery_acks a
    WHERE a.ctid IN (
      SELECT a1.ctid
      FROM delivery_acks a1
      WHERE EXISTS (
        SELECT 1
        FROM delivery_acks b
        WHERE b.convo_id = a1.convo_id
          AND b.message_id = a1.message_id
          AND b.target_ds_did = a1.target_ds_did
          AND (
            b.received_at < a1.received_at
            OR (b.received_at = a1.received_at AND b.ctid < a1.ctid)
          )
      )
      LIMIT batch_limit
    );

    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    EXIT WHEN rows_deleted = 0;

    -- Small pause between batches to reduce contention on busy systems.
    PERFORM pg_sleep(batch_sleep_seconds);
  END LOOP;
END;
$$;

ALTER TABLE delivery_acks
  DROP CONSTRAINT IF EXISTS uq_delivery_ack_message_ds;

ALTER TABLE delivery_acks
  ADD CONSTRAINT uq_delivery_ack_message_ds
  UNIQUE (convo_id, message_id, target_ds_did);

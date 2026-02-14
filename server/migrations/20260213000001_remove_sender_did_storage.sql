-- Stop indexing sender_did (all new values will be NULL)
DROP INDEX IF EXISTS idx_messages_sender;

-- Optionally null out existing sender_did values for privacy
-- (can be done in a background job to avoid table lock)
DO
$$
DECLARE
    rows_updated INTEGER;
    batch_limit INTEGER := 5000;
    batch_sleep_seconds DOUBLE PRECISION := 0.1;
BEGIN
    LOOP
        UPDATE messages
        SET sender_did = NULL
        WHERE ctid IN (
            SELECT ctid
            FROM messages
            WHERE sender_did IS NOT NULL
            LIMIT batch_limit
        );

        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        EXIT WHEN rows_updated = 0;

        -- Optional: small pause between batches to reduce contention on busy systems.
        PERFORM pg_sleep(batch_sleep_seconds);
    END LOOP;
END;
$$;

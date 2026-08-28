-- Historical remote prefixes contain accepted application entries but no local
-- send attempt. Keep the ordinary message-send invariant in the deferred trigger
-- while allowing the sealed bootstrap transaction to persist the remote wire row.

SET LOCAL lock_timeout = '2s';

CREATE OR REPLACE FUNCTION chat.assert_message_send_mapping(
    target_conversation UUID,
    target_message UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    remote BOOLEAN;
    cutoff BIGINT;
    entry_seq BIGINT;
    entry_state_version_null BOOLEAN;
    send_row chat.message_sends%ROWTYPE;
    send_found BOOLEAN;
    entry_count BIGINT;
BEGIN
    SELECT is_remote, historical_bootstrap_last_seq
      INTO remote, cutoff
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;

    SELECT * INTO send_row
      FROM chat.message_sends
     WHERE conversation_id = target_conversation
       AND message_id = target_message;
    send_found := FOUND;

    SELECT count(*), min(seq), bool_and(state_version IS NULL)
      INTO entry_count, entry_seq, entry_state_version_null
      FROM chat.entries
     WHERE conversation_id = target_conversation
       AND message_id = target_message;

    IF remote AND cutoff IS NOT NULL AND entry_count = 1 AND entry_seq <= cutoff AND entry_state_version_null THEN
        IF send_found THEN
            RAISE EXCEPTION 'historical bootstrap application entry must have zero message_sends'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF NOT send_found THEN
        IF entry_count <> 0 THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF send_row.status = 'accepted' THEN
        IF entry_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM chat.entries
             WHERE conversation_id = target_conversation
               AND seq = send_row.accepted_entry_seq
               AND message_id = target_message
               AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'
               AND signed_request_bytes = send_row.signed_request_bytes
               AND request_digest = send_row.request_digest
               AND signature = send_row.signature
               AND received_at = send_row.received_at
        ) THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF entry_count <> 0 THEN
        RAISE EXCEPTION 'application message mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

ALTER TABLE chat.entries
    DROP CONSTRAINT entries_message_send_fk;

COMMENT ON FUNCTION chat.assert_message_send_mapping(UUID, UUID) IS
    'Enforces local send/application-entry bijection, except sealed historical bootstrap entries with no destination-local send attempt.';

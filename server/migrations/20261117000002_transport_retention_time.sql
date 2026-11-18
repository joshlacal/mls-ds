-- Transport entries arrive from the conversation's authenticated sequencer.
-- Its compact, immutable application projection has no user ciphertext. Corroborate
-- the sequencer's receivedAt against its receipt and the actual row coordinate.
-- Older projections without that evidence can only establish local arrival time.
CREATE OR REPLACE FUNCTION chat.transport_application_retention_start(
    projected BYTEA, arrived TIMESTAMPTZ, convo UUID, entry UUID, sequence BIGINT
) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
    envelope JSONB;
    receipt JSONB;
    accepted TIMESTAMPTZ;
BEGIN
    IF projected IS NULL THEN
        RETURN arrived;
    END IF;
    envelope := convert_from(projected, 'UTF8')::jsonb;
    receipt := envelope->'sequencerReceipt';
    IF (envelope->>'$type' = 'blue.catbird.chat.defs#applicationEntry'
        AND envelope->>'conversationId' = convo::text
        AND envelope->>'entryId' = entry::text
        AND envelope->'seq' = to_jsonb(sequence)
        AND receipt->>'conversationId' = convo::text
        AND receipt->>'entryId' = entry::text
        AND receipt->'seq' = to_jsonb(sequence)
        AND length(receipt->>'sequencerDid') > 0
        AND length(receipt->>'kid') > 0
        AND receipt->'signature' IS NOT NULL
        AND jsonb_typeof(receipt->'issuedAtMs') = 'number'
        AND envelope->>'receivedAt' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
    ) IS NOT TRUE THEN
        RETURN arrived;
    END IF;
    accepted := (envelope->>'receivedAt')::timestamptz;
    IF floor(extract(epoch FROM accepted) * 1000) <> (receipt->>'issuedAtMs')::numeric THEN
        RETURN arrived;
    END IF;
    RETURN least(accepted, arrived);
EXCEPTION WHEN data_exception THEN
    RETURN arrived;
END
$$;

CREATE INDEX IF NOT EXISTS transport_application_retention_start_idx
    ON chat.direct_request_transport_entries (
        chat.transport_application_retention_start(
            pruned_entry_bytes, created_at, conversation_id, entry_id, seq
        ), conversation_id, seq
    )
    WHERE application_message_id IS NOT NULL AND payload_pruned_at IS NULL;

-- Remote homes erase application ciphertext without losing the original delivery,
-- signed metadata, message-id replay binding, predecessor coordinate, or I13 receipt.
-- entry_bytes remains the read projection; it is never repopulated after pruning.
--
-- Signed requests carry NUL-terminated signature domains ("...\u0000"), which
-- PostgreSQL json and jsonb reject. Nothing here parses entry JSON: the single Rust
-- writer (repository::delivery::insert_transport_entry) derives the application
-- evidence and its pruned projection; SQL only digests raw bytes and enforces
-- shape, immutability and the one irreversible prune.
ALTER TABLE chat.direct_request_transport_entries
    ADD COLUMN original_entry_sha256 BYTEA,
    ADD COLUMN application_message_id UUID,
    ADD COLUMN application_request_sha256 BYTEA,
    ADD COLUMN application_metadata_bytes BYTEA,
    ADD COLUMN application_generation BIGINT,
    ADD COLUMN pruned_entry_bytes BYTEA,
    ADD COLUMN payload_pruned_at TIMESTAMPTZ,
    -- Existing rows have no evidence yet; the Rust expiry sweep classifies each
    -- once. Every new row carries its evidence from insert.
    ADD COLUMN evidence_pending BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE chat.direct_request_transport_entries
    ALTER COLUMN evidence_pending SET DEFAULT FALSE;

DROP TRIGGER direct_request_transport_entries_immutable_trigger
    ON chat.direct_request_transport_entries;

UPDATE chat.direct_request_transport_entries
   SET original_entry_sha256 = digest(entry_bytes, 'sha256');

ALTER TABLE chat.direct_request_transport_entries
    ALTER COLUMN original_entry_sha256 SET NOT NULL,
    ADD CONSTRAINT transport_original_entry_sha256_check
        CHECK (octet_length(original_entry_sha256) = 32),
    ADD CONSTRAINT transport_application_evidence_check CHECK (
        (application_message_id IS NULL AND application_request_sha256 IS NULL
            AND application_metadata_bytes IS NULL AND application_generation IS NULL
            AND pruned_entry_bytes IS NULL AND payload_pruned_at IS NULL)
        OR (NOT evidence_pending
            AND application_message_id IS NOT NULL AND chat.is_uuid_v4(application_message_id)
            AND octet_length(application_request_sha256) = 32
            AND octet_length(application_metadata_bytes) BETWEEN 1 AND 16777216
            AND chat.is_safe_integer(application_generation)
            AND octet_length(pruned_entry_bytes) BETWEEN 1 AND 16777216
            AND (payload_pruned_at IS NULL OR entry_bytes = pruned_entry_bytes))
    );

CREATE INDEX transport_application_message_idx
    ON chat.direct_request_transport_entries (conversation_id, application_message_id)
    WHERE application_message_id IS NOT NULL;

-- Every writer, including bootstrap and C33, freezes the same original digest.
CREATE FUNCTION chat.capture_transport_entry_evidence()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.evidence_pending OR NEW.payload_pruned_at IS NOT NULL THEN
        RAISE EXCEPTION 'new transport entries must carry evidence and their original payload'
            USING ERRCODE = '23514';
    END IF;
    NEW.original_entry_sha256 := digest(NEW.entry_bytes, 'sha256');
    RETURN NEW;
END;
$$;

CREATE TRIGGER transport_entry_capture_evidence
BEFORE INSERT ON chat.direct_request_transport_entries
FOR EACH ROW EXECUTE FUNCTION chat.capture_transport_entry_evidence();

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_entries_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    evidence CONSTANT TEXT[] := ARRAY['application_message_id', 'application_request_sha256',
        'application_metadata_bytes', 'application_generation', 'pruned_entry_bytes',
        'evidence_pending'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'transport entries are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    -- A pre-migration row records its evidence exactly once and is not yet pruned.
    IF OLD.evidence_pending AND NOT NEW.evidence_pending AND NEW.payload_pruned_at IS NULL
       AND (to_jsonb(NEW) - evidence) IS NOT DISTINCT FROM (to_jsonb(OLD) - evidence) THEN
        RETURN NEW;
    END IF;
    -- Otherwise only the insert-captured projection may replace the ciphertext, once.
    IF OLD.evidence_pending
       OR OLD.application_message_id IS NULL
       OR OLD.payload_pruned_at IS NOT NULL
       OR NEW.payload_pruned_at IS NULL
       OR NEW.entry_bytes IS DISTINCT FROM OLD.pruned_entry_bytes
       OR (to_jsonb(NEW) - ARRAY['entry_bytes', 'payload_pruned_at'])
          IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['entry_bytes', 'payload_pruned_at']) THEN
        RAISE EXCEPTION 'transport entries permit only irreversible application ciphertext pruning'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER direct_request_transport_entries_immutable_trigger
BEFORE UPDATE OR DELETE ON chat.direct_request_transport_entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_transport_entries_immutable();

-- C33 homes deliberately have an inbox but no conversations row. The ACK handler
-- locks and authorizes the exact conversation/inbox before writing this watermark;
-- the device FK is retained, and the I14 wipe already deletes these ACKs explicitly.
ALTER TABLE chat.device_entry_acks
    DROP CONSTRAINT device_entry_acks_conversation_id_fkey;

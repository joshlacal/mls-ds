-- O7 for operation receipts. A completed `sendMessage` keeps its exact request
-- and response in `chat.idempotency_records`, so each receipt held the message's
-- MLS application ciphertext three times (`accepted_request_bytes`,
-- `signing_transcript_bytes`, `response_bytes`) after every other copy was
-- pruned. Each prune of that ciphertext now erases those three columns in the
-- same transaction, once and irreversibly. The receipt keeps its identity,
-- `request_digest`, `response_sha256`, signature, status, event position, JKTs
-- and completion time; its operation claim keeps the accepted-request digest
-- and mutation kind. An erased receipt replays as `IdempotencyConflict`.
--
-- `sendMessage` is the only receipt endpoint whose request or response carries
-- application ciphertext: `publishDirectRequest` keeps no row here, and its
-- signed outcome receipt (`chat.direct_request_attempts.terminal_response`)
-- holds digests and the I13 receipt only.

ALTER TABLE chat.idempotency_records
    ADD COLUMN payload_erased_at TIMESTAMPTZ,
    ALTER COLUMN accepted_request_bytes DROP NOT NULL,
    ALTER COLUMN signing_transcript_bytes DROP NOT NULL,
    ALTER COLUMN response_bytes DROP NOT NULL;

-- Each branch is definite (never NULL), so a nulled column cannot pass a check
-- by making it unknown.
ALTER TABLE chat.idempotency_records
    DROP CONSTRAINT idempotency_records_payload_sizes_check,
    ADD CONSTRAINT idempotency_records_payload_sizes_check CHECK (
        (payload_erased_at IS NULL
            AND accepted_request_bytes IS NOT NULL
            AND signing_transcript_bytes IS NOT NULL
            AND response_bytes IS NOT NULL
            AND octet_length(accepted_request_bytes) BETWEEN 1 AND 16777216
            AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
            AND octet_length(response_bytes) BETWEEN 1 AND 16777216
            AND signature IS NOT NULL AND octet_length(signature) = 64)
        OR (payload_erased_at IS NOT NULL
            AND endpoint_nsid = 'blue.catbird.chat.sendMessage'
            AND accepted_request_bytes IS NULL
            AND signing_transcript_bytes IS NULL
            AND response_bytes IS NULL
            AND signature IS NOT NULL AND octet_length(signature) = 64)
    ),
    DROP CONSTRAINT idempotency_records_hashes_check,
    ADD CONSTRAINT idempotency_records_hashes_check CHECK (
        (payload_erased_at IS NULL
            AND signing_transcript_bytes IS NOT NULL
            AND response_bytes IS NOT NULL
            AND octet_length(request_digest) = 32
            AND request_digest = digest(signing_transcript_bytes, 'sha256')
            AND octet_length(response_sha256) = 32
            AND response_sha256 = digest(response_bytes, 'sha256')
            AND (signature IS NULL OR octet_length(signature) = 64))
        OR (payload_erased_at IS NOT NULL
            AND endpoint_nsid = 'blue.catbird.chat.sendMessage'
            AND signing_transcript_bytes IS NULL
            AND response_bytes IS NULL
            AND octet_length(request_digest) = 32
            AND octet_length(response_sha256) = 32
            AND (signature IS NULL OR octet_length(signature) = 64))
    );

-- The only permitted change is the one-way erasure: the three payload columns
-- become NULL and `payload_erased_at` is set, every other column identical. An
-- erased receipt never changes again, and none is inserted already erased, so
-- each was once complete and checked against its claim. Deletes keep the
-- generic rule. NEW's stored generated claim-key columns are still NULL in a
-- BEFORE trigger; the base columns they derive from are compared.
CREATE FUNCTION chat.enforce_idempotency_record_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    ignored_cols CONSTANT TEXT[] := ARRAY['accepted_request_bytes',
        'signing_transcript_bytes', 'response_bytes', 'payload_erased_at',
        'operation_claim_fk_operation_id', 'operation_claim_fk_principal_did',
        'operation_claim_fk_endpoint_nsid'];
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.payload_erased_at IS NOT NULL THEN
            RAISE EXCEPTION 'a receipt cannot be inserted already erased'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable chat row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - ignored_cols) IS DISTINCT FROM (to_jsonb(OLD) - ignored_cols) THEN
        RAISE EXCEPTION 'immutable chat identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.accepted_request_bytes, NEW.signing_transcript_bytes, NEW.response_bytes,
        NEW.payload_erased_at)
       IS DISTINCT FROM
       (OLD.accepted_request_bytes, OLD.signing_transcript_bytes, OLD.response_bytes,
        OLD.payload_erased_at)
       AND NOT (OLD.payload_erased_at IS NULL
                AND NEW.payload_erased_at IS NOT NULL
                AND NEW.accepted_request_bytes IS NULL
                AND NEW.signing_transcript_bytes IS NULL
                AND NEW.response_bytes IS NULL) THEN
        RAISE EXCEPTION 'only an unerased receipt may lose its payload, once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER idempotency_records_immutable ON chat.idempotency_records;
CREATE TRIGGER idempotency_records_immutable
BEFORE INSERT OR UPDATE OR DELETE ON chat.idempotency_records
FOR EACH ROW EXECUTE FUNCTION chat.enforce_idempotency_record_immutable();

-- An erased receipt cannot re-derive its accepted-request digest or kinds; it is
-- bound to its claim by the digests and signature it retains, and to the kind
-- its claim recorded when the full payload was checked at completion.
CREATE OR REPLACE FUNCTION chat.assert_operation_claim_mapping(target_operation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    claim_count BIGINT;
    receipt_count BIGINT;
    receipt_required BOOLEAN;
    receipt_completed_at TIMESTAMPTZ;
    activation_cutover TIMESTAMPTZ;
    claimed_kind TEXT;
    wrapper_kind TEXT;
    transcript_kind TEXT;
    accepted_endpoint TEXT;
    endpoint_accepts_kind BOOLEAN;
BEGIN
    SELECT count(*) INTO claim_count
      FROM chat.operation_claims
     WHERE operation_id = target_operation;

    SELECT count(*) INTO receipt_count
      FROM chat.idempotency_records
     WHERE operation_id = target_operation;

    IF claim_count = 0 AND receipt_count = 0 THEN
        RETURN;
    END IF;

    IF claim_count = 0 AND receipt_count = 1 THEN
        SELECT operation_claim_required,completed_at
          INTO STRICT receipt_required,receipt_completed_at
          FROM chat.idempotency_records
         WHERE operation_id = target_operation;

        SELECT cutover_at
          INTO STRICT activation_cutover
          FROM chat.operation_claim_completeness_cutover
         WHERE singleton;

        IF NOT receipt_required
           AND receipt_completed_at <= activation_cutover THEN
            RETURN;
        END IF;

        RAISE EXCEPTION 'post-cutover receipt requires an operation claim'
            USING ERRCODE = '23514';
    END IF;

    IF claim_count <> 1 OR receipt_count <> 1 THEN
        RAISE EXCEPTION 'operation claim/receipt mapping mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT
        receipt.operation_claim_required,
        claim.mutation_kind,
        receipt.endpoint_nsid,
        CASE WHEN receipt.payload_erased_at IS NULL
             THEN chat.operation_mutation_kind_from_wrapper(receipt.accepted_request_bytes)
             ELSE claim.mutation_kind
        END,
        CASE WHEN receipt.payload_erased_at IS NULL
             THEN chat.operation_mutation_kind_from_transcript(receipt.signing_transcript_bytes)
             ELSE claim.mutation_kind
        END
      INTO
        receipt_required,
        claimed_kind,
        accepted_endpoint,
        wrapper_kind,
        transcript_kind
      FROM chat.operation_claims claim
      JOIN chat.idempotency_records receipt
        ON receipt.operation_id = claim.operation_id
       AND receipt.principal_did = claim.principal_did
       AND receipt.endpoint_nsid = claim.endpoint_nsid
       AND receipt.request_digest = claim.request_digest
       AND (receipt.payload_erased_at IS NOT NULL
            OR digest(receipt.accepted_request_bytes, 'sha256')
               = claim.accepted_request_sha256)
       AND receipt.signature = claim.signature
     WHERE claim.operation_id = target_operation;

    IF receipt_required IS DISTINCT FROM TRUE
       OR claimed_kind IS NULL
       OR wrapper_kind IS NULL
       OR transcript_kind IS NULL THEN
        RAISE EXCEPTION 'operation claim/receipt authority mismatch'
            USING ERRCODE = '23514';
    END IF;

    endpoint_accepts_kind :=
        chat.operation_endpoint_accepts_kind(
            accepted_endpoint,
            transcript_kind
        );

    IF claimed_kind <> wrapper_kind
       OR claimed_kind <> transcript_kind
       OR wrapper_kind <> transcript_kind
       OR NOT endpoint_accepts_kind THEN
        RAISE EXCEPTION 'operation claim mutation kind mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- The 30-day sweep erases every unerased receipt it reaches by completion time,
-- including one whose entry a close wiped or an earlier release pruned.
CREATE INDEX idempotency_records_unerased_send_idx
    ON chat.idempotency_records (completed_at)
    WHERE endpoint_nsid = 'blue.catbird.chat.sendMessage' AND payload_erased_at IS NULL;

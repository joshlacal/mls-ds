-- Refine the initial endpoint-family classifier to the exact signed mutation
-- arm. 00001 is already applied in one gate database and remains immutable.

DROP TRIGGER operation_claims_immutable ON chat.operation_claims;

ALTER TABLE chat.operation_claims
    DROP CONSTRAINT operation_claims_mutation_kind_check;

-- Staged rollout: existing handlers still write completed receipts without a
-- claim. Keep receipt->claim optional until every handler uses the prelude.
-- Claim->exact receipt remains deferred and mandatory below.
ALTER TABLE chat.idempotency_records
    DROP CONSTRAINT idempotency_records_operation_claim_fk;

-- PostgreSQL json/jsonb cannot represent U+0000, while every canonical
-- signatureDomain deliberately ends in NUL. Classify the exact signed arm
-- from the bytea transcript domain prefix instead of decoding wrapper JSON.
CREATE FUNCTION chat.transcript_has_exact_domain(transcript BYTEA, domain TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT octet_length(transcript)
               > octet_length(convert_to(domain,'UTF8') || decode('00','hex'))
       AND substring(
               transcript FROM 1
               FOR octet_length(convert_to(domain,'UTF8') || decode('00','hex'))
           ) = convert_to(domain,'UTF8') || decode('00','hex')
$$;

CREATE FUNCTION chat.operation_mutation_kind_from_transcript(transcript BYTEA)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-ENROLL') THEN 'blue.catbird.chat.defs#deviceEnrollmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REPLENISH') THEN 'blue.catbird.chat.defs#keyPackageReplenishmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REBIND') THEN 'blue.catbird.chat.defs#deviceAuthenticationRebindBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REVOKE') THEN 'blue.catbird.chat.defs#deviceRevocationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-BLOB-PREPARE') THEN 'blue.catbird.chat.defs#blobUploadPreparationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-BLOB-DELETE') THEN 'blue.catbird.chat.defs#blobDeletionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-CREATE') THEN 'blue.catbird.chat.defs#creationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-COMMIT') THEN 'blue.catbird.chat.defs#commitTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-POLICY') THEN 'blue.catbird.chat.defs#policyTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-ACCEPT') THEN 'blue.catbird.chat.defs#participantAcceptanceBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-MESSAGE') THEN 'blue.catbird.chat.defs#applicationSendBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-TYPING') THEN 'blue.catbird.chat.defs#typingBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-METADATA') THEN 'blue.catbird.chat.defs#metadataTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-RESET-REQUEST') THEN 'blue.catbird.chat.defs#resetRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-RESET-ACTIVATE') THEN 'blue.catbird.chat.defs#resetActivationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-REQUEST') THEN 'blue.catbird.chat.defs#leafRecoveryRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-CANCEL') THEN 'blue.catbird.chat.defs#leafRecoveryCancellationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-FULFILL') THEN 'blue.catbird.chat.defs#leafRecoveryFulfillmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-CLOSE') THEN 'blue.catbird.chat.defs#conversationCloseBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-REQUEST') THEN 'blue.catbird.chat.defs#leaveRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-ZERO-LEAF') THEN 'blue.catbird.chat.defs#zeroLeafLeaveBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-CANCEL') THEN 'blue.catbird.chat.defs#leaveCancellationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-FULFILL-COMMIT') THEN 'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-WELCOME-ACK') THEN 'blue.catbird.chat.defs#welcomeAcknowledgementBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-WELCOME-REJECT') THEN 'blue.catbird.chat.defs#welcomeRejectionBody'
        ELSE NULL
    END
$$;

-- accepted_request_bytes is the exact signed wrapper that passed the closed
-- Rust decoder. PostgreSQL json (unlike jsonb) preserves duplicate keys, so
-- json_each can count the decoded root/body authority fields exactly. Before
-- parsing, rewrite only semantic JSON \u0000 escapes to \u0001: the signature
-- domain is not read here, the replacement preserves byte length, and runs of
-- escaped backslashes such as "\\u0000" remain literal text. Any malformed
-- UTF-8/JSON, wrong container shape, duplicate body/$type, or non-string $type
-- fails closed through the exception handler.
CREATE FUNCTION chat.exact_wrapper_body_type(wrapper BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    sanitized BYTEA := wrapper;
    cursor INTEGER := 0;
    length INTEGER := octet_length(wrapper);
    slash_start INTEGER;
    slash_count INTEGER;
    document JSON;
    body_value JSON;
    type_value JSON;
    body_count BIGINT;
    type_count BIGINT;
BEGIN
    WHILE cursor < length LOOP
        IF get_byte(wrapper,cursor) <> 92 THEN
            cursor := cursor + 1;
            CONTINUE;
        END IF;
        slash_start := cursor;
        WHILE cursor < length
          AND get_byte(wrapper,cursor) = 92 LOOP
            cursor := cursor + 1;
        END LOOP;
        slash_count := cursor - slash_start;
        IF (slash_count % 2) = 1
           AND cursor + 4 < length
           AND get_byte(wrapper,cursor) = 117
           AND get_byte(wrapper,cursor + 1) = 48
           AND get_byte(wrapper,cursor + 2) = 48
           AND get_byte(wrapper,cursor + 3) = 48
           AND get_byte(wrapper,cursor + 4) = 48 THEN
            sanitized := set_byte(sanitized,cursor + 4,49);
        END IF;
    END LOOP;

    document := convert_from(sanitized,'UTF8')::json;
    SELECT count(*), min(value::text)::json
      INTO body_count, body_value
      FROM json_each(document)
     WHERE key = 'body';
    IF body_count <> 1 OR json_typeof(body_value) <> 'object' THEN
        RETURN NULL;
    END IF;

    SELECT count(*), min(value::text)::json
      INTO type_count, type_value
      FROM json_each(body_value)
     WHERE key = '$type';
    IF type_count <> 1 OR json_typeof(type_value) <> 'string' THEN
        RETURN NULL;
    END IF;

    RETURN type_value #>> '{}';
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END
$$;

CREATE FUNCTION chat.operation_mutation_kind_from_wrapper(wrapper BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    exact_type TEXT := chat.exact_wrapper_body_type(wrapper);
BEGIN
    RETURN CASE
        WHEN exact_type = 'blue.catbird.chat.defs#deviceEnrollmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#keyPackageReplenishmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#deviceAuthenticationRebindBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#deviceRevocationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#blobUploadPreparationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#blobDeletionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#creationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#commitTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#policyTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#participantAcceptanceBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#applicationSendBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#typingBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#metadataTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#resetRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#resetActivationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryCancellationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryFulfillmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#conversationCloseBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#zeroLeafLeaveBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveCancellationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveCommitFulfillmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#welcomeAcknowledgementBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#welcomeRejectionBody' THEN exact_type
        ELSE NULL
    END;
END
$$;

CREATE FUNCTION chat.operation_endpoint_accepts_kind(endpoint TEXT, kind TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE endpoint
        WHEN 'blue.catbird.chat.acceptConversation' THEN kind = 'blue.catbird.chat.defs#participantAcceptanceBody'
        WHEN 'blue.catbird.chat.acknowledgeWelcome' THEN kind = 'blue.catbird.chat.defs#welcomeAcknowledgementBody'
        WHEN 'blue.catbird.chat.activateReset' THEN kind = 'blue.catbird.chat.defs#resetActivationBody'
        WHEN 'blue.catbird.chat.cancelLeafRecovery' THEN kind = 'blue.catbird.chat.defs#leafRecoveryCancellationBody'
        WHEN 'blue.catbird.chat.cancelLeave' THEN kind = 'blue.catbird.chat.defs#leaveCancellationBody'
        WHEN 'blue.catbird.chat.closeConversation' THEN kind = 'blue.catbird.chat.defs#conversationCloseBody'
        WHEN 'blue.catbird.chat.createConversation' THEN kind = 'blue.catbird.chat.defs#creationBody'
        WHEN 'blue.catbird.chat.deleteBlob' THEN kind = 'blue.catbird.chat.defs#blobDeletionBody'
        WHEN 'blue.catbird.chat.enrollDevice' THEN kind = 'blue.catbird.chat.defs#deviceEnrollmentBody'
        WHEN 'blue.catbird.chat.prepareBlobUpload' THEN kind = 'blue.catbird.chat.defs#blobUploadPreparationBody'
        WHEN 'blue.catbird.chat.rebindDeviceAuthentication' THEN kind = 'blue.catbird.chat.defs#deviceAuthenticationRebindBody'
        WHEN 'blue.catbird.chat.rejectWelcome' THEN kind = 'blue.catbird.chat.defs#welcomeRejectionBody'
        WHEN 'blue.catbird.chat.replenishKeyPackages' THEN kind = 'blue.catbird.chat.defs#keyPackageReplenishmentBody'
        WHEN 'blue.catbird.chat.requestLeafRecovery' THEN kind = 'blue.catbird.chat.defs#leafRecoveryRequestBody'
        WHEN 'blue.catbird.chat.requestLeave' THEN kind = 'blue.catbird.chat.defs#leaveRequestBody'
        WHEN 'blue.catbird.chat.requestReset' THEN kind = 'blue.catbird.chat.defs#resetRequestBody'
        WHEN 'blue.catbird.chat.revokeDevice' THEN kind = 'blue.catbird.chat.defs#deviceRevocationBody'
        WHEN 'blue.catbird.chat.sendMessage' THEN kind = 'blue.catbird.chat.defs#applicationSendBody'
        WHEN 'blue.catbird.chat.publishTyping' THEN kind = 'blue.catbird.chat.defs#typingBody'
        WHEN 'blue.catbird.chat.submitTransition' THEN kind = ANY (ARRAY[
            'blue.catbird.chat.defs#commitTransitionBody',
            'blue.catbird.chat.defs#policyTransitionBody',
            'blue.catbird.chat.defs#metadataTransitionBody',
            'blue.catbird.chat.defs#leafRecoveryFulfillmentBody',
            'blue.catbird.chat.defs#zeroLeafLeaveBody',
            'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        ])
        ELSE FALSE
    END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chat.operation_claims claim
          LEFT JOIN chat.idempotency_records receipt
            ON receipt.operation_id = claim.operation_id
           AND receipt.principal_did = claim.principal_did
           AND receipt.endpoint_nsid = claim.endpoint_nsid
           AND receipt.request_digest = claim.request_digest
           AND digest(receipt.accepted_request_bytes, 'sha256')
               = claim.accepted_request_sha256
           AND receipt.signature = claim.signature
         WHERE receipt.operation_id IS NULL
            OR chat.operation_mutation_kind_from_wrapper(
                   receipt.accepted_request_bytes
               ) IS NULL
            OR chat.operation_mutation_kind_from_transcript(
                   receipt.signing_transcript_bytes
               ) IS NULL
            OR chat.operation_mutation_kind_from_wrapper(
                   receipt.accepted_request_bytes
               ) <> chat.operation_mutation_kind_from_transcript(
                   receipt.signing_transcript_bytes
               )
            OR NOT chat.operation_endpoint_accepts_kind(
                   receipt.endpoint_nsid,
                   chat.operation_mutation_kind_from_transcript(
                       receipt.signing_transcript_bytes
                   )
               )
    ) THEN
        RAISE EXCEPTION 'cannot refine invalid operation claim material'
            USING ERRCODE = '23514';
    END IF;
END
$$;

UPDATE chat.operation_claims claim
   SET mutation_kind =
       chat.operation_mutation_kind_from_transcript(receipt.signing_transcript_bytes)
  FROM chat.idempotency_records receipt
 WHERE receipt.operation_id = claim.operation_id;

ALTER TABLE chat.operation_claims
    ADD CONSTRAINT operation_claims_mutation_kind_check CHECK (
        chat.operation_endpoint_accepts_kind(endpoint_nsid,mutation_kind)
    );

CREATE OR REPLACE FUNCTION chat.assert_operation_claim_mapping(target_operation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    claim_count BIGINT;
    receipt_count BIGINT;
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

    -- Legacy receipt-only rows remain temporarily valid during handler
    -- migration. A claim, however, must map to exactly one exact receipt.
    IF claim_count = 0 THEN
        RETURN;
    END IF;

    IF claim_count <> 1 OR receipt_count <> 1 THEN
        RAISE EXCEPTION 'operation claim/receipt mapping mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT
        claim.mutation_kind,
        receipt.endpoint_nsid,
        chat.operation_mutation_kind_from_wrapper(
            receipt.accepted_request_bytes
        ),
        chat.operation_mutation_kind_from_transcript(
            receipt.signing_transcript_bytes
        )
      INTO claimed_kind, accepted_endpoint, wrapper_kind, transcript_kind
      FROM chat.operation_claims claim
      JOIN chat.idempotency_records receipt
        ON receipt.operation_id = claim.operation_id
       AND receipt.principal_did = claim.principal_did
       AND receipt.endpoint_nsid = claim.endpoint_nsid
       AND receipt.request_digest = claim.request_digest
       AND digest(receipt.accepted_request_bytes, 'sha256')
           = claim.accepted_request_sha256
       AND receipt.signature = claim.signature
     WHERE claim.operation_id = target_operation;

    IF claimed_kind IS NULL
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

CREATE TRIGGER operation_claims_immutable
BEFORE UPDATE OR DELETE ON chat.operation_claims
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Operation-claim completeness activation. This reviewed source mirrors
-- 20260728000004_activate_operation_claim_completeness.sql byte-for-byte.
--
-- DO NOT ACTIVATE merely because the database tests are green. Before freezing
-- this file, all three formerly receipt-only handlers:
--
--   blue.catbird.chat.enrollDevice
--   blue.catbird.chat.rebindDeviceAuthentication
--   blue.catbird.chat.replenishKeyPackages
--
-- must use the shared operation prelude. The formerly receipt-only handlers
-- previously relied on these staged repository bypasses:
--
--   arbitrate_business_idempotency
--   recheck_business_authority
--   record_completed_idempotency
--
-- They must remain removed or unreachable outside the shared prelude. Until then,
-- operation-claim completeness is staged, not globally enforced.
--
-- The activation deliberately preserves existing receipt-only rows as bounded,
-- immutable legacy orphans. It never invents claim authority from handler output.
-- SQLx owns the migration transaction; this body must not nest BEGIN/COMMIT.

-- This operator gate makes the code-migration prerequisite explicit in the
-- executable artifact. Check it before taking disruptive table locks. The
-- forward migration runner must set it deliberately.
DO $$
BEGIN
    IF current_setting(
        'chat.operation_claim_activation_approved',
        true
    ) IS DISTINCT FROM 'handlers-and-legacy-apis-sealed' THEN
        RAISE EXCEPTION
            'operation-claim activation requires migrated handlers and sealed legacy APIs'
            USING ERRCODE = '55000';
    END IF;
END
$$;

-- Drain every operation-claim and receipt writer before choosing the cutover.
-- SQLx keeps both locks until its migration transaction commits, so no receipt
-- can cross the watermark.
LOCK TABLE chat.operation_claims IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chat.idempotency_records IN ACCESS EXCLUSIVE MODE;

-- Correct the immutable 00002 endpoint-family mapping without rewriting its
-- installed bytes. Zero-leaf leave is a requestLeave mutation; it is not a
-- submitTransition mutation.
CREATE OR REPLACE FUNCTION chat.operation_endpoint_accepts_kind(endpoint TEXT, kind TEXT)
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
        WHEN 'blue.catbird.chat.requestLeave' THEN kind = ANY (ARRAY[
            'blue.catbird.chat.defs#leaveRequestBody',
            'blue.catbird.chat.defs#zeroLeafLeaveBody'
        ])
        WHEN 'blue.catbird.chat.requestReset' THEN kind = 'blue.catbird.chat.defs#resetRequestBody'
        WHEN 'blue.catbird.chat.revokeDevice' THEN kind = 'blue.catbird.chat.defs#deviceRevocationBody'
        WHEN 'blue.catbird.chat.sendMessage' THEN kind = 'blue.catbird.chat.defs#applicationSendBody'
        WHEN 'blue.catbird.chat.publishTyping' THEN kind = 'blue.catbird.chat.defs#typingBody'
        WHEN 'blue.catbird.chat.submitTransition' THEN kind = ANY (ARRAY[
            'blue.catbird.chat.defs#commitTransitionBody',
            'blue.catbird.chat.defs#policyTransitionBody',
            'blue.catbird.chat.defs#metadataTransitionBody',
            'blue.catbird.chat.defs#leafRecoveryFulfillmentBody',
            'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        ])
        ELSE FALSE
    END
$$;

CREATE TABLE chat.operation_claim_completeness_cutover (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    cutover_at TIMESTAMPTZ NOT NULL,
    legacy_receipt_count BIGINT NOT NULL CHECK (legacy_receipt_count >= 0),
    legacy_receipt_set_sha256 BYTEA NOT NULL
        CHECK (octet_length(legacy_receipt_set_sha256) = 32)
);

-- PRE-FK PREFLIGHT 1: claims already assert authority, so every existing claim
-- must have one exact receipt before any legacy-orphan classification occurs.
DO $$
DECLARE
    invalid_operation UUID;
BEGIN
    SELECT claim.operation_id
      INTO invalid_operation
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
        OR claim.mutation_kind IS DISTINCT FROM
           chat.operation_mutation_kind_from_wrapper(
               receipt.accepted_request_bytes
           )
        OR claim.mutation_kind IS DISTINCT FROM
           chat.operation_mutation_kind_from_transcript(
               receipt.signing_transcript_bytes
           )
        OR NOT chat.operation_endpoint_accepts_kind(
            receipt.endpoint_nsid,
            claim.mutation_kind
        )
     LIMIT 1;

    IF invalid_operation IS NOT NULL THEN
        RAISE EXCEPTION
            'operation-claim activation preflight failed for operation %',
            invalid_operation
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Record the only authority boundary for legacy receipt-only rows while both
-- writer tables remain exclusively locked.
INSERT INTO chat.operation_claim_completeness_cutover (
    singleton,
    cutover_at,
    legacy_receipt_count,
    legacy_receipt_set_sha256
)
SELECT
    TRUE,
    clock_timestamp(),
    count(*),
    digest(
        convert_to('CATBIRD-CHAT-LEGACY-RECEIPT-SET','UTF8')
        || decode('00','hex')
        || convert_to(
            coalesce(
                string_agg(receipt.operation_id::text, ',' ORDER BY receipt.operation_id),
                ''
            ),
            'UTF8'
        ),
        'sha256'
    )
  FROM chat.idempotency_records receipt
  LEFT JOIN chat.operation_claims claim
    ON claim.operation_id = receipt.operation_id
 WHERE claim.operation_id IS NULL;

CREATE TRIGGER operation_claim_completeness_cutover_immutable
BEFORE UPDATE OR DELETE ON chat.operation_claim_completeness_cutover
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

ALTER TABLE chat.idempotency_records
    ADD COLUMN operation_claim_required BOOLEAN;

-- The table is immutable in normal operation. Temporarily remove exactly that
-- trigger while the exclusive lock protects the one-time classification.
DROP TRIGGER idempotency_records_immutable ON chat.idempotency_records;

UPDATE chat.idempotency_records receipt
   SET operation_claim_required = EXISTS (
       SELECT 1
         FROM chat.operation_claims claim
        WHERE claim.operation_id = receipt.operation_id
   );

-- A populated classification UPDATE queues both existing INITIALLY DEFERRED
-- row-integrity triggers. PostgreSQL refuses the generated-column ALTER below
-- while those events are pending, so drain exactly those two constraints after
-- classification and then restore their original deferred mode.
SET CONSTRAINTS
    chat.idempotency_records_operation_claim_mapping_deferred,
    chat.idempotency_records_revocation_mapping_deferred
IMMEDIATE;
SET CONSTRAINTS
    chat.idempotency_records_operation_claim_mapping_deferred,
    chat.idempotency_records_revocation_mapping_deferred
DEFERRED;

ALTER TABLE chat.idempotency_records
    ALTER COLUMN operation_claim_required SET NOT NULL,
    ALTER COLUMN operation_claim_required SET DEFAULT TRUE,
    ADD COLUMN operation_claim_fk_operation_id UUID
        GENERATED ALWAYS AS (
            CASE WHEN operation_claim_required THEN operation_id END
        ) STORED,
    ADD COLUMN operation_claim_fk_principal_did TEXT
        GENERATED ALWAYS AS (
            CASE WHEN operation_claim_required THEN principal_did END
        ) STORED,
    ADD COLUMN operation_claim_fk_endpoint_nsid TEXT
        GENERATED ALWAYS AS (
            CASE WHEN operation_claim_required THEN endpoint_nsid END
        ) STORED;

-- A NOT VALID CHECK is enforced for every later INSERT/UPDATE, but does not
-- scan and reject the already-classified legacy FALSE rows. Callers therefore
-- cannot supply FALSE to null the generated FK projection after cutover. This
-- constraint intentionally remains unvalidated for the life of those orphans.
ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_operation_claim_required_after_cutover
        CHECK (operation_claim_required)
        NOT VALID;

CREATE TRIGGER idempotency_records_immutable
BEFORE UPDATE OR DELETE ON chat.idempotency_records
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- PRE-FK PREFLIGHT 2: prove that every required receipt has an exact claim and
-- every exception is an actually pre-cutover receipt-only row. No INSERT into
-- chat.operation_claims is permitted during activation.
DO $$
DECLARE
    invalid_operation UUID;
    classified_legacy_count BIGINT;
    recorded_legacy_count BIGINT;
    classified_legacy_set_sha256 BYTEA;
    recorded_legacy_set_sha256 BYTEA;
BEGIN
    SELECT
        count(*),
        digest(
            convert_to('CATBIRD-CHAT-LEGACY-RECEIPT-SET','UTF8')
            || decode('00','hex')
            || convert_to(
                coalesce(
                    string_agg(receipt.operation_id::text, ',' ORDER BY receipt.operation_id),
                    ''
                ),
                'UTF8'
            ),
            'sha256'
        )
      INTO classified_legacy_count,classified_legacy_set_sha256
      FROM chat.idempotency_records receipt
     WHERE NOT receipt.operation_claim_required;

    SELECT legacy_receipt_count,legacy_receipt_set_sha256
      INTO STRICT recorded_legacy_count,recorded_legacy_set_sha256
      FROM chat.operation_claim_completeness_cutover
     WHERE singleton;

    IF classified_legacy_count <> recorded_legacy_count
       OR classified_legacy_set_sha256 <> recorded_legacy_set_sha256 THEN
        RAISE EXCEPTION
            'operation-claim legacy classification set mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT receipt.operation_id
      INTO invalid_operation
      FROM chat.idempotency_records receipt
      CROSS JOIN chat.operation_claim_completeness_cutover cutover
      LEFT JOIN chat.operation_claims claim
        ON claim.operation_id = receipt.operation_id
       AND claim.principal_did = receipt.principal_did
       AND claim.endpoint_nsid = receipt.endpoint_nsid
     WHERE (
         receipt.operation_claim_required
         AND claim.operation_id IS NULL
     ) OR (
         NOT receipt.operation_claim_required
         AND (
             claim.operation_id IS NOT NULL
             OR receipt.completed_at > cutover.cutover_at
         )
     )
     LIMIT 1;

    IF invalid_operation IS NOT NULL THEN
        RAISE EXCEPTION
            'operation-claim legacy classification failed for operation %',
            invalid_operation
            USING ERRCODE = '23514';
    END IF;
END
$$;

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
        chat.operation_mutation_kind_from_wrapper(
            receipt.accepted_request_bytes
        ),
        chat.operation_mutation_kind_from_transcript(
            receipt.signing_transcript_bytes
        )
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
       AND digest(receipt.accepted_request_bytes, 'sha256')
           = claim.accepted_request_sha256
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

-- MATCH FULL prevents a partially-null projection. NOT VALID is intentional:
-- add the relationship only after both explicit preflights, then ask PostgreSQL
-- to perform its own complete validation before SQLx commits the activation.
ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_operation_claim_fk
        FOREIGN KEY (
            operation_claim_fk_operation_id,
            operation_claim_fk_principal_did,
            operation_claim_fk_endpoint_nsid
        )
        REFERENCES chat.operation_claims (
            operation_id,
            principal_did,
            endpoint_nsid
        )
        MATCH FULL
        NOT VALID;

ALTER TABLE chat.idempotency_records
    VALIDATE CONSTRAINT idempotency_records_operation_claim_fk;

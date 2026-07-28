-- One global namespace for clean-chat mutation operation IDs.
--
-- A claim is deliberately created in the same caller-owned transaction as
-- the business mutation. PostgreSQL rollback therefore releases both the row
-- and the transaction-scoped advisory lock; a failed first attempt never
-- burns an operation ID.

DO $$
BEGIN
    IF EXISTS (
        SELECT operation_id
          FROM chat.idempotency_records
         GROUP BY operation_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot establish global operation identity: duplicate completed operation_id'
            USING ERRCODE = '23505';
    END IF;
END
$$;

CREATE TABLE chat.operation_claims (
    operation_id UUID PRIMARY KEY,
    principal_did TEXT NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    mutation_kind TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    accepted_request_sha256 BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT operation_claims_principal_fk FOREIGN KEY (principal_did)
        REFERENCES chat.principals(user_did),
    CONSTRAINT operation_claims_identity_uq
        UNIQUE (operation_id, principal_did, endpoint_nsid),
    CONSTRAINT operation_claims_principal_did_check
        CHECK (chat.is_bare_did(principal_did)),
    CONSTRAINT operation_claims_operation_id_check
        CHECK (chat.is_uuid_v4(operation_id)),
    CONSTRAINT operation_claims_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.submitTransition'
        ])
    ),
    -- mutation_kind is an immutable protocol classifier. The initial
    -- repository slice uses the frozen endpoint NSID as that classifier;
    -- the request digest and accepted-wrapper hash bind the exact arm.
    CONSTRAINT operation_claims_mutation_kind_check
        CHECK (mutation_kind = endpoint_nsid),
    CONSTRAINT operation_claims_hashes_check CHECK (
        octet_length(request_digest) = 32
        AND octet_length(accepted_request_sha256) = 32
        AND octet_length(signature) = 64
    )
);

INSERT INTO chat.operation_claims (
    operation_id,
    principal_did,
    endpoint_nsid,
    mutation_kind,
    request_digest,
    accepted_request_sha256,
    signature,
    claimed_at
)
SELECT
    operation_id,
    principal_did,
    endpoint_nsid,
    endpoint_nsid,
    request_digest,
    digest(accepted_request_bytes, 'sha256'),
    signature,
    completed_at
  FROM chat.idempotency_records;

ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_operation_id_uq UNIQUE (operation_id),
    ADD CONSTRAINT idempotency_records_operation_claim_fk
        FOREIGN KEY (operation_id, principal_did, endpoint_nsid)
        REFERENCES chat.operation_claims (
            operation_id, principal_did, endpoint_nsid
        );

CREATE FUNCTION chat.assert_operation_claim_mapping(target_operation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    claim_count BIGINT;
    receipt_count BIGINT;
BEGIN
    SELECT count(*) INTO claim_count
      FROM chat.operation_claims
     WHERE operation_id = target_operation;

    SELECT count(*) INTO receipt_count
      FROM chat.idempotency_records
     WHERE operation_id = target_operation;

    IF claim_count <> receipt_count OR claim_count NOT IN (0, 1) THEN
        RAISE EXCEPTION 'operation claim/receipt mapping mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF claim_count = 1 AND NOT EXISTS (
        SELECT 1
          FROM chat.operation_claims claim
          JOIN chat.idempotency_records receipt
            ON receipt.operation_id = claim.operation_id
           AND receipt.principal_did = claim.principal_did
           AND receipt.endpoint_nsid = claim.endpoint_nsid
           AND receipt.request_digest = claim.request_digest
           AND digest(receipt.accepted_request_bytes, 'sha256')
               = claim.accepted_request_sha256
           AND receipt.signature = claim.signature
         WHERE claim.operation_id = target_operation
    ) THEN
        RAISE EXCEPTION 'operation claim/receipt authority mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_operation_claim_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_operation UUID;
    new_operation UUID;
BEGIN
    IF TG_OP <> 'INSERT' THEN old_operation := OLD.operation_id; END IF;
    IF TG_OP <> 'DELETE' THEN new_operation := NEW.operation_id; END IF;

    IF old_operation IS NOT NULL THEN
        PERFORM chat.assert_operation_claim_mapping(old_operation);
    END IF;
    IF new_operation IS NOT NULL
       AND new_operation IS DISTINCT FROM old_operation THEN
        PERFORM chat.assert_operation_claim_mapping(new_operation);
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER operation_claims_receipt_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.operation_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_operation_claim_mapping();

CREATE CONSTRAINT TRIGGER idempotency_records_operation_claim_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.idempotency_records
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_operation_claim_mapping();

CREATE TRIGGER operation_claims_immutable
BEFORE UPDATE OR DELETE ON chat.operation_claims
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

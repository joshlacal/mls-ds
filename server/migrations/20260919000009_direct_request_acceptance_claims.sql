-- Cover direct scoped INSERT as well as the normal once-only UPDATE path.
DROP TRIGGER inventory_request_scope_immutable ON chat.inventory_sessions;
CREATE TRIGGER inventory_request_scope_immutable BEFORE INSERT OR UPDATE ON chat.inventory_sessions
    FOR EACH ROW EXECUTE FUNCTION chat.guard_inventory_request_scope();

ALTER TABLE chat.direct_request_welcome_outcomes
    ADD CONSTRAINT direct_request_welcome_outcomes_nonnull_digest CHECK (
        status='expired' OR request_digest IS NOT NULL
    );

-- Acceptance has a distinct canonical operation ID. Retain exact response bytes
-- independently of later account/conversation lifecycle changes.
CREATE TABLE chat.direct_request_acceptance_claims (
    operation_id UUID PRIMARY KEY CHECK(chat.is_uuid_v4(operation_id)),
    request_id UUID NOT NULL UNIQUE REFERENCES chat.direct_request_publications(request_id),
    principal_did TEXT NOT NULL REFERENCES chat.principals(user_did),
    request_digest BYTEA NOT NULL CHECK(octet_length(request_digest)=32),
    accepted_request BYTEA NOT NULL CHECK(octet_length(accepted_request) BETWEEN 1 AND 16777216),
    signature BYTEA NOT NULL CHECK(octet_length(signature)=64),
    response_bytes BYTEA NOT NULL CHECK(octet_length(response_bytes) BETWEEN 1 AND 16777216),
    response_sha256 BYTEA NOT NULL CHECK(octet_length(response_sha256)=32 AND response_sha256=digest(response_bytes,'sha256')),
    recorded_at TIMESTAMPTZ NOT NULL,
    CHECK(operation_id<>request_id)
);
CREATE TRIGGER direct_request_acceptance_claims_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_acceptance_claims
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE OR REPLACE FUNCTION chat.guard_direct_request_operation_namespace() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE operation UUID;
BEGIN
    IF TG_TABLE_NAME='direct_request_attempts' THEN operation:=NEW.request_id;
    ELSE operation:=NEW.operation_id; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('chat-operation-id:'||operation::text,0));
    IF (TG_TABLE_NAME<>'operation_claims' AND EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=operation))
       OR (TG_TABLE_NAME<>'direct_request_attempts' AND EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=operation))
       OR (TG_TABLE_NAME<>'direct_request_key_publications' AND EXISTS(SELECT 1 FROM chat.direct_request_key_publications WHERE operation_id=operation))
       OR (TG_TABLE_NAME<>'direct_request_acceptance_claims' AND EXISTS(SELECT 1 FROM chat.direct_request_acceptance_claims WHERE operation_id=operation)) THEN
        RAISE EXCEPTION 'operation ID already belongs to another protocol mutation' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER direct_request_acceptance_operation_namespace BEFORE INSERT ON chat.direct_request_acceptance_claims
    FOR EACH ROW EXECUTE FUNCTION chat.guard_direct_request_operation_namespace();

CREATE FUNCTION chat.assert_direct_request_acceptance_claim(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE claim chat.direct_request_acceptance_claims%ROWTYPE;
        life chat.direct_request_lifecycle%ROWTYPE;
        response JSONB;
        request JSONB;
BEGIN
    SELECT * INTO claim FROM chat.direct_request_acceptance_claims WHERE request_id=target;
    SELECT * INTO life FROM chat.direct_request_lifecycle WHERE request_id=target;
    IF life.accepted_at IS NULL AND claim.operation_id IS NULL THEN RETURN; END IF;
    IF claim.operation_id IS NULL OR life.accepted_at IS NULL THEN
        RAISE EXCEPTION 'request consent and operation receipt must commit together' USING ERRCODE='23514';
    END IF;
    response := convert_from(claim.response_bytes,'UTF8')::jsonb;
    request := convert_from(claim.accepted_request,'UTF8')::jsonb;
    IF (claim.request_digest=life.acceptance_digest AND claim.recorded_at=life.accepted_at
        AND response->'acceptanceProof'=convert_from(life.acceptance_proof,'UTF8')::jsonb
        AND response->'coordinates'=response->'acceptanceProof'->'receipt'->'body'->'next'
        AND request=response->'acceptanceProof'->'entry'->'signedRequest'
        AND request->'body'->>'actorDid'=claim.principal_did
        AND request->'body'->>'requestId'=target::text
        AND request->'body'->>'idempotencyKey'=claim.operation_id::text
        AND request->'body'->>'transitionId'=claim.operation_id::text
        AND decode(request->>'signature','base64')=claim.signature) IS NOT TRUE THEN
        RAISE EXCEPTION 'request acceptance operation receipt mismatch' USING ERRCODE='23514';
    END IF;
END $$;
CREATE FUNCTION chat.enforce_direct_request_acceptance_claim() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM chat.assert_direct_request_acceptance_claim(NEW.request_id);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_acceptance_claim_graph AFTER INSERT ON chat.direct_request_acceptance_claims
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_acceptance_claim();
CREATE CONSTRAINT TRIGGER direct_request_acceptance_lifecycle_claim AFTER INSERT OR UPDATE ON chat.direct_request_lifecycle
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_acceptance_claim();

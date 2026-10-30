-- Scope initialization is allowed once, before any domain is materialized.
-- The scope-specific trigger freezes these fields afterwards; all legacy
-- immutable-identity columns retain their original protection.
DROP TRIGGER inventory_sessions_identity_immutable ON chat.inventory_sessions;
CREATE TRIGGER inventory_sessions_identity_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'conversations_complete', 'welcomes_complete', 'recovery_complete',
    'conversation_item_count', 'conversation_items_sha256',
    'welcome_item_count', 'welcome_items_sha256',
    'recovery_item_count', 'recovery_items_sha256',
    'conversations_consumed', 'conversations_consumed_at',
    'welcomes_consumed', 'welcomes_consumed_at',
    'recovery_consumed', 'recovery_consumed_at',
    'conversation_payload_bytes', 'welcome_payload_bytes', 'recovery_payload_bytes',
    'supported_protocol_versions', 'inventory_scope', 'scoped_conversation_ids'
);

CREATE FUNCTION chat.guard_direct_request_lifecycle() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'direct request consent evidence is retained' USING ERRCODE='23514';
    END IF;
    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.acceptance_proof IS DISTINCT FROM OLD.acceptance_proof
       OR NEW.acceptance_digest IS DISTINCT FROM OLD.acceptance_digest
       OR NEW.accepted_at IS DISTINCT FROM OLD.accepted_at
       OR (OLD.consent='closed' AND NEW IS DISTINCT FROM OLD)
       OR (OLD.consent='accepted' AND NEW.consent NOT IN ('accepted','closed')) THEN
        RAISE EXCEPTION 'direct request consent evidence is immutable and monotonic' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER direct_request_lifecycle_monotonic BEFORE UPDATE OR DELETE ON chat.direct_request_lifecycle
FOR EACH ROW EXECUTE FUNCTION chat.guard_direct_request_lifecycle();

-- Link the consent row to the exact canonical acceptance control entry and
-- signed authority receipt. Cryptographic signature validation remains in the
-- locked admission/projection code; this fence forbids relational fabrication.
CREATE FUNCTION chat.assert_direct_request_lifecycle(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE life chat.direct_request_lifecycle%ROWTYPE;
        publication chat.direct_request_publications%ROWTYPE;
        proof JSONB;
BEGIN
    SELECT * INTO life FROM chat.direct_request_lifecycle WHERE request_id=target;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO publication FROM chat.direct_request_publications WHERE request_id=target;
    IF publication.conversation_id IS DISTINCT FROM life.conversation_id THEN
        RAISE EXCEPTION 'request lifecycle publication mismatch' USING ERRCODE='23514';
    END IF;
    IF life.accepted_at IS NOT NULL THEN
        proof := convert_from(life.acceptance_proof,'UTF8')::jsonb;
        IF NOT EXISTS (
            SELECT 1 FROM chat.transitions t
            JOIN chat.entries e ON e.conversation_id=t.conversation_id AND e.seq=t.entry_seq
            WHERE t.conversation_id=life.conversation_id AND t.kind='directRequestAcceptance'
              AND t.actor_did=publication.recipient_did
              AND t.request_digest=life.acceptance_digest AND t.accepted_at=life.accepted_at
              AND e.entry_kind='blue.catbird.chat.defs#directRequestAcceptanceEntry'
              AND (convert_from(e.accepted_payload_bytes,'UTF8')::jsonb - '$type') = proof->'entry'
              AND convert_from(e.server_fields_bytes,'UTF8')::jsonb = proof->'receipt'
              AND convert_from(t.signed_request_bytes,'UTF8')::jsonb = proof->'entry'->'signedRequest'
              AND proof->'entry'->'signedRequest'->'body'->>'requestId'=target::text
              AND proof->'receipt'->'body'->>'requestId'=target::text
        ) THEN RAISE EXCEPTION 'request acceptance lacks exact canonical consent proof' USING ERRCODE='23514'; END IF;
    END IF;
    IF life.consent='closed' AND NOT EXISTS (
        SELECT 1 FROM chat.conversations c WHERE c.conversation_id=life.conversation_id
          AND c.lifecycle='closed' AND c.closed_at=life.closed_at
    ) THEN RAISE EXCEPTION 'request close lacks canonical closure' USING ERRCODE='23514'; END IF;
END $$;
CREATE FUNCTION chat.enforce_direct_request_lifecycle() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM chat.assert_direct_request_lifecycle(NEW.request_id);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_lifecycle_graph AFTER INSERT OR UPDATE ON chat.direct_request_lifecycle
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_lifecycle();

ALTER TABLE chat.inventory_sessions DROP CONSTRAINT inventory_scope_shape;
ALTER TABLE chat.inventory_sessions ADD CONSTRAINT inventory_scope_shape CHECK ((
    (supported_protocol_versions IS NULL AND inventory_scope IS NULL AND scoped_conversation_ids IS NULL)
    OR (supported_protocol_versions IS NOT NULL
        AND supported_protocol_versions IN (ARRAY['1'],ARRAY['2'],ARRAY['1','2'])
        AND inventory_scope IS NOT NULL AND scoped_conversation_ids IS NOT NULL
        AND inventory_scope->'supportedProtocolVersions' = to_jsonb(supported_protocol_versions)
        AND inventory_scope->>'scopeDigest' IS NOT NULL)
) IS TRUE);

ALTER TABLE chat.relationship_projection_snapshots DROP CONSTRAINT relationship_projection_snapshots_scope_check;
ALTER TABLE chat.relationship_projection_snapshots ADD CONSTRAINT relationship_projection_snapshots_scope_check CHECK (
    operation_scope IN ('creation','pendingAdd','acceptance','recoveryReservation','recoveryFulfillment','traffic','directRequestPreparation','directRequestAcceptance')
);

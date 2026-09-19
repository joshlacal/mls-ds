-- A negotiated inventory is one immutable audience across every page, domain,
-- event cursor and subscription ticket. Existing sessions remain legacy.
ALTER TABLE chat.inventory_sessions
    ADD COLUMN IF NOT EXISTS supported_protocol_versions TEXT[],
    ADD COLUMN IF NOT EXISTS inventory_scope JSONB,
    ADD COLUMN IF NOT EXISTS scoped_conversation_ids UUID[];
ALTER TABLE chat.inventory_sessions ADD CONSTRAINT inventory_scope_shape CHECK (
    (supported_protocol_versions IS NULL AND inventory_scope IS NULL)
    OR (supported_protocol_versions IN (ARRAY['1'],ARRAY['2'],ARRAY['1','2'])
        AND inventory_scope IS NOT NULL
        AND inventory_scope->'supportedProtocolVersions' = to_jsonb(supported_protocol_versions)
        AND inventory_scope->>'scopeDigest' IS NOT NULL)
);
CREATE FUNCTION chat.guard_inventory_request_scope() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.inventory_scope IS NOT NULL AND
       (NEW.inventory_scope IS DISTINCT FROM OLD.inventory_scope OR
        NEW.supported_protocol_versions IS DISTINCT FROM OLD.supported_protocol_versions OR
        NEW.scoped_conversation_ids IS DISTINCT FROM OLD.scoped_conversation_ids) THEN
        RAISE EXCEPTION 'inventory request scope is immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.inventory_scope IS NULL AND NEW.inventory_scope IS NOT NULL AND
       (OLD.conversations_complete OR OLD.welcomes_complete OR OLD.recovery_complete) THEN
        RAISE EXCEPTION 'inventory request scope must precede materialization' USING ERRCODE='23514';
    END IF;
    IF NEW.inventory_scope IS NOT NULL AND OLD.inventory_scope IS NULL THEN
        IF NEW.scoped_conversation_ids IS NULL OR EXISTS (
            SELECT 1 FROM unnest(NEW.scoped_conversation_ids) id
            LEFT JOIN chat.conversations c ON c.conversation_id=id
            WHERE c.conversation_id IS NULL OR NOT(c.protocol_version=ANY(NEW.supported_protocol_versions))
        ) THEN RAISE EXCEPTION 'inventory scope audience version mismatch' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER inventory_request_scope_immutable BEFORE UPDATE ON chat.inventory_sessions
    FOR EACH ROW EXECUTE FUNCTION chat.guard_inventory_request_scope();

-- Absence means pending only when the immutable publication exists. A member
-- device alone never implies recipient consent.
CREATE TABLE IF NOT EXISTS chat.direct_request_lifecycle (
    request_id UUID PRIMARY KEY REFERENCES chat.direct_request_publications(request_id),
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id),
    consent TEXT NOT NULL CHECK (consent IN ('accepted','closed')),
    acceptance_proof BYTEA,
    acceptance_digest BYTEA,
    accepted_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    CHECK ((accepted_at IS NULL AND acceptance_proof IS NULL AND acceptance_digest IS NULL)
        OR (accepted_at IS NOT NULL AND acceptance_proof IS NOT NULL AND octet_length(acceptance_digest)=32)),
    CHECK (consent <> 'accepted' OR accepted_at IS NOT NULL),
    CHECK ((consent='closed') = (closed_at IS NOT NULL))
);

CREATE FUNCTION chat.assert_direct_request_inventory_scope(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE s chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO s FROM chat.inventory_sessions WHERE inventory_session_id=target;
    IF NOT FOUND OR s.inventory_scope IS NULL THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM chat.inventory_conversation_items i WHERE i.inventory_session_id=target AND NOT(i.conversation_id=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_welcome_items i JOIN chat.welcome_bundles w USING(welcome_id) WHERE i.inventory_session_id=target AND NOT(w.conversation_id=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_recovery_items i LEFT JOIN chat.leaf_recovery_requests r ON r.recovery_request_id=i.leaf_recovery_request_id LEFT JOIN chat.recovery_work_items w ON w.recovery_work_id=i.recovery_work_id WHERE i.inventory_session_id=target AND NOT(COALESCE(r.conversation_id,w.conversation_id)=ANY(s.scoped_conversation_ids)))
    THEN RAISE EXCEPTION 'inventory item lies outside immutable negotiated audience' USING ERRCODE='23514'; END IF;
END $$;
CREATE FUNCTION chat.enforce_direct_request_inventory_scope() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM chat.assert_direct_request_inventory_scope(NEW.inventory_session_id);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_inventory_scope_session AFTER INSERT OR UPDATE ON chat.inventory_sessions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_inventory_scope();
CREATE CONSTRAINT TRIGGER direct_request_inventory_scope_conversations AFTER INSERT OR UPDATE ON chat.inventory_conversation_items
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_inventory_scope();
CREATE CONSTRAINT TRIGGER direct_request_inventory_scope_welcomes AFTER INSERT OR UPDATE ON chat.inventory_welcome_items
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_inventory_scope();
CREATE CONSTRAINT TRIGGER direct_request_inventory_scope_recovery AFTER INSERT OR UPDATE ON chat.inventory_recovery_items
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_inventory_scope();

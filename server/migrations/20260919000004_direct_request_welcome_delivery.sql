-- Per-device terminal outcomes do not alter account consent, peer receipts, or
-- any sibling's Welcome. Absence is pending until the immutable import horizon.
CREATE TABLE chat.direct_request_welcome_outcomes (
    request_id UUID NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('acknowledged','rejected','expired')),
    terminal_at TIMESTAMPTZ NOT NULL,
    signed_request_bytes BYTEA,
    request_digest BYTEA,
    PRIMARY KEY(request_id,recipient_did,recipient_device_id),
    FOREIGN KEY(request_id,recipient_did,recipient_device_id)
        REFERENCES chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id),
    CHECK ((status='expired' AND signed_request_bytes IS NULL AND request_digest IS NULL)
        OR (status IN ('acknowledged','rejected') AND signed_request_bytes IS NOT NULL AND octet_length(request_digest)=32))
);
CREATE TRIGGER direct_request_welcome_outcomes_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_welcome_outcomes
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Preserve the exact legacy delivery foreign keys through a generated nullable
-- key; the new arm has its own exact request/device provenance foreign key.
ALTER TABLE chat.inventory_welcome_items ADD COLUMN direct_request_id UUID,
    ADD COLUMN legacy_welcome_id UUID GENERATED ALWAYS AS (CASE WHEN direct_request_id IS NULL THEN welcome_id ELSE NULL END) STORED;
ALTER TABLE chat.inventory_welcome_items DROP CONSTRAINT inventory_welcome_items_welcome_fk,
    DROP CONSTRAINT inventory_welcome_items_source_fk;
ALTER TABLE chat.inventory_welcome_items
    ADD CONSTRAINT inventory_welcome_items_welcome_fk FOREIGN KEY(legacy_welcome_id) REFERENCES chat.welcome_deliveries(welcome_id),
    ADD CONSTRAINT inventory_welcome_items_source_fk FOREIGN KEY(legacy_welcome_id,recipient_did,recipient_device_id) REFERENCES chat.welcome_deliveries(welcome_id,recipient_did,recipient_device_id),
    ADD CONSTRAINT inventory_welcome_items_request_source_fk FOREIGN KEY(direct_request_id,recipient_did,recipient_device_id) REFERENCES chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id),
    ADD CONSTRAINT inventory_welcome_items_request_identity CHECK(direct_request_id IS NULL OR welcome_id=direct_request_id);

CREATE OR REPLACE FUNCTION chat.assert_direct_request_inventory_scope(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE s chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO s FROM chat.inventory_sessions WHERE inventory_session_id=target;
    IF NOT FOUND OR s.inventory_scope IS NULL THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM chat.inventory_conversation_items i WHERE i.inventory_session_id=target AND NOT(i.conversation_id=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_welcome_items i LEFT JOIN chat.welcome_bundles w USING(welcome_id) LEFT JOIN chat.direct_request_publications p ON p.request_id=i.direct_request_id WHERE i.inventory_session_id=target AND NOT(COALESCE(w.conversation_id,p.conversation_id)=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_recovery_items i LEFT JOIN chat.leaf_recovery_requests r ON r.recovery_request_id=i.leaf_recovery_request_id LEFT JOIN chat.recovery_work_items w ON w.recovery_work_id=i.recovery_work_id WHERE i.inventory_session_id=target AND NOT(COALESCE(r.conversation_id,w.conversation_id)=ANY(s.scoped_conversation_ids)))
    THEN RAISE EXCEPTION 'inventory item lies outside immutable negotiated audience' USING ERRCODE='23514'; END IF;
END $$;

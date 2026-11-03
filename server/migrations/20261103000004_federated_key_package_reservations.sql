-- GET blue.catbird.mlsDS.fetchKeyPackage hands one recovery KeyPackage to an
-- authorized remote DS. The package leaves the local pool for good: it becomes
-- `reserved`, and this row is its reservation, so the deferred mapping holds at
-- commit and neither local recovery, a group export, nor another fetch can
-- select it again. Reservations are owner-scoped, not conversation rows.
CREATE TABLE chat.federated_key_package_reservations (
    key_package_ref BYTEA PRIMARY KEY
        REFERENCES chat.key_packages(key_package_ref) ON DELETE CASCADE,
    requester_ds_did TEXT NOT NULL CHECK (chat.is_bare_did(requester_ds_did)),
    reserved_at TIMESTAMPTZ NOT NULL
);

CREATE TRIGGER federated_key_package_reservations_immutable
BEFORE UPDATE ON chat.federated_key_package_reservations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE CONSTRAINT TRIGGER federated_key_package_reservations_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.federated_key_package_reservations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

-- 20260919000022's mapping, plus: a reserved recovery package has exactly one
-- active recovery reservation or one federated reservation, and a federated
-- package can only stay reserved, expire, or be revoked.
CREATE OR REPLACE FUNCTION chat.assert_key_package_reservation_mapping(target_package BYTEA)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    package_row chat.key_packages%ROWTYPE;
    active_count BIGINT;
    consumed_count BIGINT;
    selected_count BIGINT;
    retired_count BIGINT;
    federated_count BIGINT;
BEGIN
    SELECT * INTO package_row FROM chat.key_packages WHERE key_package_ref=target_package;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM 1 FROM chat.principals WHERE user_did=package_row.owner_did FOR UPDATE;
    SELECT count(*) INTO federated_count FROM chat.federated_key_package_reservations
     WHERE key_package_ref=target_package;
    IF package_row.usage_scope='direct-request' THEN
        IF EXISTS(SELECT 1 FROM chat.key_package_reservations WHERE key_package_ref=target_package)
           OR federated_count<>0 THEN
            RAISE EXCEPTION 'request package cannot have recovery reservation' USING ERRCODE='23514';
        END IF;
        SELECT count(*) INTO selected_count FROM chat.direct_request_selected_devices
         WHERE key_package_ref=target_package;
        SELECT count(*) INTO retired_count FROM chat.direct_request_retired_packages
         WHERE key_package_ref=target_package;
        IF (package_row.status='available' AND (selected_count<>0 OR retired_count<>0))
           OR (package_row.status='reserved' AND selected_count+retired_count<>1)
           OR (package_row.status='consumed' AND NOT (
               (selected_count=1 AND retired_count=0 AND package_row.terminal_transition_id IS NOT NULL AND EXISTS(
                   SELECT 1 FROM chat.direct_request_selected_devices s JOIN chat.direct_request_attempts a USING(request_id)
                    WHERE s.key_package_ref=target_package AND s.request_id=package_row.terminal_transition_id
                      AND a.status='published' AND a.terminal_at=package_row.terminal_at
                      AND s.owner_did=package_row.owner_did AND s.owner_device_id=package_row.owner_device_id
                      AND s.owner_key_id=package_row.owner_key_id AND s.auth_generation=package_row.owner_auth_generation
               ))
               OR
               (selected_count=0 AND retired_count=0 AND package_row.terminal_remote_lease_id IS NOT NULL AND EXISTS(
                   SELECT 1 FROM chat.direct_request_remote_leases l
                    JOIN chat.direct_request_transport_inbox i
                      ON i.request_id = l.request_id AND i.recipient_device_id = l.owner_device_id
                    WHERE l.key_package_ref=target_package AND l.lease_id=package_row.terminal_remote_lease_id
                      AND l.finalized_at IS NOT NULL AND l.finalized_at=package_row.terminal_at
                      AND l.recipient_did=package_row.owner_did AND l.owner_device_id=package_row.owner_device_id
                      AND l.status='finalized'
               ))
           )) THEN
            RAISE EXCEPTION 'request key package reservation mapping mismatch' USING ERRCODE='23514';
        END IF;
        RETURN;
    END IF;
    SELECT count(*) FILTER(WHERE status='active'),
           count(*) FILTER(WHERE status='consumed' AND consumed_transition_id=package_row.terminal_transition_id)
      INTO active_count,consumed_count FROM chat.key_package_reservations WHERE key_package_ref=target_package;
    IF package_row.status='reserved' AND active_count+federated_count<>1 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    ELSIF package_row.status='consumed' AND (consumed_count<>1 OR federated_count<>0) THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    ELSIF package_row.status NOT IN ('reserved','consumed') AND active_count<>0 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    ELSIF package_row.status='available' AND federated_count<>0 THEN
        RAISE EXCEPTION 'federated key package cannot return to the pool' USING ERRCODE='23514';
    END IF;
END $$;

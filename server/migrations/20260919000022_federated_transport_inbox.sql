-- 20260919000022_federated_transport_inbox.sql
-- C33 Two-Authority Direct Request Federation:
-- 1. Request-bound remote leases on recipient home DS (packages stay available until finalized)
-- 2. Durable verified recipient transport inbox & transport entries on recipient home DS
-- 3. Dedicated remote lease FK on key_packages (terminal_remote_lease_id) preserving key_packages_terminal_transition_fk unchanged
-- 4. Dedicated transport inbox FK on inventory_welcome_items (transport_inbox_delivery_id) preserving existing FKs unchanged
-- 5. Exclusive-source checks ensuring exactly one authoritative parent for consumed packages and welcome items
-- 6. Extend key package reservation mapping to require both finalized remote lease AND durable inbox row
-- 7. Immutable identity & monotonic status triggers on remote leases and transport inbox

CREATE TABLE IF NOT EXISTS chat.direct_request_remote_leases (
    lease_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL CHECK (chat.is_uuid_v4(request_id)),
    coordinator_did TEXT NOT NULL CHECK (chat.is_bare_did(coordinator_did)),
    sender_did TEXT NOT NULL CHECK (chat.is_bare_did(sender_did)),
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did)),
    key_package_ref BYTEA NOT NULL REFERENCES chat.key_packages(key_package_ref),
    owner_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(owner_device_id)),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released', 'finalized', 'expired')),
    leased_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > leased_at),
    released_at TIMESTAMPTZ,
    finalized_at TIMESTAMPTZ,
    CONSTRAINT direct_request_remote_leases_lifetime_check
        CHECK (expires_at <= leased_at + INTERVAL '360 seconds'),
    CONSTRAINT direct_request_remote_leases_terminal_shape_check
        CHECK (released_at IS NULL OR finalized_at IS NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS direct_request_remote_leases_active_pkg_idx
    ON chat.direct_request_remote_leases (key_package_ref)
    WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS direct_request_remote_leases_idempotency_idx
    ON chat.direct_request_remote_leases (request_id, owner_device_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS direct_request_remote_leases_expiry_idx
    ON chat.direct_request_remote_leases (expires_at)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS chat.direct_request_transport_inbox (
    delivery_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL CHECK (chat.is_uuid_v4(request_id)),
    conversation_id UUID NOT NULL CHECK (chat.is_uuid_v4(conversation_id)),
    first_message_id UUID NOT NULL CHECK (chat.is_uuid_v4(first_message_id)),
    coordinator_did TEXT NOT NULL CHECK (chat.is_bare_did(coordinator_did)),
    sender_did TEXT NOT NULL CHECK (chat.is_bare_did(sender_did)),
    sender_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(sender_device_id)),
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did)),
    recipient_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(recipient_device_id)),
    request_entry BYTEA NOT NULL,
    signed_publication BYTEA NOT NULL,
    full_welcome BYTEA NOT NULL,
    full_welcome_sha256 BYTEA NOT NULL CHECK (octet_length(full_welcome_sha256) = 32),
    provenance BYTEA NOT NULL,
    publication_receipt BYTEA NOT NULL,
    acceptance_proof BYTEA,
    acceptance_outcome BYTEA,
    import_until TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT direct_request_transport_inbox_unique_pkg
        UNIQUE (request_id, recipient_device_id)
);

CREATE INDEX IF NOT EXISTS direct_request_transport_inbox_pending_idx
    ON chat.direct_request_transport_inbox (recipient_did, recipient_device_id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS direct_request_transport_inbox_convo_idx
    ON chat.direct_request_transport_inbox (conversation_id);

ALTER TABLE chat.direct_request_transport_inbox
    ADD COLUMN IF NOT EXISTS sender_device_id UUID,
    ADD COLUMN IF NOT EXISTS acceptance_proof BYTEA,
    ADD COLUMN IF NOT EXISTS acceptance_outcome BYTEA;

CREATE TABLE IF NOT EXISTS chat.direct_request_transport_entries (
    delivery_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL CHECK (chat.is_uuid_v4(conversation_id)),
    seq BIGINT NOT NULL CHECK (seq >= 1),
    entry_id UUID NOT NULL CHECK (chat.is_uuid_v4(entry_id)),
    entry_bytes BYTEA NOT NULL CHECK (octet_length(entry_bytes) <= 16777216),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT direct_request_transport_entries_convo_seq_uq UNIQUE (conversation_id, seq)
);

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_entries_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'transport entries are immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.conversation_id <> OLD.conversation_id
           OR NEW.seq <> OLD.seq
           OR NEW.entry_id <> OLD.entry_id
           OR NEW.entry_bytes <> OLD.entry_bytes THEN
            RAISE EXCEPTION 'transport entries cannot be modified' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := OLD.created_at;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS direct_request_transport_entries_immutable_trigger ON chat.direct_request_transport_entries;
CREATE TRIGGER direct_request_transport_entries_immutable_trigger
BEFORE UPDATE OR DELETE ON chat.direct_request_transport_entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_transport_entries_immutable();

CREATE INDEX IF NOT EXISTS direct_request_transport_entries_lookup_idx
    ON chat.direct_request_transport_entries (conversation_id, seq);

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_remote_leases_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'remote lease rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.lease_id <> OLD.lease_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.key_package_ref <> OLD.key_package_ref
       OR NEW.owner_device_id <> OLD.owner_device_id
       OR NEW.leased_at <> OLD.leased_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'remote lease immutable columns cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF OLD.status NOT IN ('active', 'expired') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal remote lease status is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'expired' AND NEW.status <> 'finalized' THEN
        RAISE EXCEPTION 'expired remote lease can only transition to finalized' USING ERRCODE = '23514';
    END IF;
    IF OLD.finalized_at IS NOT NULL AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at THEN
        RAISE EXCEPTION 'finalized_at is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
        RAISE EXCEPTION 'released_at is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS direct_request_remote_leases_monotonic_trigger ON chat.direct_request_remote_leases;
CREATE TRIGGER direct_request_remote_leases_monotonic_trigger
BEFORE UPDATE OR DELETE ON chat.direct_request_remote_leases
FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_remote_leases_monotonic();

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_inbox_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'transport inbox rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.delivery_id <> OLD.delivery_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.first_message_id <> OLD.first_message_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.sender_device_id IS DISTINCT FROM OLD.sender_device_id
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.recipient_device_id <> OLD.recipient_device_id
       OR NEW.full_welcome <> OLD.full_welcome
       OR NEW.full_welcome_sha256 <> OLD.full_welcome_sha256
       OR NEW.created_at <> OLD.created_at
       OR NEW.request_entry <> OLD.request_entry
       OR NEW.signed_publication <> OLD.signed_publication
       OR NEW.provenance <> OLD.provenance
       OR NEW.publication_receipt <> OLD.publication_receipt
       OR NEW.import_until <> OLD.import_until THEN
        RAISE EXCEPTION 'transport inbox immutable identity cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'pending' AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal transport inbox status is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.acceptance_proof IS NOT NULL AND NEW.acceptance_proof IS DISTINCT FROM OLD.acceptance_proof THEN
        RAISE EXCEPTION 'transport inbox acceptance_proof is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.acceptance_outcome IS NOT NULL AND NEW.acceptance_outcome IS DISTINCT FROM OLD.acceptance_outcome THEN
        RAISE EXCEPTION 'transport inbox acceptance_outcome is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS direct_request_transport_inbox_monotonic_trigger ON chat.direct_request_transport_inbox;
CREATE TRIGGER direct_request_transport_inbox_monotonic_trigger
BEFORE UPDATE OR DELETE ON chat.direct_request_transport_inbox
FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_transport_inbox_monotonic();

-- Add separate remote lease FK on chat.key_packages (preserving key_packages_terminal_transition_fk intact)
ALTER TABLE chat.key_packages
    ADD COLUMN IF NOT EXISTS terminal_remote_lease_id UUID;

-- Remote consumption adds exactly one terminal provenance field; all other
-- package identity columns retain the original immutable trigger protection.
DROP TRIGGER key_packages_identity_immutable ON chat.key_packages;
CREATE TRIGGER key_packages_identity_immutable
BEFORE UPDATE OR DELETE ON chat.key_packages
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at',
    'terminal_remote_lease_id'
);

-- The original lifecycle permits reserved -> consumed. A remote lease keeps
-- the package available to existing readers, then finalizes it in one transaction.
CREATE FUNCTION chat.enforce_federated_key_package_lifecycle()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('consumed', 'expired', 'revoked') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal KeyPackage cannot be rewritten' USING ERRCODE = '23514';
    END IF;
    IF (OLD.status = 'available' AND NEW.status NOT IN ('available', 'reserved', 'expired', 'revoked')
        AND NOT (NEW.status = 'consumed' AND OLD.usage_scope = 'direct-request'
            AND NEW.terminal_remote_lease_id IS NOT NULL
            AND EXISTS (SELECT 1 FROM chat.direct_request_remote_leases l
                WHERE l.lease_id = NEW.terminal_remote_lease_id
                  AND l.key_package_ref = NEW.key_package_ref AND l.status = 'finalized')))
       OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'available', 'consumed', 'expired', 'revoked'))
       OR NEW.terminal_at < OLD.terminal_at THEN
        RAISE EXCEPTION 'invalid KeyPackage lifecycle transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER key_packages_lifecycle_monotonic ON chat.key_packages;
CREATE TRIGGER key_packages_lifecycle_monotonic
BEFORE UPDATE ON chat.key_packages
FOR EACH ROW EXECUTE FUNCTION chat.enforce_federated_key_package_lifecycle();

ALTER TABLE chat.key_packages
    DROP CONSTRAINT IF EXISTS key_packages_terminal_remote_lease_fk;

ALTER TABLE chat.key_packages
    ADD CONSTRAINT key_packages_terminal_remote_lease_fk
        FOREIGN KEY (terminal_remote_lease_id)
        REFERENCES chat.direct_request_remote_leases(lease_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.key_packages
    DROP CONSTRAINT IF EXISTS key_packages_terminal_shape_check;

ALTER TABLE chat.key_packages
    ADD CONSTRAINT key_packages_terminal_shape_check CHECK (
        (status IN ('available','reserved') AND terminal_transition_id IS NULL AND terminal_remote_lease_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at IS NULL)
        OR (status = 'consumed' AND num_nonnulls(terminal_transition_id, terminal_remote_lease_id) = 1
            AND terminal_revocation_id IS NULL AND terminal_at IS NOT NULL)
        OR (status = 'expired' AND terminal_transition_id IS NULL AND terminal_remote_lease_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at = not_after)
        OR (status = 'revoked' AND terminal_transition_id IS NULL AND terminal_remote_lease_id IS NULL
            AND chat.is_uuid_v4(terminal_revocation_id)
            AND terminal_at >= created_at AND terminal_at < not_after)
    );

-- Add separate transport inbox FK on chat.inventory_welcome_items (preserving existing FKs intact)
ALTER TABLE chat.inventory_welcome_items
    ADD COLUMN IF NOT EXISTS transport_inbox_delivery_id UUID;

ALTER TABLE chat.inventory_welcome_items
    DROP CONSTRAINT IF EXISTS inventory_welcome_items_transport_inbox_fk;

ALTER TABLE chat.inventory_welcome_items
    ADD CONSTRAINT inventory_welcome_items_transport_inbox_fk
        FOREIGN KEY (transport_inbox_delivery_id)
        REFERENCES chat.direct_request_transport_inbox(delivery_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.inventory_welcome_items
    DROP COLUMN IF EXISTS legacy_welcome_id CASCADE;

ALTER TABLE chat.inventory_welcome_items
    ADD COLUMN legacy_welcome_id UUID GENERATED ALWAYS AS (
        CASE WHEN direct_request_id IS NULL AND transport_inbox_delivery_id IS NULL THEN welcome_id ELSE NULL END
    ) STORED;

ALTER TABLE chat.inventory_welcome_items
    ADD CONSTRAINT inventory_welcome_items_welcome_fk
        FOREIGN KEY(legacy_welcome_id) REFERENCES chat.welcome_deliveries(welcome_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT inventory_welcome_items_source_fk
        FOREIGN KEY(legacy_welcome_id, recipient_did, recipient_device_id)
        REFERENCES chat.welcome_deliveries(welcome_id, recipient_did, recipient_device_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.inventory_welcome_items
    DROP CONSTRAINT IF EXISTS inventory_welcome_items_exclusive_source_check;

ALTER TABLE chat.inventory_welcome_items
    ADD CONSTRAINT inventory_welcome_items_exclusive_source_check
        CHECK (num_nonnulls(direct_request_id, transport_inbox_delivery_id, legacy_welcome_id) = 1);

-- Preserve the immutable audience fence while admitting only this session's
-- authenticated device to a protocol-2 transport-inbox conversation.
CREATE OR REPLACE FUNCTION chat.guard_inventory_request_scope()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
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
            WHERE NOT EXISTS (
                SELECT 1 FROM chat.conversations c
                WHERE c.conversation_id = id AND c.protocol_version = ANY(NEW.supported_protocol_versions)
            ) AND NOT (
                '2' = ANY(NEW.supported_protocol_versions) AND EXISTS (
                    SELECT 1 FROM chat.direct_request_transport_inbox t
                    WHERE t.conversation_id = id AND t.recipient_did = NEW.user_did
                      AND t.recipient_device_id = NEW.device_id AND t.status = 'pending'
                      AND t.import_until > transaction_timestamp()
                )
            )
        ) THEN RAISE EXCEPTION 'inventory scope audience version mismatch' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION chat.assert_direct_request_inventory_scope(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE s chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO s FROM chat.inventory_sessions WHERE inventory_session_id=target;
    IF NOT FOUND OR s.inventory_scope IS NULL THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM chat.inventory_conversation_items i WHERE i.inventory_session_id=target AND NOT(i.conversation_id=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_welcome_items i
                  LEFT JOIN chat.welcome_bundles w USING(welcome_id)
                  LEFT JOIN chat.direct_request_publications p ON p.request_id=i.direct_request_id
                  LEFT JOIN chat.direct_request_transport_inbox t ON t.delivery_id=i.transport_inbox_delivery_id
                  WHERE i.inventory_session_id=target AND NOT(COALESCE(w.conversation_id,p.conversation_id,t.conversation_id)=ANY(s.scoped_conversation_ids)))
       OR EXISTS (SELECT 1 FROM chat.inventory_recovery_items i LEFT JOIN chat.leaf_recovery_requests r ON r.recovery_request_id=i.leaf_recovery_request_id LEFT JOIN chat.recovery_work_items w ON w.recovery_work_id=i.recovery_work_id WHERE i.inventory_session_id=target AND NOT(COALESCE(r.conversation_id,w.conversation_id)=ANY(s.scoped_conversation_ids)))
    THEN RAISE EXCEPTION 'inventory item lies outside immutable negotiated audience' USING ERRCODE='23514'; END IF;
END $$;

CREATE OR REPLACE FUNCTION chat.assert_key_package_reservation_mapping(target_package BYTEA)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    package_row chat.key_packages%ROWTYPE;
    active_count BIGINT;
    consumed_count BIGINT;
    selected_count BIGINT;
    retired_count BIGINT;
BEGIN
    SELECT * INTO package_row FROM chat.key_packages WHERE key_package_ref=target_package;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM 1 FROM chat.principals WHERE user_did=package_row.owner_did FOR UPDATE;
    IF package_row.usage_scope='direct-request' THEN
        IF EXISTS(SELECT 1 FROM chat.key_package_reservations WHERE key_package_ref=target_package) THEN
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
    -- The original recovery package mapping is unchanged.
    SELECT count(*) FILTER(WHERE status='active'),
           count(*) FILTER(WHERE status='consumed' AND consumed_transition_id=package_row.terminal_transition_id)
      INTO active_count,consumed_count FROM chat.key_package_reservations WHERE key_package_ref=target_package;
    IF package_row.status='reserved' AND active_count<>1 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    ELSIF package_row.status='consumed' AND consumed_count<>1 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    ELSIF package_row.status NOT IN ('reserved','consumed') AND active_count<>0 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch' USING ERRCODE='23514';
    END IF;
END $$;

DROP TRIGGER IF EXISTS direct_request_remote_leases_mapping_deferred ON chat.direct_request_remote_leases;
CREATE CONSTRAINT TRIGGER direct_request_remote_leases_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.direct_request_remote_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

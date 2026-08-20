-- Expand-only migration: Make legacy custom-DPoP JKT columns nullable and unused
-- for standard ATProto service auth in MLS v2 AppView.
-- Preserves all existing columns and historical data for rollback safety.
-- Do NOT drop columns or contract schema until authorized stabilization gate.

-- 1. chat.devices: allow NULL dpop_jkt for standard service-authenticated devices.
ALTER TABLE chat.devices
    ALTER COLUMN dpop_jkt DROP NOT NULL;

ALTER TABLE chat.devices
    DROP CONSTRAINT IF EXISTS devices_dpop_jkt_check;

ALTER TABLE chat.devices
    ADD CONSTRAINT devices_dpop_jkt_check
    CHECK (dpop_jkt IS NULL OR chat.is_base64url_sha256(dpop_jkt));

-- 2. chat.idempotency_records: allow NULL historical_jkt / current_jkt for all endpoints.
ALTER TABLE chat.idempotency_records
    DROP CONSTRAINT IF EXISTS idempotency_records_jkt_check;

ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_jkt_check
    CHECK (
        (historical_jkt IS NULL OR chat.is_base64url_sha256(historical_jkt))
        AND (current_jkt IS NULL OR chat.is_base64url_sha256(current_jkt))
    );

-- 3. chat.inventory_sessions: allow NULL jkt for standard auth sessions.
ALTER TABLE chat.inventory_sessions
    ALTER COLUMN jkt DROP NOT NULL;

ALTER TABLE chat.inventory_sessions
    DROP CONSTRAINT IF EXISTS inventory_sessions_jkt_check;

ALTER TABLE chat.inventory_sessions
    ADD CONSTRAINT inventory_sessions_jkt_check
    CHECK (jkt IS NULL OR chat.is_base64url_sha256(jkt));

-- 4. chat.device_inventory_sessions: allow NULL jkt.
ALTER TABLE chat.device_inventory_sessions
    ALTER COLUMN jkt DROP NOT NULL;

ALTER TABLE chat.device_inventory_sessions
    DROP CONSTRAINT IF EXISTS device_inventory_sessions_jkt_check;

ALTER TABLE chat.device_inventory_sessions
    ADD CONSTRAINT device_inventory_sessions_jkt_check
    CHECK (jkt IS NULL OR chat.is_base64url_sha256(jkt));

-- 5. chat.subscription_tickets: allow NULL jkt.
ALTER TABLE chat.subscription_tickets
    ALTER COLUMN jkt DROP NOT NULL;

ALTER TABLE chat.subscription_tickets
    DROP CONSTRAINT IF EXISTS subscription_tickets_jkt_check;

ALTER TABLE chat.subscription_tickets
    ADD CONSTRAINT subscription_tickets_jkt_check
    CHECK (jkt IS NULL OR chat.is_base64url_sha256(jkt));

-- 6. chat.inventory_page_receipts: allow NULL jkt.
ALTER TABLE chat.inventory_page_receipts
    ALTER COLUMN jkt DROP NOT NULL;

ALTER TABLE chat.inventory_page_receipts
    DROP CONSTRAINT IF EXISTS inventory_page_receipts_binding_check;

ALTER TABLE chat.inventory_page_receipts
    ADD CONSTRAINT inventory_page_receipts_binding_check CHECK (
        chat.is_uuid_v4(inventory_session_id)
        AND cursor_format_version = 1
        AND page_limit BETWEEN 1 AND 100
        AND octet_length(canonical_filter_sha256) = 32
        AND chat.is_bare_did(user_did)
        AND chat.is_uuid_v4(device_id)
        AND (jkt IS NULL OR chat.is_base64url_sha256(jkt))
        AND chat.is_safe_integer(auth_generation)
        AND auth_generation >= 1
        AND chat.is_uuid_v4(protocol_instance_id)
        AND chat.is_base64url_sha256(cursor_key_id)
        AND chat.is_safe_integer(snapshot_event_position)
        AND octet_length(snapshot_event_cursor_sha256) = 32
        AND chat.is_safe_integer(snapshot_retained_floor)
        AND snapshot_retained_floor <= snapshot_event_position
        AND expires_at > created_at
        AND expires_at <= created_at + interval '15 minutes'
    );

-- 7. chat.event_cursor_receipts: allow NULL jkt.
ALTER TABLE chat.event_cursor_receipts
    ALTER COLUMN jkt DROP NOT NULL;

ALTER TABLE chat.event_cursor_receipts
    DROP CONSTRAINT IF EXISTS event_cursor_receipts_shape_check;

ALTER TABLE chat.event_cursor_receipts
    ADD CONSTRAINT event_cursor_receipts_shape_check CHECK (
        octet_length(cursor_hash) = 32
        AND chat.is_uuid_v4(inventory_session_id)
        AND chat.is_bare_did(user_did)
        AND chat.is_uuid_v4(device_id)
        AND (jkt IS NULL OR chat.is_base64url_sha256(jkt))
        AND chat.is_safe_integer(auth_generation)
        AND auth_generation >= 1
        AND chat.is_uuid_v4(protocol_instance_id)
        AND chat.is_base64url_sha256(cursor_key_id)
        AND chat.is_safe_integer(event_position)
        AND chat.is_safe_integer(retained_floor_at_issue)
        AND retained_floor_at_issue <= event_position
        AND octet_length(cursor_nonce) = 12
        AND octet_length(cursor_ciphertext) BETWEEN 1 AND 512
        AND (
            (
                predecessor_cursor_hash IS NULL
                AND canonical_envelope_sha256 IS NULL
            )
            OR (
                octet_length(predecessor_cursor_hash) = 32
                AND octet_length(canonical_envelope_sha256) = 32
            )
        )
        AND expires_at > created_at
        AND expires_at <= created_at + interval '15 minutes'
    );

-- 8. Null-safe inventory session identity guard.
CREATE OR REPLACE FUNCTION chat.assert_inventory_session_identity(target_session UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    session_row chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = target_session;
    IF NOT FOUND THEN RETURN; END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.devices device
         WHERE device.user_did = session_row.user_did
           AND device.device_id = session_row.device_id
           AND device.status = 'active'
           AND device.dpop_jkt IS NOT DISTINCT FROM session_row.jkt
           AND device.auth_generation = session_row.auth_generation
           AND device.created_at <= session_row.created_at
           AND device.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'inventory session authentication identity mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- 9. Null-safe subscription ticket binding guard.
CREATE OR REPLACE FUNCTION chat.assert_subscription_ticket_binding(target_ticket BYTEA)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    ticket_row chat.subscription_tickets%ROWTYPE;
    session_row chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO ticket_row
      FROM chat.subscription_tickets
     WHERE ticket_hash = target_ticket;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = ticket_row.inventory_session_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'subscription ticket inventory binding mismatch'
            USING ERRCODE = '23514';
    END IF;

    -- Retained pre-G7 tickets remain representable but are unusable because
    -- their parent session is explicitly expired and its cursor invalidated.
    IF session_row.legacy_cursor_invalidated_at IS NOT NULL
       AND ticket_row.protocol_instance_id IS NULL
       AND ticket_row.cursor_key_id IS NULL
       AND ticket_row.snapshot_retained_floor IS NULL
       AND ticket_row.created_at < session_row.legacy_cursor_invalidated_at THEN
        RETURN;
    END IF;

    IF session_row.legacy_cursor_invalidated_at IS NOT NULL
       OR session_row.conversations_complete IS FALSE
       OR session_row.welcomes_complete IS FALSE
       OR session_row.recovery_complete IS FALSE
       OR session_row.conversations_consumed IS FALSE
       OR session_row.welcomes_consumed IS FALSE
       OR session_row.recovery_consumed IS FALSE
       OR ticket_row.protocol_instance_id IS NULL
       OR ticket_row.cursor_key_id IS NULL
       OR ticket_row.snapshot_retained_floor IS NULL
       OR ticket_row.user_did <> session_row.user_did
       OR ticket_row.device_id <> session_row.device_id
       OR ticket_row.jkt IS DISTINCT FROM session_row.jkt
       OR ticket_row.auth_generation <> session_row.auth_generation
       OR ticket_row.event_position <> session_row.snapshot_event_position
       OR ticket_row.event_cursor_sha256 <> session_row.snapshot_event_cursor_sha256
       OR ticket_row.protocol_instance_id
          IS DISTINCT FROM session_row.protocol_instance_id
       OR ticket_row.cursor_key_id IS DISTINCT FROM session_row.cursor_key_id
       OR ticket_row.snapshot_retained_floor
          IS DISTINCT FROM session_row.snapshot_retained_floor
       OR ticket_row.created_at < session_row.created_at
       OR ticket_row.created_at >= session_row.expires_at
       OR ticket_row.expires_at > session_row.expires_at
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices device
             WHERE device.user_did = ticket_row.user_did
               AND device.device_id = ticket_row.device_id
               AND device.status = 'active'
               AND device.dpop_jkt IS NOT DISTINCT FROM ticket_row.jkt
               AND device.auth_generation = ticket_row.auth_generation
               AND device.created_at <= ticket_row.created_at
               AND device.revoked_at IS NULL
       ) THEN
        RAISE EXCEPTION 'subscription ticket inventory binding mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;
-- 10. Null-safe inventory page receipt session binding guard.
CREATE OR REPLACE FUNCTION chat.assert_inventory_page_receipt_session_binding(target_receipt UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    receipt_row chat.inventory_page_receipts%ROWTYPE;
    session_row chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO receipt_row
      FROM chat.inventory_page_receipts
     WHERE page_receipt_id = target_receipt;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = receipt_row.inventory_session_id;
    IF NOT FOUND
       OR receipt_row.user_did <> session_row.user_did
       OR receipt_row.device_id <> session_row.device_id
       OR receipt_row.jkt IS DISTINCT FROM session_row.jkt
       OR receipt_row.auth_generation <> session_row.auth_generation
       OR receipt_row.protocol_instance_id <> session_row.protocol_instance_id
       OR receipt_row.cursor_key_id <> session_row.cursor_key_id
       OR receipt_row.cursor_format_version <> session_row.cursor_format_version
       OR receipt_row.snapshot_event_position <> session_row.snapshot_event_position
       OR receipt_row.snapshot_event_cursor_sha256 <> session_row.snapshot_event_cursor_sha256
       OR receipt_row.snapshot_retained_floor <> session_row.snapshot_retained_floor
       OR receipt_row.expires_at <> session_row.expires_at THEN
        RAISE EXCEPTION 'inventory page receipt session binding mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.enforce_inventory_page_receipt_session_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        PERFORM chat.assert_inventory_page_receipt_session_binding(NEW.page_receipt_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS inventory_page_receipts_session_binding_deferred ON chat.inventory_page_receipts;
CREATE CONSTRAINT TRIGGER inventory_page_receipts_session_binding_deferred
AFTER INSERT OR UPDATE ON chat.inventory_page_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_page_receipt_session_binding();

-- 11. Null-safe event cursor receipt session binding guard.
CREATE OR REPLACE FUNCTION chat.assert_event_cursor_receipt_session_binding(target_cursor BYTEA)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    receipt_row chat.event_cursor_receipts%ROWTYPE;
    session_row chat.inventory_sessions%ROWTYPE;
BEGIN
    SELECT * INTO receipt_row
      FROM chat.event_cursor_receipts
     WHERE cursor_hash = target_cursor;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = receipt_row.inventory_session_id;
    IF NOT FOUND
       OR receipt_row.user_did <> session_row.user_did
       OR receipt_row.device_id <> session_row.device_id
       OR receipt_row.jkt IS DISTINCT FROM session_row.jkt
       OR receipt_row.auth_generation <> session_row.auth_generation
       OR receipt_row.protocol_instance_id <> session_row.protocol_instance_id
       OR receipt_row.cursor_key_id <> session_row.cursor_key_id
       OR receipt_row.retained_floor_at_issue <> session_row.snapshot_retained_floor
       OR receipt_row.expires_at <> session_row.expires_at THEN
        RAISE EXCEPTION 'event cursor receipt session binding mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.enforce_event_cursor_receipt_session_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        PERFORM chat.assert_event_cursor_receipt_session_binding(NEW.cursor_hash);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS event_cursor_receipts_session_binding_deferred ON chat.event_cursor_receipts;
CREATE CONSTRAINT TRIGGER event_cursor_receipts_session_binding_deferred
AFTER INSERT OR UPDATE ON chat.event_cursor_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_event_cursor_receipt_session_binding();
-- 10. Update chat.enforce_core_lifecycle_transition() trigger function,
-- copied verbatim from 20260730000001_reset_request_revocation_terminal.sql with
-- only the device JKT predicate modified for nullable dpop_jkt.
CREATE OR REPLACE FUNCTION chat.enforce_core_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_kind TEXT;
BEGIN
    IF TG_TABLE_NAME = 'devices' THEN
        IF OLD.status = 'revoked' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'revoked device is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.auth_generation < OLD.auth_generation
           OR NEW.auth_generation > OLD.auth_generation + 1
           OR (OLD.dpop_jkt IS NOT NULL AND NEW.dpop_jkt IS NOT NULL
               AND ((NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt)
                    <> (NEW.auth_generation = OLD.auth_generation + 1)))
           OR NEW.updated_at < OLD.updated_at
           OR (OLD.status = 'active' AND NEW.status NOT IN ('active','revoked')) THEN
            RAISE EXCEPTION 'invalid device lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'device_keys' THEN
        IF OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'revoked device key is terminal' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'key_packages' THEN
        IF OLD.status IN ('consumed','expired','revoked') AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal KeyPackage cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF (OLD.status = 'available' AND NEW.status NOT IN ('available','reserved','expired','revoked'))
           OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved','available','consumed','expired','revoked'))
           OR NEW.terminal_at < OLD.terminal_at THEN
            RAISE EXCEPTION 'invalid KeyPackage lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'conversations' THEN
        IF OLD.lifecycle = 'superseded' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'superseded conversation is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.current_generation < OLD.current_generation
           OR (NEW.current_generation = OLD.current_generation
               AND NEW.current_state_version < OLD.current_state_version)
           OR NEW.next_entry_seq < OLD.next_entry_seq
           OR (OLD.lifecycle = 'active' AND NEW.lifecycle NOT IN ('active','superseded')) THEN
            RAISE EXCEPTION 'invalid conversation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'generations' THEN
        IF OLD.lifecycle = 'superseded' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'superseded generation is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.current_state_version < OLD.current_state_version
           OR (OLD.lifecycle = 'active' AND NEW.lifecycle NOT IN ('active','superseded')) THEN
            RAISE EXCEPTION 'invalid generation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'participants' THEN
        SELECT kind INTO conversation_kind
          FROM chat.conversations
         WHERE conversation_id = NEW.conversation_id;
        IF NOT OLD.current_membership AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'closed participant period is terminal' USING ERRCODE = '23514';
        END IF;
        IF ((NEW.role IS DISTINCT FROM OLD.role) <> (
                NEW.role_transition_id IS DISTINCT FROM OLD.role_transition_id
                AND NEW.role_changed_at > OLD.role_changed_at
            ))
           OR ((NEW.role_transition_id IS DISTINCT FROM OLD.role_transition_id)
               <> (NEW.role_changed_at IS DISTINCT FROM OLD.role_changed_at))
           OR (NEW.role IS DISTINCT FROM OLD.role AND (
                conversation_kind <> 'group'
                OR OLD.status <> 'active' OR NEW.status <> 'active'
                OR NOT OLD.current_membership OR NOT NEW.current_membership
           ))
           OR (OLD.status = 'active' AND NEW.status <> 'active')
           OR (OLD.status = 'pending' AND NEW.status NOT IN ('pending','active'))
           OR (NOT OLD.current_membership AND NEW.current_membership)
           OR (OLD.acceptance_transition_id IS NOT NULL
               AND (NEW.acceptance_transition_id, NEW.acceptance_entry_id, NEW.accepted_at)
                   IS DISTINCT FROM
                   (OLD.acceptance_transition_id, OLD.acceptance_entry_id, OLD.accepted_at))
           OR (OLD.removing_transition_id IS NOT NULL
               AND (NEW.removing_transition_id, NEW.removing_seq, NEW.removed_at)
                   IS DISTINCT FROM
                   (OLD.removing_transition_id, OLD.removing_seq, OLD.removed_at)) THEN
            RAISE EXCEPTION 'invalid participant lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'member_devices' THEN
        IF NOT OLD.active AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'closed leaf period is terminal' USING ERRCODE = '23514';
        END IF;
        IF (NOT OLD.active AND NEW.active)
           OR (OLD.removed_transition_id IS NOT NULL
               AND (NEW.removed_state_version, NEW.removed_transition_id,
                    NEW.removed_seq, NEW.removed_at)
                   IS DISTINCT FROM
                   (OLD.removed_state_version, OLD.removed_transition_id,
                    OLD.removed_seq, OLD.removed_at)) THEN
            RAISE EXCEPTION 'invalid leaf lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'key_package_reservations' THEN
        IF OLD.status <> 'active' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal reservation cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'active'
           AND NEW.status NOT IN ('active','consumed','expired','released') THEN
            RAISE EXCEPTION 'invalid reservation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'reset_requests' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal reset request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending'
           AND NEW.status NOT IN ('pending','stale','consumed','expired','revoked') THEN
            RAISE EXCEPTION 'invalid reset request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'leaf_recovery_requests' THEN
        IF OLD.status <> 'open' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal recovery request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'open'
           AND NEW.status NOT IN ('open','fulfilled','cancelled','expired','superseded') THEN
            RAISE EXCEPTION 'invalid recovery request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'leave_requests' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal leave request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending'
           AND NEW.status NOT IN ('pending','fulfilled','cancelled','expired','stale') THEN
            RAISE EXCEPTION 'invalid leave request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'relationship_projection_revision_allocations' THEN
        IF OLD.consumed_projection_id IS NOT NULL
           OR OLD.consumed_at IS NOT NULL
           OR NEW.consumed_projection_id IS NULL
           OR NEW.consumed_at IS NULL
           OR NEW.consumed_at < OLD.allocated_at THEN
            RAISE EXCEPTION 'invalid relationship projection allocation lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON TABLE chat.devices IS
    'Multi-device registry tracking all active/revoked devices per user. Standard service-authenticated devices leave dpop_jkt NULL.';

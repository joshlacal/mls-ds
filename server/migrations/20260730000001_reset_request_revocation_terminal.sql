-- Finding 3, fix (b): give chat.reset_requests a revocation-bound terminal.
--
-- revokeDevice must be able to terminalize the revoked principal's pending
-- reset requests. Before this migration it could not, because no terminal shape
-- fitted a revocation: 'stale' and 'consumed' both require a NON-NULL
-- terminal_transition_id (FK to chat.transitions) and a revocation performs no
-- transition, while 'expired' pins terminal_at = expires_at and would therefore
-- record a false expiry instant. The table simply never received the treatment
-- chat.leaf_recovery_requests already has.
--
-- This mirrors that precedent: a terminal_revocation_id column, a status whose
-- shape requires it, and the same composite FK into chat.device_revocations,
-- which structurally guarantees the terminalized row's requester IS the revoked
-- target -- a reset request can never be attributed to someone else's
-- revocation.
--
-- Deliberately NO upper bound on terminal_at for the 'revoked' arm. A device may
-- be revoked long after a pending request lapsed, and binding terminal_at to
-- <= expires_at would make revokeDevice itself fail with 23514 on exactly those
-- rows. The lower bound stays: a revocation cannot pre-date the request its
-- requester signed.
--
-- Existing rows are untouched. Every previously valid (status, terminal columns)
-- combination still binds exactly as before; the new arm is additive.

ALTER TABLE chat.reset_requests
    ADD COLUMN IF NOT EXISTS terminal_revocation_id UUID;

ALTER TABLE chat.reset_requests
    DROP CONSTRAINT IF EXISTS reset_requests_status_check,
    ADD CONSTRAINT reset_requests_status_check
        CHECK (status IN ('pending','stale','consumed','expired','revoked'));

ALTER TABLE chat.reset_requests
    DROP CONSTRAINT IF EXISTS reset_requests_terminal_transition_check,
    ADD CONSTRAINT reset_requests_terminal_transition_check CHECK (
        (terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id))
        AND (terminal_revocation_id IS NULL OR chat.is_uuid_v4(terminal_revocation_id))
    );

ALTER TABLE chat.reset_requests
    DROP CONSTRAINT IF EXISTS reset_requests_terminal_shape_check,
    ADD CONSTRAINT reset_requests_terminal_shape_check CHECK (
        (status = 'pending' AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at IS NULL)
        OR (status IN ('stale','consumed')
            AND terminal_transition_id IS NOT NULL
            AND terminal_revocation_id IS NULL AND terminal_at IS NOT NULL)
        OR (status = 'expired' AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at = expires_at)
        OR (status = 'revoked' AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NOT NULL
            -- terminal_at IS NOT NULL is load-bearing, not redundant: a CHECK
            -- fails only on FALSE, and a bare `terminal_at >= received_at`
            -- evaluates to NULL when terminal_at is NULL, so the whole
            -- constraint would evaluate NULL and ADMIT a revoked row with no
            -- terminal instant.
            AND terminal_at IS NOT NULL
            AND terminal_at >= received_at)
    );

ALTER TABLE chat.reset_requests
    ADD CONSTRAINT reset_requests_terminal_revocation_fk FOREIGN KEY (
        requester_did, requester_device_id, terminal_revocation_id, terminal_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED;

-- The immutability trigger whitelists the EXACT set of mutable columns, so a new
-- terminal column is unwritable until it joins that list. Without this the
-- 'revoked' arm above would be unreachable: the CHECK admits the shape and the
-- BEFORE trigger then rejects the write as an identity change. Re-created rather
-- than altered because the column list is a trigger argument.
DROP TRIGGER IF EXISTS reset_requests_identity_immutable ON chat.reset_requests;

CREATE TRIGGER reset_requests_identity_immutable
BEFORE UPDATE OR DELETE ON chat.reset_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at'
);

-- Reproduced verbatim from 20260722000001_chat_protocol_core.sql with exactly
-- one change: the reset_requests arm admits 'revoked' as a terminal successor
-- of 'pending'. Every other table's rules are byte-identical.
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
           OR ((NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt)
               <> (NEW.auth_generation = OLD.auth_generation + 1))
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
END
$$;

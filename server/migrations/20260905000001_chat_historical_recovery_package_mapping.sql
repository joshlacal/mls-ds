-- Exact deployed-function custody guard. Do not amend an earlier migration.
-- No data rewrite, trigger change, constraint timing change, or lock-scope change.
DO $preflight$
BEGIN
    IF to_regprocedure('chat.recovery_released_package_has_valid_current_mapping(uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'historical recovery package helper already exists';
    END IF;
    IF pg_get_functiondef('chat.assert_recovery_fulfillment_mapping(uuid)'::regprocedure)
       IS DISTINCT FROM $expected_deployed$CREATE OR REPLACE FUNCTION chat.assert_recovery_fulfillment_mapping(target_request uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
DECLARE
    request_row chat.leaf_recovery_requests%ROWTYPE;
    reservation_row chat.key_package_reservations%ROWTYPE;
    package_row chat.key_packages%ROWTYPE;
    terminal_transition chat.transitions%ROWTYPE;
    delivery_count BIGINT;
    linked_welcome UUID;
BEGIN
    SELECT * INTO request_row
      FROM chat.leaf_recovery_requests
     WHERE recovery_request_id = target_request;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.welcome_deliveries
             WHERE recovery_request_id = target_request
        ) THEN
            RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = request_row.conversation_id
     FOR UPDATE;
    SELECT * INTO reservation_row
      FROM chat.key_package_reservations
     WHERE recovery_request_id = target_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
            USING ERRCODE = '23514';
    END IF;
    SELECT * INTO package_row
      FROM chat.key_packages
     WHERE key_package_ref = reservation_row.key_package_ref
       AND owner_did = reservation_row.recipient_did
       AND owner_device_id = reservation_row.recipient_device_id;
    IF NOT FOUND
       OR reservation_row.conversation_id <> request_row.conversation_id
       OR reservation_row.generation <> request_row.generation
       OR reservation_row.requester_did <> request_row.requester_did
       OR reservation_row.requester_device_id <> request_row.requester_device_id
       OR reservation_row.requester_key_id <> request_row.requester_key_id
       OR reservation_row.requester_auth_generation <> request_row.requester_auth_generation
       OR reservation_row.recipient_did <> request_row.requester_did
       OR reservation_row.recipient_device_id <> request_row.requester_device_id
       OR reservation_row.bound_state_version <> request_row.bound_state_version
       OR reservation_row.bound_group_id <> request_row.bound_group_id
       OR reservation_row.bound_epoch <> request_row.bound_epoch
       OR reservation_row.bound_group_context_hash <> request_row.bound_group_context_hash
       OR reservation_row.bound_confirmation_tag <> request_row.bound_confirmation_tag
       OR reservation_row.created_at <> request_row.requested_at
       OR reservation_row.expires_at <> request_row.expires_at
       OR reservation_row.expires_at
          <> LEAST(reservation_row.created_at + INTERVAL '5 minutes', package_row.not_after)
       OR NOT EXISTS (
            SELECT 1 FROM chat.participants participant
             WHERE participant.conversation_id = request_row.conversation_id
               AND participant.user_did = request_row.requester_did
               AND participant.status = 'active'
               AND participant.created_at <= request_row.requested_at
               AND (participant.accepted_at IS NULL
                    OR participant.accepted_at <= request_row.requested_at)
               AND (participant.removed_at IS NULL
                    OR participant.removed_at >= request_row.requested_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices device
              JOIN chat.device_keys device_key
                ON device_key.user_did = device.user_did
               AND device_key.device_id = device.device_id
               AND device_key.key_id = request_row.requester_key_id
             WHERE device.user_did = request_row.requester_did
               AND device.device_id = request_row.requester_device_id
               AND device.created_at <= request_row.requested_at
               AND (device.revoked_at IS NULL
                    OR device.revoked_at >= request_row.requested_at)
               AND device_key.created_at <= request_row.requested_at
               AND (device_key.revoked_at IS NULL
                    OR device_key.revoked_at >= request_row.requested_at)
       )
       OR NOT EXISTS (
            SELECT 1 FROM chat.generation_states state
             WHERE state.conversation_id = request_row.conversation_id
               AND state.generation = request_row.generation
               AND state.state_version = request_row.bound_state_version
               AND state.created_at <= request_row.requested_at
       )
       OR (
            request_row.recovery_kind = 'replace'
            AND NOT EXISTS (
                SELECT 1 FROM chat.member_devices member
                 WHERE member.leaf_period_id = request_row.replaced_leaf_period_id
                   AND member.conversation_id = request_row.conversation_id
                   AND member.generation = request_row.generation
                   AND member.user_did = request_row.requester_did
                   AND member.device_id = request_row.requester_device_id
                   AND member.joined_state_version <= request_row.bound_state_version
                   AND (member.removed_state_version IS NULL
                        OR member.removed_state_version > request_row.bound_state_version)
            )
       )
       OR (
            request_row.recovery_kind = 'add'
            AND EXISTS (
                SELECT 1 FROM chat.member_devices member
                 WHERE member.conversation_id = request_row.conversation_id
                   AND member.generation = request_row.generation
                   AND member.user_did = request_row.requester_did
                   AND member.device_id = request_row.requester_device_id
                   AND member.joined_state_version <= request_row.bound_state_version
                   AND (member.removed_state_version IS NULL
                        OR member.removed_state_version > request_row.bound_state_version)
            )
       )
    THEN
        RAISE EXCEPTION 'recovery request reservation mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO delivery_count
      FROM chat.welcome_deliveries
     WHERE recovery_request_id = target_request;
    SELECT welcome_id INTO linked_welcome
      FROM chat.welcome_deliveries
     WHERE recovery_request_id = target_request
     LIMIT 1;

    IF request_row.status = 'fulfilled' THEN
        SELECT * INTO terminal_transition
          FROM chat.transitions
         WHERE transition_id = request_row.fulfilling_transition_id;
        IF delivery_count <> 1
           OR NOT FOUND
           OR terminal_transition.kind <> 'leafRecovery'
           OR terminal_transition.conversation_id <> request_row.conversation_id
           OR terminal_transition.prior_generation <> request_row.generation
           OR terminal_transition.prior_state_version <> request_row.bound_state_version
           OR terminal_transition.accepted_at <> request_row.terminal_at
           OR request_row.terminal_at >= request_row.expires_at
           OR reservation_row.status <> 'consumed'
           OR reservation_row.consumed_transition_id
              IS DISTINCT FROM request_row.fulfilling_transition_id
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR package_row.status <> 'consumed'
           OR package_row.terminal_transition_id
              IS DISTINCT FROM request_row.fulfilling_transition_id
           OR package_row.terminal_revocation_id IS NOT NULL
           OR package_row.terminal_at <> request_row.terminal_at
           OR request_row.terminal_at >= package_row.not_after THEN
            RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM chat.member_devices member
             WHERE member.conversation_id = request_row.conversation_id
               AND member.generation = request_row.generation
               AND member.user_did = request_row.requester_did
               AND member.device_id = request_row.requester_device_id
               AND member.origin = 'keyPackage'
               AND member.join_key_package_ref = reservation_row.key_package_ref
               AND member.joined_transition_id = request_row.fulfilling_transition_id
               AND (
                    (request_row.recovery_kind = 'add')
                    OR (request_row.recovery_kind = 'replace'
                        AND EXISTS (
                            SELECT 1 FROM chat.member_devices replaced
                             WHERE replaced.leaf_period_id = request_row.replaced_leaf_period_id
                               AND replaced.removed_transition_id
                                   = request_row.fulfilling_transition_id
                        ))
               )
        ) THEN
            RAISE EXCEPTION 'recovery fulfillment leaf kind mismatch'
                USING ERRCODE = '23514';
        END IF;
        PERFORM chat.assert_welcome_mapping(linked_welcome);
    ELSIF request_row.status = 'open' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'active'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR package_row.status <> 'reserved'
           OR package_row.terminal_transition_id IS NOT NULL
           OR package_row.terminal_revocation_id IS NOT NULL THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'cancelled' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'released'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest
              IS DISTINCT FROM request_row.terminal_request_digest
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR package_row.status <> 'available'
           OR package_row.terminal_transition_id IS NOT NULL
           OR package_row.terminal_revocation_id IS NOT NULL
           OR package_row.terminal_at IS NOT NULL THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'superseded' THEN
        IF request_row.terminal_transition_id IS NOT NULL THEN
            SELECT * INTO terminal_transition
              FROM chat.transitions
             WHERE transition_id = request_row.terminal_transition_id;
            IF NOT FOUND
               OR terminal_transition.conversation_id <> request_row.conversation_id
               OR terminal_transition.prior_generation <> request_row.generation
               OR terminal_transition.prior_state_version <> request_row.bound_state_version
               OR terminal_transition.accepted_at <> request_row.terminal_at THEN
                RAISE EXCEPTION 'recovery superseding transition mismatch'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        IF delivery_count <> 0
           OR reservation_row.status <> 'released'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id
              IS DISTINCT FROM request_row.terminal_transition_id
           OR reservation_row.terminal_revocation_id
              IS DISTINCT FROM request_row.terminal_revocation_id
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR (
                request_row.terminal_revocation_id IS NOT NULL
                AND (
                    package_row.status <> 'revoked'
                    OR package_row.terminal_revocation_id
                       IS DISTINCT FROM request_row.terminal_revocation_id
                    OR package_row.terminal_at <> request_row.terminal_at
                )
           )
           OR (
                request_row.terminal_transition_id IS NOT NULL
                AND (
                    package_row.status <> 'available'
                    OR package_row.terminal_transition_id IS NOT NULL
                    OR package_row.terminal_revocation_id IS NOT NULL
                    OR package_row.terminal_at IS NOT NULL
                )
           ) THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'expired' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'expired'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR reservation_row.terminal_at <> request_row.expires_at
           OR (
                (request_row.expires_at = package_row.not_after
                    AND (package_row.status <> 'expired'
                         OR package_row.terminal_at <> package_row.not_after))
                OR (request_row.expires_at < package_row.not_after
                    AND (package_row.status <> 'available'
                         OR package_row.terminal_at IS NOT NULL))
           ) THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$function$
$expected_deployed$ THEN
        RAISE EXCEPTION 'recovery fulfillment guard differs from reviewed deployed definition';
    END IF;
END
$preflight$;

-- A retained release describes the old reservation, not the package's current
-- owner. Later reuse must have its own exact reservation/request and cannot
-- predate the retained release. Equality is intentional for millisecond times.
-- Read-only: no recursive mapping calls or additional row-lock acquisition.
CREATE FUNCTION chat.recovery_released_package_has_valid_current_mapping(target_request UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $released_package$
DECLARE
    retained chat.key_package_reservations%ROWTYPE;
    package_row chat.key_packages%ROWTYPE;
    active_count BIGINT;
    consumed_count BIGINT;
BEGIN
    SELECT * INTO retained FROM chat.key_package_reservations
     WHERE recovery_request_id = target_request;
    IF NOT FOUND OR retained.terminal_at IS NULL
       OR retained.status NOT IN ('released', 'expired')
       OR retained.consumed_transition_id IS NOT NULL
       OR retained.terminal_revocation_id IS NOT NULL THEN
        RETURN FALSE;
    END IF;
    SELECT * INTO package_row FROM chat.key_packages
     WHERE key_package_ref = retained.key_package_ref;
    IF NOT FOUND
       OR (package_row.owner_did, package_row.owner_device_id,
           package_row.owner_key_id, package_row.owner_auth_generation)
          IS DISTINCT FROM
          (retained.requester_did, retained.requester_device_id,
           retained.requester_key_id, retained.requester_auth_generation)
       OR (package_row.owner_did, package_row.owner_device_id)
          IS DISTINCT FROM (retained.recipient_did, retained.recipient_device_id)
       OR retained.terminal_at >= package_row.not_after THEN
        RETURN FALSE;
    END IF;

    -- The existing assert_key_package_reservation_mapping and its deferred
    -- triggers remain in force. Check the same current cardinality here
    -- without taking the principal lock a second time from a new call site.
    SELECT count(*) FILTER (WHERE status = 'active'),
           count(*) FILTER (WHERE status = 'consumed'
                AND consumed_transition_id = package_row.terminal_transition_id)
      INTO active_count, consumed_count
      FROM chat.key_package_reservations
     WHERE key_package_ref = package_row.key_package_ref;
    IF (package_row.status = 'reserved' AND active_count <> 1)
       OR (package_row.status <> 'reserved' AND active_count <> 0)
       OR (package_row.status = 'consumed' AND consumed_count <> 1) THEN
        RETURN FALSE;
    END IF;

    IF package_row.status = 'available' THEN
        RETURN package_row.terminal_transition_id IS NULL
           AND package_row.terminal_revocation_id IS NULL
           AND package_row.terminal_at IS NULL;
    ELSIF package_row.status = 'expired' THEN
        RETURN package_row.terminal_transition_id IS NULL
           AND package_row.terminal_revocation_id IS NULL
           AND package_row.terminal_at IS NOT DISTINCT FROM package_row.not_after
           AND package_row.terminal_at >= retained.terminal_at;
    ELSIF package_row.status = 'revoked' THEN
        RETURN package_row.terminal_transition_id IS NULL
           AND package_row.terminal_revocation_id IS NOT NULL
           AND package_row.terminal_at >= retained.terminal_at
           AND package_row.terminal_at < package_row.not_after
           AND EXISTS (
                SELECT 1 FROM chat.device_revocations revocation
                 WHERE revocation.revocation_id = package_row.terminal_revocation_id
                   AND revocation.target_did = package_row.owner_did
                   AND revocation.target_device_id = package_row.owner_device_id
                   AND revocation.target_auth_generation = package_row.owner_auth_generation
                   AND revocation.accepted_at = package_row.terminal_at
           );
    ELSIF package_row.status NOT IN ('reserved', 'consumed') THEN
        RETURN FALSE;
    END IF;

    RETURN EXISTS (
        SELECT 1
          FROM chat.key_package_reservations current_reservation
          JOIN chat.leaf_recovery_requests current_request
            ON current_request.recovery_request_id = current_reservation.recovery_request_id
           AND current_request.reservation_request_id = current_reservation.recovery_request_id
         WHERE current_reservation.key_package_ref = package_row.key_package_ref
           AND current_reservation.recovery_request_id <> retained.recovery_request_id
           AND current_reservation.requester_did = package_row.owner_did
           AND current_reservation.requester_device_id = package_row.owner_device_id
           AND current_reservation.requester_key_id = package_row.owner_key_id
           AND current_reservation.requester_auth_generation = package_row.owner_auth_generation
           AND current_reservation.recipient_did = package_row.owner_did
           AND current_reservation.recipient_device_id = package_row.owner_device_id
           AND current_reservation.purpose = 'leafRecovery'
           AND current_reservation.created_at >= retained.terminal_at
           AND current_reservation.created_at < current_reservation.expires_at
           AND current_reservation.expires_at = LEAST(
                current_reservation.created_at + INTERVAL '5 minutes', package_row.not_after)
           AND (current_request.conversation_id, current_request.generation,
                current_request.requester_did, current_request.requester_device_id,
                current_request.requester_key_id, current_request.requester_auth_generation,
                current_request.bound_state_version, current_request.bound_group_id,
                current_request.bound_epoch, current_request.bound_group_context_hash,
                current_request.bound_confirmation_tag, current_request.requested_at,
                current_request.expires_at)
               = (current_reservation.conversation_id, current_reservation.generation,
                  current_reservation.requester_did, current_reservation.requester_device_id,
                  current_reservation.requester_key_id, current_reservation.requester_auth_generation,
                  current_reservation.bound_state_version, current_reservation.bound_group_id,
                  current_reservation.bound_epoch, current_reservation.bound_group_context_hash,
                  current_reservation.bound_confirmation_tag, current_reservation.created_at,
                  current_reservation.expires_at)
           AND current_reservation.terminal_transition_id IS NULL
           AND current_reservation.terminal_revocation_id IS NULL
           AND current_reservation.terminal_request_digest IS NULL
           AND current_request.terminal_transition_id IS NULL
           AND current_request.terminal_revocation_id IS NULL
           AND current_request.terminal_request_digest IS NULL
           AND (
                (package_row.status = 'reserved'
                    AND package_row.terminal_transition_id IS NULL
                    AND package_row.terminal_revocation_id IS NULL
                    AND package_row.terminal_at IS NULL
                    AND current_reservation.status = 'active'
                    AND current_reservation.consumed_transition_id IS NULL
                    AND current_reservation.terminal_at IS NULL
                    AND current_request.status = 'open'
                    AND current_request.fulfilling_transition_id IS NULL
                    AND current_request.terminal_at IS NULL)
                OR
                (package_row.status = 'consumed'
                    AND package_row.terminal_transition_id IS NOT NULL
                    AND package_row.terminal_revocation_id IS NULL
                    AND package_row.terminal_at >= retained.terminal_at
                    AND package_row.terminal_at < package_row.not_after
                    AND current_reservation.status = 'consumed'
                    AND current_reservation.consumed_transition_id = package_row.terminal_transition_id
                    AND current_reservation.terminal_at = package_row.terminal_at
                    AND current_reservation.terminal_at >= current_reservation.created_at
                    AND current_reservation.terminal_at < current_reservation.expires_at
                    AND current_request.status = 'fulfilled'
                    AND current_request.fulfilling_transition_id = package_row.terminal_transition_id
                    AND current_request.terminal_at = package_row.terminal_at
                    AND EXISTS (
                        SELECT 1 FROM chat.transitions transition
                         WHERE transition.transition_id = package_row.terminal_transition_id
                           AND transition.kind = 'leafRecovery'
                           AND transition.conversation_id = current_reservation.conversation_id
                           AND transition.prior_generation = current_reservation.generation
                           AND transition.prior_state_version = current_reservation.bound_state_version
                           AND transition.accepted_at = package_row.terminal_at
                    ))
           )
    );
END
$released_package$;

CREATE OR REPLACE FUNCTION chat.assert_recovery_fulfillment_mapping(target_request uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
DECLARE
    request_row chat.leaf_recovery_requests%ROWTYPE;
    reservation_row chat.key_package_reservations%ROWTYPE;
    package_row chat.key_packages%ROWTYPE;
    terminal_transition chat.transitions%ROWTYPE;
    delivery_count BIGINT;
    linked_welcome UUID;
BEGIN
    SELECT * INTO request_row
      FROM chat.leaf_recovery_requests
     WHERE recovery_request_id = target_request;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.welcome_deliveries
             WHERE recovery_request_id = target_request
        ) THEN
            RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = request_row.conversation_id
     FOR UPDATE;
    SELECT * INTO reservation_row
      FROM chat.key_package_reservations
     WHERE recovery_request_id = target_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
            USING ERRCODE = '23514';
    END IF;
    SELECT * INTO package_row
      FROM chat.key_packages
     WHERE key_package_ref = reservation_row.key_package_ref
       AND owner_did = reservation_row.recipient_did
       AND owner_device_id = reservation_row.recipient_device_id;
    IF NOT FOUND
       OR reservation_row.conversation_id <> request_row.conversation_id
       OR reservation_row.generation <> request_row.generation
       OR reservation_row.requester_did <> request_row.requester_did
       OR reservation_row.requester_device_id <> request_row.requester_device_id
       OR reservation_row.requester_key_id <> request_row.requester_key_id
       OR reservation_row.requester_auth_generation <> request_row.requester_auth_generation
       OR reservation_row.recipient_did <> request_row.requester_did
       OR reservation_row.recipient_device_id <> request_row.requester_device_id
       OR reservation_row.bound_state_version <> request_row.bound_state_version
       OR reservation_row.bound_group_id <> request_row.bound_group_id
       OR reservation_row.bound_epoch <> request_row.bound_epoch
       OR reservation_row.bound_group_context_hash <> request_row.bound_group_context_hash
       OR reservation_row.bound_confirmation_tag <> request_row.bound_confirmation_tag
       OR reservation_row.created_at <> request_row.requested_at
       OR reservation_row.expires_at <> request_row.expires_at
       OR reservation_row.expires_at
          <> LEAST(reservation_row.created_at + INTERVAL '5 minutes', package_row.not_after)
       OR NOT EXISTS (
            SELECT 1 FROM chat.participants participant
             WHERE participant.conversation_id = request_row.conversation_id
               AND participant.user_did = request_row.requester_did
               AND participant.status = 'active'
               AND participant.created_at <= request_row.requested_at
               AND (participant.accepted_at IS NULL
                    OR participant.accepted_at <= request_row.requested_at)
               AND (participant.removed_at IS NULL
                    OR participant.removed_at >= request_row.requested_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices device
              JOIN chat.device_keys device_key
                ON device_key.user_did = device.user_did
               AND device_key.device_id = device.device_id
               AND device_key.key_id = request_row.requester_key_id
             WHERE device.user_did = request_row.requester_did
               AND device.device_id = request_row.requester_device_id
               AND device.created_at <= request_row.requested_at
               AND (device.revoked_at IS NULL
                    OR device.revoked_at >= request_row.requested_at)
               AND device_key.created_at <= request_row.requested_at
               AND (device_key.revoked_at IS NULL
                    OR device_key.revoked_at >= request_row.requested_at)
       )
       OR NOT EXISTS (
            SELECT 1 FROM chat.generation_states state
             WHERE state.conversation_id = request_row.conversation_id
               AND state.generation = request_row.generation
               AND state.state_version = request_row.bound_state_version
               AND state.created_at <= request_row.requested_at
       )
       OR (
            request_row.recovery_kind = 'replace'
            AND NOT EXISTS (
                SELECT 1 FROM chat.member_devices member
                 WHERE member.leaf_period_id = request_row.replaced_leaf_period_id
                   AND member.conversation_id = request_row.conversation_id
                   AND member.generation = request_row.generation
                   AND member.user_did = request_row.requester_did
                   AND member.device_id = request_row.requester_device_id
                   AND member.joined_state_version <= request_row.bound_state_version
                   AND (member.removed_state_version IS NULL
                        OR member.removed_state_version > request_row.bound_state_version)
            )
       )
       OR (
            request_row.recovery_kind = 'add'
            AND EXISTS (
                SELECT 1 FROM chat.member_devices member
                 WHERE member.conversation_id = request_row.conversation_id
                   AND member.generation = request_row.generation
                   AND member.user_did = request_row.requester_did
                   AND member.device_id = request_row.requester_device_id
                   AND member.joined_state_version <= request_row.bound_state_version
                   AND (member.removed_state_version IS NULL
                        OR member.removed_state_version > request_row.bound_state_version)
            )
       )
    THEN
        RAISE EXCEPTION 'recovery request reservation mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO delivery_count
      FROM chat.welcome_deliveries
     WHERE recovery_request_id = target_request;
    SELECT welcome_id INTO linked_welcome
      FROM chat.welcome_deliveries
     WHERE recovery_request_id = target_request
     LIMIT 1;

    IF request_row.status = 'fulfilled' THEN
        SELECT * INTO terminal_transition
          FROM chat.transitions
         WHERE transition_id = request_row.fulfilling_transition_id;
        IF delivery_count <> 1
           OR NOT FOUND
           OR terminal_transition.kind <> 'leafRecovery'
           OR terminal_transition.conversation_id <> request_row.conversation_id
           OR terminal_transition.prior_generation <> request_row.generation
           OR terminal_transition.prior_state_version <> request_row.bound_state_version
           OR terminal_transition.accepted_at <> request_row.terminal_at
           OR request_row.terminal_at >= request_row.expires_at
           OR reservation_row.status <> 'consumed'
           OR reservation_row.consumed_transition_id
              IS DISTINCT FROM request_row.fulfilling_transition_id
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR package_row.status <> 'consumed'
           OR package_row.terminal_transition_id
              IS DISTINCT FROM request_row.fulfilling_transition_id
           OR package_row.terminal_revocation_id IS NOT NULL
           OR package_row.terminal_at <> request_row.terminal_at
           OR request_row.terminal_at >= package_row.not_after THEN
            RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM chat.member_devices member
             WHERE member.conversation_id = request_row.conversation_id
               AND member.generation = request_row.generation
               AND member.user_did = request_row.requester_did
               AND member.device_id = request_row.requester_device_id
               AND member.origin = 'keyPackage'
               AND member.join_key_package_ref = reservation_row.key_package_ref
               AND member.joined_transition_id = request_row.fulfilling_transition_id
               AND (
                    (request_row.recovery_kind = 'add')
                    OR (request_row.recovery_kind = 'replace'
                        AND EXISTS (
                            SELECT 1 FROM chat.member_devices replaced
                             WHERE replaced.leaf_period_id = request_row.replaced_leaf_period_id
                               AND replaced.removed_transition_id
                                   = request_row.fulfilling_transition_id
                        ))
               )
        ) THEN
            RAISE EXCEPTION 'recovery fulfillment leaf kind mismatch'
                USING ERRCODE = '23514';
        END IF;
        PERFORM chat.assert_welcome_mapping(linked_welcome);
    ELSIF request_row.status = 'open' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'active'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR package_row.status <> 'reserved'
           OR package_row.terminal_transition_id IS NOT NULL
           OR package_row.terminal_revocation_id IS NOT NULL THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'cancelled' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'released'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest
              IS DISTINCT FROM request_row.terminal_request_digest
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR chat.recovery_released_package_has_valid_current_mapping(target_request) IS NOT TRUE THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'superseded' THEN
        IF request_row.terminal_transition_id IS NOT NULL THEN
            SELECT * INTO terminal_transition
              FROM chat.transitions
             WHERE transition_id = request_row.terminal_transition_id;
            IF NOT FOUND
               OR terminal_transition.conversation_id <> request_row.conversation_id
               OR terminal_transition.prior_generation <> request_row.generation
               OR terminal_transition.prior_state_version <> request_row.bound_state_version
               OR terminal_transition.accepted_at <> request_row.terminal_at THEN
                RAISE EXCEPTION 'recovery superseding transition mismatch'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        IF delivery_count <> 0
           OR reservation_row.status <> 'released'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id
              IS DISTINCT FROM request_row.terminal_transition_id
           OR reservation_row.terminal_revocation_id
              IS DISTINCT FROM request_row.terminal_revocation_id
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR reservation_row.terminal_at <> request_row.terminal_at
           OR (
                request_row.terminal_revocation_id IS NOT NULL
                AND (
                    package_row.status <> 'revoked'
                    OR package_row.terminal_revocation_id
                       IS DISTINCT FROM request_row.terminal_revocation_id
                    OR package_row.terminal_at <> request_row.terminal_at
                )
           )
           OR (
                request_row.terminal_transition_id IS NOT NULL
                AND chat.recovery_released_package_has_valid_current_mapping(target_request) IS NOT TRUE
           ) THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF request_row.status = 'expired' THEN
        IF delivery_count <> 0
           OR reservation_row.status <> 'expired'
           OR reservation_row.consumed_transition_id IS NOT NULL
           OR reservation_row.terminal_transition_id IS NOT NULL
           OR reservation_row.terminal_revocation_id IS NOT NULL
           OR reservation_row.terminal_request_digest IS NOT NULL
           OR reservation_row.terminal_at <> request_row.expires_at
           OR (
                (request_row.expires_at = package_row.not_after
                    AND (package_row.status <> 'expired'
                         OR package_row.terminal_at <> package_row.not_after))
                OR (request_row.expires_at < package_row.not_after
                    AND chat.recovery_released_package_has_valid_current_mapping(target_request) IS NOT TRUE)
           ) THEN
            RAISE EXCEPTION 'recovery request reservation mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$function$;

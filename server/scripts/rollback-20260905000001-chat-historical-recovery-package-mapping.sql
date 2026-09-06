-- REVIEW-ONLY rollback definition, not an automatically safe inverse.
-- Once retained historical releases coexist with later package reuse, restoring
-- the old guard makes those valid durable rows fail mapping. Prefer a reviewed
-- forward repair. A rollback decision requires a separate data compatibility
-- audit and deployment approval; this file makes no data changes.
-- Quiesce protocol writers before this compatibility scan and keep them stopped
-- through the transaction. BEGIN alone does not exclude concurrent reuse commits.
-- An alternative maintenance lock strategy requires separate review.
-- Apply atomically only after those gates. SQLx migration metadata is untouched.
BEGIN;
-- Refuse blind schema reversal after the newly legal reuse has occurred.
DO $rollback_preflight$
BEGIN
    IF to_regprocedure('chat.recovery_released_package_has_valid_current_mapping(uuid)') IS NULL
       OR pg_get_functiondef('chat.assert_recovery_fulfillment_mapping(uuid)'::regprocedure)
          IS DISTINCT FROM $expected_candidate$CREATE OR REPLACE FUNCTION chat.assert_recovery_fulfillment_mapping(target_request uuid)
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
$function$
$expected_candidate$ THEN
        RAISE EXCEPTION 'reviewed historical recovery mapping is not installed';
    END IF;
    IF EXISTS (
        SELECT 1 FROM chat.leaf_recovery_requests request
        JOIN chat.key_package_reservations reservation USING (recovery_request_id)
        JOIN chat.key_packages package USING (key_package_ref)
        WHERE (request.status = 'cancelled'
            OR (request.status = 'superseded' AND request.terminal_transition_id IS NOT NULL)
            OR (request.status = 'expired' AND request.expires_at < package.not_after))
          AND (package.status <> 'available'
            OR package.terminal_transition_id IS NOT NULL
            OR package.terminal_revocation_id IS NOT NULL
            OR package.terminal_at IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'retained package reuse prevents rollback; reviewed forward repair required';
    END IF;
END
$rollback_preflight$;
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
$function$;
DROP FUNCTION chat.recovery_released_package_has_valid_current_mapping(UUID);
COMMIT;

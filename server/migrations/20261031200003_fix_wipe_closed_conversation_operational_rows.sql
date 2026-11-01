-- Migration: Fix `chat.wipe_closed_conversation_operational_rows(UUID)` operational wipe:
-- 1. Remove stale `DELETE FROM public.{federation_outbox,outbound_queue,federation_sync_state}`
--    referencing legacy tables dropped in `20261031200001_clean_slate_spaces_only.sql`.
-- 2. Delete `chat.conversation_space_writers` (`20261031200002_space_host_operational_state.sql`).
-- 3. Join `inventory_welcome_items`, `welcome_dispositions`, and `welcome_deliveries` via
--    `welcome_id IN (SELECT welcome_id FROM chat.welcome_bundles WHERE conversation_id = ...)`
--    and `inventory_recovery_items` via `leaf_recovery_request_id` / `recovery_work_id`
--    (those tables do not carry a direct `conversation_id` column).
-- 4. Order `DELETE FROM chat.key_packages` AFTER `chat.member_devices`, `chat.welcome_deliveries`,
--    `chat.key_package_reservations`, and `chat.direct_request_selected_devices` so
--    `member_devices_package_fk` and sibling key_package foreign keys are respected.

CREATE OR REPLACE FUNCTION chat.wipe_closed_conversation_operational_rows(target_conversation UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    conv_lifecycle TEXT;
    req_ids UUID[];
    gross_retained BIGINT := 0;
BEGIN
    SELECT lifecycle INTO conv_lifecycle
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    IF conv_lifecycle = 'active' THEN
        RAISE EXCEPTION 'cannot wipe operational rows of active conversation %', target_conversation
            USING ERRCODE = '23514';
    END IF;

    PERFORM chat.open_conversation_wipe_scope();

    SELECT array_agg(request_id) INTO req_ids
      FROM chat.direct_request_publications
     WHERE conversation_id = target_conversation;

    DELETE FROM chat.device_entry_acks WHERE conversation_id = target_conversation;
    DELETE FROM chat.conversation_space_writers
     WHERE space_uri IN (
         SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.conversation_space_syncers
     WHERE space_uri IN (
         SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.space_credential_jtis
     WHERE space_uri IN (
         SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.conversation_spaces WHERE conversation_id = target_conversation;

    DELETE FROM chat.direct_request_transport_entries WHERE conversation_id = target_conversation;
    DELETE FROM chat.direct_request_transport_inbox WHERE conversation_id = target_conversation;

    DELETE FROM public.federation_outbox WHERE conversation_id = target_conversation::text;
    DELETE FROM public.outbound_queue WHERE convo_id = target_conversation::text;
    DELETE FROM public.federation_sync_state WHERE convo_id = target_conversation::text;
    DELETE FROM chat.federation_delivery_receipts WHERE conversation_id = target_conversation;
    DELETE FROM chat.inventory_conversation_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.inventory_welcome_items
     WHERE welcome_id IN (
         SELECT welcome_id FROM chat.welcome_bundles WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.inventory_recovery_items
     WHERE leaf_recovery_request_id IN (
         SELECT recovery_request_id FROM chat.leaf_recovery_requests WHERE conversation_id = target_conversation
     )
        OR recovery_work_id IN (
         SELECT recovery_work_id FROM chat.recovery_work_items WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.recovery_work_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.welcome_dispositions
     WHERE welcome_id IN (
         SELECT welcome_id FROM chat.welcome_bundles WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.welcome_deliveries
     WHERE welcome_id IN (
         SELECT welcome_id FROM chat.welcome_bundles WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.welcome_bundles WHERE conversation_id = target_conversation;
    DELETE FROM chat.leaf_recovery_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.key_package_reservations WHERE conversation_id = target_conversation;
    DELETE FROM chat.leave_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.reset_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.application_schedule_terminal_proofs WHERE conversation_id = target_conversation;
    DELETE FROM chat.application_intervals WHERE conversation_id = target_conversation;
    DELETE FROM chat.entry_recipients WHERE conversation_id = target_conversation;
    DELETE FROM chat.message_sends WHERE conversation_id = target_conversation;
    DELETE FROM chat.metadata_snapshots WHERE conversation_id = target_conversation;
    DELETE FROM chat.member_devices WHERE conversation_id = target_conversation;
    DELETE FROM chat.participants WHERE conversation_id = target_conversation;

    IF req_ids IS NOT NULL THEN
        SELECT COALESCE(sum(charged_bytes), 0) INTO gross_retained
          FROM chat.direct_request_retained_charges
         WHERE request_id = ANY(req_ids);

        DELETE FROM chat.direct_request_push_event_recipients WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_push_events WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_welcome_outcomes WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_decision_slots WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_expiry_receipts WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_acceptance_claims WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_releases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_charges WHERE request_id = ANY(req_ids);
        IF gross_retained > 0 THEN
            UPDATE chat.direct_request_budget
               SET retained_bytes = GREATEST(0, retained_bytes - gross_retained)
             WHERE singleton;
        END IF;
        DELETE FROM chat.direct_request_pending_releases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_lifecycle_reserves WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_lifecycle WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_reserved_remote_packages WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_reservation_intents WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_outbound_routes WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_device_deliveries WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_selected_devices WHERE request_id = ANY(req_ids);
        DELETE FROM chat.key_packages
         WHERE terminal_remote_lease_id IN (
             SELECT lease_id FROM chat.direct_request_remote_leases WHERE request_id = ANY(req_ids)
         )
            OR terminal_transition_id = ANY(req_ids);
        DELETE FROM chat.direct_request_remote_leases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_publications WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_attempts WHERE request_id = ANY(req_ids);
    END IF;

    DELETE FROM chat.key_packages
     WHERE terminal_transition_id IN (
         SELECT transition_id FROM chat.transitions WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.entries WHERE conversation_id = target_conversation;
    DELETE FROM chat.transitions WHERE conversation_id = target_conversation;
    DELETE FROM chat.generation_states WHERE conversation_id = target_conversation;
    DELETE FROM chat.generations WHERE conversation_id = target_conversation;
    DELETE FROM chat.conversations WHERE conversation_id = target_conversation;

    RETURN TRUE;
END;
$$;

-- 5. Guard `previous_interval` inside `IF has_previous THEN ... END IF` in
--    `chat.assert_application_interval_schedule` so PL/pgSQL does not evaluate
--    unassigned `RECORD` fields when all intervals of a wiped conversation are deleted.
CREATE OR REPLACE FUNCTION chat.assert_application_interval_schedule(
    target_conversation UUID,
    target_did TEXT,
    target_device UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    has_previous BOOLEAN := FALSE;
    previous_interval RECORD;
    current_interval RECORD;
BEGIN
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    FOR current_interval IN
        SELECT * FROM chat.application_intervals
         WHERE conversation_id = target_conversation
           AND recipient_did = target_did
           AND recipient_device_id = target_device
         ORDER BY start_seq, membership_interval_id
    LOOP
        IF has_previous THEN
            IF previous_interval.terminal_seq IS NULL THEN
                RAISE EXCEPTION 'interval successor after open interval' USING ERRCODE = '23514';
            END IF;
            IF previous_interval.terminal_seq > current_interval.start_seq THEN
                RAISE EXCEPTION 'overlapping application intervals' USING ERRCODE = '23514';
            END IF;
            IF previous_interval.terminal_seq = current_interval.start_seq THEN
                IF NOT (
                    ((previous_interval.closing_kind = 'replace' AND current_interval.opening_kind = 'add')
                     OR (previous_interval.closing_kind = 'reset' AND current_interval.opening_kind = 'reset')
                     OR (previous_interval.closing_kind='directRequest' AND current_interval.opening_kind='directRequest'))
                    AND previous_interval.closing_transition_id = current_interval.opening_transition_id
                    AND previous_interval.closing_outer_entry_fingerprint = current_interval.opening_outer_entry_fingerprint
                ) THEN
                    RAISE EXCEPTION 'illegal touching application intervals' USING ERRCODE = '23514';
                END IF;
            ELSIF previous_interval.closing_kind IN ('replace','terminal')
                  OR (previous_interval.closing_kind IN ('reset','directRequest')
                      AND current_interval.opening_kind <> 'add') THEN
                RAISE EXCEPTION 'required touching boundary or terminal finality violated' USING ERRCODE = '23514';
            END IF;
        END IF;
        previous_interval := current_interval;
        has_previous := TRUE;
    END LOOP;
    IF has_previous THEN
        IF previous_interval.terminal_seq IS NOT NULL
           AND previous_interval.closing_kind = 'replace' THEN
            RAISE EXCEPTION 'replacement interval lacks touching successor'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
         WHERE proof.conversation_id = target_conversation
           AND proof.recipient_did = target_did
           AND proof.recipient_device_id = target_device
           AND EXISTS (
                SELECT 1 FROM chat.application_intervals later
                 WHERE later.conversation_id = target_conversation
                   AND later.recipient_did = target_did
                   AND later.recipient_device_id = target_device
                   AND later.start_seq >= proof.terminal_seq
           )
    ) THEN
        RAISE EXCEPTION 'application schedule continues after terminal proof'
            USING ERRCODE = '23514';
    END IF;
END
$$;

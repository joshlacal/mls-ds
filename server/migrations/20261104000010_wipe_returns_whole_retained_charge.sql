-- Migration: the close wipe returns each wiped request's whole retained charge.
--
-- `chat.direct_request_budget.retained_bytes` carries every retained charge
-- whole; a terminal prune only appends `chat.direct_request_retained_releases`,
-- which `chat.direct_request_effective_budget` subtracts. The wipe deletes a
-- request's charge together with its release, so it must take the whole charge
-- off the counter. `20261102000003` took `charged - released` off and then also
-- deleted the release, leaving the released bytes counted forever: a partially
-- pruned request leaked its release, a fully released one its whole charge.
-- Only that sum changes below; the rest of the function is `20261102000003`'s.
CREATE OR REPLACE FUNCTION chat.wipe_closed_conversation_operational_rows(target_conversation UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    conv_lifecycle TEXT;
    req_ids UUID[];
    lease_ids UUID[];
    request_packages BYTEA[];
    gross_retained BIGINT := 0;
BEGIN
    SELECT lifecycle INTO conv_lifecycle
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN
        IF NOT EXISTS (
            SELECT 1 FROM chat.conversation_close_terminal_entries terminal
            JOIN chat.events event USING (event_position)
             WHERE event.event_kind = 'conversationClosed'
               AND convert_from(event.payload_bytes, 'UTF8')::jsonb->>'conversationId'
                   = target_conversation::text
        ) THEN
            RETURN FALSE;
        END IF;
    ELSIF conv_lifecycle = 'active' THEN
        RAISE EXCEPTION 'cannot wipe operational rows of active conversation %', target_conversation
            USING ERRCODE = '23514';
    END IF;

    PERFORM chat.open_conversation_wipe_scope();

    SELECT array_agg(request_id) INTO req_ids
      FROM (
          SELECT request_id FROM chat.direct_request_publications
           WHERE conversation_id = target_conversation
          UNION
          SELECT request_id FROM chat.direct_request_transport_inbox
           WHERE conversation_id = target_conversation
      ) requests;

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

    DELETE FROM chat.inventory_welcome_items
     WHERE transport_inbox_delivery_id IN (
         SELECT delivery_id FROM chat.direct_request_transport_inbox
          WHERE conversation_id = target_conversation
     )
        OR direct_request_id = ANY(COALESCE(req_ids, ARRAY[]::UUID[]));
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
        -- Whole charges: their releases are deleted with them below.
        SELECT COALESCE(sum(charge.charged_bytes), 0)
          INTO gross_retained
          FROM chat.direct_request_retained_charges charge
         WHERE charge.request_id = ANY(req_ids);

        DELETE FROM chat.direct_request_push_event_recipients WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_push_events WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_welcome_outcomes WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_welcome_slots WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_decision_slots WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_expiry_receipts WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_acceptance_claims WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_releases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_charges WHERE request_id = ANY(req_ids);
        IF gross_retained > 0 THEN
            UPDATE chat.direct_request_budget
               SET retained_bytes = retained_bytes - gross_retained
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

        SELECT array_agg(lease_id) INTO lease_ids
          FROM chat.direct_request_remote_leases
         WHERE request_id = ANY(req_ids);
        SELECT array_agg(key_package_ref) INTO request_packages
          FROM chat.key_packages
         WHERE terminal_remote_lease_id = ANY(COALESCE(lease_ids, ARRAY[]::UUID[]))
            OR terminal_transition_id = ANY(req_ids);
        IF request_packages IS NOT NULL THEN
            -- A package can have earlier expired preparations or released
            -- remote leases. They cannot keep a spent package's operational
            -- bytes alive after its consuming conversation closes.
            DELETE FROM chat.direct_request_selected_devices WHERE key_package_ref = ANY(request_packages);
            DELETE FROM chat.direct_request_grants WHERE key_package_ref = ANY(request_packages);
            DELETE FROM chat.direct_request_retired_packages WHERE key_package_ref = ANY(request_packages);
        END IF;
        DELETE FROM chat.direct_request_remote_leases
         WHERE request_id = ANY(req_ids)
            OR key_package_ref = ANY(COALESCE(request_packages, ARRAY[]::BYTEA[]));
        IF request_packages IS NOT NULL THEN
            DELETE FROM chat.key_packages WHERE key_package_ref = ANY(request_packages);
        END IF;
        DELETE FROM chat.direct_request_publications WHERE request_id = ANY(req_ids);
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

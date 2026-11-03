-- Migration: retained terminal close evidence after the `I14` operational wipe.
--
-- `closeConversation` (and a verified remote `deliverGroupEntry` close) delete every
-- operational row of the conversation in the same transaction through
-- `chat.wipe_closed_conversation_operational_rows`. The exact signed close entry is
-- retained only as an attachment to its immutable `conversationClosed` event, so the
-- devices in that event's frozen audience still learn the authenticated close through
-- `getEntries`. Rows are keyed by `event_position` (never `conversation_id`) and carry
-- no plaintext, ciphertext, membership, or key material.

CREATE TABLE chat.conversation_close_terminal_entries (
    event_position BIGINT PRIMARY KEY,
    entry_bytes BYTEA NOT NULL,
    entry_sha256 BYTEA NOT NULL,
    CONSTRAINT conversation_close_terminal_entries_event_fk FOREIGN KEY (event_position)
        REFERENCES chat.events(event_position),
    CONSTRAINT conversation_close_terminal_entries_bytes_check CHECK (
        octet_length(entry_bytes) BETWEEN 1 AND 16777216
        AND octet_length(entry_sha256) = 32
        AND entry_sha256 = digest(entry_bytes, 'sha256')
    )
);

CREATE FUNCTION chat.enforce_conversation_close_terminal_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM chat.events
         WHERE event_position = NEW.event_position
           AND event_kind = 'conversationClosed'
    ) THEN
        RAISE EXCEPTION 'close terminal entry must attach to a conversationClosed event'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER conversation_close_terminal_entries_event_kind
BEFORE INSERT ON chat.conversation_close_terminal_entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_close_terminal_event();

CREATE TRIGGER conversation_close_terminal_entries_immutable
BEFORE UPDATE OR DELETE ON chat.conversation_close_terminal_entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- `chat.wipe_closed_conversation_operational_rows` now runs inside every real close.
-- Forward fixes to `20261031200003`:
-- 1. Inventory Welcome items that reference a request device delivery (immediate FK) or a
--    transport inbox delivery (deferred FK) are removed before their parents.
-- 2. Remote leases are removed before the packages they lease (lease -> package FK is
--    immediate; package -> lease FK is deferred), and spent direct-request grants and
--    retirement rows are removed before their packages.
-- 3. `chat.direct_request_attempts` request tombstones are retained: they carry no
--    conversation id, have no TTL, and are the request-level idempotency receipt that
--    late cancel/prepare/publish replays return.
-- 4. Transport-only recipient homes also use this same wipe once the verified
--    remote close has attached its terminal event; active conversations still
--    cannot be wiped. Discover request ids from inboxes before deleting them.
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
        SELECT COALESCE(sum(charge.charged_bytes - COALESCE(reclaimed.released_bytes, 0)), 0)
          INTO gross_retained
          FROM chat.direct_request_retained_charges charge
          LEFT JOIN chat.direct_request_retained_releases reclaimed USING (request_id)
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

-- Deferred constraint triggers validate the live graph of a conversation. Once the
-- wipe removes that graph, a check queued for a deleted row (or for the verified
-- remote close's lifecycle update) can only fail. A constraint trigger's WHEN
-- condition is evaluated when the row changes, not when the deferred check runs, so
-- changes made inside the wipe scope queue no graph check; foreign keys still apply.
-- A local close fires its own pending checks against the complete graph before it
-- opens the wipe scope (`handlers/chat/leave.rs`).
DO $$
DECLARE
    target RECORD;
    guarded TEXT;
BEGIN
    FOR target IN
        SELECT trigger_row.tgname,
               trigger_row.tgrelid::regclass AS relation,
               pg_get_triggerdef(trigger_row.oid) AS definition
          FROM pg_trigger trigger_row
         WHERE NOT trigger_row.tgisinternal
           AND trigger_row.tgconstraint <> 0
           AND trigger_row.tgqual IS NULL
           AND (
                (trigger_row.tgtype & 8) <> 0
                OR trigger_row.tgrelid = 'chat.conversations'::regclass
           )
           AND trigger_row.tgrelid = ANY (ARRAY[
                'chat.device_entry_acks', 'chat.conversation_space_writers',
                'chat.conversation_space_syncers', 'chat.space_credential_jtis',
                'chat.conversation_spaces', 'chat.inventory_welcome_items',
                'chat.direct_request_transport_entries', 'chat.direct_request_transport_inbox',
                'chat.federation_delivery_receipts', 'chat.inventory_conversation_items',
                'chat.inventory_recovery_items', 'chat.recovery_work_items',
                'chat.welcome_dispositions', 'chat.welcome_deliveries', 'chat.welcome_bundles',
                'chat.leaf_recovery_requests', 'chat.key_package_reservations',
                'chat.leave_requests', 'chat.reset_requests',
                'chat.application_schedule_terminal_proofs', 'chat.application_intervals',
                'chat.entry_recipients', 'chat.message_sends', 'chat.metadata_snapshots',
                'chat.member_devices', 'chat.participants',
                'chat.direct_request_push_event_recipients', 'chat.direct_request_push_events',
                'chat.direct_request_welcome_outcomes', 'chat.direct_request_welcome_slots',
                'chat.direct_request_decision_slots', 'chat.direct_request_expiry_receipts',
                'chat.direct_request_acceptance_claims', 'chat.direct_request_retained_releases',
                'chat.direct_request_retained_charges', 'chat.direct_request_pending_releases',
                'chat.direct_request_lifecycle_reserves', 'chat.direct_request_lifecycle',
                'chat.direct_request_reserved_remote_packages',
                'chat.direct_request_reservation_intents', 'chat.direct_request_outbound_routes',
                'chat.direct_request_device_deliveries', 'chat.direct_request_selected_devices',
                'chat.direct_request_grants', 'chat.direct_request_retired_packages',
                'chat.direct_request_remote_leases', 'chat.key_packages',
                'chat.direct_request_publications', 'chat.entries', 'chat.transitions',
                'chat.generation_states', 'chat.generations', 'chat.conversations'
           ]::regclass[])
         ORDER BY trigger_row.tgrelid::regclass::text, trigger_row.tgname
    LOOP
        guarded := replace(
            target.definition,
            ' FOR EACH ROW EXECUTE ',
            ' FOR EACH ROW WHEN (NOT chat.in_conversation_wipe_scope()) EXECUTE '
        );
        IF guarded = target.definition THEN
            RAISE EXCEPTION 'unexpected constraint trigger definition: %', target.definition;
        END IF;
        EXECUTE format('DROP TRIGGER %I ON %s', target.tgname, target.relation);
        EXECUTE guarded;
    END LOOP;
END
$$;

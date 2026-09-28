-- 20260919000025_federated_inventory_conversation_items.sql
-- C33 Two-Authority Direct Request Federation:
-- Dedicated transport inbox FK on inventory_conversation_items (transport_inbox_delivery_id)
-- preserving existing conversation and participant FKs intact via generated legacy_conversation_id.

ALTER TABLE chat.inventory_conversation_items
    ADD COLUMN IF NOT EXISTS transport_inbox_delivery_id UUID;

ALTER TABLE chat.inventory_conversation_items
    DROP CONSTRAINT IF EXISTS inventory_conversation_items_transport_inbox_fk;

ALTER TABLE chat.inventory_conversation_items
    ADD CONSTRAINT inventory_conversation_items_transport_inbox_fk
        FOREIGN KEY (transport_inbox_delivery_id)
        REFERENCES chat.direct_request_transport_inbox(delivery_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.inventory_conversation_items
    DROP COLUMN IF EXISTS legacy_conversation_id CASCADE;

ALTER TABLE chat.inventory_conversation_items
    ADD COLUMN legacy_conversation_id UUID GENERATED ALWAYS AS (
        CASE WHEN transport_inbox_delivery_id IS NULL THEN conversation_id ELSE NULL END
    ) STORED;

ALTER TABLE chat.inventory_conversation_items
    DROP CONSTRAINT IF EXISTS inventory_conversation_items_conversation_fk;

ALTER TABLE chat.inventory_conversation_items
    ADD CONSTRAINT inventory_conversation_items_conversation_fk
        FOREIGN KEY (legacy_conversation_id)
        REFERENCES chat.conversations(conversation_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.inventory_conversation_items
    DROP CONSTRAINT IF EXISTS inventory_conversation_items_arm_shape_check;

ALTER TABLE chat.inventory_conversation_items
    ADD CONSTRAINT inventory_conversation_items_arm_shape_check CHECK (
        (item_kind = 'blue.catbird.chat.defs#conversationInventoryState'::text
         AND ((transport_inbox_delivery_id IS NULL AND participant_period_id IS NOT NULL)
              OR (transport_inbox_delivery_id IS NOT NULL AND participant_period_id IS NULL))
         AND membership_interval_id IS NULL AND interval_terminal_seq IS NULL
         AND interval_closing_transition_id IS NULL AND interval_closing_outer_entry_fingerprint IS NULL
         AND interval_removed_at IS NULL AND schedule_terminal_seq IS NULL
         AND schedule_terminal_transition_id IS NULL AND schedule_terminal_outer_entry_fingerprint IS NULL)
        OR
        (item_kind = 'blue.catbird.chat.defs#conversationRemovalTombstone'::text
         AND transport_inbox_delivery_id IS NULL
         AND participant_period_id IS NULL AND membership_interval_id IS NOT NULL
         AND interval_terminal_seq IS NOT NULL AND interval_closing_transition_id IS NOT NULL
         AND interval_closing_outer_entry_fingerprint IS NOT NULL AND interval_removed_at IS NOT NULL
         AND schedule_terminal_seq IS NULL AND schedule_terminal_transition_id IS NULL
         AND schedule_terminal_outer_entry_fingerprint IS NULL)
        OR
        (item_kind = 'blue.catbird.chat.defs#conversationCloseTombstone'::text
         AND transport_inbox_delivery_id IS NULL
         AND participant_period_id IS NULL AND membership_interval_id IS NULL
         AND interval_terminal_seq IS NULL AND interval_closing_transition_id IS NULL
         AND interval_closing_outer_entry_fingerprint IS NULL AND interval_removed_at IS NULL
         AND schedule_terminal_seq IS NOT NULL AND schedule_terminal_transition_id IS NOT NULL
         AND schedule_terminal_outer_entry_fingerprint IS NOT NULL)
    );

CREATE OR REPLACE FUNCTION chat.validate_inventory_conversation_item_source()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    session_row chat.inventory_sessions%ROWTYPE;
    conversation_row chat.conversations%ROWTYPE;
BEGIN
    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = NEW.inventory_session_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation inventory session source is absent'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.transport_inbox_delivery_id IS NOT NULL THEN
        IF NEW.item_kind <> 'blue.catbird.chat.defs#conversationInventoryState' THEN
            RAISE EXCEPTION 'remote transport conversation inventory item kind mismatch'
                USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM chat.direct_request_transport_inbox t
             WHERE t.delivery_id = NEW.transport_inbox_delivery_id
               AND t.conversation_id = NEW.conversation_id
               AND t.recipient_did = NEW.recipient_did
               AND t.recipient_device_id = NEW.recipient_device_id
               AND (t.status = 'accepted' OR
                    (t.status = 'pending' AND t.import_until > session_row.created_at))
        ) THEN
            RAISE EXCEPTION 'remote transport conversation inventory source mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO conversation_row
      FROM chat.conversations
     WHERE conversation_id = NEW.conversation_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation inventory conversation source is absent'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.item_kind = 'blue.catbird.chat.defs#conversationCloseTombstone' THEN
        IF conversation_row.lifecycle <> 'superseded'
           OR conversation_row.created_at > session_row.created_at
           OR conversation_row.closed_at IS NULL
           OR conversation_row.closed_at > session_row.created_at
           OR NOT EXISTS (
                SELECT 1
                  FROM chat.application_schedule_terminal_proofs proof
                 WHERE proof.conversation_id = NEW.conversation_id
                   AND proof.recipient_did = NEW.recipient_did
                   AND proof.recipient_device_id = NEW.recipient_device_id
                   AND proof.terminal_seq = NEW.schedule_terminal_seq
                   AND proof.transition_id = NEW.schedule_terminal_transition_id
                   AND proof.outer_entry_fingerprint
                       = NEW.schedule_terminal_outer_entry_fingerprint
                   AND proof.received_at <= session_row.created_at
           ) THEN
            RAISE EXCEPTION 'conversation close inventory source or precedence mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.item_kind =
          'blue.catbird.chat.defs#conversationRemovalTombstone' THEN
        IF conversation_row.created_at > session_row.created_at
           OR (
                conversation_row.closed_at IS NOT NULL
                AND conversation_row.closed_at <= session_row.created_at
           )
           OR NEW.interval_removed_at > session_row.created_at
           OR NOT EXISTS (
                SELECT 1
                  FROM chat.application_intervals exact_interval
                 WHERE exact_interval.membership_interval_id =
                           NEW.membership_interval_id
                   AND exact_interval.conversation_id = NEW.conversation_id
                   AND exact_interval.recipient_did = NEW.recipient_did
                   AND exact_interval.recipient_device_id =
                           NEW.recipient_device_id
                   AND exact_interval.created_at <= session_row.created_at
                   AND exact_interval.removed_at <= session_row.created_at
           )
           OR NEW.membership_interval_id IS DISTINCT FROM (
                SELECT finite_interval.membership_interval_id
                  FROM chat.application_intervals finite_interval
                 WHERE finite_interval.conversation_id = NEW.conversation_id
                   AND finite_interval.recipient_did = NEW.recipient_did
                   AND finite_interval.recipient_device_id =
                           NEW.recipient_device_id
                   AND finite_interval.created_at <= session_row.created_at
                   AND finite_interval.removed_at <= session_row.created_at
                 ORDER BY finite_interval.start_seq DESC,
                          finite_interval.membership_interval_id DESC
                 LIMIT 1
           )
           OR EXISTS (
                SELECT 1
                  FROM chat.application_intervals exact_interval
                  JOIN chat.application_intervals later
                    ON later.conversation_id = exact_interval.conversation_id
                   AND later.recipient_did = exact_interval.recipient_did
                   AND later.recipient_device_id =
                           exact_interval.recipient_device_id
                 WHERE later.conversation_id = NEW.conversation_id
                   AND exact_interval.membership_interval_id =
                           NEW.membership_interval_id
                   AND later.created_at <= session_row.created_at
                   AND (
                        later.removed_at IS NULL
                        OR later.removed_at > session_row.created_at
                   )
                   AND ROW(
                        later.start_seq,
                        later.membership_interval_id
                   ) > ROW(
                        exact_interval.start_seq,
                        exact_interval.membership_interval_id
                   )
           ) THEN
            RAISE EXCEPTION 'conversation removal inventory source or precedence mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.item_kind =
          'blue.catbird.chat.defs#conversationInventoryState' THEN
        IF conversation_row.created_at > session_row.created_at
           OR (
                conversation_row.closed_at IS NOT NULL
                AND conversation_row.closed_at <= session_row.created_at
           )
           OR NOT EXISTS (
                SELECT 1
                  FROM chat.participants participant
                 WHERE participant.participant_period_id = NEW.participant_period_id
                   AND participant.conversation_id = NEW.conversation_id
                   AND participant.user_did = NEW.recipient_did
                   AND participant.created_at <= session_row.created_at
                   AND (
                        participant.invitation_transition_id IS NULL
                        OR participant.accepted_at <= session_row.created_at
                        OR (
                            participant.invitation_transition_id IS NOT NULL
                            AND (
                                participant.accepted_at IS NULL
                                OR participant.accepted_at >
                                   session_row.created_at
                            )
                            AND conversation_row.kind IN ('group', 'direct')
                        )
                   )
                   AND (
                        participant.removed_at IS NULL
                        OR participant.removed_at > session_row.created_at
                   )
           )
           OR (
                NOT EXISTS (
                    SELECT 1
                      FROM chat.application_intervals open_interval
                     WHERE open_interval.conversation_id = NEW.conversation_id
                       AND open_interval.recipient_did = NEW.recipient_did
                       AND open_interval.recipient_device_id = NEW.recipient_device_id
                       AND open_interval.created_at <= session_row.created_at
                       AND (
                            open_interval.removed_at IS NULL
                            OR open_interval.removed_at > session_row.created_at
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM chat.application_intervals finite_interval
                     WHERE finite_interval.conversation_id = NEW.conversation_id
                       AND finite_interval.recipient_did = NEW.recipient_did
                       AND finite_interval.recipient_device_id = NEW.recipient_device_id
                       AND finite_interval.removed_at <= session_row.created_at
                )
           ) THEN
            RAISE EXCEPTION 'conversation state inventory source or precedence mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown conversation inventory arm'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;

-- A remote accepted direct remains in the recipient's inventory after its
-- introduction import deadline; scope it to the exact authenticated device.
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
                      AND t.recipient_device_id = NEW.device_id
                      AND (t.status = 'accepted' OR
                           (t.status = 'pending' AND t.import_until > transaction_timestamp()))
                )
            )
        ) THEN RAISE EXCEPTION 'inventory scope audience version mismatch' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END $$;

-- Direct-pending state-only inventory item source precedence correction.
--
-- Relaxes the pending-invitation branch in chat.validate_inventory_conversation_item_source()
-- to admit direct conversations in addition to group conversations for pending state items.
-- Preserves exact recipient, timestamp, current membership, and finite interval precedence checks.
--
-- No table schema changes, backfills, constraint drops, or trigger changes.

DO $preflight$
DECLARE
    current_def text;
    expected_old text;
    expected_new text;
BEGIN
    IF to_regprocedure('chat.validate_inventory_conversation_item_source()') IS NULL THEN
        RAISE EXCEPTION 'required function chat.validate_inventory_conversation_item_source() is absent';
    END IF;

    current_def := pg_get_functiondef('chat.validate_inventory_conversation_item_source()'::regprocedure);

    expected_old := $expected_old$CREATE OR REPLACE FUNCTION chat.validate_inventory_conversation_item_source()
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
                            AND conversation_row.kind = 'group'
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
$function$
$expected_old$;

    expected_new := $expected_new$CREATE OR REPLACE FUNCTION chat.validate_inventory_conversation_item_source()
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
$function$
$expected_new$;

    IF current_def IS DISTINCT FROM expected_old
       AND current_def IS DISTINCT FROM expected_new
       AND replace(current_def, E'\r\n', E'\n') IS DISTINCT FROM expected_old
       AND replace(current_def, E'\r\n', E'\n') IS DISTINCT FROM expected_new
    THEN
        RAISE EXCEPTION 'chat.validate_inventory_conversation_item_source() definition drifted from expected historical and corrected definitions';
    END IF;
END
$preflight$;

CREATE OR REPLACE FUNCTION chat.validate_inventory_conversation_item_source()
RETURNS trigger
LANGUAGE plpgsql
AS $$
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
$$;

DO $postflight$
DECLARE
    current_def text;
    expected_new text;
BEGIN
    current_def := pg_get_functiondef('chat.validate_inventory_conversation_item_source()'::regprocedure);
    expected_new := $expected_new$CREATE OR REPLACE FUNCTION chat.validate_inventory_conversation_item_source()
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
$function$
$expected_new$;

    IF current_def IS DISTINCT FROM expected_new
       AND replace(current_def, E'\r\n', E'\n') IS DISTINCT FROM expected_new
    THEN
        RAISE EXCEPTION 'chat.validate_inventory_conversation_item_source() postflight verification failed';
    END IF;
END
$postflight$;

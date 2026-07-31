-- G7 inventory entitlement, materialization/consumption separation, and
-- hash-only random cursor receipts.
--
-- This migration is deliberately forward-only. Retained item payload bytes are
-- never rewritten or deleted. Every legacy session is expired at this
-- transaction's timestamp because SQL migration code cannot possess the
-- runtime cursor AEAD key needed to seal its plaintext cursor.

LOCK TABLE
    chat.inventory_sessions,
    chat.inventory_conversation_items,
    chat.inventory_welcome_items,
    chat.inventory_recovery_items,
    chat.subscription_tickets
IN ACCESS EXCLUSIVE MODE;

LOCK TABLE
    chat.protocol_instances,
    chat.event_retention,
    chat.participants,
    chat.application_intervals,
    chat.application_schedule_terminal_proofs
IN SHARE MODE;

SET CONSTRAINTS ALL IMMEDIATE;

DO $$
DECLARE
    trigger_row RECORD;
BEGIN
    FOR trigger_row IN
        SELECT required.tgname, trigger_catalog.tgenabled,
               pg_get_triggerdef(trigger_catalog.oid, false) AS trigger_definition
          FROM (
              VALUES
                ('inventory_sessions_identity_immutable'),
                ('inventory_sessions_lifecycle_monotonic'),
                ('inventory_sessions_materialization_deferred'),
                ('inventory_conversation_items_immutable')
          ) AS required(tgname)
          LEFT JOIN pg_trigger trigger_catalog
            ON trigger_catalog.tgname = required.tgname
           AND NOT trigger_catalog.tgisinternal
          LEFT JOIN pg_class relation ON relation.oid = trigger_catalog.tgrelid
          LEFT JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'chat' OR trigger_catalog.oid IS NULL
    LOOP
        IF trigger_row.tgenabled IS DISTINCT FROM 'O' THEN
            RAISE EXCEPTION 'required G7 predecessor trigger % is absent or disabled',
                trigger_row.tgname
                USING ERRCODE = '23514';
        END IF;
        IF trigger_row.tgname = 'inventory_sessions_identity_immutable'
           AND trigger_row.trigger_definition NOT LIKE
               '%chat.enforce_immutable_identity(''conversations_complete'', ''welcomes_complete'', ''recovery_complete'', ''conversation_item_count'', ''conversation_items_sha256'', ''welcome_item_count'', ''welcome_items_sha256'', ''recovery_item_count'', ''recovery_items_sha256'')%' THEN
            RAISE EXCEPTION 'inventory session identity trigger arguments drifted'
                USING ERRCODE = '23514';
        ELSIF trigger_row.tgname = 'inventory_sessions_lifecycle_monotonic'
           AND trigger_row.trigger_definition NOT LIKE
               '%chat.enforce_delivery_lifecycle_transition()%' THEN
            RAISE EXCEPTION 'inventory session lifecycle trigger drifted'
                USING ERRCODE = '23514';
        ELSIF trigger_row.tgname = 'inventory_sessions_materialization_deferred'
           AND (
                trigger_row.trigger_definition NOT LIKE '%DEFERRABLE INITIALLY DEFERRED%'
                OR trigger_row.trigger_definition NOT LIKE
                    '%chat.enforce_inventory_materialization()%'
           ) THEN
            RAISE EXCEPTION 'inventory materialization trigger drifted'
                USING ERRCODE = '23514';
        ELSIF trigger_row.tgname = 'inventory_conversation_items_immutable'
           AND trigger_row.trigger_definition NOT LIKE
               '%chat.enforce_immutable_identity()%' THEN
            RAISE EXCEPTION 'inventory conversation immutability trigger drifted'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;

    IF (
        SELECT count(*)
          FROM pg_trigger trigger_catalog
          JOIN pg_class relation ON relation.oid = trigger_catalog.tgrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'chat'
           AND NOT trigger_catalog.tgisinternal
           AND trigger_catalog.tgname IN (
                'inventory_sessions_identity_immutable',
                'inventory_sessions_lifecycle_monotonic',
                'inventory_sessions_materialization_deferred',
                'inventory_conversation_items_immutable'
           )
    ) <> 4 THEN
        RAISE EXCEPTION 'required G7 predecessor trigger set is ambiguous'
            USING ERRCODE = '23514';
    END IF;
END
$$;

DROP TRIGGER inventory_sessions_identity_immutable
    ON chat.inventory_sessions;
DROP TRIGGER inventory_sessions_lifecycle_monotonic
    ON chat.inventory_sessions;
DROP TRIGGER inventory_conversation_items_immutable
    ON chat.inventory_conversation_items;

ALTER TABLE chat.inventory_conversation_items
    ADD COLUMN item_kind TEXT,
    ADD COLUMN participant_period_id UUID,
    ADD COLUMN membership_interval_id UUID,
    ADD COLUMN interval_terminal_seq BIGINT,
    ADD COLUMN interval_closing_transition_id UUID,
    ADD COLUMN interval_closing_outer_entry_fingerprint BYTEA,
    ADD COLUMN interval_removed_at TIMESTAMPTZ;

ALTER TABLE chat.inventory_sessions
    ADD COLUMN protocol_instance_id UUID,
    ADD COLUMN cursor_key_id TEXT,
    ADD COLUMN cursor_format_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN snapshot_retained_floor BIGINT,
    ADD COLUMN conversation_payload_bytes BIGINT,
    ADD COLUMN welcome_payload_bytes BIGINT,
    ADD COLUMN recovery_payload_bytes BIGINT,
    ADD COLUMN conversations_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN welcomes_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN recovery_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN conversations_consumed_at TIMESTAMPTZ,
    ADD COLUMN welcomes_consumed_at TIMESTAMPTZ,
    ADD COLUMN recovery_consumed_at TIMESTAMPTZ,
    ADD COLUMN snapshot_event_cursor_nonce BYTEA,
    ADD COLUMN snapshot_event_cursor_ciphertext BYTEA,
    ADD COLUMN legacy_cursor_invalidated_at TIMESTAMPTZ;

ALTER TABLE chat.subscription_tickets
    ADD COLUMN protocol_instance_id UUID,
    ADD COLUMN cursor_key_id TEXT,
    ADD COLUMN snapshot_retained_floor BIGINT;

ALTER TABLE chat.subscription_tickets
    DROP CONSTRAINT subscription_tickets_inventory_identity_fk;
ALTER TABLE chat.inventory_sessions
    DROP CONSTRAINT inventory_sessions_ticket_identity_uq,
    DROP CONSTRAINT inventory_sessions_cursor_hash_check,
    DROP CONSTRAINT inventory_sessions_completion_evidence_check;
ALTER TABLE chat.subscription_tickets
    DROP CONSTRAINT subscription_tickets_cursor_hash_check;

-- Every historical conversation item was emitted by the legacy active-leaf
-- selector unless it already carries a complete terminal schedule proof.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chat.inventory_conversation_items item
         WHERE num_nonnulls(
                item.schedule_terminal_seq,
                item.schedule_terminal_transition_id,
                item.schedule_terminal_outer_entry_fingerprint
         ) NOT IN (0, 3)
    ) THEN
        RAISE EXCEPTION 'legacy conversation inventory has an incomplete schedule proof'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM chat.inventory_conversation_items item
          JOIN chat.inventory_sessions session
            ON session.inventory_session_id = item.inventory_session_id
         WHERE item.schedule_terminal_seq IS NULL
           AND (
                SELECT count(*)
                  FROM chat.application_intervals interval_source
                  JOIN chat.member_devices leaf
                    ON leaf.leaf_period_id = interval_source.opening_leaf_period_id
                  JOIN chat.participants participant
                    ON participant.participant_period_id = leaf.participant_period_id
                   AND participant.conversation_id = item.conversation_id
                   AND participant.user_did = item.recipient_did
                  JOIN chat.conversations conversation
                    ON conversation.conversation_id = item.conversation_id
                 WHERE interval_source.conversation_id = item.conversation_id
                   AND interval_source.recipient_did = item.recipient_did
                   AND interval_source.recipient_device_id = item.recipient_device_id
                   AND interval_source.created_at <= session.created_at
                   AND (
                        interval_source.removed_at IS NULL
                        OR interval_source.removed_at > session.created_at
                   )
                   AND participant.created_at <= session.created_at
                   AND (
                        participant.invitation_transition_id IS NULL
                        OR participant.accepted_at <= session.created_at
                        OR (
                            participant.invitation_transition_id IS NOT NULL
                            AND (
                                participant.accepted_at IS NULL
                                OR participant.accepted_at > session.created_at
                            )
                            AND conversation.kind = 'group'
                        )
                   )
                   AND (
                        participant.removed_at IS NULL
                        OR participant.removed_at > session.created_at
                   )
                   AND conversation.created_at <= session.created_at
                   AND (
                        conversation.closed_at IS NULL
                        OR conversation.closed_at > session.created_at
                   )
           ) <> 1
    ) THEN
        RAISE EXCEPTION 'legacy conversation inventory source is absent or ambiguous'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM chat.inventory_conversation_items item
          JOIN chat.inventory_sessions session
            ON session.inventory_session_id = item.inventory_session_id
          JOIN chat.conversations conversation
            ON conversation.conversation_id = item.conversation_id
         WHERE item.schedule_terminal_seq IS NOT NULL
           AND (
                conversation.created_at > session.created_at
                OR conversation.closed_at IS NULL
                OR conversation.closed_at > session.created_at
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.application_schedule_terminal_proofs proof
                     WHERE proof.conversation_id = item.conversation_id
                       AND proof.recipient_did = item.recipient_did
                       AND proof.recipient_device_id = item.recipient_device_id
                       AND proof.terminal_seq = item.schedule_terminal_seq
                       AND proof.transition_id =
                               item.schedule_terminal_transition_id
                       AND proof.outer_entry_fingerprint
                           = item.schedule_terminal_outer_entry_fingerprint
                       AND proof.received_at <= session.created_at
                )
           )
    ) THEN
        RAISE EXCEPTION 'legacy close inventory source is absent or mismatched'
            USING ERRCODE = '23514';
    END IF;
END
$$;

WITH exact_legacy_source AS (
    SELECT item.inventory_session_id,
           item.conversation_id,
           participant.participant_period_id
      FROM chat.inventory_conversation_items item
      JOIN chat.inventory_sessions session
        ON session.inventory_session_id = item.inventory_session_id
      JOIN chat.application_intervals interval_source
        ON interval_source.conversation_id = item.conversation_id
       AND interval_source.recipient_did = item.recipient_did
       AND interval_source.recipient_device_id = item.recipient_device_id
       AND interval_source.created_at <= session.created_at
       AND (
            interval_source.removed_at IS NULL
            OR interval_source.removed_at > session.created_at
       )
      JOIN chat.member_devices leaf
        ON leaf.leaf_period_id = interval_source.opening_leaf_period_id
      JOIN chat.conversations conversation
        ON conversation.conversation_id = item.conversation_id
       AND conversation.created_at <= session.created_at
       AND (
            conversation.closed_at IS NULL
            OR conversation.closed_at > session.created_at
       )
      JOIN chat.participants participant
        ON participant.participant_period_id = leaf.participant_period_id
       AND participant.conversation_id = item.conversation_id
       AND participant.user_did = item.recipient_did
       AND participant.created_at <= session.created_at
       AND (
            participant.invitation_transition_id IS NULL
            OR participant.accepted_at <= session.created_at
            OR (
                participant.invitation_transition_id IS NOT NULL
                AND (
                    participant.accepted_at IS NULL
                    OR participant.accepted_at > session.created_at
                )
                AND conversation.kind = 'group'
            )
       )
       AND (
            participant.removed_at IS NULL
            OR participant.removed_at > session.created_at
       )
     WHERE item.schedule_terminal_seq IS NULL
)
UPDATE chat.inventory_conversation_items item
   SET item_kind = 'blue.catbird.chat.defs#conversationInventoryState',
       participant_period_id = source.participant_period_id
  FROM exact_legacy_source source
 WHERE item.inventory_session_id = source.inventory_session_id
   AND item.conversation_id = source.conversation_id;

UPDATE chat.inventory_conversation_items
   SET item_kind = 'blue.catbird.chat.defs#conversationCloseTombstone'
 WHERE schedule_terminal_seq IS NOT NULL;

-- Every retained session receives one exact protocol/key/retention binding. A
-- retained session whose snapshot has fallen below the current retained floor
-- cannot be made authoritative and aborts the migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM chat.inventory_sessions)
       AND (SELECT count(*) FROM chat.protocol_instances WHERE singleton) <> 1 THEN
        RAISE EXCEPTION 'retained inventory sessions require one protocol singleton'
            USING ERRCODE = '23514';
    END IF;
END
$$;

UPDATE chat.inventory_sessions session
   SET protocol_instance_id = protocol.protocol_instance_id,
       cursor_key_id = protocol.cursor_key_id,
       snapshot_retained_floor = retention.retained_floor
  FROM chat.protocol_instances protocol
  JOIN chat.event_retention retention
    ON retention.protocol_instance_id = protocol.protocol_instance_id
 WHERE protocol.singleton;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chat.inventory_sessions
         WHERE protocol_instance_id IS NULL
            OR cursor_key_id IS NULL
            OR snapshot_retained_floor IS NULL
            OR snapshot_retained_floor > snapshot_event_position
    ) THEN
        RAISE EXCEPTION 'retained inventory session protocol/retention binding is absent or stale'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM chat.inventory_sessions
         WHERE created_at >= transaction_timestamp()
    ) THEN
        RAISE EXCEPTION 'legacy inventory session timestamp is not before G7 migration'
            USING ERRCODE = '23514';
    END IF;
END
$$;

UPDATE chat.inventory_sessions
   SET legacy_cursor_invalidated_at = transaction_timestamp(),
       expires_at = LEAST(expires_at, transaction_timestamp()),
       snapshot_event_cursor_nonce = NULL,
       snapshot_event_cursor_ciphertext = NULL;

ALTER TABLE chat.inventory_sessions
    DROP COLUMN snapshot_event_cursor_bytes;
ALTER TABLE chat.subscription_tickets
    DROP COLUMN event_cursor_bytes;

ALTER TABLE chat.inventory_sessions
    ADD CONSTRAINT inventory_sessions_ticket_identity_uq UNIQUE (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        snapshot_event_position, snapshot_event_cursor_sha256,
        protocol_instance_id, cursor_key_id, snapshot_retained_floor
    ),
    ADD CONSTRAINT inventory_sessions_receipt_identity_uq UNIQUE (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, cursor_format_version,
        snapshot_event_position, snapshot_event_cursor_sha256,
        snapshot_retained_floor, expires_at
    ),
    ADD CONSTRAINT inventory_sessions_event_receipt_identity_uq UNIQUE (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, snapshot_retained_floor, expires_at
    );

ALTER TABLE chat.subscription_tickets
    ADD CONSTRAINT subscription_tickets_inventory_identity_fk FOREIGN KEY (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        event_position, event_cursor_sha256,
        protocol_instance_id, cursor_key_id, snapshot_retained_floor
    ) REFERENCES chat.inventory_sessions (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        snapshot_event_position, snapshot_event_cursor_sha256,
        protocol_instance_id, cursor_key_id, snapshot_retained_floor
    ) MATCH SIMPLE DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT subscription_tickets_g7_binding_shape_check CHECK (
        (
            protocol_instance_id IS NULL
            AND cursor_key_id IS NULL
            AND snapshot_retained_floor IS NULL
        )
        OR (
            protocol_instance_id IS NOT NULL
            AND cursor_key_id IS NOT NULL
            AND snapshot_retained_floor IS NOT NULL
            AND event_cursor_sha256 IS NOT NULL
            AND chat.is_uuid_v4(protocol_instance_id)
            AND chat.is_base64url_sha256(cursor_key_id)
            AND chat.is_safe_integer(snapshot_retained_floor)
            AND octet_length(event_cursor_sha256) = 32
        )
    ) NOT VALID;

CREATE TABLE chat.inventory_page_receipts (
    page_receipt_id UUID PRIMARY KEY,
    request_cursor_hash BYTEA,
    inventory_session_id UUID NOT NULL,
    domain TEXT NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    cursor_format_version SMALLINT NOT NULL,
    page_limit SMALLINT NOT NULL,
    canonical_filter_sha256 BYTEA NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    protocol_instance_id UUID NOT NULL,
    cursor_key_id TEXT NOT NULL,
    snapshot_event_position BIGINT NOT NULL,
    snapshot_event_cursor_sha256 BYTEA NOT NULL,
    snapshot_retained_floor BIGINT NOT NULL,
    after_ordinal BIGINT,
    first_ordinal BIGINT,
    item_count BIGINT,
    items_sha256 BYTEA,
    has_more BOOLEAN,
    successor_cursor_hash BYTEA,
    successor_cursor_nonce BYTEA,
    successor_cursor_ciphertext BYTEA,
    canonical_response_sha256 BYTEA,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    served_at TIMESTAMPTZ,
    CONSTRAINT inventory_page_receipts_id_check CHECK (
        chat.is_uuid_v4(page_receipt_id)
    ),
    CONSTRAINT inventory_page_receipts_request_cursor_uq UNIQUE (
        request_cursor_hash
    ),
    CONSTRAINT inventory_page_receipts_successor_cursor_uq UNIQUE (
        successor_cursor_hash
    ),
    CONSTRAINT inventory_page_receipts_request_boundary_fk FOREIGN KEY (
        request_cursor_hash
    ) REFERENCES chat.inventory_page_receipts(successor_cursor_hash)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inventory_page_receipts_session_binding_fk FOREIGN KEY (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, cursor_format_version,
        snapshot_event_position, snapshot_event_cursor_sha256,
        snapshot_retained_floor, expires_at
    ) REFERENCES chat.inventory_sessions (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, cursor_format_version,
        snapshot_event_position, snapshot_event_cursor_sha256,
        snapshot_retained_floor, expires_at
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inventory_page_receipts_binding_check CHECK (
        chat.is_uuid_v4(inventory_session_id)
        AND cursor_format_version = 1
        AND page_limit BETWEEN 1 AND 100
        AND octet_length(canonical_filter_sha256) = 32
        AND chat.is_bare_did(user_did)
        AND chat.is_uuid_v4(device_id)
        AND chat.is_base64url_sha256(jkt)
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
    ),
    CONSTRAINT inventory_page_receipts_domain_endpoint_check CHECK (
        (domain, endpoint_nsid) IN (
            ('conversations', 'blue.catbird.chat.getConversations'),
            ('welcomes', 'blue.catbird.chat.getPendingWelcomes'),
            ('recovery', 'blue.catbird.chat.getLeafRecoveryInbox')
        )
    ),
    CONSTRAINT inventory_page_receipts_shape_check CHECK (
        (
            (request_cursor_hash IS NULL AND after_ordinal IS NULL)
            OR (
                request_cursor_hash IS NOT NULL
                AND after_ordinal IS NOT NULL
                AND octet_length(request_cursor_hash) = 32
                AND chat.is_safe_integer(after_ordinal)
                AND after_ordinal >= 0
            )
        )
        AND (
            (
                served_at IS NULL
                AND first_ordinal IS NULL
                AND item_count IS NULL
                AND items_sha256 IS NULL
                AND has_more IS NULL
                AND successor_cursor_hash IS NULL
                AND successor_cursor_nonce IS NULL
                AND successor_cursor_ciphertext IS NULL
                AND canonical_response_sha256 IS NULL
            )
            OR (
                served_at IS NOT NULL
                AND item_count IS NOT NULL
                AND items_sha256 IS NOT NULL
                AND has_more IS NOT NULL
                AND canonical_response_sha256 IS NOT NULL
                AND served_at >= created_at
                AND served_at < expires_at
                AND chat.is_safe_integer(item_count)
                AND item_count BETWEEN 0 AND 100
                AND (
                    (item_count = 0 AND first_ordinal IS NULL)
                    OR (
                        item_count > 0
                        AND first_ordinal IS NOT NULL
                        AND chat.is_safe_integer(first_ordinal)
                        AND first_ordinal >= 0
                    )
                )
                AND octet_length(items_sha256) = 32
                AND octet_length(canonical_response_sha256) = 32
                AND (
                    (
                        has_more IS TRUE
                        AND item_count > 0
                        AND successor_cursor_hash IS NOT NULL
                        AND successor_cursor_nonce IS NOT NULL
                        AND successor_cursor_ciphertext IS NOT NULL
                        AND octet_length(successor_cursor_hash) = 32
                        AND octet_length(successor_cursor_nonce) = 12
                        AND octet_length(successor_cursor_ciphertext) BETWEEN 1 AND 512
                    )
                    OR (
                        has_more IS FALSE
                        AND successor_cursor_hash IS NULL
                        AND successor_cursor_nonce IS NULL
                        AND successor_cursor_ciphertext IS NULL
                    )
                )
            )
        )
    )
);

CREATE UNIQUE INDEX inventory_page_receipts_initial_uq
    ON chat.inventory_page_receipts (
        inventory_session_id, domain, page_limit, canonical_filter_sha256
    )
    WHERE request_cursor_hash IS NULL;

CREATE INDEX inventory_page_receipts_session_domain_idx
    ON chat.inventory_page_receipts (
        inventory_session_id, domain, created_at, page_receipt_id
    );

CREATE TABLE chat.event_cursor_receipts (
    cursor_hash BYTEA PRIMARY KEY,
    inventory_session_id UUID NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    protocol_instance_id UUID NOT NULL,
    cursor_key_id TEXT NOT NULL,
    event_position BIGINT NOT NULL,
    predecessor_cursor_hash BYTEA,
    retained_floor_at_issue BIGINT NOT NULL,
    cursor_nonce BYTEA NOT NULL,
    cursor_ciphertext BYTEA NOT NULL,
    canonical_envelope_sha256 BYTEA,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT event_cursor_receipts_session_binding_fk FOREIGN KEY (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, retained_floor_at_issue, expires_at
    ) REFERENCES chat.inventory_sessions (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        protocol_instance_id, cursor_key_id, snapshot_retained_floor, expires_at
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT event_cursor_receipts_predecessor_fk FOREIGN KEY (
        predecessor_cursor_hash
    ) REFERENCES chat.event_cursor_receipts(cursor_hash)
      DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT event_cursor_receipts_shape_check CHECK (
        octet_length(cursor_hash) = 32
        AND chat.is_uuid_v4(inventory_session_id)
        AND chat.is_bare_did(user_did)
        AND chat.is_uuid_v4(device_id)
        AND chat.is_base64url_sha256(jkt)
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
    ),
    CONSTRAINT event_cursor_receipts_position_uq UNIQUE (
        inventory_session_id, device_id, event_position
    )
);

CREATE INDEX event_cursor_receipts_session_position_idx
    ON chat.event_cursor_receipts (
        inventory_session_id, event_position, cursor_hash
    );

-- Exact composite FK targets. The first coordinate in each source is already
-- unique, but named full-tuple targets make provenance review and FK identity
-- explicit.
ALTER TABLE chat.participants
    ADD CONSTRAINT participants_inventory_source_uq UNIQUE (
        participant_period_id, conversation_id, user_did
    );
ALTER TABLE chat.application_intervals
    ADD CONSTRAINT application_intervals_inventory_terminal_source_uq UNIQUE (
        membership_interval_id, conversation_id, recipient_did,
        recipient_device_id, terminal_seq, closing_transition_id,
        closing_outer_entry_fingerprint, removed_at
    );

CREATE INDEX participants_current_user_conversation_idx
    ON chat.participants (user_did, conversation_id, participant_period_id)
    WHERE current_membership;

ALTER TABLE chat.inventory_conversation_items
    ADD CONSTRAINT inventory_conversation_items_kind_check CHECK (
        item_kind IN (
            'blue.catbird.chat.defs#conversationInventoryState',
            'blue.catbird.chat.defs#conversationRemovalTombstone',
            'blue.catbird.chat.defs#conversationCloseTombstone'
        )
    ) NOT VALID,
    ADD CONSTRAINT inventory_conversation_items_arm_shape_check CHECK (
        (
            item_kind = 'blue.catbird.chat.defs#conversationInventoryState'
            AND participant_period_id IS NOT NULL
            AND membership_interval_id IS NULL
            AND interval_terminal_seq IS NULL
            AND interval_closing_transition_id IS NULL
            AND interval_closing_outer_entry_fingerprint IS NULL
            AND interval_removed_at IS NULL
            AND schedule_terminal_seq IS NULL
            AND schedule_terminal_transition_id IS NULL
            AND schedule_terminal_outer_entry_fingerprint IS NULL
        )
        OR (
            item_kind = 'blue.catbird.chat.defs#conversationRemovalTombstone'
            AND participant_period_id IS NULL
            AND membership_interval_id IS NOT NULL
            AND interval_terminal_seq IS NOT NULL
            AND interval_closing_transition_id IS NOT NULL
            AND interval_closing_outer_entry_fingerprint IS NOT NULL
            AND interval_removed_at IS NOT NULL
            AND schedule_terminal_seq IS NULL
            AND schedule_terminal_transition_id IS NULL
            AND schedule_terminal_outer_entry_fingerprint IS NULL
        )
        OR (
            item_kind = 'blue.catbird.chat.defs#conversationCloseTombstone'
            AND participant_period_id IS NULL
            AND membership_interval_id IS NULL
            AND interval_terminal_seq IS NULL
            AND interval_closing_transition_id IS NULL
            AND interval_closing_outer_entry_fingerprint IS NULL
            AND interval_removed_at IS NULL
            AND schedule_terminal_seq IS NOT NULL
            AND schedule_terminal_transition_id IS NOT NULL
            AND schedule_terminal_outer_entry_fingerprint IS NOT NULL
        )
    ) NOT VALID,
    ADD CONSTRAINT inventory_conversation_items_participant_source_fk
        FOREIGN KEY (participant_period_id, conversation_id, recipient_did)
        REFERENCES chat.participants (
            participant_period_id, conversation_id, user_did
        ) MATCH SIMPLE DEFERRABLE INITIALLY DEFERRED NOT VALID,
    ADD CONSTRAINT inventory_conversation_items_interval_source_fk
        FOREIGN KEY (
            membership_interval_id, conversation_id, recipient_did,
            recipient_device_id, interval_terminal_seq,
            interval_closing_transition_id,
            interval_closing_outer_entry_fingerprint, interval_removed_at
        )
        REFERENCES chat.application_intervals (
            membership_interval_id, conversation_id, recipient_did,
            recipient_device_id, terminal_seq, closing_transition_id,
            closing_outer_entry_fingerprint, removed_at
        ) MATCH SIMPLE DEFERRABLE INITIALLY DEFERRED NOT VALID;

ALTER TABLE chat.event_retention
    ADD CONSTRAINT event_retention_instance_floor_uq UNIQUE (
        protocol_instance_id, retained_floor
    );

ALTER TABLE chat.inventory_sessions
    ADD CONSTRAINT inventory_sessions_g7_binding_check CHECK (
        chat.is_uuid_v4(protocol_instance_id)
        AND chat.is_base64url_sha256(cursor_key_id)
        AND cursor_format_version = 1
        AND chat.is_safe_integer(snapshot_retained_floor)
        AND snapshot_retained_floor <= snapshot_event_position
        AND octet_length(snapshot_event_cursor_sha256) = 32
        AND (
            (
                legacy_cursor_invalidated_at IS NOT NULL
                AND expires_at <= legacy_cursor_invalidated_at
                AND snapshot_event_cursor_nonce IS NULL
                AND snapshot_event_cursor_ciphertext IS NULL
            )
            OR (
                legacy_cursor_invalidated_at IS NULL
                AND snapshot_event_cursor_nonce IS NOT NULL
                AND snapshot_event_cursor_ciphertext IS NOT NULL
                AND octet_length(snapshot_event_cursor_nonce) = 12
                AND octet_length(snapshot_event_cursor_ciphertext) BETWEEN 1 AND 512
            )
        )
    ) NOT VALID,
    ADD CONSTRAINT inventory_sessions_consumption_check CHECK (
        (
            (
                conversations_consumed IS FALSE
                AND conversations_consumed_at IS NULL
            )
            OR (
                conversations_consumed IS TRUE
                AND conversations_complete IS TRUE
                AND conversations_consumed_at IS NOT NULL
                AND conversations_consumed_at >= created_at
                AND conversations_consumed_at < expires_at
            )
        )
        AND (
            (welcomes_consumed IS FALSE AND welcomes_consumed_at IS NULL)
            OR (
                welcomes_consumed IS TRUE
                AND welcomes_complete IS TRUE
                AND welcomes_consumed_at IS NOT NULL
                AND welcomes_consumed_at >= created_at
                AND welcomes_consumed_at < expires_at
            )
        )
        AND (
            (recovery_consumed IS FALSE AND recovery_consumed_at IS NULL)
            OR (
                recovery_consumed IS TRUE
                AND recovery_complete IS TRUE
                AND recovery_consumed_at IS NOT NULL
                AND recovery_consumed_at >= created_at
                AND recovery_consumed_at < expires_at
            )
        )
    ) NOT VALID,
    ADD CONSTRAINT inventory_sessions_protocol_instance_fk FOREIGN KEY (
        protocol_instance_id
    ) REFERENCES chat.protocol_instances(protocol_instance_id) NOT VALID,
    ADD CONSTRAINT inventory_sessions_retention_binding_fk FOREIGN KEY (
        protocol_instance_id, snapshot_retained_floor
    ) REFERENCES chat.event_retention(protocol_instance_id, retained_floor)
      NOT VALID;

ALTER TABLE chat.inventory_conversation_items
    VALIDATE CONSTRAINT inventory_conversation_items_kind_check,
    VALIDATE CONSTRAINT inventory_conversation_items_arm_shape_check,
    VALIDATE CONSTRAINT inventory_conversation_items_participant_source_fk,
    VALIDATE CONSTRAINT inventory_conversation_items_interval_source_fk;
ALTER TABLE chat.inventory_sessions
    VALIDATE CONSTRAINT inventory_sessions_g7_binding_check,
    VALIDATE CONSTRAINT inventory_sessions_consumption_check,
    VALIDATE CONSTRAINT inventory_sessions_protocol_instance_fk,
    VALIDATE CONSTRAINT inventory_sessions_retention_binding_fk;
ALTER TABLE chat.subscription_tickets
    VALIDATE CONSTRAINT subscription_tickets_inventory_identity_fk,
    VALIDATE CONSTRAINT subscription_tickets_g7_binding_shape_check;

ALTER TABLE chat.inventory_conversation_items
    ALTER COLUMN item_kind SET NOT NULL;
ALTER TABLE chat.inventory_sessions
    ALTER COLUMN protocol_instance_id SET NOT NULL,
    ALTER COLUMN cursor_key_id SET NOT NULL,
    ALTER COLUMN snapshot_retained_floor SET NOT NULL;

-- Canonical materialization proof. Nullable provenance fields are explicitly
-- tagged, so no two source arms can collide in the digest transcript.
CREATE OR REPLACE FUNCTION chat.assert_inventory_materialization(target_session UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    session_row chat.inventory_sessions%ROWTYPE;
    conversation_count BIGINT;
    welcome_count BIGINT;
    recovery_count BIGINT;
    conversation_bytes BIGINT;
    welcome_bytes BIGINT;
    recovery_bytes BIGINT;
    minimum_ordinal BIGINT;
    maximum_ordinal BIGINT;
    rows_digest BYTEA;
BEGIN
    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = target_session
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    IF EXISTS (
        SELECT 1
          FROM chat.inventory_conversation_items item
          LEFT JOIN chat.inventory_sessions session
            ON session.inventory_session_id = item.inventory_session_id
           AND item.recipient_did = session.user_did
           AND item.recipient_device_id = session.device_id
         WHERE item.inventory_session_id = target_session
           AND session.inventory_session_id IS NULL
    ) OR EXISTS (
        SELECT 1
          FROM chat.inventory_welcome_items item
          LEFT JOIN chat.inventory_sessions session
            ON session.inventory_session_id = item.inventory_session_id
           AND item.recipient_did = session.user_did
           AND item.recipient_device_id = session.device_id
         WHERE item.inventory_session_id = target_session
           AND session.inventory_session_id IS NULL
    ) OR EXISTS (
        SELECT 1
          FROM chat.inventory_recovery_items item
          LEFT JOIN chat.inventory_sessions session
            ON session.inventory_session_id = item.inventory_session_id
           AND item.recipient_did = session.user_did
           AND item.recipient_device_id = session.device_id
         WHERE item.inventory_session_id = target_session
           AND session.inventory_session_id IS NULL
    ) THEN
        RAISE EXCEPTION 'inventory item recipient binding mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0),
           digest(COALESCE(string_agg(
               int8send(ordinal)
               || item_key_bytes
               || int4send(octet_length(convert_to(item_kind, 'UTF8')))
               || convert_to(item_kind, 'UTF8')
               || CASE WHEN participant_period_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || uuid_send(participant_period_id) END
               || CASE WHEN membership_interval_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || uuid_send(membership_interval_id) END
               || CASE WHEN interval_terminal_seq IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || int8send(interval_terminal_seq) END
               || CASE WHEN interval_closing_transition_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || uuid_send(interval_closing_transition_id) END
               || CASE WHEN interval_closing_outer_entry_fingerprint IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || interval_closing_outer_entry_fingerprint END
               || CASE WHEN interval_removed_at IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || timestamptz_send(interval_removed_at) END
               || CASE WHEN schedule_terminal_seq IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || int8send(schedule_terminal_seq) END
               || CASE WHEN schedule_terminal_transition_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || uuid_send(schedule_terminal_transition_id) END
               || CASE WHEN schedule_terminal_outer_entry_fingerprint IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || schedule_terminal_outer_entry_fingerprint END
               || payload_sha256
               || int8send(octet_length(payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO conversation_count, minimum_ordinal, maximum_ordinal,
           conversation_bytes, rows_digest
      FROM chat.inventory_conversation_items
     WHERE inventory_session_id = target_session;
    IF conversation_count > 10000
       OR conversation_bytes > 67108864
       OR (
            conversation_count > 0
            AND (
                minimum_ordinal <> 0
                OR maximum_ordinal <> conversation_count - 1
            )
       )
       OR (
            session_row.conversations_complete IS TRUE
            AND (
                session_row.conversation_item_count IS DISTINCT FROM conversation_count
                OR session_row.conversation_items_sha256 IS DISTINCT FROM rows_digest
                OR session_row.conversation_payload_bytes IS DISTINCT FROM conversation_bytes
            )
       ) THEN
        RAISE EXCEPTION 'conversation inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0),
           digest(COALESCE(string_agg(
               int8send(ordinal)
               || item_key_bytes
               || payload_sha256
               || int8send(octet_length(payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO welcome_count, minimum_ordinal, maximum_ordinal,
           welcome_bytes, rows_digest
      FROM chat.inventory_welcome_items
     WHERE inventory_session_id = target_session;
    IF welcome_count > 10000
       OR welcome_bytes > 67108864
       OR (
            welcome_count > 0
            AND (
                minimum_ordinal <> 0
                OR maximum_ordinal <> welcome_count - 1
            )
       )
       OR (
            session_row.welcomes_complete IS TRUE
            AND (
                session_row.welcome_item_count IS DISTINCT FROM welcome_count
                OR session_row.welcome_items_sha256 IS DISTINCT FROM rows_digest
                OR session_row.welcome_payload_bytes IS DISTINCT FROM welcome_bytes
            )
       ) THEN
        RAISE EXCEPTION 'Welcome inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0),
           digest(COALESCE(string_agg(
               int8send(ordinal)
               || item_key_bytes
               || payload_sha256
               || int8send(octet_length(payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO recovery_count, minimum_ordinal, maximum_ordinal,
           recovery_bytes, rows_digest
      FROM chat.inventory_recovery_items
     WHERE inventory_session_id = target_session;
    IF recovery_count > 10000
       OR recovery_bytes > 67108864
       OR (
            recovery_count > 0
            AND (
                minimum_ordinal <> 0
                OR maximum_ordinal <> recovery_count - 1
            )
       )
       OR (
            session_row.recovery_complete IS TRUE
            AND (
                session_row.recovery_item_count IS DISTINCT FROM recovery_count
                OR session_row.recovery_items_sha256 IS DISTINCT FROM rows_digest
                OR session_row.recovery_payload_bytes IS DISTINCT FROM recovery_bytes
            )
       ) THEN
        RAISE EXCEPTION 'recovery inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF conversation_count + welcome_count + recovery_count > 30000
       OR conversation_bytes + welcome_bytes + recovery_bytes > 67108864 THEN
        RAISE EXCEPTION 'inventory session aggregate ceiling exceeded'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Recompute evidence for completed retained domains without changing counts or
-- any payload bytes.
SET CONSTRAINTS chat.inventory_sessions_materialization_deferred DEFERRED;

WITH conversation_aggregate AS (
    SELECT session.inventory_session_id,
           COALESCE(sum(octet_length(item.payload_bytes))::BIGINT, 0) AS payload_bytes,
           digest(COALESCE(string_agg(
               int8send(item.ordinal)
               || item.item_key_bytes
               || int4send(octet_length(convert_to(item.item_kind, 'UTF8')))
               || convert_to(item.item_kind, 'UTF8')
               || CASE WHEN item.participant_period_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || uuid_send(item.participant_period_id) END
               || CASE WHEN item.membership_interval_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || uuid_send(item.membership_interval_id) END
               || CASE WHEN item.interval_terminal_seq IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || int8send(item.interval_terminal_seq) END
               || CASE WHEN item.interval_closing_transition_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || uuid_send(item.interval_closing_transition_id) END
               || CASE WHEN item.interval_closing_outer_entry_fingerprint IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || item.interval_closing_outer_entry_fingerprint END
               || CASE WHEN item.interval_removed_at IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || timestamptz_send(item.interval_removed_at) END
               || CASE WHEN item.schedule_terminal_seq IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex') || int8send(item.schedule_terminal_seq) END
               || CASE WHEN item.schedule_terminal_transition_id IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || uuid_send(item.schedule_terminal_transition_id) END
               || CASE WHEN item.schedule_terminal_outer_entry_fingerprint IS NULL
                       THEN decode('00', 'hex')
                       ELSE decode('01', 'hex')
                            || item.schedule_terminal_outer_entry_fingerprint END
               || item.payload_sha256
               || int8send(octet_length(item.payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY item.ordinal
           ), decode('', 'hex')), 'sha256') AS items_sha256
      FROM chat.inventory_sessions session
      LEFT JOIN chat.inventory_conversation_items item
        ON item.inventory_session_id = session.inventory_session_id
     GROUP BY session.inventory_session_id
), welcome_aggregate AS (
    SELECT session.inventory_session_id,
           COALESCE(sum(octet_length(item.payload_bytes))::BIGINT, 0) AS payload_bytes,
           digest(COALESCE(string_agg(
               int8send(item.ordinal)
               || item.item_key_bytes
               || item.payload_sha256
               || int8send(octet_length(item.payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY item.ordinal
           ), decode('', 'hex')), 'sha256') AS items_sha256
      FROM chat.inventory_sessions session
      LEFT JOIN chat.inventory_welcome_items item
        ON item.inventory_session_id = session.inventory_session_id
     GROUP BY session.inventory_session_id
), recovery_aggregate AS (
    SELECT session.inventory_session_id,
           COALESCE(sum(octet_length(item.payload_bytes))::BIGINT, 0) AS payload_bytes,
           digest(COALESCE(string_agg(
               int8send(item.ordinal)
               || item.item_key_bytes
               || item.payload_sha256
               || int8send(octet_length(item.payload_bytes)::BIGINT),
               decode('', 'hex') ORDER BY item.ordinal
           ), decode('', 'hex')), 'sha256') AS items_sha256
      FROM chat.inventory_sessions session
      LEFT JOIN chat.inventory_recovery_items item
        ON item.inventory_session_id = session.inventory_session_id
     GROUP BY session.inventory_session_id
)
UPDATE chat.inventory_sessions session
   SET conversation_payload_bytes =
           CASE WHEN session.conversations_complete IS TRUE
                THEN conversation_aggregate.payload_bytes
                ELSE session.conversation_payload_bytes END,
       conversation_items_sha256 =
           CASE WHEN session.conversations_complete IS TRUE
                THEN conversation_aggregate.items_sha256
                ELSE session.conversation_items_sha256 END,
       welcome_payload_bytes =
           CASE WHEN session.welcomes_complete IS TRUE
                THEN welcome_aggregate.payload_bytes
                ELSE session.welcome_payload_bytes END,
       welcome_items_sha256 =
           CASE WHEN session.welcomes_complete IS TRUE
                THEN welcome_aggregate.items_sha256
                ELSE session.welcome_items_sha256 END,
       recovery_payload_bytes =
           CASE WHEN session.recovery_complete IS TRUE
                THEN recovery_aggregate.payload_bytes
                ELSE session.recovery_payload_bytes END,
       recovery_items_sha256 =
           CASE WHEN session.recovery_complete IS TRUE
                THEN recovery_aggregate.items_sha256
                ELSE session.recovery_items_sha256 END
  FROM conversation_aggregate,
       welcome_aggregate,
       recovery_aggregate
 WHERE session.inventory_session_id =
           conversation_aggregate.inventory_session_id
   AND session.inventory_session_id =
           welcome_aggregate.inventory_session_id
   AND session.inventory_session_id =
           recovery_aggregate.inventory_session_id
   AND (
        session.conversations_complete IS TRUE
        OR session.welcomes_complete IS TRUE
        OR session.recovery_complete IS TRUE
   );

SET CONSTRAINTS chat.inventory_sessions_materialization_deferred IMMEDIATE;

ALTER TABLE chat.inventory_sessions
    ADD CONSTRAINT inventory_sessions_completion_evidence_check CHECK (
        (
            (
                conversations_complete IS FALSE
                AND conversation_item_count IS NULL
                AND conversation_items_sha256 IS NULL
                AND conversation_payload_bytes IS NULL
            )
            OR (
                conversations_complete IS TRUE
                AND conversation_item_count IS NOT NULL
                AND chat.is_safe_integer(conversation_item_count)
                AND conversation_item_count BETWEEN 0 AND 10000
                AND conversation_items_sha256 IS NOT NULL
                AND octet_length(conversation_items_sha256) = 32
                AND conversation_payload_bytes IS NOT NULL
                AND chat.is_safe_integer(conversation_payload_bytes)
                AND conversation_payload_bytes BETWEEN 0 AND 67108864
            )
        )
        AND (
            (
                welcomes_complete IS FALSE
                AND welcome_item_count IS NULL
                AND welcome_items_sha256 IS NULL
                AND welcome_payload_bytes IS NULL
            )
            OR (
                welcomes_complete IS TRUE
                AND welcome_item_count IS NOT NULL
                AND chat.is_safe_integer(welcome_item_count)
                AND welcome_item_count BETWEEN 0 AND 10000
                AND welcome_items_sha256 IS NOT NULL
                AND octet_length(welcome_items_sha256) = 32
                AND welcome_payload_bytes IS NOT NULL
                AND chat.is_safe_integer(welcome_payload_bytes)
                AND welcome_payload_bytes BETWEEN 0 AND 67108864
            )
        )
        AND (
            (
                recovery_complete IS FALSE
                AND recovery_item_count IS NULL
                AND recovery_items_sha256 IS NULL
                AND recovery_payload_bytes IS NULL
            )
            OR (
                recovery_complete IS TRUE
                AND recovery_item_count IS NOT NULL
                AND chat.is_safe_integer(recovery_item_count)
                AND recovery_item_count BETWEEN 0 AND 10000
                AND recovery_items_sha256 IS NOT NULL
                AND octet_length(recovery_items_sha256) = 32
                AND recovery_payload_bytes IS NOT NULL
                AND chat.is_safe_integer(recovery_payload_bytes)
                AND recovery_payload_bytes BETWEEN 0 AND 67108864
            )
        )
    ) NOT VALID,
    ADD CONSTRAINT inventory_sessions_total_ceiling_check CHECK (
        COALESCE(conversation_item_count, 0)
            + COALESCE(welcome_item_count, 0)
            + COALESCE(recovery_item_count, 0) <= 30000
        AND COALESCE(conversation_payload_bytes, 0)
            + COALESCE(welcome_payload_bytes, 0)
            + COALESCE(recovery_payload_bytes, 0) <= 67108864
    ) NOT VALID;

ALTER TABLE chat.inventory_sessions
    VALIDATE CONSTRAINT inventory_sessions_completion_evidence_check,
    VALIDATE CONSTRAINT inventory_sessions_total_ceiling_check;

-- Insert-time source validation establishes precedence once. It is deliberately
-- not an UPDATE/deferred revalidator: retained history stays valid when the
-- participant or interval later transitions.
CREATE FUNCTION chat.validate_inventory_conversation_item_source()
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
$$;

CREATE TRIGGER inventory_conversation_items_source_precedence
BEFORE INSERT ON chat.inventory_conversation_items
FOR EACH ROW EXECUTE FUNCTION chat.validate_inventory_conversation_item_source();

CREATE FUNCTION chat.validate_inventory_page_receipt_boundary()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    predecessor chat.inventory_page_receipts%ROWTYPE;
BEGIN
    IF NEW.request_cursor_hash IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT * INTO predecessor
      FROM chat.inventory_page_receipts receipt
     WHERE receipt.successor_cursor_hash = NEW.request_cursor_hash
     FOR SHARE;
    IF NOT FOUND
       OR predecessor.served_at IS NULL
       OR predecessor.has_more IS DISTINCT FROM TRUE
       OR ROW(
            predecessor.inventory_session_id,
            predecessor.domain,
            predecessor.endpoint_nsid,
            predecessor.cursor_format_version,
            predecessor.page_limit,
            predecessor.canonical_filter_sha256,
            predecessor.user_did,
            predecessor.device_id,
            predecessor.jkt,
            predecessor.auth_generation,
            predecessor.protocol_instance_id,
            predecessor.cursor_key_id,
            predecessor.snapshot_event_position,
            predecessor.snapshot_event_cursor_sha256,
            predecessor.snapshot_retained_floor,
            predecessor.expires_at
       ) IS DISTINCT FROM ROW(
            NEW.inventory_session_id,
            NEW.domain,
            NEW.endpoint_nsid,
            NEW.cursor_format_version,
            NEW.page_limit,
            NEW.canonical_filter_sha256,
            NEW.user_did,
            NEW.device_id,
            NEW.jkt,
            NEW.auth_generation,
            NEW.protocol_instance_id,
            NEW.cursor_key_id,
            NEW.snapshot_event_position,
            NEW.snapshot_event_cursor_sha256,
            NEW.snapshot_retained_floor,
            NEW.expires_at
       )
       OR NEW.created_at < predecessor.served_at
       OR NEW.after_ordinal IS DISTINCT FROM
            predecessor.first_ordinal + predecessor.item_count - 1 THEN
        RAISE EXCEPTION 'inventory page continuation boundary mismatch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER inventory_page_receipts_boundary
BEFORE INSERT ON chat.inventory_page_receipts
FOR EACH ROW EXECUTE FUNCTION chat.validate_inventory_page_receipt_boundary();

CREATE FUNCTION chat.validate_event_cursor_receipt_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    session_row chat.inventory_sessions%ROWTYPE;
    predecessor chat.event_cursor_receipts%ROWTYPE;
BEGIN
    SELECT * INTO session_row
      FROM chat.inventory_sessions session
     WHERE session.inventory_session_id = NEW.inventory_session_id
     FOR SHARE;
    IF NOT FOUND THEN
        -- Let the named session FK (and the row's own shape CHECKs) report the
        -- malformed insert in normal constraint order.
        RETURN NEW;
    END IF;

    IF NEW.predecessor_cursor_hash IS NULL THEN
        IF NEW.cursor_hash IS DISTINCT FROM session_row.snapshot_event_cursor_sha256
           OR NEW.event_position IS DISTINCT FROM session_row.snapshot_event_position
           OR NEW.canonical_envelope_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'snapshot event cursor receipt binding mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO predecessor
      FROM chat.event_cursor_receipts receipt
     WHERE receipt.cursor_hash = NEW.predecessor_cursor_hash
     FOR SHARE;
    IF NOT FOUND
       OR ROW(
            predecessor.inventory_session_id,
            predecessor.user_did,
            predecessor.device_id,
            predecessor.jkt,
            predecessor.auth_generation,
            predecessor.protocol_instance_id,
            predecessor.cursor_key_id,
            predecessor.retained_floor_at_issue,
            predecessor.expires_at
       ) IS DISTINCT FROM ROW(
            NEW.inventory_session_id,
            NEW.user_did,
            NEW.device_id,
            NEW.jkt,
            NEW.auth_generation,
            NEW.protocol_instance_id,
            NEW.cursor_key_id,
            NEW.retained_floor_at_issue,
            NEW.expires_at
       )
       OR NEW.event_position <= predecessor.event_position
       OR NEW.created_at < predecessor.created_at
       OR NEW.canonical_envelope_sha256 IS NULL THEN
        RAISE EXCEPTION 'event cursor receipt chain mismatch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER event_cursor_receipts_chain
BEFORE INSERT ON chat.event_cursor_receipts
FOR EACH ROW EXECUTE FUNCTION chat.validate_event_cursor_receipt_chain();

CREATE FUNCTION chat.enforce_inventory_consumption_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD.conversations_consumed IS TRUE AND (
            NEW.conversations_consumed IS FALSE
            OR NEW.conversations_consumed_at IS DISTINCT FROM OLD.conversations_consumed_at
        ))
       OR (OLD.welcomes_consumed IS TRUE AND (
            NEW.welcomes_consumed IS FALSE
            OR NEW.welcomes_consumed_at IS DISTINCT FROM OLD.welcomes_consumed_at
        ))
       OR (OLD.recovery_consumed IS TRUE AND (
            NEW.recovery_consumed IS FALSE
            OR NEW.recovery_consumed_at IS DISTINCT FROM OLD.recovery_consumed_at
        ))
       OR (
            OLD.conversations_consumed IS FALSE
            AND NEW.conversations_consumed IS TRUE
            AND (
                NEW.conversations_complete IS FALSE
                OR NEW.conversations_consumed_at IS NULL
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.inventory_page_receipts receipt
                     WHERE receipt.inventory_session_id = NEW.inventory_session_id
                       AND receipt.domain = 'conversations'
                       AND receipt.served_at = NEW.conversations_consumed_at
                       AND receipt.has_more IS FALSE
                )
            )
       )
       OR (
            OLD.welcomes_consumed IS FALSE
            AND NEW.welcomes_consumed IS TRUE
            AND (
                NEW.welcomes_complete IS FALSE
                OR NEW.welcomes_consumed_at IS NULL
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.inventory_page_receipts receipt
                     WHERE receipt.inventory_session_id = NEW.inventory_session_id
                       AND receipt.domain = 'welcomes'
                       AND receipt.served_at = NEW.welcomes_consumed_at
                       AND receipt.has_more IS FALSE
                )
            )
       )
       OR (
            OLD.recovery_consumed IS FALSE
            AND NEW.recovery_consumed IS TRUE
            AND (
                NEW.recovery_complete IS FALSE
                OR NEW.recovery_consumed_at IS NULL
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.inventory_page_receipts receipt
                     WHERE receipt.inventory_session_id = NEW.inventory_session_id
                       AND receipt.domain = 'recovery'
                       AND receipt.served_at = NEW.recovery_consumed_at
                       AND receipt.has_more IS FALSE
                )
            )
       ) THEN
        RAISE EXCEPTION 'inventory consumption proof is not monotonic'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER inventory_sessions_consumption_monotonic
BEFORE UPDATE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_consumption_monotonic();

CREATE FUNCTION chat.enforce_inventory_page_receipt_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.served_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'served inventory page receipt is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.served_at IS NULL
       AND NEW.served_at IS NULL
       AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'unserved inventory page receipt may only become served'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER inventory_page_receipts_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_page_receipts
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'first_ordinal', 'item_count', 'items_sha256', 'has_more',
    'successor_cursor_hash', 'successor_cursor_nonce',
    'successor_cursor_ciphertext', 'canonical_response_sha256', 'served_at'
);

CREATE TRIGGER inventory_page_receipts_lifecycle_monotonic
BEFORE UPDATE ON chat.inventory_page_receipts
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_page_receipt_lifecycle();

CREATE TRIGGER event_cursor_receipts_immutable
BEFORE UPDATE OR DELETE ON chat.event_cursor_receipts
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

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
       OR ticket_row.jkt <> session_row.jkt
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
               AND device.dpop_jkt = ticket_row.jkt
               AND device.auth_generation = ticket_row.auth_generation
               AND device.created_at <= ticket_row.created_at
               AND device.revoked_at IS NULL
       ) THEN
        RAISE EXCEPTION 'subscription ticket inventory binding mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE TRIGGER inventory_sessions_identity_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'conversations_complete', 'welcomes_complete', 'recovery_complete',
    'conversation_item_count', 'conversation_items_sha256',
    'welcome_item_count', 'welcome_items_sha256',
    'recovery_item_count', 'recovery_items_sha256',
    'conversations_consumed', 'conversations_consumed_at',
    'welcomes_consumed', 'welcomes_consumed_at',
    'recovery_consumed', 'recovery_consumed_at',
    'conversation_payload_bytes', 'welcome_payload_bytes',
    'recovery_payload_bytes'
);

CREATE TRIGGER inventory_sessions_lifecycle_monotonic
BEFORE UPDATE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER inventory_conversation_items_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_conversation_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

SET CONSTRAINTS ALL IMMEDIATE;

DO $$
DECLARE
    materialization_definition TEXT;
BEGIN
    IF (
        SELECT count(*)
          FROM pg_trigger trigger_catalog
          JOIN pg_class relation ON relation.oid = trigger_catalog.tgrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'chat'
           AND NOT trigger_catalog.tgisinternal
           AND trigger_catalog.tgenabled = 'O'
           AND trigger_catalog.tgname IN (
                'inventory_sessions_identity_immutable',
                'inventory_sessions_lifecycle_monotonic',
                'inventory_sessions_materialization_deferred',
                'inventory_sessions_consumption_monotonic',
                'inventory_conversation_items_immutable',
                'inventory_conversation_items_source_precedence',
                'inventory_page_receipts_boundary',
                'inventory_page_receipts_immutable',
                'inventory_page_receipts_lifecycle_monotonic',
                'event_cursor_receipts_chain',
                'event_cursor_receipts_immutable'
           )
    ) <> 11 THEN
        RAISE EXCEPTION 'G7 postflight trigger set is absent or disabled'
            USING ERRCODE = '23514';
    END IF;

    IF pg_get_triggerdef((
        SELECT oid FROM pg_trigger
         WHERE tgname = 'inventory_sessions_identity_immutable'
           AND NOT tgisinternal
    ), false) NOT LIKE
       '%''conversation_payload_bytes'', ''welcome_payload_bytes'', ''recovery_payload_bytes'')%' THEN
        RAISE EXCEPTION 'G7 inventory identity trigger arguments drifted'
            USING ERRCODE = '23514';
    END IF;

    SELECT pg_get_functiondef(routine.oid)
      INTO materialization_definition
      FROM pg_proc routine
      JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
     WHERE namespace.nspname = 'chat'
       AND routine.proname = 'assert_inventory_materialization'
       AND pg_get_function_identity_arguments(routine.oid) = 'target_session uuid';
    IF materialization_definition IS NULL
       OR materialization_definition NOT LIKE '%conversation_payload_bytes%'
       OR materialization_definition NOT LIKE '%item_kind%'
       OR materialization_definition NOT LIKE '%interval_closing_outer_entry_fingerprint%'
       OR materialization_definition NOT LIKE '%30000%'
       OR materialization_definition NOT LIKE '%67108864%' THEN
        RAISE EXCEPTION 'G7 materialization function body drifted'
            USING ERRCODE = '23514';
    END IF;
END
$$;

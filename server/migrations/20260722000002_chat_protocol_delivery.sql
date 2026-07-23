CREATE TABLE chat.entries (
    conversation_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    entry_id UUID NOT NULL UNIQUE,
    entry_kind TEXT NOT NULL,
    accepted_payload_bytes BYTEA NOT NULL,
    accepted_payload_sha256 BYTEA NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    server_fields_bytes BYTEA NOT NULL,
    outer_entry_fingerprint BYTEA NOT NULL,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    actor_key_id TEXT NOT NULL,
    actor_auth_generation BIGINT NOT NULL,
    generation BIGINT,
    state_version BIGINT,
    transition_id UUID,
    message_id UUID,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, seq),
    CONSTRAINT entries_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT entries_actor_key_fk FOREIGN KEY (actor_did, actor_device_id, actor_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT entries_transition_fk FOREIGN KEY (transition_id)
        REFERENCES chat.transitions(transition_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT entries_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT entries_seq_check CHECK (chat.is_safe_integer(seq) AND seq >= 1),
    CONSTRAINT entries_entry_id_check CHECK (chat.is_uuid_v4(entry_id)),
    CONSTRAINT entries_kind_check CHECK (entry_kind IN (
        'blue.catbird.chat.defs#applicationEntry',
        'blue.catbird.chat.defs#commitEntry',
        'blue.catbird.chat.defs#policyEntry',
        'blue.catbird.chat.defs#metadataEntry',
        'blue.catbird.chat.defs#creationEntry',
        'blue.catbird.chat.defs#participantAcceptanceEntry',
        'blue.catbird.chat.defs#conversationCloseEntry',
        'blue.catbird.chat.defs#resetRequestEntry',
        'blue.catbird.chat.defs#resetActivationEntry',
        'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
        'blue.catbird.chat.defs#leaveRequestEntry',
        'blue.catbird.chat.defs#zeroLeafLeaveEntry',
        'blue.catbird.chat.defs#leaveCancellationEntry',
        'blue.catbird.chat.defs#leaveCommitFulfillmentEntry'
    )),
    CONSTRAINT entries_payload_hash_check CHECK (
        octet_length(accepted_payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(accepted_payload_sha256) = 32
        AND accepted_payload_sha256 = digest(accepted_payload_bytes, 'sha256')
    ),
    CONSTRAINT entries_crypto_shape_check CHECK (
        octet_length(request_digest) = 32
        AND octet_length(signature) = 64
        AND octet_length(outer_entry_fingerprint) = 32
        AND octet_length(server_fields_bytes) BETWEEN 1 AND 1048576
    ),
    CONSTRAINT entries_actor_did_check CHECK (chat.is_bare_did(actor_did)),
    CONSTRAINT entries_actor_device_check CHECK (chat.is_uuid_v4(actor_device_id)),
    CONSTRAINT entries_actor_key_check CHECK (chat.is_base64url_sha256(actor_key_id)),
    CONSTRAINT entries_actor_auth_generation_check CHECK (
        chat.is_safe_integer(actor_auth_generation) AND actor_auth_generation >= 1
    ),
    CONSTRAINT entries_generation_check CHECK (generation IS NULL OR chat.is_safe_integer(generation)),
    CONSTRAINT entries_state_version_check CHECK (
        state_version IS NULL OR chat.is_safe_integer(state_version)
    ),
    CONSTRAINT entries_transition_id_check CHECK (
        transition_id IS NULL OR chat.is_uuid_v4(transition_id)
    ),
    CONSTRAINT entries_message_id_check CHECK (message_id IS NULL OR chat.is_uuid_v4(message_id)),
    CONSTRAINT entries_reference_shape_check CHECK (
        (entry_kind = 'blue.catbird.chat.defs#applicationEntry'
            AND message_id IS NOT NULL AND transition_id IS NULL)
        OR (entry_kind IN (
                'blue.catbird.chat.defs#resetRequestEntry',
                'blue.catbird.chat.defs#leaveRequestEntry',
                'blue.catbird.chat.defs#leaveCancellationEntry'
            ) AND transition_id IS NULL AND message_id IS NULL)
        OR (entry_kind NOT IN (
                'blue.catbird.chat.defs#applicationEntry',
                'blue.catbird.chat.defs#resetRequestEntry',
                'blue.catbird.chat.defs#leaveRequestEntry',
                'blue.catbird.chat.defs#leaveCancellationEntry'
            )
            AND transition_id IS NOT NULL AND message_id IS NULL)
    ),
    CONSTRAINT entries_transition_identity_uq UNIQUE (
        conversation_id, seq, transition_id
    ),
    CONSTRAINT entries_participant_provenance_uq UNIQUE (
        entry_id, conversation_id, transition_id
    ),
    CONSTRAINT entries_application_identity_uq UNIQUE (
        conversation_id, seq, message_id
    ),
    CONSTRAINT entries_message_identity_uq UNIQUE (
        conversation_id, message_id
    ),
    CONSTRAINT entries_application_actor_identity_uq UNIQUE (
        conversation_id, seq, message_id, actor_did, actor_device_id
    ),
    CONSTRAINT entries_transition_fingerprint_uq UNIQUE (
        conversation_id, seq, transition_id, outer_entry_fingerprint
    ),
    CONSTRAINT entries_transition_actor_uq UNIQUE (
        conversation_id, seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ),
    CONSTRAINT entries_transition_actor_fk FOREIGN KEY (
        conversation_id, seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ) REFERENCES chat.transitions(
        conversation_id, entry_seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ) DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_entry_actor_fk FOREIGN KEY (
        conversation_id, entry_seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ) REFERENCES chat.entries(
        conversation_id, seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_author_origin_entry_fk
    FOREIGN KEY (
        conversation_id, author_origin_seq, origin_transition_id,
        author_did, author_device_id, author_key_id, author_auth_generation
    ) REFERENCES chat.entries(
        conversation_id, seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.participants
    ADD CONSTRAINT participants_invitation_transition_fk
    FOREIGN KEY (invitation_transition_id) REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_invitation_entry_fk
    FOREIGN KEY (invitation_entry_id) REFERENCES chat.entries(entry_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_invitation_provenance_fk
    FOREIGN KEY (invitation_entry_id, conversation_id, invitation_transition_id)
    REFERENCES chat.entries(entry_id, conversation_id, transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_acceptance_transition_fk
    FOREIGN KEY (acceptance_transition_id) REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_acceptance_entry_fk
    FOREIGN KEY (acceptance_entry_id) REFERENCES chat.entries(entry_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_acceptance_provenance_fk
    FOREIGN KEY (acceptance_entry_id, conversation_id, acceptance_transition_id)
    REFERENCES chat.entries(entry_id, conversation_id, transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_removing_transition_fk
    FOREIGN KEY (removing_transition_id) REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT participants_removal_provenance_fk
    FOREIGN KEY (conversation_id, removing_seq, removing_transition_id)
    REFERENCES chat.entries(conversation_id, seq, transition_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_joined_entry_fk
    FOREIGN KEY (conversation_id, joined_seq, joined_transition_id)
    REFERENCES chat.entries(conversation_id, seq, transition_id)
    DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT member_devices_removed_entry_fk
    FOREIGN KEY (conversation_id, removed_seq, removed_transition_id)
    REFERENCES chat.entries(conversation_id, seq, transition_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION chat.assert_entry_transition_mapping(target_transition UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    transition_row chat.transitions%ROWTYPE;
    mapped_entries BIGINT;
BEGIN
    SELECT * INTO transition_row
      FROM chat.transitions
     WHERE transition_id = target_transition;
    IF NOT FOUND THEN
        IF EXISTS (SELECT 1 FROM chat.entries WHERE transition_id = target_transition) THEN
            RAISE EXCEPTION 'entry transition mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = transition_row.conversation_id
     FOR UPDATE;
    SELECT count(*) INTO mapped_entries
      FROM chat.entries
     WHERE transition_id = target_transition;

    IF mapped_entries <> 1 OR NOT EXISTS (
        SELECT 1
          FROM chat.entries entry
         WHERE entry.transition_id = target_transition
           AND entry.conversation_id = transition_row.conversation_id
           AND entry.seq = transition_row.entry_seq
           AND entry.generation IS NOT DISTINCT FROM transition_row.next_generation
           AND entry.state_version IS NOT DISTINCT FROM transition_row.next_state_version
           AND entry.signed_request_bytes = transition_row.signed_request_bytes
           AND entry.request_digest = transition_row.request_digest
           AND entry.signature = transition_row.signature
           AND entry.received_at = transition_row.accepted_at
           AND entry.entry_kind = CASE transition_row.kind
               WHEN 'creation' THEN 'blue.catbird.chat.defs#creationEntry'
               WHEN 'commit' THEN 'blue.catbird.chat.defs#commitEntry'
               WHEN 'policy' THEN 'blue.catbird.chat.defs#policyEntry'
               WHEN 'acceptConversation' THEN 'blue.catbird.chat.defs#participantAcceptanceEntry'
               WHEN 'metadata' THEN 'blue.catbird.chat.defs#metadataEntry'
               WHEN 'leafRecovery' THEN 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry'
               WHEN 'leaveCommit' THEN 'blue.catbird.chat.defs#leaveCommitFulfillmentEntry'
               WHEN 'leavePolicy' THEN 'blue.catbird.chat.defs#zeroLeafLeaveEntry'
               WHEN 'closeConversation' THEN 'blue.catbird.chat.defs#conversationCloseEntry'
               WHEN 'resetActivation' THEN 'blue.catbird.chat.defs#resetActivationEntry'
           END
    ) THEN
        RAISE EXCEPTION 'entry transition mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_entry_transition_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'transitions' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_entry_transition_mapping(OLD.transition_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_entry_transition_mapping(NEW.transition_id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' AND OLD.transition_id IS NOT NULL THEN
            PERFORM chat.assert_entry_transition_mapping(OLD.transition_id);
        END IF;
        IF TG_OP <> 'DELETE' AND NEW.transition_id IS NOT NULL
           AND (TG_OP = 'INSERT'
                OR NEW.transition_id IS DISTINCT FROM OLD.transition_id) THEN
            PERFORM chat.assert_entry_transition_mapping(NEW.transition_id);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER transitions_entry_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.transitions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_entry_transition_mapping();

CREATE CONSTRAINT TRIGGER entries_transition_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_entry_transition_mapping();

CREATE FUNCTION chat.assert_reset_request_mapping(target_request UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    request_row chat.reset_requests%ROWTYPE;
    request_entry_count BIGINT;
BEGIN
    SELECT * INTO request_row
      FROM chat.reset_requests
     WHERE reset_request_id = target_request;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = request_row.conversation_id
     FOR UPDATE;
    SELECT count(*) INTO request_entry_count
      FROM chat.entries entry
     WHERE entry.conversation_id = request_row.conversation_id
       AND entry.entry_kind = 'blue.catbird.chat.defs#resetRequestEntry'
       AND entry.transition_id IS NULL
       AND entry.actor_did = request_row.requester_did
       AND entry.actor_device_id = request_row.requester_device_id
       AND entry.actor_key_id = request_row.requester_key_id
       AND entry.actor_auth_generation = request_row.requester_auth_generation
       AND entry.signed_request_bytes = request_row.signed_request_bytes
       AND entry.request_digest = request_row.request_digest
       AND entry.signature = request_row.signature
       AND entry.received_at = request_row.received_at;
    IF request_entry_count <> 1 THEN
        RAISE EXCEPTION 'reset request entry mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
    IF request_row.status = 'consumed' AND NOT EXISTS (
        SELECT 1 FROM chat.transitions transition
         WHERE transition.transition_id = request_row.terminal_transition_id
           AND transition.reset_request_id = request_row.reset_request_id
           AND transition.conversation_id = request_row.conversation_id
           AND transition.kind = 'resetActivation'
           AND transition.prior_generation = request_row.prior_generation
           AND transition.prior_state_version = request_row.prior_state_version
           AND transition.accepted_at = request_row.terminal_at
    ) THEN
        RAISE EXCEPTION 'reset activation request mapping mismatch'
            USING ERRCODE = '23514';
    ELSIF request_row.status = 'stale' AND NOT EXISTS (
        SELECT 1 FROM chat.transitions transition
         WHERE transition.transition_id = request_row.terminal_transition_id
           AND transition.conversation_id = request_row.conversation_id
           AND transition.prior_generation = request_row.prior_generation
           AND transition.prior_state_version = request_row.prior_state_version
           AND transition.accepted_at = request_row.terminal_at
           AND NOT (
                transition.kind = 'resetActivation'
                AND transition.reset_request_id = request_row.reset_request_id
           )
    ) THEN
        RAISE EXCEPTION 'stale reset request mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.assert_leave_request_mapping(target_request UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    request_row chat.leave_requests%ROWTYPE;
    request_entry_count BIGINT;
BEGIN
    SELECT * INTO request_row
      FROM chat.leave_requests
     WHERE leave_request_id = target_request;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = request_row.conversation_id
     FOR UPDATE;
    SELECT count(*) INTO request_entry_count
      FROM chat.entries entry
     WHERE entry.conversation_id = request_row.conversation_id
       AND entry.entry_kind = 'blue.catbird.chat.defs#leaveRequestEntry'
       AND entry.transition_id IS NULL
       AND entry.actor_did = request_row.requester_did
       AND entry.actor_device_id = request_row.requester_device_id
       AND entry.actor_key_id = request_row.requester_key_id
       AND entry.actor_auth_generation = request_row.requester_auth_generation
       AND entry.signed_request_bytes = request_row.signed_request_bytes
       AND entry.request_digest = request_row.request_digest
       AND entry.signature = request_row.signature
       AND entry.received_at = request_row.received_at;
    IF request_entry_count <> 1 THEN
        RAISE EXCEPTION 'leave request entry mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
    IF request_row.status IN ('fulfilled','stale') AND NOT EXISTS (
        SELECT 1 FROM chat.transitions transition
         WHERE transition.transition_id = request_row.terminal_transition_id
           AND transition.conversation_id = request_row.conversation_id
           AND transition.prior_generation = request_row.prior_generation
           AND transition.prior_state_version = request_row.prior_state_version
           AND transition.request_digest = request_row.terminal_request_digest
           AND transition.accepted_at = request_row.terminal_at
           AND (
                (request_row.status = 'fulfilled'
                    AND transition.kind IN ('leaveCommit','leavePolicy'))
                OR (request_row.status = 'stale'
                    AND transition.kind NOT IN ('leaveCommit','leavePolicy'))
           )
    ) THEN
        RAISE EXCEPTION 'terminal leave transition mapping mismatch'
            USING ERRCODE = '23514';
    ELSIF request_row.status = 'cancelled' AND NOT EXISTS (
        SELECT 1 FROM chat.entries entry
         WHERE entry.conversation_id = request_row.conversation_id
           AND entry.entry_kind = 'blue.catbird.chat.defs#leaveCancellationEntry'
           AND entry.transition_id IS NULL
           AND entry.actor_did = request_row.requester_did
           AND entry.actor_device_id = request_row.requester_device_id
           AND entry.actor_key_id = request_row.requester_key_id
           AND entry.actor_auth_generation = request_row.requester_auth_generation
           AND entry.request_digest = request_row.terminal_request_digest
           AND entry.received_at = request_row.terminal_at
    ) THEN
        RAISE EXCEPTION 'leave cancellation entry mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.assert_control_request_entry(
    target_conversation UUID,
    target_seq BIGINT
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    entry_row chat.entries%ROWTYPE;
    mapping_count BIGINT;
BEGIN
    SELECT * INTO entry_row
      FROM chat.entries
     WHERE conversation_id = target_conversation AND seq = target_seq;
    IF NOT FOUND THEN RETURN; END IF;
    IF entry_row.entry_kind = 'blue.catbird.chat.defs#resetRequestEntry' THEN
        SELECT count(*) INTO mapping_count
          FROM chat.reset_requests request
         WHERE request.conversation_id = entry_row.conversation_id
           AND request.requester_did = entry_row.actor_did
           AND request.requester_device_id = entry_row.actor_device_id
           AND request.requester_key_id = entry_row.actor_key_id
           AND request.requester_auth_generation = entry_row.actor_auth_generation
           AND request.signed_request_bytes = entry_row.signed_request_bytes
           AND request.request_digest = entry_row.request_digest
           AND request.signature = entry_row.signature
           AND request.received_at = entry_row.received_at;
    ELSIF entry_row.entry_kind = 'blue.catbird.chat.defs#leaveRequestEntry' THEN
        SELECT count(*) INTO mapping_count
          FROM chat.leave_requests request
         WHERE request.conversation_id = entry_row.conversation_id
           AND request.requester_did = entry_row.actor_did
           AND request.requester_device_id = entry_row.actor_device_id
           AND request.requester_key_id = entry_row.actor_key_id
           AND request.requester_auth_generation = entry_row.actor_auth_generation
           AND request.signed_request_bytes = entry_row.signed_request_bytes
           AND request.request_digest = entry_row.request_digest
           AND request.signature = entry_row.signature
           AND request.received_at = entry_row.received_at;
    ELSIF entry_row.entry_kind = 'blue.catbird.chat.defs#leaveCancellationEntry' THEN
        SELECT count(*) INTO mapping_count
          FROM chat.leave_requests request
         WHERE request.conversation_id = entry_row.conversation_id
           AND request.status = 'cancelled'
           AND request.requester_did = entry_row.actor_did
           AND request.requester_device_id = entry_row.actor_device_id
           AND request.requester_key_id = entry_row.actor_key_id
           AND request.requester_auth_generation = entry_row.actor_auth_generation
           AND request.terminal_request_digest = entry_row.request_digest
           AND request.terminal_at = entry_row.received_at;
    ELSE
        RETURN;
    END IF;
    IF mapping_count <> 1 THEN
        RAISE EXCEPTION 'control request entry mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_control_request_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_request UUID;
BEGIN
    IF TG_TABLE_NAME = 'reset_requests' THEN
        IF TG_OP <> 'INSERT' THEN PERFORM chat.assert_reset_request_mapping(OLD.reset_request_id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM chat.assert_reset_request_mapping(NEW.reset_request_id); END IF;
    ELSIF TG_TABLE_NAME = 'leave_requests' THEN
        IF TG_OP <> 'INSERT' THEN PERFORM chat.assert_leave_request_mapping(OLD.leave_request_id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM chat.assert_leave_request_mapping(NEW.leave_request_id); END IF;
    ELSIF TG_TABLE_NAME = 'entries' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_control_request_entry(OLD.conversation_id, OLD.seq);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_control_request_entry(NEW.conversation_id, NEW.seq);
        END IF;
        FOR linked_request IN
            SELECT reset_request_id FROM chat.reset_requests
             WHERE conversation_id = COALESCE(NEW.conversation_id, OLD.conversation_id)
            UNION
            SELECT leave_request_id FROM chat.leave_requests
             WHERE conversation_id = COALESCE(NEW.conversation_id, OLD.conversation_id)
        LOOP
            IF EXISTS (SELECT 1 FROM chat.reset_requests WHERE reset_request_id = linked_request) THEN
                PERFORM chat.assert_reset_request_mapping(linked_request);
            ELSE
                PERFORM chat.assert_leave_request_mapping(linked_request);
            END IF;
        END LOOP;
    ELSE
        FOR linked_request IN
            SELECT reset_request_id FROM chat.reset_requests
             WHERE terminal_transition_id IN (OLD.transition_id, NEW.transition_id)
                OR reset_request_id IN (OLD.reset_request_id, NEW.reset_request_id)
        LOOP
            PERFORM chat.assert_reset_request_mapping(linked_request);
        END LOOP;
        FOR linked_request IN
            SELECT leave_request_id FROM chat.leave_requests
             WHERE terminal_transition_id IN (OLD.transition_id, NEW.transition_id)
        LOOP
            PERFORM chat.assert_leave_request_mapping(linked_request);
        END LOOP;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER reset_requests_entry_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.reset_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_control_request_mapping();

CREATE CONSTRAINT TRIGGER leave_requests_entry_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.leave_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_control_request_mapping();

CREATE CONSTRAINT TRIGGER entries_control_request_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_control_request_mapping();

CREATE CONSTRAINT TRIGGER transitions_control_request_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.transitions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_control_request_mapping();

CREATE FUNCTION chat.assert_participant_provenance(target_participant UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    participant_row chat.participants%ROWTYPE;
BEGIN
    SELECT * INTO participant_row
      FROM chat.participants
     WHERE participant_period_id = target_participant;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = participant_row.conversation_id
     FOR UPDATE;

    IF participant_row.invitation_transition_id IS NULL THEN
        IF NOT EXISTS (
            SELECT 1
              FROM chat.transitions transition
              JOIN chat.entries entry
                ON entry.conversation_id = transition.conversation_id
               AND entry.seq = transition.entry_seq
               AND entry.transition_id = transition.transition_id
             WHERE transition.conversation_id = participant_row.conversation_id
               AND transition.kind = 'creation'
               AND transition.actor_did = participant_row.created_by_did
               AND transition.actor_device_id = participant_row.created_by_device_id
               AND entry.entry_kind = 'blue.catbird.chat.defs#creationEntry'
               AND participant_row.user_did = participant_row.created_by_did
               AND participant_row.created_at = transition.accepted_at
               AND entry.received_at = transition.accepted_at
        ) THEN
            RAISE EXCEPTION 'participant provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1
              FROM chat.entries entry
              JOIN chat.transitions transition
                ON transition.transition_id = entry.transition_id
               AND transition.conversation_id = entry.conversation_id
               AND transition.entry_seq = entry.seq
             WHERE entry.entry_id = participant_row.invitation_entry_id
               AND entry.conversation_id = participant_row.conversation_id
               AND entry.transition_id = participant_row.invitation_transition_id
               AND transition.actor_did = participant_row.created_by_did
               AND transition.actor_device_id = participant_row.created_by_device_id
               AND participant_row.created_at = transition.accepted_at
               AND participant_row.invited_at = transition.accepted_at
               AND entry.received_at = transition.accepted_at
               AND (
                    (entry.entry_kind = 'blue.catbird.chat.defs#creationEntry'
                     AND transition.kind = 'creation')
                    OR
                    (entry.entry_kind = 'blue.catbird.chat.defs#policyEntry'
                     AND transition.kind = 'policy'
                     AND transition.actor_role = 'admin'
                     AND transition.actor_device_status = 'active')
               )
        ) THEN
            RAISE EXCEPTION 'participant provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF participant_row.acceptance_transition_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM chat.entries entry
          JOIN chat.transitions transition
            ON transition.transition_id = entry.transition_id
           AND transition.conversation_id = entry.conversation_id
           AND transition.entry_seq = entry.seq
         WHERE entry.entry_id = participant_row.acceptance_entry_id
           AND entry.conversation_id = participant_row.conversation_id
           AND entry.transition_id = participant_row.acceptance_transition_id
           AND entry.entry_kind = 'blue.catbird.chat.defs#participantAcceptanceEntry'
           AND transition.kind = 'acceptConversation'
           AND transition.actor_did = participant_row.user_did
           AND participant_row.accepted_at = transition.accepted_at
           AND entry.received_at = transition.accepted_at
    ) THEN
        RAISE EXCEPTION 'participant provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF participant_row.removing_transition_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM chat.entries entry
          JOIN chat.transitions transition
            ON transition.transition_id = entry.transition_id
           AND transition.conversation_id = entry.conversation_id
           AND transition.entry_seq = entry.seq
         WHERE entry.conversation_id = participant_row.conversation_id
           AND entry.seq = participant_row.removing_seq
           AND entry.transition_id = participant_row.removing_transition_id
           AND participant_row.removed_at = transition.accepted_at
           AND entry.received_at = transition.accepted_at
           AND (
                (transition.actor_did = participant_row.user_did
                 AND transition.kind = 'leavePolicy'
                 AND entry.entry_kind = 'blue.catbird.chat.defs#zeroLeafLeaveEntry')
                OR
                (transition.actor_did <> participant_row.user_did
                 AND transition.kind = 'leaveCommit'
                 AND entry.entry_kind = 'blue.catbird.chat.defs#leaveCommitFulfillmentEntry'
                 AND EXISTS (
                    SELECT 1 FROM chat.leave_requests leave_request
                     WHERE leave_request.conversation_id = participant_row.conversation_id
                       AND leave_request.requester_did = participant_row.user_did
                       AND leave_request.status = 'fulfilled'
                       AND leave_request.terminal_transition_id = transition.transition_id
                       AND leave_request.terminal_request_digest = transition.request_digest
                       AND leave_request.terminal_at = transition.accepted_at
                 ))
                OR
                (transition.kind = 'policy'
                 AND entry.entry_kind = 'blue.catbird.chat.defs#policyEntry'
                 AND transition.actor_role = 'admin'
                 AND transition.actor_device_status = 'active')
           )
    ) THEN
        RAISE EXCEPTION 'participant provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.transitions role_transition
          JOIN chat.entries role_entry
            ON role_entry.conversation_id = role_transition.conversation_id
           AND role_entry.seq = role_transition.entry_seq
           AND role_entry.transition_id = role_transition.transition_id
         WHERE role_transition.transition_id = participant_row.role_transition_id
           AND role_transition.conversation_id = participant_row.conversation_id
           AND role_transition.accepted_at = participant_row.role_changed_at
           AND ((role_transition.kind = 'creation'
                 AND role_entry.entry_kind = 'blue.catbird.chat.defs#creationEntry')
                OR (role_transition.kind = 'policy'
                    AND role_entry.entry_kind = 'blue.catbird.chat.defs#policyEntry'))
           AND (
                (participant_row.role_transition_id = participant_row.invitation_transition_id
                 AND role_transition.kind IN ('creation','policy'))
                OR (participant_row.invitation_transition_id IS NULL
                    AND role_transition.kind = 'creation')
                OR (role_transition.kind = 'policy'
                    AND role_transition.actor_role = 'admin'
                    AND role_transition.actor_device_status = 'active')
           )
    ) THEN
        RAISE EXCEPTION 'participant role transition provenance mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_participant_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_participant_provenance(OLD.participant_period_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.participant_period_id IS DISTINCT FROM OLD.participant_period_id) THEN
        PERFORM chat.assert_participant_provenance(NEW.participant_period_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER participants_provenance_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.participants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_participant_provenance();

CREATE INDEX entries_transition_idx ON chat.entries (conversation_id, transition_id);
CREATE INDEX entries_message_idx ON chat.entries (conversation_id, message_id);

CREATE TABLE chat.message_sends (
    conversation_id UUID NOT NULL,
    message_id UUID NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    status TEXT NOT NULL,
    accepted_entry_seq BIGINT,
    outcome_bytes BYTEA NOT NULL,
    outcome_sha256 BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, message_id),
    CONSTRAINT message_sends_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT message_sends_application_entry_fk FOREIGN KEY (
        conversation_id, accepted_entry_seq, message_id
    ) REFERENCES chat.entries(conversation_id, seq, message_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT message_sends_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT message_sends_message_id_check CHECK (chat.is_uuid_v4(message_id)),
    CONSTRAINT message_sends_signature_check CHECK (
        octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32
        AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT message_sends_status_check CHECK (status IN ('accepted','stale')),
    CONSTRAINT message_sends_entry_seq_check CHECK (
        accepted_entry_seq IS NULL OR chat.is_safe_integer(accepted_entry_seq)
    ),
    CONSTRAINT message_sends_status_shape_check CHECK (
        (status = 'accepted' AND accepted_entry_seq IS NOT NULL)
        OR (status = 'stale' AND accepted_entry_seq IS NULL)
    ),
    CONSTRAINT message_sends_outcome_hash_check CHECK (
        octet_length(outcome_bytes) BETWEEN 1 AND 16777216
        AND octet_length(outcome_sha256) = 32
        AND outcome_sha256 = digest(outcome_bytes, 'sha256')
    )
);

ALTER TABLE chat.entries
    ADD CONSTRAINT entries_message_send_fk
    FOREIGN KEY (conversation_id, message_id)
    REFERENCES chat.message_sends(conversation_id, message_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION chat.assert_message_send_mapping(
    target_conversation UUID,
    target_message UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    send_row chat.message_sends%ROWTYPE;
    send_found BOOLEAN;
    entry_count BIGINT;
BEGIN
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT * INTO send_row
      FROM chat.message_sends
     WHERE conversation_id = target_conversation
       AND message_id = target_message;
    send_found := FOUND;
    SELECT count(*) INTO entry_count
      FROM chat.entries
     WHERE conversation_id = target_conversation
       AND message_id = target_message;

    IF NOT send_found THEN
        IF entry_count <> 0 THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF send_row.status = 'accepted' THEN
        IF entry_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM chat.entries
             WHERE conversation_id = target_conversation
               AND seq = send_row.accepted_entry_seq
               AND message_id = target_message
               AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'
               AND signed_request_bytes = send_row.signed_request_bytes
               AND request_digest = send_row.request_digest
               AND signature = send_row.signature
               AND received_at = send_row.received_at
        ) THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF entry_count <> 0 THEN
        RAISE EXCEPTION 'application message mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_message_send_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'message_sends' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_message_send_mapping(OLD.conversation_id, OLD.message_id);
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT'
                OR (NEW.conversation_id, NEW.message_id)
                   IS DISTINCT FROM (OLD.conversation_id, OLD.message_id)) THEN
            PERFORM chat.assert_message_send_mapping(NEW.conversation_id, NEW.message_id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' AND OLD.message_id IS NOT NULL THEN
            PERFORM chat.assert_message_send_mapping(OLD.conversation_id, OLD.message_id);
        END IF;
        IF TG_OP <> 'DELETE' AND NEW.message_id IS NOT NULL
           AND (TG_OP = 'INSERT'
                OR (NEW.conversation_id, NEW.message_id)
                   IS DISTINCT FROM (OLD.conversation_id, OLD.message_id)) THEN
            PERFORM chat.assert_message_send_mapping(NEW.conversation_id, NEW.message_id);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER message_sends_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.message_sends
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_message_send_mapping();

CREATE CONSTRAINT TRIGGER entries_message_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_message_send_mapping();

CREATE TABLE chat.application_intervals (
    membership_interval_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    start_seq BIGINT NOT NULL,
    opening_kind TEXT NOT NULL,
    opening_transition_id UUID NOT NULL,
    opening_outer_entry_fingerprint BYTEA NOT NULL,
    opening_state_version BIGINT NOT NULL,
    opening_group_id BYTEA NOT NULL,
    opening_epoch BIGINT NOT NULL,
    opening_group_context_hash BYTEA NOT NULL,
    opening_confirmation_tag BYTEA NOT NULL,
    opening_leaf_period_id UUID NOT NULL,
    terminal_seq BIGINT,
    closing_state_version BIGINT,
    closing_transition_id UUID,
    closing_outer_entry_fingerprint BYTEA,
    closing_kind TEXT,
    closing_leaf_period_id UUID,
    removed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT application_intervals_generation_fk FOREIGN KEY (conversation_id, generation)
        REFERENCES chat.generations(conversation_id, generation),
    CONSTRAINT application_intervals_recipient_device_fk FOREIGN KEY (recipient_did, recipient_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT application_intervals_opening_entry_fk FOREIGN KEY (conversation_id, start_seq)
        REFERENCES chat.entries(conversation_id, seq) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_closing_entry_fk FOREIGN KEY (conversation_id, terminal_seq)
        REFERENCES chat.entries(conversation_id, seq) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_opening_leaf_fk FOREIGN KEY (opening_leaf_period_id)
        REFERENCES chat.member_devices(leaf_period_id),
    CONSTRAINT application_intervals_closing_leaf_fk FOREIGN KEY (closing_leaf_period_id)
        REFERENCES chat.member_devices(leaf_period_id),
    CONSTRAINT application_intervals_opening_transition_fk FOREIGN KEY (opening_transition_id)
        REFERENCES chat.transitions(transition_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_closing_transition_fk FOREIGN KEY (closing_transition_id)
        REFERENCES chat.transitions(transition_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_opening_provenance_fk FOREIGN KEY (
        conversation_id, start_seq, opening_transition_id, opening_outer_entry_fingerprint
    ) REFERENCES chat.entries(
        conversation_id, seq, transition_id, outer_entry_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_closing_provenance_fk FOREIGN KEY (
        conversation_id, terminal_seq, closing_transition_id, closing_outer_entry_fingerprint
    ) REFERENCES chat.entries(
        conversation_id, seq, transition_id, outer_entry_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_opening_state_fk FOREIGN KEY (
        conversation_id, generation, opening_state_version, opening_group_id,
        opening_epoch, opening_group_context_hash, opening_confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id,
        epoch, group_context_hash, confirmation_tag
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_opening_leaf_identity_fk FOREIGN KEY (
        opening_leaf_period_id, conversation_id, generation, recipient_did, recipient_device_id,
        opening_state_version, opening_transition_id, start_seq
    ) REFERENCES chat.member_devices(
        leaf_period_id, conversation_id, generation, user_did, device_id,
        joined_state_version, joined_transition_id, joined_seq
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_closing_leaf_identity_fk FOREIGN KEY (
        closing_leaf_period_id, conversation_id, generation, recipient_did, recipient_device_id,
        closing_state_version, closing_transition_id, terminal_seq
    ) REFERENCES chat.member_devices(
        leaf_period_id, conversation_id, generation, user_did, device_id,
        removed_state_version, removed_transition_id, removed_seq
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_intervals_id_check CHECK (
        chat.is_uuid_v4(membership_interval_id)
        AND membership_interval_id = opening_transition_id
    ),
    CONSTRAINT application_intervals_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT application_intervals_recipient_did_check CHECK (chat.is_bare_did(recipient_did)),
    CONSTRAINT application_intervals_recipient_device_check CHECK (chat.is_uuid_v4(recipient_device_id)),
    CONSTRAINT application_intervals_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT application_intervals_start_seq_check CHECK (
        chat.is_safe_integer(start_seq) AND start_seq >= 1
    ),
    CONSTRAINT application_intervals_opening_kind_check CHECK (opening_kind IN ('creation','add','reset')),
    CONSTRAINT application_intervals_opening_transition_check CHECK (chat.is_uuid_v4(opening_transition_id)),
    CONSTRAINT application_intervals_opening_context_check CHECK (
        chat.is_safe_integer(opening_state_version)
        AND chat.is_safe_integer(opening_epoch)
        AND octet_length(opening_outer_entry_fingerprint) = 32
        AND octet_length(opening_group_id) = 32
        AND octet_length(opening_group_context_hash) = 32
        AND octet_length(opening_confirmation_tag) = 32
    ),
    CONSTRAINT application_intervals_terminal_seq_check CHECK (
        terminal_seq IS NULL OR chat.is_safe_integer(terminal_seq)
    ),
    CONSTRAINT application_intervals_closing_state_version_check CHECK (
        closing_state_version IS NULL OR chat.is_safe_integer(closing_state_version)
    ),
    CONSTRAINT application_intervals_closing_transition_check CHECK (
        closing_transition_id IS NULL OR chat.is_uuid_v4(closing_transition_id)
    ),
    CONSTRAINT application_intervals_close_kind_check CHECK (
        closing_kind IS NULL OR closing_kind IN ('remove','replace','reset','terminal')
    ),
    CONSTRAINT application_intervals_close_shape_check CHECK (
        (terminal_seq IS NULL AND closing_state_version IS NULL AND closing_transition_id IS NULL
            AND closing_outer_entry_fingerprint IS NULL AND closing_kind IS NULL
            AND closing_leaf_period_id IS NULL AND removed_at IS NULL)
        OR (terminal_seq IS NOT NULL AND terminal_seq > start_seq
            AND closing_state_version IS NOT NULL
            AND closing_transition_id IS NOT NULL
            AND octet_length(closing_outer_entry_fingerprint) = 32
            AND closing_kind IS NOT NULL AND closing_leaf_period_id IS NOT NULL
            AND removed_at IS NOT NULL)
    ),
    CONSTRAINT application_intervals_terminal_identity_uq UNIQUE (
        conversation_id, recipient_did, recipient_device_id, terminal_seq,
        closing_transition_id, closing_outer_entry_fingerprint
    ),
    CONSTRAINT application_intervals_leaf_opening_uq UNIQUE (
        opening_leaf_period_id, conversation_id, generation, recipient_did,
        recipient_device_id, opening_state_version, opening_transition_id, start_seq
    ),
    CONSTRAINT application_intervals_leaf_closing_uq UNIQUE (
        closing_leaf_period_id, conversation_id, generation, recipient_did,
        recipient_device_id, closing_state_version, closing_transition_id, terminal_seq
    )
);

ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_opening_interval_fk FOREIGN KEY (
        leaf_period_id, conversation_id, generation, user_did, device_id,
        joined_state_version, joined_transition_id, joined_seq
    ) REFERENCES chat.application_intervals(
        opening_leaf_period_id, conversation_id, generation, recipient_did,
        recipient_device_id, opening_state_version, opening_transition_id, start_seq
    ) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT member_devices_closing_interval_fk FOREIGN KEY (
        leaf_period_id, conversation_id, generation, user_did, device_id,
        removed_state_version, removed_transition_id, removed_seq
    ) REFERENCES chat.application_intervals(
        closing_leaf_period_id, conversation_id, generation, recipient_did,
        recipient_device_id, closing_state_version, closing_transition_id, terminal_seq
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX application_intervals_opening_uq
    ON chat.application_intervals (
        conversation_id, recipient_did, recipient_device_id, start_seq,
        opening_transition_id, opening_outer_entry_fingerprint
    );
CREATE INDEX application_intervals_visible_idx
    ON chat.application_intervals (conversation_id, recipient_did, recipient_device_id, start_seq, terminal_seq);

CREATE FUNCTION chat.assert_member_interval_mapping(target_leaf UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    member_row chat.member_devices%ROWTYPE;
    interval_row chat.application_intervals%ROWTYPE;
    opening_transition chat.transitions%ROWTYPE;
    closing_transition chat.transitions%ROWTYPE;
BEGIN
    SELECT * INTO member_row
      FROM chat.member_devices
     WHERE leaf_period_id = target_leaf;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.application_intervals
             WHERE opening_leaf_period_id = target_leaf
                OR closing_leaf_period_id = target_leaf
        ) THEN
            RAISE EXCEPTION 'leaf interval mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = member_row.conversation_id
     FOR UPDATE;
    SELECT * INTO interval_row
      FROM chat.application_intervals
     WHERE opening_leaf_period_id = target_leaf;
    IF NOT FOUND
       OR (interval_row.conversation_id, interval_row.generation,
           interval_row.recipient_did, interval_row.recipient_device_id,
           interval_row.opening_state_version, interval_row.opening_transition_id,
           interval_row.start_seq)
          IS DISTINCT FROM
          (member_row.conversation_id, member_row.generation,
           member_row.user_did, member_row.device_id,
           member_row.joined_state_version, member_row.joined_transition_id,
           member_row.joined_seq)
       OR member_row.active IS DISTINCT FROM (interval_row.terminal_seq IS NULL)
       OR member_row.created_at <> interval_row.created_at THEN
        RAISE EXCEPTION 'leaf interval mapping mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO opening_transition
      FROM chat.transitions
     WHERE transition_id = member_row.joined_transition_id;
    IF NOT FOUND
       OR opening_transition.conversation_id <> member_row.conversation_id
       OR opening_transition.entry_seq <> member_row.joined_seq
       OR member_row.created_at <> opening_transition.accepted_at
       OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
             WHERE state.conversation_id = member_row.conversation_id
               AND state.generation = member_row.generation
               AND state.state_version = member_row.joined_state_version
               AND state.producing_transition_id = member_row.joined_transition_id
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.participants participant
             WHERE participant.participant_period_id = member_row.participant_period_id
               AND participant.conversation_id = member_row.conversation_id
               AND participant.user_did = member_row.user_did
               AND participant.status = 'active'
               AND participant.created_at <= opening_transition.accepted_at
               AND (participant.accepted_at IS NULL
                    OR participant.accepted_at <= opening_transition.accepted_at)
               AND (participant.removed_at IS NULL
                    OR participant.removed_at >= opening_transition.accepted_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices device
             WHERE device.user_did = member_row.user_did
               AND device.device_id = member_row.device_id
               AND device.created_at <= opening_transition.accepted_at
               AND (device.revoked_at IS NULL
                    OR device.revoked_at >= opening_transition.accepted_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.device_keys device_key
             WHERE device_key.user_did = member_row.user_did
               AND device_key.device_id = member_row.device_id
               AND device_key.key_id = member_row.leaf_key_id
               AND device_key.signing_public_key = member_row.leaf_signature_key
               AND device_key.created_at <= opening_transition.accepted_at
               AND (device_key.revoked_at IS NULL
                    OR device_key.revoked_at >= opening_transition.accepted_at)
       ) THEN
        RAISE EXCEPTION 'leaf opening provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF member_row.origin = 'genesis' THEN
        IF member_row.join_key_package_ref IS NOT NULL
           OR interval_row.opening_kind NOT IN ('creation','reset')
           OR ((interval_row.opening_kind = 'creation')
               <> (opening_transition.kind = 'creation'))
           OR ((interval_row.opening_kind = 'reset')
               <> (opening_transition.kind = 'resetActivation'))
           OR (member_row.user_did, member_row.device_id)
              IS DISTINCT FROM
              (opening_transition.actor_did, opening_transition.actor_device_id)
           OR (member_row.leaf_key_id, member_row.leaf_auth_generation)
              IS DISTINCT FROM
              (opening_transition.actor_key_id, opening_transition.actor_auth_generation) THEN
            RAISE EXCEPTION 'genesis leaf provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF interval_row.opening_kind <> 'add'
           OR opening_transition.kind <> 'leafRecovery'
           OR NOT EXISTS (
                SELECT 1
                  FROM chat.key_packages package
                 WHERE package.key_package_ref = member_row.join_key_package_ref
                   AND package.owner_did = member_row.user_did
                   AND package.owner_device_id = member_row.device_id
                   AND package.owner_key_id = member_row.leaf_key_id
                   AND package.owner_auth_generation = member_row.leaf_auth_generation
                   AND package.status = 'consumed'
                   AND package.terminal_transition_id = member_row.joined_transition_id
           ) THEN
            RAISE EXCEPTION 'KeyPackage leaf provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NOT member_row.active THEN
        SELECT * INTO closing_transition
          FROM chat.transitions
         WHERE transition_id = member_row.removed_transition_id;
        IF NOT FOUND
           OR interval_row.closing_leaf_period_id <> member_row.leaf_period_id
           OR interval_row.closing_state_version <> member_row.removed_state_version
           OR interval_row.closing_transition_id <> member_row.removed_transition_id
           OR interval_row.terminal_seq <> member_row.removed_seq
           OR interval_row.removed_at <> member_row.removed_at
           OR member_row.removed_at <> closing_transition.accepted_at
           OR (
                interval_row.closing_kind = 'reset'
                AND NOT (
                    closing_transition.kind = 'resetActivation'
                    AND closing_transition.retired_generation = member_row.generation
                    AND closing_transition.retired_state_version = member_row.removed_state_version
                )
           )
           OR (
                interval_row.closing_kind <> 'reset'
                AND NOT (
                    closing_transition.conversation_id = member_row.conversation_id
                    AND closing_transition.next_generation = member_row.generation
                    AND closing_transition.next_state_version = member_row.removed_state_version
                )
           )
           OR NOT EXISTS (
                SELECT 1
                  FROM chat.generation_states state
                 WHERE state.conversation_id = member_row.conversation_id
                   AND state.generation = member_row.generation
                   AND state.state_version = member_row.removed_state_version
                   AND state.producing_transition_id = member_row.removed_transition_id
           ) THEN
            RAISE EXCEPTION 'leaf closing provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_member_interval_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'member_devices' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_member_interval_mapping(OLD.leaf_period_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_member_interval_mapping(NEW.leaf_period_id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_member_interval_mapping(OLD.opening_leaf_period_id);
            IF OLD.closing_leaf_period_id IS NOT NULL
               AND OLD.closing_leaf_period_id <> OLD.opening_leaf_period_id THEN
                PERFORM chat.assert_member_interval_mapping(OLD.closing_leaf_period_id);
            END IF;
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_member_interval_mapping(NEW.opening_leaf_period_id);
            IF NEW.closing_leaf_period_id IS NOT NULL
               AND NEW.closing_leaf_period_id <> NEW.opening_leaf_period_id THEN
                PERFORM chat.assert_member_interval_mapping(NEW.closing_leaf_period_id);
            END IF;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER member_devices_interval_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.member_devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_member_interval_mapping();

CREATE CONSTRAINT TRIGGER application_intervals_member_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.application_intervals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_member_interval_mapping();

CREATE TABLE chat.application_schedule_terminal_proofs (
    conversation_id UUID NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    terminal_seq BIGINT NOT NULL,
    transition_id UUID NOT NULL,
    outer_entry_fingerprint BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, recipient_did, recipient_device_id),
    CONSTRAINT application_schedule_terminal_proofs_entry_fk FOREIGN KEY (conversation_id, terminal_seq)
        REFERENCES chat.entries(conversation_id, seq),
    CONSTRAINT application_schedule_terminal_proofs_device_fk FOREIGN KEY (recipient_did, recipient_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT application_schedule_terminal_proofs_transition_fk FOREIGN KEY (transition_id)
        REFERENCES chat.transitions(transition_id),
    CONSTRAINT application_schedule_terminal_proofs_provenance_fk FOREIGN KEY (
        conversation_id, terminal_seq, transition_id, outer_entry_fingerprint
    ) REFERENCES chat.entries(
        conversation_id, seq, transition_id, outer_entry_fingerprint
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT application_schedule_terminal_proofs_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT application_schedule_terminal_proofs_recipient_did_check CHECK (chat.is_bare_did(recipient_did)),
    CONSTRAINT application_schedule_terminal_proofs_device_id_check CHECK (chat.is_uuid_v4(recipient_device_id)),
    CONSTRAINT application_schedule_terminal_proofs_terminal_seq_check CHECK (
        chat.is_safe_integer(terminal_seq) AND terminal_seq >= 1
    ),
    CONSTRAINT application_schedule_terminal_proofs_transition_id_check CHECK (chat.is_uuid_v4(transition_id)),
    CONSTRAINT application_schedule_terminal_proofs_fingerprint_check CHECK (
        octet_length(outer_entry_fingerprint) = 32
    )
);

CREATE INDEX application_schedule_terminal_proofs_device_idx
    ON chat.application_schedule_terminal_proofs (recipient_did, recipient_device_id, conversation_id);

CREATE TABLE chat.entry_recipients (
    conversation_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    entitlement_kind TEXT NOT NULL,
    PRIMARY KEY (conversation_id, seq, user_did, device_id),
    CONSTRAINT entry_recipients_entry_fk FOREIGN KEY (conversation_id, seq)
        REFERENCES chat.entries(conversation_id, seq),
    CONSTRAINT entry_recipients_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT entry_recipients_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT entry_recipients_seq_check CHECK (chat.is_safe_integer(seq) AND seq >= 1),
    CONSTRAINT entry_recipients_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT entry_recipients_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT entry_recipients_kind_check CHECK (
        entitlement_kind IN ('control','intervalClose','scheduleTerminal')
    )
);

CREATE INDEX entry_recipients_device_scan_idx
    ON chat.entry_recipients (user_did, device_id, conversation_id, seq);

CREATE TABLE chat.welcome_bundles (
    welcome_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    transition_id UUID NOT NULL UNIQUE,
    entry_seq BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    state_version BIGINT NOT NULL,
    group_id BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    group_context_hash BYTEA NOT NULL,
    confirmation_tag BYTEA NOT NULL,
    wrapper_bytes BYTEA NOT NULL,
    wrapper_sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT welcome_bundles_entry_fk FOREIGN KEY (conversation_id, entry_seq)
        REFERENCES chat.entries(conversation_id, seq) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT welcome_bundles_transition_fk FOREIGN KEY (transition_id)
        REFERENCES chat.transitions(transition_id),
    CONSTRAINT welcome_bundles_provenance_fk FOREIGN KEY (
        conversation_id, entry_seq, transition_id
    ) REFERENCES chat.entries(conversation_id, seq, transition_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT welcome_bundles_state_fk FOREIGN KEY (
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag, transition_id
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag, producing_transition_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT welcome_bundles_welcome_id_check CHECK (chat.is_uuid_v4(welcome_id)),
    CONSTRAINT welcome_bundles_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT welcome_bundles_transition_id_check CHECK (chat.is_uuid_v4(transition_id)),
    CONSTRAINT welcome_bundles_entry_seq_check CHECK (chat.is_safe_integer(entry_seq) AND entry_seq >= 1),
    CONSTRAINT welcome_bundles_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT welcome_bundles_state_version_check CHECK (chat.is_safe_integer(state_version)),
    CONSTRAINT welcome_bundles_epoch_check CHECK (chat.is_safe_integer(epoch)),
    CONSTRAINT welcome_bundles_crypto_lengths_check CHECK (
        octet_length(group_id) = 32 AND octet_length(group_context_hash) = 32
        AND octet_length(confirmation_tag) = 32
    ),
    CONSTRAINT welcome_bundles_artifact_hash_check CHECK (
        octet_length(wrapper_bytes) BETWEEN 8 AND 1048576
        AND octet_length(wrapper_sha256) = 32
        AND wrapper_sha256 = digest(wrapper_bytes, 'sha256')
    )
);

CREATE TABLE chat.welcome_deliveries (
    welcome_id UUID PRIMARY KEY,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    recovery_request_id UUID NOT NULL UNIQUE,
    key_package_ref BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT welcome_deliveries_bundle_fk FOREIGN KEY (welcome_id)
        REFERENCES chat.welcome_bundles(welcome_id),
    CONSTRAINT welcome_deliveries_device_fk FOREIGN KEY (recipient_did, recipient_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT welcome_deliveries_request_fk FOREIGN KEY (recovery_request_id)
        REFERENCES chat.leaf_recovery_requests(recovery_request_id),
    CONSTRAINT welcome_deliveries_reservation_identity_fk
        FOREIGN KEY (
            recovery_request_id, key_package_ref, recipient_did, recipient_device_id
        )
        REFERENCES chat.key_package_reservations(
            recovery_request_id, key_package_ref, recipient_did, recipient_device_id
        ),
    CONSTRAINT welcome_deliveries_package_identity_fk
        FOREIGN KEY (key_package_ref, recipient_did, recipient_device_id, expires_at)
        REFERENCES chat.key_packages(
            key_package_ref, owner_did, owner_device_id, not_after
        ),
    CONSTRAINT welcome_deliveries_welcome_id_check CHECK (chat.is_uuid_v4(welcome_id)),
    CONSTRAINT welcome_deliveries_recipient_did_check CHECK (chat.is_bare_did(recipient_did)),
    CONSTRAINT welcome_deliveries_recipient_device_check CHECK (chat.is_uuid_v4(recipient_device_id)),
    CONSTRAINT welcome_deliveries_recovery_request_check CHECK (chat.is_uuid_v4(recovery_request_id)),
    CONSTRAINT welcome_deliveries_package_ref_check CHECK (octet_length(key_package_ref) = 32),
    CONSTRAINT welcome_deliveries_status_check CHECK (
        status IN ('pending','acknowledged','rejected','expired','superseded')
    ),
    CONSTRAINT welcome_deliveries_terminal_shape_check CHECK (
        (status = 'pending' AND terminal_at IS NULL)
        OR (status = 'expired' AND terminal_at = expires_at)
        OR (status IN ('acknowledged','rejected','superseded')
            AND terminal_at IS NOT NULL AND terminal_at <= expires_at)
    )
);

CREATE INDEX welcome_deliveries_pending_device_idx
    ON chat.welcome_deliveries (recipient_did, recipient_device_id, expires_at, welcome_id)
    WHERE status = 'pending';

CREATE INDEX welcome_deliveries_pending_global_expiry_idx
    ON chat.welcome_deliveries (expires_at, welcome_id)
    WHERE status = 'pending';

CREATE TABLE chat.welcome_dispositions (
    welcome_id UUID PRIMARY KEY,
    winner_kind TEXT NOT NULL,
    signed_request_bytes BYTEA,
    signing_transcript_bytes BYTEA,
    request_digest BYTEA,
    signature BYTEA,
    rejection_reason TEXT,
    terminal_at TIMESTAMPTZ NOT NULL,
    event_position BIGINT NOT NULL,
    CONSTRAINT welcome_dispositions_delivery_fk FOREIGN KEY (welcome_id)
        REFERENCES chat.welcome_deliveries(welcome_id),
    CONSTRAINT welcome_dispositions_welcome_id_check CHECK (chat.is_uuid_v4(welcome_id)),
    CONSTRAINT welcome_dispositions_winner_check CHECK (
        winner_kind IN ('acknowledged','rejected','expired','superseded')
    ),
    CONSTRAINT welcome_dispositions_signature_shape_check CHECK (
        (winner_kind IN ('acknowledged','rejected')
            AND signed_request_bytes IS NOT NULL AND signing_transcript_bytes IS NOT NULL
            AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
            AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
            AND octet_length(request_digest) = 32
            AND request_digest = digest(signing_transcript_bytes, 'sha256')
            AND octet_length(signature) = 64)
        OR (winner_kind IN ('expired','superseded')
            AND signed_request_bytes IS NULL AND signing_transcript_bytes IS NULL
            AND request_digest IS NULL AND signature IS NULL)
    ),
    CONSTRAINT welcome_dispositions_reason_check CHECK (
        (winner_kind = 'rejected' AND rejection_reason IS NOT NULL AND rejection_reason IN (
            'noMatchingKeyPackage','invalidWelcome','unsupportedCipherSuite',
            'coordinateMismatch','localStateConflict'
        ))
        OR (winner_kind <> 'rejected' AND rejection_reason IS NULL)
    ),
    CONSTRAINT welcome_dispositions_event_position_check CHECK (
        chat.is_safe_integer(event_position) AND event_position >= 1
    ),
    CONSTRAINT welcome_dispositions_event_position_uq UNIQUE (event_position)
);

CREATE TABLE chat.recovery_work_items (
    recovery_work_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    source_kind TEXT NOT NULL,
    source_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    state_version BIGINT NOT NULL,
    status TEXT NOT NULL,
    terminal_transition_id UUID,
    terminal_revocation_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT recovery_work_items_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT recovery_work_items_device_fk FOREIGN KEY (recipient_did, recipient_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT recovery_work_items_coordinate_fk
        FOREIGN KEY (conversation_id, generation, state_version)
        REFERENCES chat.generation_states(conversation_id, generation, state_version)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT recovery_work_items_source_fk FOREIGN KEY (source_id)
        REFERENCES chat.welcome_dispositions(welcome_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT recovery_work_items_terminal_transition_fk
        FOREIGN KEY (conversation_id, terminal_transition_id, terminal_at)
        REFERENCES chat.transitions(conversation_id, transition_id, accepted_at)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT recovery_work_items_terminal_revocation_fk
        FOREIGN KEY (recipient_did, recipient_device_id, terminal_revocation_id, terminal_at)
        REFERENCES chat.device_revocations(
            target_did, target_device_id, revocation_id, accepted_at
        ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT recovery_work_items_id_check CHECK (chat.is_uuid_v4(recovery_work_id)),
    CONSTRAINT recovery_work_items_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT recovery_work_items_recipient_did_check CHECK (chat.is_bare_did(recipient_did)),
    CONSTRAINT recovery_work_items_recipient_device_check CHECK (chat.is_uuid_v4(recipient_device_id)),
    CONSTRAINT recovery_work_items_source_id_check CHECK (chat.is_uuid_v4(source_id)),
    CONSTRAINT recovery_work_items_source_kind_check CHECK (
        source_kind IN ('welcomeExpired','welcomeRejected')
    ),
    CONSTRAINT recovery_work_items_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT recovery_work_items_state_version_check CHECK (chat.is_safe_integer(state_version)),
    CONSTRAINT recovery_work_items_status_check CHECK (status IN ('pending','completed','superseded')),
    CONSTRAINT recovery_work_items_terminal_transition_check CHECK (
        terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id)
    ),
    CONSTRAINT recovery_work_items_terminal_revocation_check CHECK (
        terminal_revocation_id IS NULL OR chat.is_uuid_v4(terminal_revocation_id)
    ),
    CONSTRAINT recovery_work_items_terminal_shape_check CHECK (
        (status = 'pending'
            AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NULL
            AND terminal_at IS NULL)
        OR (status = 'completed'
            AND terminal_transition_id IS NOT NULL
            AND terminal_revocation_id IS NULL
            AND terminal_at IS NOT NULL
            AND terminal_at >= created_at)
        OR (status = 'superseded'
            AND terminal_at IS NOT NULL
            AND terminal_at >= created_at
            AND num_nonnulls(terminal_transition_id, terminal_revocation_id) = 1)
    ),
    CONSTRAINT recovery_work_items_source_uq UNIQUE (source_id)
);

CREATE INDEX recovery_work_items_pending_device_idx
    ON chat.recovery_work_items (recipient_did, recipient_device_id, created_at, recovery_work_id)
    WHERE status = 'pending';

CREATE TABLE chat.events (
    event_position BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_kind TEXT NOT NULL,
    payload_bytes BYTEA NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    protocol_instance_id UUID NOT NULL,
    CONSTRAINT events_protocol_instance_fk FOREIGN KEY (protocol_instance_id)
        REFERENCES chat.protocol_instances(protocol_instance_id),
    CONSTRAINT events_position_check CHECK (
        chat.is_safe_integer(event_position) AND event_position >= 1
    ),
    CONSTRAINT events_event_id_check CHECK (chat.is_uuid_v4(event_id)),
    CONSTRAINT events_kind_check CHECK (event_kind IN (
        'conversationChanged','conversationClosed','messageAvailable','welcomeAvailable',
        'welcomeDisposition','resetRequested','leafRecovery','leaveRequest','accessEnded','watermark'
    )),
    CONSTRAINT events_payload_hash_check CHECK (
        octet_length(payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(payload_sha256) = 32
        AND payload_sha256 = digest(payload_bytes, 'sha256')
    ),
    CONSTRAINT events_protocol_instance_id_check CHECK (chat.is_uuid_v4(protocol_instance_id))
);

ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_event_fk
    FOREIGN KEY (event_position) REFERENCES chat.events(event_position)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.welcome_dispositions
    ADD CONSTRAINT welcome_dispositions_event_fk
    FOREIGN KEY (event_position) REFERENCES chat.events(event_position)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE chat.event_recipients (
    event_position BIGINT NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    entitlement_kind TEXT NOT NULL,
    audience_predecessor_position BIGINT,
    PRIMARY KEY (event_position, user_did, device_id),
    CONSTRAINT event_recipients_device_position_uq UNIQUE (
        user_did, device_id, event_position
    ),
    CONSTRAINT event_recipients_event_fk FOREIGN KEY (event_position)
        REFERENCES chat.events(event_position),
    CONSTRAINT event_recipients_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT event_recipients_predecessor_fk FOREIGN KEY (
        user_did, device_id, audience_predecessor_position
    ) REFERENCES chat.event_recipients(
        user_did, device_id, event_position
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT event_recipients_position_check CHECK (
        chat.is_safe_integer(event_position) AND event_position >= 1
    ),
    CONSTRAINT event_recipients_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT event_recipients_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT event_recipients_kind_check CHECK (
        entitlement_kind IN ('participant','leaf','welcome','recovery','historicalSchedule')
    ),
    CONSTRAINT event_recipients_predecessor_check CHECK (
        audience_predecessor_position IS NULL
        OR (chat.is_safe_integer(audience_predecessor_position)
            AND audience_predecessor_position < event_position)
    )
);

CREATE INDEX event_recipients_device_position_idx
    ON chat.event_recipients (user_did, device_id, event_position);

CREATE FUNCTION chat.assert_event_recipient_chain(target_did TEXT, target_device UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    recipient RECORD;
    predecessor BIGINT := NULL;
BEGIN
    PERFORM 1 FROM chat.devices
     WHERE user_did = target_did AND device_id = target_device
     FOR UPDATE;
    FOR recipient IN
        SELECT event_position, audience_predecessor_position
          FROM chat.event_recipients
         WHERE user_did = target_did AND device_id = target_device
         ORDER BY event_position
    LOOP
        IF recipient.audience_predecessor_position IS DISTINCT FROM predecessor THEN
            RAISE EXCEPTION 'event audience predecessor chain mismatch'
                USING ERRCODE = '23514';
        END IF;
        predecessor := recipient.event_position;
    END LOOP;
END
$$;

CREATE FUNCTION chat.enforce_event_recipient_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_event_recipient_chain(OLD.user_did, OLD.device_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR (NEW.user_did, NEW.device_id)
               IS DISTINCT FROM (OLD.user_did, OLD.device_id)) THEN
        PERFORM chat.assert_event_recipient_chain(NEW.user_did, NEW.device_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER event_recipients_chain_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.event_recipients
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_event_recipient_chain();

CREATE FUNCTION chat.assert_welcome_disposition_cas(target_welcome UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    delivery_row chat.welcome_deliveries%ROWTYPE;
    disposition_count BIGINT;
BEGIN
    SELECT * INTO delivery_row
      FROM chat.welcome_deliveries
     WHERE welcome_id = target_welcome;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.welcome_dispositions
             WHERE welcome_id = target_welcome
        ) THEN
            RAISE EXCEPTION 'Welcome disposition CAS mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1
      FROM chat.welcome_bundles bundle
      JOIN chat.conversations conversation
        ON conversation.conversation_id = bundle.conversation_id
     WHERE bundle.welcome_id = target_welcome
     FOR UPDATE OF conversation;
    SELECT count(*) INTO disposition_count
      FROM chat.welcome_dispositions
     WHERE welcome_id = target_welcome;

    IF delivery_row.status = 'pending' THEN
        IF disposition_count <> 0 THEN
            RAISE EXCEPTION 'pending Welcome has terminal disposition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF disposition_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM chat.welcome_dispositions disposition
          JOIN chat.events event
            ON event.event_position = disposition.event_position
         WHERE disposition.welcome_id = target_welcome
           AND disposition.winner_kind = delivery_row.status
           AND disposition.terminal_at = delivery_row.terminal_at
           AND event.event_kind = 'welcomeDisposition'
           AND event.created_at = delivery_row.terminal_at
           AND EXISTS (
                SELECT 1
                  FROM chat.event_recipients recipient
                 WHERE recipient.event_position = event.event_position
                   AND recipient.user_did = delivery_row.recipient_did
                   AND recipient.device_id = delivery_row.recipient_device_id
                   AND recipient.entitlement_kind = 'welcome'
           )
           AND EXISTS (
                SELECT 1
                  FROM chat.outbox work
                 WHERE work.event_position = event.event_position
                   AND work.work_kind = 'stream'
           )
    ) THEN
        RAISE EXCEPTION 'terminal Welcome disposition mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_welcome_disposition_cas()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_welcome_disposition_cas(OLD.welcome_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT' OR NEW.welcome_id IS DISTINCT FROM OLD.welcome_id) THEN
        PERFORM chat.assert_welcome_disposition_cas(NEW.welcome_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER welcome_deliveries_disposition_cas_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_deliveries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_disposition_cas();

CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_disposition_cas();

CREATE FUNCTION chat.assert_recovery_work_integrity(target_welcome UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    disposition_row RECORD;
    work_row chat.recovery_work_items%ROWTYPE;
    source_count BIGINT;
    exact_count BIGINT;
BEGIN
    SELECT disposition.winner_kind,
           disposition.terminal_at AS disposition_terminal_at,
           delivery.recipient_did,
           delivery.recipient_device_id,
           bundle.conversation_id,
           bundle.generation,
           bundle.state_version,
           bundle.group_id,
           bundle.epoch,
           bundle.group_context_hash,
           bundle.confirmation_tag
      INTO disposition_row
      FROM chat.welcome_dispositions disposition
      JOIN chat.welcome_deliveries delivery
        ON delivery.welcome_id = disposition.welcome_id
      JOIN chat.welcome_bundles bundle
        ON bundle.welcome_id = delivery.welcome_id
     WHERE disposition.welcome_id = target_welcome
     FOR UPDATE OF delivery;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.recovery_work_items work
             WHERE work.source_id = target_welcome
        ) THEN
            RAISE EXCEPTION 'recovery work has no Welcome disposition source'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT count(*) INTO source_count
      FROM chat.recovery_work_items work
     WHERE work.source_id = target_welcome;

    IF disposition_row.winner_kind IN ('expired','rejected') THEN
        SELECT count(*) INTO exact_count
          FROM chat.recovery_work_items work
          JOIN chat.generation_states state
            ON state.conversation_id = work.conversation_id
           AND state.generation = work.generation
           AND state.state_version = work.state_version
         WHERE work.source_id = target_welcome
           AND work.source_kind = CASE disposition_row.winner_kind
                WHEN 'expired' THEN 'welcomeExpired'
                ELSE 'welcomeRejected'
           END
           AND work.recipient_did = disposition_row.recipient_did
           AND work.recipient_device_id = disposition_row.recipient_device_id
           AND work.conversation_id = disposition_row.conversation_id
           AND work.generation = disposition_row.generation
           AND work.state_version = disposition_row.state_version
           AND state.group_id = disposition_row.group_id
           AND state.epoch = disposition_row.epoch
           AND state.group_context_hash = disposition_row.group_context_hash
           AND state.confirmation_tag = disposition_row.confirmation_tag
           AND work.created_at = disposition_row.disposition_terminal_at;
        IF source_count <> 1 OR exact_count <> 1 THEN
            RAISE EXCEPTION 'terminal Welcome recovery work mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF source_count <> 0 THEN
        RAISE EXCEPTION 'non-recovery Welcome disposition has recovery work'
            USING ERRCODE = '23514';
    ELSE
        RETURN;
    END IF;

    SELECT * INTO work_row
      FROM chat.recovery_work_items work
     WHERE work.source_id = target_welcome;
    IF work_row.status = 'pending' THEN RETURN; END IF;

    IF work_row.terminal_transition_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1 FROM chat.transitions transition
             WHERE transition.transition_id = work_row.terminal_transition_id
               AND transition.conversation_id = work_row.conversation_id
               AND transition.accepted_at = work_row.terminal_at
       ) THEN
        RAISE EXCEPTION 'recovery work terminal transition mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF work_row.status = 'superseded'
       AND work_row.terminal_transition_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1 FROM chat.transitions transition
             WHERE transition.transition_id = work_row.terminal_transition_id
               AND transition.conversation_id = work_row.conversation_id
               AND transition.accepted_at = work_row.terminal_at
               AND transition.prior_generation = work_row.generation
               AND transition.prior_state_version = work_row.state_version
               AND (transition.next_generation, transition.next_state_version)
                   IS DISTINCT FROM (work_row.generation, work_row.state_version)
       ) THEN
        RAISE EXCEPTION 'recovery work superseding transition does not invalidate source coordinate'
            USING ERRCODE = '23514';
    END IF;

    IF work_row.terminal_revocation_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1 FROM chat.device_revocations revocation
             WHERE revocation.revocation_id = work_row.terminal_revocation_id
               AND revocation.target_did = work_row.recipient_did
               AND revocation.target_device_id = work_row.recipient_device_id
               AND revocation.accepted_at = work_row.terminal_at
       ) THEN
        RAISE EXCEPTION 'recovery work terminal revocation mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF work_row.status = 'completed' AND NOT EXISTS (
        SELECT 1
          FROM chat.leaf_recovery_requests request
          JOIN chat.transitions transition
            ON transition.transition_id = request.fulfilling_transition_id
         WHERE request.conversation_id = work_row.conversation_id
           AND request.requester_did = work_row.recipient_did
           AND request.requester_device_id = work_row.recipient_device_id
           AND request.source = 'requestLeafRecovery'
           AND request.status = 'fulfilled'
           AND request.fulfilling_transition_id = work_row.terminal_transition_id
           AND request.terminal_at = work_row.terminal_at
           AND request.requested_at >= work_row.created_at
           AND transition.kind = 'leafRecovery'
           AND transition.conversation_id = work_row.conversation_id
           AND transition.accepted_at = work_row.terminal_at
    ) THEN
        RAISE EXCEPTION 'completed recovery work has no matching leaf recovery fulfillment'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_recovery_work_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'welcome_dispositions' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_recovery_work_integrity(OLD.welcome_id);
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT' OR NEW.welcome_id IS DISTINCT FROM OLD.welcome_id) THEN
            PERFORM chat.assert_recovery_work_integrity(NEW.welcome_id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_recovery_work_integrity(OLD.source_id);
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT' OR NEW.source_id IS DISTINCT FROM OLD.source_id) THEN
            PERFORM chat.assert_recovery_work_integrity(NEW.source_id);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_recovery_work_integrity();

CREATE CONSTRAINT TRIGGER recovery_work_items_integrity_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.recovery_work_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_recovery_work_integrity();

CREATE TABLE chat.outbox (
    outbox_id UUID PRIMARY KEY,
    event_position BIGINT NOT NULL,
    work_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count BIGINT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT outbox_event_fk FOREIGN KEY (event_position) REFERENCES chat.events(event_position),
    CONSTRAINT outbox_event_work_uq UNIQUE (event_position, work_kind),
    CONSTRAINT outbox_id_check CHECK (chat.is_uuid_v4(outbox_id)),
    CONSTRAINT outbox_event_position_check CHECK (
        chat.is_safe_integer(event_position) AND event_position >= 1
    ),
    CONSTRAINT outbox_kind_check CHECK (work_kind IN ('stream','notification','recovery')),
    CONSTRAINT outbox_status_check CHECK (status IN ('pending','leased','delivered','failed')),
    CONSTRAINT outbox_attempt_count_check CHECK (chat.is_safe_integer(attempt_count)),
    CONSTRAINT outbox_lease_owner_check CHECK (lease_owner IS NULL OR chat.is_uuid_v4(lease_owner)),
    CONSTRAINT outbox_status_shape_check CHECK (
        (status = 'pending' AND lease_owner IS NULL AND lease_expires_at IS NULL AND delivered_at IS NULL)
        OR (status = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND delivered_at IS NULL)
        OR (status = 'delivered' AND delivered_at IS NOT NULL)
        OR (status = 'failed' AND delivered_at IS NULL)
    )
);

CREATE INDEX outbox_claim_order_idx
    ON chat.outbox (event_position, next_attempt_at)
    WHERE status = 'pending';

CREATE INDEX outbox_expired_lease_reclaim_idx
    ON chat.outbox (lease_expires_at, event_position)
    WHERE status = 'leased';

CREATE TABLE chat.event_retention (
    protocol_instance_id UUID PRIMARY KEY,
    retained_floor BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT event_retention_instance_fk FOREIGN KEY (protocol_instance_id)
        REFERENCES chat.protocol_instances(protocol_instance_id),
    CONSTRAINT event_retention_instance_id_check CHECK (chat.is_uuid_v4(protocol_instance_id)),
    CONSTRAINT event_retention_floor_check CHECK (chat.is_safe_integer(retained_floor))
);

CREATE TABLE chat.inventory_sessions (
    inventory_session_id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    snapshot_event_position BIGINT NOT NULL,
    snapshot_event_cursor_bytes BYTEA NOT NULL,
    snapshot_event_cursor_sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    conversations_complete BOOLEAN NOT NULL DEFAULT FALSE,
    welcomes_complete BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_complete BOOLEAN NOT NULL DEFAULT FALSE,
    conversation_item_count BIGINT,
    conversation_items_sha256 BYTEA,
    welcome_item_count BIGINT,
    welcome_items_sha256 BYTEA,
    recovery_item_count BIGINT,
    recovery_items_sha256 BYTEA,
    CONSTRAINT inventory_sessions_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT inventory_sessions_id_check CHECK (chat.is_uuid_v4(inventory_session_id)),
    CONSTRAINT inventory_sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT inventory_sessions_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT inventory_sessions_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT inventory_sessions_jkt_check CHECK (chat.is_base64url_sha256(jkt)),
    CONSTRAINT inventory_sessions_auth_generation_check CHECK (
        chat.is_safe_integer(auth_generation) AND auth_generation >= 1
    ),
    CONSTRAINT inventory_sessions_event_position_check CHECK (
        chat.is_safe_integer(snapshot_event_position)
    ),
    CONSTRAINT inventory_sessions_cursor_hash_check CHECK (
        octet_length(snapshot_event_cursor_bytes) BETWEEN 1 AND 512
        AND octet_length(snapshot_event_cursor_sha256) = 32
        AND snapshot_event_cursor_sha256 = digest(snapshot_event_cursor_bytes, 'sha256')
    ),
    CONSTRAINT inventory_sessions_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT inventory_sessions_completion_evidence_check CHECK (
        ((NOT conversations_complete AND conversation_item_count IS NULL
            AND conversation_items_sha256 IS NULL)
         OR (conversations_complete AND chat.is_safe_integer(conversation_item_count)
            AND conversation_item_count IS NOT NULL
            AND conversation_items_sha256 IS NOT NULL
            AND octet_length(conversation_items_sha256) = 32))
        AND ((NOT welcomes_complete AND welcome_item_count IS NULL
            AND welcome_items_sha256 IS NULL)
         OR (welcomes_complete AND chat.is_safe_integer(welcome_item_count)
            AND welcome_item_count IS NOT NULL
            AND welcome_items_sha256 IS NOT NULL
            AND octet_length(welcome_items_sha256) = 32))
        AND ((NOT recovery_complete AND recovery_item_count IS NULL
            AND recovery_items_sha256 IS NULL)
         OR (recovery_complete AND chat.is_safe_integer(recovery_item_count)
            AND recovery_item_count IS NOT NULL
            AND recovery_items_sha256 IS NOT NULL
            AND octet_length(recovery_items_sha256) = 32))
    ),
    CONSTRAINT inventory_sessions_ticket_identity_uq UNIQUE (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        snapshot_event_position, snapshot_event_cursor_bytes,
        snapshot_event_cursor_sha256
    )
);

CREATE TABLE chat.inventory_conversation_items (
    inventory_session_id UUID NOT NULL,
    ordinal BIGINT NOT NULL,
    conversation_id UUID NOT NULL,
    item_key_bytes BYTEA NOT NULL,
    payload_bytes BYTEA NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    PRIMARY KEY (inventory_session_id, ordinal),
    CONSTRAINT inventory_conversation_items_session_fk FOREIGN KEY (inventory_session_id)
        REFERENCES chat.inventory_sessions(inventory_session_id),
    CONSTRAINT inventory_conversation_items_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT inventory_conversation_items_session_id_check CHECK (chat.is_uuid_v4(inventory_session_id)),
    CONSTRAINT inventory_conversation_items_ordinal_check CHECK (chat.is_safe_integer(ordinal)),
    CONSTRAINT inventory_conversation_items_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT inventory_conversation_items_payload_hash_check CHECK (
        octet_length(item_key_bytes) = 16
        AND item_key_bytes = uuid_send(conversation_id)
        AND octet_length(payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(payload_sha256) = 32 AND payload_sha256 = digest(payload_bytes, 'sha256')
    ),
    CONSTRAINT inventory_conversation_items_conversation_uq UNIQUE (
        inventory_session_id, conversation_id
    ),
    CONSTRAINT inventory_conversation_items_key_uq UNIQUE (
        inventory_session_id, item_key_bytes
    )
);

CREATE TABLE chat.inventory_welcome_items (
    inventory_session_id UUID NOT NULL,
    ordinal BIGINT NOT NULL,
    welcome_id UUID NOT NULL,
    item_key_bytes BYTEA NOT NULL,
    payload_bytes BYTEA NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    PRIMARY KEY (inventory_session_id, ordinal),
    CONSTRAINT inventory_welcome_items_session_fk FOREIGN KEY (inventory_session_id)
        REFERENCES chat.inventory_sessions(inventory_session_id),
    CONSTRAINT inventory_welcome_items_welcome_fk FOREIGN KEY (welcome_id)
        REFERENCES chat.welcome_deliveries(welcome_id),
    CONSTRAINT inventory_welcome_items_session_id_check CHECK (chat.is_uuid_v4(inventory_session_id)),
    CONSTRAINT inventory_welcome_items_ordinal_check CHECK (chat.is_safe_integer(ordinal)),
    CONSTRAINT inventory_welcome_items_welcome_id_check CHECK (chat.is_uuid_v4(welcome_id)),
    CONSTRAINT inventory_welcome_items_payload_hash_check CHECK (
        octet_length(item_key_bytes) = 16
        AND item_key_bytes = uuid_send(welcome_id)
        AND octet_length(payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(payload_sha256) = 32 AND payload_sha256 = digest(payload_bytes, 'sha256')
    ),
    CONSTRAINT inventory_welcome_items_welcome_uq UNIQUE (
        inventory_session_id, welcome_id
    ),
    CONSTRAINT inventory_welcome_items_key_uq UNIQUE (
        inventory_session_id, item_key_bytes
    )
);

CREATE TABLE chat.inventory_recovery_items (
    inventory_session_id UUID NOT NULL,
    ordinal BIGINT NOT NULL,
    item_kind TEXT NOT NULL,
    leaf_recovery_request_id UUID,
    recovery_work_id UUID,
    item_key_bytes BYTEA NOT NULL,
    payload_bytes BYTEA NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    PRIMARY KEY (inventory_session_id, ordinal),
    CONSTRAINT inventory_recovery_items_session_fk FOREIGN KEY (inventory_session_id)
        REFERENCES chat.inventory_sessions(inventory_session_id),
    CONSTRAINT inventory_recovery_items_request_fk FOREIGN KEY (leaf_recovery_request_id)
        REFERENCES chat.leaf_recovery_requests(recovery_request_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inventory_recovery_items_work_fk FOREIGN KEY (recovery_work_id)
        REFERENCES chat.recovery_work_items(recovery_work_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inventory_recovery_items_session_id_check CHECK (chat.is_uuid_v4(inventory_session_id)),
    CONSTRAINT inventory_recovery_items_ordinal_check CHECK (chat.is_safe_integer(ordinal)),
    CONSTRAINT inventory_recovery_items_kind_check CHECK (
        item_kind IN ('leafRecoveryRequest','recoveryWork')
    ),
    CONSTRAINT inventory_recovery_items_request_id_check CHECK (
        leaf_recovery_request_id IS NULL OR chat.is_uuid_v4(leaf_recovery_request_id)
    ),
    CONSTRAINT inventory_recovery_items_work_id_check CHECK (
        recovery_work_id IS NULL OR chat.is_uuid_v4(recovery_work_id)
    ),
    CONSTRAINT inventory_recovery_items_identity_check CHECK (
        (item_kind = 'leafRecoveryRequest'
            AND leaf_recovery_request_id IS NOT NULL
            AND recovery_work_id IS NULL
            AND octet_length(item_key_bytes) = 17
            AND item_key_bytes
                = decode('00', 'hex') || uuid_send(leaf_recovery_request_id))
        OR (item_kind = 'recoveryWork'
            AND leaf_recovery_request_id IS NULL
            AND recovery_work_id IS NOT NULL
            AND octet_length(item_key_bytes) = 17
            AND item_key_bytes
                = decode('01', 'hex') || uuid_send(recovery_work_id))
    ),
    CONSTRAINT inventory_recovery_items_payload_hash_check CHECK (
        octet_length(payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(payload_sha256) = 32 AND payload_sha256 = digest(payload_bytes, 'sha256')
    ),
    CONSTRAINT inventory_recovery_items_request_uq
        UNIQUE (inventory_session_id, leaf_recovery_request_id),
    CONSTRAINT inventory_recovery_items_work_uq
        UNIQUE (inventory_session_id, recovery_work_id),
    CONSTRAINT inventory_recovery_items_key_uq UNIQUE (
        inventory_session_id, item_key_bytes
    )
);

CREATE TABLE chat.device_inventory_sessions (
    device_inventory_session_id UUID PRIMARY KEY,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    fence_revision BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    complete BOOLEAN NOT NULL DEFAULT FALSE,
    item_count BIGINT,
    items_sha256 BYTEA,
    CONSTRAINT device_inventory_sessions_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT device_inventory_sessions_id_check CHECK (chat.is_uuid_v4(device_inventory_session_id)),
    CONSTRAINT device_inventory_sessions_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT device_inventory_sessions_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT device_inventory_sessions_jkt_check CHECK (chat.is_base64url_sha256(jkt)),
    CONSTRAINT device_inventory_sessions_auth_generation_check CHECK (
        chat.is_safe_integer(auth_generation) AND auth_generation >= 1
    ),
    CONSTRAINT device_inventory_sessions_fence_revision_check CHECK (chat.is_safe_integer(fence_revision)),
    CONSTRAINT device_inventory_sessions_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT device_inventory_sessions_completion_evidence_check CHECK (
        (NOT complete AND item_count IS NULL AND items_sha256 IS NULL)
        OR (complete AND item_count IS NOT NULL AND chat.is_safe_integer(item_count)
            AND items_sha256 IS NOT NULL AND octet_length(items_sha256) = 32)
    )
);

CREATE TABLE chat.device_inventory_items (
    device_inventory_session_id UUID NOT NULL,
    ordinal BIGINT NOT NULL,
    subject_device_id UUID NOT NULL,
    payload_bytes BYTEA NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    PRIMARY KEY (device_inventory_session_id, ordinal),
    CONSTRAINT device_inventory_items_session_fk FOREIGN KEY (device_inventory_session_id)
        REFERENCES chat.device_inventory_sessions(device_inventory_session_id),
    CONSTRAINT device_inventory_items_session_id_check CHECK (chat.is_uuid_v4(device_inventory_session_id)),
    CONSTRAINT device_inventory_items_ordinal_check CHECK (chat.is_safe_integer(ordinal)),
    CONSTRAINT device_inventory_items_subject_device_check CHECK (chat.is_uuid_v4(subject_device_id)),
    CONSTRAINT device_inventory_items_payload_hash_check CHECK (
        octet_length(payload_bytes) BETWEEN 1 AND 16777216
        AND octet_length(payload_sha256) = 32 AND payload_sha256 = digest(payload_bytes, 'sha256')
    ),
    CONSTRAINT device_inventory_items_subject_uq UNIQUE (
        device_inventory_session_id, subject_device_id
    )
);

CREATE TABLE chat.subscription_tickets (
    ticket_hash BYTEA PRIMARY KEY,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    inventory_session_id UUID NOT NULL,
    event_position BIGINT NOT NULL,
    event_cursor_bytes BYTEA NOT NULL,
    event_cursor_sha256 BYTEA NOT NULL,
    subscription_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT subscription_tickets_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT subscription_tickets_inventory_fk FOREIGN KEY (inventory_session_id)
        REFERENCES chat.inventory_sessions(inventory_session_id),
    CONSTRAINT subscription_tickets_inventory_identity_fk FOREIGN KEY (
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        event_position, event_cursor_bytes, event_cursor_sha256
    ) REFERENCES chat.inventory_sessions(
        inventory_session_id, user_did, device_id, jkt, auth_generation,
        snapshot_event_position, snapshot_event_cursor_bytes,
        snapshot_event_cursor_sha256
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT subscription_tickets_hash_check CHECK (octet_length(ticket_hash) = 32),
    CONSTRAINT subscription_tickets_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT subscription_tickets_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT subscription_tickets_jkt_check CHECK (chat.is_base64url_sha256(jkt)),
    CONSTRAINT subscription_tickets_auth_generation_check CHECK (
        chat.is_safe_integer(auth_generation) AND auth_generation >= 1
    ),
    CONSTRAINT subscription_tickets_inventory_session_id_check CHECK (chat.is_uuid_v4(inventory_session_id)),
    CONSTRAINT subscription_tickets_event_position_check CHECK (chat.is_safe_integer(event_position)),
    CONSTRAINT subscription_tickets_cursor_hash_check CHECK (
        octet_length(event_cursor_bytes) BETWEEN 1 AND 512
        AND octet_length(event_cursor_sha256) = 32
        AND event_cursor_sha256 = digest(event_cursor_bytes, 'sha256')
    ),
    CONSTRAINT subscription_tickets_path_check CHECK (
        subscription_path = '/xrpc/blue.catbird.chat.subscribeEvents'
    ),
    CONSTRAINT subscription_tickets_expiry_check CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '60 seconds'
    ),
    CONSTRAINT subscription_tickets_consumption_check CHECK (
        consumed_at IS NULL OR consumed_at BETWEEN created_at AND expires_at
    )
);

CREATE FUNCTION chat.assert_inventory_session_identity(target_session UUID)
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
           AND device.dpop_jkt = session_row.jkt
           AND device.auth_generation = session_row.auth_generation
           AND device.created_at <= session_row.created_at
           AND device.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'inventory session authentication identity mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_inventory_session_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        PERFORM chat.assert_inventory_session_identity(NEW.inventory_session_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER inventory_sessions_auth_identity_deferred
AFTER INSERT OR UPDATE ON chat.inventory_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_session_identity();

CREATE FUNCTION chat.assert_subscription_ticket_binding(target_ticket BYTEA)
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
    IF NOT FOUND
       OR NOT session_row.conversations_complete
       OR NOT session_row.welcomes_complete
       OR NOT session_row.recovery_complete
       OR ticket_row.user_did <> session_row.user_did
       OR ticket_row.device_id <> session_row.device_id
       OR ticket_row.jkt <> session_row.jkt
       OR ticket_row.auth_generation <> session_row.auth_generation
       OR ticket_row.event_position <> session_row.snapshot_event_position
       OR ticket_row.event_cursor_bytes <> session_row.snapshot_event_cursor_bytes
       OR ticket_row.event_cursor_sha256 <> session_row.snapshot_event_cursor_sha256
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

CREATE FUNCTION chat.enforce_subscription_ticket_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_ticket BYTEA;
BEGIN
    IF TG_TABLE_NAME = 'subscription_tickets' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_subscription_ticket_binding(OLD.ticket_hash);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_subscription_ticket_binding(NEW.ticket_hash);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            FOR linked_ticket IN
                SELECT ticket_hash FROM chat.subscription_tickets
                 WHERE inventory_session_id = OLD.inventory_session_id
            LOOP
                PERFORM chat.assert_subscription_ticket_binding(linked_ticket);
            END LOOP;
        END IF;
        IF TG_OP <> 'DELETE' THEN
            FOR linked_ticket IN
                SELECT ticket_hash FROM chat.subscription_tickets
                 WHERE inventory_session_id = NEW.inventory_session_id
            LOOP
                PERFORM chat.assert_subscription_ticket_binding(linked_ticket);
            END LOOP;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER subscription_tickets_inventory_binding_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.subscription_tickets
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_subscription_ticket_binding();

CREATE CONSTRAINT TRIGGER inventory_sessions_ticket_binding_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.inventory_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_subscription_ticket_binding();

CREATE FUNCTION chat.assert_device_inventory_item_principal(
    target_session UUID,
    target_device UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chat.device_inventory_items item
          JOIN chat.device_inventory_sessions session
            ON session.device_inventory_session_id = item.device_inventory_session_id
         WHERE item.device_inventory_session_id = target_session
           AND item.subject_device_id = target_device
           AND NOT EXISTS (
                SELECT 1 FROM chat.devices device
                 WHERE device.user_did = session.user_did
                   AND device.device_id = item.subject_device_id
           )
    ) THEN
        RAISE EXCEPTION 'device inventory item crosses principal boundary'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_device_inventory_item_principal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_device_inventory_item_principal(
            OLD.device_inventory_session_id, OLD.subject_device_id
        );
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM chat.assert_device_inventory_item_principal(
            NEW.device_inventory_session_id, NEW.subject_device_id
        );
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER device_inventory_items_principal_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.device_inventory_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_inventory_item_principal();

CREATE FUNCTION chat.assert_inventory_materialization(target_session UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    session_row chat.inventory_sessions%ROWTYPE;
    row_count BIGINT;
    minimum_ordinal BIGINT;
    maximum_ordinal BIGINT;
    rows_digest BYTEA;
BEGIN
    SELECT * INTO session_row
      FROM chat.inventory_sessions
     WHERE inventory_session_id = target_session
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           digest(COALESCE(string_agg(
               int8send(ordinal) || uuid_send(conversation_id)
               || item_key_bytes || payload_sha256,
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO row_count, minimum_ordinal, maximum_ordinal, rows_digest
      FROM chat.inventory_conversation_items
     WHERE inventory_session_id = target_session;
    IF (row_count > 0 AND (minimum_ordinal <> 0 OR maximum_ordinal <> row_count - 1))
       OR (session_row.conversations_complete AND (
            session_row.conversation_item_count IS DISTINCT FROM row_count
            OR session_row.conversation_items_sha256 IS DISTINCT FROM rows_digest
       )) THEN
        RAISE EXCEPTION 'conversation inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           digest(COALESCE(string_agg(
               int8send(ordinal) || uuid_send(welcome_id)
               || item_key_bytes || payload_sha256,
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO row_count, minimum_ordinal, maximum_ordinal, rows_digest
      FROM chat.inventory_welcome_items
     WHERE inventory_session_id = target_session;
    IF (row_count > 0 AND (minimum_ordinal <> 0 OR maximum_ordinal <> row_count - 1))
       OR (session_row.welcomes_complete AND (
            session_row.welcome_item_count IS DISTINCT FROM row_count
            OR session_row.welcome_items_sha256 IS DISTINCT FROM rows_digest
       )) THEN
        RAISE EXCEPTION 'Welcome inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           digest(COALESCE(string_agg(
               int8send(ordinal) || item_key_bytes || payload_sha256,
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO row_count, minimum_ordinal, maximum_ordinal, rows_digest
      FROM chat.inventory_recovery_items
     WHERE inventory_session_id = target_session;
    IF (row_count > 0 AND (minimum_ordinal <> 0 OR maximum_ordinal <> row_count - 1))
       OR (session_row.recovery_complete AND (
            session_row.recovery_item_count IS DISTINCT FROM row_count
            OR session_row.recovery_items_sha256 IS DISTINCT FROM rows_digest
       )) THEN
        RAISE EXCEPTION 'recovery inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_inventory_materialization()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_inventory_materialization(OLD.inventory_session_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.inventory_session_id IS DISTINCT FROM OLD.inventory_session_id) THEN
        PERFORM chat.assert_inventory_materialization(NEW.inventory_session_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER inventory_sessions_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.inventory_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_materialization();

CREATE CONSTRAINT TRIGGER inventory_conversation_items_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.inventory_conversation_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_materialization();

CREATE CONSTRAINT TRIGGER inventory_welcome_items_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.inventory_welcome_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_materialization();

CREATE CONSTRAINT TRIGGER inventory_recovery_items_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.inventory_recovery_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_inventory_materialization();

CREATE FUNCTION chat.assert_device_inventory_materialization(target_session UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    session_row chat.device_inventory_sessions%ROWTYPE;
    row_count BIGINT;
    minimum_ordinal BIGINT;
    maximum_ordinal BIGINT;
    rows_digest BYTEA;
BEGIN
    SELECT * INTO session_row
      FROM chat.device_inventory_sessions
     WHERE device_inventory_session_id = target_session
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT count(*), min(ordinal), max(ordinal),
           digest(COALESCE(string_agg(
               int8send(ordinal) || uuid_send(subject_device_id) || payload_sha256,
               decode('', 'hex') ORDER BY ordinal
           ), decode('', 'hex')), 'sha256')
      INTO row_count, minimum_ordinal, maximum_ordinal, rows_digest
      FROM chat.device_inventory_items
     WHERE device_inventory_session_id = target_session;
    IF (row_count > 0 AND (minimum_ordinal <> 0 OR maximum_ordinal <> row_count - 1))
       OR (session_row.complete AND (
            session_row.item_count IS DISTINCT FROM row_count
            OR session_row.items_sha256 IS DISTINCT FROM rows_digest
       )) THEN
        RAISE EXCEPTION 'device inventory materialization mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_device_inventory_materialization()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'device_inventory_sessions' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_device_inventory_materialization(
                OLD.device_inventory_session_id
            );
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_device_inventory_materialization(
                NEW.device_inventory_session_id
            );
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_device_inventory_materialization(
                OLD.device_inventory_session_id
            );
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT'
                OR NEW.device_inventory_session_id
                   IS DISTINCT FROM OLD.device_inventory_session_id) THEN
            PERFORM chat.assert_device_inventory_materialization(
                NEW.device_inventory_session_id
            );
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER device_inventory_sessions_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.device_inventory_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_inventory_materialization();

CREATE CONSTRAINT TRIGGER device_inventory_items_materialization_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.device_inventory_items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_inventory_materialization();

CREATE FUNCTION chat.assert_welcome_mapping(target_welcome UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    bundle_conversation UUID;
BEGIN
    SELECT conversation_id INTO bundle_conversation
      FROM chat.welcome_bundles
     WHERE welcome_id = target_welcome;
    IF NOT FOUND THEN
        IF EXISTS (SELECT 1 FROM chat.welcome_deliveries WHERE welcome_id = target_welcome) THEN
            RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = bundle_conversation
     FOR UPDATE;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.welcome_bundles bundle
          JOIN chat.welcome_deliveries delivery
            ON delivery.welcome_id = bundle.welcome_id
          JOIN chat.leaf_recovery_requests request
            ON request.recovery_request_id = delivery.recovery_request_id
          JOIN chat.key_package_reservations reservation
            ON reservation.recovery_request_id = request.recovery_request_id
           AND reservation.key_package_ref = delivery.key_package_ref
           AND reservation.recipient_did = delivery.recipient_did
           AND reservation.recipient_device_id = delivery.recipient_device_id
          JOIN chat.key_packages package
            ON package.key_package_ref = delivery.key_package_ref
           AND package.owner_did = delivery.recipient_did
           AND package.owner_device_id = delivery.recipient_device_id
          JOIN chat.transitions transition
            ON transition.transition_id = bundle.transition_id
           AND transition.conversation_id = bundle.conversation_id
           AND transition.entry_seq = bundle.entry_seq
          JOIN chat.entries entry
            ON entry.conversation_id = transition.conversation_id
           AND entry.seq = transition.entry_seq
           AND entry.transition_id = transition.transition_id
         WHERE bundle.welcome_id = target_welcome
           AND transition.kind = 'leafRecovery'
           AND entry.entry_kind = 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry'
           AND request.conversation_id = bundle.conversation_id
           AND request.generation = transition.prior_generation
           AND request.bound_state_version = transition.prior_state_version
           AND request.status = 'fulfilled'
           AND request.fulfilling_transition_id = bundle.transition_id
           AND request.terminal_at = transition.accepted_at
           AND transition.accepted_at < request.expires_at
           AND request.requester_did = delivery.recipient_did
           AND request.requester_device_id = delivery.recipient_device_id
           AND reservation.conversation_id = request.conversation_id
           AND reservation.generation = request.generation
           AND reservation.requester_did = request.requester_did
           AND reservation.requester_device_id = request.requester_device_id
           AND reservation.requester_key_id = request.requester_key_id
           AND reservation.requester_auth_generation = request.requester_auth_generation
           AND reservation.bound_state_version = request.bound_state_version
           AND reservation.bound_group_id = request.bound_group_id
           AND reservation.bound_epoch = request.bound_epoch
           AND reservation.bound_group_context_hash = request.bound_group_context_hash
           AND reservation.bound_confirmation_tag = request.bound_confirmation_tag
           AND reservation.expires_at = request.expires_at
           AND reservation.status = 'consumed'
           AND reservation.consumed_transition_id = bundle.transition_id
           AND reservation.terminal_at = transition.accepted_at
           AND package.status = 'consumed'
           AND package.terminal_transition_id = bundle.transition_id
           AND package.terminal_at = transition.accepted_at
           AND transition.accepted_at < package.not_after
           AND delivery.expires_at = package.not_after
           AND bundle.created_at = transition.accepted_at
           AND bundle.generation = transition.next_generation
           AND bundle.state_version = transition.next_state_version
    ) THEN
        RAISE EXCEPTION 'Welcome recovery fulfillment mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.assert_recovery_fulfillment_mapping(target_request UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
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
$$;

CREATE FUNCTION chat.assert_key_package_reservation_mapping(target_package BYTEA)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    package_row chat.key_packages%ROWTYPE;
    active_count BIGINT;
    consumed_count BIGINT;
BEGIN
    SELECT * INTO package_row
      FROM chat.key_packages
     WHERE key_package_ref = target_package;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM 1 FROM chat.principals
     WHERE user_did = package_row.owner_did
     FOR UPDATE;
    SELECT count(*) FILTER (WHERE status = 'active'),
           count(*) FILTER (
               WHERE status = 'consumed'
                 AND consumed_transition_id = package_row.terminal_transition_id
           )
      INTO active_count, consumed_count
      FROM chat.key_package_reservations
     WHERE key_package_ref = target_package;

    IF package_row.status = 'reserved' AND active_count <> 1 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch'
            USING ERRCODE = '23514';
    ELSIF package_row.status = 'consumed' AND consumed_count <> 1 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch'
            USING ERRCODE = '23514';
    ELSIF package_row.status NOT IN ('reserved','consumed') AND active_count <> 0 THEN
        RAISE EXCEPTION 'key package reservation mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_welcome_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_welcome UUID;
BEGIN
    IF TG_TABLE_NAME IN ('welcome_bundles','welcome_deliveries') THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_welcome_mapping(OLD.welcome_id);
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT' OR NEW.welcome_id IS DISTINCT FROM OLD.welcome_id) THEN
            PERFORM chat.assert_welcome_mapping(NEW.welcome_id);
        END IF;
    ELSIF TG_TABLE_NAME IN ('leaf_recovery_requests','key_package_reservations') THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_recovery_fulfillment_mapping(OLD.recovery_request_id);
            IF TG_TABLE_NAME = 'key_package_reservations' THEN
                PERFORM chat.assert_key_package_reservation_mapping(OLD.key_package_ref);
            END IF;
            FOR linked_welcome IN
                SELECT welcome_id FROM chat.welcome_deliveries
                 WHERE recovery_request_id = OLD.recovery_request_id
            LOOP
                PERFORM chat.assert_welcome_mapping(linked_welcome);
            END LOOP;
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT'
                OR NEW.recovery_request_id IS DISTINCT FROM OLD.recovery_request_id) THEN
            PERFORM chat.assert_recovery_fulfillment_mapping(NEW.recovery_request_id);
            IF TG_TABLE_NAME = 'key_package_reservations' THEN
                PERFORM chat.assert_key_package_reservation_mapping(NEW.key_package_ref);
            END IF;
            FOR linked_welcome IN
                SELECT welcome_id FROM chat.welcome_deliveries
                 WHERE recovery_request_id = NEW.recovery_request_id
            LOOP
                PERFORM chat.assert_welcome_mapping(linked_welcome);
            END LOOP;
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_key_package_reservation_mapping(OLD.key_package_ref);
            FOR linked_welcome IN
                SELECT welcome_id FROM chat.welcome_deliveries
                 WHERE key_package_ref = OLD.key_package_ref
            LOOP
                PERFORM chat.assert_welcome_mapping(linked_welcome);
            END LOOP;
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT'
                OR NEW.key_package_ref IS DISTINCT FROM OLD.key_package_ref) THEN
            PERFORM chat.assert_key_package_reservation_mapping(NEW.key_package_ref);
            FOR linked_welcome IN
                SELECT welcome_id FROM chat.welcome_deliveries
                 WHERE key_package_ref = NEW.key_package_ref
            LOOP
                PERFORM chat.assert_welcome_mapping(linked_welcome);
            END LOOP;
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER welcome_bundles_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_bundles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

CREATE CONSTRAINT TRIGGER welcome_deliveries_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_deliveries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

CREATE CONSTRAINT TRIGGER leaf_recovery_requests_welcome_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.leaf_recovery_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

CREATE CONSTRAINT TRIGGER key_package_reservations_welcome_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.key_package_reservations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

CREATE CONSTRAINT TRIGGER key_packages_welcome_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.key_packages
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_mapping();

CREATE FUNCTION chat.assert_application_interval_provenance(target_interval UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    interval_row chat.application_intervals%ROWTYPE;
BEGIN
    SELECT * INTO interval_row
      FROM chat.application_intervals
     WHERE membership_interval_id = target_interval;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = interval_row.conversation_id
     FOR UPDATE;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.transitions transition
          JOIN chat.entries entry
            ON entry.conversation_id = transition.conversation_id
           AND entry.seq = transition.entry_seq
           AND entry.transition_id = transition.transition_id
          JOIN chat.generation_states state
            ON state.conversation_id = interval_row.conversation_id
           AND state.generation = interval_row.generation
           AND state.state_version = interval_row.opening_state_version
           AND state.group_id = interval_row.opening_group_id
           AND state.epoch = interval_row.opening_epoch
           AND state.group_context_hash = interval_row.opening_group_context_hash
           AND state.confirmation_tag = interval_row.opening_confirmation_tag
           AND state.producing_transition_id = interval_row.opening_transition_id
         WHERE transition.transition_id = interval_row.opening_transition_id
           AND transition.conversation_id = interval_row.conversation_id
           AND transition.entry_seq = interval_row.start_seq
           AND entry.outer_entry_fingerprint = interval_row.opening_outer_entry_fingerprint
           AND (
                (interval_row.opening_kind = 'creation'
                 AND transition.kind = 'creation'
                 AND state.state_kind = 'creation')
                OR
                (interval_row.opening_kind = 'add'
                 AND transition.kind = 'leafRecovery'
                 AND state.state_kind = 'commit')
                OR
                (interval_row.opening_kind = 'reset'
                 AND transition.kind = 'resetActivation'
                 AND state.state_kind = 'resetSuccessor')
           )
    ) THEN
        RAISE EXCEPTION 'application interval provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF interval_row.terminal_seq IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM chat.transitions transition
          JOIN chat.entries entry
            ON entry.conversation_id = transition.conversation_id
           AND entry.seq = transition.entry_seq
           AND entry.transition_id = transition.transition_id
         WHERE transition.transition_id = interval_row.closing_transition_id
           AND transition.conversation_id = interval_row.conversation_id
           AND transition.entry_seq = interval_row.terminal_seq
           AND entry.outer_entry_fingerprint = interval_row.closing_outer_entry_fingerprint
           AND (
                (interval_row.closing_kind = 'remove'
                 AND transition.kind IN ('commit','leaveCommit'))
                OR
                (interval_row.closing_kind = 'replace'
                 AND transition.kind = 'leafRecovery')
                OR
                (interval_row.closing_kind = 'reset'
                 AND transition.kind = 'resetActivation')
                OR
                (interval_row.closing_kind = 'terminal'
                 AND transition.kind = 'closeConversation')
           )
    ) THEN
        RAISE EXCEPTION 'application interval provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF interval_row.closing_kind IN ('remove','replace','reset') AND NOT EXISTS (
        SELECT 1
          FROM chat.entry_recipients recipient
         WHERE recipient.conversation_id = interval_row.conversation_id
           AND recipient.seq = interval_row.terminal_seq
           AND recipient.user_did = interval_row.recipient_did
           AND recipient.device_id = interval_row.recipient_device_id
           AND recipient.entitlement_kind = 'intervalClose'
    ) THEN
        RAISE EXCEPTION 'interval close recipient routing missing'
            USING ERRCODE = '23514';
    END IF;

    IF interval_row.closing_kind = 'terminal' AND NOT EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
          JOIN chat.entry_recipients recipient
            ON recipient.conversation_id = proof.conversation_id
           AND recipient.seq = proof.terminal_seq
           AND recipient.user_did = proof.recipient_did
           AND recipient.device_id = proof.recipient_device_id
           AND recipient.entitlement_kind = 'scheduleTerminal'
         WHERE proof.conversation_id = interval_row.conversation_id
           AND proof.recipient_did = interval_row.recipient_did
           AND proof.recipient_device_id = interval_row.recipient_device_id
           AND proof.terminal_seq = interval_row.terminal_seq
           AND proof.transition_id = interval_row.closing_transition_id
           AND proof.outer_entry_fingerprint = interval_row.closing_outer_entry_fingerprint
    ) THEN
        RAISE EXCEPTION 'terminal proof provenance mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.assert_application_terminal_proof(
    target_conversation UUID,
    target_did TEXT,
    target_device UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
          JOIN chat.entry_recipients recipient
            ON recipient.conversation_id = proof.conversation_id
           AND recipient.seq = proof.terminal_seq
           AND recipient.user_did = proof.recipient_did
           AND recipient.device_id = proof.recipient_device_id
           AND recipient.entitlement_kind = 'scheduleTerminal'
          JOIN chat.transitions transition
            ON transition.transition_id = proof.transition_id
           AND transition.conversation_id = proof.conversation_id
           AND transition.entry_seq = proof.terminal_seq
           AND transition.kind = 'closeConversation'
         WHERE proof.conversation_id = target_conversation
           AND proof.recipient_did = target_did
           AND proof.recipient_device_id = target_device
           AND EXISTS (
                SELECT 1
                  FROM (
                    SELECT interval.*
                      FROM chat.application_intervals interval
                     WHERE interval.conversation_id = proof.conversation_id
                       AND interval.recipient_did = proof.recipient_did
                       AND interval.recipient_device_id = proof.recipient_device_id
                       AND interval.start_seq < proof.terminal_seq
                     ORDER BY interval.start_seq DESC
                     LIMIT 1
                  ) latest
                 WHERE (
                    latest.closing_kind = 'terminal'
                    AND latest.terminal_seq = proof.terminal_seq
                    AND latest.closing_transition_id = proof.transition_id
                    AND latest.closing_outer_entry_fingerprint = proof.outer_entry_fingerprint
                 ) OR (
                    latest.closing_kind IN ('remove','reset')
                    AND latest.terminal_seq < proof.terminal_seq
                 )
           )
           AND NOT EXISTS (
                SELECT 1
                  FROM chat.application_intervals later
                 WHERE later.conversation_id = proof.conversation_id
                   AND later.recipient_did = proof.recipient_did
                   AND later.recipient_device_id = proof.recipient_device_id
                   AND later.start_seq >= proof.terminal_seq
           )
    ) THEN
        RAISE EXCEPTION 'terminal proof provenance mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_application_terminal_proof()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_application_terminal_proof(
            OLD.conversation_id, OLD.recipient_did, OLD.recipient_device_id
        );
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR (NEW.conversation_id, NEW.recipient_did, NEW.recipient_device_id)
               IS DISTINCT FROM
               (OLD.conversation_id, OLD.recipient_did, OLD.recipient_device_id)) THEN
        PERFORM chat.assert_application_terminal_proof(
            NEW.conversation_id, NEW.recipient_did, NEW.recipient_device_id
        );
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION chat.assert_entry_recipient_mapping(
    target_conversation UUID,
    target_seq BIGINT,
    target_did TEXT,
    target_device UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    recipient_kind TEXT;
BEGIN
    SELECT entitlement_kind INTO recipient_kind
      FROM chat.entry_recipients
     WHERE conversation_id = target_conversation
       AND seq = target_seq
       AND user_did = target_did
       AND device_id = target_device;
    IF NOT FOUND THEN RETURN; END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF recipient_kind = 'scheduleTerminal' AND NOT EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
         WHERE proof.conversation_id = target_conversation
           AND proof.terminal_seq = target_seq
           AND proof.recipient_did = target_did
           AND proof.recipient_device_id = target_device
           AND EXISTS (
                SELECT 1
                  FROM chat.application_intervals interval
                 WHERE interval.conversation_id = proof.conversation_id
                   AND interval.recipient_did = proof.recipient_did
                   AND interval.recipient_device_id = proof.recipient_device_id
                   AND interval.start_seq < proof.terminal_seq
           )
    ) THEN
        RAISE EXCEPTION 'entry recipient entitlement mismatch'
            USING ERRCODE = '23514';
    ELSIF recipient_kind = 'intervalClose' AND NOT EXISTS (
        SELECT 1
          FROM chat.application_intervals interval
         WHERE interval.conversation_id = target_conversation
           AND interval.terminal_seq = target_seq
           AND interval.recipient_did = target_did
           AND interval.recipient_device_id = target_device
           AND interval.closing_kind IN ('remove','replace','reset')
    ) THEN
        RAISE EXCEPTION 'entry recipient entitlement mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_entry_recipient_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_interval UUID;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_entry_recipient_mapping(
            OLD.conversation_id, OLD.seq, OLD.user_did, OLD.device_id
        );
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR (NEW.conversation_id, NEW.seq, NEW.user_did, NEW.device_id)
               IS DISTINCT FROM
               (OLD.conversation_id, OLD.seq, OLD.user_did, OLD.device_id)) THEN
        PERFORM chat.assert_entry_recipient_mapping(
            NEW.conversation_id, NEW.seq, NEW.user_did, NEW.device_id
        );
    END IF;
    IF TG_OP <> 'INSERT' THEN
        FOR linked_interval IN
            SELECT membership_interval_id
              FROM chat.application_intervals
             WHERE conversation_id = OLD.conversation_id
               AND terminal_seq = OLD.seq
               AND recipient_did = OLD.user_did
               AND recipient_device_id = OLD.device_id
        LOOP
            PERFORM chat.assert_application_interval_provenance(linked_interval);
        END LOOP;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        FOR linked_interval IN
            SELECT membership_interval_id
              FROM chat.application_intervals
             WHERE conversation_id = NEW.conversation_id
               AND terminal_seq = NEW.seq
               AND recipient_did = NEW.user_did
               AND recipient_device_id = NEW.device_id
        LOOP
            PERFORM chat.assert_application_interval_provenance(linked_interval);
        END LOOP;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER application_terminal_proofs_provenance_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.application_schedule_terminal_proofs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_application_terminal_proof();

CREATE CONSTRAINT TRIGGER entry_recipients_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entry_recipients
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_entry_recipient_mapping();

CREATE FUNCTION chat.assert_application_interval_schedule(
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
                     OR (previous_interval.closing_kind = 'reset' AND current_interval.opening_kind = 'reset'))
                    AND previous_interval.closing_transition_id = current_interval.opening_transition_id
                    AND previous_interval.closing_outer_entry_fingerprint = current_interval.opening_outer_entry_fingerprint
                ) THEN
                    RAISE EXCEPTION 'illegal touching application intervals' USING ERRCODE = '23514';
                END IF;
            ELSIF previous_interval.closing_kind IN ('replace','terminal')
                  OR (previous_interval.closing_kind = 'reset'
                      AND current_interval.opening_kind <> 'add') THEN
                RAISE EXCEPTION 'required touching boundary or terminal finality violated' USING ERRCODE = '23514';
            END IF;
        END IF;
        previous_interval := current_interval;
        has_previous := TRUE;
    END LOOP;
    IF has_previous
       AND previous_interval.terminal_seq IS NOT NULL
       AND previous_interval.closing_kind = 'replace' THEN
        RAISE EXCEPTION 'replacement interval lacks touching successor'
            USING ERRCODE = '23514';
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

CREATE FUNCTION chat.enforce_application_interval_schedule()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_application_interval_provenance(OLD.membership_interval_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.membership_interval_id IS DISTINCT FROM OLD.membership_interval_id) THEN
        PERFORM chat.assert_application_interval_provenance(NEW.membership_interval_id);
    END IF;
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_application_interval_schedule(
            OLD.conversation_id, OLD.recipient_did, OLD.recipient_device_id
        );
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR (NEW.conversation_id, NEW.recipient_did, NEW.recipient_device_id)
               IS DISTINCT FROM
               (OLD.conversation_id, OLD.recipient_did, OLD.recipient_device_id)) THEN
        PERFORM chat.assert_application_interval_schedule(
            NEW.conversation_id, NEW.recipient_did, NEW.recipient_device_id
        );
    END IF;
    IF TG_OP <> 'DELETE' AND EXISTS (
        SELECT 1 FROM chat.application_schedule_terminal_proofs proof
         WHERE proof.conversation_id = NEW.conversation_id
           AND proof.recipient_did = NEW.recipient_did
           AND proof.recipient_device_id = NEW.recipient_device_id
    ) THEN
        PERFORM chat.assert_application_terminal_proof(
            NEW.conversation_id, NEW.recipient_did, NEW.recipient_device_id
        );
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER application_intervals_schedule_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.application_intervals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_application_interval_schedule();

CREATE FUNCTION chat.assert_conversation_terminal_schedules(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row chat.conversations%ROWTYPE;
    schedule_count BIGINT;
    proof_count BIGINT;
BEGIN
    SELECT * INTO conversation_row
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT count(*) INTO schedule_count FROM (
        SELECT DISTINCT recipient_did, recipient_device_id
          FROM chat.application_intervals
         WHERE conversation_id = target_conversation
    ) schedules;
    SELECT count(*) INTO proof_count
      FROM chat.application_schedule_terminal_proofs
     WHERE conversation_id = target_conversation;

    IF conversation_row.lifecycle = 'active' THEN
        IF proof_count <> 0 THEN
            RAISE EXCEPTION 'active conversation has terminal schedule proof'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF schedule_count <> proof_count OR EXISTS (
        SELECT 1
          FROM (
            SELECT DISTINCT recipient_did, recipient_device_id
              FROM chat.application_intervals
             WHERE conversation_id = target_conversation
          ) schedule
          LEFT JOIN chat.application_schedule_terminal_proofs proof
            ON proof.conversation_id = target_conversation
           AND proof.recipient_did = schedule.recipient_did
           AND proof.recipient_device_id = schedule.recipient_device_id
         WHERE proof.conversation_id IS NULL
    ) OR EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
         WHERE proof.conversation_id = target_conversation
           AND (
                proof.terminal_seq <> conversation_row.close_seq
                OR proof.transition_id <> conversation_row.close_transition_id
                OR proof.received_at <> conversation_row.closed_at
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.application_intervals interval
                     WHERE interval.conversation_id = proof.conversation_id
                       AND interval.recipient_did = proof.recipient_did
                       AND interval.recipient_device_id = proof.recipient_device_id
                       AND interval.start_seq < proof.terminal_seq
                )
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.entry_recipients recipient
                     WHERE recipient.conversation_id = proof.conversation_id
                       AND recipient.seq = proof.terminal_seq
                       AND recipient.user_did = proof.recipient_did
                       AND recipient.device_id = proof.recipient_device_id
                       AND recipient.entitlement_kind = 'scheduleTerminal'
                )
                OR EXISTS (
                    SELECT 1
                      FROM chat.application_intervals later
                     WHERE later.conversation_id = proof.conversation_id
                       AND later.recipient_did = proof.recipient_did
                       AND later.recipient_device_id = proof.recipient_device_id
                       AND later.start_seq >= proof.terminal_seq
                )
           )
    ) THEN
        RAISE EXCEPTION 'terminal conversation schedule proof set mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_conversation_terminal_schedules()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_conversation_terminal_schedules(OLD.conversation_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id) THEN
        PERFORM chat.assert_conversation_terminal_schedules(NEW.conversation_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER conversations_terminal_schedules_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_terminal_schedules();

CREATE CONSTRAINT TRIGGER application_intervals_terminal_schedules_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.application_intervals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_terminal_schedules();

CREATE CONSTRAINT TRIGGER application_terminal_proofs_completeness_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.application_schedule_terminal_proofs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_terminal_schedules();

CREATE CONSTRAINT TRIGGER entry_recipients_terminal_schedules_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entry_recipients
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_terminal_schedules();

CREATE FUNCTION chat.assert_conversation_entry_contiguity(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row chat.conversations%ROWTYPE;
    entry_count BIGINT;
    minimum_seq BIGINT;
    maximum_seq BIGINT;
BEGIN
    SELECT * INTO conversation_row
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT count(*), min(seq), max(seq)
      INTO entry_count, minimum_seq, maximum_seq
      FROM chat.entries
     WHERE conversation_id = target_conversation;

    IF (entry_count = 0 AND conversation_row.next_entry_seq <> 1)
       OR (entry_count > 0 AND (
            minimum_seq <> 1
            OR maximum_seq <> entry_count
            OR conversation_row.next_entry_seq <> maximum_seq + 1
       ))
       OR (conversation_row.lifecycle = 'superseded' AND (
            conversation_row.close_seq IS NULL
            OR maximum_seq IS DISTINCT FROM conversation_row.close_seq
       )) THEN
        RAISE EXCEPTION 'conversation entry sequence is not contiguous'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_conversation_entry_contiguity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_conversation_entry_contiguity(OLD.conversation_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id) THEN
        PERFORM chat.assert_conversation_entry_contiguity(NEW.conversation_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER conversations_entry_contiguity_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_entry_contiguity();

CREATE CONSTRAINT TRIGGER entries_contiguity_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_entry_contiguity();

CREATE FUNCTION chat.enforce_delivery_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'application_intervals' THEN
        IF OLD.terminal_seq IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'closed application interval is terminal'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'welcome_deliveries' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal Welcome delivery cannot be rewritten'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending'
           AND NEW.status NOT IN ('pending','acknowledged','rejected','expired','superseded') THEN
            RAISE EXCEPTION 'invalid Welcome delivery lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'recovery_work_items' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal recovery work cannot be rewritten'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending' AND NEW.status NOT IN ('pending','completed','superseded') THEN
            RAISE EXCEPTION 'invalid recovery work lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'outbox' THEN
        IF OLD.status IN ('delivered','failed') AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal outbox work cannot be rewritten'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.attempt_count < OLD.attempt_count
           OR (OLD.status = 'pending' AND NEW.status NOT IN ('pending','leased','failed'))
           OR (OLD.status = 'leased' AND NEW.status NOT IN ('leased','pending','delivered','failed')) THEN
            RAISE EXCEPTION 'invalid outbox lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'event_retention' THEN
        IF NEW.retained_floor < OLD.retained_floor OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'event retention floor cannot move backward'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'inventory_sessions' THEN
        IF (OLD.conversations_complete AND NOT NEW.conversations_complete)
           OR (OLD.welcomes_complete AND NOT NEW.welcomes_complete)
           OR (OLD.recovery_complete AND NOT NEW.recovery_complete)
           OR (OLD.conversations_complete AND
               (NEW.conversation_item_count, NEW.conversation_items_sha256)
               IS DISTINCT FROM
               (OLD.conversation_item_count, OLD.conversation_items_sha256))
           OR (OLD.welcomes_complete AND
               (NEW.welcome_item_count, NEW.welcome_items_sha256)
               IS DISTINCT FROM
               (OLD.welcome_item_count, OLD.welcome_items_sha256))
           OR (OLD.recovery_complete AND
               (NEW.recovery_item_count, NEW.recovery_items_sha256)
               IS DISTINCT FROM
               (OLD.recovery_item_count, OLD.recovery_items_sha256)) THEN
            RAISE EXCEPTION 'inventory completion cannot be cleared'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'device_inventory_sessions' THEN
        IF OLD.complete AND (
            NOT NEW.complete
            OR (NEW.item_count, NEW.items_sha256)
               IS DISTINCT FROM (OLD.item_count, OLD.items_sha256)
        ) THEN
            RAISE EXCEPTION 'device inventory completion cannot be cleared'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'subscription_tickets' THEN
        IF OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'consumed subscription ticket is terminal'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER entries_immutable
BEFORE UPDATE OR DELETE ON chat.entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER message_sends_immutable
BEFORE UPDATE OR DELETE ON chat.message_sends
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER application_intervals_identity_immutable
BEFORE UPDATE OR DELETE ON chat.application_intervals
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'terminal_seq', 'closing_state_version', 'closing_transition_id', 'closing_outer_entry_fingerprint',
    'closing_kind', 'closing_leaf_period_id', 'removed_at'
);

CREATE TRIGGER application_intervals_lifecycle_monotonic
BEFORE UPDATE ON chat.application_intervals
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER application_schedule_terminal_proofs_immutable
BEFORE UPDATE OR DELETE ON chat.application_schedule_terminal_proofs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER entry_recipients_immutable
BEFORE UPDATE OR DELETE ON chat.entry_recipients
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER welcome_bundles_immutable
BEFORE UPDATE OR DELETE ON chat.welcome_bundles
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER welcome_deliveries_identity_immutable
BEFORE UPDATE OR DELETE ON chat.welcome_deliveries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('status', 'terminal_at');

CREATE TRIGGER welcome_deliveries_lifecycle_monotonic
BEFORE UPDATE ON chat.welcome_deliveries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER welcome_dispositions_immutable
BEFORE UPDATE OR DELETE ON chat.welcome_dispositions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER recovery_work_items_identity_immutable
BEFORE UPDATE OR DELETE ON chat.recovery_work_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at'
);

CREATE TRIGGER recovery_work_items_lifecycle_monotonic
BEFORE UPDATE ON chat.recovery_work_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER events_immutable
BEFORE UPDATE OR DELETE ON chat.events
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER event_recipients_immutable
BEFORE UPDATE OR DELETE ON chat.event_recipients
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER outbox_identity_immutable
BEFORE UPDATE OR DELETE ON chat.outbox
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'attempt_count', 'next_attempt_at', 'lease_owner',
    'lease_expires_at', 'delivered_at'
);

CREATE TRIGGER outbox_lifecycle_monotonic
BEFORE UPDATE ON chat.outbox
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER event_retention_identity_immutable
BEFORE UPDATE OR DELETE ON chat.event_retention
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('retained_floor', 'updated_at');

CREATE TRIGGER event_retention_lifecycle_monotonic
BEFORE UPDATE ON chat.event_retention
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER inventory_sessions_identity_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'conversations_complete', 'welcomes_complete', 'recovery_complete',
    'conversation_item_count', 'conversation_items_sha256',
    'welcome_item_count', 'welcome_items_sha256',
    'recovery_item_count', 'recovery_items_sha256'
);

CREATE TRIGGER inventory_sessions_lifecycle_monotonic
BEFORE UPDATE ON chat.inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER inventory_conversation_items_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_conversation_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER inventory_welcome_items_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_welcome_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER inventory_recovery_items_immutable
BEFORE UPDATE OR DELETE ON chat.inventory_recovery_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER device_inventory_sessions_identity_immutable
BEFORE UPDATE OR DELETE ON chat.device_inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'complete', 'item_count', 'items_sha256'
);

CREATE TRIGGER device_inventory_sessions_lifecycle_monotonic
BEFORE UPDATE ON chat.device_inventory_sessions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

CREATE TRIGGER device_inventory_items_immutable
BEFORE UPDATE OR DELETE ON chat.device_inventory_items
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER subscription_tickets_identity_immutable
BEFORE UPDATE OR DELETE ON chat.subscription_tickets
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('consumed_at');

CREATE TRIGGER subscription_tickets_lifecycle_monotonic
BEFORE UPDATE ON chat.subscription_tickets
FOR EACH ROW EXECUTE FUNCTION chat.enforce_delivery_lifecycle_transition();

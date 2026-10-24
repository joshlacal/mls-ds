-- V2 publication keeps cryptographic membership separate from recipient consent.
-- Existing v1 rows and invariants remain authoritative. Only an immutable,
-- atomically published request grants the narrowly scoped pending-leaf exception.
ALTER TABLE chat.conversations ADD COLUMN protocol_version TEXT NOT NULL DEFAULT '1'
    CHECK (protocol_version IN ('1','2'));

CREATE TABLE chat.direct_request_publications (
    request_id UUID PRIMARY KEY REFERENCES chat.direct_request_attempts(request_id),
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id),
    generation BIGINT NOT NULL CHECK (chat.is_safe_integer(generation)),
    state_version BIGINT NOT NULL CHECK (state_version = 1),
    first_message_id UUID NOT NULL UNIQUE CHECK (chat.is_uuid_v4(first_message_id)),
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    actor_key_id TEXT NOT NULL,
    actor_auth_generation BIGINT NOT NULL,
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did) AND recipient_did <> actor_did),
    context_hash BYTEA NOT NULL CHECK (octet_length(context_hash) = 32),
    preparation_digest BYTEA NOT NULL CHECK (octet_length(preparation_digest) = 32),
    publication_digest BYTEA NOT NULL CHECK (octet_length(publication_digest) = 32),
    signed_publication BYTEA NOT NULL CHECK (octet_length(signed_publication) BETWEEN 1 AND 16777216),
    request_entry BYTEA NOT NULL CHECK (octet_length(request_entry) BETWEEN 1 AND 16777216),
    request_entry_sha256 BYTEA NOT NULL CHECK (request_entry_sha256 = digest(request_entry,'sha256')),
    final_group_info BYTEA NOT NULL CHECK (octet_length(final_group_info) BETWEEN 8 AND 1048576),
    final_group_info_sha256 BYTEA NOT NULL CHECK (final_group_info_sha256 = digest(final_group_info,'sha256')),
    full_welcome BYTEA NOT NULL CHECK (octet_length(full_welcome) BETWEEN 8 AND 8388608),
    full_welcome_sha256 BYTEA NOT NULL CHECK (full_welcome_sha256 = digest(full_welcome,'sha256')),
    initial_ciphertext BYTEA NOT NULL CHECK (octet_length(initial_ciphertext) BETWEEN 1 AND 98304),
    initial_ciphertext_sha256 BYTEA NOT NULL CHECK (initial_ciphertext_sha256 = digest(initial_ciphertext,'sha256')),
    metadata_snapshot BYTEA NOT NULL CHECK (octet_length(metadata_snapshot) BETWEEN 1 AND 1048576),
    metadata_snapshot_sha256 BYTEA NOT NULL CHECK (metadata_snapshot_sha256 = digest(metadata_snapshot,'sha256')),
    import_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (import_until >= created_at + INTERVAL '7 days 300 seconds'),
    UNIQUE (conversation_id,generation),
    UNIQUE (request_id,conversation_id,generation,state_version),
    FOREIGN KEY (actor_did,actor_device_id,actor_key_id)
        REFERENCES chat.device_keys(user_did,device_id,key_id),
    FOREIGN KEY (conversation_id,generation,state_version)
        REFERENCES chat.generation_states(conversation_id,generation,state_version)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (request_id) REFERENCES chat.transitions(transition_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- The complete common Welcome is stored once above. Device rows reference it;
-- slicing its secret list would invalidate the cryptographic object.
CREATE TABLE chat.direct_request_device_deliveries (
    request_id UUID NOT NULL REFERENCES chat.direct_request_publications(request_id),
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1),
    key_package_ref BYTEA NOT NULL CHECK (octet_length(key_package_ref) = 32),
    grant_id UUID NOT NULL REFERENCES chat.direct_request_grants(grant_id),
    grant_revision BIGINT NOT NULL CHECK (chat.is_safe_integer(grant_revision) AND grant_revision >= 1),
    grant_digest BYTEA NOT NULL CHECK (octet_length(grant_digest) = 32),
    leaf_index BIGINT NOT NULL CHECK (chat.is_safe_integer(leaf_index)),
    import_until TIMESTAMPTZ NOT NULL,
    provenance BYTEA NOT NULL CHECK (octet_length(provenance) BETWEEN 1 AND 8388608),
    provenance_sha256 BYTEA NOT NULL CHECK (provenance_sha256 = digest(provenance,'sha256')),
    PRIMARY KEY (request_id,owner_did,owner_device_id),
    UNIQUE (request_id,leaf_index),
    FOREIGN KEY (request_id,owner_did,owner_device_id)
        REFERENCES chat.direct_request_selected_devices(request_id,owner_did,owner_device_id),
    FOREIGN KEY (owner_did,owner_device_id,owner_key_id)
        REFERENCES chat.device_keys(user_did,device_id,key_id)
);
CREATE TRIGGER direct_request_publications_immutable
    BEFORE UPDATE OR DELETE ON chat.direct_request_publications
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_device_deliveries_immutable
    BEFORE UPDATE OR DELETE ON chat.direct_request_device_deliveries
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- This predicate authenticates historical opening provenance, not present
-- consent, current key authority, or permission to send. It remains true after
-- acceptance/removal so a historical membership proof cannot become invalid.
CREATE FUNCTION chat.direct_request_leaf_has_provenance(target_leaf UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM chat.member_devices m
        JOIN chat.direct_request_publications p
          ON p.request_id=m.joined_transition_id AND p.conversation_id=m.conversation_id
         AND p.generation=m.generation AND p.state_version=m.joined_state_version
        JOIN chat.direct_request_attempts a ON a.request_id=p.request_id
        JOIN chat.transitions t ON t.transition_id=p.request_id
        WHERE m.leaf_period_id=target_leaf AND a.status='published'
          AND a.selected_digest=p.preparation_digest AND a.publication_digest=p.publication_digest
          AND t.kind='directRequestPublication' AND t.accepted_at=p.created_at
          AND m.created_at=p.created_at AND m.joined_seq=t.entry_seq
          AND ((m.origin='genesis' AND m.join_key_package_ref IS NULL
                AND (m.user_did,m.device_id,m.leaf_key_id,m.leaf_auth_generation)
                    =(p.actor_did,p.actor_device_id,p.actor_key_id,p.actor_auth_generation))
            OR (m.origin='keyPackage' AND EXISTS (
                SELECT 1 FROM chat.direct_request_device_deliveries d
                JOIN chat.direct_request_selected_devices s
                  ON s.request_id=d.request_id AND s.owner_did=d.owner_did
                 AND s.owner_device_id=d.owner_device_id
                JOIN chat.direct_request_grants g ON g.grant_id=d.grant_id
                JOIN chat.key_packages k ON k.key_package_ref=d.key_package_ref
                WHERE d.request_id=p.request_id
                  AND (d.owner_did,d.owner_device_id,d.owner_key_id,d.auth_generation,d.leaf_index,d.key_package_ref)
                    =(m.user_did,m.device_id,m.leaf_key_id,m.leaf_auth_generation,m.leaf_index,m.join_key_package_ref)
                  AND (s.owner_key_id,s.auth_generation,s.key_package_ref,s.grant_id,s.grant_digest)
                    =(d.owner_key_id,d.auth_generation,d.key_package_ref,d.grant_id,d.grant_digest)
                  AND (g.revision,g.grant_digest,g.key_package_ref,g.owner_did,g.owner_device_id,g.owner_key_id,g.auth_generation)
                    =(d.grant_revision,d.grant_digest,d.key_package_ref,d.owner_did,d.owner_device_id,d.owner_key_id,d.auth_generation)
                  AND d.import_until=p.import_until AND d.import_until<=g.expires_at
                  AND d.import_until<=k.not_after AND k.usage_scope='direct-request'
                  AND k.status='consumed' AND k.terminal_transition_id=p.request_id
                  AND k.terminal_at=p.created_at
            )))
    )
$$;

CREATE FUNCTION chat.is_authorized_pending_request_leaf(target_leaf UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM chat.member_devices m
        JOIN chat.conversations c ON c.conversation_id=m.conversation_id
        JOIN chat.participants recipient ON recipient.participant_period_id=m.participant_period_id
        JOIN chat.direct_request_publications p ON p.request_id=m.joined_transition_id
        WHERE m.leaf_period_id=target_leaf AND m.active
          AND c.kind='direct' AND c.protocol_version='2' AND c.current_generation=m.generation
          AND recipient.current_membership AND recipient.status='pending'
          AND recipient.user_did=p.recipient_did AND recipient.user_did=m.user_did
          AND chat.direct_request_leaf_has_provenance(m.leaf_period_id)
    )
$$;

CREATE FUNCTION chat.assert_direct_request_publication(target_request UUID)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE p chat.direct_request_publications%ROWTYPE;
        a chat.direct_request_attempts%ROWTYPE;
        selected_count BIGINT;
BEGIN
    SELECT * INTO a FROM chat.direct_request_attempts WHERE request_id=target_request;
    SELECT * INTO p FROM chat.direct_request_publications WHERE request_id=target_request;
    IF NOT FOUND THEN
        IF a.status='published' THEN
            RAISE EXCEPTION 'published request lacks canonical publication' USING ERRCODE='23514';
        END IF;
        RETURN;
    END IF;
    PERFORM 1 FROM chat.conversations WHERE conversation_id=p.conversation_id FOR UPDATE;
    IF a.status IS DISTINCT FROM 'published'
       OR (a.actor_did,a.actor_device_id,a.actor_key_id,a.actor_auth_generation,a.recipient_did,a.selected_digest,a.publication_digest,a.terminal_at)
          IS DISTINCT FROM (p.actor_did,p.actor_device_id,p.actor_key_id,p.actor_auth_generation,p.recipient_did,p.preparation_digest,p.publication_digest,p.created_at)
       OR NOT EXISTS (
          SELECT 1 FROM chat.conversations c JOIN chat.transitions t ON t.conversation_id=c.conversation_id
          JOIN chat.entries e ON e.conversation_id=t.conversation_id AND e.seq=t.entry_seq
          WHERE c.conversation_id=p.conversation_id AND c.kind='direct' AND c.protocol_version='2'
            AND c.direct_did_low=LEAST(p.actor_did COLLATE "C",p.recipient_did COLLATE "C")
            AND c.direct_did_high=GREATEST(p.actor_did COLLATE "C",p.recipient_did COLLATE "C")
            AND t.transition_id=p.request_id AND t.kind='directRequestPublication'
            AND (t.next_generation,t.next_state_version,t.actor_did,t.actor_device_id,t.actor_key_id,t.actor_auth_generation,t.request_digest,t.accepted_at)
              =(p.generation,p.state_version,p.actor_did,p.actor_device_id,p.actor_key_id,p.actor_auth_generation,p.publication_digest,p.created_at)
            AND t.signed_request_bytes=p.signed_publication
            AND e.entry_kind='blue.catbird.chat.defs#directRequestEntry'
            AND e.transition_id=p.request_id AND e.message_id=p.first_message_id
            AND e.accepted_payload_bytes=p.request_entry AND e.accepted_payload_sha256=p.request_entry_sha256
       ) THEN RAISE EXCEPTION 'request publication provenance mismatch' USING ERRCODE='23514'; END IF;
    SELECT count(*) INTO selected_count FROM chat.direct_request_selected_devices WHERE request_id=target_request;
    IF selected_count NOT BETWEEN 1 AND 39
       OR (SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id=target_request)<>selected_count
       OR (SELECT count(*) FROM chat.member_devices WHERE joined_transition_id=target_request)<>selected_count+1
       OR NOT EXISTS (SELECT 1 FROM chat.direct_request_device_deliveries WHERE request_id=target_request AND owner_did=p.recipient_did)
       OR EXISTS (SELECT 1 FROM chat.member_devices m WHERE m.joined_transition_id=target_request
            AND (m.user_did NOT IN (p.actor_did,p.recipient_did) OR NOT chat.direct_request_leaf_has_provenance(m.leaf_period_id)))
       OR (SELECT count(*) FROM chat.member_devices WHERE joined_transition_id=target_request AND origin='genesis')<>1
       OR EXISTS (SELECT 1 FROM chat.member_devices WHERE joined_transition_id=target_request GROUP BY user_did HAVING count(*)>20)
       OR EXISTS (SELECT 1 FROM chat.direct_request_device_deliveries d WHERE d.request_id=target_request
           AND NOT EXISTS (SELECT 1 FROM chat.member_devices m WHERE m.joined_transition_id=target_request
               AND m.user_did=d.owner_did AND m.device_id=d.owner_device_id AND m.leaf_index=d.leaf_index
               AND m.join_key_package_ref=d.key_package_ref))
    THEN RAISE EXCEPTION 'request publication device set mismatch' USING ERRCODE='23514'; END IF;
END $$;

CREATE FUNCTION chat.enforce_direct_request_publication() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP<>'DELETE' THEN PERFORM chat.assert_direct_request_publication(NEW.request_id); END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_publication_complete
    AFTER INSERT ON chat.direct_request_publications DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_publication();
CREATE CONSTRAINT TRIGGER direct_request_deliveries_complete
    AFTER INSERT ON chat.direct_request_device_deliveries DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_publication();
CREATE CONSTRAINT TRIGGER direct_request_published_attempt_complete
    AFTER INSERT OR UPDATE ON chat.direct_request_attempts DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_publication();




-- Canonical v1 invariants extended for authenticated v2 request edges.


ALTER TABLE chat.generation_states DROP CONSTRAINT generation_states_kind_check;
ALTER TABLE chat.generation_states ADD CONSTRAINT generation_states_kind_check CHECK (
        state_kind IN ('creation','commit','policy','acceptConversation','metadata','leavePolicy',
                       'resetRetirement','resetSuccessor','closeConversation',
                       'directRequestPublication','directRequestRetirement','directRequestAcceptance')
    );


ALTER TABLE chat.transitions DROP CONSTRAINT transitions_kind_check;
ALTER TABLE chat.transitions ADD CONSTRAINT transitions_kind_check CHECK (
        kind IN ('creation','commit','policy','acceptConversation','metadata','leafRecovery',
                 'leaveCommit','leavePolicy','closeConversation','resetActivation',
                 'directRequestPublication','directRequestAcceptance')
    );


ALTER TABLE chat.transitions DROP CONSTRAINT transitions_actor_authority_check;
ALTER TABLE chat.transitions ADD CONSTRAINT transitions_actor_authority_check CHECK (
        actor_role IN ('member','admin') AND actor_device_status = 'active'
        AND (kind NOT IN ('creation','policy','metadata','resetActivation','closeConversation','directRequestPublication','directRequestAcceptance')
             OR actor_role = 'admin')
    );


ALTER TABLE chat.transitions DROP CONSTRAINT transitions_kind_coordinate_shape_check;
ALTER TABLE chat.transitions ADD CONSTRAINT transitions_kind_coordinate_shape_check CHECK ((
        (kind = 'creation'
            AND prior_generation IS NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND next_generation = 0 AND next_state_version = 0
            AND retired_generation IS NULL AND successor_generation IS NULL
            AND reset_request_id IS NULL)
        OR (kind = 'resetActivation'
            AND prior_generation IS NOT NULL AND prior_state_version IS NOT NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND retired_generation IS NOT NULL AND retired_state_version IS NOT NULL
            AND successor_generation IS NOT NULL AND successor_state_version IS NOT NULL
            AND retired_generation = prior_generation
            AND retired_state_version = prior_state_version + 1
            AND successor_generation = prior_generation + 1
            AND successor_state_version = 0
            AND next_generation = successor_generation
            AND next_state_version = successor_state_version
            AND reset_request_id IS NOT NULL)
        OR (kind IN ('commit','policy','acceptConversation','metadata','leafRecovery',
                     'leaveCommit','leavePolicy','closeConversation','directRequestAcceptance')
            AND prior_generation IS NOT NULL AND prior_state_version IS NOT NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND next_generation = prior_generation
            AND next_state_version = prior_state_version + 1
            AND retired_generation IS NULL AND successor_generation IS NULL
            AND reset_request_id IS NULL)
    ) OR (
        kind='directRequestPublication' AND next_generation IS NOT NULL AND next_state_version=1
        AND reset_request_id IS NULL
        AND ((prior_generation IS NULL AND next_generation=0
                AND retired_generation IS NULL AND successor_generation IS NULL)
             OR (prior_generation IS NOT NULL AND prior_state_version IS NOT NULL
                AND retired_generation IS NOT NULL AND successor_generation IS NOT NULL
                AND retired_generation=prior_generation AND retired_state_version=prior_state_version+1
                AND successor_generation=prior_generation+1 AND successor_state_version=1
                AND next_generation=successor_generation))
));


ALTER TABLE chat.entries DROP CONSTRAINT entries_kind_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_kind_check CHECK (entry_kind IN (
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
        'blue.catbird.chat.defs#leaveCommitFulfillmentEntry',
        'blue.catbird.chat.defs#directRequestEntry',
        'blue.catbird.chat.defs#directRequestAcceptanceEntry'
    ));


ALTER TABLE chat.entries DROP CONSTRAINT entries_reference_shape_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_reference_shape_check CHECK ((
        (entry_kind = 'blue.catbird.chat.defs#applicationEntry'
            AND message_id IS NOT NULL AND transition_id IS NULL)
        OR (entry_kind IN (
                'blue.catbird.chat.defs#resetRequestEntry',
                'blue.catbird.chat.defs#leaveRequestEntry',
                'blue.catbird.chat.defs#leaveCancellationEntry'
            ) AND transition_id IS NULL AND message_id IS NULL)
        OR (entry_kind NOT IN (
                'blue.catbird.chat.defs#directRequestEntry',
                'blue.catbird.chat.defs#applicationEntry',
                'blue.catbird.chat.defs#resetRequestEntry',
                'blue.catbird.chat.defs#leaveRequestEntry',
                'blue.catbird.chat.defs#leaveCancellationEntry'
            )
            AND transition_id IS NOT NULL AND message_id IS NULL)
    ) OR (entry_kind='blue.catbird.chat.defs#directRequestEntry' AND transition_id IS NOT NULL AND message_id IS NOT NULL));


ALTER TABLE chat.application_intervals DROP CONSTRAINT application_intervals_id_check;
ALTER TABLE chat.application_intervals ADD CONSTRAINT application_intervals_id_check CHECK (
        chat.is_uuid_v4(membership_interval_id)
        AND (membership_interval_id = opening_transition_id OR opening_kind='directRequest')
    );


ALTER TABLE chat.application_intervals DROP CONSTRAINT application_intervals_opening_kind_check;
ALTER TABLE chat.application_intervals ADD CONSTRAINT application_intervals_opening_kind_check CHECK (opening_kind IN ('creation','add','reset','directRequest'));


ALTER TABLE chat.application_intervals DROP CONSTRAINT application_intervals_close_kind_check;
ALTER TABLE chat.application_intervals ADD CONSTRAINT application_intervals_close_kind_check CHECK (
        closing_kind IS NULL OR closing_kind IN ('remove','replace','reset','terminal','directRequest')
    );



DROP INDEX chat.generation_states_crypto_edge_uq;
CREATE UNIQUE INDEX generation_states_crypto_edge_uq ON chat.generation_states
    (conversation_id,generation,group_id,epoch,group_context_hash,confirmation_tag)
    WHERE state_kind IN ('creation','commit','resetSuccessor','directRequestPublication');

DROP TRIGGER conversations_identity_immutable ON chat.conversations;
CREATE TRIGGER conversations_identity_immutable BEFORE UPDATE OR DELETE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle','current_generation','current_state_version','next_entry_seq',
    'close_transition_id','close_generation','close_state_version','close_seq','closed_at','protocol_version'
);
CREATE FUNCTION chat.enforce_request_protocol_upgrade() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.protocol_version IS DISTINCT FROM NEW.protocol_version
       AND NOT (OLD.protocol_version='1' AND NEW.protocol_version='2'
                AND OLD.kind='direct' AND OLD.lifecycle='active'
                AND NEW.current_generation=OLD.current_generation+1) THEN
        RAISE EXCEPTION 'invalid conversation protocol transition' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER conversations_protocol_monotonic BEFORE UPDATE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_request_protocol_upgrade();
CREATE FUNCTION chat.enforce_request_protocol_provenance() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE target UUID; version TEXT;
BEGIN
    target:=NEW.conversation_id;
    SELECT protocol_version INTO version FROM chat.conversations WHERE conversation_id=target;
    IF version='2' AND NOT EXISTS (SELECT 1 FROM chat.direct_request_publications WHERE conversation_id=target) THEN
        RAISE EXCEPTION 'v2 conversation lacks request publication' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND OLD.protocol_version='1' AND NEW.protocol_version='2'
       AND NOT EXISTS (SELECT 1 FROM chat.direct_request_publications p JOIN chat.transitions t ON t.transition_id=p.request_id
            WHERE p.conversation_id=target AND p.generation=NEW.current_generation
              AND t.prior_generation=OLD.current_generation AND t.prior_state_version=OLD.current_state_version) THEN
        RAISE EXCEPTION 'protocol upgrade lacks exact predecessor' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER conversations_protocol_provenance AFTER INSERT OR UPDATE ON chat.conversations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_request_protocol_provenance();


CREATE OR REPLACE FUNCTION chat.assert_transition_state_outputs(target_transition UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    transition_row chat.transitions%ROWTYPE;
    output_count BIGINT;
BEGIN
    SELECT * INTO transition_row
      FROM chat.transitions
     WHERE transition_id = target_transition;

    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.generation_states
             WHERE producing_transition_id = target_transition
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = transition_row.conversation_id
     FOR UPDATE;

    SELECT count(*) INTO output_count
      FROM chat.generation_states
     WHERE producing_transition_id = target_transition;

    IF EXISTS (
        SELECT 1 FROM chat.generation_states state
         WHERE state.producing_transition_id = target_transition
           AND state.created_at <> transition_row.accepted_at
    ) THEN
        RAISE EXCEPTION 'generation state trusted time mismatch'
            USING ERRCODE = '23514';
    END IF;


    IF transition_row.kind='directRequestPublication' THEN
        PERFORM chat.assert_direct_request_publication(target_transition);
        IF output_count<>(CASE WHEN transition_row.prior_generation IS NULL THEN 1 ELSE 2 END)
           OR NOT EXISTS (
             SELECT 1 FROM chat.generation_states s JOIN chat.generations g
               ON g.conversation_id=s.conversation_id AND g.generation=s.generation
             WHERE s.producing_transition_id=target_transition
               AND s.conversation_id=transition_row.conversation_id
               AND s.generation=transition_row.next_generation AND s.state_version=1
               AND s.state_kind='directRequestPublication' AND s.lifecycle='active' AND s.epoch=1
               AND s.leaf_count BETWEEN 2 AND 40
               AND g.activated_seq=transition_row.entry_seq AND g.activated_at=transition_row.accepted_at
           ) THEN RAISE EXCEPTION 'request publication state mismatch' USING ERRCODE='23514'; END IF;
        IF transition_row.prior_generation IS NULL THEN
            IF NOT EXISTS (SELECT 1 FROM chat.conversations WHERE conversation_id=transition_row.conversation_id
                AND created_at=transition_row.accepted_at) THEN
                RAISE EXCEPTION 'request creation time mismatch' USING ERRCODE='23514'; END IF;
        ELSIF NOT EXISTS (
            SELECT 1 FROM chat.generation_states retired
            JOIN chat.generation_states prior ON prior.conversation_id=transition_row.conversation_id
              AND prior.generation=transition_row.prior_generation AND prior.state_version=transition_row.prior_state_version
            JOIN chat.generation_states successor ON successor.conversation_id=prior.conversation_id
              AND successor.generation=transition_row.next_generation AND successor.state_version=transition_row.next_state_version
            JOIN chat.generations g ON g.conversation_id=retired.conversation_id AND g.generation=retired.generation
            WHERE retired.producing_transition_id=target_transition
              AND retired.conversation_id=prior.conversation_id AND retired.generation=prior.generation
              AND retired.state_version=prior.state_version+1 AND retired.state_kind='directRequestRetirement'
              AND retired.lifecycle='superseded'
              AND (retired.group_id,retired.epoch,retired.group_context_hash,retired.confirmation_tag,
                   retired.public_snapshot_bytes,retired.tree_summary_bytes,retired.leaf_count)
                =(prior.group_id,prior.epoch,prior.group_context_hash,prior.confirmation_tag,
                  prior.public_snapshot_bytes,prior.tree_summary_bytes,prior.leaf_count)
              AND successor.group_id<>prior.group_id AND successor.group_context_hash<>prior.group_context_hash
              AND successor.confirmation_tag<>prior.confirmation_tag
              AND g.superseded_seq=transition_row.entry_seq AND g.superseded_at=transition_row.accepted_at
        ) THEN RAISE EXCEPTION 'request predecessor retirement mismatch' USING ERRCODE='23514'; END IF;
    ELSIF transition_row.kind = 'creation' THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'creation'
               AND state.lifecycle = 'active'
               AND state.epoch = 0
               AND EXISTS (
                    SELECT 1 FROM chat.conversations conversation
                     WHERE conversation.conversation_id = transition_row.conversation_id
                       AND conversation.created_at = transition_row.accepted_at
               )
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.next_generation
                       AND generation.activated_seq = transition_row.entry_seq
                       AND generation.activated_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN ('commit','leafRecovery','leaveCommit') THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'commit'
               AND state.lifecycle = 'active'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch + 1
               AND state.group_context_hash <> prior.group_context_hash
               AND state.confirmation_tag <> prior.confirmation_tag
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN (
        'policy','acceptConversation','metadata','leavePolicy','directRequestAcceptance'
    ) THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = transition_row.kind
               AND state.lifecycle = 'active'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch
               AND state.group_context_hash = prior.group_context_hash
               AND state.confirmation_tag = prior.confirmation_tag
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;

        IF transition_row.kind='directRequestAcceptance' AND NOT EXISTS (
            SELECT 1 FROM chat.direct_request_publications p
            JOIN chat.participants recipient ON recipient.conversation_id=p.conversation_id AND recipient.user_did=p.recipient_did
            JOIN chat.generation_states prior ON prior.conversation_id=p.conversation_id
              AND prior.generation=transition_row.prior_generation AND prior.state_version=transition_row.prior_state_version
            JOIN chat.generation_states successor ON successor.conversation_id=p.conversation_id
              AND successor.generation=transition_row.next_generation AND successor.state_version=transition_row.next_state_version
            WHERE p.conversation_id=transition_row.conversation_id AND p.generation=transition_row.prior_generation
              AND transition_row.actor_did=p.recipient_did AND recipient.status='active'
              AND recipient.acceptance_transition_id=target_transition AND recipient.accepted_at=transition_row.accepted_at
              AND successor.public_snapshot_bytes=prior.public_snapshot_bytes
              AND successor.tree_summary_bytes=prior.tree_summary_bytes AND successor.leaf_count=prior.leaf_count
        ) THEN RAISE EXCEPTION 'request acceptance proof mismatch' USING ERRCODE='23514'; END IF;
    ELSIF transition_row.kind = 'closeConversation' THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'closeConversation'
               AND state.lifecycle = 'superseded'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch
               AND state.group_context_hash = prior.group_context_hash
               AND state.confirmation_tag = prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.next_generation
                       AND generation.superseded_seq = transition_row.entry_seq
                       AND generation.superseded_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind = 'resetActivation' THEN
        IF output_count <> 2 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states retired
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE retired.producing_transition_id = target_transition
               AND retired.conversation_id = transition_row.conversation_id
               AND retired.generation = transition_row.retired_generation
               AND retired.state_version = transition_row.retired_state_version
               AND retired.state_kind = 'resetRetirement'
               AND retired.lifecycle = 'superseded'
               AND retired.group_id = prior.group_id
               AND retired.epoch = prior.epoch
               AND retired.group_context_hash = prior.group_context_hash
               AND retired.confirmation_tag = prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.retired_generation
                       AND generation.superseded_seq = transition_row.entry_seq
                       AND generation.superseded_at = transition_row.accepted_at
               )
        ) OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states successor
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE successor.producing_transition_id = target_transition
               AND successor.conversation_id = transition_row.conversation_id
               AND successor.generation = transition_row.successor_generation
               AND successor.state_version = transition_row.successor_state_version
               AND successor.state_kind = 'resetSuccessor'
               AND successor.lifecycle = 'active'
               AND successor.epoch = 0
               AND successor.group_id <> prior.group_id
               AND successor.group_context_hash <> prior.group_context_hash
               AND successor.confirmation_tag <> prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.successor_generation
                       AND generation.activated_seq = transition_row.entry_seq
                       AND generation.activated_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'transition state output mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_metadata_snapshot_mapping(target_transition UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    transition_row chat.transitions%ROWTYPE;
    snapshot_row chat.metadata_snapshots%ROWTYPE;
    prior_snapshot chat.metadata_snapshots%ROWTYPE;
    snapshot_count BIGINT;
    requires_snapshot BOOLEAN;
BEGIN
    SELECT * INTO transition_row
      FROM chat.transitions
     WHERE transition_id = target_transition;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.metadata_snapshots
             WHERE producing_transition_id = target_transition
        ) THEN
            RAISE EXCEPTION 'metadata snapshot transition mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = transition_row.conversation_id
     FOR UPDATE;
    requires_snapshot := transition_row.kind IN (
        'creation','commit','metadata','leafRecovery','leaveCommit','resetActivation','directRequestPublication'
    );
    SELECT count(*) INTO snapshot_count
      FROM chat.metadata_snapshots
     WHERE producing_transition_id = target_transition;

    IF NOT requires_snapshot THEN
        IF snapshot_count <> 0 OR transition_row.metadata_snapshot_id IS NOT NULL THEN
            RAISE EXCEPTION 'transition unexpectedly carries metadata snapshot'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT * INTO snapshot_row
      FROM chat.metadata_snapshots
     WHERE producing_transition_id = target_transition;
    IF snapshot_count <> 1 OR NOT FOUND
       OR transition_row.metadata_snapshot_id IS DISTINCT FROM snapshot_row.metadata_snapshot_id
       OR snapshot_row.conversation_id <> transition_row.conversation_id
       OR snapshot_row.generation <> transition_row.next_generation
       OR snapshot_row.state_version <> transition_row.next_state_version
       OR snapshot_row.created_at <> transition_row.accepted_at THEN
        RAISE EXCEPTION 'metadata snapshot transition mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.transitions origin
          JOIN chat.devices device
            ON device.user_did = origin.actor_did
           AND device.device_id = origin.actor_device_id
           AND device.created_at <= origin.accepted_at
           AND (device.revoked_at IS NULL OR device.revoked_at >= origin.accepted_at)
         WHERE origin.transition_id = snapshot_row.origin_transition_id
           AND origin.conversation_id = snapshot_row.conversation_id
           AND origin.entry_seq = snapshot_row.author_origin_seq
           AND origin.actor_did = snapshot_row.author_did
           AND origin.actor_device_id = snapshot_row.author_device_id
           AND origin.actor_key_id = snapshot_row.author_key_id
           AND origin.actor_auth_generation = snapshot_row.author_auth_generation
           AND origin.actor_role = snapshot_row.author_role
           AND origin.actor_role = 'admin'
           AND origin.actor_device_status = snapshot_row.author_device_status
           AND origin.actor_device_status = 'active'
           AND origin.kind IN ('creation','metadata','resetActivation','directRequestPublication')
    ) THEN
        RAISE EXCEPTION 'metadata author proof mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF transition_row.kind IN ('creation','directRequestPublication') THEN
        IF snapshot_row.metadata_version <> 1
           OR snapshot_row.origin_transition_id <> target_transition
           OR (snapshot_row.avatar_blob_id IS NOT NULL AND (
                snapshot_row.avatar_binding_origin_transition_id <> target_transition
                OR snapshot_row.avatar_binding_metadata_version <> 1
                OR snapshot_row.avatar_binding_owner_did <> snapshot_row.author_did
                OR snapshot_row.avatar_binding_owner_device_id <> snapshot_row.author_device_id
           ))
           OR (snapshot_row.author_did, snapshot_row.author_device_id,
               snapshot_row.author_key_id, snapshot_row.author_auth_generation)
              IS DISTINCT FROM
              (transition_row.actor_did, transition_row.actor_device_id,
               transition_row.actor_key_id, transition_row.actor_auth_generation) THEN
            RAISE EXCEPTION 'creation metadata snapshot mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT snapshot.* INTO prior_snapshot
      FROM chat.metadata_snapshots snapshot
      JOIN chat.transitions producer
        ON producer.transition_id = snapshot.producing_transition_id
     WHERE snapshot.conversation_id = transition_row.conversation_id
       AND snapshot.generation = transition_row.prior_generation
       AND producer.entry_seq < transition_row.entry_seq
     ORDER BY producer.entry_seq DESC
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'metadata predecessor snapshot missing'
            USING ERRCODE = '23514';
    END IF;

    IF transition_row.kind = 'metadata' THEN
        IF snapshot_row.metadata_version <> prior_snapshot.metadata_version + 1
           OR snapshot_row.origin_transition_id <> target_transition
           OR (
                snapshot_row.avatar_blob_id IS NOT DISTINCT FROM prior_snapshot.avatar_blob_id
                AND (snapshot_row.avatar_binding_origin_transition_id,
                     snapshot_row.avatar_binding_metadata_version,
                     snapshot_row.avatar_binding_owner_did,
                     snapshot_row.avatar_binding_owner_device_id)
                    IS DISTINCT FROM
                    (prior_snapshot.avatar_binding_origin_transition_id,
                     prior_snapshot.avatar_binding_metadata_version,
                     prior_snapshot.avatar_binding_owner_did,
                     prior_snapshot.avatar_binding_owner_device_id)
           )
           OR (
                snapshot_row.avatar_blob_id IS DISTINCT FROM prior_snapshot.avatar_blob_id
                AND snapshot_row.avatar_blob_id IS NOT NULL
                AND (snapshot_row.avatar_binding_origin_transition_id,
                     snapshot_row.avatar_binding_metadata_version,
                     snapshot_row.avatar_binding_owner_did,
                     snapshot_row.avatar_binding_owner_device_id)
                    IS DISTINCT FROM
                    (target_transition, snapshot_row.metadata_version,
                     snapshot_row.author_did, snapshot_row.author_device_id)
           )
           OR (snapshot_row.author_did, snapshot_row.author_device_id,
               snapshot_row.author_key_id, snapshot_row.author_auth_generation)
              IS DISTINCT FROM
              (transition_row.actor_did, transition_row.actor_device_id,
               transition_row.actor_key_id, transition_row.actor_auth_generation) THEN
            RAISE EXCEPTION 'metadata update version or author mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN ('commit','leafRecovery','leaveCommit') THEN
        IF (snapshot_row.metadata_version, snapshot_row.origin_transition_id,
            snapshot_row.ciphertext_size,
            snapshot_row.avatar_blob_id, snapshot_row.avatar_ciphertext_sha256,
            snapshot_row.avatar_ciphertext_size, snapshot_row.avatar_purpose,
            snapshot_row.avatar_binding_origin_transition_id,
            snapshot_row.avatar_binding_metadata_version,
            snapshot_row.avatar_binding_owner_did,
            snapshot_row.avatar_binding_owner_device_id,
            snapshot_row.author_did, snapshot_row.author_device_id,
            snapshot_row.author_key_id, snapshot_row.author_public_key,
            snapshot_row.author_auth_generation, snapshot_row.author_origin_seq,
            snapshot_row.author_role, snapshot_row.author_device_status)
           IS DISTINCT FROM
           (prior_snapshot.metadata_version, prior_snapshot.origin_transition_id,
            prior_snapshot.ciphertext_size,
            prior_snapshot.avatar_blob_id, prior_snapshot.avatar_ciphertext_sha256,
            prior_snapshot.avatar_ciphertext_size, prior_snapshot.avatar_purpose,
            prior_snapshot.avatar_binding_origin_transition_id,
            prior_snapshot.avatar_binding_metadata_version,
            prior_snapshot.avatar_binding_owner_did,
            prior_snapshot.avatar_binding_owner_device_id,
            prior_snapshot.author_did, prior_snapshot.author_device_id,
            prior_snapshot.author_key_id, prior_snapshot.author_public_key,
            prior_snapshot.author_auth_generation, prior_snapshot.author_origin_seq,
            prior_snapshot.author_role, prior_snapshot.author_device_status) THEN
            RAISE EXCEPTION 'epoch transition metadata provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind = 'resetActivation' THEN
        IF NOT (
            (snapshot_row.metadata_version, snapshot_row.origin_transition_id,
             snapshot_row.ciphertext_size,
             snapshot_row.avatar_blob_id, snapshot_row.avatar_ciphertext_sha256,
             snapshot_row.avatar_ciphertext_size, snapshot_row.avatar_purpose,
             snapshot_row.avatar_binding_origin_transition_id,
             snapshot_row.avatar_binding_metadata_version,
             snapshot_row.avatar_binding_owner_did,
             snapshot_row.avatar_binding_owner_device_id,
             snapshot_row.author_did, snapshot_row.author_device_id,
             snapshot_row.author_key_id, snapshot_row.author_public_key,
             snapshot_row.author_auth_generation, snapshot_row.author_origin_seq,
             snapshot_row.author_role, snapshot_row.author_device_status)
            IS NOT DISTINCT FROM
            (prior_snapshot.metadata_version, prior_snapshot.origin_transition_id,
             prior_snapshot.ciphertext_size,
             prior_snapshot.avatar_blob_id, prior_snapshot.avatar_ciphertext_sha256,
             prior_snapshot.avatar_ciphertext_size, prior_snapshot.avatar_purpose,
             prior_snapshot.avatar_binding_origin_transition_id,
             prior_snapshot.avatar_binding_metadata_version,
             prior_snapshot.avatar_binding_owner_did,
             prior_snapshot.avatar_binding_owner_device_id,
             prior_snapshot.author_did, prior_snapshot.author_device_id,
             prior_snapshot.author_key_id, prior_snapshot.author_public_key,
             prior_snapshot.author_auth_generation, prior_snapshot.author_origin_seq,
             prior_snapshot.author_role, prior_snapshot.author_device_status)
            OR (
                snapshot_row.metadata_version = prior_snapshot.metadata_version + 1
                AND snapshot_row.origin_transition_id = target_transition
                AND snapshot_row.avatar_blob_id IS NULL
                AND snapshot_row.author_did = transition_row.actor_did
                AND snapshot_row.author_device_id = transition_row.actor_device_id
                AND snapshot_row.author_key_id = transition_row.actor_key_id
                AND snapshot_row.author_auth_generation = transition_row.actor_auth_generation
            )
        ) THEN
            RAISE EXCEPTION 'reset metadata snapshot mismatch'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.enforce_roster_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    conversation_kind TEXT;
    conversation_lifecycle TEXT;
    direct_did_low TEXT;
    direct_did_high TEXT;
    current_count BIGINT;
    active_admin_count BIGINT;
    invalid_pending_count BIGINT;
    pending_with_leaf_count BIGINT;
    invalid_direct_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN target_conversation := OLD.conversation_id;
    ELSE target_conversation := NEW.conversation_id;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT kind, lifecycle, c.direct_did_low, c.direct_did_high
      INTO conversation_kind, conversation_lifecycle, direct_did_low, direct_did_high
      FROM chat.conversations c WHERE c.conversation_id = target_conversation;
    SELECT count(*),
           count(*) FILTER (WHERE status = 'active' AND role = 'admin'),
           count(*) FILTER (WHERE status = 'pending' AND (
               (conversation_kind = 'group' AND role <> 'member')
               OR (conversation_kind = 'direct' AND role <> 'admin')
           ))
      INTO current_count, active_admin_count, invalid_pending_count
      FROM chat.participants
     WHERE conversation_id = target_conversation AND current_membership;
    SELECT count(*) INTO pending_with_leaf_count
      FROM chat.participants p
     WHERE p.conversation_id = target_conversation
       AND p.current_membership
       AND p.status = 'pending'
       AND EXISTS (
           SELECT 1 FROM chat.member_devices m
           WHERE m.participant_period_id = p.participant_period_id AND m.active
             AND NOT chat.is_authorized_pending_request_leaf(m.leaf_period_id)
       );
    SELECT count(*) INTO invalid_direct_count
      FROM chat.participants participant
     WHERE participant.conversation_id = target_conversation
       AND participant.current_membership
       AND conversation_kind = 'direct'
       AND (participant.user_did NOT IN (direct_did_low, direct_did_high)
            OR participant.role <> 'admin');
    IF conversation_lifecycle = 'active' THEN
        IF current_count < 1 OR current_count > 100 OR active_admin_count < 1
           OR invalid_pending_count <> 0 OR pending_with_leaf_count <> 0
           OR (conversation_kind = 'direct'
               AND (current_count <> 2 OR invalid_direct_count <> 0)) THEN
            RAISE EXCEPTION 'logical roster invariant violated' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_leaf_invariants(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_lifecycle TEXT;
    current_generation BIGINT;
    active_leaf_count BIGINT;
    expected_leaf_count BIGINT;
    stale_active_leaf_count BIGINT;
    invalid_owner_count BIGINT;
    over_limit_dids BIGINT;
BEGIN
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT lifecycle, c.current_generation
      INTO conversation_lifecycle, current_generation
      FROM chat.conversations c WHERE c.conversation_id = target_conversation;
    SELECT s.leaf_count INTO expected_leaf_count
      FROM chat.conversations c
      JOIN chat.generation_states s
        ON s.conversation_id = c.conversation_id
       AND s.generation = c.current_generation
       AND s.state_version = c.current_state_version
     WHERE c.conversation_id = target_conversation;
    SELECT count(*) INTO active_leaf_count
      FROM chat.member_devices
     WHERE conversation_id = target_conversation
       AND generation = current_generation
       AND active;
    SELECT count(*) INTO stale_active_leaf_count
      FROM chat.member_devices
     WHERE conversation_id = target_conversation
       AND generation <> current_generation
       AND active;
    SELECT count(*) INTO invalid_owner_count
      FROM chat.member_devices m
      LEFT JOIN chat.participants p
        ON p.participant_period_id = m.participant_period_id
       AND p.conversation_id = m.conversation_id
     WHERE m.conversation_id = target_conversation
       AND m.generation = current_generation
       AND m.active
       AND ((p.status IS DISTINCT FROM 'active' AND NOT chat.is_authorized_pending_request_leaf(m.leaf_period_id)) OR NOT p.current_membership
            OR p.user_did IS DISTINCT FROM m.user_did);
    SELECT count(*) INTO over_limit_dids FROM (
        SELECT user_did
          FROM chat.member_devices
         WHERE conversation_id = target_conversation
           AND generation = current_generation AND active
         GROUP BY user_did HAVING count(*) > 20
    ) limits;
    IF conversation_lifecycle = 'active'
       AND (active_leaf_count < 1 OR active_leaf_count > 100
            OR active_leaf_count IS DISTINCT FROM expected_leaf_count
            OR stale_active_leaf_count <> 0
            OR invalid_owner_count <> 0 OR over_limit_dids <> 0) THEN
        RAISE EXCEPTION 'MLS leaf invariant violated' USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_entry_transition_mapping(target_transition UUID)
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
               WHEN 'directRequestPublication' THEN 'blue.catbird.chat.defs#directRequestEntry'
               WHEN 'directRequestAcceptance' THEN 'blue.catbird.chat.defs#directRequestAcceptanceEntry'
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

CREATE OR REPLACE FUNCTION chat.assert_participant_provenance(target_participant UUID)
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
               AND transition.kind IN ('creation','directRequestPublication')
               AND transition.actor_did = participant_row.created_by_did
               AND transition.actor_device_id = participant_row.created_by_device_id
               AND entry.entry_kind = CASE transition.kind WHEN 'creation' THEN 'blue.catbird.chat.defs#creationEntry'
                    ELSE 'blue.catbird.chat.defs#directRequestEntry' END
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
                    OR (entry.entry_kind='blue.catbird.chat.defs#directRequestEntry'
                        AND transition.kind='directRequestPublication'
                        AND EXISTS (SELECT 1 FROM chat.direct_request_publications p WHERE p.request_id=transition.transition_id
                            AND p.recipient_did=participant_row.user_did))
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
           AND ((entry.entry_kind='blue.catbird.chat.defs#participantAcceptanceEntry' AND transition.kind='acceptConversation')
                OR (entry.entry_kind='blue.catbird.chat.defs#directRequestAcceptanceEntry' AND transition.kind='directRequestAcceptance'))
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
                OR (role_transition.kind='directRequestPublication'
                    AND role_entry.entry_kind='blue.catbird.chat.defs#directRequestEntry')
                OR (role_transition.kind = 'policy'
                    AND role_entry.entry_kind = 'blue.catbird.chat.defs#policyEntry'))
           AND (
                (participant_row.role_transition_id = participant_row.invitation_transition_id
                 AND role_transition.kind IN ('creation','policy','directRequestPublication'))
                OR (participant_row.invitation_transition_id IS NULL
                    AND role_transition.kind IN ('creation','directRequestPublication'))
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

CREATE OR REPLACE FUNCTION chat.assert_member_interval_mapping(target_leaf UUID)
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
               AND (participant.status='active' OR chat.direct_request_leaf_has_provenance(member_row.leaf_period_id))
               AND participant.created_at <= opening_transition.accepted_at
               AND (participant.accepted_at IS NULL
                    OR participant.accepted_at <= opening_transition.accepted_at
                    OR chat.direct_request_leaf_has_provenance(member_row.leaf_period_id))
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


    IF opening_transition.kind='directRequestPublication' THEN
        IF interval_row.opening_kind<>'directRequest'
           OR NOT chat.direct_request_leaf_has_provenance(member_row.leaf_period_id) THEN
            RAISE EXCEPTION 'request leaf opening provenance mismatch' USING ERRCODE='23514'; END IF;
    ELSIF member_row.origin = 'genesis' THEN
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
                interval_row.closing_kind IN ('reset','directRequest')
                AND NOT (
                    closing_transition.kind = CASE interval_row.closing_kind WHEN 'reset' THEN 'resetActivation' ELSE 'directRequestPublication' END
                    AND closing_transition.retired_generation = member_row.generation
                    AND closing_transition.retired_state_version = member_row.removed_state_version
                )
           )
           OR (
                interval_row.closing_kind NOT IN ('reset','directRequest')
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

CREATE OR REPLACE FUNCTION chat.assert_application_interval_provenance(target_interval UUID)
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
                OR (interval_row.opening_kind='directRequest'
                    AND transition.kind='directRequestPublication'
                    AND state.state_kind='directRequestPublication'
                    AND chat.direct_request_leaf_has_provenance(interval_row.opening_leaf_period_id))
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
                OR (interval_row.closing_kind='directRequest' AND transition.kind='directRequestPublication')
                OR
                (interval_row.closing_kind = 'terminal'
                 AND transition.kind = 'closeConversation')
           )
    ) THEN
        RAISE EXCEPTION 'application interval provenance mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF interval_row.closing_kind IN ('remove','replace','reset','directRequest') AND NOT EXISTS (
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

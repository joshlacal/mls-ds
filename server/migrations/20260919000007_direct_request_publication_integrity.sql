-- Complete reverse mappings for the dedicated request publication edge.
-- Earlier applied migration bytes remain unchanged. The SQL graph must reject
-- a published tombstone without effects and effects without its tombstone.


CREATE OR REPLACE FUNCTION chat.assert_direct_request_publication(target_request UUID)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE p chat.direct_request_publications%ROWTYPE;
        a chat.direct_request_attempts%ROWTYPE;
        selected_count BIGINT;
BEGIN
    SELECT * INTO a FROM chat.direct_request_attempts WHERE request_id=target_request;
    SELECT * INTO p FROM chat.direct_request_publications WHERE request_id=target_request;
    IF NOT FOUND THEN
        IF a.status='published' OR EXISTS (SELECT 1 FROM chat.transitions WHERE transition_id=target_request AND kind='directRequestPublication') THEN
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
    IF NOT EXISTS (
        SELECT 1 FROM chat.generation_states state
        JOIN chat.metadata_snapshots metadata
          ON metadata.producing_transition_id=p.request_id
         AND metadata.conversation_id=state.conversation_id
         AND metadata.generation=state.generation AND metadata.state_version=state.state_version
        CROSS JOIN LATERAL (SELECT convert_from(p.signed_publication,'UTF8')::jsonb AS signed) wrapper
        CROSS JOIN LATERAL (SELECT wrapper.signed->'body' AS b) body
        WHERE state.conversation_id=p.conversation_id AND state.generation=p.generation
          AND state.state_version=p.state_version AND state.producing_transition_id=p.request_id
          AND state.state_kind='directRequestPublication'
          AND body.b->>'requestId'=p.request_id::text
          AND body.b->>'conversationId'=p.conversation_id::text
          AND body.b->>'firstMessageId'=p.first_message_id::text
          AND body.b->>'actorDid'=p.actor_did AND body.b->>'recipientDid'=p.recipient_did
          AND body.b->>'actorDeviceId'=p.actor_device_id::text AND body.b->>'keyId'=p.actor_key_id
          AND (body.b->>'authGeneration')::bigint=p.actor_auth_generation
          AND decode(body.b->>'contextHash','base64')=p.context_hash
          AND decode(body.b->>'preparationDigest','base64')=p.preparation_digest
          AND convert_from(p.request_entry,'UTF8')::jsonb->'signedRequest'=wrapper.signed
          AND decode(body.b#>>'{artifacts,finalGroupInfo,bytes}','base64')=p.final_group_info
          AND decode(body.b#>>'{artifacts,welcome,opaqueWelcome}','base64')=p.full_welcome
          AND decode(body.b#>>'{artifacts,initialCiphertext}','base64')=p.initial_ciphertext
          AND body.b#>'{artifacts,metadataSnapshot}'=convert_from(p.metadata_snapshot,'UTF8')::jsonb
          AND decode(body.b#>>'{artifacts,metadataSnapshot,ciphertext}','base64')=metadata.ciphertext
          AND decode(body.b#>>'{artifacts,metadataSnapshot,nonce}','base64')=metadata.nonce
          AND (body.b->>'importUntil')::timestamptz=p.import_until
          AND state.leaf_count=(SELECT count(*)+1 FROM chat.direct_request_selected_devices WHERE request_id=target_request)
    ) THEN RAISE EXCEPTION 'request publication artifact graph mismatch' USING ERRCODE='23514'; END IF;
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

CREATE OR REPLACE FUNCTION chat.direct_request_leaf_has_provenance(target_leaf UUID)
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
                  AND g.capability_revision=s.capability_revision
                  AND (g.revision,g.grant_digest,g.key_package_ref,g.owner_did,g.owner_device_id,g.owner_key_id,g.auth_generation)
                    =(d.grant_revision,d.grant_digest,d.key_package_ref,d.owner_did,d.owner_device_id,d.owner_key_id,d.auth_generation)
                  AND d.import_until=p.import_until AND d.import_until<=g.expires_at
                  AND d.import_until<=k.not_after AND k.usage_scope='direct-request'
                  AND k.status='consumed' AND k.terminal_transition_id=p.request_id
                  AND k.terminal_at=p.created_at
            )))
    )
$$;

CREATE CONSTRAINT TRIGGER direct_request_selection_publication_complete
    AFTER INSERT ON chat.direct_request_selected_devices DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_publication();
CREATE FUNCTION chat.enforce_request_member_publication() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN PERFORM chat.assert_direct_request_publication(OLD.joined_transition_id); END IF;
    IF TG_OP<>'DELETE' THEN PERFORM chat.assert_direct_request_publication(NEW.joined_transition_id); END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_member_publication_complete
    AFTER INSERT OR UPDATE OR DELETE ON chat.member_devices DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_request_member_publication();


CREATE OR REPLACE FUNCTION chat.assert_entry_recipient_mapping(
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
    -- Resolve the audience row jointly with the entry it addresses. The JOIN to
    -- chat.entries makes the audience-to-entry binding structural: the row is
    -- only ever evaluated against the exact entry at its (conversation, seq).
    SELECT recipient.entitlement_kind
      INTO recipient_kind
      FROM chat.entry_recipients recipient
      JOIN chat.entries entry
        ON entry.conversation_id = recipient.conversation_id
       AND entry.seq = recipient.seq
     WHERE recipient.conversation_id = target_conversation
       AND recipient.seq = target_seq
       AND recipient.user_did = target_did
       AND recipient.device_id = target_device;
    IF NOT FOUND THEN RETURN; END IF;

    -- An audience row must never attach to an application entry, on any arm. The
    -- intervalClose/scheduleTerminal arms are additionally bound to the exact
    -- closing/terminal transition + outer fingerprint by their provenance FKs
    -- (application_intervals_closing_provenance_fk /
    -- application_schedule_terminal_proofs_provenance_fk). This guard closes the
    -- previously unguarded 'control' entitlement and any other attempt to route
    -- an audience row at an application seq.
    IF NOT EXISTS (
        SELECT 1
          FROM chat.entry_recipients recipient
          JOIN chat.entries entry
            ON entry.conversation_id = recipient.conversation_id
           AND entry.seq = recipient.seq
         WHERE recipient.conversation_id = target_conversation
           AND recipient.seq = target_seq
           AND recipient.user_did = target_did
           AND recipient.device_id = target_device
           AND entry.entry_kind <> 'blue.catbird.chat.defs#applicationEntry'
    ) THEN
        RAISE EXCEPTION 'entry recipient audience on application entry'
            USING ERRCODE = '23514';
    END IF;

    -- Positive control-arm check: a 'control' audience row must bind a
    -- non-application control entry (not merely "not an application entry" by
    -- omission -- the entry must exist and be a non-application entry_kind).
    IF recipient_kind = 'control' AND NOT EXISTS (
        SELECT 1
          FROM chat.entries entry
         WHERE entry.conversation_id = target_conversation
           AND entry.seq = target_seq
           AND entry.entry_kind <> 'blue.catbird.chat.defs#applicationEntry'
    ) THEN
        RAISE EXCEPTION 'control audience must bind a non-application entry'
            USING ERRCODE = '23514';
    END IF;

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
           AND interval.closing_kind IN ('remove','replace','reset','directRequest')
    ) THEN
        RAISE EXCEPTION 'entry recipient entitlement mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_application_terminal_proof(
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
                    latest.closing_kind IN ('remove','reset','directRequest')
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

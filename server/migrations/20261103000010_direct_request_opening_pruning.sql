-- O7 for the C33 opening. A published direct request carries its first
-- application ciphertext in `signedRequest.body.artifacts.initialCiphertext`.
-- Once the opening's frozen recipient audience acknowledged its seq, or its
-- sender's account is deleted, that ciphertext leaves both homes. The signed
-- evidence stays: every original digest, the sender signature, the I13
-- `sequencerReceipt`, the `publicationReceipt` and a retained redacted entry
-- whose `initialCiphertext` is replaced by that ciphertext's SHA-256. The
-- sender signature can then no longer be re-verified, so coordinator hydration
-- binds the redacted body to the coordinator's own signed publication receipt.
--
-- Signed requests end their signature domains in "\u0000", which PostgreSQL
-- json/jsonb reject, so SQL never parses entry JSON: the single Rust writer
-- derives every redacted form; SQL captures raw digests and allows exactly one
-- irreversible prune per copy.

-- 1. Coordinator: chat.entries keeps the redacted opening row once pruned.
ALTER TABLE chat.entries ADD COLUMN pruned_payload_bytes BYTEA;

ALTER TABLE chat.entries DROP CONSTRAINT entries_payload_hash_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_payload_hash_check CHECK (
    (payload_pruned_at IS NULL
        AND pruned_payload_bytes IS NULL
        AND accepted_payload_bytes IS NOT NULL
        AND octet_length(accepted_payload_bytes) BETWEEN 1 AND 16777216
        AND signed_request_bytes IS NOT NULL
        AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(accepted_payload_sha256) = 32
        AND accepted_payload_sha256 = digest(accepted_payload_bytes, 'sha256'))
    OR (payload_pruned_at IS NOT NULL
        AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'
        AND pruned_payload_bytes IS NULL
        AND accepted_payload_bytes IS NULL
        AND signed_request_bytes IS NULL
        AND octet_length(accepted_payload_sha256) = 32)
    OR (payload_pruned_at IS NOT NULL
        AND entry_kind = 'blue.catbird.chat.defs#directRequestEntry'
        AND pruned_payload_bytes IS NOT NULL
        AND octet_length(pruned_payload_bytes) BETWEEN 1 AND 16777216
        AND accepted_payload_bytes IS NULL
        AND signed_request_bytes IS NULL
        AND octet_length(accepted_payload_sha256) = 32)
);

CREATE OR REPLACE FUNCTION chat.enforce_entries_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_cols CONSTANT TEXT[] := ARRAY[
        'accepted_payload_bytes',
        'signed_request_bytes',
        'payload_pruned_at',
        'sequencer_receipt_bytes',
        'pruned_payload_bytes'
    ];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_cols) IS DISTINCT FROM (to_jsonb(OLD) - mutable_cols) THEN
        RAISE EXCEPTION 'immutable identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF OLD.sequencer_receipt_bytes IS NOT NULL
       AND NEW.sequencer_receipt_bytes IS DISTINCT FROM OLD.sequencer_receipt_bytes THEN
        RAISE EXCEPTION 'sequencer receipt cannot be rewritten: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.accepted_payload_bytes, NEW.signed_request_bytes, NEW.payload_pruned_at,
        NEW.pruned_payload_bytes)
       IS DISTINCT FROM
       (OLD.accepted_payload_bytes, OLD.signed_request_bytes, OLD.payload_pruned_at,
        OLD.pruned_payload_bytes) THEN
        IF NOT (
            OLD.payload_pruned_at IS NULL
            AND NEW.payload_pruned_at IS NOT NULL
            AND NEW.accepted_payload_bytes IS NULL
            AND NEW.signed_request_bytes IS NULL
            AND ((OLD.entry_kind = 'blue.catbird.chat.defs#applicationEntry'
                    AND NEW.pruned_payload_bytes IS NULL)
                 OR (OLD.entry_kind = 'blue.catbird.chat.defs#directRequestEntry'
                    AND NEW.pruned_payload_bytes IS NOT NULL))
        ) THEN
            RAISE EXCEPTION 'only unpruned applicationEntry or directRequestEntry ciphertext may be pruned, once'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- Both copies of an opening lose their bytes in one transaction; every other
-- mapped column still matches exactly.
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
           AND entry.signed_request_bytes IS NOT DISTINCT FROM transition_row.signed_request_bytes
           AND (entry.payload_pruned_at IS NULL) = (transition_row.payload_pruned_at IS NULL)
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

-- 2. Coordinator: the publication transition loses its signed wrapper, unsigned
--    projection and transcript; its digest and signature stay.
ALTER TABLE chat.transitions
    ALTER COLUMN signed_request_bytes DROP NOT NULL,
    ALTER COLUMN unsigned_projection_bytes DROP NOT NULL,
    ALTER COLUMN signing_transcript_bytes DROP NOT NULL,
    ADD COLUMN payload_pruned_at TIMESTAMPTZ;

ALTER TABLE chat.transitions DROP CONSTRAINT transitions_signature_check;
ALTER TABLE chat.transitions ADD CONSTRAINT transitions_signature_check CHECK (
    (payload_pruned_at IS NULL
        AND signed_request_bytes IS NOT NULL
        AND unsigned_projection_bytes IS NOT NULL
        AND signing_transcript_bytes IS NOT NULL
        AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(unsigned_projection_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32 AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64)
    OR (payload_pruned_at IS NOT NULL
        AND kind = 'directRequestPublication'
        AND signed_request_bytes IS NULL
        AND unsigned_projection_bytes IS NULL
        AND signing_transcript_bytes IS NULL
        AND octet_length(request_digest) = 32
        AND octet_length(signature) = 64)
);

CREATE FUNCTION chat.enforce_transitions_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    opening_cols CONSTANT TEXT[] := ARRAY['signed_request_bytes', 'unsigned_projection_bytes',
        'signing_transcript_bytes', 'payload_pruned_at'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable chat row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - opening_cols) IS DISTINCT FROM (to_jsonb(OLD) - opening_cols) THEN
        RAISE EXCEPTION 'immutable chat identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.signed_request_bytes, NEW.unsigned_projection_bytes, NEW.signing_transcript_bytes,
        NEW.payload_pruned_at)
       IS DISTINCT FROM
       (OLD.signed_request_bytes, OLD.unsigned_projection_bytes, OLD.signing_transcript_bytes,
        OLD.payload_pruned_at)
       AND NOT (OLD.kind = 'directRequestPublication'
                AND OLD.payload_pruned_at IS NULL
                AND NEW.payload_pruned_at IS NOT NULL
                AND NEW.signed_request_bytes IS NULL
                AND NEW.unsigned_projection_bytes IS NULL
                AND NEW.signing_transcript_bytes IS NULL) THEN
        RAISE EXCEPTION 'only an unpruned direct-request opening transition may lose its ciphertext, once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER transitions_immutable ON chat.transitions;
CREATE TRIGGER transitions_immutable
BEFORE UPDATE OR DELETE ON chat.transitions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_transitions_immutable();

-- 3. Coordinator: the publication row drops its opening copies (signed
--    publication, request entry, initial ciphertext); the Welcome, GroupInfo and
--    metadata snapshot stay until the existing terminal prune. Pruned artifacts
--    never return.
ALTER TABLE chat.direct_request_publications ADD COLUMN opening_pruned_at TIMESTAMPTZ;

ALTER TABLE chat.direct_request_publications DROP CONSTRAINT direct_request_publications_prune_shape;
ALTER TABLE chat.direct_request_publications ADD CONSTRAINT direct_request_publications_prune_shape CHECK (
    (pruned_at IS NULL AND opening_pruned_at IS NULL
     AND signed_publication IS NOT NULL AND request_entry IS NOT NULL
     AND final_group_info IS NOT NULL AND full_welcome IS NOT NULL
     AND initial_ciphertext IS NOT NULL AND metadata_snapshot IS NOT NULL)
 OR (pruned_at IS NULL AND opening_pruned_at IS NOT NULL
     AND signed_publication IS NULL AND request_entry IS NULL AND initial_ciphertext IS NULL
     AND final_group_info IS NOT NULL AND full_welcome IS NOT NULL
     AND metadata_snapshot IS NOT NULL)
 OR (pruned_at IS NOT NULL AND signed_publication IS NULL AND request_entry IS NULL
     AND final_group_info IS NULL AND full_welcome IS NULL
     AND initial_ciphertext IS NULL AND metadata_snapshot IS NULL)
);

DROP TRIGGER direct_request_publications_immutable ON chat.direct_request_publications;
CREATE TRIGGER direct_request_publications_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_publications
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
        'signed_publication','request_entry','final_group_info','full_welcome',
        'initial_ciphertext','metadata_snapshot','pruned_at','opening_pruned_at'
    );

CREATE FUNCTION chat.enforce_direct_request_artifacts_never_return()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.signed_publication IS NOT NULL AND NEW.signed_publication IS DISTINCT FROM OLD.signed_publication)
       OR (NEW.request_entry IS NOT NULL AND NEW.request_entry IS DISTINCT FROM OLD.request_entry)
       OR (NEW.final_group_info IS NOT NULL AND NEW.final_group_info IS DISTINCT FROM OLD.final_group_info)
       OR (NEW.full_welcome IS NOT NULL AND NEW.full_welcome IS DISTINCT FROM OLD.full_welcome)
       OR (NEW.initial_ciphertext IS NOT NULL AND NEW.initial_ciphertext IS DISTINCT FROM OLD.initial_ciphertext)
       OR (NEW.metadata_snapshot IS NOT NULL AND NEW.metadata_snapshot IS DISTINCT FROM OLD.metadata_snapshot)
       OR (OLD.pruned_at IS NOT NULL AND NEW.pruned_at IS DISTINCT FROM OLD.pruned_at)
       OR (OLD.opening_pruned_at IS NOT NULL AND NEW.opening_pruned_at IS DISTINCT FROM OLD.opening_pruned_at) THEN
        RAISE EXCEPTION 'pruned direct request artifacts never return' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER direct_request_publications_artifacts_never_return
BEFORE UPDATE ON chat.direct_request_publications
FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_artifacts_never_return();

-- 4. Peer home: each inbox row freezes its opening digests at insert and later
--    trades the opening for the redacted entry exactly once.
ALTER TABLE chat.direct_request_transport_inbox
    ADD COLUMN request_entry_sha256 BYTEA,
    ADD COLUMN signed_publication_sha256 BYTEA,
    ADD COLUMN redacted_request_entry BYTEA,
    ADD COLUMN opening_pruned_at TIMESTAMPTZ;

UPDATE chat.direct_request_transport_inbox
   SET request_entry_sha256 = digest(request_entry, 'sha256'),
       signed_publication_sha256 = digest(signed_publication, 'sha256');

ALTER TABLE chat.direct_request_transport_inbox
    ALTER COLUMN request_entry_sha256 SET NOT NULL,
    ALTER COLUMN signed_publication_sha256 SET NOT NULL,
    ALTER COLUMN request_entry DROP NOT NULL,
    ALTER COLUMN signed_publication DROP NOT NULL,
    ADD CONSTRAINT transport_inbox_opening_shape_check CHECK (
        octet_length(request_entry_sha256) = 32
        AND octet_length(signed_publication_sha256) = 32
        AND ((opening_pruned_at IS NULL
                AND request_entry IS NOT NULL
                AND signed_publication IS NOT NULL
                AND redacted_request_entry IS NULL)
             OR (opening_pruned_at IS NOT NULL
                AND request_entry IS NULL
                AND signed_publication IS NULL
                AND redacted_request_entry IS NOT NULL
                AND octet_length(redacted_request_entry) BETWEEN 1 AND 16777216))
    );

CREATE FUNCTION chat.capture_transport_inbox_opening_digests()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.opening_pruned_at IS NOT NULL OR NEW.redacted_request_entry IS NOT NULL THEN
        RAISE EXCEPTION 'new transport inbox rows carry their original opening'
            USING ERRCODE = '23514';
    END IF;
    NEW.request_entry_sha256 := digest(NEW.request_entry, 'sha256');
    NEW.signed_publication_sha256 := digest(NEW.signed_publication, 'sha256');
    RETURN NEW;
END;
$$;

CREATE TRIGGER transport_inbox_capture_opening_digests
BEFORE INSERT ON chat.direct_request_transport_inbox
FOR EACH ROW EXECUTE FUNCTION chat.capture_transport_inbox_opening_digests();

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_inbox_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'transport inbox rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.delivery_id <> OLD.delivery_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.first_message_id <> OLD.first_message_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.sender_device_id IS DISTINCT FROM OLD.sender_device_id
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.recipient_device_id <> OLD.recipient_device_id
       OR NEW.full_welcome <> OLD.full_welcome
       OR NEW.full_welcome_sha256 <> OLD.full_welcome_sha256
       OR NEW.created_at <> OLD.created_at
       OR NEW.request_entry_sha256 IS DISTINCT FROM OLD.request_entry_sha256
       OR NEW.signed_publication_sha256 IS DISTINCT FROM OLD.signed_publication_sha256
       OR NEW.provenance <> OLD.provenance
       OR NEW.publication_receipt <> OLD.publication_receipt
       OR NEW.import_until <> OLD.import_until THEN
        RAISE EXCEPTION 'transport inbox immutable identity cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF (NEW.request_entry, NEW.signed_publication, NEW.redacted_request_entry,
        NEW.opening_pruned_at)
       IS DISTINCT FROM
       (OLD.request_entry, OLD.signed_publication, OLD.redacted_request_entry,
        OLD.opening_pruned_at)
       AND NOT (OLD.opening_pruned_at IS NULL
                AND NEW.opening_pruned_at IS NOT NULL
                AND NEW.request_entry IS NULL
                AND NEW.signed_publication IS NULL
                AND NEW.redacted_request_entry IS NOT NULL) THEN
        RAISE EXCEPTION 'transport inbox opening permits only one irreversible ciphertext prune'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'pending' AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal transport inbox status is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- 5. Peer home: the opening's transport copy captures its pruned projection at
--    insert, exactly as application copies do, and is pruned to it once.
ALTER TABLE chat.direct_request_transport_entries ADD COLUMN opening_request_id UUID;

ALTER TABLE chat.direct_request_transport_entries
    DROP CONSTRAINT transport_application_evidence_check;
ALTER TABLE chat.direct_request_transport_entries
    ADD CONSTRAINT transport_application_evidence_check CHECK (
        (application_message_id IS NULL AND application_request_sha256 IS NULL
            AND application_metadata_bytes IS NULL AND application_generation IS NULL
            AND opening_request_id IS NULL
            AND pruned_entry_bytes IS NULL AND payload_pruned_at IS NULL)
        OR (NOT evidence_pending AND opening_request_id IS NULL
            AND application_message_id IS NOT NULL AND chat.is_uuid_v4(application_message_id)
            AND application_request_sha256 IS NOT NULL
            AND octet_length(application_request_sha256) = 32
            AND application_metadata_bytes IS NOT NULL
            AND octet_length(application_metadata_bytes) BETWEEN 1 AND 16777216
            AND application_generation IS NOT NULL
            AND chat.is_safe_integer(application_generation)
            AND pruned_entry_bytes IS NOT NULL
            AND octet_length(pruned_entry_bytes) BETWEEN 1 AND 16777216
            AND (payload_pruned_at IS NULL OR entry_bytes = pruned_entry_bytes))
        OR (NOT evidence_pending
            AND application_message_id IS NULL AND application_request_sha256 IS NULL
            AND application_metadata_bytes IS NULL AND application_generation IS NULL
            AND opening_request_id IS NOT NULL AND chat.is_uuid_v4(opening_request_id)
            AND pruned_entry_bytes IS NOT NULL
            AND octet_length(pruned_entry_bytes) BETWEEN 1 AND 16777216
            AND (payload_pruned_at IS NULL OR entry_bytes = pruned_entry_bytes))
    );

CREATE INDEX transport_opening_request_idx
    ON chat.direct_request_transport_entries (conversation_id, opening_request_id)
    WHERE opening_request_id IS NOT NULL;

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_entries_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    evidence CONSTANT TEXT[] := ARRAY['application_message_id', 'application_request_sha256',
        'application_metadata_bytes', 'application_generation', 'opening_request_id',
        'pruned_entry_bytes', 'evidence_pending'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'transport entries are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    -- A pre-migration row records its evidence exactly once and is not yet pruned.
    IF OLD.evidence_pending AND NOT NEW.evidence_pending AND NEW.payload_pruned_at IS NULL
       AND (to_jsonb(NEW) - evidence) IS NOT DISTINCT FROM (to_jsonb(OLD) - evidence) THEN
        RETURN NEW;
    END IF;
    -- Otherwise only the insert-captured projection may replace the ciphertext, once.
    IF OLD.evidence_pending
       OR (OLD.application_message_id IS NULL AND OLD.opening_request_id IS NULL)
       OR OLD.payload_pruned_at IS NOT NULL
       OR NEW.payload_pruned_at IS NULL
       OR NEW.entry_bytes IS DISTINCT FROM OLD.pruned_entry_bytes
       OR (to_jsonb(NEW) - ARRAY['entry_bytes', 'payload_pruned_at'])
          IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['entry_bytes', 'payload_pruned_at']) THEN
        RAISE EXCEPTION 'transport entries permit only irreversible application ciphertext pruning'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- The deferred publication assertion re-runs when a pruned transition row
-- changes. Once a publication's bytes are pruned (opening or terminal prune),
-- its provenance is proven by the retained digests; the artifact graph was
-- proven against the bytes at publication and cannot be re-read after.
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
            AND (t.signed_request_bytes=p.signed_publication OR p.signed_publication IS NULL)
            AND e.entry_kind='blue.catbird.chat.defs#directRequestEntry'
            AND e.transition_id=p.request_id AND e.message_id IS NULL
            AND (e.accepted_payload_bytes=p.request_entry OR p.request_entry IS NULL)
            AND e.accepted_payload_sha256=p.request_entry_sha256
       ) THEN RAISE EXCEPTION 'request publication provenance mismatch' USING ERRCODE='23514'; END IF;
    IF p.signed_publication IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM chat.generation_states state
        JOIN chat.metadata_snapshots metadata
          ON metadata.producing_transition_id=p.request_id
         AND metadata.conversation_id=state.conversation_id
         AND metadata.generation=state.generation AND metadata.state_version=state.state_version
        CROSS JOIN LATERAL (SELECT chat.direct_request_json_projection(convert_from(p.signed_publication,'UTF8')::json) AS signed) wrapper
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
          AND chat.direct_request_json_projection(convert_from(p.request_entry,'UTF8')::json)->'signedRequest'=wrapper.signed
          AND chat.direct_request_json_projection(convert_from(p.request_entry,'UTF8')::json)#>>'{signedRequest,body,firstMessageId}'=p.first_message_id::text
          AND decode(body.b#>>'{artifacts,finalGroupInfo,bytes}','base64')=p.final_group_info
          AND decode(body.b#>>'{artifacts,welcome,opaqueWelcome}','base64')=p.full_welcome
          AND decode(body.b#>>'{artifacts,initialCiphertext}','base64')=p.initial_ciphertext
          AND body.b#>'{artifacts,metadataSnapshot}'=chat.direct_request_json_projection(convert_from(p.metadata_snapshot,'UTF8')::json)
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

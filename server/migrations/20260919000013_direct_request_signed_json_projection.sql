-- Preserve immutable signed JSON bytes containing the required NUL domain separator.
-- PostgreSQL json accepts its escaped spelling, whereas jsonb cannot represent NUL.
-- This comparison-only projection treats signatureDomain as an opaque JSON string
-- lexeme (including quotes). It is injective in that lexeme, never removes a field,
-- and never changes stored/signed bytes. All other fields retain jsonb semantics.
-- Canonical server serialization supplies the same spelling on both graph sides;
-- a different spelling is conservatively unequal, never an authorization bypass.
CREATE FUNCTION chat.direct_request_json_projection(document JSON, depth INTEGER DEFAULT 0)
RETURNS JSONB LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE projected JSONB;
        field RECORD;
        element JSON;
BEGIN
    IF depth > 64 THEN
        RAISE EXCEPTION 'request JSON nesting exceeds comparison limit' USING ERRCODE='23514';
    END IF;
    CASE json_typeof(document)
    WHEN 'object' THEN
        projected := '{}'::jsonb;
        FOR field IN SELECT key, value FROM json_each(document) LOOP
            IF projected ? field.key THEN
                RAISE EXCEPTION 'duplicate request JSON field' USING ERRCODE='23514';
            END IF;
            IF field.key = 'signatureDomain' THEN
                IF json_typeof(field.value) <> 'string' THEN
                    RAISE EXCEPTION 'request signature domain must be a string' USING ERRCODE='23514';
                END IF;
                projected := projected || jsonb_build_object(field.key, to_jsonb(field.value::text));
            ELSE
                projected := projected || jsonb_build_object(field.key,
                    chat.direct_request_json_projection(field.value, depth + 1));
            END IF;
        END LOOP;
        RETURN projected;
    WHEN 'array' THEN
        projected := '[]'::jsonb;
        FOR element IN SELECT value FROM json_array_elements(document) LOOP
            projected := projected || jsonb_build_array(
                chat.direct_request_json_projection(element, depth + 1));
        END LOOP;
        RETURN projected;
    ELSE
        RETURN document::jsonb;
    END CASE;
END $$;

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

CREATE OR REPLACE FUNCTION chat.assert_direct_request_lifecycle(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE life chat.direct_request_lifecycle%ROWTYPE;
        publication chat.direct_request_publications%ROWTYPE;
        proof JSONB;
BEGIN
    SELECT * INTO life FROM chat.direct_request_lifecycle WHERE request_id=target;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO publication FROM chat.direct_request_publications WHERE request_id=target;
    IF publication.conversation_id IS DISTINCT FROM life.conversation_id THEN
        RAISE EXCEPTION 'request lifecycle publication mismatch' USING ERRCODE='23514';
    END IF;
    IF life.accepted_at IS NOT NULL THEN
        proof := chat.direct_request_json_projection(convert_from(life.acceptance_proof,'UTF8')::json);
        IF NOT EXISTS (
            SELECT 1 FROM chat.transitions t
            JOIN chat.entries e ON e.conversation_id=t.conversation_id AND e.seq=t.entry_seq
            WHERE t.conversation_id=life.conversation_id AND t.kind='directRequestAcceptance'
              AND t.actor_did=publication.recipient_did
              AND t.request_digest=life.acceptance_digest AND t.accepted_at=life.accepted_at
              AND e.entry_kind='blue.catbird.chat.defs#directRequestAcceptanceEntry'
              AND (chat.direct_request_json_projection(convert_from(e.accepted_payload_bytes,'UTF8')::json) - '$type') = proof->'entry'
              AND chat.direct_request_json_projection(convert_from(e.server_fields_bytes,'UTF8')::json) = proof->'receipt'
              AND chat.direct_request_json_projection(convert_from(t.signed_request_bytes,'UTF8')::json) = proof->'entry'->'signedRequest'
              AND proof->'entry'->'signedRequest'->'body'->>'requestId'=target::text
              AND proof->'receipt'->'body'->>'requestId'=target::text
        ) THEN RAISE EXCEPTION 'request acceptance lacks exact canonical consent proof' USING ERRCODE='23514'; END IF;
    END IF;
    IF life.consent='closed' AND NOT EXISTS (
        SELECT 1 FROM chat.conversations c WHERE c.conversation_id=life.conversation_id
          AND c.lifecycle='closed' AND c.closed_at=life.closed_at
    ) THEN RAISE EXCEPTION 'request close lacks canonical closure' USING ERRCODE='23514'; END IF;
END $$;

CREATE OR REPLACE FUNCTION chat.assert_direct_request_acceptance_claim(target UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE claim chat.direct_request_acceptance_claims%ROWTYPE;
        life chat.direct_request_lifecycle%ROWTYPE;
        response JSONB;
        request JSONB;
BEGIN
    SELECT * INTO claim FROM chat.direct_request_acceptance_claims WHERE request_id=target;
    SELECT * INTO life FROM chat.direct_request_lifecycle WHERE request_id=target;
    IF life.accepted_at IS NULL AND claim.operation_id IS NULL THEN RETURN; END IF;
    IF claim.operation_id IS NULL OR life.accepted_at IS NULL THEN
        RAISE EXCEPTION 'request consent and operation receipt must commit together' USING ERRCODE='23514';
    END IF;
    response := chat.direct_request_json_projection(convert_from(claim.response_bytes,'UTF8')::json);
    request := chat.direct_request_json_projection(convert_from(claim.accepted_request,'UTF8')::json);
    IF (claim.request_digest=life.acceptance_digest AND claim.recorded_at=life.accepted_at
        AND response->'acceptanceProof'=chat.direct_request_json_projection(convert_from(life.acceptance_proof,'UTF8')::json)
        AND response->'coordinates'=response->'acceptanceProof'->'receipt'->'body'->'next'
        AND request=response->'acceptanceProof'->'entry'->'signedRequest'
        AND request->'body'->>'actorDid'=claim.principal_did
        AND request->'body'->>'requestId'=target::text
        AND request->'body'->>'idempotencyKey'=claim.operation_id::text
        AND request->'body'->>'transitionId'=claim.operation_id::text
        AND decode(request->>'signature','base64')=claim.signature) IS NOT TRUE THEN
        RAISE EXCEPTION 'request acceptance operation receipt mismatch' USING ERRCODE='23514';
    END IF;
END $$;

-- Direct-request first-message identity belongs to its signed publication
-- graph. The ordinary entries.message_id column is reserved for application
-- sends and activates entries_message_send_fk when non-NULL.

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
    ) OR (
        entry_kind='blue.catbird.chat.defs#directRequestEntry'
        AND transition_id IS NOT NULL
        AND message_id IS NULL
    ));

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
            AND e.transition_id=p.request_id AND e.message_id IS NULL
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

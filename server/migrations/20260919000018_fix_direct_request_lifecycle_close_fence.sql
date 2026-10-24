-- 20260919000018_fix_direct_request_lifecycle_close_fence.sql
-- Fix close-branch predicate in chat.assert_direct_request_lifecycle:
-- chat.conversations lifecycle is constrained by conversations_lifecycle_check
-- to ('active', 'superseded'). When a conversation is closed via closeConversation,
-- its lifecycle transitions to 'superseded' with closed_at set. The fence
-- previously checked c.lifecycle='closed', which is rejected by the check constraint.

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
          AND c.lifecycle='superseded' AND c.closed_at=life.closed_at
    ) THEN RAISE EXCEPTION 'request close lacks canonical closure' USING ERRCODE='23514'; END IF;
END $$;

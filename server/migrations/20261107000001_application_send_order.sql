-- Migration: per-device application send order (StaleSend).
--
-- A sequencer resolving a messageId for the first time accepts it only if its
-- signed (prior.generation, prior.epoch, sendCounter) is lexicographically
-- greater than the actor device's last accepted send in the conversation;
-- otherwise it refuses StaleSend and writes nothing. One row per device holds
-- that last accepted triple. `resolve_application_send` advances it with one
-- conditional upsert under the already-held conversation head lock, so a held
-- send can never be sequenced behind the same device's newer sends.
-- The close wipe deletes the conversation row last; the cascade removes these.
CREATE TABLE IF NOT EXISTS chat.application_send_order (
    conversation_id UUID NOT NULL
        REFERENCES chat.conversations(conversation_id) ON DELETE CASCADE,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (chat.is_safe_integer(generation)),
    epoch BIGINT NOT NULL CHECK (chat.is_safe_integer(epoch)),
    last_send_counter BIGINT NOT NULL
        CHECK (last_send_counter >= 1 AND chat.is_safe_integer(last_send_counter)),
    PRIMARY KEY (conversation_id, actor_did, actor_device_id)
);

-- A sequencer or mirror upgraded with accepted application history starts each
-- device at the greatest triple that history signed, so a held send it already
-- passed is StaleSend after the upgrade or a mirror takeover, as on a fresh
-- tree; an exact replay still answers from `chat.message_sends` first. SHARE
-- holds every entry writer until this transaction commits, so no accepted
-- entry escapes the scan. An entry signed before sendCounter existed orders
-- nothing, and a pruned entry's signed request is gone with its triple.
-- Signing domains end in an escaped NUL (`\u0000`), which no JSON function
-- accepts as text. The regexp consumes the request's escapes left to right and
-- drops only `\u0000` (an escaped backslash before `u0000` is kept), so the
-- cast succeeds; only the numeric triple is read.
LOCK TABLE chat.entries IN SHARE MODE;
WITH signed AS (
    SELECT conversation_id, actor_did, actor_device_id,
           regexp_replace(convert_from(signed_request_bytes, 'UTF8'),
                          '\\(u0000)|(\\.)', '\2', 'g')::jsonb->'body' AS body
      FROM chat.entries
     WHERE entry_kind = 'blue.catbird.chat.defs#applicationEntry'
       AND signed_request_bytes IS NOT NULL
), latest AS (
    SELECT DISTINCT ON (conversation_id, actor_did, actor_device_id)
           conversation_id, actor_did, actor_device_id,
           (body->'prior'->>'generation')::BIGINT AS generation,
           (body->'prior'->>'epoch')::BIGINT AS epoch,
           (body->>'sendCounter')::BIGINT AS last_send_counter
      FROM signed
     WHERE body->>'sendCounter' IS NOT NULL
     ORDER BY conversation_id, actor_did, actor_device_id,
              generation DESC, epoch DESC, last_send_counter DESC
)
INSERT INTO chat.application_send_order AS o(
    conversation_id, actor_did, actor_device_id,
    generation, epoch, last_send_counter
)
SELECT conversation_id, actor_did, actor_device_id, generation, epoch, last_send_counter
  FROM latest
ON CONFLICT (conversation_id, actor_did, actor_device_id) DO UPDATE
   SET generation = EXCLUDED.generation,
       epoch = EXCLUDED.epoch,
       last_send_counter = EXCLUDED.last_send_counter
 WHERE (o.generation, o.epoch, o.last_send_counter)
     < (EXCLUDED.generation, EXCLUDED.epoch, EXCLUDED.last_send_counter);

-- A conversation's ciphertext placement is chosen once. Existing histories
-- remain DS-hosted; a deleted Space cannot be rebound or silently recreated.
CREATE TABLE IF NOT EXISTS labyrinth.thread_storage (
    conversation_id UUID PRIMARY KEY REFERENCES chat.conversations(conversation_id),
    placement TEXT NOT NULL CHECK (placement IN ('mlsds', 'space')),
    generation UUID NOT NULL UNIQUE,
    space TEXT UNIQUE,
    deleted_at TIMESTAMPTZ,
    CHECK ((placement = 'mlsds' AND space IS NULL AND deleted_at IS NULL)
        OR (placement = 'space' AND space IS NOT NULL
            AND chat.is_bare_did(split_part(space, '/', 3))
            AND space = 'at://' || split_part(space, '/', 3)
                || '/space/blue.catbird.labyrinth.conversation/' || generation::text))
);
INSERT INTO labyrinth.thread_storage (conversation_id, placement, generation)
SELECT conversation_id, 'mlsds', gen_random_uuid() FROM chat.conversations
ON CONFLICT DO NOTHING;

CREATE FUNCTION labyrinth.guard_thread_storage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR (to_jsonb(NEW) - 'deleted_at') IS DISTINCT FROM (to_jsonb(OLD) - 'deleted_at')
       OR OLD.deleted_at IS NOT NULL OR NEW.deleted_at IS NULL THEN
        RAISE EXCEPTION 'immutable conversation storage lifecycle' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER thread_storage_immutable BEFORE UPDATE OR DELETE ON labyrinth.thread_storage
FOR EACH ROW EXECUTE FUNCTION labyrinth.guard_thread_storage();

ALTER TABLE labyrinth.meks ADD COLUMN IF NOT EXISTS chat_generation BIGINT;
ALTER TABLE labyrinth.meks ADD CONSTRAINT meks_chat_generation_check
    CHECK (chat_generation IS NULL OR (chat_generation >= 0 AND chat.is_safe_integer(chat_generation)));
ALTER TABLE labyrinth.meks DISABLE TRIGGER meks_identity_immutable;
UPDATE labyrinth.meks m SET chat_generation = (
    SELECT g.generation FROM chat.generations g WHERE g.conversation_id = m.conversation_id
      AND g.activated_seq <= m.chat_seq
      AND (g.superseded_seq IS NULL OR m.chat_seq < g.superseded_seq)
    ORDER BY g.activated_seq DESC LIMIT 1
);
ALTER TABLE labyrinth.meks ENABLE TRIGGER meks_identity_immutable;
-- Historical rows without a provable generation are deliberately not usable
-- for new Space writes. Their existing DS history is unchanged.
ALTER TABLE labyrinth.batches ADD COLUMN IF NOT EXISTS space_generation UUID REFERENCES labyrinth.thread_storage(generation);
ALTER TABLE labyrinth.batches ADD COLUMN IF NOT EXISTS space_ref TEXT;
ALTER TABLE labyrinth.batches ADD COLUMN IF NOT EXISTS source_cid TEXT;
ALTER TABLE labyrinth.batches DROP CONSTRAINT IF EXISTS batches_rkey_check;
ALTER TABLE labyrinth.batches ADD CONSTRAINT batches_rkey_check CHECK (
    (space_generation IS NULL AND rkey ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$')
    OR (space_generation IS NOT NULL AND length(rkey) BETWEEN 1 AND 64
        AND rkey ~ '^[A-Za-z0-9._:-]+$' AND rkey NOT IN ('.', '..'))
);
ALTER TABLE labyrinth.batches ADD CONSTRAINT batches_source_shape CHECK (
    (space_generation IS NULL AND space_ref IS NULL AND source_cid IS NULL)
    OR (space_generation IS NOT NULL AND space_ref IS NOT NULL AND source_cid IS NOT NULL)
);
-- Metadata rows reuse the existing immutable batch_items, retention functions,
-- signed tombstones, attachment invalidation and federation deletion outbox.
-- No ciphertext can enter even through another SQL caller or a later rewrite.
CREATE FUNCTION labyrinth.guard_space_batch_metadata() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.space_generation IS NULL THEN
        IF NOT EXISTS (SELECT 1 FROM labyrinth.thread_storage s
            WHERE s.conversation_id = NEW.conversation_id AND s.placement = 'mlsds') THEN
            RAISE EXCEPTION 'legacy ciphertext requires DS storage placement' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM labyrinth.thread_storage s
            WHERE s.conversation_id = NEW.conversation_id AND s.placement = 'space'
              AND s.generation = NEW.space_generation AND s.space = NEW.space_ref)
           OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.record->'items') i
                      WHERE i->'signedEncMessage' IS DISTINCT FROM '{"$bytes":""}'::jsonb) THEN
            RAISE EXCEPTION 'Space batch must contain only bound metadata' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER space_batch_metadata BEFORE INSERT OR UPDATE ON labyrinth.batches
FOR EACH ROW EXECUTE FUNCTION labyrinth.guard_space_batch_metadata();

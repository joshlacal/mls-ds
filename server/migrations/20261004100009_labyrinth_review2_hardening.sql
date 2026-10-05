-- Migration: Labyrinth 1.1 storage backend, part 9 — second security review
-- hardening (findings 4, 5, 8, 9, 11). New migration only; parts 1-8 are
-- unchanged.
--
-- 1. relay_outbox: durable DS-to-DS jobs, retried with backoff, so one
--    unreachable DS can neither block a local account purge nor lose the
--    remote part of it (finding 4), and so redactions reach the attachment
--    references held on members' home DSes (finding 5).
-- 2. attachment_refs.state_digest and orf_state_tombstones: a reference
--    records (as a keyed digest) the ORF state it was created through; every
--    ORF-state deletion leaves a tombstone the retention pass drains by
--    deleting those references, releasing their blob pins (finding 5).
-- 3. redacted_messages: keyed digests of (message, author) pairs that were
--    redacted here or announced by the conversation's sequencer;
--    putAttachmentRef refuses them (finding 9).
-- 4. One MEK id per conversation, and batches record their MEK's author so
--    readability joins on (mek_id, author) (finding 8).
-- 5. DELETE on attachment_refs and orf_states now requires the retention
--    scope like every other labyrinth table (finding 11).

CREATE TABLE labyrinth.relay_outbox (
    job_id BIGSERIAL PRIMARY KEY,
    target_ds TEXT NOT NULL,
    op TEXT NOT NULL,
    request JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT relay_outbox_op_check CHECK (op IN ('purgeAuthor', 'invalidateMessages')),
    CONSTRAINT relay_outbox_status_check CHECK (status IN ('pending', 'done', 'dead')),
    CONSTRAINT relay_outbox_target_check CHECK (octet_length(target_ds) BETWEEN 1 AND 2048)
);

CREATE INDEX relay_outbox_due_idx
    ON labyrinth.relay_outbox (next_attempt_at) WHERE status = 'pending';

ALTER TABLE labyrinth.attachment_refs ADD COLUMN state_digest BYTEA;
ALTER TABLE labyrinth.attachment_refs
    ADD CONSTRAINT attachment_refs_state_digest_check
    CHECK (state_digest IS NULL OR octet_length(state_digest) = 32);
CREATE INDEX attachment_refs_state_idx ON labyrinth.attachment_refs (state_digest);

CREATE TABLE labyrinth.orf_state_tombstones (
    tombstone_id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL,
    device_key BYTEA NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION labyrinth.tombstone_orf_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO labyrinth.orf_state_tombstones (owner_did, device_key)
    VALUES (OLD.owner_did, OLD.device_key);
    RETURN OLD;
END;
$$;

CREATE TRIGGER orf_states_tombstone
AFTER DELETE ON labyrinth.orf_states
FOR EACH ROW EXECUTE FUNCTION labyrinth.tombstone_orf_state();

CREATE TABLE labyrinth.redacted_messages (
    message_digest BYTEA NOT NULL,
    author_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (message_digest, author_digest),
    CONSTRAINT redacted_messages_message_check CHECK (octet_length(message_digest) = 32),
    CONSTRAINT redacted_messages_author_check CHECK (octet_length(author_digest) = 32)
);

CREATE TRIGGER redacted_messages_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.redacted_messages
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Finding 8: a MEK id names one MEK (one author) per conversation.
CREATE UNIQUE INDEX meks_conversation_mek_uq ON labyrinth.meks (conversation_id, mek_id);

ALTER TABLE labyrinth.batches ADD COLUMN mek_author_did TEXT;
ALTER TABLE labyrinth.batches DISABLE TRIGGER batches_retained_identity;
UPDATE labyrinth.batches b SET mek_author_did = m.author_did
  FROM labyrinth.meks m
 WHERE m.conversation_id = b.conversation_id AND m.mek_id = b.mek_id;
ALTER TABLE labyrinth.batches ENABLE TRIGGER batches_retained_identity;
ALTER TABLE labyrinth.batches ALTER COLUMN mek_author_did SET NOT NULL;
ALTER TABLE labyrinth.batches
    ADD CONSTRAINT batches_mek_fk FOREIGN KEY (conversation_id, mek_author_did, mek_id)
    REFERENCES labyrinth.meks (conversation_id, author_did, mek_id);

-- Finding 11.
CREATE TRIGGER attachment_refs_retained_delete
BEFORE DELETE ON labyrinth.attachment_refs
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

CREATE TRIGGER orf_states_retained_delete
BEFORE DELETE ON labyrinth.orf_states
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

-- Finding 5: a message's sender-side state for `reader`, for items of
-- `author` only. `redacted`: some item of the author with this id is
-- redacted (an unsent message is gone for everyone). `live`: an unredacted
-- item of the author with this id that the reader can read per MEK.
CREATE FUNCTION labyrinth.sender_message_state(reader TEXT, conv UUID, msg TEXT, author TEXT)
RETURNS TABLE (live BOOLEAN, redacted BOOLEAN)
LANGUAGE sql
STABLE
AS $$
    SELECT
        EXISTS (
            SELECT 1
              FROM labyrinth.batch_items bi
              JOIN labyrinth.batches b
                ON b.conversation_id = bi.conversation_id
               AND b.author_did = bi.author_did AND b.rkey = bi.rkey
             WHERE bi.conversation_id = conv AND bi.message_id = msg
               AND bi.author_did = author AND bi.redacted_at IS NULL
               AND (b.author_did = reader OR EXISTS (
                    SELECT 1 FROM labyrinth.meks m
                     WHERE m.conversation_id = b.conversation_id AND m.mek_id = b.mek_id
                       AND m.author_did = b.mek_author_did
                       AND (m.author_did = reader OR EXISTS (
                            SELECT 1 FROM labyrinth.mek_recipients r
                             WHERE r.conversation_id = m.conversation_id
                               AND r.mek_id = m.mek_id AND r.author_did = m.author_did
                               AND r.recipient_did = reader))))),
        EXISTS (
            SELECT 1 FROM labyrinth.batch_items bi
             WHERE bi.conversation_id = conv AND bi.message_id = msg
               AND bi.author_did = author AND bi.redacted_at IS NOT NULL)
$$;

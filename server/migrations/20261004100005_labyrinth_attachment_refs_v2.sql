-- Migration: Labyrinth 1.1 storage backend, part 5 — attachment references
-- without clear linkage, and message indexes (gap audit G-P0-1 and J4;
-- whitepaper v1.1 p.8 "Content Unlinkability", p.41-42).
--
-- 1. attachment_refs is rebuilt. The part-3 table stored owner DID,
--    conversation, message and blob in clear, so a database reader could
--    link users, messages and attachments. The rebuilt table keeps:
--      orf_index      orf_server_map(device state, index domain, blindedIndex)
--      owner_digest   HMAC(server key, owner DID)
--      message_digest HMAC(server key, conversation id, message id)
--      token_mac      HMAC(key = orf_server_map(state, token domain,
--                     blindedTokenSalt), json([threadId, messageId]))
--      blob_id        clear: the GC pin and the served object need it
--    The server key (LABYRINTH_ATTACHMENT_DIGEST_KEY) lives outside the
--    database. The part-3 table was never deployed (local bookmark only), so
--    it is dropped rather than migrated; its rows could not be converted
--    without the key anyway.
-- 2. attachment_blobs fixes one message per blob (v1.1 p.42: "any given
--    attachment object must currently only ever be referenced by one
--    message"); refs reference (blob_id, message_digest) there.
-- 3. batch_items / owner_batch_items index stored message ids so the server
--    can tell whether an attachment's message still exists (p.42) and, from
--    part 6 on, redact items. Both are maintained by AFTER INSERT triggers
--    and backfilled here.
--
-- Refs are deletable (deleteAttachmentRef, redaction, purges): like ORF
-- states, removing the row is the revocation. UPDATE is refused.

DROP TABLE labyrinth.attachment_refs;

CREATE TABLE labyrinth.attachment_blobs (
    blob_id UUID PRIMARY KEY REFERENCES chat.blobs(blob_id),
    message_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT attachment_blobs_blob_message_uq UNIQUE (blob_id, message_digest),
    CONSTRAINT attachment_blobs_digest_check CHECK (octet_length(message_digest) = 32)
);

CREATE TRIGGER attachment_blobs_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.attachment_blobs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TABLE labyrinth.attachment_refs (
    orf_index BYTEA PRIMARY KEY,
    owner_digest BYTEA NOT NULL,
    message_digest BYTEA NOT NULL,
    blob_id UUID NOT NULL,
    token_mac BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT attachment_refs_blob_message_fk FOREIGN KEY (blob_id, message_digest)
        REFERENCES labyrinth.attachment_blobs(blob_id, message_digest),
    CONSTRAINT attachment_refs_index_check CHECK (octet_length(orf_index) = 32),
    CONSTRAINT attachment_refs_owner_check CHECK (octet_length(owner_digest) = 32),
    CONSTRAINT attachment_refs_message_check CHECK (octet_length(message_digest) = 32),
    CONSTRAINT attachment_refs_token_mac_check CHECK (octet_length(token_mac) = 32)
);

CREATE INDEX attachment_refs_owner_idx ON labyrinth.attachment_refs (owner_digest);
CREATE INDEX attachment_refs_message_idx ON labyrinth.attachment_refs (message_digest);
CREATE INDEX attachment_refs_blob_idx ON labyrinth.attachment_refs (blob_id);

CREATE TRIGGER attachment_refs_no_update
BEFORE UPDATE ON labyrinth.attachment_refs
FOR EACH ROW EXECUTE FUNCTION labyrinth.reject_update();

-- One row per stored sender item. redacted_at is set once by redaction
-- (part 6).
CREATE TABLE labyrinth.batch_items (
    conversation_id UUID NOT NULL,
    author_did TEXT NOT NULL,
    rkey TEXT NOT NULL,
    item_index INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    redacted_at TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, author_did, rkey, item_index),
    CONSTRAINT batch_items_batch_fk FOREIGN KEY (conversation_id, author_did, rkey)
        REFERENCES labyrinth.batches(conversation_id, author_did, rkey) ON DELETE CASCADE,
    CONSTRAINT batch_items_index_check CHECK (item_index BETWEEN 0 AND 255),
    CONSTRAINT batch_items_message_id_check CHECK (octet_length(message_id) BETWEEN 1 AND 128)
);

CREATE INDEX batch_items_message_idx
    ON labyrinth.batch_items (conversation_id, message_id);
CREATE INDEX batch_items_author_message_idx
    ON labyrinth.batch_items (conversation_id, author_did, message_id);

CREATE FUNCTION labyrinth.batch_items_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (to_jsonb(NEW) - 'redacted_at') IS DISTINCT FROM (to_jsonb(OLD) - 'redacted_at')
       OR (OLD.redacted_at IS NOT NULL AND NEW.redacted_at IS DISTINCT FROM OLD.redacted_at) THEN
        RAISE EXCEPTION 'labyrinth batch item is immutable except redacted_at, set once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER batch_items_immutable
BEFORE UPDATE ON labyrinth.batch_items
FOR EACH ROW EXECUTE FUNCTION labyrinth.batch_items_immutable();

CREATE TABLE labyrinth.owner_batch_items (
    owner_did TEXT NOT NULL,
    rkey TEXT NOT NULL,
    item_index INTEGER NOT NULL,
    thread_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY (owner_did, rkey, item_index),
    CONSTRAINT owner_batch_items_batch_fk FOREIGN KEY (owner_did, rkey)
        REFERENCES labyrinth.owner_batches(owner_did, rkey) ON DELETE CASCADE,
    CONSTRAINT owner_batch_items_index_check CHECK (item_index BETWEEN 0 AND 255)
);

CREATE INDEX owner_batch_items_message_idx
    ON labyrinth.owner_batch_items (owner_did, thread_id, message_id);

CREATE TRIGGER owner_batch_items_no_update
BEFORE UPDATE ON labyrinth.owner_batch_items
FOR EACH ROW EXECUTE FUNCTION labyrinth.reject_update();

CREATE FUNCTION labyrinth.index_batch_items()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO labyrinth.batch_items
        (conversation_id, author_did, rkey, item_index, message_id)
    SELECT NEW.conversation_id, NEW.author_did, NEW.rkey, (item.ord - 1)::integer,
           item.value->>'messageId'
      FROM jsonb_array_elements(NEW.record->'items') WITH ORDINALITY AS item(value, ord);
    RETURN NEW;
END;
$$;

CREATE TRIGGER batches_index_items
AFTER INSERT ON labyrinth.batches
FOR EACH ROW EXECUTE FUNCTION labyrinth.index_batch_items();

CREATE FUNCTION labyrinth.index_owner_batch_items()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO labyrinth.owner_batch_items
        (owner_did, rkey, item_index, thread_id, message_id)
    SELECT NEW.owner_did, NEW.rkey, (item.ord - 1)::integer,
           item.value->>'threadId', item.value->>'messageId'
      FROM jsonb_array_elements(NEW.record->'items') WITH ORDINALITY AS item(value, ord);
    RETURN NEW;
END;
$$;

CREATE TRIGGER owner_batches_index_items
AFTER INSERT ON labyrinth.owner_batches
FOR EACH ROW EXECUTE FUNCTION labyrinth.index_owner_batch_items();

INSERT INTO labyrinth.batch_items (conversation_id, author_did, rkey, item_index, message_id)
SELECT b.conversation_id, b.author_did, b.rkey, (item.ord - 1)::integer, item.value->>'messageId'
  FROM labyrinth.batches b,
       jsonb_array_elements(b.record->'items') WITH ORDINALITY AS item(value, ord);

INSERT INTO labyrinth.owner_batch_items (owner_did, rkey, item_index, thread_id, message_id)
SELECT o.owner_did, o.rkey, (item.ord - 1)::integer, item.value->>'threadId',
       item.value->>'messageId'
  FROM labyrinth.owner_batches o,
       jsonb_array_elements(o.record->'items') WITH ORDINALITY AS item(value, ord);

-- Whether a message of a conversation still exists for `reader` (p.42): an
-- unredacted sender item the reader can read per MEK (design §3), or an item
-- of the reader's own owner archive for that thread.
CREATE FUNCTION labyrinth.message_live_for(reader TEXT, conv UUID, msg TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM labyrinth.batch_items bi
          JOIN labyrinth.batches b
            ON b.conversation_id = bi.conversation_id
           AND b.author_did = bi.author_did AND b.rkey = bi.rkey
         WHERE bi.conversation_id = conv AND bi.message_id = msg
           AND bi.redacted_at IS NULL
           AND (b.author_did = reader OR EXISTS (
                SELECT 1 FROM labyrinth.meks m
                 WHERE m.conversation_id = b.conversation_id AND m.mek_id = b.mek_id
                   AND (m.author_did = reader OR EXISTS (
                        SELECT 1 FROM labyrinth.mek_recipients r
                         WHERE r.conversation_id = m.conversation_id
                           AND r.mek_id = m.mek_id AND r.author_did = m.author_did
                           AND r.recipient_did = reader))))
    ) OR EXISTS (
        SELECT 1 FROM labyrinth.owner_batch_items o
         WHERE o.owner_did = reader AND o.thread_id = conv::text AND o.message_id = msg
    )
$$;

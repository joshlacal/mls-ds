-- Migration: Labyrinth 1.1 storage backend, part 3 — ORF server state and
-- attachment references (labyrinth SPEC §8, [CB-17]; docs/MLSDS_BACKEND.md
-- §2 "ORF and attachments", §4, Y8).
--
-- An ORF state is one Ristretto255 scalar per Labyrinth device key. It is
-- stored raw (Y8: relies on database at-rest encryption) and is never
-- updated: evolution registers a NEW device key's state; revocation DELETEs
-- the row, which is the point of the construction, so DELETE is allowed here
-- while UPDATE is refused.

CREATE TABLE labyrinth.orf_states (
    owner_did TEXT NOT NULL,
    device_key BYTEA NOT NULL,
    server_state BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, device_key),
    CONSTRAINT orf_states_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT orf_states_device_key_check CHECK (octet_length(device_key) = 32),
    CONSTRAINT orf_states_state_check CHECK (octet_length(server_state) = 32)
);

CREATE FUNCTION labyrinth.reject_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'labyrinth row cannot be updated: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER orf_states_no_update
BEFORE UPDATE ON labyrinth.orf_states
FOR EACH ROW EXECUTE FUNCTION labyrinth.reject_update();

-- One reference per (owner, server-mapped attachment index). orf_index and
-- token_mac are orf_server_map outputs under fixed server domains. The FK
-- keeps the chat.blobs row; it does NOT yet keep the blob's stored object
-- from chat object GC (design §4 "attachment refs pin their blob" is a
-- follow-up that must change chat.claim_blob_object_gc).
CREATE TABLE labyrinth.attachment_refs (
    owner_did TEXT NOT NULL,
    orf_index BYTEA NOT NULL,
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id),
    blob_id UUID NOT NULL REFERENCES chat.blobs(blob_id),
    message_id TEXT NOT NULL,
    token_mac BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, orf_index),
    CONSTRAINT attachment_refs_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT attachment_refs_index_check CHECK (octet_length(orf_index) = 32),
    CONSTRAINT attachment_refs_message_id_check CHECK (octet_length(message_id) BETWEEN 1 AND 256),
    CONSTRAINT attachment_refs_token_mac_check CHECK (octet_length(token_mac) = 32)
);

CREATE INDEX attachment_refs_blob_idx ON labyrinth.attachment_refs (blob_id);

CREATE TRIGGER attachment_refs_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.attachment_refs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

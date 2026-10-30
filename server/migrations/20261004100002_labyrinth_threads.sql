-- Migration: Labyrinth 1.1 storage backend, part 2 — per-conversation sender
-- records with server order stamps (labyrinth docs/MLSDS_BACKEND.md §1b, §2
-- "Thread", §3, §4).
--
-- thread_id is chat.conversations.conversation_id ([CB-2]). Every MEK and
-- batch row carries the serverOrder stamp assigned under the conversation row
-- lock: seq (per-conversation Labyrinth counter), chat_seq (last chat entry
-- seq, linearized against MLS entries) and received_at (request instant).
-- Reads are authorized per MEK through mek_recipients (design §3), so a
-- member who leaves keeps the history it was addressed in and a late joiner
-- sees nothing sealed before it joined.

CREATE TABLE labyrinth.thread_counters (
    conversation_id UUID PRIMARY KEY REFERENCES chat.conversations(conversation_id),
    next_seq BIGINT NOT NULL,
    CONSTRAINT thread_counters_next_seq_check CHECK (
        next_seq >= 1 AND chat.is_safe_integer(next_seq)
    )
);

CREATE TRIGGER thread_counters_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.thread_counters
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('next_seq');

-- Thread record bytes per author DID across all conversations (design Y6:
-- 1 GiB).
CREATE TABLE labyrinth.author_usage (
    author_did TEXT PRIMARY KEY,
    bytes_used BIGINT NOT NULL,
    CONSTRAINT author_usage_did_check CHECK (chat.is_bare_did(author_did)),
    CONSTRAINT author_usage_bytes_quota CHECK (bytes_used BETWEEN 0 AND 1073741824)
);

CREATE TRIGGER author_usage_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.author_usage
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('bytes_used');

-- `mek` records, rkey = hex(mekId), one per (author, mekId) ([CB-21]).
CREATE TABLE labyrinth.meks (
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id),
    author_did TEXT NOT NULL,
    mek_id BYTEA NOT NULL,
    sender_kind TEXT NOT NULL,
    attestation_key_id TEXT REFERENCES chat.device_keys(key_id),
    writer_device_id UUID NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    seq BIGINT NOT NULL,
    chat_seq BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, author_did, mek_id),
    CONSTRAINT meks_seq_uq UNIQUE (conversation_id, seq),
    CONSTRAINT meks_author_did_check CHECK (chat.is_bare_did(author_did)),
    CONSTRAINT meks_mek_id_check CHECK (octet_length(mek_id) = 12),
    CONSTRAINT meks_sender_kind_check CHECK (
        (sender_kind = 'labyrinth' AND attestation_key_id IS NOT NULL)
        OR (sender_kind = 'transport' AND attestation_key_id IS NULL)
    ),
    CONSTRAINT meks_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 1048576),
    CONSTRAINT meks_seq_check CHECK (seq >= 1 AND chat.is_safe_integer(seq)),
    CONSTRAINT meks_chat_seq_check CHECK (chat_seq >= 0 AND chat.is_safe_integer(chat_seq))
);

CREATE INDEX meks_mek_id_idx ON labyrinth.meks (conversation_id, mek_id);

CREATE TRIGGER meks_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.meks
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Per-MEK read index: who a MEK was addressed to.
CREATE TABLE labyrinth.mek_recipients (
    conversation_id UUID NOT NULL,
    mek_id BYTEA NOT NULL,
    author_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    PRIMARY KEY (conversation_id, mek_id, author_did, recipient_did),
    CONSTRAINT mek_recipients_mek_fk FOREIGN KEY (conversation_id, author_did, mek_id)
        REFERENCES labyrinth.meks(conversation_id, author_did, mek_id),
    CONSTRAINT mek_recipients_did_check CHECK (chat.is_bare_did(recipient_did))
);

CREATE INDEX mek_recipients_reader_idx
    ON labyrinth.mek_recipients (conversation_id, recipient_did, mek_id);

CREATE TRIGGER mek_recipients_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.mek_recipients
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- `batch` records, rkey = server TID, single-MEK (design Y4).
CREATE TABLE labyrinth.batches (
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id),
    author_did TEXT NOT NULL,
    rkey TEXT NOT NULL,
    mek_id BYTEA NOT NULL,
    writer_device_id UUID NOT NULL,
    min_ts BIGINT NOT NULL,
    max_ts BIGINT NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    seq BIGINT NOT NULL,
    chat_seq BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, author_did, rkey),
    CONSTRAINT batches_seq_uq UNIQUE (conversation_id, seq),
    CONSTRAINT batches_author_did_check CHECK (chat.is_bare_did(author_did)),
    CONSTRAINT batches_rkey_check CHECK (rkey ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'),
    CONSTRAINT batches_mek_id_check CHECK (octet_length(mek_id) = 12),
    CONSTRAINT batches_ts_check CHECK (min_ts >= 0 AND max_ts >= min_ts),
    CONSTRAINT batches_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 1048576),
    CONSTRAINT batches_seq_check CHECK (seq >= 1 AND chat.is_safe_integer(seq)),
    CONSTRAINT batches_chat_seq_check CHECK (chat_seq >= 0 AND chat.is_safe_integer(chat_seq))
);

CREATE INDEX batches_mek_idx ON labyrinth.batches (conversation_id, mek_id, seq);

CREATE TRIGGER batches_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.batches
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

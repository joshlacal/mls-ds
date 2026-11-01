-- Migration: Option A Conversation SpaceHost operational columns & writer revision index (`atproto#5187`).
-- Additive forward migration on top of `20261031200001_clean_slate_spaces_only.sql`.

ALTER TABLE chat.conversation_spaces
    ADD COLUMN IF NOT EXISTS latest_space_rev TEXT,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

ALTER TABLE chat.space_credential_jtis
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS space_credential_jtis_space_writer_idx
    ON chat.space_credential_jtis (space_uri, writer_did);

ALTER TABLE chat.conversation_space_syncers
    ADD COLUMN IF NOT EXISTS service_ref TEXT,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '24 hours');

UPDATE chat.conversation_space_syncers
   SET service_ref = service_did
 WHERE service_ref IS NULL;

ALTER TABLE chat.conversation_space_syncers
    ALTER COLUMN service_ref SET NOT NULL,
    DROP CONSTRAINT IF EXISTS conversation_space_syncers_pkey,
    ADD PRIMARY KEY (space_uri, service_ref);

CREATE TABLE IF NOT EXISTS chat.conversation_space_writers (
    space_uri TEXT NOT NULL REFERENCES chat.conversation_spaces(space_uri) ON DELETE CASCADE,
    writer_did TEXT NOT NULL,
    repo_rev TEXT NOT NULL,
    space_rev TEXT NOT NULL,
    data_cid BYTEA NOT NULL CHECK (octet_length(data_cid) = 32),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (space_uri, writer_did),
    UNIQUE (space_uri, space_rev),
    CONSTRAINT conversation_space_writers_did_check CHECK (chat.is_bare_did(writer_did))
);

CREATE INDEX IF NOT EXISTS conversation_space_writers_order_idx
    ON chat.conversation_space_writers (space_uri, space_rev ASC);

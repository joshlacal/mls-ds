-- Space URIs moved from `at://{spaceDid}/space/{rest}` to `at:space/{spaceDid}/{rest}`
-- (atproto permissioned-data-alpha, 2026-11-24). Rewrite stored Space refs in place,
-- mirroring the reference PDS `rewriteSpaceUris`.
--
-- * Only values still in the old form are touched, so a re-run is a no-op.
-- * A DID contains no `/`, so the first `/` after `at://` always ends the space DID.
-- * `chat.conversation_space_records.record_cbor` is CID-covered record bytes and is
--   left as written.
--
-- Columns covered (every stored Space ref in this schema):
--   chat.conversation_spaces.space_uri
--   chat.conversation_space_syncers.space_uri
--   chat.conversation_space_writers.space_uri
--   chat.conversation_space_subscribers.space_uri
--   chat.managed_space_members.space_uri
--   chat.conversation_space_records.space_uri
--   chat.space_credential_jtis.space_uri
--
-- Not rewritten: S2S outbox/queue payloads (`DeliverGroupEntryRequest.spaceUri`; the
-- receiver ignores it), and the HMAC'd writer-inventory cursors handed to clients
-- (they cover the old string and fail closed; clients restart pagination).
--
-- The `conversation_spaces_uri_check` CHECK is replaced with the `at:space/` form, and
-- the foreign keys onto `chat.conversation_spaces` (no ON UPDATE CASCADE) are dropped and
-- re-created with the same name and definition around the rewrite. SQLx runs this file
-- in one transaction.
--
-- Down (manual; migrations here are forward-only): drop the new CHECK, run the same
-- block with regexp_replace(col, '^at:space/([^/]+)/', 'at://\1/space/') WHERE
-- col ~ '^at:space/[^/]+/', then restore the old CHECK
-- (space_uri LIKE 'at://%/space/blue.catbird.labyrinth.conversation/%').

ALTER TABLE chat.conversation_spaces
    DROP CONSTRAINT IF EXISTS conversation_spaces_uri_check;

DO $$
DECLARE
    fk RECORD;
    target RECORD;
    saved_fks JSONB := '[]'::jsonb;
BEGIN
    FOR fk IN
        SELECT conrelid::regclass::text AS tbl, conname, pg_get_constraintdef(oid) AS def
          FROM pg_constraint
         WHERE contype = 'f'
           AND conparentid = 0
           AND confrelid = 'chat.conversation_spaces'::regclass
    LOOP
        saved_fks := saved_fks || jsonb_build_object('tbl', fk.tbl, 'name', fk.conname, 'def', fk.def);
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.tbl, fk.conname);
    END LOOP;

    FOR target IN
        SELECT * FROM (VALUES
            ('chat.conversation_spaces'),
            ('chat.conversation_space_syncers'),
            ('chat.conversation_space_writers'),
            ('chat.conversation_space_subscribers'),
            ('chat.managed_space_members'),
            ('chat.conversation_space_records'),
            ('chat.space_credential_jtis')
        ) AS t(tbl)
    LOOP
        EXECUTE format(
            'UPDATE %s SET space_uri = regexp_replace(space_uri, %L, %L) WHERE space_uri ~ %L',
            target.tbl,
            '^at://([^/]+)/space/', 'at:space/\1/',
            '^at://[^/]+/space/'
        );
    END LOOP;

    FOR fk IN SELECT * FROM jsonb_to_recordset(saved_fks) AS s(tbl TEXT, name TEXT, def TEXT)
    LOOP
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', fk.tbl, fk.name, fk.def);
    END LOOP;
END $$;

ALTER TABLE chat.conversation_spaces
    ADD CONSTRAINT conversation_spaces_uri_check
    CHECK (space_uri LIKE 'at:space/%/blue.catbird.labyrinth.conversation/%');

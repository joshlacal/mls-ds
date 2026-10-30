-- Migration: Labyrinth 1.1 storage backend, part 6 — retention: unsend
-- (author redaction), mailbox and account purge, recovery-bundle expiry and
-- idempotency-record GC (decisions J1, J2; whitepaper v1.1 p.41-42, p.48).
--
-- Default retention is "keep until the owner deletes" (Labyrinth is the
-- long-term history archive). Nothing here expires message records by age.
--
-- Every labyrinth row stays immutable to ordinary SQL. The only DELETE and
-- record-rewrite path is the functions below: each opens a *retention
-- scope* (labyrinth.open_retention_scope, a transaction-local GUC bound to
-- the current transaction id, the same pattern as
-- chat.inventory_gc_delete_table) and labyrinth.enforce_retained_identity
-- admits a DELETE, or a rewrite of a batch record, only inside it. The scope
-- is an accident guard, not a privilege boundary: the service role can
-- already write these tables.

CREATE FUNCTION labyrinth.open_retention_scope()
RETURNS void
LANGUAGE sql
AS $$ SELECT set_config('labyrinth.retention_scope', txid_current()::text, true) $$;

CREATE FUNCTION labyrinth.in_retention_scope()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT coalesce(current_setting('labyrinth.retention_scope', true), '')
           = txid_current()::text
$$;

-- chat.enforce_immutable_identity(mutable_columns...) plus the retention
-- scope: DELETE, and on labyrinth.batches a rewrite of record/record_bytes
-- (redaction), are admitted only inside the scope.
CREATE FUNCTION labyrinth.enforce_retained_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_columns TEXT[] := CASE WHEN TG_NARGS = 0 THEN ARRAY[]::TEXT[] ELSE TG_ARGV END;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF labyrinth.in_retention_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable labyrinth row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'batches' AND labyrinth.in_retention_scope() THEN
        mutable_columns := mutable_columns || ARRAY['record', 'record_bytes'];
    END IF;
    IF (to_jsonb(NEW) - mutable_columns) IS DISTINCT FROM (to_jsonb(OLD) - mutable_columns) THEN
        RAISE EXCEPTION 'immutable labyrinth identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER mailboxes_identity_immutable ON labyrinth.mailboxes;
CREATE TRIGGER mailboxes_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.mailboxes
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity(
    'bytes_used', 'record_count', 'epoch_count', 'vdevice_count', 'next_owner_seq'
);

DROP TRIGGER devices_identity_immutable ON labyrinth.devices;
CREATE TRIGGER devices_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.devices
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity('revoked_at');

DROP TRIGGER epochs_identity_immutable ON labyrinth.epochs;
CREATE TRIGGER epochs_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.epochs
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

DROP TRIGGER epoch_members_identity_immutable ON labyrinth.epoch_members;
CREATE TRIGGER epoch_members_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.epoch_members
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

-- Recovery bundles gain a server-stamped last use (J2).
ALTER TABLE labyrinth.virtual_devices ADD COLUMN last_used_at TIMESTAMPTZ;

DROP TRIGGER virtual_devices_identity_immutable ON labyrinth.virtual_devices;
CREATE TRIGGER virtual_devices_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.virtual_devices
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity('last_used_at');

DROP TRIGGER owner_batches_identity_immutable ON labyrinth.owner_batches;
CREATE TRIGGER owner_batches_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.owner_batches
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

DROP TRIGGER epoch_heads_identity_immutable ON labyrinth.epoch_heads;
CREATE TRIGGER epoch_heads_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.epoch_heads
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

DROP TRIGGER operations_identity_immutable ON labyrinth.operations;
CREATE TRIGGER operations_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.operations
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

DROP TRIGGER batches_identity_immutable ON labyrinth.batches;
CREATE TRIGGER batches_retained_identity
BEFORE UPDATE OR DELETE ON labyrinth.batches
FOR EACH ROW EXECUTE FUNCTION labyrinth.enforce_retained_identity();

CREATE INDEX operations_created_at_idx ON labyrinth.operations (created_at);
CREATE INDEX virtual_devices_last_use_idx
    ON labyrinth.virtual_devices ((coalesce(last_used_at, created_at)));

-- Unsend / account-deletion redaction (J1): every unredacted item of
-- `author` in `conv` with a message id in `msgs` (NULL: every item) keeps
-- its batch, server order and identifying fields; its signedEncMessage
-- becomes empty bytes and it gains `redaction` (with redactedAt = `at`).
-- record_bytes and the author's usage move by the size change of the stored
-- JSON (a signed redaction can outweigh a short ciphertext). Returns the
-- number of items redacted.
CREATE FUNCTION labyrinth.redact_items(
    conv UUID, author TEXT, msgs TEXT[], redaction JSONB, at TIMESTAMPTZ
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    target RECORD;
    rewritten JSONB;
    new_bytes INTEGER;
    hits INTEGER := 0;
    marker JSONB := redaction || jsonb_build_object(
        'redactedAt', to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
BEGIN
    PERFORM labyrinth.open_retention_scope();
    FOR target IN
        SELECT b.rkey, b.record, b.record_bytes,
               array_agg(bi.item_index) AS indexes
          FROM labyrinth.batch_items bi
          JOIN labyrinth.batches b
            ON b.conversation_id = bi.conversation_id
           AND b.author_did = bi.author_did AND b.rkey = bi.rkey
         WHERE bi.conversation_id = conv AND bi.author_did = author
           AND bi.redacted_at IS NULL
           AND (msgs IS NULL OR bi.message_id = ANY(msgs))
         GROUP BY b.rkey, b.record, b.record_bytes
         ORDER BY b.rkey
    LOOP
        SELECT jsonb_agg(
                 CASE WHEN (item.ord - 1)::integer = ANY(target.indexes)
                      THEN item.value || jsonb_build_object(
                             'signedEncMessage', jsonb_build_object('$bytes', ''),
                             'redaction', marker)
                      ELSE item.value END
                 ORDER BY item.ord)
          INTO rewritten
          FROM jsonb_array_elements(target.record->'items') WITH ORDINALITY AS item(value, ord);
        rewritten := jsonb_set(target.record, '{items}', rewritten);
        new_bytes := GREATEST(target.record_bytes
            + octet_length(rewritten::text) - octet_length(target.record::text), 1);
        UPDATE labyrinth.batches
           SET record = rewritten, record_bytes = new_bytes
         WHERE conversation_id = conv AND author_did = author AND rkey = target.rkey;
        UPDATE labyrinth.batch_items SET redacted_at = at
         WHERE conversation_id = conv AND author_did = author AND rkey = target.rkey
           AND item_index = ANY(target.indexes);
        UPDATE labyrinth.author_usage
           SET bytes_used = GREATEST(bytes_used + new_bytes - target.record_bytes, 0)
         WHERE author_did = author;
        hits := hits + cardinality(target.indexes);
    END LOOP;
    RETURN hits;
END;
$$;

-- Release a recovery bundle and its ORF state (deleteVirtualDevice, J2
-- expiry). Returns whether a bundle was removed.
CREATE FUNCTION labyrinth.drop_virtual_device(owner TEXT, vdevice BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    gone RECORD;
BEGIN
    PERFORM labyrinth.open_retention_scope();
    DELETE FROM labyrinth.virtual_devices
     WHERE owner_did = owner AND vdevice_id = vdevice
    RETURNING device_key, record_bytes INTO gone;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    DELETE FROM labyrinth.orf_states WHERE owner_did = owner AND device_key = gone.device_key;
    UPDATE labyrinth.mailboxes
       SET bytes_used = GREATEST(bytes_used - gone.record_bytes, 0),
           record_count = GREATEST(record_count - 1, 0),
           vdevice_count = GREATEST(vdevice_count - 1, 0)
     WHERE owner_did = owner;
    RETURN TRUE;
END;
$$;

-- J2: keychain and passkey bundles unused since `before` expire. Code and
-- otc bundles never do. Returns the number removed.
CREATE FUNCTION labyrinth.expire_virtual_devices(before TIMESTAMPTZ, batch_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    target RECORD;
    removed INTEGER := 0;
BEGIN
    FOR target IN
        SELECT owner_did, vdevice_id FROM labyrinth.virtual_devices
         WHERE record->>'mechanism' IN ('keychain', 'passkey')
           AND coalesce(last_used_at, created_at) < before
         ORDER BY coalesce(last_used_at, created_at)
         LIMIT batch_limit
         FOR UPDATE SKIP LOCKED
    LOOP
        IF labyrinth.drop_virtual_device(target.owner_did, target.vdevice_id) THEN
            removed := removed + 1;
        END IF;
    END LOOP;
    RETURN removed;
END;
$$;

-- Idempotency records past `before`. A retry that old cannot be admitted
-- anyway: its signed write body is outside the 5-minute signedAt window.
CREATE FUNCTION labyrinth.gc_operations(before TIMESTAMPTZ, batch_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    removed INTEGER;
BEGIN
    PERFORM labyrinth.open_retention_scope();
    WITH doomed AS (
        SELECT owner_did, operation_id FROM labyrinth.operations
         WHERE created_at < before
         ORDER BY created_at
         LIMIT batch_limit
         FOR UPDATE SKIP LOCKED
    )
    DELETE FROM labyrinth.operations o USING doomed
     WHERE o.owner_did = doomed.owner_did AND o.operation_id = doomed.operation_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

-- purgeMailbox: the whole personal mailbox of `owner`, its ORF states and
-- its chain in the head directory. Attachment references are keyed by an
-- owner digest the database cannot compute; the server deletes them first.
CREATE FUNCTION labyrinth.purge_mailbox(owner TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM labyrinth.open_retention_scope();
    DELETE FROM labyrinth.orf_states WHERE owner_did = owner;
    DELETE FROM labyrinth.owner_batches WHERE owner_did = owner;
    DELETE FROM labyrinth.epoch_members WHERE owner_did = owner;
    DELETE FROM labyrinth.epochs WHERE owner_did = owner;
    DELETE FROM labyrinth.virtual_devices WHERE owner_did = owner;
    DELETE FROM labyrinth.devices WHERE owner_did = owner;
    DELETE FROM labyrinth.mailboxes WHERE owner_did = owner;
    DELETE FROM labyrinth.epoch_heads WHERE did = owner;
END;
$$;

-- The account part of deleteAccountData on this DS: the DID's idempotency
-- records (thread redaction and the mailbox purge are separate calls).
CREATE FUNCTION labyrinth.purge_operations(owner TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM labyrinth.open_retention_scope();
    DELETE FROM labyrinth.operations WHERE owner_did = owner;
END;
$$;

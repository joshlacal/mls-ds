-- Migration: Labyrinth 1.1 security hardening (findings L-F01, L-F07).
-- Additive migration only; earlier migrations are unchanged.
--
-- 1. L-F01: `labyrinth.epoch_head_floors` records the highest epoch number ever
--    anchored for a DID before `purge_mailbox` deletes its `epoch_heads` and
--    `epochs` rows, preventing post-purge epoch-number reuse. Relax
--    `previous_epoch_head` CHECK constraints on `epochs` and `epoch_heads` so a
--    post-purge chain restart at `prior_max + 1` (> 0) with `previous_epoch_head
--    IS NULL` can be stored when admitted by `directory::record_head`.
-- 2. L-F07:
--    a) Relax `batches_record_bytes_check` to `1..=1179648` so redacting a batch
--       originally near the 1 MiB admission ceiling cannot fail on tombstone
--       expansion.
--    b) Update `labyrinth.redact_items` so `author_usage.bytes_used` never
--       increases when a redaction tombstone is larger than a short ciphertext.
--    c) Update `labyrinth.drop_virtual_device` so deleting or expiring a
--       recovery bundle also stamps `revoked_at` on its virtual `labyrinth.devices`
--       row.
--    d) Harden `labyrinth.sender_message_state` (and `labyrinth.message_live_for`)
--       with `labyrinth.ever_participant` and `labyrinth.leaf_covered`.

CREATE TABLE labyrinth.epoch_head_floors (
    did TEXT PRIMARY KEY,
    max_epoch_number BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT epoch_head_floors_did_check CHECK (chat.is_bare_did(did)),
    CONSTRAINT epoch_head_floors_epoch_number_check CHECK (
        max_epoch_number BETWEEN 0 AND 1099511627776
    )
);

CREATE FUNCTION labyrinth.epoch_head_floors_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'labyrinth epoch_head_floors cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.did IS DISTINCT FROM OLD.did OR NEW.max_epoch_number < OLD.max_epoch_number THEN
        RAISE EXCEPTION 'labyrinth epoch_head_floors is monotonic'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER epoch_head_floors_monotonic
BEFORE UPDATE OR DELETE ON labyrinth.epoch_head_floors
FOR EACH ROW EXECUTE FUNCTION labyrinth.epoch_head_floors_monotonic();

ALTER TABLE labyrinth.epochs DROP CONSTRAINT epochs_previous_head_check;
ALTER TABLE labyrinth.epochs ADD CONSTRAINT epochs_previous_head_check CHECK (
    (epoch_number = 0 AND previous_epoch_head IS NULL)
    OR (epoch_number > 0 AND (previous_epoch_head IS NULL OR octet_length(previous_epoch_head) = 32))
);

ALTER TABLE labyrinth.epoch_heads DROP CONSTRAINT epoch_heads_previous_head_check;
ALTER TABLE labyrinth.epoch_heads ADD CONSTRAINT epoch_heads_previous_head_check CHECK (
    (epoch_number = 0 AND previous_epoch_head IS NULL)
    OR (epoch_number > 0 AND (previous_epoch_head IS NULL OR octet_length(previous_epoch_head) = 32))
);

CREATE OR REPLACE FUNCTION labyrinth.purge_mailbox(owner TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    prior_max BIGINT;
BEGIN
    PERFORM labyrinth.open_retention_scope();
    SELECT MAX(e) INTO prior_max FROM (
        SELECT MAX(epoch_number) AS e FROM labyrinth.epoch_heads WHERE did = owner
        UNION ALL
        SELECT MAX(epoch_number) AS e FROM labyrinth.epochs WHERE owner_did = owner
    ) seen;
    IF prior_max IS NOT NULL THEN
        INSERT INTO labyrinth.epoch_head_floors (did, max_epoch_number, updated_at)
        VALUES (owner, prior_max, clock_timestamp())
        ON CONFLICT (did) DO UPDATE
           SET max_epoch_number = GREATEST(
                   labyrinth.epoch_head_floors.max_epoch_number,
                   EXCLUDED.max_epoch_number
               ),
               updated_at = EXCLUDED.updated_at;
    END IF;
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

ALTER TABLE labyrinth.batches DROP CONSTRAINT batches_record_bytes_check;
ALTER TABLE labyrinth.batches ADD CONSTRAINT batches_record_bytes_check
    CHECK (record_bytes BETWEEN 1 AND 1179648);

CREATE OR REPLACE FUNCTION labyrinth.redact_items(
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
           SET bytes_used = GREATEST(bytes_used + LEAST(0, new_bytes - target.record_bytes), 0)
         WHERE author_did = author;
        hits := hits + cardinality(target.indexes);
    END LOOP;
    RETURN hits;
END;
$$;

CREATE OR REPLACE FUNCTION labyrinth.drop_virtual_device(owner TEXT, vdevice BYTEA)
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
    UPDATE labyrinth.devices
       SET revoked_at = to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
     WHERE owner_did = owner AND device_key = gone.device_key
       AND is_virtual AND revoked_at IS NULL;
    UPDATE labyrinth.mailboxes
       SET bytes_used = GREATEST(bytes_used - gone.record_bytes, 0),
           record_count = GREATEST(record_count - 1, 0),
           vdevice_count = GREATEST(vdevice_count - 1, 0)
     WHERE owner_did = owner;
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION labyrinth.ever_participant(conv UUID, reader TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM chat.participants
         WHERE conversation_id = conv AND user_did = reader AND status = 'active'
    )
$$;

CREATE OR REPLACE FUNCTION labyrinth.leaf_covered(conv UUID, reader TEXT, target_chat_seq BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM chat.member_devices d
         WHERE d.conversation_id = conv AND d.user_did = reader
           AND d.joined_seq <= target_chat_seq
           AND (d.removed_seq IS NULL OR target_chat_seq < d.removed_seq)
    )
$$;

CREATE OR REPLACE FUNCTION labyrinth.sender_message_state(reader TEXT, conv UUID, msg TEXT, author TEXT)
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
               AND labyrinth.ever_participant(conv, reader)
               AND labyrinth.leaf_covered(conv, reader, b.chat_seq)
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

CREATE OR REPLACE FUNCTION labyrinth.message_live_for(reader TEXT, conv UUID, msg TEXT)
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
           AND labyrinth.ever_participant(conv, reader)
           AND labyrinth.leaf_covered(conv, reader, b.chat_seq)
           AND (b.author_did = reader OR EXISTS (
                SELECT 1 FROM labyrinth.meks m
                 WHERE m.conversation_id = b.conversation_id AND m.mek_id = b.mek_id
                   AND m.author_did = b.mek_author_did
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

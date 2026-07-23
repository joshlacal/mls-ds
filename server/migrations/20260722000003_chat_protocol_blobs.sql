CREATE TABLE chat.blob_usage (
    user_did TEXT PRIMARY KEY,
    used_ciphertext_bytes BIGINT NOT NULL DEFAULT 0,
    reserved_ciphertext_bytes BIGINT NOT NULL DEFAULT 0,
    live_unbound_count BIGINT NOT NULL DEFAULT 0,
    blob_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT blob_usage_principal_fk FOREIGN KEY (user_did)
        REFERENCES chat.principals(user_did),
    CONSTRAINT blob_usage_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT blob_usage_used_bytes_check CHECK (chat.is_safe_integer(used_ciphertext_bytes)),
    CONSTRAINT blob_usage_reserved_bytes_check CHECK (chat.is_safe_integer(reserved_ciphertext_bytes)),
    CONSTRAINT blob_usage_live_unbound_count_check CHECK (chat.is_safe_integer(live_unbound_count)),
    CONSTRAINT blob_usage_blob_count_check CHECK (chat.is_safe_integer(blob_count)),
    CONSTRAINT blob_usage_caps_check CHECK (
        used_ciphertext_bytes + reserved_ciphertext_bytes <= 524288000
        AND live_unbound_count <= 100
    )
);

CREATE TABLE chat.blobs (
    blob_id UUID PRIMARY KEY,
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    owner_auth_generation BIGINT NOT NULL,
    purpose TEXT NOT NULL,
    media_type TEXT NOT NULL,
    plaintext_size BIGINT NOT NULL,
    ciphertext_size BIGINT NOT NULL,
    ciphertext_sha256 BYTEA NOT NULL,
    object_store_key TEXT,
    status TEXT NOT NULL,
    prepared_at TIMESTAMPTZ NOT NULL,
    upload_expires_at TIMESTAMPTZ NOT NULL,
    uploaded_at TIMESTAMPTZ,
    unbound_expires_at TIMESTAMPTZ,
    bound_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    -- blobs-3: zero-reference object-store GC bookkeeping. object_gc_status
    -- tracks whether the underlying physical object still needs reclaiming
    -- ('none' while the blob may still own a live object, 'pending' once the
    -- blob has entered a terminal state that orphans its object, 'reclaimed'
    -- once chat.claim_blob_object_gc has dropped object_store_key).
    object_gc_status TEXT NOT NULL DEFAULT 'none',
    object_gc_after TIMESTAMPTZ,
    object_deleted_at TIMESTAMPTZ,
    CONSTRAINT blobs_owner_key_fk FOREIGN KEY (owner_did, owner_device_id, owner_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT blobs_id_check CHECK (chat.is_uuid_v4(blob_id)),
    CONSTRAINT blobs_owner_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT blobs_owner_device_check CHECK (chat.is_uuid_v4(owner_device_id)),
    CONSTRAINT blobs_owner_key_check CHECK (chat.is_base64url_sha256(owner_key_id)),
    CONSTRAINT blobs_owner_auth_generation_check CHECK (
        chat.is_safe_integer(owner_auth_generation) AND owner_auth_generation >= 1
    ),
    CONSTRAINT blobs_purpose_check CHECK (purpose IN ('attachment','metadata')),
    CONSTRAINT blobs_media_type_check CHECK (
        (purpose = 'attachment' AND media_type IN (
            'image/heic','image/jpeg','image/png','image/webp','image/gif',
            'audio/aac','audio/mp4','audio/ogg','audio/opus'
        ))
        OR (purpose = 'metadata' AND media_type IN (
            'image/heic','image/jpeg','image/png','image/webp'
        ))
    ),
    CONSTRAINT blobs_plaintext_size_check CHECK (
        chat.is_safe_integer(plaintext_size) AND plaintext_size >= 1
    ),
    CONSTRAINT blobs_ciphertext_size_check CHECK (
        chat.is_safe_integer(ciphertext_size) AND ciphertext_size >= 17
    ),
    CONSTRAINT blobs_sizes_check CHECK (
        ciphertext_size = plaintext_size + 16
        AND ciphertext_size <= 10485760
        AND (media_type NOT LIKE 'audio/%' OR ciphertext_size <= 8388608)
    ),
    CONSTRAINT blobs_ciphertext_hash_check CHECK (octet_length(ciphertext_sha256) = 32),
    CONSTRAINT blobs_object_store_key_check CHECK (
        object_store_key IS NULL OR octet_length(object_store_key) BETWEEN 1 AND 1024
    ),
    CONSTRAINT blobs_status_check CHECK (
        status IN ('prepared','completedUnbound','bound','deleted','expired')
    ),
    CONSTRAINT blobs_upload_expiry_check CHECK (
        upload_expires_at = prepared_at + INTERVAL '5 minutes'
    ),
    CONSTRAINT blobs_status_shape_check CHECK (
        (status = 'prepared' AND uploaded_at IS NULL AND unbound_expires_at IS NULL
            AND bound_at IS NULL AND deleted_at IS NULL AND expired_at IS NULL)
        OR (status = 'completedUnbound' AND uploaded_at IS NOT NULL
            AND unbound_expires_at = uploaded_at + INTERVAL '1 hour'
            AND object_store_key IS NOT NULL AND bound_at IS NULL
            AND deleted_at IS NULL AND expired_at IS NULL)
        OR (status = 'bound' AND uploaded_at IS NOT NULL AND unbound_expires_at IS NOT NULL
            AND object_store_key IS NOT NULL AND bound_at IS NOT NULL
            AND deleted_at IS NULL AND expired_at IS NULL)
        OR (status = 'deleted' AND uploaded_at IS NOT NULL AND deleted_at IS NOT NULL
            AND bound_at IS NULL AND expired_at IS NULL)
        OR (status = 'expired' AND expired_at IS NOT NULL AND bound_at IS NULL
            AND (
                (uploaded_at IS NULL AND object_store_key IS NULL
                    AND unbound_expires_at IS NULL AND expired_at = upload_expires_at)
                OR (uploaded_at IS NOT NULL
                    AND (object_store_key IS NOT NULL OR object_gc_status = 'reclaimed')
                    AND unbound_expires_at = uploaded_at + INTERVAL '1 hour'
                    AND expired_at = unbound_expires_at)
            ))
    ),
    -- blobs-2: a blob may only be bound inside its unbound window. Without
    -- this a row could be marked 'bound' after unbound_expires_at had already
    -- lapsed (or before it was even uploaded). Half-open [uploaded_at,
    -- unbound_expires_at) matches the expiry convention used elsewhere.
    CONSTRAINT blobs_bound_at_window_check CHECK (
        bound_at IS NULL OR (
            uploaded_at IS NOT NULL AND unbound_expires_at IS NOT NULL
            AND uploaded_at <= bound_at AND bound_at < unbound_expires_at
        )
    ),
    -- blobs-3: object-store GC bookkeeping must stay coherent with the blob's
    -- terminal state. Only terminal ('deleted'/'expired') blobs schedule GC,
    -- and object_store_key may only be NULL on a fully reclaimed row.
    CONSTRAINT blobs_object_gc_status_check CHECK (
        object_gc_status IN ('none','pending','reclaimed')
    ),
    CONSTRAINT blobs_object_gc_shape_check CHECK (
        (object_gc_status = 'none'
            AND object_gc_after IS NULL AND object_deleted_at IS NULL)
        OR (object_gc_status = 'pending'
            AND status IN ('deleted','expired')
            AND object_gc_after IS NOT NULL
            AND object_store_key IS NOT NULL
            AND object_deleted_at IS NULL)
        OR (object_gc_status = 'reclaimed'
            AND status IN ('deleted','expired')
            AND object_gc_after IS NOT NULL
            AND object_store_key IS NULL
            AND object_deleted_at IS NOT NULL)
    ),
    CONSTRAINT blobs_ticket_owner_uq UNIQUE (blob_id, owner_did, owner_device_id),
    CONSTRAINT blobs_ticket_lifetime_uq UNIQUE (
        blob_id, owner_did, owner_device_id, prepared_at, upload_expires_at
    ),
    CONSTRAINT blobs_binding_identity_uq UNIQUE (
        blob_id, owner_did, owner_device_id, ciphertext_sha256,
        plaintext_size, ciphertext_size, purpose
    ),
    -- blobs-2: superkey unique (blob_id is already the PK) exposing the upload
    -- window as a composite FK target so chat.blob_bindings can bind its own
    -- copy of (uploaded_at, unbound_expires_at) to the exact owning blob and
    -- assert the same strict bind-time ordering on the binding row.
    CONSTRAINT blobs_upload_window_uq UNIQUE (
        blob_id, uploaded_at, unbound_expires_at
    )
);

CREATE INDEX blobs_live_owner_idx
    ON chat.blobs (owner_did, status, unbound_expires_at, blob_id)
    WHERE status IN ('prepared','completedUnbound');

-- blobs-1: one physical object may back at most one blob row. Without this a
-- single object_store_key could alias multiple blobs and be freed while still
-- referenced. Partial so reclaimed rows (NULL key) do not collide.
CREATE UNIQUE INDEX blobs_object_store_key_uq
    ON chat.blobs (object_store_key)
    WHERE object_store_key IS NOT NULL;

-- blobs-4: supports the per-(owner_did, owner_device_id) active-blob cap
-- aggregation in chat.assert_blob_device_active_cap.
CREATE INDEX blobs_active_device_idx
    ON chat.blobs (owner_did, owner_device_id, status);

-- blobs-3: claim ordering for chat.claim_blob_object_gc. Partial so only rows
-- awaiting physical reclaim are scanned.
CREATE INDEX blobs_object_gc_claim_idx
    ON chat.blobs (object_gc_after)
    WHERE object_gc_status = 'pending';

CREATE TABLE chat.blob_upload_tickets (
    ticket_hash BYTEA PRIMARY KEY,
    blob_id UUID NOT NULL UNIQUE,
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT blob_upload_tickets_blob_owner_fk
        FOREIGN KEY (blob_id, owner_did, owner_device_id)
        REFERENCES chat.blobs(blob_id, owner_did, owner_device_id),
    CONSTRAINT blob_upload_tickets_blob_lifetime_fk
        FOREIGN KEY (blob_id, owner_did, owner_device_id, created_at, expires_at)
        REFERENCES chat.blobs(
            blob_id, owner_did, owner_device_id, prepared_at, upload_expires_at
        ),
    CONSTRAINT blob_upload_tickets_owner_device_fk FOREIGN KEY (owner_did, owner_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT blob_upload_tickets_hash_check CHECK (octet_length(ticket_hash) = 32),
    CONSTRAINT blob_upload_tickets_blob_id_check CHECK (chat.is_uuid_v4(blob_id)),
    CONSTRAINT blob_upload_tickets_owner_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT blob_upload_tickets_owner_device_check CHECK (chat.is_uuid_v4(owner_device_id)),
    CONSTRAINT blob_upload_tickets_expiry_check CHECK (
        expires_at = created_at + INTERVAL '5 minutes'
    ),
    CONSTRAINT blob_upload_tickets_consumption_check CHECK (
        consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at)
    )
);

ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_avatar_binding_identity_uq UNIQUE (
        conversation_id, origin_transition_id, metadata_version, avatar_blob_id,
        avatar_ciphertext_sha256, avatar_ciphertext_size, avatar_purpose,
        author_did, author_device_id
    );

CREATE TABLE chat.blob_bindings (
    blob_id UUID PRIMARY KEY,
    binding_kind TEXT NOT NULL,
    conversation_id UUID NOT NULL,
    entry_seq BIGINT,
    message_id UUID,
    metadata_origin_transition_id UUID,
    metadata_version BIGINT,
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    descriptor_bytes BYTEA NOT NULL,
    descriptor_sha256 BYTEA NOT NULL,
    aad_bytes BYTEA NOT NULL,
    aad_sha256 BYTEA NOT NULL,
    ciphertext_sha256 BYTEA NOT NULL,
    plaintext_size BIGINT NOT NULL,
    ciphertext_size BIGINT NOT NULL,
    purpose TEXT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL,
    -- blobs-2: the binding copies the owning blob's unbound window so it can
    -- assert the same strict bind-time ordering (uploaded_at <= bound_at <
    -- unbound_expires_at) as a hard table constraint on the binding row itself.
    -- blob_bindings_blob_window_fk binds these to the exact blob, so they cannot
    -- be forged independently of chat.blobs.
    uploaded_at TIMESTAMPTZ NOT NULL,
    unbound_expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT blob_bindings_blob_identity_fk
        FOREIGN KEY (
            blob_id, owner_did, owner_device_id, ciphertext_sha256,
            plaintext_size, ciphertext_size, purpose
        )
        REFERENCES chat.blobs(
            blob_id, owner_did, owner_device_id, ciphertext_sha256,
            plaintext_size, ciphertext_size, purpose
        ),
    CONSTRAINT blob_bindings_blob_window_fk
        FOREIGN KEY (blob_id, uploaded_at, unbound_expires_at)
        REFERENCES chat.blobs(blob_id, uploaded_at, unbound_expires_at)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT blob_bindings_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT blob_bindings_entry_fk FOREIGN KEY (conversation_id, entry_seq)
        REFERENCES chat.entries(conversation_id, seq) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT blob_bindings_application_entry_fk FOREIGN KEY (
        conversation_id, entry_seq, message_id, owner_did, owner_device_id
    ) REFERENCES chat.entries(
        conversation_id, seq, message_id, actor_did, actor_device_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT blob_bindings_metadata_snapshot_fk FOREIGN KEY (
        conversation_id, metadata_origin_transition_id, metadata_version, blob_id,
        ciphertext_sha256, ciphertext_size, purpose, owner_did, owner_device_id
    ) REFERENCES chat.metadata_snapshots(
        conversation_id, origin_transition_id, metadata_version, avatar_blob_id,
        avatar_ciphertext_sha256, avatar_ciphertext_size, avatar_purpose,
        author_did, author_device_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT blob_bindings_owner_device_fk FOREIGN KEY (owner_did, owner_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT blob_bindings_blob_id_check CHECK (chat.is_uuid_v4(blob_id)),
    CONSTRAINT blob_bindings_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT blob_bindings_entry_seq_check CHECK (
        entry_seq IS NULL OR chat.is_safe_integer(entry_seq)
    ),
    CONSTRAINT blob_bindings_message_id_check CHECK (message_id IS NULL OR chat.is_uuid_v4(message_id)),
    CONSTRAINT blob_bindings_metadata_origin_check CHECK (
        metadata_origin_transition_id IS NULL OR chat.is_uuid_v4(metadata_origin_transition_id)
    ),
    CONSTRAINT blob_bindings_metadata_version_check CHECK (
        metadata_version IS NULL OR (chat.is_safe_integer(metadata_version) AND metadata_version >= 1)
    ),
    CONSTRAINT blob_bindings_owner_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT blob_bindings_owner_device_check CHECK (chat.is_uuid_v4(owner_device_id)),
    CONSTRAINT blob_bindings_kind_check CHECK (binding_kind IN ('application','metadataAvatar')),
    CONSTRAINT blob_bindings_context_shape_check CHECK (
        (binding_kind = 'application' AND purpose = 'attachment'
            AND entry_seq IS NOT NULL AND message_id IS NOT NULL
            AND metadata_origin_transition_id IS NULL AND metadata_version IS NULL)
        OR (binding_kind = 'metadataAvatar' AND purpose = 'metadata'
            AND entry_seq IS NULL AND message_id IS NULL
            AND metadata_origin_transition_id IS NOT NULL AND metadata_version IS NOT NULL)
    ),
    CONSTRAINT blob_bindings_descriptor_hash_check CHECK (
        octet_length(descriptor_bytes) BETWEEN 1 AND 16384
        AND octet_length(descriptor_sha256) = 32
        AND descriptor_sha256 = digest(descriptor_bytes, 'sha256')
    ),
    CONSTRAINT blob_bindings_aad_hash_check CHECK (
        octet_length(aad_bytes) BETWEEN 1 AND 4096
        AND octet_length(aad_sha256) = 32
        AND aad_sha256 = digest(aad_bytes, 'sha256')
    ),
    CONSTRAINT blob_bindings_ciphertext_hash_check CHECK (octet_length(ciphertext_sha256) = 32),
    CONSTRAINT blob_bindings_plaintext_size_check CHECK (
        chat.is_safe_integer(plaintext_size) AND plaintext_size >= 1
    ),
    CONSTRAINT blob_bindings_ciphertext_size_check CHECK (
        chat.is_safe_integer(ciphertext_size) AND ciphertext_size >= 17
    ),
    CONSTRAINT blob_bindings_size_relation_check CHECK (
        ciphertext_size = plaintext_size + 16 AND ciphertext_size <= 10485760
    ),
    -- blobs-2: the binding row carries the same strict bind-time ordering as the
    -- owning blob's blobs_bound_at_window_check. Its window columns are pinned to
    -- the exact blob by blob_bindings_blob_window_fk, so this is a hard,
    -- non-forgeable ordering constraint at the binding grain.
    CONSTRAINT blob_bindings_bound_at_check CHECK (
        uploaded_at <= bound_at AND bound_at < unbound_expires_at
    ),
    CONSTRAINT blob_bindings_metadata_identity_uq UNIQUE (
        blob_id, conversation_id, metadata_origin_transition_id, metadata_version,
        ciphertext_sha256, ciphertext_size, purpose, owner_did, owner_device_id
    )
);

ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_avatar_blob_fk
    FOREIGN KEY (avatar_blob_id) REFERENCES chat.blobs(blob_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_avatar_binding_fk FOREIGN KEY (
        avatar_blob_id, conversation_id, avatar_binding_origin_transition_id,
        avatar_binding_metadata_version,
        avatar_ciphertext_sha256, avatar_ciphertext_size, avatar_purpose,
        avatar_binding_owner_did, avatar_binding_owner_device_id
    ) REFERENCES chat.blob_bindings(
        blob_id, conversation_id, metadata_origin_transition_id, metadata_version,
        ciphertext_sha256, ciphertext_size, purpose, owner_did, owner_device_id
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION chat.assert_blob_binding_lifecycle(target_blob UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    blob_row chat.blobs%ROWTYPE;
    blob_found BOOLEAN;
    binding_count BIGINT;
BEGIN
    SELECT * INTO blob_row FROM chat.blobs WHERE blob_id = target_blob;
    blob_found := FOUND;
    SELECT count(*) INTO binding_count
      FROM chat.blob_bindings
     WHERE blob_id = target_blob;
    IF NOT blob_found THEN
        IF binding_count <> 0 THEN
            RAISE EXCEPTION 'blob binding lifecycle mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.principals
     WHERE user_did = blob_row.owner_did
     FOR UPDATE;
    IF blob_row.status = 'bound' THEN
        IF binding_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM chat.blob_bindings binding
             WHERE binding.blob_id = target_blob
               AND binding.bound_at = blob_row.bound_at
        ) THEN
            RAISE EXCEPTION 'blob binding lifecycle mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF binding_count <> 0 THEN
        RAISE EXCEPTION 'blob binding lifecycle mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_blob_binding_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_blob_binding_lifecycle(OLD.blob_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT' OR NEW.blob_id IS DISTINCT FROM OLD.blob_id) THEN
        PERFORM chat.assert_blob_binding_lifecycle(NEW.blob_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER blobs_binding_lifecycle_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_binding_lifecycle();

CREATE CONSTRAINT TRIGGER blob_bindings_lifecycle_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blob_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_binding_lifecycle();

CREATE FUNCTION chat.assert_blob_ticket_lifecycle(target_blob UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    blob_row chat.blobs%ROWTYPE;
    ticket_row chat.blob_upload_tickets%ROWTYPE;
    ticket_count BIGINT;
BEGIN
    SELECT * INTO blob_row FROM chat.blobs WHERE blob_id = target_blob;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.blob_upload_tickets WHERE blob_id = target_blob
        ) THEN
            RAISE EXCEPTION 'blob upload ticket lifecycle mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;
    PERFORM 1 FROM chat.principals
     WHERE user_did = blob_row.owner_did
     FOR UPDATE;
    SELECT count(*) INTO ticket_count
      FROM chat.blob_upload_tickets
     WHERE blob_id = target_blob;
    SELECT * INTO ticket_row
      FROM chat.blob_upload_tickets
     WHERE blob_id = target_blob;
    IF ticket_count <> 1 OR NOT FOUND
       OR ticket_row.created_at <> blob_row.prepared_at
       OR ticket_row.expires_at <> blob_row.upload_expires_at
       OR (blob_row.status = 'prepared' AND ticket_row.consumed_at IS NOT NULL)
       OR (blob_row.status IN ('completedUnbound','bound','deleted')
           AND ticket_row.consumed_at IS DISTINCT FROM blob_row.uploaded_at)
       OR (blob_row.status = 'expired'
           AND ticket_row.consumed_at IS DISTINCT FROM blob_row.uploaded_at) THEN
        RAISE EXCEPTION 'blob upload ticket lifecycle mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_blob_ticket_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_blob_ticket_lifecycle(OLD.blob_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT' OR NEW.blob_id IS DISTINCT FROM OLD.blob_id) THEN
        PERFORM chat.assert_blob_ticket_lifecycle(NEW.blob_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER blobs_ticket_lifecycle_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_ticket_lifecycle();

CREATE CONSTRAINT TRIGGER blob_upload_tickets_blob_lifecycle_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blob_upload_tickets
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_ticket_lifecycle();

-- blobs-5: per-row usage maintenance is incremental. chat.apply_blob_usage_delta
-- (below) is the O(1) counter-maintenance path applied under the principal
-- anchor on every mutation instead of re-deriving counters from the owner's full
-- blob history. chat.assert_blob_usage is the per-row guard on the hot path: it
-- verifies the structural invariants any correct delta sequence must preserve
-- WITHOUT scanning owner history, so per-row blob mutations never rescan. The
-- authoritative O(n) re-derivation is retained off the hot path as
-- chat.reconcile_blob_usage (defined after the trigger function) for a periodic
-- verification sweep.
CREATE FUNCTION chat.assert_blob_usage(target_did TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    usage_row chat.blob_usage%ROWTYPE;
BEGIN
    PERFORM 1 FROM chat.principals WHERE user_did = target_did FOR UPDATE;
    SELECT * INTO usage_row FROM chat.blob_usage WHERE user_did = target_did;
    IF NOT FOUND THEN RETURN; END IF;
    -- Structural consistency any correct incremental delta must preserve:
    -- counters are non-negative and the live-unbound set is a subset of all live
    -- blobs (live_unbound_count <= blob_count). This localizes a delta bug to the
    -- offending write without a full owner-history scan. Absolute owner ceilings
    -- (<= 500 MiB, <= 100 live-unbound) remain enforced by blob_usage_caps_check.
    IF usage_row.used_ciphertext_bytes < 0
       OR usage_row.reserved_ciphertext_bytes < 0
       OR usage_row.live_unbound_count < 0
       OR usage_row.blob_count < 0
       OR usage_row.live_unbound_count > usage_row.blob_count THEN
        RAISE EXCEPTION 'blob usage counters are structurally inconsistent'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- blobs-5: incremental, O(1) counter maintenance -- the delta path applied on
-- every per-row blob mutation under the principal anchor, instead of
-- re-aggregating owner history. Deltas may be negative (e.g. a reserved blob is
-- consumed or a live blob is deleted). The principal row is locked FOR UPDATE to
-- serialize concurrent counter updates; the existing usage row is mutated in
-- place with an explicit UPDATE, falling back to an INSERT only for the owner's
-- first blob. blob_usage_caps_check still bounds the resulting counters.
CREATE FUNCTION chat.apply_blob_usage_delta(
    target_did TEXT,
    used_delta BIGINT,
    reserved_delta BIGINT,
    unbound_delta BIGINT,
    count_delta BIGINT
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    touched BIGINT;
BEGIN
    PERFORM 1 FROM chat.principals WHERE user_did = target_did FOR UPDATE;
    UPDATE chat.blob_usage
       SET used_ciphertext_bytes = used_ciphertext_bytes + used_delta,
           reserved_ciphertext_bytes = reserved_ciphertext_bytes + reserved_delta,
           live_unbound_count = live_unbound_count + unbound_delta,
           blob_count = blob_count + count_delta,
           updated_at = clock_timestamp()
     WHERE user_did = target_did;
    GET DIAGNOSTICS touched = ROW_COUNT;
    IF touched = 0 THEN
        INSERT INTO chat.blob_usage (
            user_did, used_ciphertext_bytes, reserved_ciphertext_bytes,
            live_unbound_count, blob_count, updated_at
        )
        VALUES (
            target_did,
            GREATEST(used_delta, 0), GREATEST(reserved_delta, 0),
            GREATEST(unbound_delta, 0), GREATEST(count_delta, 0),
            clock_timestamp()
        );
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_blob_usage()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'blob_usage' THEN
        IF TG_OP <> 'INSERT' THEN PERFORM chat.assert_blob_usage(OLD.user_did); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM chat.assert_blob_usage(NEW.user_did); END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN PERFORM chat.assert_blob_usage(OLD.owner_did); END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT' OR NEW.owner_did IS DISTINCT FROM OLD.owner_did) THEN
            PERFORM chat.assert_blob_usage(NEW.owner_did);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

-- blobs-5: authoritative O(n) reconciliation, retained OFF the per-row hot path
-- for a periodic verification sweep. It re-derives every counter from the
-- owner's full blob history and rejects any drift from the maintained
-- chat.blob_usage counters. It is intentionally NOT wired to the per-row usage
-- triggers (those use the incremental delta plus the structural guard in
-- chat.assert_blob_usage); a scheduled job calls this to catch accumulated
-- drift.
CREATE FUNCTION chat.reconcile_blob_usage(target_did TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    usage_row chat.blob_usage%ROWTYPE;
    expected_used BIGINT;
    expected_reserved BIGINT;
    expected_unbound BIGINT;
    expected_count BIGINT;
BEGIN
    PERFORM 1 FROM chat.principals WHERE user_did = target_did FOR UPDATE;
    SELECT
        COALESCE(sum(ciphertext_size) FILTER (
            WHERE status IN ('completedUnbound','bound')
        ), 0),
        COALESCE(sum(ciphertext_size) FILTER (WHERE status = 'prepared'), 0),
        count(*) FILTER (WHERE status IN ('prepared','completedUnbound')),
        count(*) FILTER (WHERE status IN ('prepared','completedUnbound','bound'))
      INTO expected_used, expected_reserved, expected_unbound, expected_count
      FROM chat.blobs
     WHERE owner_did = target_did;
    SELECT * INTO usage_row FROM chat.blob_usage WHERE user_did = target_did;
    IF NOT FOUND THEN
        IF expected_count <> 0 THEN
            RAISE EXCEPTION 'blob usage row missing' USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;
    IF usage_row.used_ciphertext_bytes <> expected_used
       OR usage_row.reserved_ciphertext_bytes <> expected_reserved
       OR usage_row.live_unbound_count <> expected_unbound
       OR usage_row.blob_count <> expected_count THEN
        RAISE EXCEPTION 'blob usage counters disagree with authoritative blobs'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE CONSTRAINT TRIGGER blob_usage_reconciled_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blob_usage
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_usage();

CREATE CONSTRAINT TRIGGER blobs_usage_reconciled_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_usage();

CREATE FUNCTION chat.enforce_blob_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'blobs' THEN
        -- blobs-3: zero-reference object-store GC reclaim. This is the ONLY
        -- mutation permitted on a terminal ('deleted'/'expired') blob and the
        -- ONLY path allowed to null object_store_key. It flips a pending
        -- reclaim to 'reclaimed', stamps object_deleted_at, drops the
        -- object_store_key, and must leave every other column untouched.
        IF OLD.object_gc_status = 'pending' AND NEW.object_gc_status = 'reclaimed' THEN
            IF OLD.object_store_key IS NULL
               OR NEW.object_store_key IS NOT NULL
               OR NEW.object_deleted_at IS NULL
               OR (to_jsonb(NEW) - ARRAY['object_gc_status','object_store_key','object_deleted_at'])
                  IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['object_gc_status','object_store_key','object_deleted_at']) THEN
                RAISE EXCEPTION 'invalid blob object-store gc reclaim' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;

        IF OLD.status IN ('bound','deleted','expired') AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal blob cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF (OLD.status = 'prepared'
            AND NEW.status NOT IN ('prepared','completedUnbound','expired'))
           OR (OLD.status = 'completedUnbound'
            AND NEW.status NOT IN ('completedUnbound','bound','deleted','expired'))
           OR (OLD.object_store_key IS NOT NULL
               AND NEW.object_store_key IS DISTINCT FROM OLD.object_store_key)
           OR (OLD.uploaded_at IS NOT NULL AND NEW.uploaded_at IS DISTINCT FROM OLD.uploaded_at)
           OR (OLD.unbound_expires_at IS NOT NULL
               AND NEW.unbound_expires_at IS DISTINCT FROM OLD.unbound_expires_at)
           OR (NEW.uploaded_at IS NOT NULL AND NEW.uploaded_at >= NEW.upload_expires_at) THEN
            RAISE EXCEPTION 'invalid blob lifecycle transition' USING ERRCODE = '23514';
        END IF;

        -- blobs-3: entering a terminal state that still owns a physical object
        -- schedules zero-reference object-store GC. 'deleted' always inherits
        -- an object from completedUnbound; 'expired' only does so for the
        -- uploaded sub-shape (object_store_key IS NOT NULL). A 24h grace after
        -- the terminal timestamp lets in-flight reads drain before the object
        -- is physically reclaimed by chat.claim_blob_object_gc.
        IF NEW.status IN ('deleted','expired')
           AND OLD.status NOT IN ('deleted','expired')
           AND NEW.object_store_key IS NOT NULL
           AND NEW.object_gc_status = 'none' THEN
            NEW.object_gc_status := 'pending';
            NEW.object_gc_after := COALESCE(NEW.deleted_at, NEW.expired_at) + INTERVAL '24 hours';
        END IF;
    ELSE
        IF OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'consumed blob upload ticket is terminal'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE UNIQUE INDEX blob_bindings_application_entry_uq
    ON chat.blob_bindings (conversation_id, entry_seq)
    WHERE binding_kind = 'application';

CREATE TRIGGER blobs_identity_immutable
BEFORE UPDATE OR DELETE ON chat.blobs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'object_store_key', 'status', 'uploaded_at', 'unbound_expires_at',
    'bound_at', 'deleted_at', 'expired_at',
    -- blobs-3: object-store GC bookkeeping is lifecycle state, not identity;
    -- enforce_blob_lifecycle_transition gates every legal change to these.
    'object_gc_status', 'object_gc_after', 'object_deleted_at'
);

CREATE TRIGGER blobs_lifecycle_monotonic
BEFORE UPDATE ON chat.blobs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_lifecycle_transition();

CREATE TRIGGER blob_usage_identity_immutable
BEFORE UPDATE OR DELETE ON chat.blob_usage
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'used_ciphertext_bytes', 'reserved_ciphertext_bytes',
    'live_unbound_count', 'blob_count', 'updated_at'
);

CREATE TRIGGER blob_upload_tickets_identity_immutable
BEFORE UPDATE OR DELETE ON chat.blob_upload_tickets
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('consumed_at');

CREATE TRIGGER blob_upload_tickets_lifecycle_monotonic
BEFORE UPDATE ON chat.blob_upload_tickets
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_lifecycle_transition();

CREATE TRIGGER blob_bindings_immutable
BEFORE UPDATE OR DELETE ON chat.blob_bindings
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- blobs-3: zero-reference object-store GC claim, mirroring the chat.outbox
-- SKIP LOCKED lease convention. Selects up to batch_limit pending rows whose
-- grace window has elapsed, marks each 'reclaimed' (the sole path permitted to
-- null object_store_key -- gated by enforce_blob_lifecycle_transition), and
-- returns the physical object_store_key that WAS attached so the caller can
-- delete the underlying object. Concurrent GC workers never collide because the
-- inner SELECT takes row locks with FOR UPDATE SKIP LOCKED.
CREATE FUNCTION chat.claim_blob_object_gc(batch_limit INTEGER)
RETURNS TABLE (blob_id UUID, object_store_key TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH claimed AS (
        SELECT c.blob_id AS claimed_blob_id, c.object_store_key AS claimed_store_key
          FROM chat.blobs c
         WHERE c.object_gc_status = 'pending'
           AND c.object_gc_after <= clock_timestamp()
         ORDER BY c.object_gc_after
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
    ),
    reclaimed AS (
        UPDATE chat.blobs b
           SET object_gc_status = 'reclaimed',
               object_store_key = NULL,
               object_deleted_at = clock_timestamp()
          FROM claimed
         WHERE b.blob_id = claimed.claimed_blob_id
        RETURNING b.blob_id AS reclaimed_blob_id
    )
    SELECT claimed.claimed_blob_id, claimed.claimed_store_key
      FROM claimed
      JOIN reclaimed ON reclaimed.reclaimed_blob_id = claimed.claimed_blob_id;
END
$$;

-- blobs-4: per-(owner_did, owner_device_id) live-unbound blob ceiling. The
-- per-user chat.blob_usage.live_unbound_count cap is a maintained counter; this
-- check aggregates chat.blobs directly, so it holds even if that counter drifts
-- or is bypassed, and it bounds any single device independently. The principal
-- row is locked FOR UPDATE to serialize concurrent creation (mirrors
-- chat.assert_blob_usage). 100 matches the per-user live_unbound ceiling; a
-- legitimate client never approaches 100 simultaneously in-flight uploads, so
-- this is a defense-in-depth bound that can be tuned downward to cap a single
-- device to a fraction of a multi-device user's budget.
-- blobs-4: structural configured ceiling for active (prepared/completedUnbound)
-- blobs per exact {owner_did, owner_device_id}. 100 matches the per-user
-- live_unbound ceiling; a legitimate client never approaches this many
-- simultaneous in-flight uploads, so it is a defense-in-depth bound that can be
-- tuned downward to cap a single device to a fraction of a multi-device user's
-- budget.
CREATE FUNCTION chat.max_active_blobs_per_device()
RETURNS INT
LANGUAGE sql
IMMUTABLE
AS $$ SELECT 100 $$;

CREATE FUNCTION chat.assert_blob_device_active_cap(target_did TEXT, target_device UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    active_count BIGINT;
BEGIN
    PERFORM 1 FROM chat.principals WHERE user_did = target_did FOR UPDATE;
    SELECT count(*) INTO active_count
      FROM chat.blobs
     WHERE owner_did = target_did
       AND owner_device_id = target_device
       AND status IN ('prepared','completedUnbound');
    IF active_count > chat.max_active_blobs_per_device() THEN
        RAISE EXCEPTION 'per-device active blob cap exceeded'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_blob_device_active_cap()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_blob_device_active_cap(OLD.owner_did, OLD.owner_device_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT'
            OR NEW.owner_did IS DISTINCT FROM OLD.owner_did
            OR NEW.owner_device_id IS DISTINCT FROM OLD.owner_device_id
            OR NEW.status IS DISTINCT FROM OLD.status) THEN
        PERFORM chat.assert_blob_device_active_cap(NEW.owner_did, NEW.owner_device_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER blobs_device_active_cap_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.blobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_blob_device_active_cap();

-- blobs-6: bounded GC for terminal upload tickets. The blob<->ticket lifecycle
-- (chat.assert_blob_ticket_lifecycle) requires every existing blob row to keep
-- exactly one ticket, and requires a ticket's blob to exist -- so a ticket is
-- terminal (permanently unusable) precisely once its owning blob row is gone.
-- This reclaims those orphaned tickets in bounded SKIP LOCKED batches, mirroring
-- chat.gc_expired_inventory_sessions. It runs with triggers suspended
-- (session_replication_role = replica) because blob_upload_tickets_identity_immutable
-- otherwise forbids any DELETE.
CREATE INDEX blob_upload_tickets_terminal_gc_idx
    ON chat.blob_upload_tickets (expires_at, ticket_hash);

CREATE FUNCTION chat.gc_terminal_blob_upload_tickets(batch_limit INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    victims BYTEA[];
    removed BIGINT;
BEGIN
    IF batch_limit < 0 THEN batch_limit := 0; END IF;
    PERFORM set_config('session_replication_role', 'replica', true);
    SELECT array_agg(ticket_hash) INTO victims
      FROM (
        SELECT t.ticket_hash
          FROM chat.blob_upload_tickets t
         WHERE NOT EXISTS (
                SELECT 1 FROM chat.blobs b WHERE b.blob_id = t.blob_id
           )
         ORDER BY t.expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
      ) terminal;
    IF victims IS NULL THEN RETURN 0; END IF;
    DELETE FROM chat.blob_upload_tickets WHERE ticket_hash = ANY(victims);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;

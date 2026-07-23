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
                OR (uploaded_at IS NOT NULL AND object_store_key IS NOT NULL
                    AND unbound_expires_at = uploaded_at + INTERVAL '1 hour'
                    AND expired_at = unbound_expires_at)
            ))
    ),
    CONSTRAINT blobs_ticket_owner_uq UNIQUE (blob_id, owner_did, owner_device_id),
    CONSTRAINT blobs_ticket_lifetime_uq UNIQUE (
        blob_id, owner_did, owner_device_id, prepared_at, upload_expires_at
    ),
    CONSTRAINT blobs_binding_identity_uq UNIQUE (
        blob_id, owner_did, owner_device_id, ciphertext_sha256,
        plaintext_size, ciphertext_size, purpose
    )
);

CREATE INDEX blobs_live_owner_idx
    ON chat.blobs (owner_did, status, unbound_expires_at, blob_id)
    WHERE status IN ('prepared','completedUnbound');

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
        consumed_at IS NULL OR consumed_at BETWEEN created_at AND expires_at
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
    CONSTRAINT blob_bindings_blob_identity_fk
        FOREIGN KEY (
            blob_id, owner_did, owner_device_id, ciphertext_sha256,
            plaintext_size, ciphertext_size, purpose
        )
        REFERENCES chat.blobs(
            blob_id, owner_did, owner_device_id, ciphertext_sha256,
            plaintext_size, ciphertext_size, purpose
        ),
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

CREATE FUNCTION chat.assert_blob_usage(target_did TEXT)
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
           OR (NEW.uploaded_at IS NOT NULL AND NEW.uploaded_at > NEW.upload_expires_at) THEN
            RAISE EXCEPTION 'invalid blob lifecycle transition' USING ERRCODE = '23514';
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
    'bound_at', 'deleted_at', 'expired_at'
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

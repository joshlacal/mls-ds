CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA chat;

CREATE FUNCTION chat.is_safe_integer(value BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value >= 0 AND value <= 9007199254740991
$$;

CREATE FUNCTION chat.is_uuid_v4(value UUID)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value::TEXT ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$$;

CREATE FUNCTION chat.is_base64url_sha256(value TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT octet_length(value) = 43
       AND value ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
$$;

CREATE FUNCTION chat.ed25519_key_id(signing_public_key BYTEA)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT rtrim(
        translate(encode(digest(signing_public_key, 'sha256'), 'base64'), '+/', '-_'),
        '='
    )
$$;

CREATE FUNCTION chat.protocol_capabilities()
RETURNS JSONB
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT $json${
      "protocolVersion":"1",
      "mlsVersion":"1.0",
      "cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
      "credentialType":"basic",
      "addByValue":"supported",
      "updatePath":"supported",
      "removeByValue":"supported",
      "ratchetTreeGroupInfo":"supported",
      "externalPubGroupInfo":"presentButExternalCommitsForbidden",
      "applicationFrameProfile":"dagCborApplication1",
      "controlProfile":"publicGroup1",
      "attachmentProfile":"aes256GcmBlob1",
      "metadataProfile":"exporterAes256Gcm1",
      "typingProfile":"signedClearEphemeral1"
    }$json$::JSONB
$$;

CREATE FUNCTION chat.is_bare_did(value TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    host TEXT;
    labels TEXT[];
    label TEXT;
    final_label TEXT;
BEGIN
    IF octet_length(value) < 12 OR octet_length(value) > 261 OR value !~ '^[[:ascii:]]+$' THEN
        RETURN FALSE;
    END IF;
    IF value ~ '^did:plc:[a-z2-7]{24}$' THEN
        RETURN TRUE;
    END IF;
    IF left(value, 8) <> 'did:web:' THEN
        RETURN FALSE;
    END IF;
    host := substring(value FROM 9);
    IF octet_length(host) < 1
       OR octet_length(host) > 253
       OR host <> lower(host)
       OR host !~ '^[a-z0-9.-]+$'
       OR host LIKE '.%'
       OR host LIKE '%.'
       OR position('..' IN host) > 0 THEN
        RETURN FALSE;
    END IF;
    labels := string_to_array(host, '.');
    IF cardinality(labels) < 2 THEN
        RETURN FALSE;
    END IF;
    FOREACH label IN ARRAY labels LOOP
        IF octet_length(label) < 1
           OR octet_length(label) > 63
           OR label !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$' THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    final_label := labels[cardinality(labels)];
    IF final_label !~ '^[a-z](?:[a-z0-9-]*[a-z0-9])?$'
       OR final_label IN ('alt','arpa','example','internal','invalid','local','localhost','onion','test') THEN
        RETURN FALSE;
    END IF;
    RETURN TRUE;
END
$$;

CREATE FUNCTION chat.enforce_immutable_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_columns TEXT[] := CASE
        WHEN TG_NARGS = 0 THEN ARRAY[]::TEXT[]
        ELSE TG_ARGV
    END;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'immutable chat row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_columns)
       IS DISTINCT FROM (to_jsonb(OLD) - mutable_columns) THEN
        RAISE EXCEPTION 'immutable chat identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION chat.enforce_core_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_kind TEXT;
BEGIN
    IF TG_TABLE_NAME = 'devices' THEN
        IF OLD.status = 'revoked' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'revoked device is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.auth_generation < OLD.auth_generation
           OR NEW.auth_generation > OLD.auth_generation + 1
           OR ((NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt)
               <> (NEW.auth_generation = OLD.auth_generation + 1))
           OR NEW.updated_at < OLD.updated_at
           OR (OLD.status = 'active' AND NEW.status NOT IN ('active','revoked')) THEN
            RAISE EXCEPTION 'invalid device lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'device_keys' THEN
        IF OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'revoked device key is terminal' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'key_packages' THEN
        IF OLD.status IN ('consumed','expired','revoked') AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal KeyPackage cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF (OLD.status = 'available' AND NEW.status NOT IN ('available','reserved','expired','revoked'))
           OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved','available','consumed','expired','revoked'))
           OR NEW.terminal_at < OLD.terminal_at THEN
            RAISE EXCEPTION 'invalid KeyPackage lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'conversations' THEN
        IF OLD.lifecycle = 'superseded' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'superseded conversation is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.current_generation < OLD.current_generation
           OR (NEW.current_generation = OLD.current_generation
               AND NEW.current_state_version < OLD.current_state_version)
           OR NEW.next_entry_seq < OLD.next_entry_seq
           OR (OLD.lifecycle = 'active' AND NEW.lifecycle NOT IN ('active','superseded')) THEN
            RAISE EXCEPTION 'invalid conversation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'generations' THEN
        IF OLD.lifecycle = 'superseded' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'superseded generation is terminal' USING ERRCODE = '23514';
        END IF;
        IF NEW.current_state_version < OLD.current_state_version
           OR (OLD.lifecycle = 'active' AND NEW.lifecycle NOT IN ('active','superseded')) THEN
            RAISE EXCEPTION 'invalid generation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'participants' THEN
        SELECT kind INTO conversation_kind
          FROM chat.conversations
         WHERE conversation_id = NEW.conversation_id;
        IF NOT OLD.current_membership AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'closed participant period is terminal' USING ERRCODE = '23514';
        END IF;
        IF ((NEW.role IS DISTINCT FROM OLD.role) <> (
                NEW.role_transition_id IS DISTINCT FROM OLD.role_transition_id
                AND NEW.role_changed_at > OLD.role_changed_at
            ))
           OR ((NEW.role_transition_id IS DISTINCT FROM OLD.role_transition_id)
               <> (NEW.role_changed_at IS DISTINCT FROM OLD.role_changed_at))
           OR (NEW.role IS DISTINCT FROM OLD.role AND (
                conversation_kind <> 'group'
                OR OLD.status <> 'active' OR NEW.status <> 'active'
                OR NOT OLD.current_membership OR NOT NEW.current_membership
           ))
           OR (OLD.status = 'active' AND NEW.status <> 'active')
           OR (OLD.status = 'pending' AND NEW.status NOT IN ('pending','active'))
           OR (NOT OLD.current_membership AND NEW.current_membership)
           OR (OLD.acceptance_transition_id IS NOT NULL
               AND (NEW.acceptance_transition_id, NEW.acceptance_entry_id, NEW.accepted_at)
                   IS DISTINCT FROM
                   (OLD.acceptance_transition_id, OLD.acceptance_entry_id, OLD.accepted_at))
           OR (OLD.removing_transition_id IS NOT NULL
               AND (NEW.removing_transition_id, NEW.removing_seq, NEW.removed_at)
                   IS DISTINCT FROM
                   (OLD.removing_transition_id, OLD.removing_seq, OLD.removed_at)) THEN
            RAISE EXCEPTION 'invalid participant lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'member_devices' THEN
        IF NOT OLD.active AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'closed leaf period is terminal' USING ERRCODE = '23514';
        END IF;
        IF (NOT OLD.active AND NEW.active)
           OR (OLD.removed_transition_id IS NOT NULL
               AND (NEW.removed_state_version, NEW.removed_transition_id,
                    NEW.removed_seq, NEW.removed_at)
                   IS DISTINCT FROM
                   (OLD.removed_state_version, OLD.removed_transition_id,
                    OLD.removed_seq, OLD.removed_at)) THEN
            RAISE EXCEPTION 'invalid leaf lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'key_package_reservations' THEN
        IF OLD.status <> 'active' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal reservation cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'active'
           AND NEW.status NOT IN ('active','consumed','expired','released') THEN
            RAISE EXCEPTION 'invalid reservation lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'reset_requests' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal reset request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending' AND NEW.status NOT IN ('pending','stale','consumed','expired') THEN
            RAISE EXCEPTION 'invalid reset request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'leaf_recovery_requests' THEN
        IF OLD.status <> 'open' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal recovery request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'open'
           AND NEW.status NOT IN ('open','fulfilled','cancelled','expired','superseded') THEN
            RAISE EXCEPTION 'invalid recovery request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'leave_requests' THEN
        IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal leave request cannot be rewritten' USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'pending'
           AND NEW.status NOT IN ('pending','fulfilled','cancelled','expired','stale') THEN
            RAISE EXCEPTION 'invalid leave request lifecycle transition' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'relationship_projection_revision_allocations' THEN
        IF OLD.consumed_projection_id IS NOT NULL
           OR OLD.consumed_at IS NOT NULL
           OR NEW.consumed_projection_id IS NULL
           OR NEW.consumed_at IS NULL
           OR NEW.consumed_at < OLD.allocated_at THEN
            RAISE EXCEPTION 'invalid relationship projection allocation lifecycle transition'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE chat.protocol_instances (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    protocol_version TEXT NOT NULL DEFAULT '1',
    protocol_instance_id UUID NOT NULL UNIQUE,
    cursor_key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT protocol_instances_singleton_check CHECK (singleton),
    CONSTRAINT protocol_instances_protocol_version_check CHECK (protocol_version = '1'),
    CONSTRAINT protocol_instances_uuid_check CHECK (chat.is_uuid_v4(protocol_instance_id)),
    CONSTRAINT protocol_instances_cursor_key_check CHECK (chat.is_base64url_sha256(cursor_key_id))
);

CREATE TABLE chat.principals (
    user_did TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT principals_user_did_check CHECK (chat.is_bare_did(user_did))
);

CREATE TABLE chat.devices (
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    device_name TEXT NOT NULL,
    status TEXT NOT NULL,
    dpop_jkt TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    capabilities JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_id UUID,
    PRIMARY KEY (user_did, device_id),
    CONSTRAINT devices_principal_fk FOREIGN KEY (user_did) REFERENCES chat.principals(user_did),
    CONSTRAINT devices_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT devices_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT devices_name_check CHECK (octet_length(device_name) BETWEEN 1 AND 128),
    CONSTRAINT devices_status_check CHECK (status IN ('active','revoked')),
    CONSTRAINT devices_dpop_jkt_check CHECK (chat.is_base64url_sha256(dpop_jkt)),
    CONSTRAINT devices_auth_generation_check CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1),
    CONSTRAINT devices_capabilities_check CHECK (capabilities = chat.protocol_capabilities()),
    CONSTRAINT devices_revocation_shape_check CHECK (
        (status = 'active' AND revoked_at IS NULL AND revocation_id IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL
            AND chat.is_uuid_v4(revocation_id))
    )
);

CREATE UNIQUE INDEX devices_active_dpop_jkt_uq
    ON chat.devices (user_did, dpop_jkt)
    WHERE status = 'active';

CREATE TABLE chat.device_keys (
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    key_id TEXT NOT NULL,
    signing_public_key BYTEA NOT NULL,
    enrollment_auth_generation BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_id UUID,
    PRIMARY KEY (user_did, device_id),
    CONSTRAINT device_keys_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT device_keys_identity_uq UNIQUE (user_did, device_id, key_id),
    CONSTRAINT device_keys_author_proof_uq UNIQUE (
        user_did, device_id, key_id, signing_public_key
    ),
    CONSTRAINT device_keys_key_id_uq UNIQUE (key_id),
    CONSTRAINT device_keys_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT device_keys_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT device_keys_key_id_check CHECK (chat.is_base64url_sha256(key_id)),
    CONSTRAINT device_keys_public_key_length_check CHECK (octet_length(signing_public_key) = 32),
    CONSTRAINT device_keys_key_id_binding_check CHECK (
        key_id = chat.ed25519_key_id(signing_public_key)
    ),
    CONSTRAINT device_keys_auth_generation_check CHECK (
        chat.is_safe_integer(enrollment_auth_generation) AND enrollment_auth_generation >= 1
    ),
    CONSTRAINT device_keys_revocation_time_check CHECK (
        (revoked_at IS NULL AND revocation_id IS NULL)
        OR (revoked_at >= created_at AND chat.is_uuid_v4(revocation_id))
    )
);

CREATE TABLE chat.device_revocations (
    revocation_id UUID PRIMARY KEY,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    actor_key_id TEXT NOT NULL,
    actor_auth_generation BIGINT NOT NULL,
    target_did TEXT NOT NULL,
    target_device_id UUID NOT NULL,
    target_auth_generation BIGINT NOT NULL,
    accepted_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_revocations_actor_key_fk FOREIGN KEY (
        actor_did, actor_device_id, actor_key_id
    ) REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT device_revocations_target_device_fk FOREIGN KEY (
        target_did, target_device_id
    ) REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT device_revocations_id_check CHECK (chat.is_uuid_v4(revocation_id)),
    CONSTRAINT device_revocations_same_principal_check CHECK (
        actor_did = target_did AND chat.is_bare_did(actor_did)
    ),
    CONSTRAINT device_revocations_device_check CHECK (
        chat.is_uuid_v4(actor_device_id) AND chat.is_uuid_v4(target_device_id)
    ),
    CONSTRAINT device_revocations_key_check CHECK (chat.is_base64url_sha256(actor_key_id)),
    CONSTRAINT device_revocations_generation_check CHECK (
        chat.is_safe_integer(actor_auth_generation) AND actor_auth_generation >= 1
        AND chat.is_safe_integer(target_auth_generation) AND target_auth_generation >= 1
    ),
    CONSTRAINT device_revocations_signature_check CHECK (
        octet_length(accepted_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32
        AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT device_revocations_time_check CHECK (
        signed_at BETWEEN accepted_at - INTERVAL '5 minutes'
                      AND accepted_at + INTERVAL '60 seconds'
    ),
    CONSTRAINT device_revocations_target_identity_uq UNIQUE (
        target_did, target_device_id, revocation_id,
        target_auth_generation, accepted_at
    ),
    CONSTRAINT device_revocations_target_time_uq UNIQUE (
        target_did, target_device_id, revocation_id, accepted_at
    ),
    CONSTRAINT device_revocations_one_per_target_uq UNIQUE (
        target_did, target_device_id
    )
);

ALTER TABLE chat.devices
    ADD CONSTRAINT devices_revocation_fk FOREIGN KEY (
        user_did, device_id, revocation_id, auth_generation, revoked_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id,
        target_auth_generation, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.device_keys
    ADD CONSTRAINT device_keys_revocation_fk FOREIGN KEY (
        user_did, device_id, revocation_id, revoked_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE chat.dpop_replays (
    replay_id UUID PRIMARY KEY,
    replay_namespace TEXT NOT NULL,
    issuer TEXT,
    token_jti UUID,
    jkt TEXT,
    proof_jti_bytes BYTEA,
    auth_txn UUID,
    token_hash BYTEA,
    proof_hash BYTEA,
    subject_did TEXT,
    audience TEXT,
    lxm TEXT,
    device_id UUID,
    chat_instance UUID,
    htu TEXT,
    htm TEXT,
    key_id TEXT,
    signing_key_sha256 BYTEA,
    enrollment_transcript_sha256 BYTEA,
    auth_time TIMESTAMPTZ,
    token_iat TIMESTAMPTZ,
    token_exp TIMESTAMPTZ,
    proof_iat TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    CONSTRAINT dpop_replays_replay_id_check CHECK (chat.is_uuid_v4(replay_id)),
    CONSTRAINT dpop_replays_namespace_check CHECK (replay_namespace IN ('token','proof','authTxn')),
    CONSTRAINT dpop_replays_authority_bounds_check CHECK (
        (issuer IS NULL OR (
            octet_length(issuer) BETWEEN 1 AND 2048 AND issuer ~ '^[[:ascii:]]+$'
        ))
        AND (audience IS NULL OR (
            octet_length(audience) BETWEEN 1 AND 2048 AND audience ~ '^[[:ascii:]]+$'
        ))
    ),
    CONSTRAINT dpop_replays_subject_did_check CHECK (subject_did IS NULL OR chat.is_bare_did(subject_did)),
    CONSTRAINT dpop_replays_device_id_check CHECK (device_id IS NULL OR chat.is_uuid_v4(device_id)),
    CONSTRAINT dpop_replays_chat_instance_check CHECK (chat_instance IS NULL OR chat.is_uuid_v4(chat_instance)),
    CONSTRAINT dpop_replays_token_jti_check CHECK (token_jti IS NULL OR chat.is_uuid_v4(token_jti)),
    CONSTRAINT dpop_replays_auth_txn_check CHECK (auth_txn IS NULL OR chat.is_uuid_v4(auth_txn)),
    CONSTRAINT dpop_replays_jkt_check CHECK (jkt IS NULL OR chat.is_base64url_sha256(jkt)),
    CONSTRAINT dpop_replays_key_id_check CHECK (key_id IS NULL OR chat.is_base64url_sha256(key_id)),
    CONSTRAINT dpop_replays_hash_lengths_check CHECK (
        (token_hash IS NULL OR octet_length(token_hash) = 32)
        AND (proof_hash IS NULL OR octet_length(proof_hash) = 32)
        AND (signing_key_sha256 IS NULL OR octet_length(signing_key_sha256) = 32)
        AND (enrollment_transcript_sha256 IS NULL OR octet_length(enrollment_transcript_sha256) = 32)
    ),
    CONSTRAINT dpop_replays_proof_jti_check CHECK (
        proof_jti_bytes IS NULL OR octet_length(proof_jti_bytes) BETWEEN 12 AND 32
    ),
    CONSTRAINT dpop_replays_http_claims_check CHECK (
        (htu IS NULL OR (
            htu LIKE 'https://%'
            AND octet_length(htu) <= 2048
            AND lxm IS NOT NULL
            AND right(htu, octet_length('/xrpc/' || lxm)) = '/xrpc/' || lxm
        ))
        AND (htm IS NULL OR htm IN ('GET','POST'))
    ),
    CONSTRAINT dpop_replays_time_check CHECK (
        retain_until >= consumed_at
        AND (token_iat IS NULL OR token_exp IS NULL OR (
            token_exp > token_iat
            AND token_exp <= token_iat + INTERVAL '120 seconds'
        ))
        AND (proof_iat IS NULL OR proof_iat BETWEEN
            consumed_at - INTERVAL '60 seconds' AND consumed_at + INTERVAL '60 seconds')
        AND (auth_time IS NULL OR consumed_at BETWEEN auth_time AND auth_time + INTERVAL '300 seconds')
        AND (auth_time IS NULL OR token_exp IS NULL OR token_exp <= auth_time + INTERVAL '300 seconds')
    ),
    CONSTRAINT dpop_replays_retention_check CHECK (
        (replay_namespace = 'token' AND retain_until >= token_exp)
        OR (replay_namespace = 'proof' AND retain_until >= proof_iat + INTERVAL '120 seconds')
        OR (replay_namespace = 'authTxn'
            AND retain_until >= GREATEST(token_exp, proof_iat + INTERVAL '120 seconds',
                                         auth_time + INTERVAL '300 seconds'))
    ),
    CONSTRAINT dpop_replays_lxm_check CHECK (
        lxm = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.getBlob',
            'blue.catbird.chat.getBlobUsage',
            'blue.catbird.chat.getConversationState',
            'blue.catbird.chat.getConversations',
            'blue.catbird.chat.getDevices',
            'blue.catbird.chat.getEntries',
            'blue.catbird.chat.getLeafRecoveryInbox',
            'blue.catbird.chat.getOwnDevices',
            'blue.catbird.chat.getPendingWelcomes',
            'blue.catbird.chat.getSubscriptionTicket',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.publishTyping',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.sendMessage',
            'blue.catbird.chat.submitTransition',
            'blue.catbird.chat.uploadBlob'
        ])
    ),
    CONSTRAINT dpop_replays_namespace_shape_check CHECK (
        (replay_namespace = 'token'
            AND issuer IS NOT NULL AND token_jti IS NOT NULL AND token_hash IS NOT NULL
            AND subject_did IS NOT NULL AND audience IS NOT NULL AND lxm IS NOT NULL
            AND device_id IS NOT NULL AND chat_instance IS NOT NULL AND jkt IS NOT NULL
            AND token_iat IS NOT NULL AND token_exp IS NOT NULL
            AND proof_jti_bytes IS NULL AND proof_hash IS NULL AND auth_txn IS NULL
            AND htu IS NULL AND htm IS NULL AND proof_iat IS NULL
            AND key_id IS NULL AND signing_key_sha256 IS NULL
            AND enrollment_transcript_sha256 IS NULL AND auth_time IS NULL)
        OR
        (replay_namespace = 'proof'
            AND issuer IS NULL AND token_jti IS NULL AND auth_txn IS NULL
            AND jkt IS NOT NULL AND proof_jti_bytes IS NOT NULL
            AND token_hash IS NOT NULL AND proof_hash IS NOT NULL
            AND subject_did IS NOT NULL AND audience IS NOT NULL AND lxm IS NOT NULL
            AND device_id IS NOT NULL AND chat_instance IS NOT NULL
            AND htu IS NOT NULL AND htm IS NOT NULL AND proof_iat IS NOT NULL
            AND token_iat IS NULL AND token_exp IS NULL
            AND key_id IS NULL AND signing_key_sha256 IS NULL
            AND enrollment_transcript_sha256 IS NULL AND auth_time IS NULL)
        OR
        (replay_namespace = 'authTxn'
            AND issuer IS NOT NULL AND auth_txn IS NOT NULL
            AND subject_did IS NOT NULL AND audience IS NOT NULL AND lxm IS NOT NULL
            AND lxm = 'blue.catbird.chat.enrollDevice'
            AND device_id IS NOT NULL AND chat_instance IS NOT NULL
            AND jkt IS NOT NULL AND key_id IS NOT NULL
            AND token_hash IS NOT NULL AND proof_hash IS NOT NULL
            AND signing_key_sha256 IS NOT NULL
            AND enrollment_transcript_sha256 IS NOT NULL AND auth_time IS NOT NULL
            AND htu IS NOT NULL AND htm IS NOT NULL
            AND token_iat IS NOT NULL AND token_exp IS NOT NULL AND proof_iat IS NOT NULL
            AND token_jti IS NULL AND proof_jti_bytes IS NULL)
    )
);

CREATE UNIQUE INDEX dpop_replays_token_uq
    ON chat.dpop_replays (issuer, token_jti)
    WHERE replay_namespace = 'token';
CREATE UNIQUE INDEX dpop_replays_proof_uq
    ON chat.dpop_replays (jkt, proof_jti_bytes)
    WHERE replay_namespace = 'proof';
CREATE UNIQUE INDEX dpop_replays_auth_txn_uq
    ON chat.dpop_replays (issuer, auth_txn)
    WHERE replay_namespace = 'authTxn';

CREATE TABLE chat.idempotency_records (
    principal_did TEXT NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    operation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL,
    accepted_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    signature BYTEA,
    completed_status INTEGER NOT NULL,
    response_bytes BYTEA NOT NULL,
    response_sha256 BYTEA NOT NULL,
    event_position BIGINT,
    historical_jkt TEXT,
    current_jkt TEXT,
    completed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_did, endpoint_nsid, operation_id),
    CONSTRAINT idempotency_records_principal_fk FOREIGN KEY (principal_did)
        REFERENCES chat.principals(user_did),
    CONSTRAINT idempotency_records_principal_did_check CHECK (chat.is_bare_did(principal_did)),
    CONSTRAINT idempotency_records_operation_id_check CHECK (chat.is_uuid_v4(operation_id)),
    CONSTRAINT idempotency_records_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.submitTransition'
        ])
    ),
    CONSTRAINT idempotency_records_payload_sizes_check CHECK (
        octet_length(accepted_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(response_bytes) BETWEEN 1 AND 16777216
        AND signature IS NOT NULL AND octet_length(signature) = 64
    ),
    CONSTRAINT idempotency_records_hashes_check CHECK (
        octet_length(request_digest) = 32
        AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(response_sha256) = 32
        AND response_sha256 = digest(response_bytes, 'sha256')
        AND (signature IS NULL OR octet_length(signature) = 64)
    ),
    CONSTRAINT idempotency_records_status_check CHECK (completed_status BETWEEN 200 AND 599),
    CONSTRAINT idempotency_records_event_position_check CHECK (
        event_position IS NULL OR chat.is_safe_integer(event_position)
    ),
    CONSTRAINT idempotency_records_jkt_check CHECK (
        (historical_jkt IS NULL OR chat.is_base64url_sha256(historical_jkt))
        AND (current_jkt IS NULL OR chat.is_base64url_sha256(current_jkt))
        AND (
            (endpoint_nsid = 'blue.catbird.chat.enrollDevice'
                AND historical_jkt IS NULL AND current_jkt IS NOT NULL)
            OR (endpoint_nsid = 'blue.catbird.chat.revokeDevice'
                AND historical_jkt IS NOT NULL AND current_jkt IS NULL)
            OR (endpoint_nsid = 'blue.catbird.chat.rebindDeviceAuthentication'
                AND historical_jkt IS NOT NULL AND current_jkt IS NOT NULL
                AND historical_jkt <> current_jkt)
            OR (endpoint_nsid NOT IN (
                    'blue.catbird.chat.enrollDevice',
                    'blue.catbird.chat.revokeDevice',
                    'blue.catbird.chat.rebindDeviceAuthentication'
                ) AND historical_jkt IS NULL AND current_jkt IS NULL)
        )
    )
);

CREATE TABLE chat.key_packages (
    key_package_ref BYTEA NOT NULL,
    wrapper_bytes BYTEA NOT NULL,
    wrapper_sha256 BYTEA NOT NULL,
    init_key BYTEA NOT NULL UNIQUE,
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    owner_auth_generation BIGINT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    terminal_transition_id UUID,
    terminal_revocation_id UUID,
    terminal_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key_package_ref),
    CONSTRAINT key_packages_owner_key_fk FOREIGN KEY (owner_did, owner_device_id, owner_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT key_packages_ref_length_check CHECK (octet_length(key_package_ref) = 32),
    CONSTRAINT key_packages_artifact_hash_check CHECK (
        octet_length(wrapper_bytes) BETWEEN 8 AND 65536
        AND octet_length(wrapper_sha256) = 32
        AND wrapper_sha256 = digest(wrapper_bytes, 'sha256')
        AND octet_length(init_key) BETWEEN 1 AND 65536
    ),
    CONSTRAINT key_packages_owner_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT key_packages_owner_device_id_check CHECK (chat.is_uuid_v4(owner_device_id)),
    CONSTRAINT key_packages_owner_key_id_check CHECK (chat.is_base64url_sha256(owner_key_id)),
    CONSTRAINT key_packages_owner_auth_generation_check CHECK (
        chat.is_safe_integer(owner_auth_generation) AND owner_auth_generation >= 1
    ),
    CONSTRAINT key_packages_status_check CHECK (status IN ('available','reserved','consumed','expired','revoked')),
    CONSTRAINT key_packages_lifetime_check CHECK (
        not_before < created_at AND created_at < not_after
        AND not_after >= created_at + INTERVAL '600 seconds'
        AND not_after <= not_before + INTERVAL '2595600 seconds'
    ),
    CONSTRAINT key_packages_terminal_shape_check CHECK (
        (status IN ('available','reserved') AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at IS NULL)
        OR (status = 'consumed' AND terminal_transition_id IS NOT NULL
            AND terminal_revocation_id IS NULL AND terminal_at IS NOT NULL)
        OR (status = 'expired' AND terminal_transition_id IS NULL
            AND terminal_revocation_id IS NULL AND terminal_at = not_after)
        OR (status = 'revoked' AND terminal_transition_id IS NULL
            AND chat.is_uuid_v4(terminal_revocation_id)
            AND terminal_at >= created_at AND terminal_at < not_after)
    ),
    CONSTRAINT key_packages_terminal_transition_check CHECK (
        terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id)
    ),
    CONSTRAINT key_packages_terminal_revocation_fk FOREIGN KEY (
        owner_did, owner_device_id, terminal_revocation_id, terminal_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT key_packages_owner_identity_uq UNIQUE (
        key_package_ref, owner_did, owner_device_id
    ),
    CONSTRAINT key_packages_delivery_identity_uq UNIQUE (
        key_package_ref, owner_did, owner_device_id, not_after
    )
);

CREATE INDEX key_packages_live_by_device_idx
    ON chat.key_packages (owner_did, owner_device_id, key_package_ref)
    WHERE status IN ('available','reserved');

CREATE TABLE chat.conversations (
    conversation_id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    current_generation BIGINT NOT NULL,
    current_state_version BIGINT NOT NULL,
    next_entry_seq BIGINT NOT NULL DEFAULT 1,
    direct_did_low TEXT,
    direct_did_high TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    close_transition_id UUID,
    close_generation BIGINT,
    close_state_version BIGINT,
    close_seq BIGINT,
    closed_at TIMESTAMPTZ,
    CONSTRAINT conversations_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT conversations_direct_low_principal_fk FOREIGN KEY (direct_did_low)
        REFERENCES chat.principals(user_did),
    CONSTRAINT conversations_direct_high_principal_fk FOREIGN KEY (direct_did_high)
        REFERENCES chat.principals(user_did),
    CONSTRAINT conversations_kind_check CHECK (kind IN ('direct','group')),
    CONSTRAINT conversations_lifecycle_check CHECK (lifecycle IN ('active','superseded')),
    CONSTRAINT conversations_current_generation_check CHECK (chat.is_safe_integer(current_generation)),
    CONSTRAINT conversations_current_state_version_check CHECK (chat.is_safe_integer(current_state_version)),
    CONSTRAINT conversations_next_entry_seq_check CHECK (
        chat.is_safe_integer(next_entry_seq) AND next_entry_seq >= 1
    ),
    CONSTRAINT conversations_direct_did_check CHECK (
        (direct_did_low IS NULL OR chat.is_bare_did(direct_did_low))
        AND (direct_did_high IS NULL OR chat.is_bare_did(direct_did_high))
    ),
    CONSTRAINT conversations_kind_shape_check CHECK (
        (kind = 'direct' AND direct_did_low IS NOT NULL AND direct_did_high IS NOT NULL
            AND direct_did_low COLLATE "C" < direct_did_high COLLATE "C")
        OR (kind = 'group' AND direct_did_low IS NULL AND direct_did_high IS NULL)
    ),
    CONSTRAINT conversations_close_transition_check CHECK (
        close_transition_id IS NULL OR chat.is_uuid_v4(close_transition_id)
    ),
    CONSTRAINT conversations_close_generation_check CHECK (
        close_generation IS NULL OR chat.is_safe_integer(close_generation)
    ),
    CONSTRAINT conversations_close_state_version_check CHECK (
        close_state_version IS NULL OR chat.is_safe_integer(close_state_version)
    ),
    CONSTRAINT conversations_close_seq_check CHECK (close_seq IS NULL OR chat.is_safe_integer(close_seq)),
    CONSTRAINT conversations_close_shape_check CHECK (
        (lifecycle = 'active' AND close_transition_id IS NULL AND close_generation IS NULL
            AND close_state_version IS NULL AND close_seq IS NULL AND closed_at IS NULL)
        OR
        (lifecycle = 'superseded' AND close_transition_id IS NOT NULL AND close_generation IS NOT NULL
            AND close_state_version IS NOT NULL AND close_seq IS NOT NULL AND closed_at IS NOT NULL)
    ),
    CONSTRAINT conversations_close_identity_uq UNIQUE (
        conversation_id, close_transition_id, close_generation,
        close_state_version, close_seq, closed_at
    )
);

CREATE UNIQUE INDEX conversations_active_direct_pair_uq
    ON chat.conversations (direct_did_low, direct_did_high)
    WHERE kind = 'direct' AND lifecycle = 'active';

CREATE TABLE chat.generations (
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    group_id BYTEA NOT NULL,
    lifecycle TEXT NOT NULL,
    genesis_group_info_bytes BYTEA NOT NULL,
    genesis_group_info_sha256 BYTEA NOT NULL,
    current_state_version BIGINT NOT NULL,
    activated_seq BIGINT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL,
    superseded_seq BIGINT,
    superseded_at TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, generation),
    CONSTRAINT generations_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT generations_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT generations_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT generations_group_id_check CHECK (octet_length(group_id) = 32),
    CONSTRAINT generations_lifecycle_check CHECK (lifecycle IN ('active','superseded')),
    CONSTRAINT generations_group_info_hash_check CHECK (
        octet_length(genesis_group_info_bytes) BETWEEN 8 AND 1048576
        AND octet_length(genesis_group_info_sha256) = 32
        AND genesis_group_info_sha256 = digest(genesis_group_info_bytes, 'sha256')
    ),
    CONSTRAINT generations_current_state_version_check CHECK (chat.is_safe_integer(current_state_version)),
    CONSTRAINT generations_activated_seq_check CHECK (chat.is_safe_integer(activated_seq)),
    CONSTRAINT generations_superseded_seq_check CHECK (
        superseded_seq IS NULL OR chat.is_safe_integer(superseded_seq)
    ),
    CONSTRAINT generations_lifecycle_shape_check CHECK (
        (lifecycle = 'active' AND superseded_seq IS NULL AND superseded_at IS NULL)
        OR (lifecycle = 'superseded' AND superseded_seq IS NOT NULL AND superseded_at IS NOT NULL)
    ),
    CONSTRAINT generations_group_identity_uq UNIQUE (
        conversation_id, generation, group_id
    )
);

CREATE UNIQUE INDEX generations_one_active_uq
    ON chat.generations (conversation_id)
    WHERE lifecycle = 'active';

CREATE TABLE chat.generation_states (
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    state_version BIGINT NOT NULL,
    group_id BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    group_context_hash BYTEA NOT NULL,
    confirmation_tag BYTEA NOT NULL,
    lifecycle TEXT NOT NULL,
    state_kind TEXT NOT NULL,
    producing_transition_id UUID NOT NULL,
    public_snapshot_bytes BYTEA NOT NULL,
    snapshot_sha256 BYTEA NOT NULL,
    tree_summary_bytes BYTEA NOT NULL,
    tree_summary_sha256 BYTEA NOT NULL,
    leaf_count BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, generation, state_version),
    CONSTRAINT generation_states_generation_fk FOREIGN KEY (
        conversation_id, generation, group_id
    ) REFERENCES chat.generations(conversation_id, generation, group_id),
    CONSTRAINT generation_states_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT generation_states_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT generation_states_state_version_check CHECK (chat.is_safe_integer(state_version)),
    CONSTRAINT generation_states_epoch_check CHECK (chat.is_safe_integer(epoch)),
    CONSTRAINT generation_states_leaf_count_check CHECK (
        chat.is_safe_integer(leaf_count) AND leaf_count BETWEEN 1 AND 100
    ),
    CONSTRAINT generation_states_crypto_lengths_check CHECK (
        octet_length(group_id) = 32
        AND octet_length(group_context_hash) = 32
        AND octet_length(confirmation_tag) = 32
    ),
    CONSTRAINT generation_states_lifecycle_check CHECK (lifecycle IN ('active','superseded')),
    CONSTRAINT generation_states_kind_check CHECK (
        state_kind IN ('creation','commit','policy','acceptConversation','metadata','leavePolicy',
                       'resetRetirement','resetSuccessor','closeConversation')
    ),
    CONSTRAINT generation_states_producing_transition_check CHECK (
        chat.is_uuid_v4(producing_transition_id)
    ),
    CONSTRAINT generation_states_snapshot_hash_check CHECK (
        octet_length(public_snapshot_bytes) BETWEEN 1 AND 8388608
        AND octet_length(snapshot_sha256) = 32
        AND snapshot_sha256 = digest(public_snapshot_bytes, 'sha256')
    ),
    CONSTRAINT generation_states_tree_hash_check CHECK (
        octet_length(tree_summary_bytes) BETWEEN 1 AND 1048576
        AND octet_length(tree_summary_sha256) = 32
        AND tree_summary_sha256 = digest(tree_summary_bytes, 'sha256')
    ),
    CONSTRAINT generation_states_public_coordinate_uq UNIQUE (
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag
    ),
    CONSTRAINT generation_states_transition_coordinate_uq UNIQUE (
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag, producing_transition_id
    )
);

CREATE UNIQUE INDEX generation_states_crypto_edge_uq
    ON chat.generation_states (
        conversation_id, generation, group_id, epoch, group_context_hash, confirmation_tag
    )
    WHERE state_kind IN ('creation','commit','resetSuccessor');

ALTER TABLE chat.conversations
    ADD CONSTRAINT conversations_current_state_fk
    FOREIGN KEY (conversation_id, current_generation, current_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE chat.generations
    ADD CONSTRAINT generations_current_state_fk
    FOREIGN KEY (conversation_id, generation, current_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE chat.participants (
    participant_period_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    user_did TEXT NOT NULL,
    status TEXT NOT NULL,
    role TEXT NOT NULL,
    role_transition_id UUID NOT NULL,
    role_changed_at TIMESTAMPTZ NOT NULL,
    created_by_did TEXT NOT NULL,
    created_by_device_id UUID NOT NULL,
    invitation_transition_id UUID,
    invitation_entry_id UUID,
    invited_at TIMESTAMPTZ,
    acceptance_transition_id UUID,
    acceptance_entry_id UUID,
    accepted_at TIMESTAMPTZ,
    removing_transition_id UUID,
    removing_seq BIGINT,
    removed_at TIMESTAMPTZ,
    current_membership BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT participants_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT participants_principal_fk FOREIGN KEY (user_did)
        REFERENCES chat.principals(user_did),
    CONSTRAINT participants_creator_device_fk FOREIGN KEY (created_by_did, created_by_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT participants_period_id_check CHECK (chat.is_uuid_v4(participant_period_id)),
    CONSTRAINT participants_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT participants_user_did_check CHECK (
        chat.is_bare_did(user_did) AND chat.is_bare_did(created_by_did)
    ),
    CONSTRAINT participants_created_by_device_check CHECK (chat.is_uuid_v4(created_by_device_id)),
    CONSTRAINT participants_status_check CHECK (status IN ('pending','active')),
    CONSTRAINT participants_role_check CHECK (role IN ('member','admin')),
    CONSTRAINT participants_role_transition_check CHECK (
        chat.is_uuid_v4(role_transition_id) AND role_changed_at >= created_at
    ),
    CONSTRAINT participants_invitation_shape_check CHECK (
        (invitation_transition_id IS NULL AND invitation_entry_id IS NULL AND invited_at IS NULL)
        OR (chat.is_uuid_v4(invitation_transition_id) AND chat.is_uuid_v4(invitation_entry_id)
            AND invited_at IS NOT NULL)
    ),
    CONSTRAINT participants_acceptance_shape_check CHECK (
        (acceptance_transition_id IS NULL AND acceptance_entry_id IS NULL AND accepted_at IS NULL)
        OR (chat.is_uuid_v4(acceptance_transition_id) AND chat.is_uuid_v4(acceptance_entry_id)
            AND accepted_at IS NOT NULL)
    ),
    CONSTRAINT participants_membership_provenance_check CHECK (
        (invitation_transition_id IS NULL
            AND status = 'active' AND role = 'admin'
            AND acceptance_transition_id IS NULL)
        OR (invitation_transition_id IS NOT NULL
            AND ((status = 'pending' AND acceptance_transition_id IS NULL)
                 OR (status = 'active' AND acceptance_transition_id IS NOT NULL)))
    ),
    CONSTRAINT participants_removal_shape_check CHECK (
        (current_membership AND removing_transition_id IS NULL AND removing_seq IS NULL AND removed_at IS NULL)
        OR (NOT current_membership AND chat.is_uuid_v4(removing_transition_id)
            AND removing_seq IS NOT NULL AND removed_at IS NOT NULL)
    ),
    CONSTRAINT participants_removing_seq_check CHECK (
        removing_seq IS NULL OR chat.is_safe_integer(removing_seq)
    )
);

CREATE UNIQUE INDEX participants_one_current_uq
    ON chat.participants (conversation_id, user_did)
    WHERE current_membership;
CREATE INDEX participants_live_inviter_recipient_idx
    ON chat.participants (created_by_did, user_did, invited_at)
    WHERE current_membership AND status = 'pending';
-- Supports the per-recipient live-pending invitation quota scope (limit 3):
-- the inviter-recipient index above leads with created_by_did and cannot serve
-- a recipient-only (user_did) scan.
CREATE INDEX participants_live_recipient_idx
    ON chat.participants (user_did, invited_at)
    WHERE current_membership AND status = 'pending';

CREATE TABLE chat.member_devices (
    leaf_period_id UUID PRIMARY KEY,
    participant_period_id UUID NOT NULL,
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    leaf_index BIGINT NOT NULL,
    basic_credential BYTEA NOT NULL,
    leaf_signature_key BYTEA NOT NULL,
    leaf_key_id TEXT NOT NULL,
    leaf_auth_generation BIGINT NOT NULL,
    origin TEXT NOT NULL,
    join_key_package_ref BYTEA,
    joined_state_version BIGINT NOT NULL,
    joined_transition_id UUID NOT NULL,
    joined_seq BIGINT NOT NULL,
    removed_state_version BIGINT,
    removed_transition_id UUID,
    removed_seq BIGINT,
    removed_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT member_devices_participant_fk FOREIGN KEY (participant_period_id)
        REFERENCES chat.participants(participant_period_id),
    CONSTRAINT member_devices_generation_fk FOREIGN KEY (conversation_id, generation)
        REFERENCES chat.generations(conversation_id, generation),
    CONSTRAINT member_devices_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT member_devices_signing_key_fk FOREIGN KEY (
        user_did, device_id, leaf_key_id, leaf_signature_key
    ) REFERENCES chat.device_keys(
        user_did, device_id, key_id, signing_public_key
    ),
    CONSTRAINT member_devices_package_fk FOREIGN KEY (
        join_key_package_ref, user_did, device_id
    ) REFERENCES chat.key_packages(
        key_package_ref, owner_did, owner_device_id
    ),
    CONSTRAINT member_devices_leaf_period_id_check CHECK (chat.is_uuid_v4(leaf_period_id)),
    CONSTRAINT member_devices_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT member_devices_user_did_check CHECK (chat.is_bare_did(user_did)),
    CONSTRAINT member_devices_device_id_check CHECK (chat.is_uuid_v4(device_id)),
    CONSTRAINT member_devices_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT member_devices_leaf_index_check CHECK (chat.is_safe_integer(leaf_index)),
    CONSTRAINT member_devices_joined_state_version_check CHECK (chat.is_safe_integer(joined_state_version)),
    CONSTRAINT member_devices_joined_transition_check CHECK (chat.is_uuid_v4(joined_transition_id)),
    CONSTRAINT member_devices_joined_seq_check CHECK (chat.is_safe_integer(joined_seq)),
    CONSTRAINT member_devices_removed_state_version_check CHECK (
        removed_state_version IS NULL OR chat.is_safe_integer(removed_state_version)
    ),
    CONSTRAINT member_devices_removed_transition_check CHECK (
        removed_transition_id IS NULL OR chat.is_uuid_v4(removed_transition_id)
    ),
    CONSTRAINT member_devices_removed_seq_check CHECK (
        removed_seq IS NULL OR chat.is_safe_integer(removed_seq)
    ),
    CONSTRAINT member_devices_basic_credential_check CHECK (
        octet_length(basic_credential) BETWEEN 49 AND 298
        AND convert_from(basic_credential, 'UTF8') = user_did || '#' || device_id::TEXT
    ),
    CONSTRAINT member_devices_signature_key_check CHECK (octet_length(leaf_signature_key) = 32),
    CONSTRAINT member_devices_leaf_key_id_check CHECK (
        chat.is_base64url_sha256(leaf_key_id)
        AND leaf_key_id = chat.ed25519_key_id(leaf_signature_key)
    ),
    CONSTRAINT member_devices_leaf_auth_generation_check CHECK (
        chat.is_safe_integer(leaf_auth_generation) AND leaf_auth_generation >= 1
    ),
    CONSTRAINT member_devices_origin_check CHECK (origin IN ('genesis','keyPackage')),
    CONSTRAINT member_devices_origin_shape_check CHECK (
        (origin = 'genesis' AND join_key_package_ref IS NULL)
        OR (origin = 'keyPackage' AND octet_length(join_key_package_ref) = 32)
    ),
    CONSTRAINT member_devices_active_shape_check CHECK (
        (active AND removed_state_version IS NULL AND removed_transition_id IS NULL
            AND removed_seq IS NULL AND removed_at IS NULL)
        OR (NOT active AND removed_state_version IS NOT NULL AND removed_transition_id IS NOT NULL
            AND removed_seq IS NOT NULL AND removed_at IS NOT NULL)
    ),
    CONSTRAINT member_devices_interval_identity_uq UNIQUE (
        leaf_period_id, conversation_id, generation, user_did, device_id
    ),
    CONSTRAINT member_devices_opening_identity_uq UNIQUE (
        leaf_period_id, conversation_id, generation, user_did, device_id,
        joined_state_version, joined_transition_id, joined_seq
    ),
    CONSTRAINT member_devices_closing_identity_uq UNIQUE (
        leaf_period_id, conversation_id, generation, user_did, device_id,
        removed_state_version, removed_transition_id, removed_seq
    )
);

CREATE UNIQUE INDEX member_devices_current_device_uq
    ON chat.member_devices (conversation_id, user_did, device_id)
    WHERE active;
CREATE UNIQUE INDEX member_devices_current_credential_uq
    ON chat.member_devices (conversation_id, basic_credential)
    WHERE active;
CREATE UNIQUE INDEX member_devices_current_leaf_index_uq
    ON chat.member_devices (conversation_id, generation, leaf_index)
    WHERE active;

CREATE TABLE chat.metadata_snapshots (
    metadata_snapshot_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    state_version BIGINT NOT NULL,
    group_id BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    group_context_hash BYTEA NOT NULL,
    confirmation_tag BYTEA NOT NULL,
    producing_transition_id UUID NOT NULL,
    origin_transition_id UUID NOT NULL,
    metadata_version BIGINT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    ciphertext_sha256 BYTEA NOT NULL,
    ciphertext_size BIGINT NOT NULL,
    avatar_blob_id UUID,
    avatar_ciphertext_sha256 BYTEA,
    avatar_ciphertext_size BIGINT,
    avatar_purpose TEXT,
    avatar_binding_origin_transition_id UUID,
    avatar_binding_metadata_version BIGINT,
    avatar_binding_owner_did TEXT,
    avatar_binding_owner_device_id UUID,
    author_did TEXT NOT NULL,
    author_device_id UUID NOT NULL,
    author_key_id TEXT NOT NULL,
    author_public_key BYTEA NOT NULL,
    author_auth_generation BIGINT NOT NULL,
    author_origin_seq BIGINT NOT NULL,
    author_role TEXT NOT NULL,
    author_device_status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT metadata_snapshots_state_fk FOREIGN KEY (
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag
    )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT metadata_snapshots_author_key_fk FOREIGN KEY (author_did, author_device_id, author_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT metadata_snapshots_id_check CHECK (chat.is_uuid_v4(metadata_snapshot_id)),
    CONSTRAINT metadata_snapshots_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT metadata_snapshots_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT metadata_snapshots_state_version_check CHECK (chat.is_safe_integer(state_version)),
    CONSTRAINT metadata_snapshots_epoch_check CHECK (chat.is_safe_integer(epoch)),
    CONSTRAINT metadata_snapshots_transition_check CHECK (
        chat.is_uuid_v4(producing_transition_id) AND chat.is_uuid_v4(origin_transition_id)
    ),
    CONSTRAINT metadata_snapshots_metadata_version_check CHECK (
        chat.is_safe_integer(metadata_version) AND metadata_version >= 1
    ),
    CONSTRAINT metadata_snapshots_crypto_lengths_check CHECK (
        octet_length(group_id) = 32 AND octet_length(group_context_hash) = 32
        AND octet_length(confirmation_tag) = 32 AND octet_length(nonce) = 12
    ),
    CONSTRAINT metadata_snapshots_ciphertext_size_check CHECK (
        chat.is_safe_integer(ciphertext_size) AND ciphertext_size BETWEEN 16 AND 16384
        AND octet_length(ciphertext) = ciphertext_size
    ),
    CONSTRAINT metadata_snapshots_ciphertext_hash_check CHECK (
        octet_length(ciphertext_sha256) = 32
        AND ciphertext_sha256 = digest(ciphertext, 'sha256')
    ),
    CONSTRAINT metadata_snapshots_avatar_blob_id_check CHECK (
        avatar_blob_id IS NULL OR chat.is_uuid_v4(avatar_blob_id)
    ),
    CONSTRAINT metadata_snapshots_avatar_size_check CHECK (
        avatar_ciphertext_size IS NULL OR (
            chat.is_safe_integer(avatar_ciphertext_size)
            AND avatar_ciphertext_size BETWEEN 17 AND 10485760
        )
    ),
    CONSTRAINT metadata_snapshots_avatar_shape_check CHECK (
        (avatar_blob_id IS NULL AND avatar_ciphertext_sha256 IS NULL
            AND avatar_ciphertext_size IS NULL AND avatar_purpose IS NULL
            AND avatar_binding_origin_transition_id IS NULL
            AND avatar_binding_metadata_version IS NULL
            AND avatar_binding_owner_did IS NULL
            AND avatar_binding_owner_device_id IS NULL)
        OR (avatar_blob_id IS NOT NULL AND octet_length(avatar_ciphertext_sha256) = 32
            AND avatar_ciphertext_size IS NOT NULL AND avatar_purpose = 'metadata'
            AND chat.is_uuid_v4(avatar_binding_origin_transition_id)
            AND chat.is_safe_integer(avatar_binding_metadata_version)
            AND avatar_binding_metadata_version >= 1
            AND chat.is_bare_did(avatar_binding_owner_did)
            AND chat.is_uuid_v4(avatar_binding_owner_device_id))
    ),
    CONSTRAINT metadata_snapshots_author_did_check CHECK (chat.is_bare_did(author_did)),
    CONSTRAINT metadata_snapshots_author_device_check CHECK (chat.is_uuid_v4(author_device_id)),
    CONSTRAINT metadata_snapshots_author_key_check CHECK (chat.is_base64url_sha256(author_key_id)),
    CONSTRAINT metadata_snapshots_author_public_key_check CHECK (octet_length(author_public_key) = 32),
    CONSTRAINT metadata_snapshots_author_auth_generation_check CHECK (
        chat.is_safe_integer(author_auth_generation) AND author_auth_generation >= 1
    ),
    CONSTRAINT metadata_snapshots_author_origin_seq_check CHECK (
        chat.is_safe_integer(author_origin_seq) AND author_origin_seq >= 1
    ),
    CONSTRAINT metadata_snapshots_author_authority_check CHECK (
        author_role = 'admin' AND author_device_status = 'active'
    ),
    CONSTRAINT metadata_snapshots_nonce_uq UNIQUE (conversation_id, generation, epoch, nonce),
    CONSTRAINT metadata_snapshots_transition_uq UNIQUE (producing_transition_id),
    CONSTRAINT metadata_snapshots_transition_identity_uq UNIQUE (
        metadata_snapshot_id, conversation_id, generation, state_version,
        producing_transition_id
    )
);

CREATE TABLE chat.key_package_reservations (
    recovery_request_id UUID PRIMARY KEY,
    key_package_ref BYTEA NOT NULL,
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_device_id UUID NOT NULL,
    requester_key_id TEXT NOT NULL,
    requester_auth_generation BIGINT NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    bound_state_version BIGINT NOT NULL,
    bound_group_id BYTEA NOT NULL,
    bound_epoch BIGINT NOT NULL,
    bound_group_context_hash BYTEA NOT NULL,
    bound_confirmation_tag BYTEA NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    consumed_transition_id UUID,
    terminal_transition_id UUID,
    terminal_revocation_id UUID,
    terminal_request_digest BYTEA,
    terminal_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT key_package_reservations_package_owner_fk
        FOREIGN KEY (key_package_ref, recipient_did, recipient_device_id)
        REFERENCES chat.key_packages(key_package_ref, owner_did, owner_device_id),
    CONSTRAINT key_package_reservations_generation_fk FOREIGN KEY (conversation_id, generation)
        REFERENCES chat.generations(conversation_id, generation),
    CONSTRAINT key_package_reservations_requester_key_fk
        FOREIGN KEY (requester_did, requester_device_id, requester_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT key_package_reservations_recipient_device_fk
        FOREIGN KEY (recipient_did, recipient_device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT key_package_reservations_request_id_check CHECK (chat.is_uuid_v4(recovery_request_id)),
    CONSTRAINT key_package_reservations_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT key_package_reservations_did_check CHECK (
        chat.is_bare_did(requester_did) AND chat.is_bare_did(recipient_did)
    ),
    CONSTRAINT key_package_reservations_device_check CHECK (
        chat.is_uuid_v4(requester_device_id) AND chat.is_uuid_v4(recipient_device_id)
    ),
    CONSTRAINT key_package_reservations_key_id_check CHECK (chat.is_base64url_sha256(requester_key_id)),
    CONSTRAINT key_package_reservations_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT key_package_reservations_auth_generation_check CHECK (
        chat.is_safe_integer(requester_auth_generation) AND requester_auth_generation >= 1
    ),
    CONSTRAINT key_package_reservations_state_version_check CHECK (chat.is_safe_integer(bound_state_version)),
    CONSTRAINT key_package_reservations_epoch_check CHECK (chat.is_safe_integer(bound_epoch)),
    CONSTRAINT key_package_reservations_crypto_lengths_check CHECK (
        octet_length(key_package_ref) = 32 AND octet_length(bound_group_id) = 32
        AND octet_length(bound_group_context_hash) = 32
        AND octet_length(bound_confirmation_tag) = 32
    ),
    CONSTRAINT key_package_reservations_purpose_check CHECK (purpose = 'leafRecovery'),
    CONSTRAINT key_package_reservations_status_check CHECK (
        status IN ('active','consumed','expired','released')
    ),
    CONSTRAINT key_package_reservations_expiry_check CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes'
    ),
    CONSTRAINT key_package_reservations_terminal_transition_check CHECK (
        (consumed_transition_id IS NULL OR chat.is_uuid_v4(consumed_transition_id))
        AND (terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id))
        AND (terminal_revocation_id IS NULL OR chat.is_uuid_v4(terminal_revocation_id))
        AND (terminal_request_digest IS NULL OR octet_length(terminal_request_digest) = 32)
    ),
    CONSTRAINT key_package_reservations_terminal_shape_check CHECK (
        (status = 'active' AND consumed_transition_id IS NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL AND terminal_at IS NULL)
        OR (status = 'consumed' AND consumed_transition_id IS NOT NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL
            AND terminal_at >= created_at AND terminal_at < expires_at)
        OR (status = 'expired' AND consumed_transition_id IS NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL AND terminal_at = expires_at)
        OR (status = 'released' AND consumed_transition_id IS NULL
            AND terminal_at >= created_at AND terminal_at < expires_at
            AND num_nonnulls(
                terminal_transition_id, terminal_revocation_id, terminal_request_digest
            ) = 1)
    ),
    CONSTRAINT key_package_reservations_terminal_revocation_fk FOREIGN KEY (
        recipient_did, recipient_device_id, terminal_revocation_id, terminal_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT key_package_reservations_request_recipient_check CHECK (
        requester_did = recipient_did AND requester_device_id = recipient_device_id
    ),
    CONSTRAINT key_package_reservations_delivery_identity_uq UNIQUE (
        recovery_request_id, key_package_ref, recipient_did, recipient_device_id
    )
);

CREATE UNIQUE INDEX key_package_reservations_active_package_uq
    ON chat.key_package_reservations (key_package_ref)
    WHERE status = 'active';

CREATE TABLE chat.reset_requests (
    reset_request_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    requester_did TEXT NOT NULL,
    requester_device_id UUID NOT NULL,
    requester_key_id TEXT NOT NULL,
    requester_auth_generation BIGINT NOT NULL,
    prior_generation BIGINT NOT NULL,
    prior_state_version BIGINT NOT NULL,
    prior_group_id BYTEA NOT NULL,
    prior_epoch BIGINT NOT NULL,
    prior_group_context_hash BYTEA NOT NULL,
    prior_confirmation_tag BYTEA NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    terminal_transition_id UUID,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT reset_requests_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT reset_requests_requester_key_fk
        FOREIGN KEY (requester_did, requester_device_id, requester_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT reset_requests_id_check CHECK (chat.is_uuid_v4(reset_request_id)),
    CONSTRAINT reset_requests_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT reset_requests_requester_did_check CHECK (chat.is_bare_did(requester_did)),
    CONSTRAINT reset_requests_requester_device_check CHECK (chat.is_uuid_v4(requester_device_id)),
    CONSTRAINT reset_requests_requester_key_check CHECK (chat.is_base64url_sha256(requester_key_id)),
    CONSTRAINT reset_requests_auth_generation_check CHECK (
        chat.is_safe_integer(requester_auth_generation) AND requester_auth_generation >= 1
    ),
    CONSTRAINT reset_requests_prior_generation_check CHECK (chat.is_safe_integer(prior_generation)),
    CONSTRAINT reset_requests_prior_state_version_check CHECK (chat.is_safe_integer(prior_state_version)),
    CONSTRAINT reset_requests_prior_epoch_check CHECK (chat.is_safe_integer(prior_epoch)),
    CONSTRAINT reset_requests_crypto_lengths_check CHECK (
        octet_length(prior_group_id) = 32 AND octet_length(prior_group_context_hash) = 32
        AND octet_length(prior_confirmation_tag) = 32
    ),
    CONSTRAINT reset_requests_reason_check CHECK (
        reason IN ('localStateLost','poisonedState','epochDivergence','manualRecovery')
    ),
    CONSTRAINT reset_requests_status_check CHECK (status IN ('pending','stale','consumed','expired')),
    CONSTRAINT reset_requests_signature_check CHECK (
        octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32 AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT reset_requests_expiry_check CHECK (expires_at = received_at + INTERVAL '24 hours'),
    CONSTRAINT reset_requests_terminal_transition_check CHECK (
        terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id)
    ),
    CONSTRAINT reset_requests_terminal_shape_check CHECK (
        (status = 'pending' AND terminal_transition_id IS NULL AND terminal_at IS NULL)
        OR (status IN ('stale','consumed')
            AND terminal_transition_id IS NOT NULL AND terminal_at IS NOT NULL)
        OR (status = 'expired' AND terminal_transition_id IS NULL AND terminal_at = expires_at)
    ),
    CONSTRAINT reset_requests_activation_identity_uq UNIQUE (
        reset_request_id, conversation_id, prior_generation, prior_state_version
    )
);

CREATE UNIQUE INDEX reset_requests_one_pending_uq
    ON chat.reset_requests (conversation_id)
    WHERE status = 'pending';

CREATE TABLE chat.leaf_recovery_requests (
    recovery_request_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    requester_did TEXT NOT NULL,
    requester_device_id UUID NOT NULL,
    requester_key_id TEXT NOT NULL,
    requester_auth_generation BIGINT NOT NULL,
    recovery_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    bound_state_version BIGINT NOT NULL,
    bound_group_id BYTEA NOT NULL,
    bound_epoch BIGINT NOT NULL,
    bound_group_context_hash BYTEA NOT NULL,
    bound_confirmation_tag BYTEA NOT NULL,
    reservation_request_id UUID NOT NULL,
    replaced_leaf_period_id UUID,
    status TEXT NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    fulfilling_transition_id UUID,
    terminal_transition_id UUID,
    terminal_revocation_id UUID,
    terminal_signed_request_bytes BYTEA,
    terminal_signing_transcript_bytes BYTEA,
    terminal_request_digest BYTEA,
    terminal_signature BYTEA,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT leaf_recovery_requests_generation_fk FOREIGN KEY (conversation_id, generation)
        REFERENCES chat.generations(conversation_id, generation),
    CONSTRAINT leaf_recovery_requests_requester_key_fk
        FOREIGN KEY (requester_did, requester_device_id, requester_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT leaf_recovery_requests_replaced_leaf_fk FOREIGN KEY (replaced_leaf_period_id)
        REFERENCES chat.member_devices(leaf_period_id),
    CONSTRAINT leaf_recovery_requests_id_check CHECK (chat.is_uuid_v4(recovery_request_id)),
    CONSTRAINT leaf_recovery_requests_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT leaf_recovery_requests_requester_did_check CHECK (chat.is_bare_did(requester_did)),
    CONSTRAINT leaf_recovery_requests_requester_device_check CHECK (chat.is_uuid_v4(requester_device_id)),
    CONSTRAINT leaf_recovery_requests_requester_key_check CHECK (chat.is_base64url_sha256(requester_key_id)),
    CONSTRAINT leaf_recovery_requests_generation_check CHECK (chat.is_safe_integer(generation)),
    CONSTRAINT leaf_recovery_requests_auth_generation_check CHECK (
        chat.is_safe_integer(requester_auth_generation) AND requester_auth_generation >= 1
    ),
    CONSTRAINT leaf_recovery_requests_state_version_check CHECK (chat.is_safe_integer(bound_state_version)),
    CONSTRAINT leaf_recovery_requests_epoch_check CHECK (chat.is_safe_integer(bound_epoch)),
    CONSTRAINT leaf_recovery_requests_crypto_lengths_check CHECK (
        octet_length(bound_group_id) = 32 AND octet_length(bound_group_context_hash) = 32
        AND octet_length(bound_confirmation_tag) = 32
    ),
    CONSTRAINT leaf_recovery_requests_kind_check CHECK (recovery_kind IN ('add','replace')),
    CONSTRAINT leaf_recovery_requests_source_check CHECK (
        source IN ('requestLeafRecovery','acceptConversation')
    ),
    CONSTRAINT leaf_recovery_requests_reservation_check CHECK (
        chat.is_uuid_v4(reservation_request_id) AND reservation_request_id = recovery_request_id
    ),
    CONSTRAINT leaf_recovery_requests_kind_shape_check CHECK (
        (recovery_kind = 'add' AND replaced_leaf_period_id IS NULL)
        OR (recovery_kind = 'replace' AND replaced_leaf_period_id IS NOT NULL)
    ),
    CONSTRAINT leaf_recovery_requests_status_check CHECK (
        status IN ('open','fulfilled','cancelled','expired','superseded')
    ),
    CONSTRAINT leaf_recovery_requests_signature_check CHECK (
        octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32 AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT leaf_recovery_requests_expiry_check CHECK (
        expires_at > requested_at AND expires_at <= requested_at + INTERVAL '5 minutes'
    ),
    CONSTRAINT leaf_recovery_requests_fulfilling_transition_check CHECK (
        (fulfilling_transition_id IS NULL OR chat.is_uuid_v4(fulfilling_transition_id))
        AND (terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id))
        AND (terminal_revocation_id IS NULL OR chat.is_uuid_v4(terminal_revocation_id))
    ),
    CONSTRAINT leaf_recovery_requests_terminal_signature_check CHECK (
        (terminal_signed_request_bytes IS NULL
            AND terminal_signing_transcript_bytes IS NULL
            AND terminal_request_digest IS NULL AND terminal_signature IS NULL)
        OR (octet_length(terminal_signed_request_bytes) BETWEEN 1 AND 16777216
            AND octet_length(terminal_signing_transcript_bytes) BETWEEN 1 AND 16777216
            AND octet_length(terminal_request_digest) = 32
            AND terminal_request_digest = digest(terminal_signing_transcript_bytes, 'sha256')
            AND octet_length(terminal_signature) = 64)
    ),
    CONSTRAINT leaf_recovery_requests_terminal_shape_check CHECK (
        (status = 'open' AND fulfilling_transition_id IS NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL AND terminal_at IS NULL)
        OR (status = 'fulfilled' AND fulfilling_transition_id IS NOT NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL
            AND terminal_at >= requested_at AND terminal_at < expires_at)
        OR (status = 'cancelled' AND fulfilling_transition_id IS NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NOT NULL
            AND terminal_at >= requested_at AND terminal_at < expires_at)
        OR (status = 'expired' AND fulfilling_transition_id IS NULL
            AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL
            AND terminal_request_digest IS NULL AND terminal_at = expires_at)
        OR (status = 'superseded' AND fulfilling_transition_id IS NULL
            AND terminal_request_digest IS NULL
            AND terminal_at >= requested_at AND terminal_at < expires_at
            AND num_nonnulls(terminal_transition_id, terminal_revocation_id) = 1)
    ),
    CONSTRAINT leaf_recovery_requests_terminal_revocation_fk FOREIGN KEY (
        requester_did, requester_device_id, terminal_revocation_id, terminal_at
    ) REFERENCES chat.device_revocations(
        target_did, target_device_id, revocation_id, accepted_at
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT leaf_recovery_requests_terminal_request_uq UNIQUE (
        recovery_request_id, terminal_request_digest, terminal_at
    ),
    -- Referenced by inventory_recovery_items_request_source_fk (inventory-1) so a
    -- leafRecoveryRequest inventory item is bound to the exact requesting device
    -- of its source request. recovery_request_id is already the PK, so this is a
    -- superkey unique that simply exposes the (request, requester device) tuple
    -- as a composite FK target.
    CONSTRAINT leaf_recovery_requests_requester_identity_uq UNIQUE (
        recovery_request_id, requester_did, requester_device_id
    )
);

ALTER TABLE chat.leaf_recovery_requests
    ADD CONSTRAINT leaf_recovery_requests_reservation_fk
    FOREIGN KEY (reservation_request_id)
    REFERENCES chat.key_package_reservations(recovery_request_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_package_reservations
    ADD CONSTRAINT key_package_reservations_request_fk
    FOREIGN KEY (recovery_request_id)
    REFERENCES chat.leaf_recovery_requests(recovery_request_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_package_reservations
    ADD CONSTRAINT key_package_reservations_terminal_request_fk
    FOREIGN KEY (recovery_request_id, terminal_request_digest, terminal_at)
    REFERENCES chat.leaf_recovery_requests(
        recovery_request_id, terminal_request_digest, terminal_at
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX leaf_recovery_requests_one_open_uq
    ON chat.leaf_recovery_requests (conversation_id, generation, requester_did, requester_device_id)
    WHERE status = 'open';
-- Non-partial index for all-status exact-device lookups. The unique index above
-- is partial (status = 'open') so terminal-row (fulfilled/cancelled/expired/
-- superseded) lookups by exact requester device would otherwise seq-scan.
CREATE INDEX leaf_recovery_requests_device_all_status_idx
    ON chat.leaf_recovery_requests (requester_did, requester_device_id, status, requested_at);

CREATE TABLE chat.leave_requests (
    leave_request_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    requester_did TEXT NOT NULL,
    requester_device_id UUID NOT NULL,
    requester_key_id TEXT NOT NULL,
    requester_auth_generation BIGINT NOT NULL,
    prior_generation BIGINT NOT NULL,
    prior_state_version BIGINT NOT NULL,
    prior_group_id BYTEA NOT NULL,
    prior_epoch BIGINT NOT NULL,
    prior_group_context_hash BYTEA NOT NULL,
    prior_confirmation_tag BYTEA NOT NULL,
    status TEXT NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    terminal_request_digest BYTEA,
    terminal_transition_id UUID,
    received_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT leave_requests_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT leave_requests_requester_key_fk
        FOREIGN KEY (requester_did, requester_device_id, requester_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT leave_requests_id_check CHECK (chat.is_uuid_v4(leave_request_id)),
    CONSTRAINT leave_requests_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT leave_requests_requester_did_check CHECK (chat.is_bare_did(requester_did)),
    CONSTRAINT leave_requests_requester_device_check CHECK (chat.is_uuid_v4(requester_device_id)),
    CONSTRAINT leave_requests_requester_key_check CHECK (chat.is_base64url_sha256(requester_key_id)),
    CONSTRAINT leave_requests_auth_generation_check CHECK (
        chat.is_safe_integer(requester_auth_generation) AND requester_auth_generation >= 1
    ),
    CONSTRAINT leave_requests_prior_generation_check CHECK (chat.is_safe_integer(prior_generation)),
    CONSTRAINT leave_requests_prior_state_version_check CHECK (chat.is_safe_integer(prior_state_version)),
    CONSTRAINT leave_requests_prior_epoch_check CHECK (chat.is_safe_integer(prior_epoch)),
    CONSTRAINT leave_requests_crypto_lengths_check CHECK (
        octet_length(prior_group_id) = 32 AND octet_length(prior_group_context_hash) = 32
        AND octet_length(prior_confirmation_tag) = 32
    ),
    CONSTRAINT leave_requests_status_check CHECK (
        status IN ('pending','fulfilled','cancelled','expired','stale')
    ),
    CONSTRAINT leave_requests_signature_check CHECK (
        octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32 AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
        AND (terminal_request_digest IS NULL OR octet_length(terminal_request_digest) = 32)
    ),
    CONSTRAINT leave_requests_expiry_check CHECK (expires_at = received_at + INTERVAL '24 hours'),
    CONSTRAINT leave_requests_terminal_transition_check CHECK (
        terminal_transition_id IS NULL OR chat.is_uuid_v4(terminal_transition_id)
    ),
    CONSTRAINT leave_requests_terminal_shape_check CHECK (
        (status = 'pending' AND terminal_request_digest IS NULL
            AND terminal_transition_id IS NULL AND terminal_at IS NULL)
        OR (status IN ('fulfilled','stale')
            AND octet_length(terminal_request_digest) = 32
            AND terminal_transition_id IS NOT NULL AND terminal_at IS NOT NULL)
        OR (status = 'cancelled'
            AND octet_length(terminal_request_digest) = 32
            AND terminal_transition_id IS NULL AND terminal_at IS NOT NULL)
        OR (status = 'expired' AND terminal_request_digest IS NULL
            AND terminal_transition_id IS NULL AND terminal_at = expires_at)
    )
);

CREATE UNIQUE INDEX leave_requests_one_pending_uq
    ON chat.leave_requests (conversation_id, requester_did)
    WHERE status = 'pending';

-- Direct-writer boundary: declarative constraints below prove structural shape,
-- timing, call counts, and child/snapshot revision separation. They cannot
-- authenticate upstream evidence or soundly reconstruct the canonical DID set,
-- operation scope, configured source identity, or aggregate evidence codec from
-- opaque bytes alone. Deployment must therefore keep these three projection
-- tables, allocation ledger, and revision sequence owner-only. A distinct runtime
-- role must receive no raw DML or sequence privileges. The owner-only allocator function
-- below is the sole revision-allocation API; it is deliberately an
-- invoker-rights function with no PUBLIC execute grant. If delegated persistence
-- is needed later, expose a separately reviewed narrow procedure that persists a
-- complete projection atomically; never grant direct table or sequence access.
-- Role names and grants remain deployment configuration, and the catalog test
-- proves that this migration leaks none of these privileges.
CREATE SEQUENCE chat.relationship_projection_revision_seq AS BIGINT
    INCREMENT BY 1
    MINVALUE 1
    MAXVALUE 9007199254740991
    START WITH 1
    CACHE 1
    NO CYCLE;

CREATE TABLE chat.relationship_projection_revision_allocations (
    allocation_id UUID PRIMARY KEY,
    projection_revision BIGINT NOT NULL,
    allocated_at TIMESTAMPTZ NOT NULL,
    consumed_projection_id UUID,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT relationship_projection_revision_allocations_revision_uq UNIQUE (
        projection_revision
    ),
    CONSTRAINT relationship_projection_revision_allocations_consumed_uq UNIQUE (
        consumed_projection_id
    ),
    CONSTRAINT relationship_projection_revision_allocations_pair_uq UNIQUE (
        allocation_id, projection_revision
    ),
    CONSTRAINT relationship_projection_revision_allocations_id_check CHECK (
        chat.is_uuid_v4(allocation_id)
    ),
    CONSTRAINT relationship_projection_revision_allocations_revision_check CHECK (
        chat.is_safe_integer(projection_revision) AND projection_revision >= 1
    ),
    CONSTRAINT relationship_projection_revision_allocations_consumed_id_check CHECK (
        consumed_projection_id IS NULL OR chat.is_uuid_v4(consumed_projection_id)
    ),
    CONSTRAINT relationship_projection_revision_allocations_terminal_check CHECK (
        (consumed_projection_id IS NULL AND consumed_at IS NULL)
        OR (consumed_projection_id IS NOT NULL AND consumed_at IS NOT NULL)
    )
);

CREATE FUNCTION chat.allocate_relationship_projection_revision()
RETURNS TABLE(allocation_id UUID, projection_revision BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    minted_allocation_id UUID := gen_random_uuid();
    minted_projection_revision BIGINT := nextval('chat.relationship_projection_revision_seq');
BEGIN
    INSERT INTO chat.relationship_projection_revision_allocations(
        allocation_id, projection_revision, allocated_at
    ) VALUES (
        minted_allocation_id, minted_projection_revision, clock_timestamp()
    );
    RETURN QUERY SELECT minted_allocation_id, minted_projection_revision;
END
$$;

REVOKE ALL ON FUNCTION chat.allocate_relationship_projection_revision() FROM PUBLIC;

CREATE TABLE chat.relationship_projection_snapshots (
    projection_id UUID PRIMARY KEY,
    projection_revision BIGINT NOT NULL,
    projection_allocation_id UUID NOT NULL,
    operation_scope TEXT NOT NULL,
    canonical_did_set_bytes BYTEA NOT NULL,
    canonical_did_set_sha256 BYTEA NOT NULL,
    scope_digest BYTEA NOT NULL,
    appview_base TEXT NOT NULL,
    configuration_fingerprint BYTEA NOT NULL,
    aggregate_evidence_bytes BYTEA NOT NULL,
    aggregate_evidence_sha256 BYTEA NOT NULL,
    source_call_count BIGINT NOT NULL,
    evidence_kind TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT relationship_projection_snapshots_revision_uq UNIQUE (projection_revision),
    CONSTRAINT relationship_projection_snapshots_allocation_uq UNIQUE (projection_allocation_id),
    CONSTRAINT relationship_projection_snapshots_allocation_pair_uq UNIQUE (
        projection_id, projection_allocation_id, projection_revision
    ),
    CONSTRAINT relationship_projection_snapshots_allocation_fk FOREIGN KEY (
        projection_allocation_id, projection_revision
    ) REFERENCES chat.relationship_projection_revision_allocations(
        allocation_id, projection_revision
    ),
    CONSTRAINT relationship_projection_snapshots_id_check CHECK (chat.is_uuid_v4(projection_id)),
    CONSTRAINT relationship_projection_snapshots_allocation_id_check CHECK (
        chat.is_uuid_v4(projection_allocation_id)
    ),
    CONSTRAINT relationship_projection_snapshots_revision_check CHECK (
        chat.is_safe_integer(projection_revision) AND projection_revision >= 1
    ),
    CONSTRAINT relationship_projection_snapshots_scope_check CHECK (
        operation_scope IN ('creation','pendingAdd','acceptance','recoveryReservation',
                            'recoveryFulfillment','traffic')
    ),
    CONSTRAINT relationship_projection_snapshots_did_set_hash_check CHECK (
        octet_length(canonical_did_set_bytes) BETWEEN 1 AND 26402
        AND octet_length(canonical_did_set_sha256) = 32
        AND canonical_did_set_sha256 = digest(canonical_did_set_bytes, 'sha256')
        AND octet_length(scope_digest) = 32
    ),
    CONSTRAINT relationship_projection_snapshots_config_check CHECK (
        appview_base ~ '^https://[a-z0-9.-]+(?::[0-9]+)?$'
        AND octet_length(appview_base) BETWEEN 9 AND 2048
        AND octet_length(configuration_fingerprint) = 32
    ),
    CONSTRAINT relationship_projection_snapshots_evidence_hash_check CHECK (
        octet_length(aggregate_evidence_bytes) BETWEEN 1 AND 8388608
        AND octet_length(aggregate_evidence_sha256) = 32
        AND aggregate_evidence_sha256 = digest(aggregate_evidence_bytes, 'sha256')
    ),
    CONSTRAINT relationship_projection_snapshots_source_call_count_check CHECK (
        chat.is_safe_integer(source_call_count)
        AND ((operation_scope = 'traffic' AND source_call_count <= 4)
             OR (operation_scope <> 'traffic' AND source_call_count <= 396))
    ),
    CONSTRAINT relationship_projection_snapshots_evidence_kind_check CHECK (
        evidence_kind IN ('live','fallback')
    ),
    CONSTRAINT relationship_projection_snapshots_completion_check CHECK (
        completed_at >= started_at
        AND completed_at <= started_at + INTERVAL '30 seconds'
    )
);

CREATE INDEX relationship_projection_fallback_lookup_idx
    ON chat.relationship_projection_snapshots (operation_scope, scope_digest,
        configuration_fingerprint,
        completed_at DESC, projection_revision DESC)
    WHERE evidence_kind = 'fallback';

ALTER TABLE chat.relationship_projection_revision_allocations
    ADD CONSTRAINT relationship_projection_revision_allocations_snapshot_fk
    FOREIGN KEY (consumed_projection_id, allocation_id, projection_revision)
    REFERENCES chat.relationship_projection_snapshots(
        projection_id, projection_allocation_id, projection_revision
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION chat.consume_relationship_projection_revision_allocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    claimed_allocation_id UUID;
BEGIN
    UPDATE chat.relationship_projection_revision_allocations
       SET consumed_projection_id = NEW.projection_id,
           consumed_at = clock_timestamp()
     WHERE allocation_id = NEW.projection_allocation_id
       AND projection_revision = NEW.projection_revision
       AND consumed_projection_id IS NULL
       AND consumed_at IS NULL
    RETURNING allocation_id INTO claimed_allocation_id;

    IF claimed_allocation_id IS NULL THEN
        RAISE EXCEPTION 'relationship projection allocation is absent, mismatched, or consumed'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER relationship_projection_snapshots_allocation_consumed
BEFORE INSERT ON chat.relationship_projection_snapshots
FOR EACH ROW EXECUTE FUNCTION chat.consume_relationship_projection_revision_allocation();

CREATE TABLE chat.relationship_projection_relationships (
    projection_id UUID NOT NULL,
    actor_did TEXT NOT NULL,
    other_did TEXT NOT NULL,
    blocking BOOLEAN NOT NULL,
    blocked_by BOOLEAN NOT NULL,
    blocking_by_list BOOLEAN NOT NULL,
    blocked_by_list BOOLEAN NOT NULL,
    following BOOLEAN NOT NULL,
    followed_by BOOLEAN NOT NULL,
    batch_ordinal BIGINT NOT NULL,
    fetch_revision BIGINT NOT NULL,
    request_digest BYTEA NOT NULL,
    response_digest BYTEA NOT NULL,
    evidence_kind TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (projection_id, actor_did, other_did),
    CONSTRAINT relationship_projection_relationships_snapshot_fk FOREIGN KEY (projection_id)
        REFERENCES chat.relationship_projection_snapshots(projection_id),
    CONSTRAINT relationship_projection_relationships_projection_id_check CHECK (chat.is_uuid_v4(projection_id)),
    CONSTRAINT relationship_projection_relationships_did_check CHECK (
        chat.is_bare_did(actor_did) AND chat.is_bare_did(other_did) AND actor_did <> other_did
    ),
    CONSTRAINT relationship_projection_relationships_revision_check CHECK (
        chat.is_safe_integer(fetch_revision) AND fetch_revision >= 1
        AND chat.is_safe_integer(batch_ordinal) AND batch_ordinal <= 29
    ),
    CONSTRAINT relationship_projection_relationships_digest_check CHECK (
        octet_length(request_digest) = 32 AND octet_length(response_digest) = 32
    ),
    CONSTRAINT relationship_projection_relationships_evidence_check CHECK (
        evidence_kind IN ('live','fallback')
    ),
    CONSTRAINT relationship_projection_relationships_batch_ordinal_uq UNIQUE (
        projection_id, fetch_revision, batch_ordinal
    )
);

CREATE INDEX relationship_projection_relationships_decision_idx
    ON chat.relationship_projection_relationships (projection_id, actor_did, other_did);
CREATE INDEX relationship_projection_relationships_batch_idx
    ON chat.relationship_projection_relationships (
        projection_id, fetch_revision, batch_ordinal
    );

CREATE TABLE chat.relationship_projection_declarations (
    projection_id UUID NOT NULL,
    recipient_did TEXT NOT NULL,
    resolved_pds_origin TEXT NOT NULL,
    service_id TEXT NOT NULL,
    fetch_revision BIGINT NOT NULL,
    did_request_digest BYTEA NOT NULL,
    did_document_digest BYTEA NOT NULL,
    record_request_digest BYTEA NOT NULL,
    record_response_digest BYTEA NOT NULL,
    record_cid TEXT,
    record_evidence_kind TEXT NOT NULL,
    incoming_policy TEXT NOT NULL,
    allow_group_invites TEXT,
    resolved_group_policy TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (projection_id, recipient_did),
    CONSTRAINT relationship_projection_declarations_revision_uq UNIQUE (
        projection_id, fetch_revision
    ),
    CONSTRAINT relationship_projection_declarations_snapshot_fk FOREIGN KEY (projection_id)
        REFERENCES chat.relationship_projection_snapshots(projection_id),
    CONSTRAINT relationship_projection_declarations_projection_id_check CHECK (chat.is_uuid_v4(projection_id)),
    CONSTRAINT relationship_projection_declarations_recipient_did_check CHECK (chat.is_bare_did(recipient_did)),
    CONSTRAINT relationship_projection_declarations_pds_check CHECK (
        resolved_pds_origin ~ '^https://[a-z0-9.-]+(?::[0-9]+)?$'
        AND octet_length(resolved_pds_origin) BETWEEN 9 AND 2048
        AND service_id IN ('#atproto_pds', recipient_did || '#atproto_pds')
    ),
    CONSTRAINT relationship_projection_declarations_revision_check CHECK (
        chat.is_safe_integer(fetch_revision) AND fetch_revision >= 1
    ),
    CONSTRAINT relationship_projection_declarations_digest_check CHECK (
        octet_length(did_request_digest) = 32
        AND octet_length(did_document_digest) = 32
        AND octet_length(record_request_digest) = 32
        AND octet_length(record_response_digest) = 32
    ),
    CONSTRAINT relationship_projection_declarations_evidence_check CHECK (
        record_evidence_kind IN ('recordPresent','structuredRecordNotFound')
        AND evidence_kind IN ('live','fallback')
    ),
    CONSTRAINT relationship_projection_declarations_policy_check CHECK (
        incoming_policy IN ('all','none','following')
        AND (allow_group_invites IS NULL
             OR allow_group_invites IN ('all','none','following'))
        AND resolved_group_policy = COALESCE(allow_group_invites, incoming_policy)
        AND (record_cid IS NULL OR octet_length(record_cid) BETWEEN 1 AND 256)
    ),
    CONSTRAINT relationship_projection_declarations_absence_check CHECK (
        (record_evidence_kind = 'recordPresent')
        OR (record_evidence_kind = 'structuredRecordNotFound' AND record_cid IS NULL
            AND incoming_policy = 'following' AND allow_group_invites IS NULL
            AND resolved_group_policy = 'following')
    )
);

CREATE FUNCTION chat.assert_relationship_projection(target_projection UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_row chat.relationship_projection_snapshots%ROWTYPE;
    graph_call_count BIGINT;
    declaration_count BIGINT;
BEGIN
    SELECT * INTO snapshot_row
      FROM chat.relationship_projection_snapshots
     WHERE projection_id = target_projection
     FOR UPDATE;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.relationship_projection_relationships
             WHERE projection_id = target_projection
            UNION ALL
            SELECT 1 FROM chat.relationship_projection_declarations
             WHERE projection_id = target_projection
        ) THEN
            RAISE EXCEPTION 'relationship projection snapshot missing'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT count(DISTINCT fetch_revision) INTO graph_call_count
      FROM chat.relationship_projection_relationships
     WHERE projection_id = target_projection;
    SELECT count(*) INTO declaration_count
      FROM chat.relationship_projection_declarations
     WHERE projection_id = target_projection;

    IF snapshot_row.source_call_count <> graph_call_count + declaration_count * 2
       OR (snapshot_row.operation_scope IN ('traffic','recoveryReservation','recoveryFulfillment')
           AND declaration_count <> 0)
       OR EXISTS (
            SELECT 1
             FROM chat.relationship_projection_relationships relation
             WHERE relation.projection_id = target_projection
               AND (relation.fetch_revision = snapshot_row.projection_revision
                    OR relation.evidence_kind <> snapshot_row.evidence_kind
                    OR relation.fetched_at < snapshot_row.started_at
                    OR relation.fetched_at > snapshot_row.completed_at)
       )
       OR EXISTS (
            SELECT 1
             FROM chat.relationship_projection_declarations declaration
             WHERE declaration.projection_id = target_projection
               AND (declaration.fetch_revision = snapshot_row.projection_revision
                    OR declaration.evidence_kind <> snapshot_row.evidence_kind
                    OR declaration.fetched_at < snapshot_row.started_at
                    OR declaration.fetched_at > snapshot_row.completed_at)
       )
       OR EXISTS (
            SELECT 1
              FROM chat.relationship_projection_declarations declaration
              JOIN chat.relationship_projection_relationships relation
                ON relation.projection_id = declaration.projection_id
               AND relation.fetch_revision = declaration.fetch_revision
             WHERE declaration.projection_id = target_projection
       )
       OR EXISTS (
            SELECT 1
              FROM (
                SELECT fetch_revision,
                       count(*) AS row_count,
                       count(DISTINCT actor_did) AS actor_count,
                       count(DISTINCT request_digest) AS request_count,
                       count(DISTINCT response_digest) AS response_count,
                       count(DISTINCT evidence_kind) AS evidence_count,
                       count(DISTINCT fetched_at) AS fetched_count,
                       min(batch_ordinal) AS minimum_ordinal,
                       max(batch_ordinal) AS maximum_ordinal
                  FROM chat.relationship_projection_relationships
                 WHERE projection_id = target_projection
                 GROUP BY fetch_revision
              ) batch
             WHERE batch.row_count NOT BETWEEN 1 AND 30
                OR batch.actor_count <> 1 OR batch.request_count <> 1
                OR batch.response_count <> 1 OR batch.evidence_count <> 1
                OR batch.fetched_count <> 1 OR batch.minimum_ordinal <> 0
                OR batch.maximum_ordinal <> batch.row_count - 1
       )
       OR EXISTS (
            SELECT 1
              FROM chat.relationship_projection_relationships left_relation
              JOIN chat.relationship_projection_relationships right_relation
                ON right_relation.projection_id = left_relation.projection_id
               AND right_relation.actor_did = left_relation.other_did
               AND right_relation.other_did = left_relation.actor_did
             WHERE left_relation.projection_id = target_projection
       ) THEN
        RAISE EXCEPTION 'relationship projection evidence mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_relationship_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM chat.assert_relationship_projection(OLD.projection_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (TG_OP = 'INSERT' OR NEW.projection_id IS DISTINCT FROM OLD.projection_id) THEN
        PERFORM chat.assert_relationship_projection(NEW.projection_id);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER relationship_projection_snapshots_complete_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.relationship_projection_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_relationship_projection();

CREATE CONSTRAINT TRIGGER relationship_projection_relationships_complete_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.relationship_projection_relationships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_relationship_projection();

CREATE CONSTRAINT TRIGGER relationship_projection_declarations_complete_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.relationship_projection_declarations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_relationship_projection();

CREATE TABLE chat.transitions (
    transition_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    kind TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    actor_key_id TEXT NOT NULL,
    actor_auth_generation BIGINT NOT NULL,
    actor_role TEXT NOT NULL,
    actor_device_status TEXT NOT NULL,
    signed_request_bytes BYTEA NOT NULL,
    unsigned_projection_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    prior_generation BIGINT,
    prior_state_version BIGINT,
    next_generation BIGINT,
    next_state_version BIGINT,
    retired_generation BIGINT,
    retired_state_version BIGINT,
    successor_generation BIGINT,
    successor_state_version BIGINT,
    reset_request_id UUID,
    close_transition_id UUID,
    metadata_snapshot_id UUID,
    entry_seq BIGINT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT transitions_conversation_fk FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT transitions_actor_key_fk FOREIGN KEY (actor_did, actor_device_id, actor_key_id)
        REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT transitions_transition_id_check CHECK (chat.is_uuid_v4(transition_id)),
    CONSTRAINT transitions_conversation_id_check CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT transitions_actor_did_check CHECK (chat.is_bare_did(actor_did)),
    CONSTRAINT transitions_actor_device_check CHECK (chat.is_uuid_v4(actor_device_id)),
    CONSTRAINT transitions_actor_key_check CHECK (chat.is_base64url_sha256(actor_key_id)),
    CONSTRAINT transitions_actor_auth_generation_check CHECK (
        chat.is_safe_integer(actor_auth_generation) AND actor_auth_generation >= 1
    ),
    CONSTRAINT transitions_actor_authority_check CHECK (
        actor_role IN ('member','admin') AND actor_device_status = 'active'
        AND (kind NOT IN ('creation','policy','metadata','resetActivation','closeConversation')
             OR actor_role = 'admin')
    ),
    CONSTRAINT transitions_kind_check CHECK (
        kind IN ('creation','commit','policy','acceptConversation','metadata','leafRecovery',
                 'leaveCommit','leavePolicy','closeConversation','resetActivation')
    ),
    CONSTRAINT transitions_signature_check CHECK (
        octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(unsigned_projection_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32 AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT transitions_prior_generation_check CHECK (
        prior_generation IS NULL OR chat.is_safe_integer(prior_generation)
    ),
    CONSTRAINT transitions_prior_state_version_check CHECK (
        prior_state_version IS NULL OR chat.is_safe_integer(prior_state_version)
    ),
    CONSTRAINT transitions_next_generation_check CHECK (
        next_generation IS NULL OR chat.is_safe_integer(next_generation)
    ),
    CONSTRAINT transitions_next_state_version_check CHECK (
        next_state_version IS NULL OR chat.is_safe_integer(next_state_version)
    ),
    CONSTRAINT transitions_retired_generation_check CHECK (
        retired_generation IS NULL OR chat.is_safe_integer(retired_generation)
    ),
    CONSTRAINT transitions_retired_state_version_check CHECK (
        retired_state_version IS NULL OR chat.is_safe_integer(retired_state_version)
    ),
    CONSTRAINT transitions_successor_generation_check CHECK (
        successor_generation IS NULL OR chat.is_safe_integer(successor_generation)
    ),
    CONSTRAINT transitions_successor_state_version_check CHECK (
        successor_state_version IS NULL OR chat.is_safe_integer(successor_state_version)
    ),
    CONSTRAINT transitions_coordinate_pairs_check CHECK (
        ((prior_generation IS NULL) = (prior_state_version IS NULL))
        AND ((next_generation IS NULL) = (next_state_version IS NULL))
        AND ((retired_generation IS NULL) = (retired_state_version IS NULL))
        AND ((successor_generation IS NULL) = (successor_state_version IS NULL))
    ),
    CONSTRAINT transitions_reset_request_id_check CHECK (
        reset_request_id IS NULL OR chat.is_uuid_v4(reset_request_id)
    ),
    CONSTRAINT transitions_close_transition_id_check CHECK (
        close_transition_id IS NULL OR chat.is_uuid_v4(close_transition_id)
    ),
    CONSTRAINT transitions_close_transition_shape_check CHECK (
        (kind = 'closeConversation' AND close_transition_id = transition_id)
        OR (kind <> 'closeConversation' AND close_transition_id IS NULL)
    ),
    CONSTRAINT transitions_metadata_snapshot_id_check CHECK (
        metadata_snapshot_id IS NULL OR chat.is_uuid_v4(metadata_snapshot_id)
    ),
    CONSTRAINT transitions_entry_seq_check CHECK (
        chat.is_safe_integer(entry_seq) AND entry_seq >= 1
    ),
    CONSTRAINT transitions_kind_coordinate_shape_check CHECK (
        (kind = 'creation'
            AND prior_generation IS NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND next_generation = 0 AND next_state_version = 0
            AND retired_generation IS NULL AND successor_generation IS NULL
            AND reset_request_id IS NULL)
        OR (kind = 'resetActivation'
            AND prior_generation IS NOT NULL AND prior_state_version IS NOT NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND retired_generation IS NOT NULL AND retired_state_version IS NOT NULL
            AND successor_generation IS NOT NULL AND successor_state_version IS NOT NULL
            AND retired_generation = prior_generation
            AND retired_state_version = prior_state_version + 1
            AND successor_generation = prior_generation + 1
            AND successor_state_version = 0
            AND next_generation = successor_generation
            AND next_state_version = successor_state_version
            AND reset_request_id IS NOT NULL)
        OR (kind IN ('commit','policy','acceptConversation','metadata','leafRecovery',
                     'leaveCommit','leavePolicy','closeConversation')
            AND prior_generation IS NOT NULL AND prior_state_version IS NOT NULL
            AND next_generation IS NOT NULL AND next_state_version IS NOT NULL
            AND next_generation = prior_generation
            AND next_state_version = prior_state_version + 1
            AND retired_generation IS NULL AND successor_generation IS NULL
            AND reset_request_id IS NULL)
    ),
    CONSTRAINT transitions_entry_identity_uq UNIQUE (
        conversation_id, entry_seq, transition_id
    ),
    CONSTRAINT transitions_entry_actor_uq UNIQUE (
        conversation_id, entry_seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    ),
    CONSTRAINT transitions_role_provenance_uq UNIQUE (
        conversation_id, transition_id, accepted_at
    ),
    CONSTRAINT transitions_close_identity_uq UNIQUE (
        conversation_id, close_transition_id, next_generation,
        next_state_version, entry_seq, accepted_at
    ),
    CONSTRAINT transitions_reset_activation_identity_uq UNIQUE (
        reset_request_id, conversation_id, prior_generation, prior_state_version
    )
);

ALTER TABLE chat.generation_states
    ADD CONSTRAINT generation_states_transition_fk
    FOREIGN KEY (producing_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.participants
    ADD CONSTRAINT participants_role_transition_fk
    FOREIGN KEY (conversation_id, role_transition_id, role_changed_at)
    REFERENCES chat.transitions(conversation_id, transition_id, accepted_at)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_transition_fk
    FOREIGN KEY (producing_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_metadata_snapshot_fk
    FOREIGN KEY (metadata_snapshot_id)
    REFERENCES chat.metadata_snapshots(metadata_snapshot_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_state_transition_fk
    FOREIGN KEY (
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag, producing_transition_id
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id, epoch,
        group_context_hash, confirmation_tag, producing_transition_id
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_author_key_proof_fk
    FOREIGN KEY (
        author_did, author_device_id, author_key_id,
        author_public_key
    ) REFERENCES chat.device_keys(
        user_did, device_id, key_id,
        signing_public_key
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_author_origin_fk
    FOREIGN KEY (
        conversation_id, author_origin_seq, origin_transition_id,
        author_did, author_device_id, author_key_id, author_auth_generation
    ) REFERENCES chat.transitions(
        conversation_id, entry_seq, transition_id,
        actor_did, actor_device_id, actor_key_id, actor_auth_generation
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_metadata_snapshot_identity_fk
    FOREIGN KEY (
        metadata_snapshot_id, conversation_id, next_generation,
        next_state_version, transition_id
    ) REFERENCES chat.metadata_snapshots(
        metadata_snapshot_id, conversation_id, generation,
        state_version, producing_transition_id
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_prior_state_fk
    FOREIGN KEY (conversation_id, prior_generation, prior_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_next_state_fk
    FOREIGN KEY (conversation_id, next_generation, next_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_retired_state_fk
    FOREIGN KEY (conversation_id, retired_generation, retired_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_successor_state_fk
    FOREIGN KEY (conversation_id, successor_generation, successor_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_reset_request_fk
    FOREIGN KEY (reset_request_id)
    REFERENCES chat.reset_requests(reset_request_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_reset_request_identity_fk
    FOREIGN KEY (
        reset_request_id, conversation_id, prior_generation, prior_state_version
    ) REFERENCES chat.reset_requests(
        reset_request_id, conversation_id, prior_generation, prior_state_version
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_packages
    ADD CONSTRAINT key_packages_terminal_transition_fk
    FOREIGN KEY (terminal_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_joined_state_fk
    FOREIGN KEY (conversation_id, generation, joined_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_joined_transition_fk
    FOREIGN KEY (joined_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_removed_state_fk
    FOREIGN KEY (conversation_id, generation, removed_state_version)
    REFERENCES chat.generation_states(conversation_id, generation, state_version)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.member_devices
    ADD CONSTRAINT member_devices_removed_transition_fk
    FOREIGN KEY (removed_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.metadata_snapshots
    ADD CONSTRAINT metadata_snapshots_origin_transition_fk
    FOREIGN KEY (origin_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_package_reservations
    ADD CONSTRAINT key_package_reservations_bound_state_fk
    FOREIGN KEY (
        conversation_id, generation, bound_state_version, bound_group_id,
        bound_epoch, bound_group_context_hash, bound_confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id,
        epoch, group_context_hash, confirmation_tag
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.reset_requests
    ADD CONSTRAINT reset_requests_prior_state_fk
    FOREIGN KEY (
        conversation_id, prior_generation, prior_state_version, prior_group_id,
        prior_epoch, prior_group_context_hash, prior_confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id,
        epoch, group_context_hash, confirmation_tag
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.leaf_recovery_requests
    ADD CONSTRAINT leaf_recovery_requests_bound_state_fk
    FOREIGN KEY (
        conversation_id, generation, bound_state_version, bound_group_id,
        bound_epoch, bound_group_context_hash, bound_confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id,
        epoch, group_context_hash, confirmation_tag
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.leave_requests
    ADD CONSTRAINT leave_requests_prior_state_fk
    FOREIGN KEY (
        conversation_id, prior_generation, prior_state_version, prior_group_id,
        prior_epoch, prior_group_context_hash, prior_confirmation_tag
    ) REFERENCES chat.generation_states(
        conversation_id, generation, state_version, group_id,
        epoch, group_context_hash, confirmation_tag
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.conversations
    ADD CONSTRAINT conversations_close_transition_fk
    FOREIGN KEY (close_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.conversations
    ADD CONSTRAINT conversations_close_identity_fk
    FOREIGN KEY (
        conversation_id, close_transition_id, close_generation,
        close_state_version, close_seq, closed_at
    ) REFERENCES chat.transitions(
        conversation_id, close_transition_id, next_generation,
        next_state_version, entry_seq, accepted_at
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.transitions
    ADD CONSTRAINT transitions_close_conversation_fk
    FOREIGN KEY (
        conversation_id, close_transition_id, next_generation,
        next_state_version, entry_seq, accepted_at
    ) REFERENCES chat.conversations(
        conversation_id, close_transition_id, close_generation,
        close_state_version, close_seq, closed_at
    )
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.reset_requests
    ADD CONSTRAINT reset_requests_terminal_transition_fk
    FOREIGN KEY (terminal_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.leaf_recovery_requests
    ADD CONSTRAINT leaf_recovery_requests_fulfilling_transition_fk
    FOREIGN KEY (fulfilling_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.leaf_recovery_requests
    ADD CONSTRAINT leaf_recovery_requests_terminal_transition_fk
    FOREIGN KEY (terminal_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.leave_requests
    ADD CONSTRAINT leave_requests_terminal_transition_fk
    FOREIGN KEY (terminal_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_package_reservations
    ADD CONSTRAINT key_package_reservations_consumed_transition_fk
    FOREIGN KEY (consumed_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE chat.key_package_reservations
    ADD CONSTRAINT key_package_reservations_terminal_transition_fk
    FOREIGN KEY (terminal_transition_id)
    REFERENCES chat.transitions(transition_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION chat.assert_transition_state_outputs(target_transition UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    transition_row chat.transitions%ROWTYPE;
    output_count BIGINT;
BEGIN
    SELECT * INTO transition_row
      FROM chat.transitions
     WHERE transition_id = target_transition;

    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.generation_states
             WHERE producing_transition_id = target_transition
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = transition_row.conversation_id
     FOR UPDATE;

    SELECT count(*) INTO output_count
      FROM chat.generation_states
     WHERE producing_transition_id = target_transition;

    IF EXISTS (
        SELECT 1 FROM chat.generation_states state
         WHERE state.producing_transition_id = target_transition
           AND state.created_at <> transition_row.accepted_at
    ) THEN
        RAISE EXCEPTION 'generation state trusted time mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF transition_row.kind = 'creation' THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'creation'
               AND state.lifecycle = 'active'
               AND state.epoch = 0
               AND EXISTS (
                    SELECT 1 FROM chat.conversations conversation
                     WHERE conversation.conversation_id = transition_row.conversation_id
                       AND conversation.created_at = transition_row.accepted_at
               )
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.next_generation
                       AND generation.activated_seq = transition_row.entry_seq
                       AND generation.activated_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN ('commit','leafRecovery','leaveCommit') THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'commit'
               AND state.lifecycle = 'active'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch + 1
               AND state.group_context_hash <> prior.group_context_hash
               AND state.confirmation_tag <> prior.confirmation_tag
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN (
        'policy','acceptConversation','metadata','leavePolicy'
    ) THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = transition_row.kind
               AND state.lifecycle = 'active'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch
               AND state.group_context_hash = prior.group_context_hash
               AND state.confirmation_tag = prior.confirmation_tag
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind = 'closeConversation' THEN
        IF output_count <> 1 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states state
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE state.producing_transition_id = target_transition
               AND state.conversation_id = transition_row.conversation_id
               AND state.generation = transition_row.next_generation
               AND state.state_version = transition_row.next_state_version
               AND state.state_kind = 'closeConversation'
               AND state.lifecycle = 'superseded'
               AND state.group_id = prior.group_id
               AND state.epoch = prior.epoch
               AND state.group_context_hash = prior.group_context_hash
               AND state.confirmation_tag = prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.next_generation
                       AND generation.superseded_seq = transition_row.entry_seq
                       AND generation.superseded_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind = 'resetActivation' THEN
        IF output_count <> 2 OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states retired
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE retired.producing_transition_id = target_transition
               AND retired.conversation_id = transition_row.conversation_id
               AND retired.generation = transition_row.retired_generation
               AND retired.state_version = transition_row.retired_state_version
               AND retired.state_kind = 'resetRetirement'
               AND retired.lifecycle = 'superseded'
               AND retired.group_id = prior.group_id
               AND retired.epoch = prior.epoch
               AND retired.group_context_hash = prior.group_context_hash
               AND retired.confirmation_tag = prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.retired_generation
                       AND generation.superseded_seq = transition_row.entry_seq
                       AND generation.superseded_at = transition_row.accepted_at
               )
        ) OR NOT EXISTS (
            SELECT 1
              FROM chat.generation_states successor
              JOIN chat.generation_states prior
                ON prior.conversation_id = transition_row.conversation_id
               AND prior.generation = transition_row.prior_generation
               AND prior.state_version = transition_row.prior_state_version
             WHERE successor.producing_transition_id = target_transition
               AND successor.conversation_id = transition_row.conversation_id
               AND successor.generation = transition_row.successor_generation
               AND successor.state_version = transition_row.successor_state_version
               AND successor.state_kind = 'resetSuccessor'
               AND successor.lifecycle = 'active'
               AND successor.epoch = 0
               AND successor.group_id <> prior.group_id
               AND successor.group_context_hash <> prior.group_context_hash
               AND successor.confirmation_tag <> prior.confirmation_tag
               AND EXISTS (
                    SELECT 1 FROM chat.generations generation
                     WHERE generation.conversation_id = transition_row.conversation_id
                       AND generation.generation = transition_row.successor_generation
                       AND generation.activated_seq = transition_row.entry_seq
                       AND generation.activated_at = transition_row.accepted_at
               )
        ) THEN
            RAISE EXCEPTION 'transition state output mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'transition state output mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_transition_state_outputs()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'transitions' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_transition_state_outputs(OLD.transition_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_transition_state_outputs(NEW.transition_id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_transition_state_outputs(OLD.producing_transition_id);
        END IF;
        IF TG_OP <> 'DELETE'
           AND (TG_OP = 'INSERT'
                OR NEW.producing_transition_id IS DISTINCT FROM OLD.producing_transition_id) THEN
            PERFORM chat.assert_transition_state_outputs(NEW.producing_transition_id);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER transitions_state_outputs_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.transitions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_transition_state_outputs();

CREATE CONSTRAINT TRIGGER generation_states_transition_outputs_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.generation_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_transition_state_outputs();

CREATE FUNCTION chat.assert_metadata_snapshot_mapping(target_transition UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    transition_row chat.transitions%ROWTYPE;
    snapshot_row chat.metadata_snapshots%ROWTYPE;
    prior_snapshot chat.metadata_snapshots%ROWTYPE;
    snapshot_count BIGINT;
    requires_snapshot BOOLEAN;
BEGIN
    SELECT * INTO transition_row
      FROM chat.transitions
     WHERE transition_id = target_transition;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.metadata_snapshots
             WHERE producing_transition_id = target_transition
        ) THEN
            RAISE EXCEPTION 'metadata snapshot transition mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = transition_row.conversation_id
     FOR UPDATE;
    requires_snapshot := transition_row.kind IN (
        'creation','commit','metadata','leafRecovery','leaveCommit','resetActivation'
    );
    SELECT count(*) INTO snapshot_count
      FROM chat.metadata_snapshots
     WHERE producing_transition_id = target_transition;

    IF NOT requires_snapshot THEN
        IF snapshot_count <> 0 OR transition_row.metadata_snapshot_id IS NOT NULL THEN
            RAISE EXCEPTION 'transition unexpectedly carries metadata snapshot'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT * INTO snapshot_row
      FROM chat.metadata_snapshots
     WHERE producing_transition_id = target_transition;
    IF snapshot_count <> 1 OR NOT FOUND
       OR transition_row.metadata_snapshot_id IS DISTINCT FROM snapshot_row.metadata_snapshot_id
       OR snapshot_row.conversation_id <> transition_row.conversation_id
       OR snapshot_row.generation <> transition_row.next_generation
       OR snapshot_row.state_version <> transition_row.next_state_version
       OR snapshot_row.created_at <> transition_row.accepted_at THEN
        RAISE EXCEPTION 'metadata snapshot transition mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM chat.transitions origin
          JOIN chat.devices device
            ON device.user_did = origin.actor_did
           AND device.device_id = origin.actor_device_id
           AND device.created_at <= origin.accepted_at
           AND (device.revoked_at IS NULL OR device.revoked_at >= origin.accepted_at)
         WHERE origin.transition_id = snapshot_row.origin_transition_id
           AND origin.conversation_id = snapshot_row.conversation_id
           AND origin.entry_seq = snapshot_row.author_origin_seq
           AND origin.actor_did = snapshot_row.author_did
           AND origin.actor_device_id = snapshot_row.author_device_id
           AND origin.actor_key_id = snapshot_row.author_key_id
           AND origin.actor_auth_generation = snapshot_row.author_auth_generation
           AND origin.actor_role = snapshot_row.author_role
           AND origin.actor_role = 'admin'
           AND origin.actor_device_status = snapshot_row.author_device_status
           AND origin.actor_device_status = 'active'
           AND origin.kind IN ('creation','metadata','resetActivation')
    ) THEN
        RAISE EXCEPTION 'metadata author proof mismatch'
            USING ERRCODE = '23514';
    END IF;

    IF transition_row.kind = 'creation' THEN
        IF snapshot_row.metadata_version <> 1
           OR snapshot_row.origin_transition_id <> target_transition
           OR (snapshot_row.avatar_blob_id IS NOT NULL AND (
                snapshot_row.avatar_binding_origin_transition_id <> target_transition
                OR snapshot_row.avatar_binding_metadata_version <> 1
                OR snapshot_row.avatar_binding_owner_did <> snapshot_row.author_did
                OR snapshot_row.avatar_binding_owner_device_id <> snapshot_row.author_device_id
           ))
           OR (snapshot_row.author_did, snapshot_row.author_device_id,
               snapshot_row.author_key_id, snapshot_row.author_auth_generation)
              IS DISTINCT FROM
              (transition_row.actor_did, transition_row.actor_device_id,
               transition_row.actor_key_id, transition_row.actor_auth_generation) THEN
            RAISE EXCEPTION 'creation metadata snapshot mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    SELECT snapshot.* INTO prior_snapshot
      FROM chat.metadata_snapshots snapshot
      JOIN chat.transitions producer
        ON producer.transition_id = snapshot.producing_transition_id
     WHERE snapshot.conversation_id = transition_row.conversation_id
       AND snapshot.generation = transition_row.prior_generation
       AND producer.entry_seq < transition_row.entry_seq
     ORDER BY producer.entry_seq DESC
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'metadata predecessor snapshot missing'
            USING ERRCODE = '23514';
    END IF;

    IF transition_row.kind = 'metadata' THEN
        IF snapshot_row.metadata_version <> prior_snapshot.metadata_version + 1
           OR snapshot_row.origin_transition_id <> target_transition
           OR (
                snapshot_row.avatar_blob_id IS NOT DISTINCT FROM prior_snapshot.avatar_blob_id
                AND (snapshot_row.avatar_binding_origin_transition_id,
                     snapshot_row.avatar_binding_metadata_version,
                     snapshot_row.avatar_binding_owner_did,
                     snapshot_row.avatar_binding_owner_device_id)
                    IS DISTINCT FROM
                    (prior_snapshot.avatar_binding_origin_transition_id,
                     prior_snapshot.avatar_binding_metadata_version,
                     prior_snapshot.avatar_binding_owner_did,
                     prior_snapshot.avatar_binding_owner_device_id)
           )
           OR (
                snapshot_row.avatar_blob_id IS DISTINCT FROM prior_snapshot.avatar_blob_id
                AND snapshot_row.avatar_blob_id IS NOT NULL
                AND (snapshot_row.avatar_binding_origin_transition_id,
                     snapshot_row.avatar_binding_metadata_version,
                     snapshot_row.avatar_binding_owner_did,
                     snapshot_row.avatar_binding_owner_device_id)
                    IS DISTINCT FROM
                    (target_transition, snapshot_row.metadata_version,
                     snapshot_row.author_did, snapshot_row.author_device_id)
           )
           OR (snapshot_row.author_did, snapshot_row.author_device_id,
               snapshot_row.author_key_id, snapshot_row.author_auth_generation)
              IS DISTINCT FROM
              (transition_row.actor_did, transition_row.actor_device_id,
               transition_row.actor_key_id, transition_row.actor_auth_generation) THEN
            RAISE EXCEPTION 'metadata update version or author mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind IN ('commit','leafRecovery','leaveCommit') THEN
        IF (snapshot_row.metadata_version, snapshot_row.origin_transition_id,
            snapshot_row.ciphertext_size,
            snapshot_row.avatar_blob_id, snapshot_row.avatar_ciphertext_sha256,
            snapshot_row.avatar_ciphertext_size, snapshot_row.avatar_purpose,
            snapshot_row.avatar_binding_origin_transition_id,
            snapshot_row.avatar_binding_metadata_version,
            snapshot_row.avatar_binding_owner_did,
            snapshot_row.avatar_binding_owner_device_id,
            snapshot_row.author_did, snapshot_row.author_device_id,
            snapshot_row.author_key_id, snapshot_row.author_public_key,
            snapshot_row.author_auth_generation, snapshot_row.author_origin_seq,
            snapshot_row.author_role, snapshot_row.author_device_status)
           IS DISTINCT FROM
           (prior_snapshot.metadata_version, prior_snapshot.origin_transition_id,
            prior_snapshot.ciphertext_size,
            prior_snapshot.avatar_blob_id, prior_snapshot.avatar_ciphertext_sha256,
            prior_snapshot.avatar_ciphertext_size, prior_snapshot.avatar_purpose,
            prior_snapshot.avatar_binding_origin_transition_id,
            prior_snapshot.avatar_binding_metadata_version,
            prior_snapshot.avatar_binding_owner_did,
            prior_snapshot.avatar_binding_owner_device_id,
            prior_snapshot.author_did, prior_snapshot.author_device_id,
            prior_snapshot.author_key_id, prior_snapshot.author_public_key,
            prior_snapshot.author_auth_generation, prior_snapshot.author_origin_seq,
            prior_snapshot.author_role, prior_snapshot.author_device_status) THEN
            RAISE EXCEPTION 'epoch transition metadata provenance mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF transition_row.kind = 'resetActivation' THEN
        IF NOT (
            (snapshot_row.metadata_version, snapshot_row.origin_transition_id,
             snapshot_row.ciphertext_size,
             snapshot_row.avatar_blob_id, snapshot_row.avatar_ciphertext_sha256,
             snapshot_row.avatar_ciphertext_size, snapshot_row.avatar_purpose,
             snapshot_row.avatar_binding_origin_transition_id,
             snapshot_row.avatar_binding_metadata_version,
             snapshot_row.avatar_binding_owner_did,
             snapshot_row.avatar_binding_owner_device_id,
             snapshot_row.author_did, snapshot_row.author_device_id,
             snapshot_row.author_key_id, snapshot_row.author_public_key,
             snapshot_row.author_auth_generation, snapshot_row.author_origin_seq,
             snapshot_row.author_role, snapshot_row.author_device_status)
            IS NOT DISTINCT FROM
            (prior_snapshot.metadata_version, prior_snapshot.origin_transition_id,
             prior_snapshot.ciphertext_size,
             prior_snapshot.avatar_blob_id, prior_snapshot.avatar_ciphertext_sha256,
             prior_snapshot.avatar_ciphertext_size, prior_snapshot.avatar_purpose,
             prior_snapshot.avatar_binding_origin_transition_id,
             prior_snapshot.avatar_binding_metadata_version,
             prior_snapshot.avatar_binding_owner_did,
             prior_snapshot.avatar_binding_owner_device_id,
             prior_snapshot.author_did, prior_snapshot.author_device_id,
             prior_snapshot.author_key_id, prior_snapshot.author_public_key,
             prior_snapshot.author_auth_generation, prior_snapshot.author_origin_seq,
             prior_snapshot.author_role, prior_snapshot.author_device_status)
            OR (
                snapshot_row.metadata_version = prior_snapshot.metadata_version + 1
                AND snapshot_row.origin_transition_id = target_transition
                AND snapshot_row.avatar_blob_id IS NULL
                AND snapshot_row.author_did = transition_row.actor_did
                AND snapshot_row.author_device_id = transition_row.actor_device_id
                AND snapshot_row.author_key_id = transition_row.actor_key_id
                AND snapshot_row.author_auth_generation = transition_row.actor_auth_generation
            )
        ) THEN
            RAISE EXCEPTION 'reset metadata snapshot mismatch'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_metadata_snapshot_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    linked_transition UUID;
BEGIN
    IF TG_TABLE_NAME = 'transitions' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_metadata_snapshot_mapping(OLD.transition_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_metadata_snapshot_mapping(NEW.transition_id);
        END IF;
    ELSIF TG_TABLE_NAME = 'metadata_snapshots' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM chat.assert_metadata_snapshot_mapping(OLD.producing_transition_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM chat.assert_metadata_snapshot_mapping(NEW.producing_transition_id);
        END IF;
    ELSIF TG_TABLE_NAME = 'participants' THEN
        FOR linked_transition IN
            SELECT DISTINCT snapshot.producing_transition_id
              FROM chat.metadata_snapshots snapshot
             WHERE snapshot.conversation_id IN (OLD.conversation_id, NEW.conversation_id)
               AND snapshot.author_did IN (OLD.user_did, NEW.user_did)
        LOOP
            PERFORM chat.assert_metadata_snapshot_mapping(linked_transition);
        END LOOP;
    ELSE
        FOR linked_transition IN
            SELECT DISTINCT snapshot.producing_transition_id
              FROM chat.metadata_snapshots snapshot
             WHERE (snapshot.author_did, snapshot.author_device_id)
                   IN ((OLD.user_did, OLD.device_id), (NEW.user_did, NEW.device_id))
        LOOP
            PERFORM chat.assert_metadata_snapshot_mapping(linked_transition);
        END LOOP;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER transitions_metadata_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.transitions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_metadata_snapshot_mapping();

CREATE CONSTRAINT TRIGGER metadata_snapshots_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.metadata_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_metadata_snapshot_mapping();

CREATE CONSTRAINT TRIGGER participants_metadata_authority_deferred
AFTER UPDATE OR DELETE ON chat.participants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_metadata_snapshot_mapping();

CREATE CONSTRAINT TRIGGER devices_metadata_authority_deferred
AFTER UPDATE OR DELETE ON chat.devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_metadata_snapshot_mapping();

CREATE FUNCTION chat.enforce_active_device_limit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_did TEXT;
    active_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_did := OLD.user_did;
    ELSE
        target_did := NEW.user_did;
    END IF;
    PERFORM 1 FROM chat.principals WHERE user_did = target_did FOR UPDATE;
    SELECT count(*) INTO active_count
      FROM chat.devices
     WHERE user_did = target_did AND status = 'active';
    IF active_count > 20 THEN
        RAISE EXCEPTION 'active device limit exceeded' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER devices_active_limit_deferred
AFTER INSERT OR UPDATE OF user_did, status ON chat.devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_active_device_limit();

CREATE FUNCTION chat.enforce_live_key_package_limit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    live_count BIGINT;
BEGIN
    PERFORM 1 FROM chat.devices
     WHERE user_did = NEW.owner_did AND device_id = NEW.owner_device_id
     FOR UPDATE;
    SELECT count(*) INTO live_count
      FROM chat.key_packages
     WHERE owner_did = NEW.owner_did
       AND owner_device_id = NEW.owner_device_id
       AND status IN ('available','reserved');
    IF live_count > 1000 THEN
        RAISE EXCEPTION 'live key package limit exceeded' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER key_packages_live_limit_deferred
AFTER INSERT OR UPDATE OF status ON chat.key_packages
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_live_key_package_limit();

CREATE FUNCTION chat.enforce_invitation_quota()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    pair_live_count BIGINT;
    inviter_recent_count BIGINT;
    recipient_live_count BIGINT;
BEGIN
    -- Only newly created live pending invitations consume invitation quota. A
    -- live pending invitation is (current_membership AND status = 'pending').
    -- Acceptance (pending -> active), removal, or close can only release live
    -- counts, never add, so no UPDATE path needs to be guarded here.
    IF NOT (NEW.current_membership AND NEW.status = 'pending') THEN
        RETURN NEW;
    END IF;

    -- Serialize concurrent invitation inserts against the inviter and recipient
    -- principals so the deferred counts below are race-free (mirrors the
    -- FOR UPDATE parent-lock pattern used by the device/key-package limits).
    -- Locking in canonical DID order keeps acquisition deterministic and
    -- deadlock-free when two transactions touch the same DIDs in opposite roles.
    PERFORM 1 FROM chat.principals
     WHERE user_did IN (NEW.created_by_did, NEW.user_did)
     ORDER BY user_did
     FOR UPDATE;

    -- Limit 1: at most 5 live pending invitations per (inviterDid, recipientDid)
    -- pair, across all conversations.
    SELECT count(*) INTO pair_live_count
      FROM chat.participants
     WHERE created_by_did = NEW.created_by_did
       AND user_did = NEW.user_did
       AND current_membership
       AND status = 'pending';
    IF pair_live_count > 5 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 5 live pending invitations per (inviter, recipient) pair'
            USING ERRCODE = '23514';
    END IF;

    -- Limit 2: at most 100 newly created pending invitations per inviter in a
    -- rolling 24 hours. This is a creation-rate cap, so it counts every
    -- invitation row this inviter created in the window regardless of current
    -- status (acceptance or removal does not refund the daily creation budget).
    SELECT count(*) INTO inviter_recent_count
      FROM chat.participants
     WHERE created_by_did = NEW.created_by_did
       AND invitation_transition_id IS NOT NULL
       AND created_at >= now() - INTERVAL '24 hours';
    IF inviter_recent_count > 100 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 100 newly created pending invitations per inviter per rolling 24h'
            USING ERRCODE = '23514';
    END IF;

    -- Limit 3: at most 100 live pending invitations per recipient, across all
    -- conversations.
    SELECT count(*) INTO recipient_live_count
      FROM chat.participants
     WHERE user_did = NEW.user_did
       AND current_membership
       AND status = 'pending';
    IF recipient_live_count > 100 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 100 live pending invitations per recipient'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER participants_invitation_quota_deferred
AFTER INSERT ON chat.participants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_invitation_quota();

CREATE FUNCTION chat.enforce_conversation_pointer_agreement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    conversation_lifecycle TEXT;
    target_generation BIGINT;
    target_state_version BIGINT;
    active_generations BIGINT;
    maximum_generation BIGINT;
    pointed_generation_lifecycle TEXT;
    pointed_state_lifecycle TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN target_conversation := OLD.conversation_id;
    ELSE target_conversation := NEW.conversation_id;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT c.lifecycle, c.current_generation, c.current_state_version
      INTO conversation_lifecycle, target_generation, target_state_version
      FROM chat.conversations c
     WHERE c.conversation_id = target_conversation;
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    SELECT count(*) INTO active_generations
      FROM chat.generations g
     WHERE g.conversation_id = target_conversation AND g.lifecycle = 'active';
    SELECT max(generation) INTO maximum_generation
      FROM chat.generations
     WHERE conversation_id = target_conversation;
    SELECT g.lifecycle, s.lifecycle
      INTO pointed_generation_lifecycle, pointed_state_lifecycle
      FROM chat.generations g
      JOIN chat.generation_states s
        ON s.conversation_id = g.conversation_id
       AND s.generation = g.generation
       AND s.state_version = g.current_state_version
     WHERE g.conversation_id = target_conversation
       AND g.generation = target_generation
       AND s.state_version = target_state_version;
    IF conversation_lifecycle = 'active' THEN
        IF active_generations <> 1
           OR target_generation IS DISTINCT FROM maximum_generation
           OR pointed_generation_lifecycle IS DISTINCT FROM 'active'
           OR pointed_state_lifecycle IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'active conversation pointer disagreement' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF active_generations <> 0
           OR target_generation IS DISTINCT FROM maximum_generation
           OR pointed_state_lifecycle IS DISTINCT FROM 'superseded' THEN
            RAISE EXCEPTION 'terminal conversation pointer disagreement' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER conversation_pointer_agreement_deferred
AFTER INSERT OR UPDATE OF lifecycle, current_generation, current_state_version ON chat.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_pointer_agreement();

CREATE CONSTRAINT TRIGGER conversation_pointer_generation_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.generations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_pointer_agreement();

CREATE CONSTRAINT TRIGGER conversation_pointer_state_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.generation_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_conversation_pointer_agreement();

CREATE FUNCTION chat.enforce_generation_pointer_agreement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    target_generation BIGINT;
    generation_lifecycle TEXT;
    generation_current_state_version BIGINT;
    maximum_state_version BIGINT;
    pointed_lifecycle TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_conversation := OLD.conversation_id;
        target_generation := OLD.generation;
    ELSE
        target_conversation := NEW.conversation_id;
        target_generation := NEW.generation;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT g.lifecycle, g.current_state_version
      INTO generation_lifecycle, generation_current_state_version
      FROM chat.generations g
     WHERE g.conversation_id = target_conversation AND g.generation = target_generation;
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    SELECT s.lifecycle INTO pointed_lifecycle
      FROM chat.generation_states s
     WHERE s.conversation_id = target_conversation
       AND s.generation = target_generation
       AND s.state_version = generation_current_state_version;
    SELECT max(state_version) INTO maximum_state_version
      FROM chat.generation_states
     WHERE conversation_id = target_conversation
       AND generation = target_generation;
    IF pointed_lifecycle IS DISTINCT FROM generation_lifecycle
       OR generation_current_state_version IS DISTINCT FROM maximum_state_version THEN
        RAISE EXCEPTION 'generation pointer disagreement' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER generation_pointer_agreement_deferred
AFTER INSERT OR UPDATE OF lifecycle, current_state_version ON chat.generations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_generation_pointer_agreement();

CREATE CONSTRAINT TRIGGER generation_pointer_state_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.generation_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_generation_pointer_agreement();

CREATE FUNCTION chat.enforce_roster_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    conversation_kind TEXT;
    conversation_lifecycle TEXT;
    direct_did_low TEXT;
    direct_did_high TEXT;
    current_count BIGINT;
    active_admin_count BIGINT;
    invalid_pending_count BIGINT;
    pending_with_leaf_count BIGINT;
    invalid_direct_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN target_conversation := OLD.conversation_id;
    ELSE target_conversation := NEW.conversation_id;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT kind, lifecycle, c.direct_did_low, c.direct_did_high
      INTO conversation_kind, conversation_lifecycle, direct_did_low, direct_did_high
      FROM chat.conversations c WHERE c.conversation_id = target_conversation;
    SELECT count(*),
           count(*) FILTER (WHERE status = 'active' AND role = 'admin'),
           count(*) FILTER (WHERE status = 'pending' AND (
               (conversation_kind = 'group' AND role <> 'member')
               OR (conversation_kind = 'direct' AND role <> 'admin')
           ))
      INTO current_count, active_admin_count, invalid_pending_count
      FROM chat.participants
     WHERE conversation_id = target_conversation AND current_membership;
    SELECT count(*) INTO pending_with_leaf_count
      FROM chat.participants p
     WHERE p.conversation_id = target_conversation
       AND p.current_membership
       AND p.status = 'pending'
       AND EXISTS (
           SELECT 1 FROM chat.member_devices m
           WHERE m.participant_period_id = p.participant_period_id AND m.active
       );
    SELECT count(*) INTO invalid_direct_count
      FROM chat.participants participant
     WHERE participant.conversation_id = target_conversation
       AND participant.current_membership
       AND conversation_kind = 'direct'
       AND (participant.user_did NOT IN (direct_did_low, direct_did_high)
            OR participant.role <> 'admin');
    IF conversation_lifecycle = 'active' THEN
        IF current_count < 1 OR current_count > 100 OR active_admin_count < 1
           OR invalid_pending_count <> 0 OR pending_with_leaf_count <> 0
           OR (conversation_kind = 'direct'
               AND (current_count <> 2 OR invalid_direct_count <> 0)) THEN
            RAISE EXCEPTION 'logical roster invariant violated' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER participants_roster_invariants_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.participants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_roster_invariants();

CREATE CONSTRAINT TRIGGER participants_roster_leaf_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.member_devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_roster_invariants();

CREATE CONSTRAINT TRIGGER participants_roster_conversation_deferred
AFTER INSERT OR UPDATE OF kind, lifecycle ON chat.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_roster_invariants();

CREATE FUNCTION chat.assert_leaf_invariants(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_lifecycle TEXT;
    current_generation BIGINT;
    active_leaf_count BIGINT;
    expected_leaf_count BIGINT;
    stale_active_leaf_count BIGINT;
    invalid_owner_count BIGINT;
    over_limit_dids BIGINT;
BEGIN
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT lifecycle, c.current_generation
      INTO conversation_lifecycle, current_generation
      FROM chat.conversations c WHERE c.conversation_id = target_conversation;
    SELECT s.leaf_count INTO expected_leaf_count
      FROM chat.conversations c
      JOIN chat.generation_states s
        ON s.conversation_id = c.conversation_id
       AND s.generation = c.current_generation
       AND s.state_version = c.current_state_version
     WHERE c.conversation_id = target_conversation;
    SELECT count(*) INTO active_leaf_count
      FROM chat.member_devices
     WHERE conversation_id = target_conversation
       AND generation = current_generation
       AND active;
    SELECT count(*) INTO stale_active_leaf_count
      FROM chat.member_devices
     WHERE conversation_id = target_conversation
       AND generation <> current_generation
       AND active;
    SELECT count(*) INTO invalid_owner_count
      FROM chat.member_devices m
      LEFT JOIN chat.participants p
        ON p.participant_period_id = m.participant_period_id
       AND p.conversation_id = m.conversation_id
     WHERE m.conversation_id = target_conversation
       AND m.generation = current_generation
       AND m.active
       AND (p.status IS DISTINCT FROM 'active' OR NOT p.current_membership
            OR p.user_did IS DISTINCT FROM m.user_did);
    SELECT count(*) INTO over_limit_dids FROM (
        SELECT user_did
          FROM chat.member_devices
         WHERE conversation_id = target_conversation
           AND generation = current_generation AND active
         GROUP BY user_did HAVING count(*) > 20
    ) limits;
    IF conversation_lifecycle = 'active'
       AND (active_leaf_count < 1 OR active_leaf_count > 100
            OR active_leaf_count IS DISTINCT FROM expected_leaf_count
            OR stale_active_leaf_count <> 0
            OR invalid_owner_count <> 0 OR over_limit_dids <> 0) THEN
        RAISE EXCEPTION 'MLS leaf invariant violated' USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_leaf_invariants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
BEGIN
    IF TG_TABLE_NAME = 'devices' THEN
        FOR target_conversation IN
            SELECT DISTINCT m.conversation_id
              FROM chat.member_devices m
             WHERE (m.user_did, m.device_id) = (OLD.user_did, OLD.device_id)
                OR (TG_OP <> 'DELETE'
                    AND (m.user_did, m.device_id) = (NEW.user_did, NEW.device_id))
             ORDER BY m.conversation_id
        LOOP
            PERFORM chat.assert_leaf_invariants(target_conversation);
        END LOOP;
    ELSE
        IF TG_OP = 'DELETE' THEN target_conversation := OLD.conversation_id;
        ELSE target_conversation := NEW.conversation_id;
        END IF;
        PERFORM chat.assert_leaf_invariants(target_conversation);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER member_devices_leaf_invariants_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.member_devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_leaf_invariants();

CREATE CONSTRAINT TRIGGER member_devices_participant_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.participants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_leaf_invariants();

CREATE CONSTRAINT TRIGGER member_devices_device_deferred
AFTER UPDATE OF user_did, status OR DELETE ON chat.devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_leaf_invariants();

CREATE CONSTRAINT TRIGGER member_devices_state_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.generation_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_leaf_invariants();

CREATE CONSTRAINT TRIGGER member_devices_conversation_deferred
AFTER INSERT OR UPDATE OF lifecycle, current_generation, current_state_version ON chat.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_leaf_invariants();

CREATE FUNCTION chat.assert_device_revocation_mapping(target_revocation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    revocation_row chat.device_revocations%ROWTYPE;
    target_key_count BIGINT;
BEGIN
    SELECT * INTO revocation_row
      FROM chat.device_revocations
     WHERE revocation_id = target_revocation;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.devices WHERE revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.device_keys WHERE revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.key_packages WHERE terminal_revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.key_package_reservations
             WHERE terminal_revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.leaf_recovery_requests
             WHERE terminal_revocation_id = target_revocation
        ) THEN
            RAISE EXCEPTION 'device revocation provenance is missing'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.principals
     WHERE user_did = revocation_row.target_did
     FOR UPDATE;

    SELECT count(*) INTO target_key_count
      FROM chat.device_keys
     WHERE user_did = revocation_row.target_did
       AND device_id = revocation_row.target_device_id;

    IF target_key_count <> 1
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices target
             WHERE target.user_did = revocation_row.target_did
               AND target.device_id = revocation_row.target_device_id
               AND target.status = 'revoked'
               AND target.auth_generation = revocation_row.target_auth_generation
               AND target.revocation_id = revocation_row.revocation_id
               AND target.revoked_at = revocation_row.accepted_at
               AND target.updated_at = revocation_row.accepted_at
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.device_keys target_key
             WHERE target_key.user_did = revocation_row.target_did
               AND target_key.device_id = revocation_row.target_device_id
               AND target_key.revocation_id = revocation_row.revocation_id
               AND target_key.revoked_at = revocation_row.accepted_at
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices actor
              JOIN chat.device_keys actor_key
                ON actor_key.user_did = actor.user_did
               AND actor_key.device_id = actor.device_id
               AND actor_key.key_id = revocation_row.actor_key_id
             WHERE actor.user_did = revocation_row.actor_did
               AND actor.device_id = revocation_row.actor_device_id
               AND actor.auth_generation = revocation_row.actor_auth_generation
               AND actor.created_at <= revocation_row.accepted_at
               AND (actor.revoked_at IS NULL
                    OR actor.revoked_at >= revocation_row.accepted_at)
               AND actor_key.created_at <= revocation_row.accepted_at
               AND (actor_key.revoked_at IS NULL
                    OR actor_key.revoked_at >= revocation_row.accepted_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.idempotency_records receipt
             WHERE receipt.principal_did = revocation_row.actor_did
               AND receipt.endpoint_nsid = 'blue.catbird.chat.revokeDevice'
               AND receipt.operation_id = revocation_row.revocation_id
               AND receipt.request_digest = revocation_row.request_digest
               AND receipt.accepted_request_bytes = revocation_row.accepted_request_bytes
               AND receipt.signing_transcript_bytes = revocation_row.signing_transcript_bytes
               AND receipt.signature = revocation_row.signature
               AND receipt.completed_status BETWEEN 200 AND 299
               AND receipt.completed_at = revocation_row.accepted_at
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_packages package
             WHERE package.owner_did = revocation_row.target_did
               AND package.owner_device_id = revocation_row.target_device_id
               AND package.status IN ('available','reserved')
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_packages package
             WHERE package.terminal_revocation_id = revocation_row.revocation_id
               AND (package.owner_did, package.owner_device_id, package.status,
                    package.terminal_at)
                   IS DISTINCT FROM
                   (revocation_row.target_did, revocation_row.target_device_id,
                    'revoked'::TEXT, revocation_row.accepted_at)
       )
       OR EXISTS (
            SELECT 1 FROM chat.leaf_recovery_requests request
             WHERE request.requester_did = revocation_row.target_did
               AND request.requester_device_id = revocation_row.target_device_id
               AND request.status = 'open'
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_package_reservations reservation
             WHERE reservation.recipient_did = revocation_row.target_did
               AND reservation.recipient_device_id = revocation_row.target_device_id
               AND reservation.status = 'active'
       ) THEN
        RAISE EXCEPTION 'device revocation terminal mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE FUNCTION chat.enforce_device_revocation_mapping()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_revocation UUID;
    new_revocation UUID;
BEGIN
    IF TG_TABLE_NAME = 'device_revocations' THEN
        IF TG_OP <> 'INSERT' THEN old_revocation := OLD.revocation_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_revocation := NEW.revocation_id; END IF;
    ELSIF TG_TABLE_NAME IN ('devices','device_keys') THEN
        IF TG_OP <> 'INSERT' THEN old_revocation := OLD.revocation_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_revocation := NEW.revocation_id; END IF;
    ELSIF TG_TABLE_NAME IN (
        'key_packages','key_package_reservations','leaf_recovery_requests'
    ) THEN
        IF TG_OP <> 'INSERT' THEN old_revocation := OLD.terminal_revocation_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_revocation := NEW.terminal_revocation_id; END IF;
    ELSE
        IF TG_OP <> 'INSERT'
           AND OLD.endpoint_nsid = 'blue.catbird.chat.revokeDevice' THEN
            old_revocation := OLD.operation_id;
        END IF;
        IF TG_OP <> 'DELETE'
           AND NEW.endpoint_nsid = 'blue.catbird.chat.revokeDevice' THEN
            new_revocation := NEW.operation_id;
        END IF;
    END IF;

    IF old_revocation IS NOT NULL THEN
        PERFORM chat.assert_device_revocation_mapping(old_revocation);
    END IF;
    IF new_revocation IS NOT NULL AND new_revocation IS DISTINCT FROM old_revocation THEN
        PERFORM chat.assert_device_revocation_mapping(new_revocation);
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER device_revocations_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.device_revocations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER devices_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.devices
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER device_keys_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.device_keys
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER key_packages_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.key_packages
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER key_package_reservations_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.key_package_reservations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER leaf_recovery_requests_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.leaf_recovery_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE CONSTRAINT TRIGGER idempotency_records_revocation_mapping_deferred
AFTER INSERT OR UPDATE OR DELETE ON chat.idempotency_records
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_revocation_mapping();

CREATE TRIGGER protocol_instances_immutable
BEFORE UPDATE OR DELETE ON chat.protocol_instances
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER principals_immutable
BEFORE UPDATE OR DELETE ON chat.principals
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER devices_identity_immutable
BEFORE UPDATE OR DELETE ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'device_name', 'status', 'dpop_jkt', 'auth_generation', 'capabilities',
    'updated_at', 'revoked_at', 'revocation_id'
);

CREATE TRIGGER devices_lifecycle_monotonic
BEFORE UPDATE ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER device_keys_identity_immutable
BEFORE UPDATE OR DELETE ON chat.device_keys
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('revoked_at', 'revocation_id');

CREATE TRIGGER device_keys_lifecycle_monotonic
BEFORE UPDATE ON chat.device_keys
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER device_revocations_immutable
BEFORE UPDATE OR DELETE ON chat.device_revocations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER dpop_replays_immutable
BEFORE UPDATE OR DELETE ON chat.dpop_replays
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER idempotency_records_immutable
BEFORE UPDATE OR DELETE ON chat.idempotency_records
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER key_packages_identity_immutable
BEFORE UPDATE OR DELETE ON chat.key_packages
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at'
);

CREATE TRIGGER key_packages_lifecycle_monotonic
BEFORE UPDATE ON chat.key_packages
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER conversations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle', 'current_generation', 'current_state_version', 'next_entry_seq',
    'close_transition_id', 'close_generation', 'close_state_version', 'close_seq',
    'closed_at'
);

CREATE TRIGGER conversations_lifecycle_monotonic
BEFORE UPDATE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER generations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.generations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle', 'current_state_version', 'superseded_seq', 'superseded_at'
);

CREATE TRIGGER generations_lifecycle_monotonic
BEFORE UPDATE ON chat.generations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER generation_states_immutable
BEFORE UPDATE OR DELETE ON chat.generation_states
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER participants_identity_immutable
BEFORE UPDATE OR DELETE ON chat.participants
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'role', 'role_transition_id', 'role_changed_at',
    'acceptance_transition_id', 'acceptance_entry_id', 'accepted_at',
    'removing_transition_id', 'removing_seq', 'removed_at', 'current_membership'
);

CREATE TRIGGER participants_lifecycle_monotonic
BEFORE UPDATE ON chat.participants
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER member_devices_identity_immutable
BEFORE UPDATE OR DELETE ON chat.member_devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'removed_state_version', 'removed_transition_id', 'removed_seq', 'removed_at', 'active'
);

CREATE TRIGGER member_devices_lifecycle_monotonic
BEFORE UPDATE ON chat.member_devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER metadata_snapshots_immutable
BEFORE UPDATE OR DELETE ON chat.metadata_snapshots
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER key_package_reservations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.key_package_reservations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'consumed_transition_id', 'terminal_transition_id',
    'terminal_revocation_id', 'terminal_request_digest', 'terminal_at'
);

CREATE TRIGGER key_package_reservations_lifecycle_monotonic
BEFORE UPDATE ON chat.key_package_reservations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER reset_requests_identity_immutable
BEFORE UPDATE OR DELETE ON chat.reset_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_transition_id', 'terminal_at'
);

CREATE TRIGGER reset_requests_lifecycle_monotonic
BEFORE UPDATE ON chat.reset_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER leaf_recovery_requests_identity_immutable
BEFORE UPDATE OR DELETE ON chat.leaf_recovery_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'fulfilling_transition_id', 'terminal_transition_id',
    'terminal_revocation_id', 'terminal_signed_request_bytes',
    'terminal_signing_transcript_bytes', 'terminal_request_digest',
    'terminal_signature', 'terminal_at'
);

CREATE TRIGGER leaf_recovery_requests_lifecycle_monotonic
BEFORE UPDATE ON chat.leaf_recovery_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER leave_requests_identity_immutable
BEFORE UPDATE OR DELETE ON chat.leave_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'status', 'terminal_request_digest', 'terminal_transition_id', 'terminal_at'
);

CREATE TRIGGER leave_requests_lifecycle_monotonic
BEFORE UPDATE ON chat.leave_requests
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER relationship_projection_revision_allocations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.relationship_projection_revision_allocations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'consumed_projection_id', 'consumed_at'
);

CREATE TRIGGER relationship_projection_allocations_lifecycle_monotonic
BEFORE UPDATE ON chat.relationship_projection_revision_allocations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_core_lifecycle_transition();

CREATE TRIGGER relationship_projection_snapshots_immutable
BEFORE UPDATE OR DELETE ON chat.relationship_projection_snapshots
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER relationship_projection_relationships_immutable
BEFORE UPDATE OR DELETE ON chat.relationship_projection_relationships
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER relationship_projection_declarations_immutable
BEFORE UPDATE OR DELETE ON chat.relationship_projection_declarations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE TRIGGER transitions_immutable
BEFORE UPDATE OR DELETE ON chat.transitions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Request admission remains disabled until the separately reviewed HTTP/auth
-- compositor is enabled. Ordinary packages do not acquire request authority.
ALTER TABLE chat.key_packages ADD COLUMN IF NOT EXISTS usage_scope TEXT NOT NULL DEFAULT 'recovery';
ALTER TABLE chat.key_packages ADD CONSTRAINT key_packages_usage_scope_check
    CHECK (usage_scope IN ('recovery','direct-request'));
ALTER TABLE chat.key_packages ADD CONSTRAINT key_packages_request_identity_uq
    UNIQUE (key_package_ref,owner_did,owner_device_id,owner_key_id,owner_auth_generation,usage_scope);

CREATE TABLE IF NOT EXISTS chat.direct_request_capabilities (
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1),
    revision BIGINT NOT NULL CHECK (chat.is_safe_integer(revision) AND revision >= 1),
    enabled BOOLEAN NOT NULL,
    protocol_version TEXT NOT NULL CHECK (protocol_version = '2'),
    signed_publication BYTEA NOT NULL CHECK (octet_length(signed_publication) > 0),
    publication_digest BYTEA NOT NULL CHECK (octet_length(publication_digest) = 32),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did,owner_device_id),
    FOREIGN KEY (owner_did,owner_device_id,owner_key_id)
        REFERENCES chat.device_keys(user_did,device_id,key_id)
);

CREATE TABLE IF NOT EXISTS chat.direct_request_grants (
    grant_id UUID PRIMARY KEY CHECK (chat.is_uuid_v4(grant_id)),
    revision BIGINT NOT NULL CHECK (chat.is_safe_integer(revision) AND revision >= 1),
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1),
    capability_revision BIGINT NOT NULL CHECK (chat.is_safe_integer(capability_revision) AND capability_revision >= 1),
    key_package_ref BYTEA NOT NULL UNIQUE,
    usage_scope TEXT NOT NULL DEFAULT 'direct-request' CHECK (usage_scope = 'direct-request'),
    purpose TEXT NOT NULL CHECK (purpose = 'direct-request-bootstrap'),
    protocol_version TEXT NOT NULL CHECK (protocol_version = '2'),
    profile TEXT NOT NULL,
    signed_grant BYTEA NOT NULL CHECK (octet_length(signed_grant) > 0),
    grant_digest BYTEA NOT NULL CHECK (octet_length(grant_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    FOREIGN KEY (key_package_ref,owner_did,owner_device_id,owner_key_id,auth_generation,usage_scope)
        REFERENCES chat.key_packages(key_package_ref,owner_did,owner_device_id,owner_key_id,owner_auth_generation,usage_scope)
);

-- Tombstones have no TTL and no cascading foreign keys. Cancellation of an
-- unknown request records the exact signed prepare digest before any lease.
CREATE TABLE IF NOT EXISTS chat.direct_request_attempts (
    request_id UUID PRIMARY KEY CHECK (chat.is_uuid_v4(request_id)),
    actor_did TEXT NOT NULL CHECK (chat.is_bare_did(actor_did)),
    actor_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(actor_device_id)),
    actor_key_id TEXT NOT NULL CHECK (chat.is_base64url_sha256(actor_key_id)),
    actor_auth_generation BIGINT NOT NULL CHECK (chat.is_safe_integer(actor_auth_generation) AND actor_auth_generation >= 1),
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did) AND recipient_did <> actor_did),
    prepare_digest BYTEA NOT NULL CHECK (octet_length(prepare_digest) = 32),
    status TEXT NOT NULL CHECK (status IN ('prepared','published','cancelled','expired','rejected','existing-direct')),
    prepare_response BYTEA,
    selected_digest BYTEA CHECK (octet_length(selected_digest) = 32),
    prepared_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    terminal_response BYTEA,
    terminal_response_sha256 BYTEA,
    publication_digest BYTEA CHECK (octet_length(publication_digest) = 32),
    reserved_bytes BIGINT NOT NULL DEFAULT 0 CHECK (reserved_bytes BETWEEN 0 AND 8388608),
    created_at TIMESTAMPTZ NOT NULL,
    CHECK ((status = 'prepared' AND terminal_at IS NULL AND terminal_response IS NULL AND terminal_response_sha256 IS NULL)
        OR (status <> 'prepared' AND terminal_at IS NOT NULL AND octet_length(terminal_response) > 0
            AND octet_length(terminal_response_sha256) = 32
            AND terminal_response_sha256 = digest(terminal_response,'sha256'))),
    CHECK ((prepared_at IS NULL AND prepare_response IS NULL AND selected_digest IS NULL AND lease_expires_at IS NULL)
        OR (prepared_at IS NOT NULL AND octet_length(prepare_response) > 0 AND selected_digest IS NOT NULL
            AND lease_expires_at > prepared_at AND lease_expires_at <= prepared_at + INTERVAL '300 seconds')),
    CHECK (status <> 'prepared' OR prepared_at IS NOT NULL),
    CHECK (status <> 'published' OR publication_digest IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS direct_request_attempts_sender_idx ON chat.direct_request_attempts(actor_did,created_at);
CREATE INDEX IF NOT EXISTS direct_request_attempts_recipient_idx ON chat.direct_request_attempts(recipient_did) WHERE status='prepared';

CREATE TABLE IF NOT EXISTS chat.direct_request_selected_devices (
    request_id UUID NOT NULL REFERENCES chat.direct_request_attempts(request_id),
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    grant_id UUID NOT NULL REFERENCES chat.direct_request_grants(grant_id),
    grant_digest BYTEA NOT NULL CHECK (octet_length(grant_digest)=32),
    capability_revision BIGINT NOT NULL,
    key_package_ref BYTEA NOT NULL UNIQUE REFERENCES chat.key_packages(key_package_ref),
    PRIMARY KEY(request_id,owner_did,owner_device_id)
);

-- Serialize byte-budget admission before principal/device/key locks. Accounts
-- are charged the complete bundle independently; terminal bytes remain charged
-- against retained capacity until a separately authorized history policy acts.
CREATE TABLE IF NOT EXISTS chat.direct_request_budget (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    pending_bytes BIGINT NOT NULL DEFAULT 0 CHECK(pending_bytes BETWEEN 0 AND 1073741824),
    retained_bytes BIGINT NOT NULL DEFAULT 0 CHECK(retained_bytes BETWEEN 0 AND 8589934592)
);
INSERT INTO chat.direct_request_budget(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;

CREATE FUNCTION chat.preserve_direct_request_attempt() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'direct request tombstones cannot be deleted'; END IF;
    IF OLD.status <> 'prepared' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal direct request receipt is immutable';
    END IF;
    IF ROW(NEW.request_id,NEW.actor_did,NEW.actor_device_id,NEW.actor_key_id,NEW.actor_auth_generation,
           NEW.recipient_did,NEW.prepare_digest,NEW.prepare_response,NEW.selected_digest,NEW.prepared_at,
           NEW.lease_expires_at,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.request_id,OLD.actor_did,OLD.actor_device_id,OLD.actor_key_id,OLD.actor_auth_generation,
           OLD.recipient_did,OLD.prepare_digest,OLD.prepare_response,OLD.selected_digest,OLD.prepared_at,
           OLD.lease_expires_at,OLD.created_at) THEN
        RAISE EXCEPTION 'direct request identity and selection are immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER preserve_direct_request_attempt BEFORE UPDATE OR DELETE ON chat.direct_request_attempts
    FOR EACH ROW EXECUTE FUNCTION chat.preserve_direct_request_attempt();

CREATE FUNCTION chat.preserve_direct_request_selection() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'direct request device selection is immutable'; END $$;
CREATE TRIGGER preserve_direct_request_selection BEFORE UPDATE OR DELETE ON chat.direct_request_selected_devices
    FOR EACH ROW EXECUTE FUNCTION chat.preserve_direct_request_selection();

CREATE TABLE IF NOT EXISTS chat.direct_request_key_publications (
    operation_id UUID PRIMARY KEY CHECK(chat.is_uuid_v4(operation_id)),
    owner_did TEXT NOT NULL,
    owner_device_id UUID NOT NULL,
    owner_key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    request_digest BYTEA NOT NULL CHECK(octet_length(request_digest)=32),
    accepted_request BYTEA NOT NULL CHECK(octet_length(accepted_request)>0),
    response_bytes BYTEA NOT NULL CHECK(octet_length(response_bytes)>0),
    response_sha256 BYTEA NOT NULL CHECK(response_sha256=digest(response_bytes,'sha256')),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(owner_did,owner_device_id,revision),
    FOREIGN KEY(owner_did,owner_device_id,owner_key_id) REFERENCES chat.device_keys(user_did,device_id,key_id)
);
CREATE TRIGGER direct_request_key_publications_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_key_publications
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_grants_identity_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_grants
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('revoked_at');
CREATE FUNCTION chat.monotonic_direct_request_grant_revocation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'request grant revocation is irreversible';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER direct_request_grants_revocation_monotonic BEFORE UPDATE ON chat.direct_request_grants
    FOR EACH ROW EXECUTE FUNCTION chat.monotonic_direct_request_grant_revocation();

-- V2 uses fingerprint-derived immutable key methods, leaving the v1 fixed
-- receipt method untouched. Retain historical public keys for exact replay.
CREATE TABLE IF NOT EXISTS chat.direct_request_receipt_keys (
    key_id TEXT PRIMARY KEY,
    authority_did TEXT NOT NULL CHECK(authority_did='did:web:chat.catbird.blue'),
    public_key BYTEA NOT NULL UNIQUE CHECK(octet_length(public_key)=33),
    created_at TIMESTAMPTZ NOT NULL,
    CHECK(key_id='did:web:chat.catbird.blue#chat-request-receipt-' || encode(digest(public_key,'sha256'),'hex'))
);
CREATE TRIGGER direct_request_receipt_keys_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_receipt_keys
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE FUNCTION chat.enforce_direct_request_pool_limit() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE available_count BIGINT;
BEGIN
    IF NEW.usage_scope='direct-request' AND NEW.status='available' THEN
        PERFORM 1 FROM chat.devices WHERE user_did=NEW.owner_did AND device_id=NEW.owner_device_id FOR UPDATE;
        SELECT count(*) INTO available_count FROM chat.key_packages
         WHERE owner_did=NEW.owner_did AND owner_device_id=NEW.owner_device_id
           AND usage_scope='direct-request' AND status='available';
        IF available_count>128 THEN RAISE EXCEPTION 'request package pool limit exceeded' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_pool_limit AFTER INSERT OR UPDATE ON chat.key_packages
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.enforce_direct_request_pool_limit();

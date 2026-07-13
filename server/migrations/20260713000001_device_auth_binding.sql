-- ADR-016 device-auth foundation. This migration is intentionally observe-only:
-- no existing endpoint requires a device binding until consumers are enrolled.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS dpop_jkt TEXT,
    ADD COLUMN IF NOT EXISTS auth_bound_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS auth_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS chk_devices_dpop_jkt;
ALTER TABLE devices
    ADD CONSTRAINT chk_devices_dpop_jkt CHECK (
        dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'
    );

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS chk_devices_auth_binding_consistent;
ALTER TABLE devices
    ADD CONSTRAINT chk_devices_auth_binding_consistent CHECK (
        (dpop_jkt IS NULL AND auth_bound_at IS NULL)
        OR (dpop_jkt IS NOT NULL AND auth_bound_at IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS idx_devices_active_auth_binding
    ON devices(user_did, device_id, dpop_jkt, auth_generation)
    WHERE active AND dpop_jkt IS NOT NULL;

CREATE OR REPLACE FUNCTION invalidate_device_auth_on_identity_change()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.signature_public_key IS DISTINCT FROM OLD.signature_public_key
       OR (OLD.active AND NOT NEW.active) THEN
        NEW.dpop_jkt := NULL;
        NEW.auth_bound_at := NULL;
        NEW.auth_generation := OLD.auth_generation + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_invalidate_device_auth_on_identity_change ON devices;
CREATE TRIGGER trg_invalidate_device_auth_on_identity_change
BEFORE UPDATE OF signature_public_key, active ON devices
FOR EACH ROW EXECUTE FUNCTION invalidate_device_auth_on_identity_change();

CREATE TABLE IF NOT EXISTS device_auth_binding_challenges (
    id UUID PRIMARY KEY,
    version SMALLINT NOT NULL DEFAULT 1 CHECK (version = 1),
    user_did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    dpop_jkt TEXT NOT NULL CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_did, device_id) REFERENCES devices(user_did, device_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_auth_challenges_expiry
    ON device_auth_binding_challenges(expires_at)
    WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_device_auth_challenges_device
    ON device_auth_binding_challenges(user_did, device_id);

CREATE TABLE IF NOT EXISTS device_auth_dpop_replay (
    dpop_jkt TEXT NOT NULL CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    replay_id TEXT NOT NULL CHECK (length(replay_id) BETWEEN 16 AND 200),
    method TEXT NOT NULL,
    uri_hash BYTEA NOT NULL CHECK (octet_length(uri_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dpop_jkt, replay_id)
);

CREATE INDEX IF NOT EXISTS idx_device_auth_dpop_replay_expiry
    ON device_auth_dpop_replay(expires_at);

COMMENT ON COLUMN devices.dpop_jkt IS
    'RFC 7638 thumbprint of the currently authorized session DPoP key.';
COMMENT ON COLUMN devices.auth_generation IS
    'Monotonic binding generation. Rebinding or revocation invalidates previously resolved authority.';

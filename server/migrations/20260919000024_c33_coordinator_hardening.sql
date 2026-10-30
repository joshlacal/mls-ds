-- 20260919000024_c33_coordinator_hardening.sql
-- C33 Federation Security Hardening:
-- 1. Immutable (request_id, owner_device_id) lease identity across all statuses
-- 2. Durable coordinator reservation intent before remote RPC
-- 3. Staged remote reservation package bindings for exact request-bound selection
-- 4. Retain coordinator_endpoint in direct_request_outbound_routes

-- 1. Enforce uniqueness of (request_id, owner_device_id) across all statuses
CREATE UNIQUE INDEX IF NOT EXISTS direct_request_remote_leases_request_device_all_idx
    ON chat.direct_request_remote_leases (request_id, owner_device_id);

-- 2. Durable coordinator intent table before remote reservation RPC
CREATE TABLE IF NOT EXISTS chat.direct_request_reservation_intents (
    request_id UUID PRIMARY KEY CHECK (chat.is_uuid_v4(request_id)),
    actor_did TEXT NOT NULL CHECK (chat.is_bare_did(actor_did)),
    actor_device_id UUID,
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did)),
    recipient_ds_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_ds_did)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE chat.direct_request_reservation_intents
    ADD COLUMN IF NOT EXISTS actor_device_id UUID;

-- 3. Exact request-bound reserved remote packages staged on coordinator
CREATE TABLE IF NOT EXISTS chat.direct_request_reserved_remote_packages (
    request_id UUID NOT NULL CHECK (chat.is_uuid_v4(request_id)),
    owner_did TEXT NOT NULL CHECK (chat.is_bare_did(owner_did)),
    owner_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(owner_device_id)),
    key_package_ref BYTEA NOT NULL REFERENCES chat.key_packages(key_package_ref) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (request_id, owner_device_id, key_package_ref)
);

CREATE INDEX IF NOT EXISTS direct_request_reserved_remote_packages_req_idx
    ON chat.direct_request_reserved_remote_packages (request_id);

-- 4. Preserve coordinator_endpoint on sender-home routes
ALTER TABLE chat.direct_request_outbound_routes
    ADD COLUMN IF NOT EXISTS coordinator_endpoint TEXT;
-- 5. Record sender_device_id, sender_signing_key, and prepare_digest on remote leases for authenticated reconciliation and commit-time proof
ALTER TABLE chat.direct_request_remote_leases
    ADD COLUMN IF NOT EXISTS sender_device_id UUID,
    ADD COLUMN IF NOT EXISTS sender_signing_key BYTEA,
    ADD COLUMN IF NOT EXISTS prepare_digest BYTEA;

-- Migration: Labyrinth 1.1 storage backend, part 1 — personal mailboxes and
-- the independent epoch-head directory (labyrinth docs/MLSDS_BACKEND.md §1a,
-- §2 "Mailbox"/"Directory", §4).
--
-- Everything lives in its own `labyrinth` schema. Rows are immutable through
-- the shared chat.enforce_immutable_identity(mutable_columns...) helper, which
-- blocks DELETE outright and admits UPDATE only of the named columns. Quotas
-- (design Y6) are CHECK constraints on counter rows, so a write that would
-- exceed one fails with SQLSTATE 23514 naming the quota constraint.

CREATE SCHEMA IF NOT EXISTS labyrinth;

-- One counter row per mailbox owner (design Y6: 256 MiB, 4096 epochs,
-- 64 virtual devices). next_owner_seq stamps owner batches (serverOrder.seq).
CREATE TABLE labyrinth.mailboxes (
    owner_did TEXT PRIMARY KEY,
    bytes_used BIGINT NOT NULL DEFAULT 0,
    record_count BIGINT NOT NULL DEFAULT 0,
    epoch_count BIGINT NOT NULL DEFAULT 0,
    vdevice_count BIGINT NOT NULL DEFAULT 0,
    next_owner_seq BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT mailboxes_owner_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT mailboxes_bytes_quota CHECK (bytes_used BETWEEN 0 AND 268435456),
    CONSTRAINT mailboxes_epoch_quota CHECK (epoch_count BETWEEN 0 AND 4096),
    CONSTRAINT mailboxes_vdevice_quota CHECK (vdevice_count BETWEEN 0 AND 64),
    CONSTRAINT mailboxes_record_count_check CHECK (record_count >= 0),
    CONSTRAINT mailboxes_next_owner_seq_check CHECK (
        next_owner_seq >= 1 AND chat.is_safe_integer(next_owner_seq)
    )
);

CREATE TRIGGER mailboxes_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.mailboxes
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'bytes_used', 'record_count', 'epoch_count', 'vdevice_count', 'next_owner_seq'
);

-- `device` records, rkey = hex(deviceKeyPubkey). Only revoked_at may change,
-- and only once (NULL -> value).
CREATE TABLE labyrinth.devices (
    owner_did TEXT NOT NULL REFERENCES labyrinth.mailboxes(owner_did),
    device_key BYTEA NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    is_virtual BOOLEAN NOT NULL,
    revoked_at TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, device_key),
    CONSTRAINT devices_device_key_check CHECK (octet_length(device_key) = 32),
    CONSTRAINT devices_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 4096),
    CONSTRAINT devices_revoked_at_check CHECK (
        revoked_at IS NULL OR octet_length(revoked_at) BETWEEN 1 AND 64
    )
);

CREATE TRIGGER devices_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('revoked_at');

CREATE FUNCTION labyrinth.devices_revoked_at_set_once()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL
       AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'labyrinth device revokedAt is set once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER devices_revoked_at_set_once
BEFORE UPDATE ON labyrinth.devices
FOR EACH ROW EXECUTE FUNCTION labyrinth.devices_revoked_at_set_once();

-- `epoch` records. epoch_id is the backend-assigned epochID ([CB-9]); the
-- UNIQUE (owner_did, epoch_number) is the createEpoch race guard.
CREATE TABLE labyrinth.epochs (
    epoch_id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES labyrinth.mailboxes(owner_did),
    epoch_number BIGINT NOT NULL,
    epoch_head BYTEA NOT NULL,
    previous_epoch_head BYTEA,
    opened_by BYTEA NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT epochs_owner_number_uq UNIQUE (owner_did, epoch_number),
    CONSTRAINT epochs_epoch_number_check CHECK (epoch_number BETWEEN 0 AND 1099511627776),
    CONSTRAINT epochs_head_check CHECK (octet_length(epoch_head) = 32),
    CONSTRAINT epochs_previous_head_check CHECK (
        (epoch_number = 0 AND previous_epoch_head IS NULL)
        OR (epoch_number > 0 AND octet_length(previous_epoch_head) = 32)
    ),
    CONSTRAINT epochs_opened_by_check CHECK (octet_length(opened_by) = 32),
    CONSTRAINT epochs_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 16384)
);

CREATE TRIGGER epochs_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.epochs
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- `epochMember` records, rkey = <12-digit epoch>-<hex deviceKeyPubkey>.
CREATE TABLE labyrinth.epoch_members (
    owner_did TEXT NOT NULL,
    epoch_number BIGINT NOT NULL,
    device_key BYTEA NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, epoch_number, device_key),
    CONSTRAINT epoch_members_epoch_fk FOREIGN KEY (owner_did, epoch_number)
        REFERENCES labyrinth.epochs(owner_did, epoch_number),
    CONSTRAINT epoch_members_device_key_check CHECK (octet_length(device_key) = 32),
    CONSTRAINT epoch_members_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 4096)
);

CREATE TRIGGER epoch_members_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.epoch_members
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- `virtualDevice` records (recovery bundles), rkey = hex(vdeviceId).
CREATE TABLE labyrinth.virtual_devices (
    owner_did TEXT NOT NULL REFERENCES labyrinth.mailboxes(owner_did),
    vdevice_id BYTEA NOT NULL,
    device_key BYTEA NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, vdevice_id),
    CONSTRAINT virtual_devices_id_check CHECK (octet_length(vdevice_id) = 16),
    CONSTRAINT virtual_devices_device_key_check CHECK (octet_length(device_key) = 32),
    CONSTRAINT virtual_devices_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 16384)
);

CREATE TRIGGER virtual_devices_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.virtual_devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- `ownerBatch` records, rkey = server TID. seq is the per-mailbox serverOrder
-- stamp; owner batches carry no chatSeq.
CREATE TABLE labyrinth.owner_batches (
    owner_did TEXT NOT NULL REFERENCES labyrinth.mailboxes(owner_did),
    rkey TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    min_ts BIGINT NOT NULL,
    max_ts BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    record JSONB NOT NULL,
    record_bytes INTEGER NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, rkey),
    CONSTRAINT owner_batches_seq_uq UNIQUE (owner_did, seq),
    CONSTRAINT owner_batches_rkey_check CHECK (rkey ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'),
    CONSTRAINT owner_batches_thread_id_check CHECK (octet_length(thread_id) BETWEEN 1 AND 256),
    CONSTRAINT owner_batches_ts_check CHECK (min_ts >= 0 AND max_ts >= min_ts),
    CONSTRAINT owner_batches_seq_check CHECK (seq >= 1 AND chat.is_safe_integer(seq)),
    CONSTRAINT owner_batches_record_bytes_check CHECK (record_bytes BETWEEN 1 AND 1048576)
);

CREATE INDEX owner_batches_thread_idx
    ON labyrinth.owner_batches (owner_did, thread_id, seq);

CREATE TRIGGER owner_batches_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.owner_batches
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- The independent head directory ([CB-29], [CB-28]): one row per
-- (did, epochNumber), append-only and contiguous from 0. The attesting key
-- must be an MLS chat device key (checked live at insert by the server).
CREATE TABLE labyrinth.epoch_heads (
    did TEXT NOT NULL,
    epoch_number BIGINT NOT NULL,
    epoch_head BYTEA NOT NULL,
    previous_epoch_head BYTEA,
    epoch_public JSONB NOT NULL,
    epoch_public_bytes INTEGER NOT NULL,
    attestation_key_id TEXT NOT NULL REFERENCES chat.device_keys(key_id),
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (did, epoch_number),
    CONSTRAINT epoch_heads_did_check CHECK (chat.is_bare_did(did)),
    CONSTRAINT epoch_heads_epoch_number_check CHECK (epoch_number BETWEEN 0 AND 1099511627776),
    CONSTRAINT epoch_heads_head_check CHECK (octet_length(epoch_head) = 32),
    CONSTRAINT epoch_heads_previous_head_check CHECK (
        (epoch_number = 0 AND previous_epoch_head IS NULL)
        OR (epoch_number > 0 AND octet_length(previous_epoch_head) = 32)
    ),
    CONSTRAINT epoch_heads_bytes_check CHECK (epoch_public_bytes BETWEEN 1 AND 8192)
);

CREATE TRIGGER epoch_heads_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.epoch_heads
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- Write idempotency (design §3): a procedure retried with the same
-- operationId and payload replays the stored response bytes; the same
-- operationId with a different payload is refused.
CREATE TABLE labyrinth.operations (
    owner_did TEXT NOT NULL,
    operation_id BYTEA NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    actor_device_id UUID NOT NULL,
    response BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_did, operation_id),
    CONSTRAINT operations_did_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT operations_id_check CHECK (octet_length(operation_id) = 16),
    CONSTRAINT operations_nsid_check CHECK (endpoint_nsid LIKE 'blue.catbird.labyrinth.%'),
    CONSTRAINT operations_payload_sha256_check CHECK (octet_length(payload_sha256) = 32),
    CONSTRAINT operations_response_check CHECK (octet_length(response) BETWEEN 2 AND 65536)
);

CREATE TRIGGER operations_identity_immutable
BEFORE UPDATE OR DELETE ON labyrinth.operations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

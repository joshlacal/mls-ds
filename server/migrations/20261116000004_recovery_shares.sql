-- Erasable Labyrinth recovery shares. The row itself becomes a permanent
-- tombstone; deleting or purging clears every secret-bearing column. A
-- separately mounted, append-only journal is the authority after DB restore.

CREATE TABLE labyrinth.recovery_shares (
    owner_did TEXT NOT NULL,
    vdevice_id BYTEA NOT NULL,
    mechanism TEXT NOT NULL,
    encrypted_share BYTEA,
    nonce BYTEA,
    kek_key_id TEXT,
    fetch_verifier BYTEA,
    created_by_device_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    last_fetched_at TIMESTAMPTZ,
    fetch_count BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (owner_did, vdevice_id),
    CONSTRAINT recovery_shares_owner_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT recovery_shares_vid_check CHECK (octet_length(vdevice_id) = 16),
    CONSTRAINT recovery_shares_mechanism_check CHECK (mechanism IN ('code', 'passkey')),
    CONSTRAINT recovery_shares_fetch_count_check CHECK (fetch_count BETWEEN 0 AND 9007199254740991),
    CONSTRAINT recovery_shares_times_check CHECK (
        (verified_at IS NULL OR verified_at >= created_at)
        AND (last_fetched_at IS NULL OR last_fetched_at >= created_at)
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    CONSTRAINT recovery_shares_live_or_erased_check CHECK (
        (deleted_at IS NULL
            AND encrypted_share IS NOT NULL AND nonce IS NOT NULL
            AND kek_key_id IS NOT NULL AND fetch_verifier IS NOT NULL
            AND octet_length(encrypted_share) = 48
            AND octet_length(nonce) = 12
            AND octet_length(kek_key_id) BETWEEN 1 AND 64
            AND octet_length(fetch_verifier) = 32)
        OR (deleted_at IS NOT NULL
            AND encrypted_share IS NULL AND nonce IS NULL AND kek_key_id IS NULL
            AND fetch_verifier IS NULL)
    )
);

CREATE INDEX recovery_shares_live_owner_idx
    ON labyrinth.recovery_shares (owner_did, vdevice_id)
    WHERE deleted_at IS NULL;

CREATE FUNCTION labyrinth.recovery_share_update_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'recovery share tombstones cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF OLD.deleted_at IS NOT NULL
       OR NEW.owner_did IS DISTINCT FROM OLD.owner_did
       OR NEW.vdevice_id IS DISTINCT FROM OLD.vdevice_id
       OR NEW.mechanism IS DISTINCT FROM OLD.mechanism
       OR NEW.created_by_device_id IS DISTINCT FROM OLD.created_by_device_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at)
       OR NEW.fetch_count < OLD.fetch_count
       OR (OLD.last_fetched_at IS NOT NULL AND (
           NEW.last_fetched_at IS NULL OR NEW.last_fetched_at < OLD.last_fetched_at))
       OR (NEW.deleted_at IS NULL AND (
           NEW.encrypted_share IS DISTINCT FROM OLD.encrypted_share
           OR NEW.nonce IS DISTINCT FROM OLD.nonce
           OR NEW.kek_key_id IS DISTINCT FROM OLD.kek_key_id
           OR NEW.fetch_verifier IS DISTINCT FROM OLD.fetch_verifier))
    THEN
        RAISE EXCEPTION 'recovery share identity or erasure cannot be reversed'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER recovery_share_update_guard
BEFORE UPDATE OR DELETE ON labyrinth.recovery_shares
FOR EACH ROW EXECUTE FUNCTION labyrinth.recovery_share_update_guard();

CREATE TABLE labyrinth.recovery_share_events (
    id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL,
    vdevice_id BYTEA NOT NULL,
    kind TEXT NOT NULL,
    actor_device_id UUID,
    at TIMESTAMPTZ NOT NULL,
    CONSTRAINT recovery_share_events_owner_check CHECK (chat.is_bare_did(owner_did)),
    CONSTRAINT recovery_share_events_vid_check CHECK (octet_length(vdevice_id) = 16),
    CONSTRAINT recovery_share_events_kind_check CHECK (
        kind IN ('put', 'verify', 'fetch', 'fetchDenied', 'delete', 'purge'))
);

CREATE INDEX recovery_share_events_owner_id_idx
    ON labyrinth.recovery_share_events (owner_did, id);
CREATE INDEX recovery_share_events_write_budget_idx
    ON labyrinth.recovery_share_events (owner_did, actor_device_id, at)
    WHERE kind = 'put';

CREATE TRIGGER recovery_share_events_immutable
BEFORE UPDATE OR DELETE ON labyrinth.recovery_share_events
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

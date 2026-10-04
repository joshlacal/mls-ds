-- An expired remote lease can still back a committed introduction. Hold its
-- package until the coordinator explicitly releases it or delivers the Welcome.
CREATE OR REPLACE FUNCTION chat.enforce_direct_request_remote_leases_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'remote lease rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.lease_id <> OLD.lease_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.key_package_ref <> OLD.key_package_ref
       OR NEW.owner_device_id <> OLD.owner_device_id
       OR NEW.leased_at <> OLD.leased_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'remote lease immutable columns cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF OLD.status NOT IN ('active', 'expired') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal remote lease status is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'expired' AND NEW.status NOT IN ('expired', 'finalized', 'released') THEN
        RAISE EXCEPTION 'expired remote lease can only be released or finalized' USING ERRCODE = '23514';
    END IF;
    IF OLD.finalized_at IS NOT NULL AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at THEN
        RAISE EXCEPTION 'finalized_at is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
        RAISE EXCEPTION 'released_at is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- Retain the sender's authenticated route before an uncertain coordinator RPC.
-- A request ID alone is insufficient to discover the remote coordinator on replay.
CREATE TABLE IF NOT EXISTS chat.direct_request_outbound_routes (
    request_id UUID PRIMARY KEY CHECK (chat.is_uuid_v4(request_id)),
    actor_did TEXT NOT NULL CHECK (chat.is_bare_did(actor_did)),
    actor_device_id UUID NOT NULL CHECK (chat.is_uuid_v4(actor_device_id)),
    recipient_did TEXT NOT NULL CHECK (chat.is_bare_did(recipient_did) AND recipient_did <> actor_did),
    coordinator_did TEXT NOT NULL CHECK (chat.is_bare_did(coordinator_did)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX direct_request_outbound_routes_actor_recent
    ON chat.direct_request_outbound_routes(actor_did, created_at);

-- Who created each direct-request attempt this DS holds, so the
-- client-facing chat endpoints can tell the sender home's own attempts from
-- the ones it coordinates for a sender homed elsewhere.
--
-- No row: the sender's home created the attempt for its own user and
-- coordinates it. 'relayed': this DS coordinates it for a sender homed on
-- sender_home_did, and only that DS drives it, over mlsDS. 'local-refusal':
-- this DS signed a refusal as the sender's home because the recipient had no
-- authority it could join; a later retry reads the pair again.
CREATE TABLE IF NOT EXISTS chat.direct_request_attempt_origins (
    request_id UUID PRIMARY KEY
        REFERENCES chat.direct_request_attempts(request_id) ON DELETE CASCADE,
    origin TEXT NOT NULL CHECK (origin IN ('relayed', 'local-refusal')),
    sender_home_did TEXT NOT NULL CHECK (chat.is_bare_did(sender_home_did)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS reissue_requests (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    recipient_device_did TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ NULL,
    welcome_blob_id TEXT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reissue_requests_convo_recipient
    ON reissue_requests(convo_id, recipient_device_did, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_reissue_requests_pending
    ON reissue_requests(convo_id, requested_at DESC)
    WHERE responded_at IS NULL;

COMMENT ON TABLE reissue_requests IS
    'Phase B Welcome recovery: recipient devices request inviter/admin reissue of a Welcome without forcing External Commit recovery.';
COMMENT ON COLUMN reissue_requests.welcome_blob_id IS
    'Identifier of the replacement Welcome row/blob supplied by the inviter/admin responder.';

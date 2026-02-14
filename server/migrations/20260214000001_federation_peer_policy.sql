-- Federation peer trust policy and behavior telemetry

CREATE TABLE IF NOT EXISTS federation_peers (
    ds_did TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    trust_score INTEGER NOT NULL DEFAULT 0,
    max_requests_per_minute INTEGER,
    note TEXT,
    invalid_token_count BIGINT NOT NULL DEFAULT 0,
    rejected_request_count BIGINT NOT NULL DEFAULT 0,
    successful_request_count BIGINT NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT federation_peers_status_check CHECK (status IN ('pending', 'allow', 'suspend', 'block'))
);

CREATE INDEX IF NOT EXISTS idx_federation_peers_status ON federation_peers(status);
CREATE INDEX IF NOT EXISTS idx_federation_peers_last_seen ON federation_peers(last_seen_at DESC);

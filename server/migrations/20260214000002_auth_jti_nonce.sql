-- Shared replay-protection nonce store for DS service auth tokens.

CREATE TABLE IF NOT EXISTS auth_jti_nonce (
    issuer_did TEXT NOT NULL,
    jti TEXT NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer_did, jti)
);

CREATE INDEX IF NOT EXISTS idx_auth_jti_nonce_expires ON auth_jti_nonce(expires_at);

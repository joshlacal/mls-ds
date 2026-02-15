-- Fix idempotency_cache schema: add caller_did scoping to prevent cross-user cache collisions.
-- The old table used (key) as PK with no caller DID, so two different users sending the same
-- idempotency key to the same endpoint would share cached results.
-- This is ephemeral cache data, safe to drop and recreate.

DROP TABLE IF EXISTS idempotency_cache;

CREATE TABLE idempotency_cache (
    caller_did TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    key TEXT NOT NULL,
    response_body JSONB NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (caller_did, endpoint, key)
);

CREATE INDEX idx_idempotency_cache_expires ON idempotency_cache (expires_at);

COMMENT ON TABLE idempotency_cache IS 'Cache for idempotent API operations (24 hour retention), scoped per caller DID';

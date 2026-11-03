-- The clean-chat request baseline omits legacy public conversations. Supply
-- only the cache from 20251213000001_federation_support.sql, as C33 does, before
-- 20260824000002_chat_actor_ds_mapping.sql. Rust and faketime harnesses share it.
CREATE TABLE IF NOT EXISTS public.ds_endpoints (
    did TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    supported_cipher_suites TEXT,
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);
CREATE INDEX IF NOT EXISTS idx_ds_endpoints_expires ON public.ds_endpoints(expires_at);

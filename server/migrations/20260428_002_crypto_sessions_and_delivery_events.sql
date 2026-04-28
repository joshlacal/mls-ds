-- Phase 2 keystone migration: crypto_sessions + delivery_events
--
-- Introduces the dedicated MLS-generation table (`crypto_sessions`) and the
-- server's source-of-truth append-only log (`delivery_events`). Adds a
-- forward-pointer column to `conversations`, extends `pending_welcomes` so
-- welcomes are bound to a specific session generation, and backfills one
-- crypto_session row per existing conversation plus a backfill marker event
-- per session.
--
-- Idempotent — safe to re-run. Wrapped automatically in a single transaction
-- by sqlx::migrate! (see src/db.rs:74). Backfill statements use
-- ON CONFLICT DO NOTHING so a partial-completion re-run is a no-op.
--
-- Plan: docs/plans (let-me-look-at-abstract-castle.md), §Phase 2.1.
-- Locked decision #1: cleanup of legacy MLS columns on `conversations` is
-- gated on telemetry showing zero legacy fallback reads, NOT on this
-- migration. Read paths in `repositories/crypto_session.rs` will prefer the
-- new table and fall back to legacy columns during the compatibility window.
--
-- Note on column naming: the plan references a `recipient_did` column on
-- `pending_welcomes`; the actual schema (greenfield 20250101000000) uses
-- `target_did`. We index on `target_did`. No rename — that would churn
-- handlers for no protocol benefit.

-- =============================================================================
-- Required extensions. The greenfield schema already loads these (idempotent
-- on re-run), but we re-declare here so this migration is self-contained
-- when applied on databases that don't carry the greenfield baseline (e.g.
-- a partial test DB or one restored from a slimmer snapshot). The backfill
-- below depends on uuid_generate_v5() from uuid-ossp.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- crypto_sessions: one MLS group generation, server-side public metadata only.
-- =============================================================================

CREATE TABLE IF NOT EXISTS crypto_sessions (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    mls_group_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN (
        'pending',
        'active',
        'reset_requested',
        'superseding',
        'superseded',
        'failed',
        'archived'
    )),
    supersedes_id TEXT REFERENCES crypto_sessions(id),
    superseded_by_id TEXT REFERENCES crypto_sessions(id),
    cipher_suite TEXT,
    last_observed_epoch INTEGER NOT NULL DEFAULT 0,
    last_confirmation_tag BYTEA,
    group_info BYTEA,
    group_info_epoch INTEGER,
    group_info_updated_at TIMESTAMPTZ,
    created_by_did TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    UNIQUE (conversation_id, generation)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_crypto_sessions_one_active_per_convo
    ON crypto_sessions(conversation_id) WHERE state = 'active';

CREATE INDEX IF NOT EXISTS idx_crypto_sessions_conversation
    ON crypto_sessions(conversation_id);

COMMENT ON TABLE crypto_sessions IS
    'Phase 2: one MLS group generation per row. Server holds public observable metadata only — clients remain the cryptographic authority.';
COMMENT ON COLUMN crypto_sessions.id IS
    'Opaque session id (UUID v4). Stable identity even across reset; meaning lives in (conversation_id, generation).';
COMMENT ON COLUMN crypto_sessions.last_observed_epoch IS
    'Highest MLS epoch the server has observed an envelope for in this session. Server does not validate cryptographic correctness, only sequence linearization.';
COMMENT ON COLUMN crypto_sessions.supersedes_id IS
    'Back-reference on the new (winning) session row to the old session it supersedes. NULL for the original (generation 0) session.';
COMMENT ON COLUMN crypto_sessions.superseded_by_id IS
    'Forward pointer set on the old session when ActivateCryptoSession marks it superseded. Aids supersession-chain queries.';

-- =============================================================================
-- delivery_events: append-only log of envelopes the server has sequenced.
-- NOT cascade-deleted with conversations — lifecycle is via retention/purge,
-- not row deletion (Phase 3 will define the retention policy). Includes
-- provenance fields for future federation; populated as available, NULL
-- otherwise.
-- =============================================================================

CREATE TABLE IF NOT EXISTS delivery_events (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    seq BIGINT NOT NULL,
    crypto_session_id TEXT REFERENCES crypto_sessions(id),
    event_type TEXT NOT NULL,
    sender_did TEXT,
    sender_device_id TEXT,
    mls_group_id TEXT,
    mls_epoch BIGINT,
    idempotency_key TEXT,
    payload BYTEA,
    payload_json JSONB,
    origin_service_did TEXT,
    home_service_did TEXT,
    remote_event_id TEXT,
    auth_issuer_did TEXT,
    received_via TEXT,
    federation_trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (conversation_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_delivery_events_session
    ON delivery_events(crypto_session_id);
CREATE INDEX IF NOT EXISTS idx_delivery_events_emitted
    ON delivery_events(created_at);

-- Idempotency UNIQUE on (conversation_id, sender_did, sender_device_id,
-- idempotency_key) needs NULL-equality semantics: under a plain UNIQUE
-- constraint Postgres treats NULLs as distinct, so two rows with the
-- same idempotency_key but NULL sender_did/sender_device_id (the chokepoint
-- emit shape — see reset_chokepoint::insert_event) would NOT collide and
-- the retry-dedup contract would silently break. Use a partial unique
-- index over COALESCE-coerced columns instead, which gives NULL-aware
-- equality. The WHERE filter only enforces idempotency when the caller
-- actually supplies a key (idempotency_key IS NOT NULL); rows without
-- one bypass the constraint, matching the "best-effort dedupe" intent.
CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_events_idempotency
    ON delivery_events (
        conversation_id,
        COALESCE(sender_did, ''),
        COALESCE(sender_device_id, ''),
        idempotency_key
    )
    WHERE idempotency_key IS NOT NULL;

COMMENT ON TABLE delivery_events IS
    'Phase 2: server source-of-truth append-only log. Per-conversation seq is monotonic and gap-free within a single conversation. Lifecycle via retention, not cascade.';
COMMENT ON COLUMN delivery_events.seq IS
    'Per-conversation monotonic sequence number. Backfill seeds seq=0; first real event is seq=1 (matches fake-repo semantics post-backfill).';

-- =============================================================================
-- conversations.active_crypto_session_id pointer.
-- =============================================================================

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS active_crypto_session_id TEXT
        REFERENCES crypto_sessions(id);

CREATE INDEX IF NOT EXISTS idx_conversations_active_crypto_session
    ON conversations(active_crypto_session_id)
    WHERE active_crypto_session_id IS NOT NULL;

COMMENT ON COLUMN conversations.active_crypto_session_id IS
    'Phase 2 forward pointer to the conversation''s active crypto_sessions row. NULL only during the compatibility window before backfill OR for legacy rows that pre-date Phase 2 backfill (defensive read path emits mls_ds_legacy_crypto_session_fallback_total when it hits NULL).';

-- =============================================================================
-- pending_welcomes binding to a specific crypto_session + generation.
--
-- The plan references `recipient_did`; the live column is `target_did`. We
-- index on the live column. We also add `commit_event_id` so welcomes can
-- be linked to the delivery event that committed the membership change that
-- produced them.
-- =============================================================================

ALTER TABLE pending_welcomes
    ADD COLUMN IF NOT EXISTS crypto_session_id TEXT REFERENCES crypto_sessions(id),
    ADD COLUMN IF NOT EXISTS generation INTEGER,
    ADD COLUMN IF NOT EXISTS commit_event_id TEXT REFERENCES delivery_events(id),
    ADD COLUMN IF NOT EXISTS recipient_device_id TEXT,
    -- bug_009 (ultrareview): WelcomeEnvelope carries `key_package_hash`
    -- but the column was missing on pending_welcomes, so the binding
    -- was silently dropped. Currently masked by the legacy
    -- welcome_messages dual-write which DOES have the column; becomes
    -- data-loss when the legacy write is dropped. Hash is hex-encoded
    -- (TEXT) to match `key_packages.key_package_hash` and the chokepoint's
    -- WelcomeEnvelope shape.
    ADD COLUMN IF NOT EXISTS key_package_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_pending_welcomes_session
    ON pending_welcomes(crypto_session_id, target_did, recipient_device_id);

COMMENT ON COLUMN pending_welcomes.crypto_session_id IS
    'Phase 2: binds the welcome to a specific crypto_session generation. Welcomes for losing reset candidates are rejected on activation (reference to a `failed` row).';
COMMENT ON COLUMN pending_welcomes.recipient_device_id IS
    'Phase 2: device identifier for multi-device routing. Disambiguates pending welcomes for the same target_did across devices.';
COMMENT ON COLUMN pending_welcomes.key_package_hash IS
    'Phase 2 (bug_009): hex-encoded hash of the recipient device''s consumed key package. Required for the eventual replacement of welcome_messages with pending_welcomes as the canonical distribution table.';

-- =============================================================================
-- Backfill: one crypto_session per conversation, one delivery_event marker
-- per crypto_session, conversations.active_crypto_session_id pointer set.
-- =============================================================================
--
-- We allocate a deterministic UUID v5 from `(conversation_id, generation)`
-- so re-running the migration on the same data yields the same id, but
-- ON CONFLICT DO NOTHING guards against partial-completion re-runs anyway.
-- The namespace UUID below is a fixed constant for this migration only.

INSERT INTO crypto_sessions (
    id,
    conversation_id,
    generation,
    mls_group_id,
    state,
    cipher_suite,
    last_observed_epoch,
    last_confirmation_tag,
    group_info,
    group_info_epoch,
    group_info_updated_at,
    created_by_did,
    created_at,
    activated_at
)
SELECT
    uuid_generate_v5(
        '6a6c6f72-7973-7373-7373-737373737373'::uuid,
        c.id || ':' || COALESCE(c.reset_count, 0)::text
    )::text,
    c.id,
    COALESCE(c.reset_count, 0),
    c.group_id,
    'active',
    c.cipher_suite,
    c.current_epoch,
    c.confirmation_tag,
    c.group_info,
    c.group_info_epoch,
    c.group_info_updated_at,
    c.creator_did,
    c.created_at,
    c.created_at
FROM conversations c
WHERE NOT EXISTS (
    SELECT 1 FROM crypto_sessions cs
    WHERE cs.conversation_id = c.id
      AND cs.generation = COALESCE(c.reset_count, 0)
)
ON CONFLICT DO NOTHING;

UPDATE conversations c
SET active_crypto_session_id = cs.id
FROM crypto_sessions cs
WHERE cs.conversation_id = c.id
  AND cs.state = 'active'
  AND c.active_crypto_session_id IS NULL;

INSERT INTO delivery_events (
    id,
    conversation_id,
    seq,
    crypto_session_id,
    event_type,
    mls_group_id,
    mls_epoch,
    idempotency_key,
    created_at
)
SELECT
    uuid_generate_v5(
        '6a6c6f72-7973-7373-7373-737373737373'::uuid,
        'event:' || cs.id
    )::text,
    cs.conversation_id,
    0,
    cs.id,
    'crypto_session_created',
    cs.mls_group_id,
    cs.last_observed_epoch::bigint,
    'backfill:' || cs.id,
    cs.created_at
FROM crypto_sessions cs
WHERE NOT EXISTS (
    SELECT 1 FROM delivery_events de
    WHERE de.conversation_id = cs.conversation_id
      AND de.seq = 0
)
ON CONFLICT DO NOTHING;

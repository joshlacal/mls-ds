-- Phase 3: Durable outbox tables for federation + notifications
--
-- Replaces the in-memory `side_effect_tx` channel with crash-recoverable rows
-- so that fanout survives a server SIGKILL between `delivery_event` commit and
-- broadcast send. New worker tasks
-- (`workers/{federation_outbox,notification_outbox}.rs`) poll due rows,
-- dispatch, and transition status with exponential backoff.
--
-- Plan: docs/plans (let-me-look-at-abstract-castle.md), §Phase 3.
--
-- Idempotent — safe to re-run. Wrapped automatically in a single transaction
-- by sqlx::migrate! (see src/db.rs:74). All schema objects use IF NOT EXISTS.
--
-- Filename: 20260429000003 — next available 14-digit prefix after
-- 20260429000002 (key_package_state). Today is 2026-04-28; 20260429 prefixes
-- already exist, so we extend that day's sequence rather than starting a new
-- day-prefix that may collide with itself if a second migration ships today.

-- =============================================================================
-- federation_outbox: one row per remote-DS dispatch attempt for a delivery
-- event. Written in the SAME tx as the originating delivery_events INSERT
-- (chokepoint write site = reset_chokepoint::activate_crypto_session_tx and
-- request_crypto_session_reset_tx; future write sites = any handler that
-- appends a delivery_event for a federated conversation).
--
-- Lifecycle: pending → in_flight → done | failed | dead.
-- Workers transition rows under FOR UPDATE SKIP LOCKED to allow horizontal
-- scaling across replicas without double-dispatch.
-- =============================================================================

CREATE TABLE IF NOT EXISTS federation_outbox (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT NOT NULL REFERENCES delivery_events(id),
    target_service_did TEXT NOT NULL,
    payload BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('pending','in_flight','done','failed','dead')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot-path index used by the worker poll. Partial index on `status='pending'`
-- so the planner can range-scan only-due rows. The worker's claim query is
-- `WHERE status = 'pending' AND next_attempt_at <= NOW()`.
CREATE INDEX IF NOT EXISTS idx_federation_outbox_due
    ON federation_outbox(next_attempt_at) WHERE status = 'pending';

-- Secondary index for retry/dispatch by event id. Used by tests and ops
-- queries that ask "did this event get federated?".
CREATE INDEX IF NOT EXISTS idx_federation_outbox_event
    ON federation_outbox(delivery_event_id);

-- =============================================================================
-- notification_outbox: one row per recipient-channel notification queued for
-- a delivery event. Currently used as a durable shadow of the in-memory SSE
-- broadcast (kind='sse'); future kinds = 'push', 'websocket'.
--
-- Phase 3 SSE refactor: dual-writes both an in-memory broadcast (best-effort,
-- low latency for connected subscribers) AND a notification_outbox row
-- (durable; the worker drains it for reconnecting subscribers via the
-- existing event_stream/cursor backfill path). See PR body and
-- realtime/sse.rs comments for the design.
-- =============================================================================

CREATE TABLE IF NOT EXISTS notification_outbox (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT NOT NULL REFERENCES delivery_events(id),
    recipient_did TEXT NOT NULL,
    recipient_device_id TEXT,
    kind TEXT NOT NULL,
    payload BYTEA,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('pending','in_flight','done','failed','dead')),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_outbox_due
    ON notification_outbox(next_attempt_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_notification_outbox_event
    ON notification_outbox(delivery_event_id);

-- Secondary index for "events this recipient hasn't received yet" queries.
CREATE INDEX IF NOT EXISTS idx_notification_outbox_recipient
    ON notification_outbox(recipient_did, status);

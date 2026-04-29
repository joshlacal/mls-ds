-- Phase 2.5 §7 R3 — backstop reminder worker state.
--
-- Tracks the rebroadcast schedule for `crypto_session_reset_requested` events
-- when a reset is requested but no client is online to respond. The worker
-- (`server/src/jobs/reset_reminder.rs`) polls this table on an interval and
-- re-emits the SSE `resetRequestedEvent` + persists a fresh
-- `crypto_session_reset_requested` delivery_event row (with a distinct
-- `idempotency_key` so the existing dedupe partial-unique-index does not
-- collide) until either:
--   (a) a client activates the session (FK CASCADE-deletes the row), or
--   (b) `attempt_count` exceeds the bounded retry sequence (1h / 6h / 24h).
--
-- After exhaustion, `escalated_at` is stamped and the worker emits a
-- `tracing::error!` admin-alert log line; further ticks for the row are
-- a no-op until ops intervenes.
--
-- Plan: docs/plans (phase-2-5-indirect-funneling.md), §7 R3.
-- The row lifecycle is decoupled from `delivery_events`: the latter is
-- the append-only audit log; this table holds only the per-session
-- scheduling state for reminders. Idempotency on the broadcast side
-- comes from the `idempotency_key` shape `reset-reminder:{cs_id}:{n}`.
--
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS reset_reminder_state (
    crypto_session_id TEXT PRIMARY KEY
        REFERENCES crypto_sessions(id) ON DELETE CASCADE,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_attempt_at TIMESTAMPTZ,
    escalated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Worker query path: scan rows whose next attempt is due AND not yet
-- escalated. The partial index keeps the working set small even as the
-- table grows over time (escalated rows linger for forensic value but
-- are never re-scanned).
CREATE INDEX IF NOT EXISTS idx_reset_reminder_state_due
    ON reset_reminder_state (next_attempt_at)
    WHERE escalated_at IS NULL;

COMMENT ON TABLE reset_reminder_state IS
    'Phase 2.5 §7 R3: per-crypto_session backstop reminder schedule. One row per session in `reset_requested`; CASCADE-deletes when the session is removed. Worker filters on cs.state=reset_requested so superseded rows go inert without explicit cleanup.';
COMMENT ON COLUMN reset_reminder_state.attempt_count IS
    'Number of reminders broadcast so far. After 3 attempts (1h, 6h, 24h delays), escalated_at is set and the row stops being scanned.';
COMMENT ON COLUMN reset_reminder_state.next_attempt_at IS
    'When the next reminder should fire. Created at original-Request-time + 1h.';
COMMENT ON COLUMN reset_reminder_state.escalated_at IS
    'Set when attempt_count reaches the bounded retry limit. Operations should investigate; the conversation is stuck in reset_requested with no online responder.';

-- Phase 2 (auto-reset): commit-health tracking columns.
--
-- These columns feed two Phase-2 systems:
--   1. The commit_group_change handler instrumentation, which bumps
--      `recent_commit_409_count` + `last_commit_409_at` on every CAS-failure /
--      stale-wire-epoch 409 and zeroes the counter + sets
--      `last_successful_commit_at` on every accepted commit.
--   2. The server-side `auto_detect_failed_groups` sweep job (Stage 4),
--      which selects conversations whose 409 count is high while no
--      successful commit has landed for a long time (the "operationally
--      unrecoverable" signal we want to auto-reset).
--
-- The partial index speeds up the sweep query. We DROP `CONCURRENTLY`
-- intentionally — sqlx wraps every migration in a transaction (per
-- migrations/README.md) and `conversations` is small enough that a brief
-- AccessExclusive lock during the index build is acceptable.
--
-- Spec: docs/superpowers/specs/2026-04-26-mls-auto-reset-phase2-design.md
-- Plan: docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md (Stage 1, Task 1)

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS last_successful_commit_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS recent_commit_409_count   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_commit_409_at        TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_conversations_health_sweep
    ON conversations (last_commit_409_at, last_successful_commit_at)
    WHERE auto_reset_disabled_at IS NULL;

COMMENT ON COLUMN conversations.last_successful_commit_at IS
    'Phase 2: timestamp of the most recent commitGroupChange that successfully advanced current_epoch. Reset to NOW() on every accepted commit; consumed by the auto_detect_failed_groups sweep to identify silent-dead groups.';

COMMENT ON COLUMN conversations.recent_commit_409_count IS
    'Phase 2: rolling count of 409 (EpochMismatch / CAS-failure) responses from commitGroupChange. Bumped on every 409, zeroed on every successful commit. Sweep treats high values combined with stale last_successful_commit_at as a failure signal.';

COMMENT ON COLUMN conversations.last_commit_409_at IS
    'Phase 2: timestamp of the most recent 409 response from commitGroupChange. Used by the sweep to ensure 409s are recent (not just lifetime accumulation).';

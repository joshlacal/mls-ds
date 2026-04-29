-- Phase 2 (B10): GroupInfo-missing failure tracking columns.
--
-- The original Phase 2 sweep (`auto_detect_failed_groups`) keys off
-- `recent_commit_409_count`, which only increments when commitGroupChange
-- returns a 409 (CAS failure / stale wire-epoch). This catches the
-- "epoch race" failure mode beautifully but completely misses the
-- "GroupInfo missing" mode: a convo whose `group_info` is NULL on the
-- server (post-reset awaiting bootstrap, or never bootstrapped post-add)
-- never has commitGroupChange called against it — clients can't get past
-- `getGroupInfo → 404` in the External Commit pre-flight, so the 409
-- counter never moves and the sweep is blind.
--
-- These two columns add a parallel signal:
--   * `recent_groupinfo_404_count` — bumped by the get_group_state
--     handler whenever it would return GroupInfoUnavailable (Ok(None)
--     branch from `crate::group_info::get_group_info`). Zeroed inside
--     `do_reset_group` (post-reset state means future fetches are
--     "expected" 404s only until bootstrap lands).
--   * `last_groupinfo_404_at` — the same recency check pattern as the
--     409 columns, so the sweep can require "404s are CURRENT, not just
--     historical lifetime accumulation".
--
-- Index extension follows the same partial-index pattern as the 409
-- columns; the sweep query in `jobs::auto_detect_failed_groups` will
-- OR these conditions onto the existing predicate so a convo qualifies
-- for auto-reset when EITHER failure mode crosses threshold.
--
-- Observed in dogfood (2026-04-27): 3 of 6 stuck convos
-- (09c309bf, 094825d8, 4b2cdbaa) sit broken-but-not-reset because the
-- existing sweep can't see their failure mode. iOS keeps trying External
-- Commit, gets 404 GroupInfo, fails before reaching commitGroupChange,
-- so recent_commit_409_count stays at 0 and sweep ignores them forever.
--
-- Spec: docs/superpowers/specs/2026-04-26-mls-auto-reset-phase2-design.md
-- (B10 addendum: GroupInfo-missing failure mode)

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS recent_groupinfo_404_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_groupinfo_404_at      TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_conversations_groupinfo_404_sweep
    ON conversations (last_groupinfo_404_at, recent_groupinfo_404_count)
    WHERE auto_reset_disabled_at IS NULL
      AND group_info IS NULL;

COMMENT ON COLUMN conversations.recent_groupinfo_404_count IS
    'Phase 2 B10: rolling count of 404 GroupInfoUnavailable responses from get_group_state when include=groupInfo. Bumped on every 404 by the handler; zeroed inside do_reset_group (post-reset state expects 404s until bootstrap lands). Sweep treats high values combined with recent last_groupinfo_404_at as the "broken-but-no-409s" failure signal that the original 409-only predicate missed.';

COMMENT ON COLUMN conversations.last_groupinfo_404_at IS
    'Phase 2 B10: timestamp of the most recent 404 GroupInfoUnavailable response. Recency check ensures the sweep targets currently-failing convos, not lifetime accumulation from convos that recovered.';

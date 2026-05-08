-- Inline-404 (and 409) trigger bootstrap gate.
--
-- Bug fixed (observed 2026-05-08 on convo 3a610a64...):
--   1. Client A calls createConvo at T=0. Row inserted with group_info=NULL.
--      First commit hasn't landed yet — group is still bootstrapping.
--   2. Client B (or A's other devices) starts polling getGroupInfo at T+1s.
--      Each poll → 404 GroupInfoUnavailable. record_groupinfo_404 bumps
--      recent_groupinfo_404_count.
--   3. At T+~4s, count crosses MIN_GROUPINFO_404_THRESHOLD (default 3) and
--      the inline-404 trigger fires a system-triggered reset.
--   4. The reset re-NULLs group_info and writes a new group_id. iOS sees
--      groupReset on every poll. Cascading-recovery cooldown (15min)
--      suppresses further resets without repairing the missing GroupInfo.
--   5. Convo is permanently zombied: state=active, group_info=NULL, no
--      client can adopt it.
--
-- Root cause: the trigger doesn't distinguish "group_info was once
-- populated, now lost" (a real failure worth resetting on) from
-- "group_info has NEVER been populated yet" (still bootstrapping after
-- createConvo, expected NULL window). Both look identical to the trigger
-- predicate today.
--
-- Structural fix:
--   * Add `bootstrap_completed_at` — sticky timestamp set the first time
--     `store_group_info_in_tx` writes a non-NULL group_info for the convo.
--     NEVER cleared, even on reset (reset preserves the bit because the
--     convo *has* completed bootstrap before, and the reset path's own
--     cooldown gates handle the post-reset NULL window separately).
--   * Inline-trigger predicates (both 404 and 409 paths) now gate on
--     `bootstrap_completed_at IS NOT NULL`. If the convo has never been
--     bootstrapped, skip the trigger entirely — no system-triggered reset
--     can fire on a still-bootstrapping convo.
--
-- Backfill: SET to created_at for any row where group_info IS NOT NULL OR
-- reset_count > 0 — both proxies for "this convo has been past its
-- initial bootstrap window." Conservatively close enough for an existing
-- prod set; no convo wedged in the bootstrap window today will be missed
-- (a convo that's never bootstrapped AND never been reset will be left
-- with bootstrap_completed_at=NULL, which is the correct semantics —
-- the gate WILL skip the trigger for them, allowing them to bootstrap
-- without spurious resets).

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS bootstrap_completed_at TIMESTAMPTZ;

COMMENT ON COLUMN conversations.bootstrap_completed_at IS
    'Sticky timestamp set on the first non-NULL group_info write for the convo. NEVER cleared (reset preserves it). Used by inline 404/409 triggers to skip system-triggered resets on still-bootstrapping convos. NULL means the convo has never had group_info populated.';

-- Backfill: any convo with non-NULL group_info OR reset_count > 0 is
-- post-bootstrap. Use created_at as the conservative pre-existing value.
UPDATE conversations
SET bootstrap_completed_at = created_at
WHERE bootstrap_completed_at IS NULL
  AND (group_info IS NOT NULL OR reset_count > 0);

-- Partial index for the trigger evaluation hot path: lookups bumping
-- recent_groupinfo_404_count read this column on the `RETURNING` clause,
-- but we also use it in the predicate for sweep paths. The
-- `WHERE bootstrap_completed_at IS NOT NULL` partial keeps the index
-- small; convos still in their bootstrap window aren't there yet by
-- definition.
CREATE INDEX IF NOT EXISTS idx_conversations_bootstrap_completed
    ON conversations (bootstrap_completed_at)
    WHERE bootstrap_completed_at IS NOT NULL;

-- Layer 1 MLS Robustness: External Commit audit log + epoch-storm circuit breaker.
--
-- Plan: ~/.claude/plans/rippling-greeting-whale.md  Layer 1, sections 1.3 + 1.4
--
-- Adds two complementary mechanisms to commit_group_change.externalCommit
-- (and other epoch-advancing branches):
--
--   1. external_commit_audit table -- one row per External Commit attempt
--      (accepted OR rejected). Powers:
--        * Section 1.2 per-(device, group) 60s cooldown query (single-table
--          lookup replaces the previous messages scan -- messages stores
--          sender_did=NULL for commits per PRIV-001 so we cannot attribute
--          there).
--        * Post-incident forensics: who EC'd this group, when, with what
--          rejection reason.
--
--   2. conversations freeze columns (frozen_until,
--      epoch_advance_count, epoch_advance_count_window_start) -- when a
--      group has > N epoch advances in M seconds, set frozen_until = NOW()
--      + cooldown and reject epoch-advancing commits with HTTP 423
--      GroupFrozen until the freeze expires (auto-thaw). Default: > 6
--      advances within 60s -> freeze for 5 minutes.
--
-- Rollback path: both changes are additive. Drop the new columns with
-- ALTER TABLE conversations DROP COLUMN ... and DROP TABLE
-- external_commit_audit. No data backfill is required for either side
-- because both default to "no observed activity" (NULL / 0).

-- -------------------------------------------------------------------------
-- Section 1.4 -- External Commit audit log
-- -------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS external_commit_audit (
    id BIGSERIAL PRIMARY KEY,
    convo_id TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    -- Nullable: legacy single-device DIDs (no #device-uuid suffix) parse
    -- to an empty device_id. We store NULL rather than empty string so
    -- the cooldown query can use IS NOT NULL filters.
    actor_device_id TEXT,
    -- For accepted ECs both are real epoch values; for ECs rejected before
    -- CAS (KP-publish gate, freeze, per-device cooldown) both equal the
    -- current epoch we observed (NOT NULL per plan 1.4 schema).
    epoch_before INTEGER NOT NULL,
    epoch_after INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL for accepted ECs. Populated for rejected ECs with a stable
    -- machine-readable token (NoKeyPackagesPublished | PerDeviceCooldown |
    -- GroupFrozen | EpochMismatch | RateLimited).
    rejection_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_external_commit_audit_convo_time
    ON external_commit_audit(convo_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_external_commit_audit_actor_time
    ON external_commit_audit(actor_did, created_at DESC);

-- Tighter index for the section 1.2 cooldown query specifically.
CREATE INDEX IF NOT EXISTS idx_external_commit_audit_device_convo_time
    ON external_commit_audit(actor_device_id, convo_id, created_at DESC)
    WHERE actor_device_id IS NOT NULL;

COMMENT ON TABLE external_commit_audit IS
    'Layer 1 section 1.4: forensic audit of External Commit attempts (accepted + rejected). Powers section 1.2 per-(device, group) cooldown query and post-incident replay. messages.sender_did is NULL for commits (PRIV-001) so this is the only attributable record of who EC''d what.';

COMMENT ON COLUMN external_commit_audit.rejection_reason IS
    'NULL = accepted; otherwise stable machine-readable token (NoKeyPackagesPublished | PerDeviceCooldown | GroupFrozen | EpochMismatch | RateLimited). New tokens may be added.';

-- -------------------------------------------------------------------------
-- Section 1.3 -- Epoch-storm circuit breaker columns on conversations
-- -------------------------------------------------------------------------

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS frozen_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS epoch_advance_count_window_start TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS epoch_advance_count INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN conversations.frozen_until IS
    'Layer 1 section 1.3: if NON-NULL and > NOW(), the group is frozen -- epoch-advancing commits return HTTP 423 GroupFrozen. Set when epoch_advance_count exceeds the threshold within the rolling window. Auto-thaws after the timestamp passes.';

COMMENT ON COLUMN conversations.epoch_advance_count_window_start IS
    'Layer 1 section 1.3: start of the current epoch-advance counting window. Reset to NOW() when the window rolls over.';

COMMENT ON COLUMN conversations.epoch_advance_count IS
    'Layer 1 section 1.3: number of epoch advances observed within the current window. Compared against the threshold (default 6) on every epoch-advancing commit; threshold breach triggers freeze.';

CREATE INDEX IF NOT EXISTS idx_conversations_frozen_until
    ON conversations (frozen_until)
    WHERE frozen_until IS NOT NULL;

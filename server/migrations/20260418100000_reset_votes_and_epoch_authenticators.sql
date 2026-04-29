-- ADR-002 §A7.2 — Per-DID quorum auto-reset with epoch_authenticator binding.
--
-- This migration:
--   1. Ensures conversations.auto_reset_disabled_at exists (was in the
--      never-applied 20260406_002_recovery_failures.sql).
--   2. Creates reset_votes, epoch_authenticators, auto_reset_history tables.
--   3. Drops the legacy per-device recovery_failures table.
--
-- Per ADR §D6 and the 2026-04-16 server audit: the old recovery_failures
-- table is dropped in the same ship because old rows would not count under
-- the new per-DID + epoch_authenticator rules anyway, and the table never
-- existed in prod (303/306 reportRecoveryFailure calls in last 24h crashed
-- with "relation recovery_failures does not exist").

-- ---------------------------------------------------------------------------
-- Ensure circuit-breaker column exists on conversations.
-- Was defined in 20260406_002_recovery_failures.sql which was never applied.
-- ---------------------------------------------------------------------------
ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS auto_reset_disabled_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------------
-- reset_votes: Per-device vote rows scoped to an identity DID.
--
-- A vote row is recorded per reporting device, but quorum counting groups
-- by `identity_did` and requires ALL of that identity's active devices in
-- the conversation's member roster to have a valid row inside the 1-hour
-- expiry window.
--
-- 24h per-DID rate-limit enforced by checking the newest voted_at for a
-- given (convo_id, identity_did) before upsert.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reset_votes (
    convo_id             TEXT        NOT NULL,
    device_did           TEXT        NOT NULL,
    identity_did         TEXT        NOT NULL,
    epoch_authenticator  TEXT        NOT NULL,  -- hex-encoded RFC 9420 §8.7 authenticator
    failure_type         TEXT        NOT NULL,
    voted_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,  -- voted_at + 24h
    PRIMARY KEY (convo_id, device_did)
);

CREATE INDEX IF NOT EXISTS idx_reset_votes_convo_identity
    ON reset_votes (convo_id, identity_did);
CREATE INDEX IF NOT EXISTS idx_reset_votes_expires
    ON reset_votes (expires_at);

COMMENT ON TABLE reset_votes IS 'Per-DID quorum votes for auto-reset (ADR-002). PK is (convo_id, device_did); per-identity aggregation via identity_did. 24h TTL.';

-- epoch_authenticators: Known-good epoch authenticators for cryptographic binding of reset votes.
-- Populated by every successful commit_group_change. A vote is accepted iff the reporter's
-- authenticator matches one of the last 3 epochs OR was recorded within the last 5 minutes.
CREATE TABLE IF NOT EXISTS epoch_authenticators (
    convo_id       TEXT        NOT NULL,
    epoch          INT         NOT NULL,
    authenticator  TEXT        NOT NULL,  -- hex-encoded
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, epoch, authenticator),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_epoch_auth_convo_recorded
    ON epoch_authenticators (convo_id, recorded_at DESC);

COMMENT ON TABLE epoch_authenticators IS 'Known-good epoch_authenticator (RFC 9420 §8.7) per conversation epoch. Written on every commit; used to validate reset_votes.';

-- auto_reset_history: Rolling 24h circuit breaker history.
-- Supersedes the lifetime reset_count on conversations for the breaker check.
-- conversations.reset_count is kept as a lifetime counter for event/telemetry.
CREATE TABLE IF NOT EXISTS auto_reset_history (
    id                  SERIAL      PRIMARY KEY,
    convo_id            TEXT        NOT NULL,
    reset_triggered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    triggered_by        TEXT        NOT NULL,  -- 'system:auto_recovery' | 'admin:<did>'
    new_group_id        TEXT        NOT NULL,
    vote_count          INT         NOT NULL,
    member_count        INT         NOT NULL,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auto_reset_history_convo_time
    ON auto_reset_history (convo_id, reset_triggered_at DESC);

COMMENT ON TABLE auto_reset_history IS 'Audit trail + circuit-breaker source. Rolling 24h count feeds the 3-per-day cap (ADR-002 D5).';

-- ---------------------------------------------------------------------------
-- Drop the legacy per-device recovery_failures table.
--
-- Per ADR §D6: old rows would not count under the new per-DID +
-- epoch_authenticator rules (no stored authenticator → treated as stale).
-- Per the 2026-04-16 audit: this table never actually existed in prod —
-- 303/306 reportRecoveryFailure calls in the last 24h crashed at the upsert
-- with "relation recovery_failures does not exist". A7 supersedes it.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS recovery_failures;

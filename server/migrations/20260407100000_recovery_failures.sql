-- Recovery failure tracking for quorum-based auto-reset.
-- Each row: "this member has exhausted External Commit retries."
-- Cleared on successful reset or rejoin.

CREATE TABLE IF NOT EXISTS recovery_failures (
    convo_id    VARCHAR(255) NOT NULL,
    member_did  VARCHAR(255) NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    failure_type VARCHAR(64) NOT NULL DEFAULT 'external_commit_exhausted',
    PRIMARY KEY (convo_id, member_did)
);

CREATE INDEX IF NOT EXISTS idx_recovery_failures_convo
    ON recovery_failures(convo_id);

-- Circuit breaker: disable auto-reset after repeated resets
ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS auto_reset_disabled_at TIMESTAMPTZ;

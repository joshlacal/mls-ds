-- ADR-008 D1 — Add failure_mode column to reset_votes for Mode A vs Mode B
-- classification (spec §8.6.1).
--
-- Per ADR-008 D1: only votes with failure_mode = 'group_state_unrecoverable'
-- (Mode B) SHOULD count toward server-side quorum auto-reset. Mode A votes
-- (`local_state_loss`) indicate the client should self-heal via §6.6 / §8.4
-- External Commit + self-Remove and SHOULD NOT trigger a global reset.
--
-- Existing rows pre-dating this column are NULL — under the interim grace
-- posture (`ENFORCE_FAILURE_MODE_QUORUM=false`, default) NULL counts toward
-- quorum like any other vote so older clients that haven't shipped the
-- failureMode field aren't suddenly silenced. Once enforcement flips on,
-- NULL is treated as `local_state_loss` (conservative) per spec §8.6.1.

ALTER TABLE reset_votes
    ADD COLUMN IF NOT EXISTS failure_mode TEXT;

COMMENT ON COLUMN reset_votes.failure_mode IS
    'ADR-008 D1: ''local_state_loss'' (Mode A, self-heal) or ''group_state_unrecoverable'' (Mode B, counts toward quorum). NULL = old client without the field. Spec §8.6.1.';

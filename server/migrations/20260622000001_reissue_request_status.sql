ALTER TABLE reissue_requests
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'requested',
    ADD COLUMN IF NOT EXISTS delivered_to_inviter_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ NULL;

UPDATE reissue_requests
SET status = 'responded'
WHERE responded_at IS NOT NULL
  AND status IN ('requested', 'delivered_to_inviter');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'reissue_requests_status_check'
    ) THEN
        ALTER TABLE reissue_requests
            ADD CONSTRAINT reissue_requests_status_check
            CHECK (status IN ('requested', 'delivered_to_inviter', 'responded', 'consumed', 'expired'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_reissue_requests_status
    ON reissue_requests(convo_id, recipient_device_did, status, requested_at DESC);

COMMENT ON COLUMN reissue_requests.status IS
    'Durable Welcome reissue state: requested, delivered_to_inviter, responded, consumed, expired.';
COMMENT ON COLUMN reissue_requests.delivered_to_inviter_at IS
    'Set when the DS has queued/persisted the inviter/admin reissue request event.';
COMMENT ON COLUMN reissue_requests.consumed_at IS
    'Set when the replacement Welcome row associated with this request is consumed/invalidated.';
COMMENT ON COLUMN reissue_requests.expired_at IS
    'Set when polling observes an unanswered request past the reissue TTL.';

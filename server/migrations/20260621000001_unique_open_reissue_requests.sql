-- Keep one open Welcome reissue request per recipient device. Production already
-- has duplicate open rows from retry storms, so collapse those before adding the
-- partial unique index used by reissueWelcome's ON CONFLICT upsert.

WITH ranked AS (
    SELECT
        id,
        FIRST_VALUE(id) OVER (
            PARTITION BY convo_id, recipient_device_did
            ORDER BY requested_at ASC, id ASC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY convo_id, recipient_device_did
            ORDER BY requested_at ASC, id ASC
        ) AS row_num,
        attempts,
        last_attempt_at
    FROM reissue_requests
    WHERE responded_at IS NULL
),
collapsed AS (
    SELECT
        keep_id,
        SUM(attempts)::INTEGER AS total_attempts,
        MAX(last_attempt_at) AS max_last_attempt_at
    FROM ranked
    GROUP BY keep_id
)
UPDATE reissue_requests kept
SET
    attempts = GREATEST(kept.attempts, collapsed.total_attempts),
    last_attempt_at = GREATEST(kept.last_attempt_at, collapsed.max_last_attempt_at)
FROM collapsed
WHERE kept.id = collapsed.keep_id;

WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY convo_id, recipient_device_did
            ORDER BY requested_at ASC, id ASC
        ) AS row_num
    FROM reissue_requests
    WHERE responded_at IS NULL
)
DELETE FROM reissue_requests rr
USING ranked
WHERE rr.id = ranked.id
  AND ranked.row_num > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_reissue_requests_open_unique
    ON reissue_requests(convo_id, recipient_device_did)
    WHERE responded_at IS NULL;

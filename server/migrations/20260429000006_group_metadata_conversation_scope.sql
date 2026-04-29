-- Scope encrypted group metadata blobs to the stable conversation timeline.
--
-- Older rows were keyed only by MLS group_id. That makes metadata lookup fragile
-- after reset because group_id rotates while the user-facing conversation stays
-- the same. New writes keep group_id for the crypto/AAD context and add convo_id
-- plus generation/version routing metadata.
ALTER TABLE group_metadata_blobs
    ADD COLUMN IF NOT EXISTS convo_id TEXT;

ALTER TABLE group_metadata_blobs
    ADD COLUMN IF NOT EXISTS reset_generation INTEGER;

ALTER TABLE group_metadata_blobs
    ADD COLUMN IF NOT EXISTS metadata_version BIGINT;

ALTER TABLE group_metadata_blobs
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'metadata';

UPDATE group_metadata_blobs AS g
SET
    convo_id = c.id,
    reset_generation = COALESCE(c.reset_count, 0)
FROM conversations AS c
WHERE g.convo_id IS NULL
  AND g.group_id = c.group_id;

CREATE INDEX IF NOT EXISTS idx_gmb_convo_generation
    ON group_metadata_blobs (convo_id, reset_generation DESC, metadata_version DESC, created_at DESC)
    WHERE convo_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_gmb_convo_group
    ON group_metadata_blobs (convo_id, group_id, created_at DESC)
    WHERE convo_id IS NOT NULL;


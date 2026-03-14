-- Add convo_id to blobs for group membership authorization on download.
-- Existing blobs get NULL (downloadable by any authenticated user for backwards compat).
-- New uploads require convo_id.

ALTER TABLE blobs ADD COLUMN IF NOT EXISTS convo_id TEXT;

CREATE INDEX IF NOT EXISTS idx_blobs_convo_id ON blobs (convo_id) WHERE convo_id IS NOT NULL;

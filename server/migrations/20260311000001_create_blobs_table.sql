-- Blob metadata for encrypted image storage
-- Actual blob bytes are stored in SeaweedFS via S3 API
-- Drop legacy blobs table (content-addressed, no owner tracking) if it exists
DROP TABLE IF EXISTS blobs;
CREATE TABLE blobs (
    id          TEXT PRIMARY KEY,
    owner_did   TEXT NOT NULL,
    size_bytes  BIGINT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    deleted_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_blobs_owner_did ON blobs(owner_did);
CREATE INDEX IF NOT EXISTS idx_blobs_expires_at ON blobs(expires_at) WHERE deleted_at IS NULL;

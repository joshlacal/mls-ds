-- Encrypted group metadata blob storage
-- Stores opaque ciphertext for group metadata (titles, avatars, etc.)
-- Blobs are immutable once written; old blobs are garbage collected via TTL sweep.
CREATE TABLE IF NOT EXISTS group_metadata_blobs (
    blob_locator TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    data BYTEA NOT NULL,
    size INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gmb_group ON group_metadata_blobs (group_id);

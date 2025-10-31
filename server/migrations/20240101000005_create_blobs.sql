-- Create blobs table
CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    size BIGINT NOT NULL,
    uploaded_by_did TEXT NOT NULL,
    convo_id TEXT,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mime_type TEXT,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE SET NULL
);

-- Add index on uploaded_by_did for user's blob lookup
CREATE INDEX idx_blobs_uploaded_by ON blobs(uploaded_by_did);

-- Add index on convo_id for conversation's blobs
CREATE INDEX idx_blobs_convo ON blobs(convo_id) WHERE convo_id IS NOT NULL;

-- Add index on uploaded_at for sorting
CREATE INDEX idx_blobs_uploaded_at ON blobs(uploaded_at DESC);

-- Add index on size for storage analytics
CREATE INDEX idx_blobs_size ON blobs(size);

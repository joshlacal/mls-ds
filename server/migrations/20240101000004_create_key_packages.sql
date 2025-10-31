-- Create key_packages table
CREATE TABLE IF NOT EXISTS key_packages (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    key_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ
);

-- Add unique constraint to prevent duplicate key packages
CREATE UNIQUE INDEX idx_key_packages_unique ON key_packages(did, cipher_suite, key_data);

-- Add index on did and cipher_suite for efficient lookup
CREATE INDEX idx_key_packages_did_suite ON key_packages(did, cipher_suite);

-- Add index for available (non-consumed) key packages
-- Note: expires_at check is done in application code for index efficiency
CREATE INDEX idx_key_packages_available ON key_packages(did, cipher_suite, expires_at) 
    WHERE consumed = FALSE;

-- Add index on expires_at for cleanup queries
CREATE INDEX idx_key_packages_expires ON key_packages(expires_at);

-- Add index on consumed for filtering
CREATE INDEX idx_key_packages_consumed ON key_packages(consumed, consumed_at);

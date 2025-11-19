-- Update key_packages table schema to match code expectations
-- Changes:
-- 1. Rename 'did' to 'owner_did' for clarity
-- 2. Rename 'key_data' to 'key_package' to match column name
-- 3. Change id from SERIAL to TEXT (UUID)
-- 4. Remove consumed boolean (we only use consumed_at timestamp)

-- Rename columns (idempotent)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='key_packages' AND column_name='did') THEN
        ALTER TABLE key_packages RENAME COLUMN did TO owner_did;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='key_packages' AND column_name='key_data') THEN
        ALTER TABLE key_packages RENAME COLUMN key_data TO key_package;
    END IF;
END $$;

-- Drop the consumed boolean column (we only use consumed_at)
ALTER TABLE key_packages DROP COLUMN IF EXISTS consumed;

-- Change id to TEXT and add consumed_by_convo tracking
-- First, alter id column type
ALTER TABLE key_packages ALTER COLUMN id TYPE TEXT;

-- Add consumed_by_convo column for tracking which conversation consumed this key package
ALTER TABLE key_packages ADD COLUMN IF NOT EXISTS consumed_by_convo TEXT;

-- Update indices to use new column names
DROP INDEX IF EXISTS idx_key_packages_owner;
DROP INDEX IF EXISTS idx_key_packages_available;
DROP INDEX IF EXISTS idx_key_packages_hash_lookup;

CREATE INDEX IF NOT EXISTS idx_key_packages_owner ON key_packages(owner_did);
CREATE INDEX IF NOT EXISTS idx_key_packages_available ON key_packages(owner_did, cipher_suite, expires_at) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_key_packages_hash_lookup ON key_packages(owner_did, key_package_hash) WHERE consumed_at IS NULL;

-- Add foreign key to users table
ALTER TABLE key_packages DROP CONSTRAINT IF EXISTS key_packages_owner_did_fkey;
ALTER TABLE key_packages ADD CONSTRAINT key_packages_owner_did_fkey
    FOREIGN KEY (owner_did) REFERENCES users(did) ON DELETE CASCADE;

-- Update unique constraint to use new column names
ALTER TABLE key_packages DROP CONSTRAINT IF EXISTS key_packages_did_cipher_suite_key_data_key;
-- Note: Not adding a new unique constraint on (owner_did, cipher_suite, key_package)
-- because users can upload the same key package multiple times

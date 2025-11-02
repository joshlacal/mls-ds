-- Backfill key_package_hash for existing key packages
-- This computes SHA256 hashes for all key packages that don't have one yet
-- NOTE: This migration is only needed if upgrading from an older version where
-- key_package_hash was nullable. For fresh installs, this is a no-op.

-- Update key_packages to add SHA256 hash where missing
-- Note: PostgreSQL's digest() function is in the pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Only attempt backfill if the column exists and is nullable
-- This handles the case where we're upgrading from old schema
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'key_packages' 
        AND column_name = 'key_package_hash'
        AND is_nullable = 'YES'
    ) THEN
        UPDATE key_packages
        SET key_package_hash = encode(digest(key_data, 'sha256'), 'hex')
        WHERE key_package_hash IS NULL OR key_package_hash = '';
        
        -- Make column NOT NULL after backfill
        ALTER TABLE key_packages ALTER COLUMN key_package_hash SET NOT NULL;
    END IF;
END $$;

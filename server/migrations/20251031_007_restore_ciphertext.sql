-- Migration: Restore ciphertext column
-- Description: Add back ciphertext column since code is not yet updated for blob storage
-- Date: 2025-10-31

-- Add ciphertext column back if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'ciphertext'
    ) THEN
        ALTER TABLE messages ADD COLUMN ciphertext BYTEA;
    END IF;
END $$;

-- Note: We're keeping both ciphertext (for inline storage) and blob_key (for future R2 storage)
-- The code currently uses ciphertext, so we need this column until the R2 migration is complete

-- Add new columns to conversations table
ALTER TABLE conversations 
ADD COLUMN IF NOT EXISTS cipher_suite TEXT,
ADD COLUMN IF NOT EXISTS name TEXT,
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS avatar_blob TEXT;

-- Rename title to name if title exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'conversations' AND column_name = 'title'
    ) THEN
        UPDATE conversations SET name = title WHERE title IS NOT NULL;
        ALTER TABLE conversations DROP COLUMN title;
    END IF;
END $$;

-- Set default cipher suite for existing conversations
UPDATE conversations 
SET cipher_suite = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'
WHERE cipher_suite IS NULL;

-- Make cipher_suite NOT NULL
ALTER TABLE conversations 
ALTER COLUMN cipher_suite SET NOT NULL;

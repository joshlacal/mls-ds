-- Fix Idempotency: Add UNIQUE constraint to messages.idempotency_key
-- Created: 2025-11-04
-- Description: Prevent duplicate message creation by enforcing unique idempotency keys at database level

-- Drop existing non-unique index if it exists
DROP INDEX IF EXISTS idx_messages_idempotency;

-- Add UNIQUE constraint on idempotency_key
-- This will automatically create a unique index
-- Note: This constraint allows multiple NULL values (which is correct)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'messages_idempotency_key_unique'
        AND conrelid = 'messages'::regclass
    ) THEN
        ALTER TABLE messages
        ADD CONSTRAINT messages_idempotency_key_unique
        UNIQUE (idempotency_key);

        RAISE NOTICE 'Added UNIQUE constraint messages_idempotency_key_unique';
    ELSE
        RAISE NOTICE 'Constraint messages_idempotency_key_unique already exists';
    END IF;
END $$;

-- Verify no existing duplicates (for safety)
-- This query will show any duplicate idempotency keys that exist
DO $$
DECLARE
    duplicate_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO duplicate_count
    FROM (
        SELECT idempotency_key, COUNT(*) as cnt
        FROM messages
        WHERE idempotency_key IS NOT NULL
        GROUP BY idempotency_key
        HAVING COUNT(*) > 1
    ) duplicates;

    IF duplicate_count > 0 THEN
        RAISE WARNING 'Found % duplicate idempotency keys in messages table. These should be cleaned up.', duplicate_count;
    ELSE
        RAISE NOTICE 'No duplicate idempotency keys found - migration is safe';
    END IF;
END $$;

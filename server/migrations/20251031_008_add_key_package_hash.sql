-- Add key_package_hash to welcome_messages table
-- This tracks which specific key package was used to create each welcome message

ALTER TABLE welcome_messages 
ADD COLUMN key_package_hash BYTEA;

-- Drop the old unique constraint
DROP INDEX IF EXISTS idx_welcome_messages_unique;

-- Create new unique constraint that includes key_package_hash
-- This allows multiple welcome messages for the same (convo, recipient) pair
-- as long as they're for different key packages (different devices)
CREATE UNIQUE INDEX idx_welcome_messages_unique_with_hash 
ON welcome_messages (convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea)) 
WHERE consumed = false;

-- Add index for efficient lookups by hash
CREATE INDEX idx_welcome_messages_hash 
ON welcome_messages(key_package_hash) 
WHERE key_package_hash IS NOT NULL;

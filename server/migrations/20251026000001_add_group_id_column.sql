-- Add group_id column to store the actual MLS group ID (hex-encoded)
ALTER TABLE conversations ADD COLUMN group_id TEXT;

-- Add index for efficient group_id lookups
CREATE INDEX idx_conversations_group_id ON conversations(group_id);

-- Add cipher_suite column to store the MLS cipher suite
ALTER TABLE conversations ADD COLUMN cipher_suite TEXT;

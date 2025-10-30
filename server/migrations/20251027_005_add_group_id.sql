-- Add group_id column to conversations table
-- This is the MLS group identifier passed from the client

ALTER TABLE conversations
ADD COLUMN IF NOT EXISTS group_id TEXT;

-- Create index for group_id lookups
CREATE INDEX IF NOT EXISTS idx_conversations_group_id ON conversations(group_id);

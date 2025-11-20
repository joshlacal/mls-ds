-- Add idempotency_key columns to support idempotent retries
-- Created: 2025-11-02
-- Description: Add optional idempotency_key columns for write operations

-- Add idempotency_key to messages table
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

-- Create unique index on idempotency_key for messages
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_idempotency_key
  ON messages(idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- Add idempotency_key to conversations table
ALTER TABLE conversations
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

-- Create unique index on idempotency_key for conversations
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_idempotency_key
  ON conversations(idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- Note: add_members and leave_convo use natural idempotency:
-- - add_members: Skip if member already exists
-- - leave_convo: Only update if left_at IS NULL

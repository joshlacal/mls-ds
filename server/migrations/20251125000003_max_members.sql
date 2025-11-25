-- Add max_members column to conversation_policy table
-- Migration: 20251125000003_max_members
-- Description: Add configurable maximum members limit per conversation

-- Add max_members column with default 1000
ALTER TABLE conversation_policy
ADD COLUMN IF NOT EXISTS max_members INTEGER NOT NULL DEFAULT 1000;

-- Add check constraint (range: 2-10000)
ALTER TABLE conversation_policy
ADD CONSTRAINT check_max_members CHECK (max_members >= 2 AND max_members <= 10000);

-- Add comment for documentation
COMMENT ON COLUMN conversation_policy.max_members IS 'Maximum members allowed in conversation (default 1000, range 2-10000)';

-- Create index for queries filtering by max_members
CREATE INDEX IF NOT EXISTS idx_conversation_policy_max_members
    ON conversation_policy(max_members);

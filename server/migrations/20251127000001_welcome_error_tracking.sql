-- Migration: Add error tracking to welcome_messages and rejoin tracking to members
-- Purpose: Support MLS recovery flow for stale Welcome messages and re-addition requests

-- Add error_reason column to welcome_messages for tracking why a Welcome was invalidated
ALTER TABLE welcome_messages
ADD COLUMN IF NOT EXISTS error_reason TEXT;

-- Index for cleanup queries - find all invalidated Welcomes
CREATE INDEX IF NOT EXISTS idx_welcome_messages_error
ON welcome_messages(error_reason)
WHERE error_reason IS NOT NULL;

-- Add rejoin tracking fields to members table
ALTER TABLE members
ADD COLUMN IF NOT EXISTS rejoin_requested_at TIMESTAMPTZ;

ALTER TABLE members
ADD COLUMN IF NOT EXISTS rejoin_attempts INTEGER DEFAULT 0;

ALTER TABLE members
ADD COLUMN IF NOT EXISTS last_rejoin_error TEXT;

-- Index for finding members needing rejoin
CREATE INDEX IF NOT EXISTS idx_members_needs_rejoin
ON members(convo_id, needs_rejoin, rejoin_requested_at)
WHERE needs_rejoin = true;

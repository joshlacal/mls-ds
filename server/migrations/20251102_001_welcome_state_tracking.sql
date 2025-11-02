-- Welcome Message State Tracking
-- Created: 2025-11-02
-- Description: Add state tracking columns to welcome_messages table for better
-- lifecycle management (available -> fetched -> consumed/confirmed)

-- Enable pgcrypto extension if not already enabled (required for other migrations)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- Add State Tracking Columns
-- =============================================================================

-- Add state column with default 'available'
-- Valid states: 'available', 'fetched', 'consumed', 'confirmed'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'welcome_messages'
        AND column_name = 'state'
    ) THEN
        ALTER TABLE welcome_messages
        ADD COLUMN state VARCHAR(20) DEFAULT 'available';
    END IF;
END $$;

-- Add fetched_at timestamp for tracking when client retrieved the welcome
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'welcome_messages'
        AND column_name = 'fetched_at'
    ) THEN
        ALTER TABLE welcome_messages
        ADD COLUMN fetched_at TIMESTAMPTZ;
    END IF;
END $$;

-- Add confirmed_at timestamp for tracking when client confirmed processing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'welcome_messages'
        AND column_name = 'confirmed_at'
    ) THEN
        ALTER TABLE welcome_messages
        ADD COLUMN confirmed_at TIMESTAMPTZ;
    END IF;
END $$;

-- =============================================================================
-- Migrate Existing Data
-- =============================================================================

-- Migrate existing welcome messages from consumed boolean to state enum
-- consumed = true  -> state = 'consumed'
-- consumed = false -> state = 'available'
UPDATE welcome_messages
SET state = CASE
    WHEN consumed = true THEN 'consumed'
    ELSE 'available'
END
WHERE state IS NULL OR state = 'available';

-- If consumed_at exists, copy it to confirmed_at for consumed messages
UPDATE welcome_messages
SET confirmed_at = consumed_at
WHERE consumed = true AND confirmed_at IS NULL;

-- =============================================================================
-- Add Indexes
-- =============================================================================

-- Index for querying available welcomes for a recipient in a conversation
-- Replaces the old (recipient_did, consumed) index pattern
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_welcome_messages_state'
    ) THEN
        CREATE INDEX idx_welcome_messages_state
        ON welcome_messages(convo_id, recipient_did, state);
    END IF;
END $$;

-- Index for finding stale fetched messages that were never confirmed
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_welcome_messages_fetched'
    ) THEN
        CREATE INDEX idx_welcome_messages_fetched
        ON welcome_messages(fetched_at)
        WHERE state = 'fetched';
    END IF;
END $$;

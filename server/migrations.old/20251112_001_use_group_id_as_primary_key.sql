-- =============================================================================
-- Migration: Use group_id as Primary Key for Conversations
-- Date: 2025-11-12
-- Description: Merge id and group_id columns - use client-provided groupId
--              as the canonical conversation identifier
-- =============================================================================

-- Step 1: Drop the old server-generated id column
-- (Safe for greenfield - no production data)
ALTER TABLE conversations DROP COLUMN IF EXISTS id CASCADE;

-- Step 2: Make group_id NOT NULL and rename it to id
-- This maintains backward compatibility with all existing queries
ALTER TABLE conversations ALTER COLUMN group_id SET NOT NULL;
ALTER TABLE conversations RENAME COLUMN group_id TO id;

-- Step 3: Add PRIMARY KEY constraint on the new id column
ALTER TABLE conversations ADD PRIMARY KEY (id);

-- Step 4: Add validation constraint for hex-encoded format
-- MLS group IDs should be hex-encoded (only 0-9, a-f characters)
ALTER TABLE conversations ADD CONSTRAINT group_id_hex_format
  CHECK (id ~ '^[0-9a-f]+$');

-- Step 5: Update the group_id index (now id index)
-- Drop the old index on group_id (column no longer exists)
DROP INDEX IF EXISTS idx_conversations_group_id;

-- Create index on id (redundant with PRIMARY KEY, but explicit)
-- Primary key already creates an index, so this is optional
-- CREATE INDEX IF NOT EXISTS idx_conversations_id ON conversations(id);

-- Step 6: Recreate foreign key constraints (they were dropped with the old PRIMARY KEY)
ALTER TABLE members
    ADD CONSTRAINT members_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE messages
    ADD CONSTRAINT messages_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE welcome_messages
    ADD CONSTRAINT welcome_messages_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE pending_welcomes
    ADD CONSTRAINT pending_welcomes_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE reports
    ADD CONSTRAINT reports_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE envelopes
    ADD CONSTRAINT envelopes_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE cursors
    ADD CONSTRAINT cursors_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

ALTER TABLE event_stream
    ADD CONSTRAINT event_stream_convo_id_fkey
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE;

-- =============================================================================
-- Notes:
-- - The id column now stores the client-provided MLS group identifier
-- - All foreign keys now reference the new id column (which contains the group_id)
-- - Queries using conversations.id continue to work without modification
-- - The hex format check ensures only valid MLS group IDs are stored
-- =============================================================================

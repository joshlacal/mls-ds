-- MLS Group Reset Support
--
-- Decouples conversation identity (conversations.id) from MLS group identity
-- (conversations.group_id). This allows an MLS group to be reset (new group_id,
-- epoch back to 0) while preserving conversation identity, members, and message
-- history.
--
-- The group_id column was added in migration 005 but never populated.

-- 1. Backfill group_id from id for all existing rows
UPDATE conversations SET group_id = id WHERE group_id IS NULL;

-- 2. Make group_id NOT NULL going forward
ALTER TABLE conversations ALTER COLUMN group_id SET NOT NULL;

-- 3. Add reset tracking columns
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS reset_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS last_reset_at TIMESTAMPTZ;
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS last_reset_by TEXT;

-- 4. Unique index on group_id (each MLS group ID must be unique across conversations)
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_group_id_unique
    ON conversations(group_id);

-- 5. Messages track which MLS group generation they belong to.
-- 0 = original group, increments on each reset. Lets clients distinguish
-- old-group ciphertext (undecryptable) from new-group ciphertext.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reset_generation INTEGER NOT NULL DEFAULT 0;

-- =============================================================================
-- Add 'warn' action type to admin_actions table
-- =============================================================================
-- Created: 2025-11-25
-- Description: Extends admin_actions table to support warning members

-- Drop the existing CHECK constraint
ALTER TABLE admin_actions DROP CONSTRAINT IF EXISTS admin_actions_action_check;

-- Add new CHECK constraint with 'warn' included
ALTER TABLE admin_actions ADD CONSTRAINT admin_actions_action_check
    CHECK (action IN ('promote', 'demote', 'remove', 'warn'));

COMMENT ON CONSTRAINT admin_actions_action_check ON admin_actions IS 'Allowed actions: promote, demote, remove, warn';

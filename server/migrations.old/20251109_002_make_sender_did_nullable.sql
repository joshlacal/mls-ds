-- =============================================================================
-- Make sender_did Nullable Migration
-- Created: 2025-11-09
-- Description: Make sender_did nullable to support privacy-preserving message
--              storage. New messages will store sender_did = NULL and clients
--              will derive sender from MLS ciphertext (leaf_index).
-- =============================================================================

-- Make sender_did nullable for privacy-preserving storage
-- This allows new messages to be stored without plaintext sender metadata
ALTER TABLE messages
ALTER COLUMN sender_did DROP NOT NULL;

-- Add index for queries that still filter by sender_did (backward compatibility)
-- Partial index only for non-NULL values to save space
CREATE INDEX IF NOT EXISTS idx_messages_sender_did
ON messages(sender_did)
WHERE sender_did IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN messages.sender_did IS 'DEPRECATED: Plaintext sender DID. NULL for privacy-preserving messages (v2+). Clients MUST derive sender from MLS ciphertext leaf_index instead of relying on this field.';

-- =============================================================================
-- Security Note
-- =============================================================================
-- After this migration, ALL new messages MUST be created with sender_did = NULL
-- to prevent metadata leakage. The only exception is legacy "commit" messages
-- for MLS protocol operations (addMembers, leaveConvo) which may still use
-- sender_did for backward compatibility during transition.
--
-- Clients MUST:
-- 1. Generate msg_id (ULID) and include it in MLS AAD
-- 2. Decrypt MLS ciphertext to get sender from leaf_index
-- 3. NEVER trust server-provided sender_did field
-- =============================================================================

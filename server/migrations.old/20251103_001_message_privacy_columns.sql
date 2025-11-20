-- =============================================================================
-- Message Privacy Columns Migration
-- Created: 2025-11-03
-- Description: Add privacy-enhancing fields to messages table for metadata
--              protection. Supports msgId deduplication, message padding, and
--              timestamp quantization.
-- =============================================================================

-- Add msg_id column for client-generated message identifiers
-- This enables protocol-layer deduplication and should be included in MLS AAD
ALTER TABLE messages
ADD COLUMN IF NOT EXISTS msg_id TEXT;

-- Add declared_size column to store original plaintext size before padding
-- This allows the server to track actual content size without leaking it
ALTER TABLE messages
ADD COLUMN IF NOT EXISTS declared_size INTEGER;

-- Add padded_size column to store the bucket size used for padding
-- Valid values: 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB
ALTER TABLE messages
ADD COLUMN IF NOT EXISTS padded_size INTEGER;

-- Add received_bucket_ts for timestamp quantization (2-second buckets)
-- This replaces the microsecond-precision created_at for privacy
ALTER TABLE messages
ADD COLUMN IF NOT EXISTS received_bucket_ts BIGINT;

-- Create unique index on (convo_id, msg_id) for deduplication
-- This prevents duplicate messages even across retries
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msg_id_dedup
ON messages(convo_id, msg_id)
WHERE msg_id IS NOT NULL;

-- Index for efficient msg_id lookups
CREATE INDEX IF NOT EXISTS idx_messages_msg_id
ON messages(msg_id)
WHERE msg_id IS NOT NULL;

-- Index for timestamp bucket queries (for privacy-preserving ordering)
CREATE INDEX IF NOT EXISTS idx_messages_bucket_ts
ON messages(convo_id, received_bucket_ts DESC)
WHERE received_bucket_ts IS NOT NULL;

-- Add check constraint for valid padding sizes (deferred to application logic)
-- Note: PostgreSQL doesn't support complex CHECK constraints, so validation
-- happens in the application layer

-- Comments for documentation
COMMENT ON COLUMN messages.msg_id IS 'Client-generated ULID for message deduplication. MUST be included in MLS message AAD.';
COMMENT ON COLUMN messages.declared_size IS 'Original plaintext size in bytes before padding (for metadata privacy)';
COMMENT ON COLUMN messages.padded_size IS 'Padded ciphertext size in bytes. Must be 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB.';
COMMENT ON COLUMN messages.received_bucket_ts IS 'Unix timestamp quantized to 2-second buckets for traffic analysis resistance';

-- =============================================================================
-- Gradual Deprecation Path for sender_did
-- =============================================================================
-- NOTE: sender_did is currently still required but should be considered
-- deprecated. Future migrations will:
-- 1. Make sender_did nullable (allow NULL for new messages)
-- 2. Eventually drop the column entirely
--
-- MLS already encrypts sender information in the ciphertext (leaf_index).
-- The server does not need plaintext sender identity for routing since
-- recipients are tracked in the envelopes table.
--
-- To maintain backward compatibility during the transition:
-- - Old clients can continue sending sender_did (will be ignored)
-- - New clients omit sender_did
-- - Recipients decrypt sender from MLS ciphertext
-- =============================================================================


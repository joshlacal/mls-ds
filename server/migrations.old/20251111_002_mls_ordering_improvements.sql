-- MLS Ordering Improvements Migration
--
-- This migration adds optimized indexes for MLS message ordering and removes
-- the legacy created_at-based index. MLS requires sequential processing by
-- (epoch, seq) for proper cryptographic decryption.
--
-- Changes:
-- 1. Add composite index on (convo_id, epoch, seq) for efficient sequential ordering
-- 2. Drop old created_at-based index (no longer needed for greenfield implementation)

-- Add new index for MLS sequential ordering
-- This index supports queries with ORDER BY epoch ASC, seq ASC
CREATE INDEX idx_messages_convo_epoch_seq
ON messages (convo_id, epoch ASC, seq ASC);

-- Drop legacy timestamp-based ordering index
-- This index was used for ORDER BY created_at DESC, which doesn't guarantee
-- MLS sequential order due to network timing and timestamp bucketing
DROP INDEX IF EXISTS idx_messages_convo;

-- Note: Server now GUARANTEES messages are returned in (epoch ASC, seq ASC) order
-- Clients can rely on this ordering and don't need to sort messages themselves

-- Add unique constraint on (convo_id, seq) to prevent duplicate sequence numbers.
-- This is a safety net for the FOR UPDATE lock in send_message.
-- Uses CREATE UNIQUE INDEX IF NOT EXISTS for idempotent application.
CREATE UNIQUE INDEX IF NOT EXISTS messages_convo_seq_unique ON messages (convo_id, seq);

-- Conversation timeline queries are sequence-first. MLS epoch can reset when a
-- stable conversation rotates to a new MLS group, so epoch is not display order.
CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
ON messages (convo_id, seq ASC);

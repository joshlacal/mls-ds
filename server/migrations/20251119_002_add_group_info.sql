-- Add GroupInfo storage to conversations table
ALTER TABLE conversations
ADD COLUMN group_info BYTEA,
ADD COLUMN group_info_updated_at TIMESTAMPTZ,
ADD COLUMN group_info_epoch INTEGER;

-- Index for efficient lookups
CREATE INDEX idx_conversations_group_info_epoch 
ON conversations(id, group_info_epoch);

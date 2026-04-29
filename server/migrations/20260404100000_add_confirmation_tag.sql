-- Add confirmation_tag column to conversations table
-- Stores the MLS confirmation tag from the latest GroupInfo for tree divergence detection
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS confirmation_tag BYTEA;

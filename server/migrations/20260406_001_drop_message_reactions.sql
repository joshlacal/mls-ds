-- Drop deprecated plaintext message_reactions table.
-- Reactions are now sent as encrypted MLS application messages.
DROP TABLE IF EXISTS message_reactions;

-- Message reactions table for MLS conversations
-- Stores emoji reactions on messages

CREATE TABLE IF NOT EXISTS message_reactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    convo_id VARCHAR(255) NOT NULL,
    message_id VARCHAR(255) NOT NULL,
    user_did VARCHAR(255) NOT NULL,
    reaction VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure one reaction type per user per message
    CONSTRAINT unique_user_reaction UNIQUE (convo_id, message_id, user_did, reaction),
    
    -- Foreign key to messages table
    CONSTRAINT fk_message FOREIGN KEY (message_id)
        REFERENCES messages(id) ON DELETE CASCADE
);

-- Index for efficient lookups by message
CREATE INDEX IF NOT EXISTS idx_reactions_by_message 
    ON message_reactions(convo_id, message_id);

-- Index for efficient lookups by user
CREATE INDEX IF NOT EXISTS idx_reactions_by_user 
    ON message_reactions(convo_id, user_did);

-- Note: No table for typing indicators - they are ephemeral SSE events only

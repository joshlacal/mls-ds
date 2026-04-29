-- Store the MLS protocol epoch carried by commit ciphertext separately from
-- the server's post-advance epoch counter.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS wire_epoch BIGINT;

CREATE INDEX IF NOT EXISTS idx_messages_commit_wire_epoch
    ON messages(convo_id, wire_epoch, seq)
    WHERE message_type = 'commit';

COMMENT ON COLUMN messages.wire_epoch IS
    'MLS protocol epoch decoded from commit ciphertext. messages.epoch remains the server post-advance epoch for API compatibility.';

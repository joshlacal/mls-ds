-- Replicated group entries retain the sequencer's exact per-device audience.
-- Entries without a durable grant are never readable through the group fallback.
CREATE TABLE IF NOT EXISTS chat.group_transport_entry_recipients (
    conversation_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    user_did TEXT NOT NULL CHECK (chat.is_bare_did(user_did)),
    device_id UUID NOT NULL CHECK (chat.is_uuid_v4(device_id)),
    PRIMARY KEY (conversation_id, seq, user_did, device_id),
    FOREIGN KEY (conversation_id, seq)
        REFERENCES chat.direct_request_transport_entries (conversation_id, seq)
        ON DELETE CASCADE,
    FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices (user_did, device_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS group_transport_entry_recipients_device_idx
    ON chat.group_transport_entry_recipients (conversation_id, user_did, device_id, seq);

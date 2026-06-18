-- Bind legacy welcome_messages rows to the recipient device selected by the
-- KeyPackage at write time. Older rows remain NULL and continue through the
-- legacy lookup fallback in getGroupState.
ALTER TABLE welcome_messages
    ADD COLUMN IF NOT EXISTS recipient_device_id TEXT;

CREATE INDEX IF NOT EXISTS idx_welcome_messages_device_lookup
    ON welcome_messages(convo_id, recipient_did, recipient_device_id)
    WHERE consumed = false AND recipient_device_id IS NOT NULL;

COMMENT ON COLUMN welcome_messages.recipient_device_id IS
    'Device identifier resolved from the consumed KeyPackage at Welcome write time. NULL means legacy user-scoped Welcome row.';

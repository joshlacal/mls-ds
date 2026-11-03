-- A home retains packages until the sequencer's signed acceptance is mirrored.
-- The short export lease prevents a concurrent local recovery from selecting
-- the same still-available package while the S2S acceptance is in flight.
CREATE TABLE IF NOT EXISTS chat.group_key_package_exports (
    key_package_ref BYTEA PRIMARY KEY REFERENCES chat.key_packages(key_package_ref) ON DELETE CASCADE,
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id) ON DELETE CASCADE,
    recovery_request_id UUID NOT NULL CHECK (chat.is_uuid_v4(recovery_request_id)),
    sequencer_did TEXT NOT NULL CHECK (chat.is_bare_did(sequencer_did)),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION chat.wipe_closed_group_package_exports()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM chat.group_key_package_exports WHERE conversation_id = NEW.conversation_id;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS group_package_exports_close_wipe ON chat.conversations;
CREATE TRIGGER group_package_exports_close_wipe
AFTER UPDATE OF lifecycle ON chat.conversations
FOR EACH ROW WHEN (NEW.lifecycle <> 'active')
EXECUTE FUNCTION chat.wipe_closed_group_package_exports();

-- A device's home transfers a published MLS package once for one signed recovery
-- request. A direct transport home may not store a conversation graph. Ordinary
-- invitation leases keep their original conversation FK and cascade semantics.
ALTER TABLE chat.group_key_package_exports
    ADD COLUMN IF NOT EXISTS transfer_request_sha256 BYTEA
        CHECK (octet_length(transfer_request_sha256) = 32),
    ADD COLUMN IF NOT EXISTS invitation_conversation_id UUID
        GENERATED ALWAYS AS (
            CASE WHEN transfer_request_sha256 IS NULL THEN conversation_id END
        ) STORED REFERENCES chat.conversations(conversation_id) ON DELETE CASCADE;
ALTER TABLE chat.group_key_package_exports
    DROP CONSTRAINT IF EXISTS group_key_package_exports_conversation_id_fkey;
CREATE UNIQUE INDEX IF NOT EXISTS group_key_package_exports_one_transfer_per_request
    ON chat.group_key_package_exports(recovery_request_id)
    WHERE transfer_request_sha256 IS NOT NULL;

-- A remote peer may have already consumed a transferred package even after a
-- close, cancellation or lost reply. Retain its single-use claim for its full
-- cryptographic lifetime. Device/account deletion still cascades from the package.
CREATE OR REPLACE FUNCTION chat.wipe_closed_group_package_exports()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM chat.group_key_package_exports
     WHERE conversation_id = NEW.conversation_id AND transfer_request_sha256 IS NULL;
    RETURN NEW;
END;
$$;

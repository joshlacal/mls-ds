-- Migration: Labyrinth 1.1 storage backend, part 4 — bind every Labyrinth
-- device record to the chat device and key that registered it (whitepaper
-- gap audit G-P0-2).
--
-- Without the binding, any active chat device of a DID could create an epoch
-- or an epoch member naming arbitrary device keys. Epoch rows are immutable,
-- so one planted member or squatted epoch number aborts every later rotation
-- and the account can never revoke a device. With it, the server requires
-- (labyrinth::repo::binding):
--   * createEpoch: openedBy is a current, non-virtual Labyrinth device bound
--     to the calling chat device and key;
--   * createEpochMember / markDeviceRevoked: the caller holds such a device;
--   * every member row names a current Labyrinth device of the DID.
--
-- Rows written before this migration have no binding (both columns NULL);
-- they can still be read and revoked but never satisfy the caller checks.

ALTER TABLE labyrinth.devices
    ADD COLUMN chat_device_id UUID,
    ADD COLUMN chat_key_id TEXT;

ALTER TABLE labyrinth.devices
    ADD CONSTRAINT devices_chat_binding_check CHECK (
        (chat_device_id IS NULL AND chat_key_id IS NULL)
        OR (chat_device_id IS NOT NULL AND chat.is_base64url_sha256(chat_key_id))
    );

CREATE INDEX devices_chat_binding_idx
    ON labyrinth.devices (owner_did, chat_device_id, chat_key_id)
    WHERE revoked_at IS NULL;

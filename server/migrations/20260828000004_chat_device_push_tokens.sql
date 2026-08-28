ALTER TABLE chat.devices
    ADD COLUMN push_token TEXT,
    ADD COLUMN push_token_updated_at TIMESTAMPTZ;

DROP TRIGGER devices_identity_immutable ON chat.devices;

CREATE TRIGGER devices_identity_immutable
BEFORE UPDATE OR DELETE ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'device_name', 'status', 'dpop_jkt', 'auth_generation', 'capabilities',
    'push_token', 'push_token_updated_at', 'updated_at', 'revoked_at', 'revocation_id'
);

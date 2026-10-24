-- Canonical authority stores signed token hashes; Nest alone stores provider tokens.
CREATE TABLE chat.request_push_bindings (
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('apns','fcm')),
    registration_id UUID NOT NULL UNIQUE,
    key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (auth_generation BETWEEN 1 AND 9007199254740991),
    app_id TEXT NOT NULL CHECK (octet_length(app_id) BETWEEN 1 AND 128),
    token_generation BIGINT NOT NULL CHECK (token_generation BETWEEN 1 AND 9007199254740991),
    token_sha256 BYTEA NOT NULL CHECK (octet_length(token_sha256)=32),
    enabled BOOLEAN NOT NULL,
    binding_digest BYTEA NOT NULL CHECK (octet_length(binding_digest)=32),
    signed_binding BYTEA NOT NULL CHECK (octet_length(signed_binding) BETWEEN 1 AND 8192),
    signed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_did,device_id,provider),
    FOREIGN KEY (user_did,device_id) REFERENCES chat.devices(user_did,device_id),
    FOREIGN KEY (user_did,device_id,key_id) REFERENCES chat.device_keys(user_did,device_id,key_id)
);
CREATE FUNCTION chat.guard_request_push_binding() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'push binding generation fence is permanent' USING ERRCODE='23514'; END IF;
    IF (OLD.user_did,OLD.device_id,OLD.provider,OLD.registration_id)
       IS DISTINCT FROM (NEW.user_did,NEW.device_id,NEW.provider,NEW.registration_id)
       OR NEW.token_generation <= OLD.token_generation THEN
        RAISE EXCEPTION 'push binding must advance the same registration' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER request_push_binding_guard BEFORE UPDATE OR DELETE ON chat.request_push_bindings
    FOR EACH ROW EXECUTE FUNCTION chat.guard_request_push_binding();

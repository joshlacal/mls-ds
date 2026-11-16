-- Durable notice precedes any pending-device recovery promotion. Existing pending
-- devices start a fresh 72-hour hold at migration time: their earlier enrollment
-- was not accompanied by this notice.
-- Hold enrollment inserts while the trigger and backfill become visible together.
LOCK TABLE chat.devices IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE chat.device_promotion_audit (
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    event_kind TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_did, device_id, event_kind),
    CONSTRAINT device_promotion_audit_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id),
    CONSTRAINT device_promotion_audit_kind_check CHECK (
        event_kind IN ('pending_notice', 'recovery_promoted')
    )
);

CREATE TRIGGER device_promotion_audit_immutable
BEFORE UPDATE OR DELETE ON chat.device_promotion_audit
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE FUNCTION chat.record_pending_device_notice()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'pending_approval' THEN
        INSERT INTO chat.device_promotion_audit
            (user_did, device_id, event_kind, recorded_at)
        VALUES (NEW.user_did, NEW.device_id, 'pending_notice', clock_timestamp());
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER devices_record_pending_notice
AFTER INSERT ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.record_pending_device_notice();

INSERT INTO chat.device_promotion_audit (user_did, device_id, event_kind, recorded_at)
SELECT user_did, device_id, 'pending_notice', clock_timestamp()
  FROM chat.devices
 WHERE status = 'pending_approval' AND revoked_at IS NULL;

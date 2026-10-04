-- Never change installed slot migration bytes. The preactivation test database
-- has no published request Welcome slots; nonempty rows require an explicit
-- reviewed original-operation digest backfill, never a fabricated digest.
ALTER TABLE chat.direct_request_welcome_slots ADD COLUMN request_digest BYTEA NOT NULL
 CHECK(octet_length(request_digest)=32);
CREATE OR REPLACE FUNCTION chat.validate_direct_request_welcome_slot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_welcome_slots s
  JOIN chat.direct_request_welcome_outcomes o USING(request_id,recipient_did,recipient_device_id)
  JOIN chat.operation_claims c ON c.operation_id=s.operation_id
  JOIN chat.idempotency_records i ON i.operation_id=c.operation_id AND i.principal_did=c.principal_did AND i.endpoint_nsid=c.endpoint_nsid
  WHERE s.request_id=NEW.request_id AND s.recipient_did=NEW.recipient_did AND s.recipient_device_id=NEW.recipient_device_id
   AND c.principal_did=s.recipient_did AND c.request_digest=s.request_digest
   AND (o.status='expired' OR (o.request_digest=s.request_digest AND o.signed_request_bytes=i.accepted_request_bytes))
   AND c.endpoint_nsid IN('blue.catbird.chat.acknowledgeWelcome','blue.catbird.chat.rejectWelcome')
   AND (o.signed_request_bytes IS NULL OR octet_length(o.signed_request_bytes)<=65536)
   AND octet_length(i.response_bytes)<=65536) THEN
  RAISE EXCEPTION 'Welcome requires one bounded completed operation slot' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

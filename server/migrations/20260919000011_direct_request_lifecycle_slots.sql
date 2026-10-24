-- Precharged finite lifecycle slots. Published graphs from the prior disabled
-- rollout require explicit reviewed backfill; never fabricate their reserve.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM chat.direct_request_publications) THEN
  RAISE EXCEPTION 'existing published requests require lifecycle reserve backfill';
 END IF;
END $$;
CREATE TABLE chat.direct_request_lifecycle_reserves (
 request_id UUID PRIMARY KEY REFERENCES chat.direct_request_publications(request_id) DEFERRABLE INITIALLY DEFERRED,
 decision_bytes BIGINT NOT NULL CHECK(decision_bytes BETWEEN 4194304 AND 8589934592),
 welcome_bytes_per_delivery BIGINT NOT NULL CHECK(welcome_bytes_per_delivery=524288),
 delivery_count BIGINT NOT NULL CHECK(delivery_count BETWEEN 1 AND 39)
);
CREATE TABLE chat.direct_request_decision_slots (
 request_id UUID PRIMARY KEY REFERENCES chat.direct_request_lifecycle_reserves,
 operation_id UUID NOT NULL UNIQUE,
 decision_kind TEXT NOT NULL CHECK(decision_kind IN('accept','close')),
 charged_bytes BIGINT NOT NULL CHECK(charged_bytes>0)
);
CREATE TABLE chat.direct_request_welcome_slots (
 request_id UUID NOT NULL REFERENCES chat.direct_request_lifecycle_reserves,
 recipient_did TEXT NOT NULL,
 recipient_device_id UUID NOT NULL,
 operation_id UUID NOT NULL UNIQUE REFERENCES chat.operation_claims(operation_id) DEFERRABLE INITIALLY DEFERRED,
 charged_bytes BIGINT NOT NULL CHECK(charged_bytes BETWEEN 1 AND 524288),
 PRIMARY KEY(request_id,recipient_did,recipient_device_id),
 FOREIGN KEY(request_id,recipient_did,recipient_device_id)
  REFERENCES chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER direct_request_lifecycle_reserves_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_lifecycle_reserves
 FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_decision_slots_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_decision_slots
 FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_welcome_slots_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_welcome_slots
 FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE FUNCTION chat.validate_direct_request_lifecycle_reserve() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_lifecycle_reserves r
   JOIN chat.direct_request_retained_charges c USING(request_id)
   WHERE r.request_id=NEW.request_id
    AND r.decision_bytes+r.welcome_bytes_per_delivery*r.delivery_count<=c.charged_bytes
    AND r.delivery_count=(SELECT count(*) FROM chat.direct_request_device_deliveries d WHERE d.request_id=r.request_id)) THEN
  RAISE EXCEPTION 'published request lacks charged lifecycle reserve' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_lifecycle_reserve_provenance AFTER INSERT ON chat.direct_request_lifecycle_reserves
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_lifecycle_reserve();
CREATE CONSTRAINT TRIGGER direct_request_publication_requires_lifecycle_reserve AFTER INSERT ON chat.direct_request_publications
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_lifecycle_reserve();
CREATE FUNCTION chat.validate_direct_request_decision_slot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_decision_slots s
   JOIN chat.direct_request_lifecycle_reserves r USING(request_id)
   JOIN chat.direct_request_lifecycle l USING(request_id)
   WHERE s.request_id=NEW.request_id AND s.charged_bytes<=r.decision_bytes
    AND ((s.decision_kind='accept' AND l.accepted_at IS NOT NULL AND EXISTS(
      SELECT 1 FROM chat.direct_request_acceptance_claims a WHERE a.request_id=s.request_id AND a.operation_id=s.operation_id))
     OR (s.decision_kind='close' AND l.accepted_at IS NULL AND l.consent='closed' AND EXISTS(
      SELECT 1 FROM chat.conversations c WHERE c.conversation_id=l.conversation_id AND c.close_transition_id=s.operation_id)))) THEN
  RAISE EXCEPTION 'request decision requires one bounded matching slot' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_decision_slot_provenance AFTER INSERT ON chat.direct_request_decision_slots
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_decision_slot();
CREATE CONSTRAINT TRIGGER direct_request_lifecycle_requires_decision_slot AFTER INSERT ON chat.direct_request_lifecycle
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_decision_slot();
CREATE FUNCTION chat.validate_direct_request_welcome_slot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_welcome_slots s
  JOIN chat.direct_request_welcome_outcomes o USING(request_id,recipient_did,recipient_device_id)
  JOIN chat.operation_claims c ON c.operation_id=s.operation_id
  JOIN chat.idempotency_records i ON i.operation_id=c.operation_id AND i.principal_did=c.principal_did AND i.endpoint_nsid=c.endpoint_nsid
  WHERE s.request_id=NEW.request_id AND s.recipient_did=NEW.recipient_did AND s.recipient_device_id=NEW.recipient_device_id
   AND c.principal_did=s.recipient_did AND c.endpoint_nsid IN('blue.catbird.chat.acknowledgeWelcome','blue.catbird.chat.rejectWelcome')
   AND (o.signed_request_bytes IS NULL OR octet_length(o.signed_request_bytes)<=65536)
   AND octet_length(i.response_bytes)<=65536) THEN
  RAISE EXCEPTION 'Welcome requires one bounded completed operation slot' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_welcome_slot_provenance AFTER INSERT ON chat.direct_request_welcome_slots
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_welcome_slot();
CREATE CONSTRAINT TRIGGER direct_request_welcome_requires_slot AFTER INSERT ON chat.direct_request_welcome_outcomes
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_welcome_slot();

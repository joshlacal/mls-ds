-- A direct-request publication already creates one immutable conversation event
-- and one notification outbox row in the publication transaction. Bind those
-- rows to the generic request-push identity and its exact recipient devices.

ALTER TABLE chat.events
    ADD CONSTRAINT events_event_id_position_uq UNIQUE(event_id,event_position);
ALTER TABLE chat.outbox
    ADD CONSTRAINT outbox_id_position_uq UNIQUE(outbox_id,event_position);
ALTER TABLE chat.direct_request_publications
    ADD CONSTRAINT direct_request_publications_push_identity_uq
    UNIQUE(request_id,conversation_id,first_message_id);

CREATE FUNCTION chat.direct_request_push_payload_digest(
    target_event UUID,
    target_request UUID,
    target_conversation UUID,
    target_first_message UUID,
    target_sender TEXT,
    target_recipient TEXT,
    target_devices UUID[]
) RETURNS BYTEA LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    transcript BYTEA := convert_to('CATBIRD-DIRECT-REQUEST-PUSH-EVENT','UTF8')
        || decode('00','hex');
    value TEXT;
    device UUID;
BEGIN
    IF cardinality(target_devices) NOT BETWEEN 1 AND 20
       OR target_sender=target_recipient
       OR target_devices IS DISTINCT FROM (
           SELECT array_agg(item ORDER BY item::text) FROM unnest(target_devices) item
       )
       OR cardinality(target_devices) <> (
           SELECT count(DISTINCT item) FROM unnest(target_devices) item
       ) THEN
        RAISE EXCEPTION 'invalid direct request push transcript' USING ERRCODE='23514';
    END IF;
    FOREACH value IN ARRAY ARRAY[
        'did:web:chat.catbird.blue',target_event::text,target_request::text,
        target_conversation::text,target_first_message::text,target_sender,target_recipient
    ] LOOP
        transcript := transcript || int4send(octet_length(convert_to(value,'UTF8')))
            || convert_to(value,'UTF8');
    END LOOP;
    transcript := transcript || int4send(cardinality(target_devices));
    FOREACH device IN ARRAY target_devices LOOP
        value := device::text;
        transcript := transcript || int4send(octet_length(convert_to(value,'UTF8')))
            || convert_to(value,'UTF8');
    END LOOP;
    RETURN digest(transcript,'sha256');
END $$;

CREATE TABLE chat.direct_request_push_events (
    event_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    event_position BIGINT NOT NULL UNIQUE,
    outbox_id UUID NOT NULL UNIQUE,
    conversation_id UUID NOT NULL,
    first_message_id UUID NOT NULL,
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    payload_digest BYTEA NOT NULL CHECK(octet_length(payload_digest)=32),
    created_at TIMESTAMPTZ NOT NULL,
    CHECK(chat.is_uuid_v4(event_id) AND chat.is_uuid_v4(request_id)
      AND chat.is_uuid_v4(outbox_id) AND chat.is_uuid_v4(conversation_id)
      AND chat.is_uuid_v4(first_message_id)),
    CHECK(chat.is_bare_did(sender_did) AND chat.is_bare_did(recipient_did)
      AND sender_did<>recipient_did),
    UNIQUE(event_id,request_id,recipient_did),
    FOREIGN KEY(event_id,event_position)
        REFERENCES chat.events(event_id,event_position),
    FOREIGN KEY(outbox_id,event_position)
        REFERENCES chat.outbox(outbox_id,event_position),
    FOREIGN KEY(request_id,conversation_id,first_message_id)
        REFERENCES chat.direct_request_publications(request_id,conversation_id,first_message_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE chat.direct_request_push_event_recipients (
    event_id UUID NOT NULL,
    request_id UUID NOT NULL,
    recipient_did TEXT NOT NULL,
    recipient_device_id UUID NOT NULL,
    PRIMARY KEY(event_id,recipient_device_id),
    FOREIGN KEY(event_id,request_id,recipient_did)
        REFERENCES chat.direct_request_push_events(event_id,request_id,recipient_did)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(request_id,recipient_did,recipient_device_id)
        REFERENCES chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK(chat.is_uuid_v4(event_id) AND chat.is_uuid_v4(request_id)
      AND chat.is_uuid_v4(recipient_device_id) AND chat.is_bare_did(recipient_did))
);

-- Backfill any pre-migration local/canary publications from the exact event and
-- notification rows that committed at the publication's trusted timestamp.
WITH candidate AS (
    SELECT p.request_id,p.conversation_id,p.first_message_id,p.actor_did,p.recipient_did,
           p.created_at,e.event_id,e.event_position,o.outbox_id,
           array_agg(d.owner_device_id ORDER BY d.owner_device_id::text) AS devices
      FROM chat.direct_request_publications p
      JOIN chat.events e ON e.event_kind='conversationChanged'
       AND e.created_at=p.created_at
       AND convert_from(e.payload_bytes,'UTF8')::jsonb->>'conversationId'=p.conversation_id::text
      JOIN chat.outbox o ON o.event_position=e.event_position AND o.work_kind='notification'
      JOIN chat.direct_request_device_deliveries d
        ON d.request_id=p.request_id AND d.owner_did=p.recipient_did
     GROUP BY p.request_id,p.conversation_id,p.first_message_id,p.actor_did,p.recipient_did,
              p.created_at,e.event_id,e.event_position,o.outbox_id
)
INSERT INTO chat.direct_request_push_events(
    event_id,request_id,event_position,outbox_id,conversation_id,first_message_id,
    sender_did,recipient_did,payload_digest,created_at
)
SELECT event_id,request_id,event_position,outbox_id,conversation_id,first_message_id,
       actor_did,recipient_did,
       chat.direct_request_push_payload_digest(event_id,request_id,conversation_id,
           first_message_id,actor_did,recipient_did,devices),created_at
  FROM candidate;

INSERT INTO chat.direct_request_push_event_recipients(
    event_id,request_id,recipient_did,recipient_device_id
)
SELECT e.event_id,e.request_id,e.recipient_did,d.owner_device_id
  FROM chat.direct_request_push_events e
  JOIN chat.direct_request_device_deliveries d
    ON d.request_id=e.request_id AND d.owner_did=e.recipient_did
 ORDER BY e.event_id,d.owner_device_id;

CREATE TRIGGER direct_request_push_events_immutable
    BEFORE UPDATE OR DELETE ON chat.direct_request_push_events
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_push_event_recipients_immutable
    BEFORE UPDATE OR DELETE ON chat.direct_request_push_event_recipients
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

CREATE FUNCTION chat.assert_direct_request_push_event(target_request UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    publication chat.direct_request_publications%ROWTYPE;
    push_event chat.direct_request_push_events%ROWTYPE;
    devices UUID[];
BEGIN
    SELECT * INTO publication FROM chat.direct_request_publications
     WHERE request_id=target_request FOR UPDATE;
    SELECT * INTO push_event FROM chat.direct_request_push_events
     WHERE request_id=target_request FOR UPDATE;
    IF publication.request_id IS NULL AND push_event.request_id IS NULL THEN RETURN; END IF;
    IF publication.request_id IS NULL OR push_event.request_id IS NULL THEN
        RAISE EXCEPTION 'direct request publication push mapping missing' USING ERRCODE='23514';
    END IF;
    SELECT array_agg(recipient_device_id ORDER BY recipient_device_id::text)
      INTO devices FROM chat.direct_request_push_event_recipients
     WHERE event_id=push_event.event_id;
    IF (push_event.conversation_id,push_event.first_message_id,push_event.sender_did,
        push_event.recipient_did,push_event.created_at)
       IS DISTINCT FROM
       (publication.conversation_id,publication.first_message_id,publication.actor_did,
        publication.recipient_did,publication.created_at)
       OR NOT EXISTS(SELECT 1 FROM chat.events event
            WHERE (event.event_id,event.event_position,event.event_kind,event.created_at)
                =(push_event.event_id,push_event.event_position,'conversationChanged',push_event.created_at)
              AND convert_from(event.payload_bytes,'UTF8')::jsonb->>'conversationId'
                    =push_event.conversation_id::text)
       OR NOT EXISTS(SELECT 1 FROM chat.outbox work
            WHERE (work.outbox_id,work.event_position,work.work_kind)
                =(push_event.outbox_id,push_event.event_position,'notification'))
       OR devices IS NULL
       OR cardinality(devices) NOT BETWEEN 1 AND 20
       OR (SELECT count(*) FROM chat.direct_request_device_deliveries delivery
            WHERE delivery.request_id=target_request
              AND delivery.owner_did=publication.recipient_did) <> cardinality(devices)
       OR EXISTS(SELECT 1 FROM chat.direct_request_device_deliveries delivery
            WHERE delivery.request_id=target_request
              AND delivery.owner_did=publication.recipient_did
              AND NOT delivery.owner_device_id=ANY(devices))
       OR push_event.payload_digest IS DISTINCT FROM chat.direct_request_push_payload_digest(
            push_event.event_id,push_event.request_id,push_event.conversation_id,
            push_event.first_message_id,push_event.sender_did,push_event.recipient_did,devices)
    THEN RAISE EXCEPTION 'direct request push event graph mismatch' USING ERRCODE='23514'; END IF;
END $$;

CREATE FUNCTION chat.enforce_direct_request_push_event() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE target UUID;
BEGIN
    target:=CASE WHEN TG_OP='DELETE' THEN OLD.request_id ELSE NEW.request_id END;
    PERFORM chat.assert_direct_request_push_event(target);
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_publication_push_event
    AFTER INSERT OR UPDATE OR DELETE ON chat.direct_request_publications
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION chat.enforce_direct_request_push_event();
CREATE CONSTRAINT TRIGGER direct_request_push_event_complete
    AFTER INSERT OR UPDATE OR DELETE ON chat.direct_request_push_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION chat.enforce_direct_request_push_event();
CREATE CONSTRAINT TRIGGER direct_request_push_event_recipient_complete
    AFTER INSERT OR UPDATE OR DELETE ON chat.direct_request_push_event_recipients
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION chat.enforce_direct_request_push_event();

-- Exact pre-send policy checks always collect fresh bilateral block evidence.
-- The distinct operation identity prevents cached acceptance evidence from
-- becoming push authority.
ALTER TABLE chat.relationship_projection_snapshots
    DROP CONSTRAINT relationship_projection_snapshots_scope_check;
ALTER TABLE chat.relationship_projection_snapshots
    ADD CONSTRAINT relationship_projection_snapshots_scope_check CHECK(
        operation_scope IN ('creation','pendingAdd','acceptance','recoveryReservation',
          'recoveryFulfillment','traffic','directRequestPreparation',
          'directRequestAcceptance','directRequestPushEligibility'));

CREATE FUNCTION chat.assert_direct_request_push_relationship_projection(target UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM chat.relationship_projection_snapshots snapshot
               WHERE snapshot.projection_id=target
                 AND snapshot.operation_scope='directRequestPushEligibility')
       AND EXISTS(SELECT 1 FROM chat.relationship_projection_declarations declaration
                   WHERE declaration.projection_id=target) THEN
        RAISE EXCEPTION 'direct request push eligibility accepts block evidence only'
          USING ERRCODE='23514';
    END IF;
END $$;
CREATE FUNCTION chat.enforce_direct_request_push_relationship_projection()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE target UUID;
BEGIN
    target:=CASE WHEN TG_OP='DELETE' THEN OLD.projection_id ELSE NEW.projection_id END;
    PERFORM chat.assert_direct_request_push_relationship_projection(target);
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_push_relationship_snapshot
    AFTER INSERT OR UPDATE OR DELETE ON chat.relationship_projection_snapshots
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION chat.enforce_direct_request_push_relationship_projection();
CREATE CONSTRAINT TRIGGER direct_request_push_relationship_declaration
    AFTER INSERT OR UPDATE OR DELETE ON chat.relationship_projection_declarations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION chat.enforce_direct_request_push_relationship_projection();

DO $$
DECLARE target_request UUID;
BEGIN
    FOR target_request IN SELECT request_id FROM chat.direct_request_publications ORDER BY request_id
    LOOP
        PERFORM chat.assert_direct_request_push_event(target_request);
    END LOOP;
END $$;

-- Logical retained artifacts, not PostgreSQL heap/index/WAL capacity.
-- This rollout has never admitted production version-two publications. Refuse
-- to guess the charge for any pre-ledger published graph.
DO $$ BEGIN
  IF EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE status='published') THEN
    RAISE EXCEPTION 'published requests require reviewed retained-artifact backfill';
  END IF;
END $$;
ALTER TABLE chat.direct_request_attempts DROP CONSTRAINT direct_request_attempts_reserved_bytes_check;
ALTER TABLE chat.direct_request_attempts ADD CONSTRAINT direct_request_attempts_reserved_bytes_check
  CHECK(reserved_bytes BETWEEN 0 AND 8589934592);
ALTER TABLE chat.direct_request_pending_releases DROP CONSTRAINT direct_request_pending_releases_released_bytes_check;
ALTER TABLE chat.direct_request_pending_releases ADD CONSTRAINT direct_request_pending_releases_released_bytes_check
  CHECK(released_bytes BETWEEN 0 AND 8589934592);
CREATE TABLE chat.direct_request_retained_charges (
  request_id UUID PRIMARY KEY REFERENCES chat.direct_request_attempts(request_id),
  charged_bytes BIGINT NOT NULL CHECK(charged_bytes BETWEEN 1 AND 8589934592),
  model_version INTEGER NOT NULL CHECK(model_version=1),
  recorded_at TIMESTAMPTZ NOT NULL
);
-- Existing non-publication tombstones retain exactly their blob lengths plus
-- the same 16KiB bounded-row allowance used by the writer. Historical attempt
-- bytes remain immutable; the new ledger supplies their retained charge.
INSERT INTO chat.direct_request_retained_charges(request_id,charged_bytes,model_version,recorded_at)
 SELECT request_id,COALESCE(octet_length(prepare_response),0)+octet_length(terminal_response)
   +(2+(SELECT count(*) FROM chat.direct_request_selected_devices s WHERE s.request_id=a.request_id))*16384,
   1,terminal_at FROM chat.direct_request_attempts a WHERE status<>'prepared';
UPDATE chat.direct_request_budget SET retained_bytes=
  COALESCE((SELECT sum(reserved_bytes) FROM chat.direct_request_attempts WHERE status='prepared'),0)
  +COALESCE((SELECT sum(charged_bytes) FROM chat.direct_request_retained_charges),0)
 WHERE singleton;
CREATE TRIGGER direct_request_retained_charges_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_retained_charges
 FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE FUNCTION chat.validate_direct_request_retained_charge() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE target UUID;
BEGIN
 target:=NEW.request_id;
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_attempts a
   JOIN chat.direct_request_retained_charges c USING(request_id)
   WHERE a.request_id=target AND a.status<>'prepared' AND a.reserved_bytes=c.charged_bytes
     AND a.terminal_at=c.recorded_at AND c.model_version=1) THEN
   RAISE EXCEPTION 'terminal request requires immutable matching retained charge' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER direct_request_retained_charge_provenance AFTER INSERT ON chat.direct_request_retained_charges
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_retained_charge();
CREATE CONSTRAINT TRIGGER direct_request_terminal_retained_charge AFTER INSERT OR UPDATE ON chat.direct_request_attempts
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.status<>'prepared')
 EXECUTE FUNCTION chat.validate_direct_request_retained_charge();

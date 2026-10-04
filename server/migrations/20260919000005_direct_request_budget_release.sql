-- Consent releases pending admission pressure, never retained ciphertext.
-- The gross counter is bounded by retained storage; the immutable release
-- ledger makes the effective pending count safe without reversing lock order.
ALTER TABLE chat.direct_request_budget DROP CONSTRAINT direct_request_budget_pending_bytes_check;
ALTER TABLE chat.direct_request_budget ADD CONSTRAINT direct_request_budget_pending_bytes_check
    CHECK (pending_bytes BETWEEN 0 AND 8589934592);
CREATE TABLE chat.direct_request_pending_releases (
    request_id UUID PRIMARY KEY REFERENCES chat.direct_request_lifecycle(request_id),
    released_bytes BIGINT NOT NULL CHECK(released_bytes BETWEEN 0 AND 8388608),
    released_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN('accepted','closed'))
);
CREATE TRIGGER direct_request_pending_releases_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_pending_releases
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE FUNCTION chat.validate_direct_request_pending_release() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM chat.direct_request_attempts a JOIN chat.direct_request_lifecycle l USING(request_id)
        WHERE a.request_id=NEW.request_id AND a.status='published'
          AND a.reserved_bytes=NEW.released_bytes
          AND ((NEW.reason='accepted' AND l.accepted_at=NEW.released_at)
            OR (NEW.reason='closed' AND l.consent='closed' AND l.closed_at=NEW.released_at))
    ) THEN RAISE EXCEPTION 'pending release must match committed request consent' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER direct_request_pending_release_provenance BEFORE INSERT ON chat.direct_request_pending_releases
    FOR EACH ROW EXECUTE FUNCTION chat.validate_direct_request_pending_release();
CREATE VIEW chat.direct_request_effective_budget AS
    SELECT b.singleton,
           b.pending_bytes-COALESCE((SELECT sum(released_bytes) FROM chat.direct_request_pending_releases),0)::bigint AS pending_bytes,
           b.retained_bytes
      FROM chat.direct_request_budget b;

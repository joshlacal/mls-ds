-- Migration 20260919000021: Direct Request Capacity Abuse Fix
-- Addresses F1 quota DoS: pending never releases for published requests,
-- missing count-based outbound/inbound quota separation, no published-request
-- expiry, no artifact pruning. See docs/design-docs/2026-09-23-request-capacity-abuse-fix.md.

-- 0. Preflight: refuse to guess for a graph this rollout never created.
DO $$ BEGIN
  IF EXISTS(SELECT 1 FROM chat.direct_request_lifecycle WHERE consent NOT IN ('accepted','closed')) THEN
    RAISE EXCEPTION 'unexpected direct request consent state requires reviewed backfill';
  END IF;
END $$;

-- 1. Lifecycle: distinct 'expired' consent with its own timestamp.
--    Only the consent enum must change: direct_request_lifecycle_check2
--    ((consent='closed')=(closed_at IS NOT NULL)) still holds for 'expired'
--    (closed_at stays NULL), and direct_request_lifecycle_check /
--    _check1 (acceptance-proof shape) are untouched because expiry never
--    carries an acceptance proof.
--    Expiry is an INSERT (a lifecycle row exists only after a decision), which
--    is exactly what chat.guard_direct_request_lifecycle requires: that trigger
--    is BEFORE DELETE OR UPDATE and explicitly forbids accepted -> expired.
ALTER TABLE chat.direct_request_lifecycle DROP CONSTRAINT direct_request_lifecycle_consent_check;
ALTER TABLE chat.direct_request_lifecycle ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ;
ALTER TABLE chat.direct_request_lifecycle ADD CONSTRAINT direct_request_lifecycle_consent_check
    CHECK (consent IN ('accepted','closed','expired'));
ALTER TABLE chat.direct_request_lifecycle ADD CONSTRAINT direct_request_lifecycle_expiry_shape CHECK (
    (consent <> 'expired') OR (accepted_at IS NULL AND closed_at IS NULL AND expired_at IS NOT NULL)
);

-- 2. Ledgers for the expiry receipt and the released retained bytes. Created
--    before the trigger function below, which references the expiry table.
CREATE TABLE IF NOT EXISTS chat.direct_request_expiry_receipts (
    request_id UUID PRIMARY KEY REFERENCES chat.direct_request_lifecycle(request_id),
    operation_id UUID NOT NULL UNIQUE,
    signed_receipt BYTEA NOT NULL CHECK (octet_length(signed_receipt) > 0),
    receipt_sha256 BYTEA NOT NULL CHECK (receipt_sha256 = digest(signed_receipt,'sha256')),
    expired_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS chat.direct_request_retained_releases (
    request_id UUID PRIMARY KEY REFERENCES chat.direct_request_attempts(request_id),
    released_bytes BIGINT NOT NULL CHECK (released_bytes BETWEEN 1 AND 8589934592),
    released_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('closed_pruned','expired_pruned'))
);
CREATE TRIGGER direct_request_expiry_receipts_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_expiry_receipts
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();
CREATE TRIGGER direct_request_retained_releases_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_retained_releases
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- 3. Decision slots: add the server-owned expiry arm. Expiry carries no client
--    operation claim, so bind it to the request's own signed expiry receipt.
ALTER TABLE chat.direct_request_decision_slots DROP CONSTRAINT direct_request_decision_slots_decision_kind_check;
ALTER TABLE chat.direct_request_decision_slots ADD CONSTRAINT direct_request_decision_slots_decision_kind_check
    CHECK (decision_kind IN ('accept','close','expire'));
CREATE OR REPLACE FUNCTION chat.validate_direct_request_decision_slot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM chat.direct_request_decision_slots s
   JOIN chat.direct_request_lifecycle_reserves r USING(request_id)
   JOIN chat.direct_request_lifecycle l USING(request_id)
   WHERE s.request_id=NEW.request_id AND s.charged_bytes<=r.decision_bytes
    AND ((s.decision_kind='accept' AND l.accepted_at IS NOT NULL AND EXISTS(
      SELECT 1 FROM chat.direct_request_acceptance_claims a WHERE a.request_id=s.request_id AND a.operation_id=s.operation_id))
     OR (s.decision_kind='close' AND l.accepted_at IS NULL AND l.consent='closed' AND EXISTS(
      SELECT 1 FROM chat.conversations c WHERE c.conversation_id=l.conversation_id AND c.close_transition_id=s.operation_id))
     OR (s.decision_kind='expire' AND l.consent='expired' AND EXISTS(
      SELECT 1 FROM chat.direct_request_expiry_receipts e WHERE e.request_id=s.request_id AND e.operation_id=s.operation_id)))) THEN
  RAISE EXCEPTION 'request decision requires one bounded matching slot' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

-- 4. Budget: pending becomes preparation-only, and retained gains its release
--    ledger. The base counter is maintained incrementally by the writer, so the
--    view just exposes the released-retained figure.
--
--    One-time backfill: rows published before this migration carry their full
--    publication charge in pending_bytes, which is exactly the defect. Recompute
--    gross pending from live preparations only. (Migrations 10/11 refuse to run
--    against a pre-ledger published graph, so every published row here has a
--    matching retained charge and is safe to move.)
UPDATE chat.direct_request_budget SET pending_bytes =
    COALESCE((SELECT sum(reserved_bytes) FROM chat.direct_request_attempts WHERE status='prepared'),0)
 WHERE singleton;
CREATE OR REPLACE VIEW chat.direct_request_effective_budget AS
    SELECT b.singleton,
           b.pending_bytes,
           b.retained_bytes
             - COALESCE((SELECT sum(released_bytes) FROM chat.direct_request_retained_releases),0)::bigint AS retained_bytes
      FROM chat.direct_request_budget b;
-- The pending bound itself is enforced in direct_request_store.rs against
-- status='prepared' rows; direct_request_pending_releases rows stay as immutable
-- historical evidence and are no longer read by admission or terminal charge.

-- 5. Prunable artifact columns: relax the byte-range CHECKs (they are written
--    as octet_length(col) >= n, so NULL would violate them), then make exactly
--    those columns mutable on the existing immutability triggers.
--    The *_sha256 commitment CHECKs (direct_request_publications_check1..5) are
--    deliberately LEFT IN PLACE: digest(NULL) is NULL, so a NULL digest column
--    still satisfies "sha256 = digest(col,'sha256')", and the stored digest for
--    a pruned blob survives as evidence of what was removed.
ALTER TABLE chat.direct_request_publications
    DROP CONSTRAINT direct_request_publications_signed_publication_check,
    DROP CONSTRAINT direct_request_publications_request_entry_check,
    DROP CONSTRAINT direct_request_publications_final_group_info_check,
    DROP CONSTRAINT direct_request_publications_full_welcome_check,
    DROP CONSTRAINT direct_request_publications_initial_ciphertext_check,
    DROP CONSTRAINT direct_request_publications_metadata_snapshot_check;
ALTER TABLE chat.direct_request_publications ALTER COLUMN signed_publication   DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ALTER COLUMN request_entry        DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ALTER COLUMN final_group_info     DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ALTER COLUMN full_welcome         DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ALTER COLUMN initial_ciphertext   DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ALTER COLUMN metadata_snapshot    DROP NOT NULL;
ALTER TABLE chat.direct_request_publications ADD COLUMN IF NOT EXISTS pruned_at TIMESTAMPTZ;
ALTER TABLE chat.direct_request_publications ADD CONSTRAINT direct_request_publications_prune_shape CHECK (
    (pruned_at IS NULL AND signed_publication IS NOT NULL AND request_entry IS NOT NULL
     AND final_group_info IS NOT NULL AND full_welcome IS NOT NULL
     AND initial_ciphertext IS NOT NULL AND metadata_snapshot IS NOT NULL)
 OR (pruned_at IS NOT NULL AND signed_publication IS NULL AND request_entry IS NULL
     AND final_group_info IS NULL AND full_welcome IS NULL
     AND initial_ciphertext IS NULL AND metadata_snapshot IS NULL)
);
DROP TRIGGER direct_request_publications_immutable ON chat.direct_request_publications;
CREATE TRIGGER direct_request_publications_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_publications
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
        'signed_publication','request_entry','final_group_info','full_welcome',
        'initial_ciphertext','metadata_snapshot','pruned_at'
    );
ALTER TABLE chat.direct_request_device_deliveries
    DROP CONSTRAINT direct_request_device_deliveries_provenance_check;
ALTER TABLE chat.direct_request_device_deliveries ALTER COLUMN provenance DROP NOT NULL;
ALTER TABLE chat.direct_request_device_deliveries ADD CONSTRAINT direct_request_device_deliveries_provenance_check
    CHECK (provenance IS NULL OR (octet_length(provenance) >= 1 AND octet_length(provenance) <= 8388608));
DROP TRIGGER direct_request_device_deliveries_immutable ON chat.direct_request_device_deliveries;
CREATE TRIGGER direct_request_device_deliveries_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_device_deliveries
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity('provenance');

-- 6. Indexes for both sweeps.
CREATE INDEX IF NOT EXISTS direct_request_unanswered_sweep_idx
    ON chat.direct_request_publications(created_at);
CREATE INDEX IF NOT EXISTS direct_request_terminal_prune_idx
    ON chat.direct_request_lifecycle(COALESCE(closed_at, expired_at));

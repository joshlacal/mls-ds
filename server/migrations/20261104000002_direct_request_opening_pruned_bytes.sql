-- O7 accounting for 20261103000010. An opening pruned before its request's
-- terminal prune clears three charged publication columns early. This records
-- exactly how many bytes that prune removed, so the terminal prune
-- (`prune_terminal_request_artifacts`) still releases every byte the
-- publication was charged for. The trigger sets the count in the prune's own
-- update, from the columns being cleared, whatever the caller wrote; it never
-- changes afterwards. Openings pruned before this migration keep NULL: their
-- cleared sizes are no longer known, and only pre-release databases have them.

ALTER TABLE chat.direct_request_publications ADD COLUMN opening_pruned_bytes BIGINT;

ALTER TABLE chat.direct_request_publications
    ADD CONSTRAINT direct_request_publications_opening_pruned_bytes CHECK (
        opening_pruned_bytes IS NULL
        OR (opening_pruned_at IS NOT NULL AND opening_pruned_bytes >= 0)
    );

DROP TRIGGER direct_request_publications_immutable ON chat.direct_request_publications;
CREATE TRIGGER direct_request_publications_immutable BEFORE UPDATE OR DELETE ON chat.direct_request_publications
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
        'signed_publication','request_entry','final_group_info','full_welcome',
        'initial_ciphertext','metadata_snapshot','pruned_at','opening_pruned_at',
        'opening_pruned_bytes'
    );

-- Fires before `direct_request_publications_immutable` (trigger names sort), so
-- the identity check sees the recorded count.
CREATE OR REPLACE FUNCTION chat.enforce_direct_request_artifacts_never_return()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (NEW.signed_publication IS NOT NULL AND NEW.signed_publication IS DISTINCT FROM OLD.signed_publication)
       OR (NEW.request_entry IS NOT NULL AND NEW.request_entry IS DISTINCT FROM OLD.request_entry)
       OR (NEW.final_group_info IS NOT NULL AND NEW.final_group_info IS DISTINCT FROM OLD.final_group_info)
       OR (NEW.full_welcome IS NOT NULL AND NEW.full_welcome IS DISTINCT FROM OLD.full_welcome)
       OR (NEW.initial_ciphertext IS NOT NULL AND NEW.initial_ciphertext IS DISTINCT FROM OLD.initial_ciphertext)
       OR (NEW.metadata_snapshot IS NOT NULL AND NEW.metadata_snapshot IS DISTINCT FROM OLD.metadata_snapshot)
       OR (OLD.pruned_at IS NOT NULL AND NEW.pruned_at IS DISTINCT FROM OLD.pruned_at)
       OR (OLD.opening_pruned_at IS NOT NULL AND NEW.opening_pruned_at IS DISTINCT FROM OLD.opening_pruned_at) THEN
        RAISE EXCEPTION 'pruned direct request artifacts never return' USING ERRCODE = '23514';
    END IF;
    IF OLD.opening_pruned_at IS NULL AND NEW.opening_pruned_at IS NOT NULL THEN
        NEW.opening_pruned_bytes := COALESCE(octet_length(OLD.signed_publication), 0)
            + COALESCE(octet_length(OLD.request_entry), 0)
            + COALESCE(octet_length(OLD.initial_ciphertext), 0);
    ELSIF NEW.opening_pruned_bytes IS DISTINCT FROM OLD.opening_pruned_bytes THEN
        RAISE EXCEPTION 'a pruned opening records its byte count once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

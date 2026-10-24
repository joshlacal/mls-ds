-- Migration: Labyrinth 1.1 storage backend, part 7 — attachment references
-- pin their blob against chat object GC (design §4 "Attachment refs pin
-- their blob"; gap audit 7.1).
--
-- A blob with a live labyrinth.attachment_refs row keeps its stored object:
-- chat.claim_blob_object_gc skips it while the reference exists and claims
-- it again (its object_gc_after has long passed) once the last reference is
-- deleted (deleteAttachmentRef, redaction, purge). The Rust GC worker
-- (handlers::chat::expiry_worker) applies the same predicate.
--
-- Race: putAttachmentRef locks the blob row FOR SHARE and its FK takes a
-- key-share lock; GC claims rows FOR UPDATE SKIP LOCKED and re-checks the
-- pin in a fresh statement after locking, so a reference committed between
-- the claim's snapshot and its lock is still seen.

CREATE FUNCTION labyrinth.blob_object_pinned(target UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (SELECT 1 FROM labyrinth.attachment_refs WHERE blob_id = target)
$$;

CREATE OR REPLACE FUNCTION chat.claim_blob_object_gc(batch_limit INTEGER)
RETURNS TABLE (blob_id UUID, object_store_key TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    candidate RECORD;
BEGIN
    FOR candidate IN
        SELECT c.blob_id AS claimed_blob_id, c.object_store_key AS claimed_store_key
          FROM chat.blobs c
         WHERE c.object_gc_status = 'pending'
           AND c.object_gc_after <= clock_timestamp()
           AND NOT labyrinth.blob_object_pinned(c.blob_id)
         ORDER BY c.object_gc_after
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
    LOOP
        -- Fresh snapshot: a reference that committed after the claim's
        -- snapshot (and before our row lock) still pins the object.
        CONTINUE WHEN EXISTS (
            SELECT 1 FROM labyrinth.attachment_refs r
             WHERE r.blob_id = candidate.claimed_blob_id
        );
        UPDATE chat.blobs b
           SET object_gc_status = 'reclaimed',
               object_store_key = NULL,
               object_deleted_at = clock_timestamp()
         WHERE b.blob_id = candidate.claimed_blob_id;
        blob_id := candidate.claimed_blob_id;
        object_store_key := candidate.claimed_store_key;
        RETURN NEXT;
    END LOOP;
END
$$;

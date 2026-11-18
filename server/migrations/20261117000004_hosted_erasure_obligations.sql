-- Mark only jobs enqueued inside a specific authenticated erasure transaction.
-- Pre-migration work has unknown provenance. Disappearing rows never prove closure.
ALTER TABLE public.outbound_queue ADD COLUMN erasure_operation_digest bytea
    CHECK (octet_length(erasure_operation_digest) = 32);
ALTER TABLE public.outbound_queue ALTER COLUMN erasure_operation_digest SET DEFAULT
    decode(nullif(current_setting('catbird.erasure_operation', true), ''), 'hex');
CREATE INDEX outbound_queue_pending_erasure_idx
    ON public.outbound_queue (erasure_operation_digest)
    WHERE erasure_operation_digest IS NOT NULL AND status IN ('pending', 'in_flight');

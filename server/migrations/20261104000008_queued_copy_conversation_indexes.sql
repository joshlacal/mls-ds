-- O7 for queued copies: every prune of an application entry's ciphertext drops,
-- in its own transaction, the entry's outbound queue and federation outbox rows
-- that no ordered delivery needs (repository/delivery.rs
-- `drop_queued_entry_copies`), found by conversation. 20260824000005 dropped the
-- outbound queue's conversation index and the federation outbox never had one,
-- so each of those prunes, and every close wipe, would scan a whole queue.
CREATE INDEX IF NOT EXISTS idx_outbound_queue_convo ON public.outbound_queue (convo_id);
CREATE INDEX IF NOT EXISTS idx_federation_outbox_conversation
    ON public.federation_outbox (conversation_id);

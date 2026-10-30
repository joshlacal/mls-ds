-- Migration: Labyrinth 1.1 storage backend, part 8 — lookup indexes
-- (whitepaper "Database Abstraction": lookup by inbox, by thread, by message
-- id and by time range).
--
-- - listBatches / listOwnerBatches page in seq order either way (the
--   existing (conversation_id, seq) / (owner_did, thread_id, seq) indexes
--   serve both directions) and filter by server receivedAt (since/until);
--   these indexes serve a narrow received window directly.
-- - listThreads lists a reader's conversations from the MEKs it wrote and
--   the MEKs addressed to it; the existing indexes lead with
--   conversation_id, so the reader-first scans need their own.
-- - getMessages uses batch_items_message_idx (part 5); listOwnerThreads
--   uses owner_batches_thread_idx (part 1).

CREATE INDEX batches_received_idx
    ON labyrinth.batches (conversation_id, received_at);

CREATE INDEX owner_batches_received_idx
    ON labyrinth.owner_batches (owner_did, thread_id, received_at);

CREATE INDEX mek_recipients_thread_list_idx
    ON labyrinth.mek_recipients (recipient_did, conversation_id);

CREATE INDEX meks_author_thread_list_idx
    ON labyrinth.meks (author_did, conversation_id);

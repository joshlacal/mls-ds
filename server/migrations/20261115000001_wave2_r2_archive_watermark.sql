-- Migration: Wave 2 R2 (`B1`) attested Space archive watermark on `chat.conversation_spaces`
-- and per-batch verified sequence tracking on `chat.conversation_space_records`.
-- Additive forward migration on top of `20261114000001_wave2_multidevice_and_spaces_nov12.sql` (zero DROP TABLE).

ALTER TABLE chat.conversation_spaces
    ADD COLUMN IF NOT EXISTS archived_through_seq BIGINT NOT NULL DEFAULT 0
        CONSTRAINT conversation_spaces_archived_through_seq_check
        CHECK (chat.is_safe_integer(archived_through_seq) AND archived_through_seq >= 0);

ALTER TABLE chat.conversation_space_records
    ADD COLUMN IF NOT EXISTS archived_seqs BIGINT[] NOT NULL DEFAULT '{}';

-- Migration: Clean Chat Federation Routing Columns, Constraints, and Indexes
-- Target: chat.conversations and chat.participants (never legacy public tables)

ALTER TABLE chat.conversations
    ADD COLUMN is_remote BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN sequencer_ds TEXT,
    ADD COLUMN sequencer_term BIGINT NOT NULL DEFAULT 0;

ALTER TABLE chat.conversations
    ADD CONSTRAINT conversations_is_remote_shape_check
        CHECK (
            (NOT is_remote AND sequencer_ds IS NULL)
            OR (is_remote AND sequencer_ds IS NOT NULL AND chat.is_bare_did(sequencer_ds))
        ),
    ADD CONSTRAINT conversations_sequencer_term_check
        CHECK (
            chat.is_safe_integer(sequencer_term) AND sequencer_term >= 0
        );

CREATE INDEX conversations_remote_sequencer_idx
    ON chat.conversations (sequencer_ds, sequencer_term)
    WHERE is_remote;

ALTER TABLE chat.participants
    ADD COLUMN ds_did TEXT;

ALTER TABLE chat.participants
    ADD CONSTRAINT participants_ds_did_check
        CHECK (
            ds_did IS NULL OR chat.is_bare_did(ds_did)
        );

CREATE INDEX participants_remote_ds_idx
    ON chat.participants (ds_did)
    WHERE current_membership AND ds_did IS NOT NULL;

-- Migration: Validate Historical Bootstrap Cutoff Constraint
-- Target: chat.conversations (conversations_historical_bootstrap_last_seq_check)

SET LOCAL lock_timeout = '2s';

ALTER TABLE chat.conversations
    VALIDATE CONSTRAINT conversations_historical_bootstrap_last_seq_check;

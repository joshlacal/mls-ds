-- Migration: per-device application send order (StaleSend).
--
-- A sequencer resolving a messageId for the first time accepts it only if its
-- signed (prior.generation, prior.epoch, sendCounter) is lexicographically
-- greater than the actor device's last accepted send in the conversation;
-- otherwise it refuses StaleSend and writes nothing. One row per device holds
-- that last accepted triple. `resolve_application_send` advances it with one
-- conditional upsert under the already-held conversation head lock, so a held
-- send can never be sequenced behind the same device's newer sends.
-- The close wipe deletes the conversation row last; the cascade removes these.
CREATE TABLE IF NOT EXISTS chat.application_send_order (
    conversation_id UUID NOT NULL
        REFERENCES chat.conversations(conversation_id) ON DELETE CASCADE,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (chat.is_safe_integer(generation)),
    epoch BIGINT NOT NULL CHECK (chat.is_safe_integer(epoch)),
    last_send_counter BIGINT NOT NULL
        CHECK (last_send_counter >= 1 AND chat.is_safe_integer(last_send_counter)),
    PRIMARY KEY (conversation_id, actor_did, actor_device_id)
);

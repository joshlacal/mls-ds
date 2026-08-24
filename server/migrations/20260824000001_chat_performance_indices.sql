-- Performance indices for member devices lookups, participant foreign keys, and entries transition lookups.

-- Index for user/device active conversation discovery (repository/core.rs discover_g6_revocation_scope)
CREATE INDEX IF NOT EXISTS member_devices_user_device_active_idx
    ON chat.member_devices (user_did, device_id, conversation_id)
    WHERE active;

-- Index for participant_period_id foreign key lookups and leaf counts (repository/inventory.rs load_conversation_state_source)
CREATE INDEX IF NOT EXISTS member_devices_participant_period_idx
    ON chat.member_devices (participant_period_id, active);

-- Index for transition-id lookups on chat.entries (repository/creation.rs lock_creation_replay_post_state)
CREATE INDEX IF NOT EXISTS entries_transition_id_idx
    ON chat.entries (transition_id)
    WHERE transition_id IS NOT NULL;

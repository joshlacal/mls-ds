-- A home's sequencer-authenticated membership index for remote groups whose
-- clean mirror graph cannot replay the group's later history. Rows are written
-- only by the home's deliverGroupEntry handler from the conversation's stored
-- sequencer, after verifying each control entry's actor signature, and only for
-- accounts homed here. `evidence_seq` orders the evidence: an older entry never
-- overwrites a newer one.
CREATE TABLE IF NOT EXISTS chat.remote_group_memberships (
    conversation_id UUID NOT NULL CHECK (chat.is_uuid_v4(conversation_id)),
    user_did TEXT NOT NULL CHECK (chat.is_bare_did(user_did)),
    sequencer_did TEXT NOT NULL CHECK (length(sequencer_did) BETWEEN 1 AND 2048),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'removed')),
    evidence_seq BIGINT NOT NULL CHECK (evidence_seq >= 1),
    evidence_entry_id UUID NOT NULL CHECK (chat.is_uuid_v4(evidence_entry_id)),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, user_did)
);

CREATE INDEX IF NOT EXISTS remote_group_memberships_user_idx
    ON chat.remote_group_memberships (user_did, conversation_id);

-- The Welcome a verified recovery fulfilment addressed to one of a member's
-- devices. Reads relay the sequencer's exact view of it; the marker only says
-- which device to ask for.
CREATE TABLE IF NOT EXISTS chat.remote_group_pending_welcomes (
    conversation_id UUID NOT NULL,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL CHECK (chat.is_uuid_v4(device_id)),
    welcome_id UUID NOT NULL CHECK (chat.is_uuid_v4(welcome_id)),
    evidence_seq BIGINT NOT NULL CHECK (evidence_seq >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, user_did, device_id, welcome_id),
    FOREIGN KEY (conversation_id, user_did)
        REFERENCES chat.remote_group_memberships (conversation_id, user_did)
        ON DELETE CASCADE,
    FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices (user_did, device_id)
        ON DELETE CASCADE
);

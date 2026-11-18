-- Preserve the first accepted scope of a device-authorized deletion across federation retries.
CREATE TABLE chat.account_deletion_operations (
    conversation_id uuid NOT NULL,
    deleted_did text NOT NULL,
    operation_id bytea NOT NULL CHECK (octet_length(operation_id) = 16),
    cutoff timestamptz NOT NULL,
    before_seq bigint NOT NULL CHECK (before_seq >= 1),
    PRIMARY KEY (conversation_id, deleted_did, operation_id)
);

-- HTTP reply caches expire. The user's already-applied erasure must never run a second time.
CREATE TABLE labyrinth.account_erasure_operations (
    operation_digest bytea PRIMARY KEY CHECK (octet_length(operation_digest) = 32),
    cutoff timestamptz NOT NULL
);

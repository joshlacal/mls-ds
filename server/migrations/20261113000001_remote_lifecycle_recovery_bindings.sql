-- A transport-only C33 home has no chat.conversations row.  Its recovery
-- routing binding is therefore keyed by the sequencer-issued request id and
-- carries its own bounded lifetime instead of borrowing a conversation FK.
CREATE TABLE chat.remote_lifecycle_recovery_bindings (
    recovery_request_id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL,
    sequencer_did TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    signed_request_sha256 BYTEA NOT NULL,
    response_sha256 BYTEA NOT NULL,
    response_bytes BYTEA NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT remote_lifecycle_recovery_bindings_request_check
        CHECK (chat.is_uuid_v4(recovery_request_id)),
    CONSTRAINT remote_lifecycle_recovery_bindings_conversation_check
        CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT remote_lifecycle_recovery_bindings_sequencer_check
        CHECK (chat.is_bare_did(sequencer_did)),
    CONSTRAINT remote_lifecycle_recovery_bindings_actor_check
        CHECK (chat.is_bare_did(actor_did)),
    CONSTRAINT remote_lifecycle_recovery_bindings_device_check
        CHECK (chat.is_uuid_v4(actor_device_id)),
    CONSTRAINT remote_lifecycle_recovery_bindings_request_digest_check
        CHECK (octet_length(signed_request_sha256) = 32),
    CONSTRAINT remote_lifecycle_recovery_bindings_response_check
        CHECK (
            octet_length(response_bytes) BETWEEN 1 AND 16777216
            AND octet_length(response_sha256) = 32
            AND response_sha256 = digest(response_bytes, 'sha256')
        ),
    CONSTRAINT remote_lifecycle_recovery_bindings_time_check
        CHECK (
            date_trunc('milliseconds', bound_at) = bound_at
            AND date_trunc('milliseconds', expires_at) = expires_at
            AND expires_at > bound_at
        )
);

-- getConversationState filters one conversation and emits bindings in this
-- stable order; expiry is included so the same index-only scan can discard a
-- due row without a heap lookup.
CREATE INDEX remote_lifecycle_recovery_projection_idx
    ON chat.remote_lifecycle_recovery_bindings
        (conversation_id, bound_at, recovery_request_id)
    INCLUDE (expires_at);

CREATE INDEX remote_lifecycle_recovery_expiry_idx
    ON chat.remote_lifecycle_recovery_bindings (expires_at);

-- A successful relayed lifecycle operation is replayable at its member's home
-- even after a close removes the routing row.  The key is endpoint-, actor-,
-- device- and operation-bound; the signed digest rejects key reuse.  Twenty
-- four hours is the direct API's idempotency-retention guarantee.
CREATE TABLE chat.remote_lifecycle_operation_replays (
    endpoint_nsid TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    conversation_id UUID NOT NULL,
    sequencer_did TEXT NOT NULL,
    signed_request_sha256 BYTEA NOT NULL,
    response_status SMALLINT NOT NULL,
    response_sha256 BYTEA NOT NULL,
    response_bytes BYTEA NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (actor_did, actor_device_id, endpoint_nsid, operation_id),
    CONSTRAINT remote_lifecycle_operation_replays_endpoint_check
        CHECK (endpoint_nsid LIKE 'blue.catbird.chat.%'),
    CONSTRAINT remote_lifecycle_operation_replays_actor_check
        CHECK (chat.is_bare_did(actor_did)),
    CONSTRAINT remote_lifecycle_operation_replays_device_check
        CHECK (chat.is_uuid_v4(actor_device_id)),
    CONSTRAINT remote_lifecycle_operation_replays_operation_check
        CHECK (chat.is_uuid_v4(operation_id)),
    CONSTRAINT remote_lifecycle_operation_replays_conversation_check
        CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT remote_lifecycle_operation_replays_sequencer_check
        CHECK (chat.is_bare_did(sequencer_did)),
    CONSTRAINT remote_lifecycle_operation_replays_request_digest_check
        CHECK (octet_length(signed_request_sha256) = 32),
    CONSTRAINT remote_lifecycle_operation_replays_response_check
        CHECK (
            response_status BETWEEN 200 AND 299
            AND octet_length(response_bytes) BETWEEN 1 AND 16777216
            AND octet_length(response_sha256) = 32
            AND response_sha256 = digest(response_bytes, 'sha256')
        ),
    CONSTRAINT remote_lifecycle_operation_replays_time_check
        CHECK (
            date_trunc('milliseconds', completed_at) = completed_at
            AND expires_at = completed_at + INTERVAL '24 hours'
        )
);

CREATE INDEX remote_lifecycle_operation_replays_expiry_idx
    ON chat.remote_lifecycle_operation_replays (expires_at);

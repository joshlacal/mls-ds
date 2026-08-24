-- Migration: Clean Chat Federation Delivery Dedupe and Receipts
-- Target: chat.federation_delivery_receipts and composite entry receipt foreign key

ALTER TABLE chat.entries
    ADD CONSTRAINT entries_delivery_receipt_source_uq UNIQUE (
        conversation_id, seq, entry_id, outer_entry_fingerprint
    );

CREATE TABLE chat.federation_delivery_receipts (
    delivery_id UUID PRIMARY KEY,
    endpoint_nsid TEXT NOT NULL,
    conversation_id UUID NOT NULL,
    sender_ds_did TEXT NOT NULL,
    receiver_ds_did TEXT NOT NULL,
    sequencer_did TEXT NOT NULL,
    sequencer_term BIGINT NOT NULL,
    envelope_sha256 BYTEA NOT NULL,
    result_sha256 BYTEA NOT NULL,
    source_entry_id UUID NOT NULL,
    source_entry_seq BIGINT NOT NULL,
    source_entry_fingerprint BYTEA NOT NULL,
    response_bytes BYTEA NOT NULL,
    response_sha256 BYTEA NOT NULL,
    receipt_signature BYTEA NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT federation_delivery_receipts_delivery_id_check
        CHECK (chat.is_uuid_v4(delivery_id)),
    CONSTRAINT federation_delivery_receipts_conversation_id_check
        CHECK (chat.is_uuid_v4(conversation_id)),
    CONSTRAINT federation_delivery_receipts_endpoint_check
        CHECK (
            endpoint_nsid IN (
                'blue.catbird.mlsDS.deliverWelcome',
                'blue.catbird.mlsDS.deliverMessage',
                'blue.catbird.mlsDS.submitCommit'
            )
        ),
    CONSTRAINT federation_delivery_receipts_sender_did_check
        CHECK (chat.is_bare_did(sender_ds_did)),
    CONSTRAINT federation_delivery_receipts_receiver_did_check
        CHECK (chat.is_bare_did(receiver_ds_did)),
    CONSTRAINT federation_delivery_receipts_sequencer_did_check
        CHECK (chat.is_bare_did(sequencer_did)),
    CONSTRAINT federation_delivery_receipts_sequencer_term_check
        CHECK (chat.is_safe_integer(sequencer_term) AND sequencer_term >= 0),
    CONSTRAINT federation_delivery_receipts_envelope_sha256_check
        CHECK (octet_length(envelope_sha256) = 32),
    CONSTRAINT federation_delivery_receipts_result_sha256_check
        CHECK (octet_length(result_sha256) = 32),
    CONSTRAINT federation_delivery_receipts_response_sha256_check
        CHECK (octet_length(response_sha256) = 32),
    CONSTRAINT federation_delivery_receipts_receipt_signature_check
        CHECK (octet_length(receipt_signature) = 64),
    CONSTRAINT federation_delivery_receipts_source_entry_shape_check
        CHECK (
            chat.is_uuid_v4(source_entry_id)
            AND chat.is_safe_integer(source_entry_seq) AND source_entry_seq >= 1
            AND octet_length(source_entry_fingerprint) = 32
        ),
    CONSTRAINT federation_delivery_receipts_conversation_fk
        FOREIGN KEY (conversation_id)
        REFERENCES chat.conversations(conversation_id),
    CONSTRAINT federation_delivery_receipts_source_entry_fk
        FOREIGN KEY (conversation_id, source_entry_seq, source_entry_id, source_entry_fingerprint)
        REFERENCES chat.entries(conversation_id, seq, entry_id, outer_entry_fingerprint)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX federation_delivery_receipts_convo_idx
    ON chat.federation_delivery_receipts (conversation_id, endpoint_nsid);

CREATE INDEX federation_delivery_receipts_sender_idx
    ON chat.federation_delivery_receipts (sender_ds_did, completed_at);

CREATE TRIGGER federation_delivery_receipts_immutable
    BEFORE UPDATE OR DELETE ON chat.federation_delivery_receipts
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

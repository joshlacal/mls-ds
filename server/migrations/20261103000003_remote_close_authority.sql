-- Retain the authenticated source of a remote terminal close after its
-- operational conversation rows are wiped. This permits only an identical
-- redelivery from that same sequencer/coordinator; an arbitrary terminal event
-- is not authority to close a nonexistent conversation.
ALTER TABLE chat.conversation_close_terminal_entries
    ADD COLUMN source_ds_did TEXT,
    ADD COLUMN source_authority_bytes BYTEA,
    ADD CONSTRAINT conversation_close_terminal_source_did_check CHECK (
        source_ds_did IS NULL OR chat.is_bare_did(source_ds_did)
    ),
    ADD CONSTRAINT conversation_close_terminal_source_authority_check CHECK (
        source_authority_bytes IS NULL
        OR (source_ds_did IS NOT NULL
            AND octet_length(source_authority_bytes) BETWEEN 1 AND 16777216)
    );

-- The existing blanket identity trigger also makes both new evidence columns
-- immutable. Local closes leave them NULL; group closes retain the dedicated
-- sequencer signature, while C33 closes retain their verified coordinator DID.

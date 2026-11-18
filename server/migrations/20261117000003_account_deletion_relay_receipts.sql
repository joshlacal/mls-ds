-- Only the authenticated, fully authorized envelope may be acknowledged offline.
ALTER TABLE chat.account_deletion_operations
    ADD COLUMN accepted_relay_sha256 bytea
        CHECK (octet_length(accepted_relay_sha256) = 32);

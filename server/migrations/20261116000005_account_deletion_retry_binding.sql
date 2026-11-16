-- A deleteAccountData service token can be retried only for the same
-- device-signed deletion intent. The optional keyProof header is deliberately
-- outside the binding so a caller can supply it after a failed PDS lookup.
ALTER TABLE auth_jti_nonce
    ADD COLUMN deletion_token_sha256 BYTEA
        CHECK (deletion_token_sha256 IS NULL OR octet_length(deletion_token_sha256) = 32),
    ADD COLUMN deletion_intent_sha256 BYTEA
        CHECK (deletion_intent_sha256 IS NULL OR octet_length(deletion_intent_sha256) = 32);

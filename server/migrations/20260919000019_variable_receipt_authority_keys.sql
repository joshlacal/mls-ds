-- 20260919000019_variable_receipt_authority_keys.sql
-- Replace the hardcoded 'did:web:chat.catbird.blue' CHECK constraints on
-- chat.direct_request_receipt_keys with enforceable bare DID, keyId, and
-- P-256 compressed Multikey fingerprint relations for configured variable authorities.

ALTER TABLE chat.direct_request_receipt_keys
    DROP CONSTRAINT IF EXISTS direct_request_receipt_keys_authority_did_check,
    DROP CONSTRAINT IF EXISTS direct_request_receipt_keys_check;

ALTER TABLE chat.direct_request_receipt_keys
    ADD CONSTRAINT direct_request_receipt_keys_authority_did_check
        CHECK (chat.is_bare_did(authority_did)),
    ADD CONSTRAINT direct_request_receipt_keys_fingerprint_check
        CHECK (key_id = authority_did || '#chat-request-receipt-' || encode(digest(public_key, 'sha256'), 'hex'));

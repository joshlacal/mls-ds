-- PostgreSQL CHECK permits NULL. These explicit presence checks close partial
-- snapshot/terminal rows without editing the installed preparation migration.
ALTER TABLE chat.direct_request_attempts ADD CONSTRAINT direct_request_terminal_receipt_present
    CHECK(status='prepared' OR (terminal_response IS NOT NULL AND terminal_response_sha256 IS NOT NULL));
ALTER TABLE chat.direct_request_attempts ADD CONSTRAINT direct_request_preparation_snapshot_present
    CHECK(prepared_at IS NULL OR (prepare_response IS NOT NULL AND lease_expires_at IS NOT NULL));

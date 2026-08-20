-- Expand-only admission ledger for standard ATProto AppView service auth.
-- Obsolete custom-DPoP columns and tables remain untouched for rollback.

CREATE TABLE chat.service_auth_admissions (
    admission_id UUID PRIMARY KEY,
    issuer_did TEXT NOT NULL,
    endpoint_nsid TEXT NOT NULL,
    device_id UUID NOT NULL,
    jti_sha256 BYTEA NOT NULL,
    token_sha256 BYTEA NOT NULL,
    token_iat TIMESTAMPTZ NOT NULL,
    token_exp TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT service_auth_admissions_issuer_nonempty
        CHECK (issuer_did <> '' AND issuer_did = BTRIM(issuer_did)),
    CONSTRAINT service_auth_admissions_endpoint_chat
        CHECK (endpoint_nsid LIKE 'blue.catbird.chat.%'),
    CONSTRAINT service_auth_admissions_jti_digest
        CHECK (OCTET_LENGTH(jti_sha256) = 32),
    CONSTRAINT service_auth_admissions_token_digest
        CHECK (OCTET_LENGTH(token_sha256) = 32),
    CONSTRAINT service_auth_admissions_time_profile
        CHECK (
            token_exp > token_iat
            AND token_exp <= token_iat + INTERVAL '120 seconds'
            AND consumed_at <= token_exp + INTERVAL '60 seconds'
        ),
    CONSTRAINT service_auth_admissions_jti_once
        UNIQUE (issuer_did, jti_sha256)
);

CREATE INDEX service_auth_admissions_expiry_idx
    ON chat.service_auth_admissions (token_exp);

COMMENT ON TABLE chat.service_auth_admissions IS
    'One-use standard ATProto service-auth admissions for MLS v2 AppView routes; contains no Nest or DPoP authority.';

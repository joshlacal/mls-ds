-- Operator account moderation, mirrored from the Catbird Ozone labeler.
--
-- Reports are never stored here: users report through their PDS straight to
-- Ozone, with ids only. These tables hold just the operator's decision about
-- an account (Ozone's `!takedown` / `!suspend` label on the account DID), so
-- service-auth admission can lock that account out.
--
-- This is operator state, not user data: account deletion does not erase it,
-- so a banned DID stays banned. Timestamps are bound by the server clock, so
-- no column defaults to the wall clock.

CREATE SCHEMA IF NOT EXISTS moderation;

CREATE TABLE moderation.account_labels (
    src        TEXT        NOT NULL,
    did        TEXT        NOT NULL,
    val        TEXT        NOT NULL,
    -- Label creation time from the labeler; the newest event wins.
    cts        TIMESTAMPTZ NOT NULL,
    exp        TIMESTAMPTZ,
    -- TRUE once the labeler negated the label (takedown reversed).
    neg        BOOLEAN     NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (src, did, val),
    CONSTRAINT account_labels_did_shape CHECK (did ~ '^did:(plc|web):[A-Za-z0-9._:%-]+$'),
    CONSTRAINT account_labels_val_len CHECK (char_length(val) BETWEEN 1 AND 128)
);

CREATE INDEX account_labels_live_by_did
    ON moderation.account_labels (did)
    WHERE NOT neg;

CREATE TABLE moderation.label_cursors (
    src        TEXT        PRIMARY KEY,
    cursor     TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

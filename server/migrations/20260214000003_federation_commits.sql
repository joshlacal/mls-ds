-- Federation commit storage for sequencer CAS submissions.

CREATE TABLE IF NOT EXISTS commits (
    convo_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    commit_data BYTEA NOT NULL,
    sender_ds_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (convo_id, epoch),
    CONSTRAINT commits_convo_fk FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_commits_convo_created
    ON commits (convo_id, created_at DESC);

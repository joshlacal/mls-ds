-- Replace the old reports table with a simpler spam_reports table

DROP TABLE IF EXISTS reports;

DROP INDEX IF EXISTS idx_reports_convo;
DROP INDEX IF EXISTS idx_reports_reporter;
DROP INDEX IF EXISTS idx_reports_reported;
DROP INDEX IF EXISTS idx_reports_status;
DROP INDEX IF EXISTS idx_reports_category;

-- Spam Reports (simple per-conversation spam reporting)
CREATE TABLE IF NOT EXISTS spam_reports (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL REFERENCES conversations(id),
    reporter_did TEXT NOT NULL,
    reported_did TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(convo_id, reporter_did, reported_did)
);
CREATE INDEX IF NOT EXISTS idx_spam_reports_convo ON spam_reports(convo_id);
CREATE INDEX IF NOT EXISTS idx_spam_reports_reported ON spam_reports(reported_did);

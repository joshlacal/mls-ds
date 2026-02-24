-- Federation peer policy mutation audit trail

CREATE TABLE IF NOT EXISTS federation_peer_policy_audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_did TEXT NOT NULL,
    target_peer_did TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT federation_peer_policy_audit_log_action_check CHECK (action IN ('upsert', 'delete'))
);

CREATE INDEX IF NOT EXISTS idx_federation_peer_policy_audit_log_created_at
    ON federation_peer_policy_audit_log (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_federation_peer_policy_audit_log_target_peer
    ON federation_peer_policy_audit_log (target_peer_did, created_at DESC);

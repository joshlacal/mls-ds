ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS dead_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dead_reason TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'key_packages_dead_reason_check'
    ) THEN
        ALTER TABLE key_packages
            ADD CONSTRAINT key_packages_dead_reason_check
            CHECK (
                dead_reason IS NULL OR
                dead_reason IN ('noMatchingKeyPackage', 'corruptInvitee', 'unowned')
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_key_packages_live_by_device
    ON key_packages(owner_did, device_id, key_package_hash)
    WHERE dead_at IS NULL;

CREATE TABLE IF NOT EXISTS key_package_audit (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('reconcile', 'invalidate')),
    owner_did TEXT NOT NULL,
    device_did TEXT NOT NULL,
    device_id TEXT,
    key_package_hash TEXT,
    reason TEXT,
    server_only_count INTEGER,
    local_only_count INTEGER,
    total INTEGER,
    device_verified BOOLEAN,
    already_dead BOOLEAN,
    actor_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_key_package_audit_device
    ON key_package_audit(device_did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_key_package_audit_hash
    ON key_package_audit(key_package_hash, created_at DESC)
    WHERE key_package_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS dead_letter_recoveries (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    operator_did TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('reset', 'drop', 'reissue-all')),
    reason TEXT,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dry_run BOOLEAN NOT NULL DEFAULT true,
    success BOOLEAN NOT NULL DEFAULT false,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_recoveries_convo
    ON dead_letter_recoveries(convo_id, ran_at DESC);

COMMENT ON TABLE key_package_audit IS
    'Phase B KP recovery audit for server-authoritative reconciliation and dead-mark invalidation.';
COMMENT ON COLUMN key_packages.dead_at IS
    'Soft-delete marker for key packages known not to exist on the owning device.';
COMMENT ON COLUMN key_packages.dead_reason IS
    'Reason the key package was dead-marked by recovery handling.';
COMMENT ON TABLE dead_letter_recoveries IS
    'Operator audit trail for the Phase B deadletter_recover admin binary.';

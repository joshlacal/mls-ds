-- =============================================================================
-- Key Package Safety Invariants — Explicit State Machine
-- =============================================================================
-- Adds:
--   * `state` TEXT (CHECK enum) — explicit lifecycle: available, claimed, expired, revoked
--   * `revoked_at` TIMESTAMPTZ — set when a key package is administratively revoked
--   * `is_last_resort` BOOLEAN — orthogonal flag; last-resort packages are still
--     claimable, just claimed only when no non-last-resort `available` rows exist
--
-- Backfill rules (ordered, most-specific first):
--   1. consumed_at IS NOT NULL                        → 'claimed'
--   2. expires_at < NOW()                             → 'expired'
--   3. otherwise                                      → 'available'
-- (No historical rows are revoked or last-resort — those start empty.)
--
-- The orphaned `reserved_at`/`reserved_by_convo` columns from the original
-- schema are NOT touched here. They are dead semantics (reserve_key_package()
-- is defined but uncalled in the codebase as of this migration); a follow-up
-- can drop them once readers are removed.

ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS state TEXT;

ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS is_last_resort BOOLEAN NOT NULL DEFAULT false;

-- Backfill state from existing nullable columns
UPDATE key_packages
SET state = CASE
    WHEN consumed_at IS NOT NULL THEN 'claimed'
    WHEN expires_at < NOW() THEN 'expired'
    ELSE 'available'
END
WHERE state IS NULL;

-- Now enforce NOT NULL + the enum check
ALTER TABLE key_packages
    ALTER COLUMN state SET NOT NULL;

ALTER TABLE key_packages
    ALTER COLUMN state SET DEFAULT 'available';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'key_packages_state_check'
    ) THEN
        ALTER TABLE key_packages
            ADD CONSTRAINT key_packages_state_check
            CHECK (state IN ('available', 'claimed', 'expired', 'revoked'));
    END IF;
END$$;

-- Hot-path index: claim queries narrow to (owner, cipher_suite, state='available').
-- Partial index keeps it small even with a large historical claimed/expired tail.
CREATE INDEX IF NOT EXISTS idx_key_packages_available_state
    ON key_packages (owner_did, cipher_suite)
    WHERE state = 'available';

-- Last-resort secondary index — used only when no non-LR `available` rows exist.
CREATE INDEX IF NOT EXISTS idx_key_packages_last_resort
    ON key_packages (owner_did, cipher_suite)
    WHERE state = 'available' AND is_last_resort = true;

COMMENT ON COLUMN key_packages.state IS
    'Explicit lifecycle: available | claimed | expired | revoked. Atomic claim transitions available -> claimed via UPDATE ... WHERE state=''available''.';
COMMENT ON COLUMN key_packages.revoked_at IS
    'Timestamp when this key package was administratively revoked (e.g. compromised credential). Set in tandem with state=''revoked''.';
COMMENT ON COLUMN key_packages.is_last_resort IS
    'Orthogonal flag — last-resort packages are still claimable, but only claimed when no non-last-resort available row exists.';

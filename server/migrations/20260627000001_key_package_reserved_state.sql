-- Activate key-package reservation semantics for getKeyPackages.
--
-- Regular key packages move:
--   available -> reserved -> claimed
--
-- The reserved state is intentionally reclaimable after a short TTL so failed
-- group creation does not permanently drain device pools.

ALTER TABLE key_packages
    DROP CONSTRAINT IF EXISTS key_packages_state_check;

ALTER TABLE key_packages
    ADD CONSTRAINT key_packages_state_check
    CHECK (state IN ('available', 'reserved', 'claimed', 'expired', 'revoked'));

CREATE INDEX IF NOT EXISTS idx_key_packages_reserved_state
    ON key_packages (owner_did, cipher_suite, reserved_at)
    WHERE state = 'reserved';

-- Reusable last-resort key packages are durable fallbacks; keep at most one
-- active row per owner/device bucket so they do not accumulate like regular
-- single-use key packages.
CREATE UNIQUE INDEX IF NOT EXISTS idx_key_packages_last_resort_one_active_per_device
    ON key_packages (owner_did, COALESCE(device_id, ''))
    WHERE is_last_resort = true
      AND state = 'available'
      AND dead_at IS NULL;

COMMENT ON COLUMN key_packages.state IS
    'Explicit lifecycle: available | reserved | claimed | expired | revoked. getKeyPackages transitions available/stale-reserved -> reserved; create/addMembers success transitions reserved -> claimed.';

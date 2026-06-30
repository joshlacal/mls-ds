-- Track the first time a key package was served into a Welcome reservation.
--
-- Unlike `reserved_at` (which the cleanup worker NULLs when releasing stale
-- reservations, and which `claim_available_key_packages_bulk` overwrites on
-- every re-serve), this stamp is set ONCE and never cleared. That gives the
-- cleanup worker a stable signal to retire "poison" key packages: ones that
-- were sealed into a Welcome but never consumed because the recipient had lost
-- the matching private key locally (process_welcome -> NoMatchingKeyPackage).
-- Without it, the reservation oscillates reserved -> available -> reserved and
-- the same dead ref keeps getting re-served to every new group.
ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS first_served_at TIMESTAMPTZ;

COMMENT ON COLUMN key_packages.first_served_at IS
    'Immutable timestamp of the first getKeyPackages reservation (first Welcome seal). Set once via COALESCE in claim_available_key_packages_bulk and never cleared. The key-package cleanup worker uses it to retire poison KPs served but never consumed past a grace window.';

-- Partial index for the reaper sweep: served-but-unconsumed, still alive.
CREATE INDEX IF NOT EXISTS idx_key_packages_served_unconsumed
    ON key_packages (first_served_at)
    WHERE consumed_at IS NULL AND dead_at IS NULL AND first_served_at IS NOT NULL;

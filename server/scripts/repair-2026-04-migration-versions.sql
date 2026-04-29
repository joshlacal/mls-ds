-- Repair _sqlx_migrations entries for the YYYYMMDD_001_*.sql migrations
-- renamed under chore/ci-cleanup (April 2026) to YYYYMMDD100000_*.sql.
--
-- Why: sqlx parses everything before the FIRST underscore as the migration
-- version. The legacy filenames were `20260403_001_drop_read_receipts.sql`
-- (version 20260403) — far smaller than the contemporaneous timestamped
-- migrations like `20251125000001_*` (version 20251125000001), causing the
-- 2026-04-* migrations to sort BEFORE the November 2025 greenfield schema
-- and break on a fresh DB. The renamed filename
-- `20260403100000_drop_read_receipts.sql` parses to version 20260403100000,
-- restoring chronological ordering.
--
-- Production DBs already have the OLD versions in _sqlx_migrations. Running
-- `sqlx migrate run` after the rename without this repair will produce one
-- of:
--   - "previously applied but is missing in the resolved migrations" (because
--     the old version is gone from the file system), or
--   - "previously applied but has been modified" (if checksums recompute).
--
-- This script remaps OLD version → NEW version in place. Description is
-- recomputed by sqlx from the new filename (`_` → ' ', strip `.sql`),
-- so we update both columns. Checksum is unchanged because the file
-- content was not modified — only the filename.
--
-- Apply BEFORE deploying the renamed migrations:
--   doppler run -- psql "$DATABASE_URL" -f scripts/repair-2026-04-migration-versions.sql
--
-- Safe to re-run; each UPDATE is conditional on the OLD version still being
-- present, so a second run is a no-op.

BEGIN;

UPDATE _sqlx_migrations
SET version = 20260403100000, description = 'drop read receipts'
WHERE version = 20260403;

UPDATE _sqlx_migrations
SET version = 20260404100000, description = 'add confirmation tag'
WHERE version = 20260404;

UPDATE _sqlx_migrations
SET version = 20260405100000, description = 'group reset support'
WHERE version = 20260405;

UPDATE _sqlx_migrations
SET version = 20260406100000, description = 'drop message reactions'
WHERE version = 20260406;

UPDATE _sqlx_migrations
SET version = 20260407100000, description = 'recovery failures'
WHERE version = 20260407;

UPDATE _sqlx_migrations
SET version = 20260418100000, description = 'reset votes and epoch authenticators'
WHERE version = 20260418;

UPDATE _sqlx_migrations
SET version = 20260425100000, description = 'messages wire epoch'
WHERE version = 20260425;

UPDATE _sqlx_migrations
SET version = 20260426100000, description = 'reset votes failure mode'
WHERE version = 20260426;

UPDATE _sqlx_migrations
SET version = 20260427100000, description = 'commit health columns'
WHERE version = 20260427;

UPDATE _sqlx_migrations
SET version = 20260428100000, description = 'groupinfo 404 health columns'
WHERE version = 20260428;

-- Verify: no rows should remain at the old version range.
DO $$
DECLARE
    leftover INT;
BEGIN
    SELECT COUNT(*) INTO leftover
    FROM _sqlx_migrations
    WHERE version BETWEEN 20260400 AND 20260499
      AND version < 20260400000000;
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'Repair incomplete: % rows still have legacy version. Check _sqlx_migrations.',
            leftover;
    END IF;
END $$;

COMMIT;

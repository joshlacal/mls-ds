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
-- Safe to re-run. Each pair runs:
--   DELETE FROM ... WHERE version = NEW AND EXISTS (... legacy)
--   UPDATE  ... SET  version = NEW WHERE version = LEGACY
--
-- The DELETE handles the case where `bootstrap-sqlx-migrations.sh` (which
-- runs before this repair in deploy.sh) already inserted a row at the new
-- 14-digit version using a freshly-computed checksum from the renamed
-- file. We delete that row ONLY when the legacy-version row also still
-- exists, so the subsequent UPDATE preserves the original applied
-- checksum + installed_on timestamp by mutating the legacy row in place.
-- Cases:
--   - Both rows present (deploy already attempted) → DELETE drops the
--     bootstrap row, UPDATE migrates legacy → new (preserves original
--     metadata).
--   - Only legacy present (clean pre-rename DB) → DELETE no-op (no new
--     row to drop), UPDATE migrates.
--   - Only new present (already-repaired DB) → DELETE no-op (EXISTS
--     clause is false), UPDATE no-op.

BEGIN;

DELETE FROM _sqlx_migrations WHERE version = 20260403100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260403);
UPDATE _sqlx_migrations
SET version = 20260403100000, description = 'drop read receipts'
WHERE version = 20260403;

DELETE FROM _sqlx_migrations WHERE version = 20260404100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260404);
UPDATE _sqlx_migrations
SET version = 20260404100000, description = 'add confirmation tag'
WHERE version = 20260404;

DELETE FROM _sqlx_migrations WHERE version = 20260405100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260405);
UPDATE _sqlx_migrations
SET version = 20260405100000, description = 'group reset support'
WHERE version = 20260405;

DELETE FROM _sqlx_migrations WHERE version = 20260406100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260406);
UPDATE _sqlx_migrations
SET version = 20260406100000, description = 'drop message reactions'
WHERE version = 20260406;

DELETE FROM _sqlx_migrations WHERE version = 20260407100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260407);
UPDATE _sqlx_migrations
SET version = 20260407100000, description = 'recovery failures'
WHERE version = 20260407;

DELETE FROM _sqlx_migrations WHERE version = 20260418100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260418);
UPDATE _sqlx_migrations
SET version = 20260418100000, description = 'reset votes and epoch authenticators'
WHERE version = 20260418;

DELETE FROM _sqlx_migrations WHERE version = 20260425100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260425);
UPDATE _sqlx_migrations
SET version = 20260425100000, description = 'messages wire epoch'
WHERE version = 20260425;

DELETE FROM _sqlx_migrations WHERE version = 20260426100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260426);
UPDATE _sqlx_migrations
SET version = 20260426100000, description = 'reset votes failure mode'
WHERE version = 20260426;

DELETE FROM _sqlx_migrations WHERE version = 20260427100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260427);
UPDATE _sqlx_migrations
SET version = 20260427100000, description = 'commit health columns'
WHERE version = 20260427;

DELETE FROM _sqlx_migrations WHERE version = 20260428100000 AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20260428);
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

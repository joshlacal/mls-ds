#!/bin/bash
#
# Fast database clear (no confirmation) — for automated testing and
# pre-cutover wipes.
#
# Uses Doppler to source DATABASE_URL from project=catbird-mls,
# config=prd. Mirrors deploy.sh / make deploy which routes all DB
# access through doppler. No hardcoded credentials.
#
# Per memory pattern `reference_doppler_psql_pattern` and the workspace
# CLAUDE.md: netcup DB queries MUST go through `bash -c
# 'psql "$DATABASE_URL" ...'`. The naive `doppler run -- psql
# "$DATABASE_URL"` form shell-expands the URL on the *local* shell
# before doppler injects, silently falling back to peer auth under the
# wrong role.
#
# Truncates every table in the `public` schema except
# `_sqlx_migrations` (sqlx tracks applied migrations there; clearing
# would re-run all of them on next startup). Schema is preserved.
#

set -euo pipefail

if ! command -v doppler &> /dev/null; then
    echo "ERROR: doppler CLI not found — install from https://docs.doppler.com/docs/install-cli" >&2
    exit 1
fi

# Stage SQL in a tempfile so we don't have to wrestle with three layers
# of nested quoting (outer shell → bash -c → psql heredoc with
# PL/pgSQL `$$ ... $$` and string literals).
SQL_FILE=$(mktemp -t clear-db-fast.XXXXXX.sql)
trap 'rm -f "$SQL_FILE"' EXIT

cat > "$SQL_FILE" <<'SQL'
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Bypass FK trigger fan-out so order doesn't matter; CASCADE on
    -- TRUNCATE then handles the dependency closure.
    SET session_replication_role = 'replica';

    FOR r IN
        SELECT tablename
          FROM pg_tables
         WHERE schemaname = 'public'
           AND tablename NOT IN ('_sqlx_migrations')
    LOOP
        EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' CASCADE';
    END LOOP;

    SET session_replication_role = 'origin';
END
$$;
SQL

doppler run --project catbird-mls --config prd -- \
    bash -c "psql \"\$DATABASE_URL\" -v ON_ERROR_STOP=1 -f \"$SQL_FILE\""

echo "✅ Database cleared (via doppler; schema and _sqlx_migrations preserved)"

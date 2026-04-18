#!/bin/bash
#
# Bootstrap _sqlx_migrations for migrations applied outside sqlx.
#
# Problem this fixes: prod was bootstrapped via raw SQL (or an earlier
# migration tool) before sqlx-cli was wired in. The schema exists but
# _sqlx_migrations is missing rows for the historical 14-digit-format
# migrations (YYYYMMDDHHMMSS_*.sql). On every `sqlx migrate run`, sqlx
# sees those versions as "pending" and tries to re-apply them, hitting
# "already exists" errors on every object.
#
# This script marks every 14-digit-format migration file as applied by
# inserting a row into _sqlx_migrations with the file's SHA-384 checksum.
# Idempotent (INSERT ... ON CONFLICT DO NOTHING) — safe to re-run.
#
# Runs BEFORE run-migrations.sh in deploy.sh.
#
# Usage: ./bootstrap-sqlx-migrations.sh [DATABASE_URL]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MIGRATIONS_DIR="$PROJECT_DIR/migrations"
DB_URL="${1:-${DATABASE_URL:-}}"

if [ -z "$DB_URL" ]; then
    echo "ERROR: DATABASE_URL not provided"
    echo "Usage: $0 [DATABASE_URL]"
    exit 1
fi

# If _sqlx_migrations doesn't exist yet, this is a fresh DB — nothing to
# bootstrap; sqlx migrate run will create the table and apply everything.
if ! psql "$DB_URL" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name = '_sqlx_migrations'" 2>/dev/null | grep -q 1; then
    echo "_sqlx_migrations table not found — fresh DB, skipping bootstrap"
    exit 0
fi

# Pick sha384 tool
if command -v sha384sum &>/dev/null; then
    SHA384="sha384sum"
elif command -v shasum &>/dev/null; then
    SHA384="shasum -a 384"
else
    echo "ERROR: neither sha384sum nor shasum found"
    exit 1
fi

inserted=0
for f in "$MIGRATIONS_DIR"/*.sql; do
    filename=$(basename "$f" .sql)

    # Only match 14-digit-format migrations: YYYYMMDDHHMMSS_description
    # (new-format migrations like 20260403_001_foo are handled by sqlx directly)
    if [[ ! "$filename" =~ ^([0-9]{14})_(.*)$ ]]; then
        continue
    fi

    version="${BASH_REMATCH[1]}"
    description_raw="${BASH_REMATCH[2]//_/ }"
    # Escape single quotes for SQL literal
    description="${description_raw//\'/\'\'}"
    checksum=$($SHA384 "$f" | cut -d' ' -f1)

    # INSERT with ON CONFLICT DO NOTHING: idempotent. If sqlx later decides
    # the checksum mismatches (someone edited the file after prod applied it
    # via raw SQL), sqlx will error clearly; that's the right signal.
    result=$(psql "$DB_URL" -v ON_ERROR_STOP=1 -tA <<SQL
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time)
VALUES (${version}, '${description}', NOW(), true, decode('${checksum}', 'hex'), 0)
ON CONFLICT (version) DO NOTHING
RETURNING version;
SQL
)

    if [ -n "$result" ]; then
        echo "  bootstrapped: ${version} ${description_raw}"
        inserted=$((inserted + 1))
    fi
done

if [ "$inserted" -eq 0 ]; then
    echo "No historical migrations needed bootstrapping (all already tracked)"
else
    echo "Bootstrapped $inserted historical migrations into _sqlx_migrations"
fi

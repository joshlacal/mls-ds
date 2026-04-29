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

# Cutover: any migration with version >= this number is "post-sqlx-cli-wiring"
# and MUST be applied via `sqlx migrate run` (not bootstrapped). Bootstrap was
# only ever needed for historical migrations applied via raw SQL before sqlx
# was wired into the deploy pipeline. Without this gate, every NEW 14-digit
# migration gets blanket-marked as applied (by this script, with a freshly-
# computed checksum from the file) BEFORE its DDL has actually run, so
# `sqlx migrate run` skips it and the schema diverges from `_sqlx_migrations`.
# History: 2026-04-28 deploy of Phase 3 + R3 hit this; federation_outbox,
# notification_outbox, reset_reminder_state were marked applied without DDL.
# Cutover chosen as the first 20260429 migration (Phase 2 keystone migration).
SQLX_CUTOVER_VERSION=20260429000000

inserted=0
skipped_post_cutover=0
for f in "$MIGRATIONS_DIR"/*.sql; do
    filename=$(basename "$f" .sql)

    # Only match 14-digit-format migrations: YYYYMMDDHHMMSS_description
    # (new-format migrations like 20260403_001_foo are handled by sqlx directly)
    if [[ ! "$filename" =~ ^([0-9]{14})_(.*)$ ]]; then
        continue
    fi

    version="${BASH_REMATCH[1]}"

    # Cutover gate — see comment above. Skip post-cutover migrations entirely
    # so sqlx can run them properly.
    if [ "$version" -ge "$SQLX_CUTOVER_VERSION" ]; then
        skipped_post_cutover=$((skipped_post_cutover + 1))
        continue
    fi

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

if [ "$skipped_post_cutover" -gt 0 ]; then
    echo "Skipped $skipped_post_cutover post-cutover migration(s) (>= ${SQLX_CUTOVER_VERSION}) — sqlx-cli will apply them"
fi

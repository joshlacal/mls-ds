#!/bin/bash
set -e

# Run database migrations
# Usage: ./run-migrations.sh [DATABASE_URL]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Get database URL from argument or environment
DATABASE_URL="${1:-${DATABASE_URL}}"

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not provided"
    echo "Usage: $0 [DATABASE_URL]"
    echo "Or set DATABASE_URL environment variable"
    exit 1
fi

echo "Running database migrations..."
echo "Database: ${DATABASE_URL%%\?*}"  # Hide password in output

# Check if sqlx-cli is installed
if ! command -v sqlx &> /dev/null; then
    echo "sqlx-cli not found. Installing..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

# Apply the 2026-04 migration-version repair (chore/ci-cleanup) BEFORE
# running sqlx. The repair UPDATEs the `version` column in
# `_sqlx_migrations` for any rows still using the legacy `YYYYMMDD_NNN_*`
# version numbers; on a DB that's already been migrated under the new
# 14-digit names, every UPDATE is a no-op.
#
# Without this step, `sqlx migrate run` errors with
#   "migration 20260403 was previously applied but is missing in the
#    resolved migrations"
# on any production DB that predates the rename.
#
# Skipped entirely on a fresh database: the repair rewrites legacy `version`
# rows, which cannot exist before `_sqlx_migrations` does. Without this guard
# the repair aborts with `relation "_sqlx_migrations" does not exist` and
# `set -e` kills the run, so this script could never bootstrap a new database.
REPAIR_SCRIPT="$SCRIPT_DIR/repair-2026-04-migration-versions.sql"
if [ -f "$REPAIR_SCRIPT" ] && [ "$(psql "$DATABASE_URL" -Atqc \
        "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")" = "t" ]; then
    echo "Applying _sqlx_migrations version repair (idempotent) ..."
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$REPAIR_SCRIPT" >/dev/null
else
    echo "Skipping _sqlx_migrations version repair (no migrations table yet)."
fi

# Authorization gate for 20260728000004_activate_operation_claim_completeness.
#
# That migration refuses to run (ERRCODE 55000) unless the connection executing
# it carries the GUC
#   chat.operation_claim_activation_approved=handlers-and-legacy-apis-sealed
# The refusal is deliberate: activating operation-claim completeness is only
# safe once the handlers are migrated and the legacy APIs are sealed. We must
# NOT set that GUC implicitly, because doing so silently weakens the gate
# (migrations/README.md: "Do not set this globally or weaken the gate").
#
# But leaving it unhandled produces the worst available failure mode: sqlx
# applies and COMMITS every earlier migration -- including `CREATE SCHEMA chat`
# -- and only then aborts on 00004, leaving a partially migrated database.
# 20260729000001 is deliberately forward-only and scripts/rollback.sh restores
# only the binary, so there is no way back.
#
# So: if 00004 is still pending, refuse before applying anything, unless the
# operator explicitly asserts the precondition.
ACTIVATION_MIGRATION_VERSION=20260728000004
ACTIVATION_GUC_VALUE=handlers-and-legacy-apis-sealed

activation_is_pending() {
    local state
    # A missing _sqlx_migrations table means a fresh database: 00004 is pending.
    # A failed query is treated as pending too -- fail closed, never open.
    state="$(psql "$DATABASE_URL" -Atqc \
        "SELECT CASE
                  WHEN to_regclass('public._sqlx_migrations') IS NULL THEN 'pending'
                  WHEN EXISTS (
                    SELECT 1 FROM public._sqlx_migrations
                     WHERE version = ${ACTIVATION_MIGRATION_VERSION}
                  ) THEN 'applied'
                  ELSE 'pending'
                END" 2>/dev/null)" || state=pending
    [ "$state" != "applied" ]
}

MIGRATION_PGOPTIONS=""
if activation_is_pending; then
    if [ "${CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED:-}" = "$ACTIVATION_GUC_VALUE" ]; then
        echo "Migration ${ACTIVATION_MIGRATION_VERSION} is pending and explicitly authorized."
        MIGRATION_PGOPTIONS="-c chat.operation_claim_activation_approved=${ACTIVATION_GUC_VALUE}"
    else
        cat >&2 <<EOF
Error: migration ${ACTIVATION_MIGRATION_VERSION} (activate operation-claim
completeness) is pending, and this run is not authorized to apply it.

Applying it requires that the chat handlers are migrated and the legacy APIs
are sealed. Confirm that is true, then re-run with:

  CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=${ACTIVATION_GUC_VALUE} \\
    $0 ${1:+<DATABASE_URL>}

Refusing now, before any migration is applied. Proceeding without this check
would commit the earlier migrations (including CREATE SCHEMA chat) and only
then abort, leaving a partially migrated database with no rollback path.
EOF
        exit 1
    fi
fi

# Run migrations
cd "$PROJECT_DIR"
if [ -n "$MIGRATION_PGOPTIONS" ]; then
    # Scope the GUC to the migration connection only -- never globally, and not
    # to the psql repair connection above.
    PGOPTIONS="$MIGRATION_PGOPTIONS" sqlx migrate run --database-url "$DATABASE_URL"
else
    sqlx migrate run --database-url "$DATABASE_URL"
fi

echo "Migrations completed successfully!"

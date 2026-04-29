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
REPAIR_SCRIPT="$SCRIPT_DIR/repair-2026-04-migration-versions.sql"
if [ -f "$REPAIR_SCRIPT" ]; then
    echo "Applying _sqlx_migrations version repair (idempotent) ..."
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$REPAIR_SCRIPT" >/dev/null
fi

# Run migrations
cd "$PROJECT_DIR"
sqlx migrate run --database-url "$DATABASE_URL"

echo "Migrations completed successfully!"

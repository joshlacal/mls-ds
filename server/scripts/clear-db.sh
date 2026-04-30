#!/bin/bash
#
# Clear all data from the MLS database (with 5-second confirmation
# delay). Schema and `_sqlx_migrations` are preserved.
#
# Uses Doppler to source DATABASE_URL from project=catbird-mls,
# config=prd. Mirrors deploy.sh / make deploy. No hardcoded
# credentials.
#
# Per `reference_doppler_psql_pattern`: psql MUST go inside
# `bash -c 'psql "$DATABASE_URL" ...'`. The naive
# `doppler run -- psql "$DATABASE_URL"` form shell-expands the URL on
# the *local* shell before doppler injects, silently falling back to
# peer auth under the wrong role.
#
# For automated / non-interactive use see clear-db-fast.sh (same
# behavior, no confirmation delay).
#

set -euo pipefail

if ! command -v doppler &> /dev/null; then
    echo "ERROR: doppler CLI not found — install from https://docs.doppler.com/docs/install-cli" >&2
    exit 1
fi

echo "⚠️  WARNING: This will delete ALL data from the database!"
echo "Press Ctrl+C to cancel, or wait 5 seconds to proceed..."
sleep 5

echo "🗑️  Clearing all tables..."

# Stage SQL in a tempfile to avoid wrestling with three layers of
# nested quoting (outer shell → bash -c → psql heredoc with PL/pgSQL
# `$$ ... $$` and string literals).
SQL_FILE=$(mktemp -t clear-db.XXXXXX.sql)
trap 'rm -f "$SQL_FILE"' EXIT

cat > "$SQL_FILE" <<'SQL'
-- Truncate every public-schema table EXCEPT `_sqlx_migrations` in a
-- single TRUNCATE statement. CASCADE resolves FK dependencies in one
-- shot — we don't need to disable triggers (which requires superuser).
DO $$
DECLARE
    table_list TEXT;
BEGIN
    SELECT string_agg(quote_ident(tablename), ', ')
      INTO table_list
      FROM pg_tables
     WHERE schemaname = 'public'
       AND tablename NOT IN ('_sqlx_migrations');

    IF table_list IS NOT NULL THEN
        EXECUTE 'TRUNCATE TABLE ' || table_list || ' CASCADE';
    END IF;
END
$$;

-- Show row counts on a few high-signal tables to verify the wipe.
SELECT 'users' AS table_name, COUNT(*) AS row_count FROM users
UNION ALL SELECT 'devices',          COUNT(*) FROM devices
UNION ALL SELECT 'conversations',    COUNT(*) FROM conversations
UNION ALL SELECT 'members',          COUNT(*) FROM members
UNION ALL SELECT 'messages',         COUNT(*) FROM messages
UNION ALL SELECT 'key_packages',     COUNT(*) FROM key_packages
UNION ALL SELECT 'welcome_messages', COUNT(*) FROM welcome_messages
UNION ALL SELECT 'event_stream',     COUNT(*) FROM event_stream
UNION ALL SELECT 'group_metadata_blobs', COUNT(*) FROM group_metadata_blobs
ORDER BY table_name;
SQL

doppler run --project catbird-mls --config prd -- \
    bash -c "psql \"\$DATABASE_URL\" -v ON_ERROR_STOP=1 -f \"$SQL_FILE\""

echo ""
echo "✅ Database cleared successfully (via doppler)"
echo "All tables are now empty. Schema and _sqlx_migrations are preserved."

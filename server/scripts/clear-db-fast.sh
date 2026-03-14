#!/bin/bash
set -e

# Fast database clear (no confirmation) - use for automated testing
# Uses catbird_mls database on netcup VPS

export PGPASSWORD='dyvmo0-bewnur-tUrqad'

psql -h localhost -U catbird -d catbird <<'EOF'
-- Disable triggers to avoid foreign key issues
SET session_replication_role = 'replica';

-- Truncate all data tables (in reverse dependency order)
TRUNCATE TABLE message_recipients CASCADE;
TRUNCATE TABLE envelopes CASCADE;
TRUNCATE TABLE cursors CASCADE;
TRUNCATE TABLE event_stream CASCADE;
TRUNCATE TABLE reports CASCADE;
TRUNCATE TABLE pending_welcomes CASCADE;
TRUNCATE TABLE welcome_messages CASCADE;
TRUNCATE TABLE key_packages CASCADE;
TRUNCATE TABLE messages CASCADE;
TRUNCATE TABLE members CASCADE;
TRUNCATE TABLE conversations CASCADE;
TRUNCATE TABLE devices CASCADE;
TRUNCATE TABLE users CASCADE;
TRUNCATE TABLE blobs CASCADE;
TRUNCATE TABLE idempotency_cache CASCADE;

-- Re-enable triggers
SET session_replication_role = 'origin';
EOF

echo "✅ Database cleared"

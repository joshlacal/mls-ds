#!/bin/bash
set -e

# Fast database clear (no confirmation) - use for automated testing

docker exec -i catbird-postgres psql -U catbird -d catbird > /dev/null 2>&1 <<'EOF'
SET session_replication_role = 'replica';
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
SET session_replication_role = 'origin';
EOF

echo "✅ Database cleared"

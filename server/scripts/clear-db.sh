#!/bin/bash
set -e

# Script to clear all data from the MLS database tables
# This preserves the schema but removes all data

echo "⚠️  WARNING: This will delete ALL data from the database!"
echo "Press Ctrl+C to cancel, or wait 5 seconds to proceed..."
sleep 5

echo "🗑️  Clearing all tables..."

# Connect to the database and truncate all tables
docker exec -i catbird-postgres psql -U catbird -d catbird <<'EOF'
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

-- Show table counts to verify
SELECT
  'users' as table_name, COUNT(*) as row_count FROM users
UNION ALL
SELECT 'devices', COUNT(*) FROM devices
UNION ALL
SELECT 'conversations', COUNT(*) FROM conversations
UNION ALL
SELECT 'members', COUNT(*) FROM members
UNION ALL
SELECT 'messages', COUNT(*) FROM messages
UNION ALL
SELECT 'key_packages', COUNT(*) FROM key_packages
UNION ALL
SELECT 'welcome_messages', COUNT(*) FROM welcome_messages
UNION ALL
SELECT 'event_stream', COUNT(*) FROM event_stream
ORDER BY table_name;

EOF

echo ""
echo "✅ Database cleared successfully!"
echo "All tables are now empty. The schema is preserved."

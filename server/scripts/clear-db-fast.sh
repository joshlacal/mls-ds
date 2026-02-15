#!/bin/bash
set -e

# Fast database clear (no confirmation) - use for automated testing
# Uses catbird_mls database on netcup VPS

export PGPASSWORD='dyvmo0-bewnur-tUrqad'

psql -h localhost -U catbird -d catbird_mls <<'EOF'
SET session_replication_role = 'replica';
TRUNCATE TABLE message_recipients CASCADE;
TRUNCATE TABLE message_reactions CASCADE;
TRUNCATE TABLE read_receipts CASCADE;
TRUNCATE TABLE envelopes CASCADE;
TRUNCATE TABLE cursors CASCADE;
TRUNCATE TABLE event_stream CASCADE;
TRUNCATE TABLE reports CASCADE;
TRUNCATE TABLE pending_welcomes CASCADE;
TRUNCATE TABLE welcome_messages CASCADE;
TRUNCATE TABLE pending_device_additions CASCADE;
TRUNCATE TABLE key_packages CASCADE;
TRUNCATE TABLE messages CASCADE;
TRUNCATE TABLE commits CASCADE;
TRUNCATE TABLE members CASCADE;
TRUNCATE TABLE conversation_policy CASCADE;
TRUNCATE TABLE chat_requests CASCADE;
TRUNCATE TABLE chat_request_rate_limits CASCADE;
TRUNCATE TABLE invites CASCADE;
TRUNCATE TABLE conversations CASCADE;
TRUNCATE TABLE devices CASCADE;
TRUNCATE TABLE users CASCADE;
TRUNCATE TABLE blobs CASCADE;
TRUNCATE TABLE idempotency_cache CASCADE;
TRUNCATE TABLE auth_jti_nonce CASCADE;
TRUNCATE TABLE held_messages CASCADE;
TRUNCATE TABLE rejoin_requests CASCADE;
TRUNCATE TABLE admin_actions CASCADE;
TRUNCATE TABLE opt_in CASCADE;
TRUNCATE TABLE delivery_acks CASCADE;
TRUNCATE TABLE outbound_queue CASCADE;
TRUNCATE TABLE sequencer_receipts CASCADE;
SET session_replication_role = 'origin';
EOF

echo "✅ Database cleared"

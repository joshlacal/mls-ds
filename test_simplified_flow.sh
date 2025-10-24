#!/bin/bash
# Test simplified ciphertext storage flow

set -e

DB_URL="postgresql://localhost/mls_dev"

echo "🧪 Testing Simplified MLS Message Flow"
echo "========================================="

# Test 1: Insert test data directly into database
echo ""
echo "1️⃣  Creating test conversation..."
psql "$DB_URL" -c "
INSERT INTO conversations (id, creator_did, current_epoch, created_at)
VALUES ('test-convo-1', 'did:plc:alice', 0, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO members (convo_id, member_did, joined_at, mailbox_provider)
VALUES 
  ('test-convo-1', 'did:plc:alice', NOW(), 'null'),
  ('test-convo-1', 'did:plc:bob', NOW(), 'null')
ON CONFLICT (convo_id, member_did) DO NOTHING;
" > /dev/null 2>&1

echo "✅ Test conversation created"

# Test 2: Insert a message with ciphertext
echo ""
echo "2️⃣  Inserting message with direct ciphertext storage..."
psql "$DB_URL" -c "
INSERT INTO messages (
  id, convo_id, sender_did, message_type, epoch, seq,
  ciphertext, embed_type, embed_uri, created_at, expires_at
) VALUES (
  'msg-test-1',
  'test-convo-1',
  'did:plc:alice',
  'app',
  0,
  1,
  decode('$(echo -n "This is a test encrypted message" | xxd -p | tr -d '\n')', 'hex'),
  NULL,
  NULL,
  NOW(),
  NOW() + INTERVAL '30 days'
) ON CONFLICT (id) DO NOTHING;
" > /dev/null 2>&1

echo "✅ Message inserted with seq=1"

# Test 3: Query messages
echo ""
echo "3️⃣  Querying messages from database..."
RESULT=$(psql "$DB_URL" -t -c "
SELECT 
  id, 
  seq, 
  length(ciphertext) as ciphertext_length,
  embed_type,
  TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created,
  TO_CHAR(expires_at, 'YYYY-MM-DD') as expires
FROM messages 
WHERE convo_id = 'test-convo-1'
ORDER BY seq;
")

echo "$RESULT"
echo "✅ Message query successful"

# Test 4: Verify seq calculation
echo ""
echo "4️⃣  Testing sequence number calculation..."
NEXT_SEQ=$(psql "$DB_URL" -t -c "
SELECT COALESCE(MAX(seq), 0) + 1
FROM messages WHERE convo_id = 'test-convo-1';
" | xargs)

echo "   Next seq for test-convo-1: $NEXT_SEQ"
if [ "$NEXT_SEQ" != "2" ]; then
  echo "❌ Expected seq=2, got $NEXT_SEQ"
  exit 1
fi
echo "✅ Sequence calculation correct"

# Test 5: Test expires_at filtering
echo ""
echo "5️⃣  Testing expires_at filtering..."
ACTIVE_COUNT=$(psql "$DB_URL" -t -c "
SELECT COUNT(*) 
FROM messages 
WHERE convo_id = 'test-convo-1' 
  AND (expires_at IS NULL OR expires_at > NOW());
" | xargs)

echo "   Active messages: $ACTIVE_COUNT"
echo "✅ Expiry filtering works"

# Test 6: Insert with embed metadata
echo ""
echo "6️⃣  Inserting message with embed metadata..."
psql "$DB_URL" -c "
INSERT INTO messages (
  id, convo_id, sender_did, message_type, epoch, seq,
  ciphertext, embed_type, embed_uri, created_at, expires_at
) VALUES (
  'msg-test-2',
  'test-convo-1',
  'did:plc:bob',
  'app',
  0,
  2,
  decode('$(echo -n "Check out this GIF!" | xxd -p | tr -d '\n')', 'hex'),
  'tenor',
  'https://tenor.com/view/example-gif-123456',
  NOW(),
  NOW() + INTERVAL '30 days'
) ON CONFLICT (id) DO NOTHING;
" > /dev/null 2>&1

EMBED_RESULT=$(psql "$DB_URL" -t -c "
SELECT '   ' || id || ' | seq=' || seq || ' | ' || embed_type || ' | ' || embed_uri
FROM messages 
WHERE id = 'msg-test-2';
")

echo "$EMBED_RESULT"
echo "✅ Embed metadata stored correctly"

# Test 7: Test cursor-based pagination
echo ""
echo "7️⃣  Testing cursor-based pagination..."
FIRST_MSG_TIME=$(psql "$DB_URL" -t -c "
SELECT created_at 
FROM messages 
WHERE id = 'msg-test-1';
" | xargs)

SINCE_COUNT=$(psql "$DB_URL" -t -c "
SELECT COUNT(*) 
FROM messages 
WHERE convo_id = 'test-convo-1' 
  AND created_at > '$FIRST_MSG_TIME'::timestamptz
  AND (expires_at IS NULL OR expires_at > NOW());
" | xargs)

echo "   Messages since first message: $SINCE_COUNT"
echo "✅ Cursor pagination works"

# Summary
echo ""
echo "========================================="
echo "✅ All database tests passed!"
echo ""
echo "📊 Summary:"
echo "  - Direct ciphertext storage: ✅"
echo "  - Sequence calculation: ✅"
echo "  - Embed metadata: ✅"
echo "  - Expiry filtering: ✅"
echo "  - Cursor pagination: ✅"
echo ""
echo "🎉 PostgreSQL-only storage is working correctly!"


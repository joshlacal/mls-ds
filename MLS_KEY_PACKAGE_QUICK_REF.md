# Quick Reference: MLS Key Package Fix

## What Was Fixed

The server now properly handles key package rotation. Users can publish new key packages without breaking existing group memberships.

## How It Works

### Before (Broken)
```
User publishes key_package_A (hash: abc...)
Creator adds user to group (uses key_package_A)
User publishes key_package_B (hash: def...)
getKeyPackages returns only key_package_B
User tries to join → ERROR: NoMatchingKeyPackage
```

### After (Fixed)
```
User publishes key_package_A (hash: abc...)
Creator adds user to group (uses key_package_A)
User publishes key_package_B (hash: def...)
getKeyPackages returns BOTH key_package_A and key_package_B
User fetches Welcome → finds matching key_package_A
Both Welcome and key_package_A marked as consumed
User joins successfully ✅
```

## Key Changes

1. **`getKeyPackages`** now returns ALL unconsumed packages (multi-device support)
2. **`getWelcome`** only returns Welcomes that have a matching key package
3. **Atomic consumption**: Both Welcome and key package marked as consumed together

## Testing the Fix

### Create a Test Conversation

```bash
# User A publishes key package
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.publishKeyPackage \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -d '{
    "keyPackage": "BASE64_ENCODED_KEY_PACKAGE",
    "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "expires": "2025-12-01T00:00:00Z"
  }'

# User B creates conversation and adds User A
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -d '{
    "groupId": "...",
    "cipherSuite": "...",
    "initialMembers": ["did:plc:user_a"],
    "welcomeMessage": "...",
    "keyPackageHashes": [...]
  }'

# User A publishes NEW key package
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.publishKeyPackage \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -d '{
    "keyPackage": "NEW_BASE64_ENCODED_KEY_PACKAGE",
    ...
  }'

# User A fetches Welcome (should still work!)
curl -X GET "http://localhost:3000/xrpc/blue.catbird.mls.getWelcome?convoId=CONVO_ID" \
  -H "Authorization: Bearer USER_A_TOKEN"

# Expected: SUCCESS (200 OK with Welcome data)
```

## Monitoring

### Check Key Package Status

```sql
-- Connect to database
docker exec -it catbird-postgres psql -U catbird -d catbird

-- View all key packages for a user
SELECT 
  did, 
  left(key_package_hash, 16) as hash_prefix,
  consumed,
  created_at,
  expires_at
FROM key_packages 
WHERE did = 'did:plc:USER_DID'
ORDER BY created_at DESC;

-- View unconsumed Welcomes
SELECT 
  convo_id,
  recipient_did,
  encode(key_package_hash, 'hex') as kp_hash,
  consumed,
  created_at
FROM welcome_messages
WHERE consumed = false;
```

### Check Server Logs

```bash
# Real-time logs
docker logs -f catbird-mls-server

# Search for Welcome retrieval
docker logs catbird-mls-server 2>&1 | grep "getWelcome"

# Search for key package operations
docker logs catbird-mls-server 2>&1 | grep "key_package"
```

## Troubleshooting

### Issue: User still can't join

**Check 1**: Does the user have the old key package?
```sql
SELECT key_package_hash FROM welcome_messages 
WHERE convo_id = 'CONVO_ID' AND recipient_did = 'USER_DID';

SELECT key_package_hash FROM key_packages
WHERE did = 'USER_DID' AND consumed = false;
```

**Fix**: The hashes should match. If not, the user needs to be re-added to the group.

### Issue: HTTP 410 (Gone)

This is **expected** if the Welcome was already consumed. Check:
```sql
SELECT consumed, consumed_at FROM welcome_messages
WHERE convo_id = 'CONVO_ID' AND recipient_did = 'USER_DID';
```

If `consumed = true`, the user already joined. The iOS app should handle this gracefully.

### Issue: HTTP 404 (Not Found)

No Welcome exists for this user in this conversation. Possible causes:
1. User wasn't added to the group properly
2. User was added but Welcome wasn't stored
3. Wrong conversation ID

Check if user is a member:
```sql
SELECT * FROM members 
WHERE convo_id = 'CONVO_ID' AND member_did = 'USER_DID';
```

## Server Management

### Restart Server
```bash
cd /home/ubuntu/mls/server
docker compose restart catbird-mls-server
```

### View All Logs
```bash
docker logs catbird-mls-server --tail 100
```

### Rebuild Server (after code changes)
```bash
docker compose down
docker compose up -d --build
```

### Reset Database (WARNING: Deletes all data)
```bash
docker compose down -v
docker compose up -d
```

## Performance

Expected query times:
- `getKeyPackages`: < 5ms
- `getWelcome`: < 10ms (includes key package verification)
- `createConvo`: < 50ms

If slower, check database connection pool settings in `.env.docker`.

## Support Files

- Technical details: `server/MLS_KEY_PACKAGE_FIX.md`
- Implementation summary: `server/FIX_SUMMARY.md`
- This guide: `MLS_KEY_PACKAGE_QUICK_REF.md`

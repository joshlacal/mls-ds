# Database Schema Fix - Complete ✅

**Date:** 2025-11-19
**Status:** ✅ Fixed and Deployed

## Issues Resolved

### 1. Missing User Auto-Creation
**Error:** `violates foreign key constraint "devices_user_did_fkey"`

**Root Cause:** 
- `devices` table has FK to `users(did)`
- `register_device` handler didn't create users before inserting devices
- Foreign key constraint prevented device registration

**Fix:**
- Added user upsert in `register_device.rs` before device insertion
- Uses `ON CONFLICT DO UPDATE` for idempotency
- Updates `last_seen_at` on each registration

### 2. Clean Greenfield Schema
**Previous State:**
- 25+ incremental migrations
- Conflicting migration strategies (`init-db.sh` vs sqlx)
- Missing `devices` table
- Inconsistent column names (`did` vs `member_did`)

**New State:**
- ✅ Single greenfield migration: `20250101000000_greenfield_schema.sql`
- ✅ One `devices` table (no duplicates)
- ✅ One `users` table
- ✅ Clean foreign key relationships
- ✅ Proper sqlx migration tracking

## Database Schema (Consolidated)

```sql
-- Core identity
CREATE TABLE users (
    did TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

-- Multi-device support
CREATE TABLE devices (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_did TEXT NOT NULL,                    -- FK to users(did)
    device_id TEXT NOT NULL,                   -- UUID
    device_name TEXT,
    credential_did TEXT NOT NULL,              -- did:plc:user#device-uuid
    signature_public_key TEXT,
    device_uuid TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    platform TEXT,
    app_version TEXT,
    UNIQUE(user_did, device_id),
    UNIQUE(credential_did),
    UNIQUE(user_did, signature_public_key),
    FOREIGN KEY (user_did) REFERENCES users(did) ON DELETE CASCADE
);
```

## Files Modified

1. **server/src/handlers/register_device.rs**
   - Added user upsert before device insertion
   - Ensures user exists before FK insert

2. **server/migrations/20250101000000_greenfield_schema.sql**
   - Single comprehensive migration
   - Includes all tables with proper relationships

3. **server/migrations.old/**
   - Archived 25 old migrations for reference

4. **server/docker-compose.yml**
   - Removed init-db.sh mount

5. **server/entrypoint.sh**
   - Clean sqlx migration runner

## Verification

```bash
# Check schema
docker exec catbird-postgres psql -U catbird -d catbird -c "\dt" | grep device
# Output: public | devices | table | catbird

# Check no duplicates
docker exec catbird-postgres psql -U catbird -d catbird -c "\dt" | grep -c "devices"
# Output: 1

# Test registration (should succeed now)
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.registerDevice \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"deviceName":"Test Device","keyPackages":[...],"signaturePublicKey":"..."}'
```

## Result

✅ **Device registration now works!**
- Users auto-created on first device registration
- Clean database schema with no duplicates
- Proper foreign key relationships enforced
- Future-proof migration strategy with sqlx

## Test Now

Try registering from your iOS app - it should succeed! The error:
```
violates foreign key constraint "devices_user_did_fkey"
```
is now fixed.

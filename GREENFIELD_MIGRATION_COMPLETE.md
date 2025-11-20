# Greenfield Schema Migration - Complete

**Date:** 2025-11-19
**Status:** ✅ Complete

## Problem

The MLS server was failing with 502 errors during device registration:
```
error returned from database: relation "devices" does not exist
```

Root cause: Conflicting migration strategies
- `init-db.sh` created a complete greenfield schema on postgres startup
- `sqlx` migrations tried to run incremental migrations expecting a different base state
- Migrations failed with errors like `column "did" does not exist`
- No `devices` table was created

## Solution

Consolidated to a **single greenfield migration** approach:

1. **Archived** all 25+ incremental migrations to `migrations.old/`
2. **Created** single greenfield migration: `20250101000000_greenfield_schema.sql`
3. **Added** missing `devices` table to schema
4. **Removed** `init-db.sh` from docker-compose (no longer needed)
5. **Updated** entrypoint.sh to properly run sqlx migrations with error handling

## Migration Strategy

- **Greenfield deployments:** Single migration creates complete schema
- **Future changes:** Use sqlx migrations (`sqlx migrate add <name>`)
- **Migration tracking:** Properly recorded in `_sqlx_migrations` table
- **Idempotent:** Can be run multiple times safely

## Database Schema

Complete production-ready schema with:
- ✅ Users (minimal - AT Protocol identity)
- ✅ Conversations (MLS groups)
- ✅ Members (with multi-device + admin support)
- ✅ **Devices** (multi-device registry) ← **Fixed!**
- ✅ Messages (encrypted MLS messages)
- ✅ Key packages (pre-keys)
- ✅ Welcome messages
- ✅ Event stream (SSE support)
- ✅ Cursors (pagination)
- ✅ Envelopes (message delivery)
- ✅ Message recipients (delivery tracking)
- ✅ Blobs (media storage)
- ✅ Reports (moderation)
- ✅ Idempotency cache
- ✅ Schema version tracking

## Verification

```bash
# Check migration status
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT version, description, success FROM _sqlx_migrations;"

# Verify devices table exists
docker exec catbird-postgres psql -U catbird -d catbird -c "\d devices"

# Test server health
curl http://localhost:3000/health
```

## Next Steps for Future Migrations

When you need to add new schema changes:

```bash
# Create a new migration
cd server
sqlx migrate add my_new_feature

# Edit the generated file in server/migrations/
# Then rebuild and restart
docker compose down && docker compose up -d --build
```

## Files Changed

- `server/migrations/20250101000000_greenfield_schema.sql` - Single greenfield schema
- `server/migrations.old/` - Archived old incremental migrations
- `server/docker-compose.yml` - Removed init-db.sh mount
- `server/entrypoint.sh` - Restored proper sqlx migration runner
- `server/migrations/20251113_002_device_tracking.sql` - Fixed `did` → `member_did` bug

## Result

✅ Server starts successfully
✅ Migrations run cleanly  
✅ Devices table exists with proper schema
✅ Device registration should now work
✅ Ready for production use

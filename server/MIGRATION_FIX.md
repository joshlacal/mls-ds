# Database Migration Fix

## Problem
The Docker container was running migrations incorrectly, causing schema inconsistencies on every restart:
- **Root cause**: `entrypoint.sh` was using raw `psql` to run migrations instead of `sqlx migrate run`
- **Result**: Migrations weren't tracked in `_sqlx_migrations`, so they'd re-run on every restart but fail due to conflicts
- **Symptoms**: Missing `ciphertext`, `key_package_hash` columns → 500 errors

## The Fix

### 1. Created Idempotent Schema Migration
- File: `migrations/20251101_000_ensure_schema_complete.sql`
- Purpose: Ensures all required columns exist regardless of migration state
- Uses `IF NOT EXISTS` checks - safe to run multiple times

### 2. Fixed entrypoint.sh
- **Before**: Ran every `.sql` file with `psql` (no state tracking)
- **After**: Runs schema-ensure migration as fallback
- **Proper solution**: Should use `sqlx migrate run` but requires sqlx-cli in Docker image

## Permanent Solution

To completely fix this, update the Dockerfile to include sqlx-cli:

```dockerfile
# In Dockerfile, add before the final stage:
RUN cargo install sqlx-cli --no-default-features --features postgres
```

Then update entrypoint.sh to use:
```bash
sqlx migrate run --database-url "$DATABASE_URL" --source /app/migrations
```

## Testing the Fix

```bash
# Restart container - should work without manual column additions
cd server
docker compose restart mls-server

# Check logs - should see "✅ Migrations complete"
docker logs catbird-mls-server --tail 30

# Test API
curl http://localhost:3000/health
```

## Why This Happened

1. **Migration chaos**: 20 migration files, many conflicting/duplicate
2. **No state tracking**: Using psql directly doesn't use `_sqlx_migrations` table
3. **Non-idempotent migrations**: Old migrations would fail on re-run

## Current State

- ✅ Idempotent schema-ensure migration in place
- ✅ entrypoint.sh runs schema validation on startup
- ✅ All required columns exist
- ⚠️  Still using psql (not ideal but works)

## TODO

- [ ] Clean up duplicate migrations (keep only 20251021+ series)
- [ ] Add sqlx-cli to Docker image
- [ ] Update entrypoint.sh to use `sqlx migrate run`
- [ ] Add migration validation in CI/CD

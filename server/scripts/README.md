# Database Maintenance Scripts

This directory contains utility scripts for managing the MLS database.

## Clear Database Scripts

### `clear-db.sh` - Interactive Clear (Safe)

Clears all data from database tables with a 5-second confirmation prompt.

**Usage:**
```bash
cd /home/ubuntu/mls/server
./scripts/clear-db.sh
```

**Features:**
- 5-second warning before clearing
- Shows table counts after clearing
- Preserves schema (tables, indexes, constraints)
- Safe for manual use

**When to use:**
- Manual testing/development
- When you want confirmation before clearing
- When you want to see the results

---

### `clear-db-fast.sh` - Instant Clear (Automated)

Immediately clears all data without confirmation.

**Usage:**
```bash
cd /home/ubuntu/mls/server
./scripts/clear-db-fast.sh
```

**Features:**
- No confirmation prompt
- Silent operation (only shows success message)
- Fast execution
- Preserves schema

**When to use:**
- Automated testing scripts
- CI/CD pipelines
- When you're absolutely sure you want to clear

---

## How It Works

Both scripts use PostgreSQL's `TRUNCATE` command which:
- Removes all rows from tables
- Preserves table structure, indexes, and constraints
- Is faster than `DELETE` for removing all data
- Handles foreign key constraints with `CASCADE`

**Temporary disables triggers** during truncation to avoid foreign key conflicts:
```sql
SET session_replication_role = 'replica';  -- Disable triggers
TRUNCATE TABLE ... CASCADE;
SET session_replication_role = 'origin';   -- Re-enable triggers
```

## Tables Cleared

The following tables are truncated (in order):
1. `message_recipients`
2. `envelopes`
3. `cursors`
4. `event_stream`
5. `reports`
6. `pending_welcomes`
7. `welcome_messages`
8. `key_packages`
9. `messages`
10. `members`
11. `conversations`
12. `devices`
13. `users`
14. `blobs`
15. `idempotency_cache`

**NOT cleared:**
- `_sqlx_migrations` - Migration tracking
- `schema_version` - Schema version tracking

## Examples

### Clear for fresh testing
```bash
# Clear database
./scripts/clear-db-fast.sh

# Restart server to verify
docker restart catbird-mls-server

# Database is now empty and ready for testing
```

### Clear in test script
```bash
#!/bin/bash
# test-workflow.sh

# Clear database before each test run
./scripts/clear-db-fast.sh

# Run your tests
npm test

# Clear again for next run
./scripts/clear-db-fast.sh
```

### Verify database is empty
```bash
./scripts/clear-db.sh

# Output shows:
#  table_name    | row_count
# ---------------+-----------
#  blobs         |         0
#  conversations |         0
#  devices       |         0
#  ...
```

## Safety Notes

⚠️ **WARNING:** These scripts delete ALL data from the database!

- **Production:** DO NOT run these scripts in production
- **Backup:** No backup is created - data is permanently deleted
- **Schema:** Only data is removed - schema remains intact
- **Recovery:** There is no way to recover cleared data

## Alternative: Full Database Reset

If you want to completely recreate the database with fresh schema:

```bash
# Stop containers and remove volumes
cd /home/ubuntu/mls/server
docker compose down -v

# Restart (will recreate database with init-db.sh)
docker compose up -d
```

This is slower but ensures a completely clean state including schema.

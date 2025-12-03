# MLS Server Scripts

This directory contains utility scripts for managing the MLS server.

## Deployment Scripts

### `deploy.sh` - Deploy to Production
Builds and deploys the server with optional environment configuration.

```bash
./scripts/deploy.sh [environment]
```

### `rollback.sh` - Rollback Deployment
Rolls back to a previously saved binary.

```bash
./scripts/rollback.sh
```

## Database Scripts

### `clear-db.sh` - Interactive Clear (Safe)
Clears all data from database tables with a 5-second confirmation prompt.

```bash
./scripts/clear-db.sh
```

### `clear-db-fast.sh` - Instant Clear (Automated)
Immediately clears all data without confirmation.

```bash
./scripts/clear-db-fast.sh
```

### `init-db.sh` - Initialize Database
Applies the greenfield schema to a fresh database.

```bash
./scripts/init-db.sh
```

### `run-migrations.sh` - Run Migrations
Runs SQLx migrations against the database.

```bash
./scripts/run-migrations.sh [DATABASE_URL]
```

### `backup-db.sh` - Backup Database
Creates a compressed backup of the database.

```bash
./scripts/backup-db.sh [BACKUP_DIR]
```

### `restore-db.sh` - Restore Database
Restores a database from a backup file.

```bash
./scripts/restore-db.sh <BACKUP_FILE>
```

## Monitoring Scripts

### `health-check.sh` - Health Check
Verifies server health with retries.

```bash
./scripts/health-check.sh [URL]
```

### `smoke-test.sh` - Smoke Tests
Runs comprehensive smoke tests after deployment.

```bash
./scripts/smoke-test.sh [BASE_URL]
```

## How Database Clear Works

Both clear scripts use PostgreSQL's `TRUNCATE` command which:
- Removes all rows from tables
- Preserves table structure, indexes, and constraints
- Is faster than `DELETE` for removing all data
- Handles foreign key constraints with `CASCADE`

## Tables Cleared

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

# Restart server
sudo systemctl restart catbird-mls-server

# Database is now empty and ready for testing
```

### View logs
```bash
sudo journalctl -u catbird-mls-server -f
```

### Check service status
```bash
sudo systemctl status catbird-mls-server
```

## Safety Notes

⚠️ **WARNING:** Clear scripts delete ALL data from the database!

- **Production:** Use extreme caution in production
- **Backup:** No backup is created - data is permanently deleted
- **Schema:** Only data is removed - schema remains intact
- **Recovery:** There is no way to recover cleared data

## Full Database Reset

If you want to completely recreate the database with fresh schema:

```bash
# Clear the database
./scripts/clear-db-fast.sh

# Re-apply schema
./scripts/init-db.sh
```

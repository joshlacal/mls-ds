# MLS Server Scripts

This directory contains utility scripts for managing the MLS server.

**Migrations are held** ([../migrations/README.md](../migrations/README.md#status)). Until the production migration is authorized, do not run `deploy.sh` or `run-migrations.sh` against production. No script here wipes a production database.

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

### `reset-dev-db.sh` - Reset a Local Development Database
Drops, recreates and migrates the `catbird` database of one local federation stack container (`docker-compose.federation.yml`: ds1 on port `5433`, ds2 on `5434`). The URL must name `localhost` or `127.0.0.1`, one of those ports and the database `catbird`, with no query string. Production's database is also named `catbird` (migration `20250101000000` grants on it), so before anything is dropped the live server must report database `catbird` and the `cluster_name` the compose file gives that port's container (`catbird-federation-ds1` or `catbird-federation-ds2`). The allowlist is fixed in the script: there is no override, no Doppler and no `.env` lookup. A fresh database must apply migration `20260728000004`, so the activation approval is required. `make reset-dev-db URL=...` runs it. Restart the home that uses the database afterwards so it re-initializes its chat fence; `docker compose -f docker-compose.federation.yml down -v` and `up` reset both homes together.

```bash
CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
  ./scripts/reset-dev-db.sh postgresql://catbird:catbird_dev_password@localhost:5433/catbird
```

### `init-db.sh` - Legacy Schema
Applies the pre-clean-slate `schema_greenfield.sql` with `psql`. It does not run the migration chain and does not produce the current schema; use `run-migrations.sh`.

```bash
./scripts/init-db.sh
```

### `run-migrations.sh` - Run Migrations
Applies the April 2026 version repair when `_sqlx_migrations` exists, then `sqlx migrate run`. If `20260728000004` is pending, it refuses before applying anything unless `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed` is set. It prints only the target host, port and database; a URL it cannot parse is not printed at all. See [../migrations/README.md](../migrations/README.md#running-migrations).

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

## Examples

### View logs
```bash
sudo journalctl -u catbird-mls-server -f
```

### Check service status
```bash
sudo systemctl status catbird-mls-server
```

## Safety Notes

⚠️ **WARNING:** `reset-dev-db.sh` deletes a database and `restore-db.sh` overwrites one. `reset-dev-db.sh` takes no backup and accepts only the local compose databases listed above.

## Full Database Reset (development only)

Use `reset-dev-db.sh`, or drop, recreate and migrate by hand as in [../migrations/README.md](../migrations/README.md#reset-a-development-database). `init-db.sh` does not reset a clean-slate database.

`test_ops_safety.py` runs `reset-dev-db.sh` and `run-migrations.sh` against stub `psql` and `sqlx` binaries. It also checks the CI workflow, the hostile-federation gate, the root federation compose file and its fixture keys.

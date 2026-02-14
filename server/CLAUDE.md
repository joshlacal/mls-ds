# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Catbird MLS Server** is a production-ready MLS (Message Layer Security) group chat server with ATProto (AT Protocol) identity integration. Built with Rust, Axum, and OpenMLS, it provides end-to-end encrypted group messaging with decentralized identity.

## Build & Development Commands

### Local Development

```bash
# Build the project
cargo build

# Build release binary
cargo build --release

# Run tests
cargo test

# Run specific test
cargo test --test integration_test

# Run the server locally
cargo run

# Run database migrations
make migrate
# or: ./scripts/run-migrations.sh
```

### Deployment

```bash
# Deploy with data preservation
make deploy
# or: ./deploy-update.sh

# Fresh deploy (wipes database)
make deploy-fresh
# or: ./deploy-fresh.sh

# Restart the server
make restart
# or: sudo systemctl restart catbird-mls-server

# View logs
make logs
# or: sudo journalctl -u catbird-mls-server -f

# Check status
make status
# or: sudo systemctl status catbird-mls-server
```

### Database Operations

```bash
# Clear all data (with confirmation)
make clear-db

# Clear all data (no confirmation)
make clear-db-fast

# Backup database
make backup

# Restore database
make restore BACKUP=/path/to/backup.sql.gz
```

## Architecture Overview

### Core Components

1. **Authentication Layer** (`src/auth.rs`)
   - ATProto JWT validation with ES256/ES256K signature verification
   - DID document resolution via PLC directory
   - Replay attack prevention with jti (JWT ID) tracking
   - Rate limiting and token caching
   - Environment variables control auth behavior:
     - `SERVICE_DID`: Required audience for inter-service JWTs
     - `ENFORCE_LXM`: Require JWT `lxm` claim to match called NSID
     - `ENFORCE_JTI`: Require `jti` and reject replays (default: true)
     - `JTI_TTL_SECONDS`: TTL for jti replay cache (default: 120)

2. **XRPC API Handlers** (`src/handlers/`)
   - Modular handler structure, one file per endpoint
   - All routes under `/xrpc/blue.catbird.mls.*` namespace:
     - `createConvo`: Create new MLS group
     - `addMembers`: Add participants to existing group
     - `sendMessage`: Send encrypted message
     - `leaveConvo`: Leave conversation (soft delete)
     - `getMessages`: Retrieve message history
     - `getConvos`: List user's conversations
     - `publishKeyPackage`: Upload pre-keys for adding to groups
     - `getKeyPackages`: Fetch pre-keys for inviting users
     - `updateCursor`: Update read position

3. **Database Layer** (`src/db.rs`, `src/storage.rs`)
   - PostgreSQL 16 with connection pooling (sqlx)
   - Tables: `conversations`, `members`, `messages`, `key_packages`, `blobs`, `envelopes`, `cursors`, `event_stream`
   - Soft delete pattern for member removal (`left_at` timestamp)
   - Migration files in `migrations/` directory (applied sequentially)

4. **Realtime Events** (`src/realtime/`)
   - SSE (Server-Sent Events) for conversation updates
   - WebSocket support with DAG-CBOR encoding
   - Event stream with cursor-based pagination
   - Buffer size configurable via `SSE_BUFFER_SIZE` env var

5. **Health Checks** (`src/health.rs`)
   - `/health`: Detailed health status with database checks
   - `/health/live`: Liveness probe
   - `/health/ready`: Readiness probe

### Key Architectural Patterns

**Authentication Flow:**
1. Client sends JWT in `Authorization: Bearer <token>` header
2. Auth middleware extracts and validates JWT signature against issuer's DID document
3. Optional lxm validation ensures token is authorized for specific endpoint
4. Optional jti validation prevents replay attacks
5. Validated `AuthUser` is passed to handlers via Axum extractor

**Database Schema Migration Pattern:**
- Sequential SQL files: `YYYYMMDD_NNN_description.sql`
- Schema evolution: `title` → `name` column (migration 002)
- Added `group_id` column for MLS group identifiers (migration 005)
- When adding new columns, use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`

**MLS Integration:**
- OpenMLS library for protocol implementation
- Key packages stored in database for async member addition
- Blob storage for encrypted message payloads

**Deploying Code Changes:**

```bash
# Build and deploy (preserves data)
./deploy-update.sh

# Or use make
make deploy
```

This script:
1. Builds the release binary
2. Restarts the systemd service

## Database Operations

### Running Migrations

```bash
# Via Makefile
make migrate

# Direct script
./scripts/run-migrations.sh
```

### Schema Inspection

```bash
# List tables
psql -h localhost -U catbird -d catbird -c "\dt"

# Describe table
psql -h localhost -U catbird -d catbird -c "\d conversations"

# Check for column existence
psql -h localhost -U catbird -d catbird -c "SELECT column_name FROM information_schema.columns WHERE table_name='conversations';"
```

### Common Database Issues

**Column name mismatches:** The schema evolved from `title` to `name` for conversations. Ensure INSERT/UPDATE statements use `name`, not `title`.

**Missing columns:** If handlers fail with "column does not exist", check if migration was applied and server uses updated code.

## Important Notes for Code Changes

### When Modifying Handlers

1. **Database column references:** Always check current schema before writing SQL queries. The `conversations` table uses `name` (not `title`) and `group_id` columns.

2. **Auth enforcement:** Handlers must call `enforce_standard()` or `enforce_privileged()` to check authorization:
   ```rust
   if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.createConvo") {
       return Err(StatusCode::UNAUTHORIZED);
   }
   ```

3. **Error handling:** Use `tracing::error!` for errors that return 500, `tracing::warn!` for client errors (400s).

### When Modifying Schema

1. Create new migration file: `migrations/YYYYMMDD_NNN_description.sql`
2. Use `IF NOT EXISTS` / `IF EXISTS` for idempotent migrations
3. Test migration on fresh database AND existing database
4. Update relevant handlers to use new columns
5. Rebuild and redeploy server after schema changes

### When Debugging Production Issues

1. Check logs: `sudo journalctl -u catbird-mls-server | grep ERROR`
2. Check specific timeframe: `sudo journalctl -u catbird-mls-server --since "1 hour ago"`
3. Verify database schema: `psql -h localhost -U catbird -d catbird -c "\d table_name"`
4. Check if server is using latest code: Look for log patterns that would only appear in new code

## Environment Configuration

### Required Variables

- `DATABASE_URL`: PostgreSQL connection (e.g., `postgresql://catbird:password@localhost:5432/catbird`)
- `REDIS_URL`: Redis connection (e.g., `redis://localhost:6379`)

### Optional Variables

- `RUST_LOG`: Logging level (default: `info`)
- `SERVER_PORT`: Server port (default: `3000`)
- `SERVICE_DID`: Required audience for JWTs
- `ENFORCE_LXM`: Require lxm claim matching endpoint (default: false)
- `ENFORCE_JTI`: Require jti for replay prevention (default: true)
- `JTI_TTL_SECONDS`: Replay cache TTL (default: 120)
- `SSE_BUFFER_SIZE`: Realtime event buffer size (default: 5000)

## Systemd Service

The server runs as a systemd service (`catbird-mls-server`). The service file is located at:
- `/home/ubuntu/mls/server/catbird-mls-server.service`

Key service commands:
```bash
# Start/stop/restart
sudo systemctl start catbird-mls-server
sudo systemctl stop catbird-mls-server
sudo systemctl restart catbird-mls-server

# Check status
sudo systemctl status catbird-mls-server

# View logs
sudo journalctl -u catbird-mls-server -f

# Enable on boot
sudo systemctl enable catbird-mls-server
```

## Related Documentation

- `README.md`: Project overview and quick start
- `DEPLOYMENT.md`: Complete deployment guide
- `DATABASE_SCHEMA.md`: Detailed schema documentation
- `QUICK_REFERENCE.md`: Command reference
- `src/auth_README.md`: Authentication implementation details
- `migrations/README.md`: Migration guidelines

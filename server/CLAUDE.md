# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Catbird MLS Server** is a production-ready MLS (Message Layer Security) group chat server with ATProto (AT Protocol) identity integration. Built with Rust, Axum, and OpenMLS, it provides end-to-end encrypted group messaging with decentralized identity.

## Build & Development Commands

### Local Development

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run specific test
cargo test --test integration_test

# Run the server locally (requires postgres & redis running)
cargo run

# Start infrastructure with Docker Compose
docker-compose up -d postgres redis

# Run database migrations
make migrate
# or: ./scripts/run-migrations.sh
```

### Docker Compose Development

```bash
# Start all services (postgres, redis, mls-server)
make run

# Start in development mode with hot reload
make run-dev

# View logs
make logs

# Stop services
make stop

# Clean up containers and volumes
make clean
```

### Docker Image Management

**IMPORTANT**: The project uses a Cargo workspace, so the build output is in `/home/ubuntu/mls/target` (parent directory), NOT in `server/target`.

```bash
# Quick deploy (RECOMMENDED - handles all steps correctly)
cd /home/ubuntu/mls
./deploy.sh

# Manual deployment (if you need more control)
cd /home/ubuntu/mls/server

# 1. Build release binary with offline sqlx mode
SQLX_OFFLINE=true cargo build --release

# 2. Copy binary from workspace target dir to Docker build location
cp ../target/release/catbird-server server/catbird-server

# 3. Stop and remove old container
docker stop catbird-mls-server && docker rm catbird-mls-server

# 4. Rebuild Docker image without cache (important!)
docker build --no-cache -f Dockerfile.prebuilt -t server-mls-server .

# 5. Start new container with correct network and environment
docker run -d \
  --name catbird-mls-server \
  --network server_catbird-network \
  -p 3000:3000 \
  -e DATABASE_URL="postgresql://catbird:changeme@catbird-postgres:5432/catbird" \
  -e REDIS_URL="redis://catbird-redis:6379" \
  -e RUST_LOG="info" \
  -e SERVICE_DID="did:web:mls.catbird.blue" \
  server-mls-server

# 6. Verify the binary was updated
docker exec catbird-mls-server ls -lh /app/catbird-server
```

**Why these steps are necessary:**

1. **Cargo Workspace**: The project root has a workspace Cargo.toml, so builds output to `/home/ubuntu/mls/target`, not `server/target`
2. **Binary Location**: Docker copies from `server/catbird-server`, so you must copy from the workspace target directory
3. **Docker Cache**: Docker's layer caching can prevent the new binary from being copied even if the file changed. Use `--no-cache` to force a fresh build
4. **Container Recreation**: `docker restart` doesn't reload the image. You must stop, remove, and recreate the container to use the new image

### Production Deployment

```bash
# Deploy with Docker Compose
make deploy

# Deploy to Kubernetes
make deploy-k8s

# Database backup
make backup

# Database restore
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
     - `JWT_SECRET`: Enables HS256 dev-mode tokens

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
   - `/health/live`: Liveness probe (Kubernetes)
   - `/health/ready`: Readiness probe (Kubernetes)

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
- Blob storage for encrypted message payloads (moving to R2)

**Docker Container Binary Updates:**

The server runs in Docker. To deploy code changes, use the automated script:

```bash
cd /home/ubuntu/mls
./deploy.sh
```

This script handles all the steps correctly:
1. Build: `SQLX_OFFLINE=true cargo build --release`
2. Copy binary from workspace: `cp ../target/release/catbird-server server/catbird-server`
3. Stop & remove container: `docker stop catbird-mls-server && docker rm catbird-mls-server`
4. Rebuild image (no cache): `docker build --no-cache -f Dockerfile.prebuilt -t server-mls-server .`
5. Recreate container with proper network and env vars
6. Verify the deployment

**CRITICAL**:
- `docker restart` does NOT pick up code changes - you must rebuild the image and recreate the container
- Use `--no-cache` when rebuilding to ensure the new binary is copied
- The binary is in `/home/ubuntu/mls/target/release/` (workspace root), NOT `server/target/release/`

## Database Operations

### Running Migrations

```bash
# Via Makefile
make migrate

# Direct script
./scripts/run-migrations.sh

# Manual (inside postgres container)
docker exec catbird-postgres psql -U catbird -d catbird -f /path/to/migration.sql
```

### Schema Inspection

```bash
# List tables
docker exec catbird-postgres psql -U catbird -d catbird -c "\dt"

# Describe table
docker exec catbird-postgres psql -U catbird -d catbird -c "\d conversations"

# Check for column existence
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT column_name FROM information_schema.columns WHERE table_name='conversations';"
```

### Common Database Issues

**Column name mismatches:** The schema evolved from `title` to `name` for conversations. Ensure INSERT/UPDATE statements use `name`, not `title`.

**Missing columns:** If handlers fail with "column does not exist", check if migration was applied and container uses updated code.

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

1. Check Docker logs: `docker logs catbird-mls-server 2>&1 | grep ERROR`
2. Check specific timeframe: `docker logs catbird-mls-server 2>&1 | grep "21:46"`
3. Verify database schema: `docker exec catbird-postgres psql -U catbird -d catbird -c "\d table_name"`
4. Check if server is using latest code: Look for log patterns that would only appear in new code

## Environment Configuration

### Required Variables

- `DATABASE_URL`: PostgreSQL connection (e.g., `postgresql://catbird:password@postgres:5432/catbird`)
- `REDIS_URL`: Redis connection (e.g., `redis://:password@redis:6379`)
- `JWT_SECRET`: Secret for HS256 dev tokens (not used in production)

### Optional Variables

- `RUST_LOG`: Logging level (default: `info`)
- `SERVER_PORT`: Server port (default: `3000`)
- `SERVICE_DID`: Required audience for JWTs
- `ENFORCE_LXM`: Require lxm claim matching endpoint (default: false)
- `ENFORCE_JTI`: Require jti for replay prevention (default: true)
- `JTI_TTL_SECONDS`: Replay cache TTL (default: 120)
- `SSE_BUFFER_SIZE`: Realtime event buffer size (default: 5000)
- `ENABLE_DIRECT_XRPC_PROXY`: Dev-only catch-all proxy (default: false)
- `UPSTREAM_XRPC_BASE`: Proxy base URL (default: `http://127.0.0.1:3000`)

## Production Deployment Notes

The server runs in Docker containers with docker-compose (simple deployment) or Kubernetes (production scale). There are three separate Docker Compose environments visible on this system:

1. **docker-compose.yml**: Main production configuration
2. **docker-compose.dev.yml**: Development overrides (hot reload, debug logging)
3. **staging/docker-compose.staging.yml**: Staging environment

Key deployment considerations:

- Use Dockerfile.prebuilt for faster rebuilds (copies pre-built binary)
- Container runs as non-root user `catbird` (UID 1000)
- Health checks required for Kubernetes liveness/readiness probes
- Migrations should run before starting the server (Job in K8s, script in Docker)
- Backup strategy: Daily automated backups via CronJob (K8s) or cron script (Docker)

## Related Documentation

- `README.md`: Project overview and quick start
- `DEPLOYMENT.md`: Complete deployment guide
- `DATABASE_SCHEMA.md`: Detailed schema documentation
- `QUICK_REFERENCE.md`: Command reference
- `src/auth_README.md`: Authentication implementation details
- `migrations/README.md`: Migration guidelines
- `k8s/README.md`: Kubernetes-specific documentation

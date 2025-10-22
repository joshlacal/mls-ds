# MLS Server Setup Guide

This guide covers the setup and operation of the Catbird MLS (Message Layer Security) Rust server for local development and testing.

## Prerequisites

- **Rust**: Latest stable version (1.70+)
- **PostgreSQL**: Version 14+ (installed via Homebrew or package manager)
- **Redis**: Version 6+ (installed via Homebrew or package manager)
- **sqlx-cli**: For database migrations (`cargo install sqlx-cli`)

## Quick Start

### 1. Database Setup

The server uses PostgreSQL for persistent storage and Redis for caching/rate limiting.

**Create the database:**
```bash
psql -U $USER -d postgres -c "CREATE DATABASE mls_dev;"
```

**Run migrations:**
```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
sqlx migrate run --database-url postgresql://localhost/mls_dev
```

This creates the following tables:
- `conversations` - MLS group conversations
- `members` - Conversation membership
- `messages` - Encrypted messages
- `key_packages` - Pre-published MLS key packages
- `blobs` - Binary data storage

### 2. Redis Setup

**Check if Redis is running:**
```bash
redis-cli ping
```

If not running, start Redis:
```bash
# macOS (Homebrew)
brew services start redis

# Or run in foreground
redis-server
```

### 3. Environment Configuration

The server uses a `.env` file for configuration. A sample configuration has been created at `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/.env`:

```env
# PostgreSQL Configuration
DATABASE_URL=postgresql://localhost/mls_dev
TEST_DATABASE_URL=postgresql://localhost/mls_dev_test

# Redis Configuration (using local Redis without password)
REDIS_URL=redis://localhost:6379

# Server Configuration
SERVER_PORT=8080

# JWT Secret (for local testing only - CHANGE IN PRODUCTION)
JWT_SECRET=test_secret_for_local_development_only

# Logging
RUST_LOG=info
```

**Important**: The JWT_SECRET shown above is for local testing only. In production, use a strong, randomly generated secret.

### 4. Build the Server

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
cargo build --release
```

The first build will take several minutes as it compiles all dependencies including OpenMLS cryptographic libraries.

### 5. Run the Server

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
cargo run --release
```

The server will start on port 8080 (or the port specified in `.env`).

Expected output:
```json
{"timestamp":"2025-10-21T17:47:52.118043Z","level":"INFO","fields":{"message":"Starting Catbird MLS Server"},"target":"catbird_server"}
{"timestamp":"2025-10-21T17:47:52.318154Z","level":"INFO","fields":{"message":"Metrics initialized"},"target":"catbird_server"}
{"timestamp":"2025-10-21T17:47:52.350853Z","level":"INFO","fields":{"message":"Database initialized"},"target":"catbird_server"}
{"timestamp":"2025-10-21T17:47:52.351028Z","level":"INFO","fields":{"message":"Server listening on 0.0.0.0:8080"},"target":"catbird_server"}
```

## Testing the Server

### Health Check Endpoints

```bash
# Main health check
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","timestamp":1761068888,"version":"0.1.0","checks":{"database":"healthy","memory":"healthy"}}

# Readiness probe (for Kubernetes)
curl http://localhost:8080/health/ready
# Expected: {"ready":true,"checks":{"database":true}}

# Liveness probe (for Kubernetes)
curl http://localhost:8080/health/live
# Expected: OK
```

### Metrics Endpoint

Prometheus-compatible metrics are exposed at:
```bash
curl http://localhost:8080/metrics
```

### API Endpoints

The server exposes AT Protocol XRPC endpoints:

- `POST /xrpc/blue.catbird.mls.createConvo` - Create MLS group
- `POST /xrpc/blue.catbird.mls.addMembers` - Add members to group
- `POST /xrpc/blue.catbird.mls.sendMessage` - Send encrypted message
- `GET /xrpc/blue.catbird.mls.getMessages` - Fetch messages
- `POST /xrpc/blue.catbird.mls.publishKeyPackage` - Publish key package
- `GET /xrpc/blue.catbird.mls.getKeyPackages` - Get key packages
- `POST /xrpc/blue.catbird.mls.uploadBlob` - Upload binary data

## Server Management

### Starting the Server

**Development mode (faster compilation, slower runtime):**
```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
cargo run
```

**Release mode (optimized, recommended for testing):**
```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
cargo run --release
```

**Background mode:**
```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls/server
cargo run --release > server.log 2>&1 &
echo $! > server.pid
```

### Stopping the Server

**If running in foreground:**
Press `Ctrl+C`

**If running in background:**
```bash
# Using saved PID
kill $(cat server.pid)

# Or find by port
lsof -ti:8080 | xargs kill

# Force kill if needed
lsof -ti:8080 | xargs kill -9
```

### Checking Server Status

```bash
# Check if server is running
lsof -i:8080

# Check server health
curl -f http://localhost:8080/health || echo "Server not responding"

# View logs (if running in background)
tail -f server.log
```

## Troubleshooting

### Issue: Database Connection Failed

**Error**: `database "catbird" does not exist` or `Failed to connect to database`

**Solution**:
1. Verify PostgreSQL is running: `pg_isready`
2. Check database exists: `psql -U $USER -d postgres -c "\l" | grep mls_dev`
3. Verify DATABASE_URL in `.env` file
4. Ensure migrations have been run: `sqlx migrate run --database-url postgresql://localhost/mls_dev`

### Issue: Redis Connection Failed

**Error**: Connection refused when connecting to Redis

**Solution**:
1. Check Redis is running: `redis-cli ping` (should return "PONG")
2. Start Redis if not running: `brew services start redis` (macOS) or `redis-server`
3. Verify REDIS_URL in `.env` file

### Issue: Port Already in Use

**Error**: `Address already in use (os error 48)`

**Solution**:
1. Check what's using the port: `lsof -i:8080`
2. Kill the process: `lsof -ti:8080 | xargs kill`
3. Or change SERVER_PORT in `.env` to a different port

### Issue: Compilation Errors

**Error**: Metrics macro errors or other compilation failures

**Solution**:
1. Ensure you're using the latest stable Rust: `rustup update stable`
2. Clean build artifacts: `cargo clean`
3. Rebuild: `cargo build --release`

### Issue: Migration Failed

**Error**: Migration fails with constraint or index errors

**Solution**:
1. Check migration status: `sqlx migrate info --database-url postgresql://localhost/mls_dev`
2. If needed, drop and recreate database:
   ```bash
   psql -U $USER -d postgres -c "DROP DATABASE IF EXISTS mls_dev;"
   psql -U $USER -d postgres -c "CREATE DATABASE mls_dev;"
   sqlx migrate run --database-url postgresql://localhost/mls_dev
   ```

## Database Maintenance

### View Migration Status
```bash
sqlx migrate info --database-url postgresql://localhost/mls_dev
```

### Reset Database (CAUTION: Deletes all data)
```bash
# Drop database
psql -U $USER -d postgres -c "DROP DATABASE mls_dev;"

# Recreate and migrate
psql -U $USER -d postgres -c "CREATE DATABASE mls_dev;"
sqlx migrate run --database-url postgresql://localhost/mls_dev
```

### Backup Database
```bash
pg_dump -U $USER mls_dev > mls_dev_backup.sql
```

### Restore Database
```bash
psql -U $USER -d mls_dev < mls_dev_backup.sql
```

## Development Tips

### Hot Reload with cargo-watch
```bash
cargo install cargo-watch
cargo watch -x run
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

### Viewing Logs
The server uses structured JSON logging. To view logs with filtering:

```bash
# Set log level
RUST_LOG=debug cargo run --release

# Filter by module
RUST_LOG=catbird_server=debug,sqlx=info cargo run --release
```

### Code Formatting and Linting
```bash
# Format code
cargo fmt

# Run clippy
cargo clippy

# Fix warnings automatically
cargo fix --bin "catbird-server"
```

## Server Status Summary

✅ **Server Built Successfully**: All dependencies compiled without errors (with expected warnings for unused code)

✅ **Database Configured**: PostgreSQL database `mls_dev` created with 6 tables

✅ **Redis Connected**: Redis running on localhost:6379

✅ **Migrations Applied**: All 5 migrations successfully applied

✅ **Server Running**: Listening on 0.0.0.0:8080

✅ **Health Checks Passing**: All health endpoints returning healthy status

## Next Steps

1. **Authentication**: Implement AT Protocol DID authentication for API endpoints
2. **Testing**: Run integration tests with real MLS clients
3. **Monitoring**: Set up Prometheus to scrape metrics endpoint
4. **Performance**: Run load tests to validate throughput
5. **Security**: Review cryptographic implementations and key management
6. **Documentation**: Document API endpoints with examples

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://localhost/mls_dev` | PostgreSQL connection string |
| `TEST_DATABASE_URL` | `postgresql://localhost/mls_dev_test` | Test database connection |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `SERVER_PORT` | `8080` | HTTP server port |
| `JWT_SECRET` | (required) | Secret key for JWT token signing |
| `RUST_LOG` | `info` | Logging level (error, warn, info, debug, trace) |

### Database Schema

- **conversations**: Stores MLS group metadata and epoch state
- **members**: Tracks group membership and roles
- **messages**: Encrypted message storage with sender/timestamp
- **key_packages**: Pre-published MLS key packages for adding members
- **blobs**: Binary data storage with content addressing

## Deployment Considerations

For production deployment, see:
- `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/DEPLOYMENT.md`
- `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/DEPLOYMENT_CHECKLIST.md`

Key production requirements:
- Use strong JWT_SECRET
- Enable TLS/HTTPS
- Configure connection pooling
- Set up monitoring and alerting
- Implement backup strategy
- Use environment-specific configuration

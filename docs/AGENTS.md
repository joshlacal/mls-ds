# Catbird MLS Deployment Guide

## Overview

Catbird MLS is deployed using Docker Compose with three services:
- **PostgreSQL** database (port 5433)
- **Redis** cache (port 6380)
- **MLS Server** (port 3000)

## Deployment Architecture

### Docker Services

All services run in Docker containers managed by `docker-compose.yml`:

```
catbird-postgres    → PostgreSQL 16 (Alpine) on port 5433
catbird-redis       → Redis 7 (Alpine) on port 6380  
catbird-mls-server  → Rust-based MLS service on port 3000
```

### Health Checks

Each service includes health checks:
- **PostgreSQL**: `pg_isready -U catbird -d catbird`
- **Redis**: `redis-cli ping`
- **MLS Server**: `curl -f http://localhost:3000/health`

### Deployment Commands

```bash
# Start all services
docker compose up -d

# Check service status
docker ps
docker compose ps

# View logs
docker logs catbird-mls-server --tail 100
docker logs catbird-postgres --tail 50
docker logs catbird-redis --tail 50

# Restart services
docker compose restart
docker compose restart catbird-mls-server

# Stop services
docker compose down
```

## Server Status Interpretation

### Current Issue: Welcome Message Already Consumed

The client error `HTTP 400: Failed to fetch Welcome message` corresponds to server status **410** (Gone):

```
WARN: Welcome already consumed for user did:plc:34x52srgxttjewbke5hguloh 
      in conversation 5a6d6f52-8c22-4e3c-bdef-e0cabdffbf39
status: 410
```

**Meaning**: The Welcome message for this conversation was already fetched and consumed. This is expected MLS behavior - Welcome messages are one-time use.

**Client Impact**: The client receives a 400 error because the iOS client isn't properly handling the 410 status code.

**Solution**: The client should:
1. Not retry fetching consumed Welcome messages
2. Use existing MLS group state if Welcome was previously processed
3. Handle 410 status gracefully (not as an error)

## Database Access

```bash
# Connect to PostgreSQL
docker exec -it catbird-postgres psql -U catbird -d catbird

# Useful queries
SELECT * FROM conversations;
SELECT * FROM members WHERE member_did = 'did:plc:34x52srgxttjewbke5hguloh';
SELECT * FROM welcome_messages WHERE consumed = false;
SELECT * FROM key_packages WHERE consumed = false;
```

## Monitoring

The server logs use structured JSON logging with fields:
- `timestamp`: ISO 8601 timestamp
- `level`: DEBUG, INFO, WARN, ERROR
- `message`: Log message
- `target`: Source module
- `span`: Request context (method, URI, auth user)

### Key Log Patterns

**Successful authentication**:
```
"Authenticated request from DID: did:plc:..."
```

**Welcome message consumed**:
```
"Welcome already consumed for user ... in conversation ..."
status: 410
```

**Normal operation**:
```
"Found 3 conversations for user ..."
"SSE subscription request"
```

## Environment Configuration

Server configured via `.env` file:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string  
- `PORT`: Server port (default: 3000)
- `RUST_LOG`: Log level configuration

## Troubleshooting

### Service not starting
```bash
docker compose logs catbird-mls-server
docker compose ps
```

### Database connection issues
```bash
docker exec -it catbird-postgres pg_isready -U catbird
```

### Reset and rebuild
```bash
docker compose down
docker compose up -d --build
```

## Production Considerations

- Database backups via `pg_dump`
- Redis persistence configured
- Health check endpoints at `/health`
- Structured logging for monitoring integration
- Container restart policies set to `unless-stopped`

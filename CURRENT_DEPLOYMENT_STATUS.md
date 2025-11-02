# Current Deployment Status

**Date**: November 2, 2025  
**Environment**: Production  
**Status**: ✅ OPERATIONAL  

---

## Deployment Overview

### Infrastructure

```yaml
Provider: OVH Cloud
Location: Ubuntu 22.04 LTS Server
IP Address: 51.81.33.144
Domain: mls.catbird.blue
SSL: Let's Encrypt (Auto-renewal enabled)
```

### Service Architecture

```
┌──────────────────────────────────────────────┐
│  Internet Traffic                             │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│  Nginx Reverse Proxy (Port 80/443)           │
│  - SSL/TLS Termination                       │
│  - DID Document Serving                      │
│  - Request Routing                           │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│  Docker Compose Stack                        │
│                                               │
│  ┌──────────────────────────────────┐        │
│  │  MLS Server Container             │        │
│  │  - Port: 3000                     │        │
│  │  - Image: server-mls-server       │        │
│  │  - Health: ✅ Healthy              │        │
│  └────────┬──────────────┬───────────┘        │
│           │              │                    │
│  ┌────────▼────────┐  ┌──▼──────────────┐    │
│  │  PostgreSQL 16  │  │  Redis 7        │    │
│  │  Port: 5433     │  │  Port: 6380     │    │
│  │  Health: ✅      │  │  Health: ✅      │    │
│  └─────────────────┘  └─────────────────┘    │
└──────────────────────────────────────────────┘
```

---

## Service Status

### Running Containers

| Service | Container Name | Image | Status | Ports |
|---------|---------------|-------|--------|-------|
| MLS Server | catbird-mls-server | server-mls-server | ✅ Healthy | 3000:3000 |
| PostgreSQL | catbird-postgres | postgres:16-alpine | ✅ Healthy | 5433:5432 |
| Redis | catbird-redis | redis:7-alpine | ✅ Healthy | 6380:6379 |

### Health Check Results

```json
{
  "status": "healthy",
  "timestamp": 1762052868,
  "version": "0.1.0",
  "checks": {
    "database": "healthy",
    "memory": "healthy"
  }
}
```

### API Endpoints

All endpoints accessible via HTTPS:

- ✅ `https://mls.catbird.blue/.well-known/did.json` - DID Document
- ✅ `https://mls.catbird.blue/health` - Health Status
- ✅ `https://mls.catbird.blue/health/ready` - Readiness Probe
- ✅ `https://mls.catbird.blue/health/live` - Liveness Probe
- ✅ `https://mls.catbird.blue/metrics` - Prometheus Metrics
- ✅ `https://mls.catbird.blue/xrpc/*` - AT Protocol XRPC Methods

---

## Configuration Details

### Environment Variables

**Docker Compose** (`/home/ubuntu/mls/server/.env`):
```env
POSTGRES_PASSWORD=********
REDIS_PASSWORD=********
JWT_SECRET=********
RUST_LOG=info
SERVICE_DID=did:web:mls.catbird.blue
```

**Application** (`/home/ubuntu/mls/server/.env`):
```env
DATABASE_URL=postgresql://catbird:********@localhost:5433/catbird
REDIS_URL=redis://:********@localhost:6380
SERVER_PORT=3000
JWT_SECRET=********
RUST_LOG=info
SERVICE_DID=did:web:mls.catbird.blue
```

### Database Schema

Current migrations applied:

```
20251101_001_initial_schema.sql
20251101_002_backfill_key_package_hashes.sql
```

Tables:
- `_sqlx_migrations` - Migration tracking
- `conversations` - MLS group conversations
- `members` - Conversation members
- `messages` - Encrypted messages
- `key_packages` - MLS key packages
- `welcome_messages` - Welcome messages for new members

---

## SSL/TLS Configuration

### Certificate Details

```
Certificate: /etc/letsencrypt/live/mls.catbird.blue/fullchain.pem
Private Key: /etc/letsencrypt/live/mls.catbird.blue/privkey.pem
Issuer: Let's Encrypt
Auto-renewal: ✅ Enabled (via Certbot)
```

### Nginx Configuration

File: `/etc/nginx/sites-available/mls.catbird.blue`

**Key Features**:
- SSL/TLS termination
- HTTP to HTTPS redirect
- DID document static file serving
- Reverse proxy to Docker container
- WebSocket upgrade support
- SSE (Server-Sent Events) support
- Long timeout for persistent connections

---

## AT Protocol Integration

### DID Document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:web:mls.catbird.blue",
  "verificationMethod": [
    {
      "id": "did:web:mls.catbird.blue#atproto",
      "type": "Multikey",
      "controller": "did:web:mls.catbird.blue",
      "publicKeyMultibase": "zWo9ufkfcQw8iA4yO-6XCwv0XhfGN1AmV01jJ0K5rmpc"
    }
  ],
  "service": [
    {
      "id": "#atproto_mls",
      "type": "AtprotoMlsService",
      "serviceEndpoint": "https://mls.catbird.blue"
    }
  ]
}
```

### Cryptographic Keys

- **Private Key**: `/home/ubuntu/mls/did_key.pem` (ED25519, 600 permissions)
- **Public Key**: `zWo9ufkfcQw8iA4yO-6XCwv0XhfGN1AmV01jJ0K5rmpc`
- **Algorithm**: ED25519

---

## Available XRPC Methods

All methods accessible via `/xrpc/blue.catbird.mls.*`:

1. **createConvo** - Create new MLS conversation
2. **addMembers** - Add members to conversation
3. **sendMessage** - Send encrypted message
4. **getMessages** - Retrieve messages from conversation
5. **publishKeyPackage** - Upload MLS key package
6. **getKeyPackages** - Fetch available key packages
7. **leaveConvo** - Leave conversation
8. **getWelcome** - Retrieve welcome message
9. **uploadBlob** - Upload binary attachment

---

## Monitoring & Logs

### Docker Logs

```bash
# View all logs
docker-compose logs -f

# View MLS server logs only
docker-compose logs -f mls-server

# Export logs
docker-compose logs --no-color > server-logs.txt
```

### Nginx Logs

```bash
# Access log
sudo tail -f /var/log/nginx/mls.catbird.blue.access.log

# Error log
sudo tail -f /var/log/nginx/mls.catbird.blue.error.log
```

### Metrics Available

Prometheus-compatible metrics exposed at `/metrics`:

- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency histogram
- `database_connections_active` - Active database connections
- `process_resident_memory_bytes` - Memory usage
- `process_cpu_seconds_total` - CPU time

---

## Backup Strategy

### Automated Backups

Currently manual - recommended to set up:

```bash
# Daily database backup (cron)
0 2 * * * docker exec catbird-postgres pg_dump -U catbird catbird | gzip > /home/ubuntu/backups/db_$(date +\%Y\%m\%d_\%H\%M\%S).sql.gz
```

### Manual Backup

```bash
# Database backup
docker exec catbird-postgres pg_dump -U catbird catbird > backup.sql

# Configuration backup
tar -czf config_backup.tar.gz /home/ubuntu/mls/server/.env /home/ubuntu/mls/.well-known/
```

---

## Management Commands

### Service Control

```bash
# Start all services
cd /home/ubuntu/mls/server
docker-compose up -d

# Stop all services
docker-compose down

# Restart MLS server
docker-compose restart mls-server

# View status
docker-compose ps

# Update and rebuild
git pull
cd server
cargo build --release
docker-compose build --no-cache mls-server
docker-compose up -d
```

### Database Access

```bash
# Connect to database
docker exec -it catbird-postgres psql -U catbird -d catbird

# Run query
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT COUNT(*) FROM conversations;"

# Check database size
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT pg_size_pretty(pg_database_size('catbird'));"
```

### Redis Access

```bash
# Connect to Redis CLI
docker exec -it catbird-redis redis-cli -a YOUR_REDIS_PASSWORD

# Check Redis info
docker exec catbird-redis redis-cli -a PASSWORD INFO server

# Monitor commands
docker exec catbird-redis redis-cli -a PASSWORD MONITOR
```

---

## Security Configuration

### Firewall (UFW)

```bash
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
```

### Fail2ban

Status: Active (SSH protection enabled)

### File Permissions

```bash
/home/ubuntu/mls/did_key.pem          600 (Private key)
/home/ubuntu/mls/server/.env          600 (Secrets)
/home/ubuntu/mls/.well-known/         755 (Public DID)
```

### Network Isolation

- PostgreSQL: Only accessible from Docker network (not exposed to internet)
- Redis: Only accessible from Docker network (not exposed to internet)
- MLS Server: Only accessible via Nginx reverse proxy

---

## Performance Metrics

### Current Resource Usage

```
Container           CPU %    MEM USAGE / LIMIT    MEM %
catbird-mls-server  0.8%     31.74 MiB            ~1%
catbird-postgres    0.2%     45 MiB               ~1.1%
catbird-redis       0.1%     8 MiB                ~0.2%
```

### Response Times

- Health endpoint: ~5ms
- DID document: ~2ms (static file)
- Database queries: ~10-50ms average

---

## Known Issues & Limitations

### Current Limitations

1. **No automated backups** - Manual backup procedure documented
2. **No alerting** - Health checks available but no automated alerts
3. **Single server** - No high availability/redundancy
4. **Manual deployment** - No CI/CD pipeline (manual git pull + rebuild)

### Recommended Improvements

1. Set up automated daily database backups
2. Configure monitoring alerts (e.g., via Uptime Robot, Pingdom)
3. Implement log rotation
4. Set up staging environment
5. Implement CI/CD pipeline
6. Add rate limiting
7. Implement request logging middleware
8. Set up Grafana dashboards for metrics visualization

---

## Testing Endpoints

### Health Checks

```bash
# Basic health
curl https://mls.catbird.blue/health

# Expected: {"status":"healthy","timestamp":...,"version":"0.1.0",...}

# Readiness
curl https://mls.catbird.blue/health/ready

# Expected: {"ready":true,"checks":{"database":true}}

# Liveness
curl https://mls.catbird.blue/health/live

# Expected: OK
```

### DID Document

```bash
curl https://mls.catbird.blue/.well-known/did.json

# Expected: Valid JSON DID document
```

### SSL Certificate

```bash
curl -vI https://mls.catbird.blue 2>&1 | grep "SSL certificate"

# Expected: Valid Let's Encrypt certificate
```

---

## Disaster Recovery

### Recovery Time Objectives

- **RTO (Recovery Time Objective)**: 30 minutes
- **RPO (Recovery Point Objective)**: 24 hours (with daily backups)

### Recovery Procedure

1. Provision new server with same specs
2. Install dependencies (Docker, Nginx, Certbot)
3. Clone repository
4. Build application
5. Restore database from backup
6. Restore configuration files
7. Configure DNS (update A record)
8. Install SSL certificate
9. Start services
10. Verify health checks

**Estimated time**: 30-60 minutes

---

## Support Information

### Documentation

- `PRODUCTION_REPLICATION_GUIDE.md` - Complete replication guide
- `DEPLOYMENT_SUMMARY.txt` - Quick deployment overview
- `ATPROTO_SERVICE_SETUP.md` - AT Protocol integration
- `TESTING_GUIDE.md` - API testing examples

### Quick Reference

```bash
# Service location
cd /home/ubuntu/mls

# Start services
cd server && docker-compose up -d

# View logs
docker-compose logs -f mls-server

# Health check
curl https://mls.catbird.blue/health

# Database backup
docker exec catbird-postgres pg_dump -U catbird catbird > backup.sql

# SSL renewal
sudo certbot renew
```

---

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-02 | 1.0 | Production deployment documented |
| 2025-11-01 | 0.9 | Docker deployment completed |
| 2025-10-31 | 0.8 | Key package fixes implemented |
| 2025-10-22 | 0.5 | Initial server setup |

---

**Status**: ✅ Production Operational  
**Uptime**: Monitored via health endpoints  
**Last Verified**: November 2, 2025 03:07 UTC

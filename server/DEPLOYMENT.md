# Catbird MLS Server - Deployment Guide

Complete production deployment guide for the Catbird MLS Server using systemd.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Systemd Deployment](#systemd-deployment)
- [Database Management](#database-management)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
- [Backup and Restore](#backup-and-restore)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Tools

- Rust 1.75+ (for building the server)
- PostgreSQL 16+
- Redis 7+
- systemd

### Infrastructure Requirements

**Minimum Resources:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB

**Production Recommended:**
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 100GB+ SSD

## Quick Start

### Initial Setup

1. **Navigate to the server directory:**
```bash
cd /home/ubuntu/mls/server
```

2. **Configure environment:**
```bash
# Edit .env file
cp .env.example .env
nano .env
```

3. **Build and deploy:**
```bash
./deploy-update.sh
```

4. **Verify deployment:**
```bash
curl http://localhost:3000/health
```

## Systemd Deployment

### Service Configuration

The systemd service file is located at `/home/ubuntu/mls/server/catbird-mls-server.service`.

**Install the service:**
```bash
sudo cp catbird-mls-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable catbird-mls-server
sudo systemctl start catbird-mls-server
```

### Service Management

```bash
# Start/stop/restart
sudo systemctl start catbird-mls-server
sudo systemctl stop catbird-mls-server
sudo systemctl restart catbird-mls-server

# Check status
sudo systemctl status catbird-mls-server

# View logs
sudo journalctl -u catbird-mls-server -f
```

### Deployment Scripts

**Update deployment (preserves data):**
```bash
./deploy-update.sh
```

**Fresh deployment (wipes data):**
```bash
./deploy-fresh.sh
```

**Quick rebuild:**
```bash
./rebuild.sh
```

## Database Management

### PostgreSQL Setup

1. **Create database and user:**
```bash
sudo -u postgres createuser catbird
sudo -u postgres createdb catbird -O catbird
sudo -u postgres psql -c "ALTER USER catbird WITH PASSWORD 'your_password';"
```

2. **Apply schema:**
```bash
./scripts/init-db.sh
# or
./scripts/run-migrations.sh
```

### Database Operations

```bash
# List tables
psql -h localhost -U catbird -d catbird -c "\dt"

# Describe table
psql -h localhost -U catbird -d catbird -c "\d conversations"

# Clear all data
./scripts/clear-db-fast.sh
```

## Monitoring and Health Checks

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Full health status with component checks |
| `/health/live` | Liveness probe |
| `/health/ready` | Readiness probe |

### Health Check Script

```bash
./scripts/health-check.sh http://localhost:3000
```

### Log Monitoring

```bash
# Follow logs in real-time
sudo journalctl -u catbird-mls-server -f

# View recent logs
sudo journalctl -u catbird-mls-server -n 100

# View logs from specific time
sudo journalctl -u catbird-mls-server --since "1 hour ago"
```

## Backup and Restore

### Database Backup

```bash
# Create backup
./scripts/backup-db.sh /var/backups/catbird

# Backups are automatically compressed and dated
ls -la /var/backups/catbird/
```

### Database Restore

```bash
./scripts/restore-db.sh /var/backups/catbird/catbird_backup_20241201_120000.sql.gz
```

## Security

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `SERVICE_DID` | Service DID for JWT validation | Recommended |

### Production Checklist

- [ ] Use strong database password
- [ ] Use strong Redis password (if applicable)
- [ ] Set `RUST_LOG=info` (not debug)
- [ ] Enable firewall, only expose port 3000
- [ ] Set up TLS termination (nginx/caddy)
- [ ] Configure rate limiting
- [ ] Enable automated backups
- [ ] Set up log monitoring/alerting

## Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check service status
sudo systemctl status catbird-mls-server

# View recent logs
sudo journalctl -u catbird-mls-server -n 50 --no-pager

# Check if port is in use
sudo lsof -i :3000
```

**Database connection issues:**
```bash
# Test database connection
psql -h localhost -U catbird -d catbird -c "SELECT 1"

# Check PostgreSQL is running
sudo systemctl status postgresql
```

**Health check failing:**
```bash
# Check server is responding
curl -v http://localhost:3000/health

# Check database connectivity
curl http://localhost:3000/health | jq .checks.database
```

### Rollback

If a deployment causes issues:

```bash
./scripts/rollback.sh
```

This will restore the previous binary and restart the service.

# Catbird MLS Server - Quick Reference

## 🚀 Quick Start Commands

### Development
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run the server locally
cargo run
```

### Deployment
```bash
# Deploy (preserves data)
make deploy
# or: ./deploy-update.sh

# Fresh deploy (wipes data)
make deploy-fresh
# or: ./deploy-fresh.sh

# Quick rebuild
./rebuild.sh
```

### Service Management
```bash
# Start/stop/restart
make start
make stop
make restart

# Check status
make status

# View logs
make logs
```

## 📁 File Structure

```
server/
├── catbird-mls-server.service      # Systemd service file
├── Makefile                        # Convenience commands
├── DEPLOYMENT.md                   # Complete deployment guide
│
├── src/
│   ├── health.rs                   # Health check endpoints
│   └── ...                         # Application code
│
├── scripts/
│   ├── deploy.sh                   # Deployment script
│   ├── init-db.sh                  # Database initialization
│   ├── run-migrations.sh           # Run database migrations
│   ├── backup-db.sh                # Database backup
│   ├── restore-db.sh               # Database restore
│   ├── clear-db.sh                 # Clear database (with confirmation)
│   ├── clear-db-fast.sh            # Clear database (no confirmation)
│   ├── health-check.sh             # Health check script
│   ├── smoke-test.sh               # Smoke tests
│   └── rollback.sh                 # Rollback to previous version
│
└── migrations/                     # Database migrations
```

## 🏥 Health Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/health` | Detailed status | JSON with checks |
| `/health/live` | Liveness probe | `200 OK` |
| `/health/ready` | Readiness probe | `200 OK` |

## 🔧 Common Operations

### Database Operations
```bash
# Run migrations
make migrate

# Clear all data
make clear-db

# Clear all data (no confirmation)
make clear-db-fast

# Backup database
make backup

# Restore database
make restore BACKUP=/path/to/backup.sql.gz
```

### Debugging
```bash
# View logs
sudo journalctl -u catbird-mls-server -f

# Recent logs
sudo journalctl -u catbird-mls-server -n 100

# Logs from specific time
sudo journalctl -u catbird-mls-server --since "1 hour ago"

# Check service status
sudo systemctl status catbird-mls-server
```

### Database Access
```bash
# Connect to database
psql -h localhost -U catbird -d catbird

# List tables
psql -h localhost -U catbird -d catbird -c "\dt"

# Describe a table
psql -h localhost -U catbird -d catbird -c "\d conversations"
```

## 🔒 Security Checklist

- [ ] Configure strong database password
- [ ] Set appropriate `SERVICE_DID`
- [ ] Disable `JWT_SECRET` in production
- [ ] Enable TLS/SSL via reverse proxy
- [ ] Configure firewall rules
- [ ] Enable automated backups
- [ ] Set up log monitoring

## 📊 Monitoring

### Health Check
```bash
# Quick health check
curl http://localhost:3000/health

# Full health check script
./scripts/health-check.sh

# Smoke tests
./scripts/smoke-test.sh
```

### Log Monitoring
```bash
# Follow logs
sudo journalctl -u catbird-mls-server -f

# Search for errors
sudo journalctl -u catbird-mls-server | grep ERROR

# View logs in JSON format
sudo journalctl -u catbird-mls-server -o json
```

## 🔄 Updates and Rollbacks

### Update Deployment
```bash
# Build and deploy
./deploy-update.sh

# Or manually
cargo build --release
sudo systemctl restart catbird-mls-server
```

### Rollback
```bash
# Restore previous binary
./scripts/rollback.sh
```

## 🆘 Troubleshooting

### Server won't start
```bash
# Check service status
sudo systemctl status catbird-mls-server

# Check logs
sudo journalctl -u catbird-mls-server -n 50

# Check if port is in use
sudo lsof -i :3000
```

### Database connection issues
```bash
# Test database
psql -h localhost -U catbird -d catbird -c "SELECT 1"

# Check PostgreSQL status
sudo systemctl status postgresql
```

### Health check failing
```bash
# Check server response
curl -v http://localhost:3000/health

# Check database component
curl http://localhost:3000/health | jq .checks.database
```

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide
- **[CLAUDE.md](CLAUDE.md)** - Developer guide
- **[README.md](README.md)** - Project overview
- **[scripts/README.md](scripts/README.md)** - Scripts documentation

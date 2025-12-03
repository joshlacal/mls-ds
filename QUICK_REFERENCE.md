# Quick Reference Guide

## JWT Token Generation

### Generate Test Tokens
```bash
cd server/scripts
python3 generate_test_jwt.py
```

**Output**: Creates 4 token files:
- `test_token_1h.txt` - Short-lived (1 hour)
- `test_token_24h.txt` - Medium-lived (24 hours)  
- `test_token_168h.txt` - Long-lived (1 week)
- `test_token_720h.txt` - Extended (30 days)

### Use Tokens in API Calls
```bash
# Load token
TOKEN=$(cat server/test_token_24h.txt)

# Make API call
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/xrpc/blue.catbird.mls.listGroups
```

### Configure Token Generation
```bash
# Set environment variables before running
export JWT_SECRET="your-secret-key"
export SERVICE_DID="did:web:your-service"
export ISSUER_DID="did:plc:your-issuer"

python3 generate_test_jwt.py
```

---

## Deployment

### Quick Deploy (preserves data)
```bash
cd server
./deploy-update.sh
# or: make deploy
```

### Fresh Deploy (wipes data)
```bash
cd server
./deploy-fresh.sh
# or: make deploy-fresh
```

### Service Control
```bash
# Start
sudo systemctl start catbird-mls-server

# Stop
sudo systemctl stop catbird-mls-server

# Restart
sudo systemctl restart catbird-mls-server

# Status
sudo systemctl status catbird-mls-server
```

---

## Database Operations

### Clear Database
```bash
cd server/scripts
./clear-db-fast.sh  # No confirmation
./clear-db.sh       # With confirmation
```

### Run Migrations
```bash
cd server
./scripts/run-migrations.sh
```

### Backup/Restore
```bash
# Backup
./scripts/backup-db.sh /var/backups/catbird

# Restore
./scripts/restore-db.sh /path/to/backup.sql.gz
```

### Database Access
```bash
psql -h localhost -U catbird -d catbird

# List tables
psql -h localhost -U catbird -d catbird -c "\dt"

# Describe table
psql -h localhost -U catbird -d catbird -c "\d messages"
```

---

## Logging & Monitoring

### View Logs
```bash
# Follow logs in real-time
sudo journalctl -u catbird-mls-server -f

# Recent logs
sudo journalctl -u catbird-mls-server -n 100

# Logs from specific time
sudo journalctl -u catbird-mls-server --since "1 hour ago"

# Filter for errors
sudo journalctl -u catbird-mls-server | grep ERROR
```

### Health Check
```bash
# Quick check
curl http://localhost:3000/health

# Full health check script
./scripts/health-check.sh

# Smoke tests
./scripts/smoke-test.sh
```

---

## API Testing

### Test Endpoints
```bash
# Health check
curl http://localhost:3000/health

# With authentication
TOKEN=$(cat server/test_token_24h.txt)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/xrpc/blue.catbird.mls.getConvos
```

### Rate Limit Check
```bash
# Check current limits
curl http://localhost:3000/health | jq .
```

---

## Troubleshooting

### Server Won't Start
```bash
# Check status
sudo systemctl status catbird-mls-server

# View recent logs
sudo journalctl -u catbird-mls-server -n 50

# Check port
sudo lsof -i :3000
```

### Database Issues
```bash
# Test connection
psql -h localhost -U catbird -d catbird -c "SELECT 1"

# Check PostgreSQL status
sudo systemctl status postgresql
```

### Rollback
```bash
./scripts/rollback.sh
```

---

## Key Files

| File | Description |
|------|-------------|
| `server/.env` | Environment configuration |
| `server/catbird-mls-server.service` | Systemd service file |
| `server/schema_greenfield.sql` | Database schema |
| `server/scripts/` | Utility scripts |

---

## Make Commands

```bash
cd server

make help           # Show all commands
make build          # Build release
make deploy         # Deploy update
make deploy-fresh   # Fresh deploy
make restart        # Restart service
make logs           # View logs
make status         # Check status
make clear-db       # Clear database
```

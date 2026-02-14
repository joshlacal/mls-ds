# Production Deployment Checklist

Use this checklist when deploying the Catbird MLS Server to production.

## Pre-Deployment

### Security
- [ ] Generate strong, random passwords for all services
  - [ ] PostgreSQL password (min 32 characters)
  - [ ] Redis password (min 32 characters, if applicable)
- [ ] Configure `SERVICE_DID` for JWT validation
- [ ] Configure firewall rules (only expose port 3000)
- [ ] Set up SSL/TLS termination (nginx/caddy)
- [ ] Review rate limiting configuration

### Infrastructure
- [ ] PostgreSQL 16+ installed and running
- [ ] Redis 7+ installed and running
- [ ] Rust toolchain installed
- [ ] systemd configured
- [ ] Backup storage configured

### Configuration
- [ ] Review `.env` settings
- [ ] Set appropriate log level (`RUST_LOG=info`)
- [ ] Configure backup retention policies
- [ ] Set up log rotation

## Deployment Steps

### 1. Database Setup
```bash
# Create database and user
sudo -u postgres createuser catbird
sudo -u postgres createdb catbird -O catbird
sudo -u postgres psql -c "ALTER USER catbird WITH PASSWORD 'YOUR_SECURE_PASSWORD';"
```
- [ ] Database created
- [ ] User created with password

### 2. Configure Environment
```bash
cd /home/ubuntu/mls/server
cp .env.example .env
nano .env
```

Update these values:
- [ ] `DATABASE_URL` with correct password
- [ ] `REDIS_URL` configured
- [ ] `SERVICE_DID` set
- [ ] `RUST_LOG=info`

### 3. Build and Deploy
```bash
# Build release binary
cargo build --release

# Run migrations
./scripts/run-migrations.sh

# Install systemd service
sudo cp catbird-mls-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable catbird-mls-server
sudo systemctl start catbird-mls-server
```
- [ ] Binary built
- [ ] Migrations applied
- [ ] Service enabled and started

### 4. Verify Deployment
```bash
# Check service status
sudo systemctl status catbird-mls-server

# Run health check
./scripts/health-check.sh

# Run smoke tests
./scripts/smoke-test.sh
```
- [ ] Service is running
- [ ] Health check passes
- [ ] Smoke tests pass

## Post-Deployment

### Monitoring
- [ ] Verify logs are being collected
- [ ] Set up alerting for health check failures
- [ ] Monitor resource usage

### Backup
- [ ] Configure automated backups
```bash
# Add to crontab
0 2 * * * /home/ubuntu/mls/server/scripts/backup-db.sh /var/backups/catbird
```
- [ ] Test backup and restore procedure

### Security
- [ ] Verify firewall rules
- [ ] Test TLS configuration
- [ ] Review access logs

## Rollback Procedure

If issues occur after deployment:

```bash
# Quick rollback
./scripts/rollback.sh

# Manual rollback
sudo systemctl stop catbird-mls-server
# Restore previous binary
sudo systemctl start catbird-mls-server
```

## Maintenance

### Regular Tasks
- Weekly: Review logs for errors
- Monthly: Test backup/restore
- Quarterly: Update dependencies
- Annually: Rotate credentials

### Updates
```bash
# Pull latest code
git pull

# Deploy update
./deploy-update.sh
```

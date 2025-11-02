# Production Deployment Replication Guide

**Last Updated**: November 2, 2025  
**Current Environment**: Ubuntu Server on OVH  
**Service**: MLS AT Protocol Service (mls.catbird.blue)

---

## Table of Contents

1. [Current Production Setup](#current-production-setup)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Step-by-Step Replication](#step-by-step-replication)
4. [Environment Configuration](#environment-configuration)
5. [SSL & DNS Setup](#ssl--dns-setup)
6. [Service Management](#service-management)
7. [Monitoring & Health Checks](#monitoring--health-checks)
8. [Backup & Recovery](#backup--recovery)
9. [Troubleshooting](#troubleshooting)

---

## Current Production Setup

### Deployment Overview

**Infrastructure:**
- **Provider**: OVH Cloud
- **Server**: Ubuntu 22.04 LTS
- **IP Address**: 51.81.33.144
- **Domain**: mls.catbird.blue
- **SSL**: Let's Encrypt via Certbot

**Architecture:**
```
Internet
    │
    ▼
┌─────────────────┐
│  Nginx (443)    │ ← SSL/TLS Termination
│  Reverse Proxy  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      Docker Compose Stack           │
│  ┌──────────────────────────────┐  │
│  │  MLS Server (Port 3000)       │  │
│  │  Rust/Axum Application        │  │
│  └────────┬────────────┬──────────┘  │
│           │            │             │
│  ┌────────▼──────┐  ┌──▼──────────┐ │
│  │  PostgreSQL   │  │    Redis     │ │
│  │  (Port 5433)  │  │  (Port 6380) │ │
│  └───────────────┘  └──────────────┘ │
└─────────────────────────────────────┘
```

### Current Services Status

```bash
✅ MLS Server: Running on port 3000 (Docker container)
✅ PostgreSQL: Running on port 5433 (Docker container)  
✅ Redis: Running on port 6380 (Docker container)
✅ Nginx: Running on port 80/443 (System service)
✅ SSL: Active (Let's Encrypt certificate)
✅ Health Status: All systems operational
```

### Application Version

- **Server Version**: 0.1.0
- **Rust Edition**: 2021
- **Framework**: Axum 0.7
- **OpenMLS**: 0.5
- **Database**: PostgreSQL 16
- **Cache**: Redis 7

---

## Infrastructure Requirements

### Minimum Server Specifications

```yaml
CPU: 2 cores (4 cores recommended)
RAM: 4GB (8GB recommended)
Disk: 50GB SSD (100GB+ for production)
Network: 100 Mbps (1 Gbps recommended)
OS: Ubuntu 22.04 LTS or newer
```

### Required Software

```bash
# Core requirements
- Docker Engine 24.0+
- Docker Compose 2.20+
- Nginx 1.18+
- Certbot (for SSL)
- Git

# Development tools (for building)
- Rust 1.75+
- PostgreSQL client tools
- curl, jq (for testing)
```

### DNS Requirements

```dns
Type:  A Record
Name:  mls (or your subdomain)
Value: Your server IP address
TTL:   300 (5 minutes)
```

---

## Step-by-Step Replication

### Phase 1: Server Provisioning

#### 1.1 Provision Server

```bash
# For OVH, AWS, DigitalOcean, or any VPS provider:
# - Ubuntu 22.04 LTS
# - Minimum 2 CPU / 4GB RAM / 50GB SSD
# - Allow ports: 80, 443, 22 (SSH)

# Connect to server
ssh root@YOUR_SERVER_IP
```

#### 1.2 Initial Server Setup

```bash
# Update system
apt update && apt upgrade -y

# Install essential packages
apt install -y curl wget git vim ufw fail2ban

# Configure firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Create non-root user (recommended)
adduser ubuntu
usermod -aG sudo ubuntu
su - ubuntu
```

### Phase 2: Install Dependencies

#### 2.1 Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

#### 2.2 Install Nginx

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

#### 2.3 Install Certbot (SSL)

```bash
sudo apt install -y certbot python3-certbot-nginx
```

#### 2.4 Install Rust (for building from source)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version
```

### Phase 3: Clone and Build Application

#### 3.1 Clone Repository

```bash
cd ~
git clone https://github.com/yourusername/mls.git
cd mls
```

#### 3.2 Build Rust Application

```bash
cd server

# Build in release mode
cargo build --release

# This creates: /home/ubuntu/mls/target/release/catbird-server
```

**Build time**: ~5-10 minutes on a 2-core server

#### 3.3 Prepare Docker Image

```bash
# Build Docker image with pre-built binary
cd /home/ubuntu/mls/server
docker build -f Dockerfile.prebuilt -t server-mls-server .
```

### Phase 4: Configure Environment

#### 4.1 Create Environment File

```bash
cd /home/ubuntu/mls/server

# Create .env file
cat > .env << 'EOF'
# PostgreSQL Configuration
POSTGRES_PASSWORD=CHANGE_THIS_SECURE_PASSWORD_123

# Redis Configuration  
REDIS_PASSWORD=CHANGE_THIS_SECURE_PASSWORD_456

# JWT Secret (minimum 32 characters)
JWT_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_STRING_MIN_32_CHARS

# Logging level
RUST_LOG=info

# Service DID
SERVICE_DID=did:web:mls.yourdomain.com
EOF

# Secure the file
chmod 600 .env
```

#### 4.2 Update Application Config

```bash
# Update server/.env
cat > server/.env << 'EOF'
DATABASE_URL=postgresql://catbird:SAME_PASSWORD_FROM_ABOVE@localhost:5433/catbird
REDIS_URL=redis://:SAME_REDIS_PASSWORD@localhost:6380
SERVER_PORT=3000
JWT_SECRET=SAME_JWT_SECRET_AS_ABOVE
RUST_LOG=info
SERVICE_DID=did:web:mls.yourdomain.com
EOF
```

### Phase 5: Configure DNS & SSL

#### 5.1 Configure DNS

At your DNS provider (Cloudflare, Route53, etc.):

```dns
Type:  A
Name:  mls
Value: YOUR_SERVER_IP
TTL:   300
```

**Wait for DNS propagation** (5-30 minutes):
```bash
# Test DNS resolution
nslookup mls.yourdomain.com
dig mls.yourdomain.com
```

#### 5.2 Configure Nginx

```bash
# Create nginx configuration
sudo tee /etc/nginx/sites-available/mls.yourdomain.com << 'EOF'
server {
    listen 80;
    server_name mls.yourdomain.com;

    access_log /var/log/nginx/mls.access.log;
    error_log /var/log/nginx/mls.error.log;

    # DID document endpoint
    location /.well-known/did.json {
        root /home/ubuntu/mls;
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
    }

    # XRPC MLS service endpoints
    location /xrpc/ {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass $http_upgrade;
        
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header X-Accel-Buffering no;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
    }

    # Health check endpoints
    location /health {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }

    location /metrics {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/mls.yourdomain.com /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 5.3 Install SSL Certificate

```bash
# Obtain Let's Encrypt certificate
sudo certbot --nginx -d mls.yourdomain.com

# Follow the prompts:
# - Enter your email
# - Agree to terms
# - Choose to redirect HTTP to HTTPS (recommended)

# Test auto-renewal
sudo certbot renew --dry-run
```

### Phase 6: Generate DID Document

#### 6.1 Create Cryptographic Keys

```bash
cd /home/ubuntu/mls

# Generate ED25519 key pair
openssl genpkey -algorithm ED25519 -out did_key.pem

# Extract public key in base64
openssl pkey -in did_key.pem -pubout -outform DER | tail -c 32 | base58 -e > did_pub.b64

# Secure private key
chmod 600 did_key.pem
```

#### 6.2 Create DID Document

```bash
mkdir -p /home/ubuntu/mls/.well-known

# Replace YOUR_PUBLIC_KEY with output from did_pub.b64
cat > /home/ubuntu/mls/.well-known/did.json << 'EOF'
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:web:mls.yourdomain.com",
  "verificationMethod": [
    {
      "id": "did:web:mls.yourdomain.com#atproto",
      "type": "Multikey",
      "controller": "did:web:mls.yourdomain.com",
      "publicKeyMultibase": "YOUR_PUBLIC_KEY_HERE"
    }
  ],
  "service": [
    {
      "id": "#atproto_mls",
      "type": "AtprotoMlsService",
      "serviceEndpoint": "https://mls.yourdomain.com"
    }
  ]
}
EOF
```

### Phase 7: Start Services

#### 7.1 Start Docker Stack

```bash
cd /home/ubuntu/mls/server

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f mls-server
```

#### 7.2 Wait for Services to Initialize

```bash
# Monitor startup (should show healthy after ~30 seconds)
watch docker-compose ps

# Check health
curl http://localhost:3000/health
```

### Phase 8: Verify Deployment

#### 8.1 Test Local Endpoints

```bash
# Health check
curl http://localhost:3000/health

# Readiness
curl http://localhost:3000/health/ready

# Metrics
curl http://localhost:3000/metrics
```

#### 8.2 Test External Endpoints

```bash
# DID document
curl https://mls.yourdomain.com/.well-known/did.json

# Health (HTTPS)
curl https://mls.yourdomain.com/health

# SSL certificate
curl -vI https://mls.yourdomain.com 2>&1 | grep -A 10 "SSL certificate"
```

#### 8.3 Test Database

```bash
# Connect to database
docker exec -it catbird-postgres psql -U catbird -d catbird

# Check tables
\dt

# Check migrations
SELECT * FROM _sqlx_migrations;

# Exit
\q
```

---

## Environment Configuration

### Production Environment Variables

**Docker Compose (.env in server/)**:
```env
# Database
POSTGRES_PASSWORD=strong_random_password_here

# Redis
REDIS_PASSWORD=another_strong_password

# JWT Secret
JWT_SECRET=minimum_32_character_random_string_here

# Logging
RUST_LOG=info

# Service Identity
SERVICE_DID=did:web:mls.yourdomain.com
```

**Application (.env in server/)**:
```env
DATABASE_URL=postgresql://catbird:PASSWORD@localhost:5433/catbird
REDIS_URL=redis://:PASSWORD@localhost:6380
SERVER_PORT=3000
JWT_SECRET=same_as_above
RUST_LOG=info
SERVICE_DID=did:web:mls.yourdomain.com
```

### Secure Secrets Management

```bash
# Generate secure random passwords
openssl rand -base64 32

# Generate JWT secret (minimum 32 chars)
openssl rand -hex 32

# Store in password manager or secrets vault
# Never commit .env files to git!
```

---

## Service Management

### Docker Commands

```bash
# Start services
cd /home/ubuntu/mls/server
docker-compose up -d

# Stop services
docker-compose down

# Restart single service
docker-compose restart mls-server

# View logs
docker-compose logs -f
docker-compose logs -f mls-server

# Check status
docker-compose ps

# Rebuild and restart
docker-compose up -d --build
```

### Database Management

```bash
# Backup database
docker exec catbird-postgres pg_dump -U catbird catbird > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore database
cat backup_file.sql | docker exec -i catbird-postgres psql -U catbird catbird

# Access database shell
docker exec -it catbird-postgres psql -U catbird -d catbird

# Check database size
docker exec catbird-postgres psql -U catbird -d catbird -c "SELECT pg_size_pretty(pg_database_size('catbird'));"
```

### Redis Management

```bash
# Access Redis CLI
docker exec -it catbird-redis redis-cli -a YOUR_REDIS_PASSWORD

# Check Redis info
docker exec catbird-redis redis-cli -a PASSWORD INFO

# Flush cache (careful!)
docker exec catbird-redis redis-cli -a PASSWORD FLUSHDB
```

### Log Management

```bash
# View live logs
docker-compose logs -f

# View last 100 lines
docker-compose logs --tail=100

# View logs for specific service
docker-compose logs -f mls-server

# Export logs
docker-compose logs --no-color > logs_$(date +%Y%m%d).txt
```

---

## Monitoring & Health Checks

### Health Endpoints

```bash
# Full health status
curl https://mls.yourdomain.com/health | jq

# Readiness probe
curl https://mls.yourdomain.com/health/ready

# Liveness probe
curl https://mls.yourdomain.com/health/live

# Metrics (Prometheus format)
curl https://mls.yourdomain.com/metrics
```

### Automated Monitoring Script

```bash
#!/bin/bash
# Save as: /home/ubuntu/mls/scripts/health-check.sh

URL="https://mls.yourdomain.com/health"
LOGFILE="/var/log/mls-health.log"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" $URL)

if [ $STATUS -eq 200 ]; then
    echo "$(date): MLS Server is healthy" >> $LOGFILE
else
    echo "$(date): MLS Server health check failed (HTTP $STATUS)" >> $LOGFILE
    # Send alert (email, Slack, etc.)
fi
```

```bash
# Add to crontab (check every 5 minutes)
chmod +x /home/ubuntu/mls/scripts/health-check.sh
crontab -e
# Add: */5 * * * * /home/ubuntu/mls/scripts/health-check.sh
```

### Container Health

```bash
# Check container health
docker-compose ps

# Inspect container
docker inspect catbird-mls-server | jq '.[0].State.Health'

# Resource usage
docker stats catbird-mls-server --no-stream
```

---

## Backup & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# Save as: /home/ubuntu/mls/scripts/backup.sh

BACKUP_DIR="/home/ubuntu/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

mkdir -p $BACKUP_DIR

# Backup database
echo "Backing up database..."
docker exec catbird-postgres pg_dump -U catbird catbird | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup environment files
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /home/ubuntu/mls/server/.env /home/ubuntu/mls/.env.example

# Remove old backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_DIR"
```

```bash
# Make executable
chmod +x /home/ubuntu/mls/scripts/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/ubuntu/mls/scripts/backup.sh
```

### Recovery Procedure

```bash
# Stop services
cd /home/ubuntu/mls/server
docker-compose down

# Restore database
gunzip < /home/ubuntu/backups/db_YYYYMMDD_HHMMSS.sql.gz | \
  docker exec -i catbird-postgres psql -U catbird catbird

# Start services
docker-compose up -d

# Verify
curl https://mls.yourdomain.com/health
```

---

## Troubleshooting

### Common Issues

#### Server Won't Start

```bash
# Check Docker logs
docker-compose logs mls-server

# Check if port is in use
sudo lsof -i :3000

# Verify environment variables
docker-compose config

# Check disk space
df -h
```

#### Database Connection Errors

```bash
# Check PostgreSQL status
docker-compose ps postgres

# Test connection
docker exec catbird-postgres pg_isready -U catbird

# Check database logs
docker-compose logs postgres

# Verify credentials
cat server/.env | grep DATABASE_URL
```

#### SSL Certificate Issues

```bash
# Check certificate status
sudo certbot certificates

# Renew certificate
sudo certbot renew --force-renewal

# Check nginx config
sudo nginx -t

# View nginx error log
sudo tail -f /var/log/nginx/mls.error.log
```

#### High Memory Usage

```bash
# Check container stats
docker stats

# Restart services
docker-compose restart

# Check for memory leaks
docker exec catbird-mls-server ps aux

# Increase container memory limit (docker-compose.yml)
# Add: mem_limit: 2g
```

### Debug Mode

```bash
# Enable debug logging
cd /home/ubuntu/mls/server
echo "RUST_LOG=debug" >> .env

# Restart service
docker-compose restart mls-server

# View detailed logs
docker-compose logs -f mls-server

# Revert to info level
sed -i 's/RUST_LOG=debug/RUST_LOG=info/' .env
docker-compose restart mls-server
```

---

## Production Checklist

### Pre-Deployment

- [ ] Server provisioned with minimum specs
- [ ] DNS configured and propagated
- [ ] SSL certificate installed
- [ ] Firewall configured (ports 80, 443, 22)
- [ ] Docker and Docker Compose installed
- [ ] Application built successfully
- [ ] Strong passwords generated for DB and Redis
- [ ] JWT secret generated (32+ characters)
- [ ] Environment files created and secured
- [ ] DID document created with proper keys

### Post-Deployment

- [ ] All Docker containers running and healthy
- [ ] Health endpoints responding (200 OK)
- [ ] DID document accessible via HTTPS
- [ ] SSL certificate valid and auto-renewal configured
- [ ] Database migrations completed
- [ ] Backup script configured and tested
- [ ] Monitoring/health checks configured
- [ ] Log rotation configured
- [ ] Documentation updated with actual domain
- [ ] Access credentials securely stored

### Security Hardening

- [ ] SSH key-only authentication enabled
- [ ] Fail2ban configured
- [ ] UFW firewall active
- [ ] Non-root user created
- [ ] File permissions secured (chmod 600 for .env files)
- [ ] Database not exposed to public internet
- [ ] Redis not exposed to public internet
- [ ] Strong passwords used (20+ characters)
- [ ] Regular security updates scheduled
- [ ] SSL/TLS only (HSTS enabled)

---

## Quick Reference Commands

```bash
# Start everything
cd /home/ubuntu/mls/server && docker-compose up -d

# Stop everything
docker-compose down

# Restart server
docker-compose restart mls-server

# View logs
docker-compose logs -f mls-server

# Health check
curl https://mls.yourdomain.com/health

# Database backup
docker exec catbird-postgres pg_dump -U catbird catbird > backup.sql

# Update application (after git pull)
cd /home/ubuntu/mls/server
cargo build --release
docker-compose build --no-cache mls-server
docker-compose up -d

# Check SSL expiration
sudo certbot certificates

# Renew SSL
sudo certbot renew

# View disk usage
df -h
du -sh /var/lib/docker
```

---

## Support & Resources

### Documentation

- [AT Protocol Documentation](https://atproto.com/)
- [OpenMLS Documentation](https://openmls.tech/)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Docker Documentation](https://docs.docker.com/)

### Local Documentation

- `DEPLOYMENT_SUMMARY.txt` - Quick deployment overview
- `ATPROTO_SERVICE_SETUP.md` - AT Protocol integration guide
- `PRODUCTION_DEPLOYMENT.md` - Detailed deployment guide
- `TESTING_GUIDE.md` - API testing examples
- `SECURITY_AUDIT_REPORT.md` - Security considerations

### Monitoring Dashboard

Access Prometheus metrics at:
```
https://mls.yourdomain.com/metrics
```

Example queries for monitoring tools:
```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m])

# Average response time
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])
```

---

## Version History

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-02 | 1.0 | Initial production replication guide |

---

**Generated**: November 2, 2025  
**Environment**: Production (mls.catbird.blue)  
**Status**: ✅ Operational

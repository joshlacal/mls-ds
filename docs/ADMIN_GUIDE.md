# MLS Server Administrator Guide

**Version**: 1.0  
**Last Updated**: October 21, 2025  
**Audience**: Server Administrators, DevOps Engineers

---

## 📖 Table of Contents

1. [Overview](#overview)
2. [Server Deployment](#server-deployment)
3. [Database Setup](#database-setup)
4. [Configuration](#configuration)
5. [Monitoring & Logging](#monitoring--logging)
6. [Backup & Restore](#backup--restore)
7. [Scaling](#scaling)
8. [Security Hardening](#security-hardening)
9. [Maintenance](#maintenance)
10. [Troubleshooting](#troubleshooting)

---

## 🌐 Overview

### Architecture

```mermaid
graph TB
    subgraph "External"
        A[iOS Clients] --> B[Load Balancer]
    end
    
    subgraph "Application Tier"
        B --> C[MLS Server 1]
        B --> D[MLS Server 2]
        B --> E[MLS Server N]
    end
    
    subgraph "Data Tier"
        C --> F[PostgreSQL Primary]
        D --> F
        E --> F
        F --> G[PostgreSQL Replica]
        
        C --> H[Redis Cache]
        D --> H
        E --> H
        
        C --> I[S3/Object Storage]
        D --> I
        E --> I
    end
    
    subgraph "Monitoring"
        C --> J[Prometheus]
        D --> J
        E --> J
        J --> K[Grafana]
        J --> L[Alertmanager]
    end
```

### System Requirements

| Resource | Minimum | Recommended | High-Traffic |
|----------|---------|-------------|--------------|
| **CPU** | 2 cores | 4 cores | 8+ cores |
| **RAM** | 4 GB | 8 GB | 16+ GB |
| **Disk** | 50 GB SSD | 100 GB SSD | 500+ GB SSD |
| **Network** | 100 Mbps | 1 Gbps | 10 Gbps |
| **Database** | Shared | Dedicated | Clustered |

### Software Dependencies

- **OS**: Ubuntu 22.04 LTS or RHEL 9
- **Rust**: 1.75+
- **PostgreSQL**: 15+
- **Redis**: 7.0+ (optional, for caching)
- **Nginx**: 1.24+ (reverse proxy)
- **Certbot**: For TLS certificates

---

## 🚀 Server Deployment

### Option 1: Docker Deployment (Recommended)

#### 1. Build Docker Image

```dockerfile
# Dockerfile
FROM rust:1.75-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY server/ ./server/
COPY mls-ffi/ ./mls-ffi/

RUN cargo build --release --bin catbird-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/catbird-server /usr/local/bin/

EXPOSE 3000
CMD ["catbird-server"]
```

Build and run:
```bash
docker build -t catbird-mls-server:latest .
docker run -d \
  --name mls-server \
  -p 3000:3000 \
  -e DATABASE_URL=postgres://user:pass@db:5432/mls \
  -e RUST_LOG=info \
  catbird-mls-server:latest
```

#### 2. Docker Compose (Full Stack)

```yaml
# docker-compose.yml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: mls
      POSTGRES_USER: mlsuser
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mlsuser"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

  server:
    image: catbird-mls-server:latest
    depends_on:
      - db
      - redis
    environment:
      DATABASE_URL: postgres://mlsuser:${DB_PASSWORD}@db:5432/mls
      REDIS_URL: redis://redis:6379
      RUST_LOG: info
      JWT_SECRET: ${JWT_SECRET}
    ports:
      - "3000:3000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    depends_on:
      - server
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    restart: unless-stopped

volumes:
  pgdata:
```

Deploy:
```bash
# Set environment variables
export DB_PASSWORD=$(openssl rand -base64 32)
export JWT_SECRET=$(openssl rand -base64 64)

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f server
```

---

### Option 2: Bare Metal / VM Deployment

#### 1. Install Dependencies

```bash
# Ubuntu 22.04
sudo apt update
sudo apt install -y curl build-essential libssl-dev pkg-config postgresql

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### 2. Build Server

```bash
cd /opt/catbird-mls
git clone <repo-url> .
cd server
cargo build --release

# Copy binary
sudo cp target/release/catbird-server /usr/local/bin/
sudo chmod +x /usr/local/bin/catbird-server
```

#### 3. Create Systemd Service

```ini
# /etc/systemd/system/catbird-mls.service
[Unit]
Description=Catbird MLS Server
After=network.target postgresql.service

[Service]
Type=simple
User=mls
Group=mls
WorkingDirectory=/opt/catbird-mls
Environment="DATABASE_URL=postgres://mlsuser:PASSWORD@localhost/mls"
Environment="RUST_LOG=info"
Environment="JWT_SECRET=your-secret-here"
ExecStart=/usr/local/bin/catbird-server
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=catbird-mls

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable catbird-mls
sudo systemctl start catbird-mls
sudo systemctl status catbird-mls
```

---

## 🗄️ Database Setup

### PostgreSQL Installation

```bash
# Install PostgreSQL 15
sudo apt install -y postgresql-15 postgresql-contrib-15

# Start service
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### Database Initialization

```bash
# Switch to postgres user
sudo -u postgres psql

-- Create database and user
CREATE DATABASE mls;
CREATE USER mlsuser WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE mls TO mlsuser;

-- Enable extensions
\c mls
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

\q
```

### Run Migrations

```bash
cd /opt/catbird-mls/server

# Set database URL
export DATABASE_URL=postgres://mlsuser:password@localhost/mls

# Run migrations
sqlx migrate run

# Verify
sqlx migrate info
```

### Schema Overview

```sql
-- Conversations (groups)
CREATE TABLE conversations (
    id UUID PRIMARY KEY,
    epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Members
CREATE TABLE conversation_members (
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    did TEXT NOT NULL,
    joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (conversation_id, did)
);

-- Messages
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    sender_did TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    epoch INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- KeyPackages
CREATE TABLE key_packages (
    id UUID PRIMARY KEY,
    did TEXT NOT NULL,
    key_package BYTEA NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_messages_conversation ON messages(conversation_id, created_at DESC);
CREATE INDEX idx_key_packages_did ON key_packages(did, expires_at);
CREATE INDEX idx_conversation_members_did ON conversation_members(did);
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:pass@host:5432/dbname
JWT_SECRET=<64-byte-base64-secret>

# Optional
RUST_LOG=info                    # Logging level: debug, info, warn, error
REDIS_URL=redis://localhost:6379 # For caching (optional)
SERVER_PORT=3000                  # Default: 3000
SERVER_HOST=0.0.0.0              # Bind address
TLS_CERT_PATH=/path/to/cert.pem  # For HTTPS
TLS_KEY_PATH=/path/to/key.pem    # For HTTPS
MAX_CONNECTIONS=100               # Database pool size
REQUEST_TIMEOUT=30                # Seconds
MAX_BODY_SIZE=10485760           # 10MB in bytes
BLOB_STORAGE_PATH=/var/lib/mls/blobs  # Local storage
```

### Configuration File

```toml
# config.toml
[server]
host = "0.0.0.0"
port = 3000
workers = 4

[database]
url = "postgres://localhost/mls"
max_connections = 100
min_connections = 10
connection_timeout = 30

[security]
jwt_secret = "${JWT_SECRET}"
jwt_expiry = 86400  # 24 hours
max_keypackage_age = 172800  # 48 hours

[storage]
type = "local"  # or "s3"
path = "/var/lib/mls/blobs"
max_blob_size = 10485760  # 10MB

[logging]
level = "info"
format = "json"
```

Load with:
```rust
use config::Config;

let settings = Config::builder()
    .add_source(config::File::with_name("config"))
    .add_source(config::Environment::with_prefix("MLS"))
    .build()?;
```

---

## 📊 Monitoring & Logging

### Prometheus Metrics

Add to `main.rs`:
```rust
use prometheus::{Encoder, TextEncoder, Registry, Counter, Histogram};
use axum::routing::get;

#[derive(Clone)]
struct Metrics {
    http_requests_total: Counter,
    http_request_duration: Histogram,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        let http_requests_total = Counter::new("http_requests_total", "Total HTTP requests")
            .unwrap();
        let http_request_duration = Histogram::new("http_request_duration_seconds", "Request duration")
            .unwrap();
        
        registry.register(Box::new(http_requests_total.clone())).unwrap();
        registry.register(Box::new(http_request_duration.clone())).unwrap();
        
        Self { http_requests_total, http_request_duration }
    }
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// Add route
.route("/metrics", get(metrics_handler))
```

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'catbird-mls'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Catbird MLS Server",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Request Duration (p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Active Connections",
        "targets": [
          {
            "expr": "sum(database_connections_active)"
          }
        ]
      }
    ]
  }
}
```

### Structured Logging

```rust
use tracing::{info, error, instrument};

#[instrument(skip(pool), fields(user_did = %claims.sub))]
async fn create_convo(
    State(pool): State<PgPool>,
    claims: Claims,
    Json(req): Json<CreateConvoRequest>,
) -> Result<Json<CreateConvoResponse>, AppError> {
    info!("Creating conversation for {} members", req.members.len());
    
    // ... handler logic
    
    info!(conversation_id = %req.conversation_id, "Conversation created");
    Ok(response)
}
```

### Log Aggregation (ELK Stack)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*.log

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "mls-logs-%{+yyyy.MM.dd}"

setup.kibana:
  host: "kibana:5601"
```

### Alerting Rules

```yaml
# alertmanager.yml
groups:
  - name: catbird-mls
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status="500"}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"
      
      - alert: DatabaseConnectionPoolExhausted
        expr: database_connections_active >= database_connections_max
        for: 2m
        annotations:
          summary: "Database connection pool exhausted"
      
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        annotations:
          summary: "API latency p99 > 2s"
```

---

## 💾 Backup & Restore

### Database Backups

#### Automated Backups

```bash
#!/bin/bash
# /opt/scripts/backup-mls-db.sh

BACKUP_DIR="/var/backups/mls"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mls_backup_$DATE.sql.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Dump database
pg_dump -h localhost -U mlsuser -d mls | gzip > $BACKUP_FILE

# Keep only last 30 days
find $BACKUP_DIR -name "mls_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

Schedule with cron:
```bash
# Run daily at 2 AM
0 2 * * * /opt/scripts/backup-mls-db.sh
```

#### Restore from Backup

```bash
# Decompress and restore
gunzip -c /var/backups/mls/mls_backup_20251021_020000.sql.gz | \
  psql -h localhost -U mlsuser -d mls
```

### Continuous Archiving (PITR)

Enable in `postgresql.conf`:
```ini
wal_level = replica
archive_mode = on
archive_command = 'test ! -f /var/lib/postgresql/archive/%f && cp %p /var/lib/postgresql/archive/%f'
```

### Blob Storage Backups

```bash
# Sync to S3
aws s3 sync /var/lib/mls/blobs s3://mls-backup-bucket/blobs/ \
  --exclude "*.tmp" \
  --storage-class STANDARD_IA

# Or use rsync to remote server
rsync -avz /var/lib/mls/blobs/ backup-server:/backups/mls/blobs/
```

---

## 📈 Scaling

### Vertical Scaling

Increase resources on existing server:

```bash
# Increase PostgreSQL connections
# In postgresql.conf:
max_connections = 200
shared_buffers = 4GB
effective_cache_size = 12GB

# Increase server workers
# In systemd service:
Environment="TOKIO_WORKER_THREADS=8"
```

### Horizontal Scaling

```mermaid
graph LR
    A[Client] --> B[Load Balancer]
    B --> C[Server 1]
    B --> D[Server 2]
    B --> E[Server 3]
    C --> F[(Primary DB)]
    D --> F
    E --> F
    F --> G[(Replica DB)]
```

#### Load Balancer (Nginx)

```nginx
# /etc/nginx/conf.d/mls-upstream.conf
upstream mls_backend {
    least_conn;
    server 10.0.1.10:3000 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:3000 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:3000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name mls.catbird.chat;
    
    ssl_certificate /etc/letsencrypt/live/mls.catbird.chat/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mls.catbird.chat/privkey.pem;
    
    location / {
        proxy_pass http://mls_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Database Scaling

#### Read Replicas

```sql
-- On primary server
CREATE PUBLICATION mls_publication FOR ALL TABLES;

-- On replica server
CREATE SUBSCRIPTION mls_subscription
    CONNECTION 'host=primary-db port=5432 dbname=mls user=replicator password=xxx'
    PUBLICATION mls_publication;
```

Configure read-only queries to use replica:
```rust
let read_pool = PgPoolOptions::new()
    .max_connections(50)
    .connect("postgres://mlsuser@replica-db/mls").await?;

let write_pool = PgPoolOptions::new()
    .max_connections(100)
    .connect("postgres://mlsuser@primary-db/mls").await?;
```

#### Connection Pooling (PgBouncer)

```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
mls = host=localhost port=5432 dbname=mls

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
```

### Caching Layer (Redis)

```rust
use redis::AsyncCommands;

async fn get_key_packages_cached(
    redis: &mut redis::aio::Connection,
    pool: &PgPool,
    did: &str,
) -> Result<Vec<KeyPackage>> {
    let cache_key = format!("keypackages:{}", did);
    
    // Try cache first
    if let Ok(cached) = redis.get::<_, String>(&cache_key).await {
        return Ok(serde_json::from_str(&cached)?);
    }
    
    // Fetch from database
    let packages = fetch_key_packages_from_db(pool, did).await?;
    
    // Cache for 5 minutes
    let _: () = redis.set_ex(&cache_key, serde_json::to_string(&packages)?, 300).await?;
    
    Ok(packages)
}
```

---

## 🔒 Security Hardening

### TLS Configuration

```bash
# Generate Let's Encrypt certificate
sudo certbot certonly --nginx -d mls.catbird.chat

# Auto-renewal
sudo systemctl enable certbot.timer
```

Nginx TLS best practices:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000" always;
```

### Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Limit SSH brute force
sudo ufw limit 22/tcp
```

### Rate Limiting

```rust
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

let governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(50)
        .finish()
        .unwrap(),
);

let app = Router::new()
    .route("/xrpc/blue.catbird.mls.sendMessage", post(handlers::send_message))
    .layer(GovernorLayer { config: governor_conf })
    // ... other routes
```

### Database Security

```sql
-- Revoke public permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE mls TO mlsuser;
GRANT USAGE ON SCHEMA public TO mlsuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mlsuser;

-- Enable row-level security
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
```

### Secrets Management

Use environment variables or secret management:

```bash
# HashiCorp Vault
vault kv put secret/mls/prod \
  database_password="xxx" \
  jwt_secret="yyy"

# In systemd service
ExecStartPre=/usr/local/bin/load-secrets.sh
```

```bash
#!/bin/bash
# load-secrets.sh
export DATABASE_PASSWORD=$(vault kv get -field=database_password secret/mls/prod)
export JWT_SECRET=$(vault kv get -field=jwt_secret secret/mls/prod)
```

---

## 🔧 Maintenance

### Routine Tasks

#### Daily
- ✅ Check server health endpoints
- ✅ Review error logs
- ✅ Monitor disk space

#### Weekly
- ✅ Verify backups
- ✅ Review security alerts
- ✅ Check for dependency updates

#### Monthly
- ✅ Database vacuum and analyze
- ✅ Review performance metrics
- ✅ Update SSL certificates (if manual)
- ✅ Security patches

### Database Maintenance

```sql
-- Vacuum and analyze
VACUUM ANALYZE;

-- Check table bloat
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Reindex if needed
REINDEX DATABASE mls;
```

### Log Rotation

```bash
# /etc/logrotate.d/catbird-mls
/var/log/catbird-mls/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 mls mls
    sharedscripts
    postrotate
        systemctl reload catbird-mls
    endscript
}
```

### Updates

```bash
# Update server
cd /opt/catbird-mls
git pull
cargo build --release

# Stop service
sudo systemctl stop catbird-mls

# Replace binary
sudo cp target/release/catbird-server /usr/local/bin/

# Run migrations
sqlx migrate run

# Start service
sudo systemctl start catbird-mls

# Verify
curl http://localhost:3000/health
```

---

## 🐛 Troubleshooting

### Server Won't Start

**Check logs:**
```bash
sudo journalctl -u catbird-mls -n 50 --no-pager
```

**Common issues:**
- Database connection failed → Verify `DATABASE_URL`
- Port already in use → Check `netstat -tlnp | grep 3000`
- Missing JWT secret → Set `JWT_SECRET` env var

---

### High Memory Usage

**Check memory:**
```bash
free -h
ps aux | grep catbird-server | awk '{print $6}'
```

**Solutions:**
- Reduce `MAX_CONNECTIONS` in database pool
- Enable connection pooling (PgBouncer)
- Add swap space if needed

---

### Slow Queries

**Enable query logging in PostgreSQL:**
```sql
-- In postgresql.conf
log_min_duration_statement = 1000  # Log queries > 1s

-- View slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

**Add indexes:**
```sql
CREATE INDEX idx_messages_created_at ON messages(created_at DESC);
ANALYZE messages;
```

---

### Disk Full

**Check disk usage:**
```bash
df -h
du -sh /var/lib/postgresql/* | sort -h
```

**Solutions:**
- Clean old backups: `find /var/backups/mls -mtime +30 -delete`
- Vacuum database: `VACUUM FULL;`
- Archive old messages to cold storage

---

### Certificate Expiry

**Check expiry:**
```bash
openssl x509 -in /etc/letsencrypt/live/mls.catbird.chat/cert.pem -noout -dates
```

**Renew:**
```bash
sudo certbot renew
sudo systemctl reload nginx
```

---

## 📚 Additional Resources

- **[MLS Protocol Spec](https://www.rfc-editor.org/rfc/rfc9420.html)**
- **[PostgreSQL Documentation](https://www.postgresql.org/docs/15/)**
- **[Axum Framework Guide](https://docs.rs/axum/latest/axum/)**
- **[Prometheus Best Practices](https://prometheus.io/docs/practices/)**

---

**Need help?** Contact the Catbird team or open an issue on GitHub.

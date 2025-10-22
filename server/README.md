# Catbird MLS Server

Production-ready MLS group chat server with ATProto identity integration, built with Rust, Axum, and OpenMLS.

## 🚀 Quick Start

### Local Development (Docker Compose)

```bash
# Start all services (Postgres, Redis, MLS Server)
make run

# Check health
make health-check

# View logs
make logs
```

### Production Deployment

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete deployment instructions.

**Quick Deploy:**
```bash
# Docker Compose
make deploy

# Kubernetes
make deploy-k8s
```

## 📁 Project Structure

```
server/
├── src/                      # Application source code
│   ├── main.rs              # Entry point
│   ├── health.rs            # Health check endpoints
│   ├── handlers.rs          # XRPC route handlers
│   ├── models.rs            # Data models
│   ├── storage.rs           # Database operations
│   ├── auth.rs              # Authentication/JWT
│   └── crypto.rs            # Cryptographic operations
│
├── migrations/              # Database migrations
├── tests/                   # Integration tests
│
├── scripts/                 # Deployment scripts
│   ├── deploy.sh           # Docker Compose deployment
│   ├── k8s-deploy.sh       # Kubernetes deployment
│   ├── run-migrations.sh   # Database migrations
│   ├── backup-db.sh        # Database backup
│   └── restore-db.sh       # Database restore
│
├── k8s/                     # Kubernetes manifests
│   ├── deployment.yaml     # Application deployment
│   ├── service.yaml        # Services
│   ├── ingress.yaml        # Ingress with TLS
│   ├── postgres.yaml       # PostgreSQL StatefulSet
│   ├── redis.yaml          # Redis StatefulSet
│   ├── hpa.yaml            # Auto-scaling
│   └── ...                 # More manifests
│
├── Dockerfile              # Multi-stage production build
├── docker-compose.yml      # Production configuration
├── docker-compose.dev.yml  # Development overrides
├── Makefile                # Convenience commands
│
└── Documentation
    ├── DEPLOYMENT.md           # Complete deployment guide
    ├── QUICK_REFERENCE.md      # Command reference
    ├── SETUP_SUMMARY.md        # Setup overview
    └── DATABASE_SCHEMA.md      # Database schema
```

## 🔧 Features

### Core Functionality
- **MLS Protocol**: End-to-end encrypted group messaging
- **ATProto Identity**: Decentralized identity integration
- **XRPC API**: RESTful endpoints for all operations
- **Key Package Management**: Automatic key package handling
- **Blob Storage**: Encrypted file attachments

### Production Features
- **Multi-stage Docker builds**: Optimized image size
- **Health checks**: Liveness and readiness probes
- **Auto-scaling**: Horizontal Pod Autoscaler (3-10 replicas)
- **Automated backups**: Daily database backups
- **TLS/SSL**: Automatic certificate provisioning
- **High availability**: Multiple replicas with load balancing
- **Zero-downtime deploys**: Rolling updates

## 🏥 Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Detailed health status with database checks |
| `/health/live` | Liveness probe (Kubernetes) |
| `/health/ready` | Readiness probe (Kubernetes) |

## 🔌 API Endpoints

All XRPC endpoints are under the `/xrpc/blue.catbird.mls.*` namespace:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `createConvo` | POST | Create a new conversation |
| `addMembers` | POST | Add members to a conversation |
| `sendMessage` | POST | Send a message |
| `leaveConvo` | POST | Leave a conversation |
| `getMessages` | GET | Retrieve messages |
| `publishKeyPackage` | POST | Publish a key package |
| `getKeyPackages` | GET | Retrieve key packages |
| `uploadBlob` | POST | Upload encrypted blob |

## 🗄️ Database

**PostgreSQL 16** with the following tables:
- `conversations` - MLS group metadata
- `members` - Conversation membership
- `messages` - Encrypted messages
- `key_packages` - Pre-keys for adding members
- `blobs` - Encrypted file storage

**Redis 7** for:
- Session management
- Caching
- Rate limiting

## 🛠️ Development

### Prerequisites
- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL client tools (optional)

### Setup

1. **Clone and install dependencies:**
```bash
cargo build
```

2. **Start database services:**
```bash
docker-compose up -d postgres redis
```

3. **Run migrations:**
```bash
make migrate
```

4. **Run the server:**
```bash
cargo run
```

### Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_test
```

### Development with Hot Reload

```bash
# Install cargo-watch
cargo install cargo-watch

# Run with hot reload
make run-dev
```

## 🚢 Deployment

### Docker Compose (Simple Deployment)

**Production:**
```bash
# Copy and configure environment
cp .env.production.example .env.production
# Edit .env.production with secure values

# Deploy
./scripts/deploy.sh production
```

**Development:**
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Kubernetes (Production)

**Prerequisites:**
- Kubernetes 1.28+
- kubectl configured
- cert-manager (for TLS)
- nginx-ingress-controller

**Deploy:**
```bash
# Create secrets
kubectl create secret generic catbird-mls-secrets \
  --from-literal=POSTGRES_PASSWORD='secure_password' \
  --from-literal=REDIS_PASSWORD='secure_redis_password' \
  --from-literal=JWT_SECRET='secure_jwt_secret' \
  -n catbird

# Deploy
./scripts/k8s-deploy.sh production
```

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete instructions.

## 📊 Makefile Commands

```bash
make help          # Show all commands
make build         # Build Docker image
make run           # Run with docker-compose
make run-dev       # Run in development mode
make stop          # Stop all containers
make test          # Run tests
make clean         # Clean up containers and volumes
make deploy        # Deploy with docker-compose
make deploy-k8s    # Deploy to Kubernetes
make migrate       # Run database migrations
make backup        # Backup database
make health-check  # Check server health
make logs          # View logs
```

## 🔒 Security

### Production Checklist
- [ ] Change all default passwords
- [ ] Use strong, randomly generated secrets
- [ ] Enable TLS/SSL
- [ ] Configure firewall rules
- [ ] Enable pod security policies
- [ ] Use network policies
- [ ] Regular security updates
- [ ] Rotate secrets regularly

### Security Features
- Non-root containers
- Read-only root filesystem ready
- Dropped Linux capabilities
- Secret management
- TLS/SSL support
- Network isolation

## 🔄 Operations

### Backup

**Automated (Kubernetes):**
- Daily backups at 2 AM
- 30-day retention
- Stored in PersistentVolume

**Manual:**
```bash
make backup
```

### Restore

```bash
make restore BACKUP=/path/to/backup.sql.gz
```

### Monitoring

```bash
# Docker Compose
docker-compose logs -f
docker stats

# Kubernetes
kubectl get pods -n catbird
kubectl top pods -n catbird
kubectl logs -f deployment/catbird-mls-server -n catbird
```

### Scaling

```bash
# Kubernetes
make k8s-scale REPLICAS=5

# Auto-scaling is enabled (3-10 replicas)
kubectl get hpa -n catbird
```

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `RUST_LOG` | Logging level | `info` |
| `SERVER_PORT` | Server port | `3000` |

## 🧪 Testing

### Unit Tests
```bash
cargo test --lib
```

### Integration Tests
```bash
cargo test --test integration_test
```

### Health Check
```bash
curl http://localhost:3000/health | jq
```

### Load Testing
```bash
# Install hey
go install github.com/rakyll/hey@latest

# Run load test
hey -n 10000 -c 100 http://localhost:3000/health
```

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide with Docker and Kubernetes
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick command reference
- **[SETUP_SUMMARY.md](SETUP_SUMMARY.md)** - Overview of deployment setup
- **[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)** - Database schema documentation
- **[k8s/README.md](k8s/README.md)** - Kubernetes-specific documentation

## 🐛 Troubleshooting

### Server won't start

```bash
# Check logs
make logs

# Check health
make health-check
```

### Database connection issues

```bash
# Test database
docker-compose exec postgres psql -U catbird -c "SELECT 1"
```

### Kubernetes pod issues

```bash
# Describe pod
kubectl describe pod <pod-name> -n catbird

# Check logs
kubectl logs <pod-name> -n catbird

# Check events
kubectl get events -n catbird --sort-by='.lastTimestamp'
```

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for more troubleshooting tips.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Submit a pull request

## 📄 License

See [LICENSE](../LICENSE) for details.

## 🔗 Related Projects

- [OpenMLS](https://github.com/openmls/openmls) - MLS protocol implementation
- [AT Protocol](https://atproto.com/) - Decentralized identity
- [Axum](https://github.com/tokio-rs/axum) - Web framework

## 📞 Support

For issues and questions:
- See troubleshooting sections in documentation
- Check existing issues
- Create a new issue with details

---

**Built with ❤️ using Rust, OpenMLS, and ATProto**
### Auth, lxm/jti, and proxying

Environment variables relevant to auth and routing:

- `SERVICE_DID` — required audience for inter-service JWTs (aud must equal this).
- `ENFORCE_LXM` — when `true`, require the JWT `lxm` claim to match the called NSID.
- `ENFORCE_JTI` — when `true` (default), require a `jti` and reject replays for a short TTL.
- `JTI_TTL_SECONDS` — TTL in seconds for jti replay cache (default 120).
- `JWT_SECRET` — enables HS256 dev-mode tokens for local testing.
- `ENABLE_DIRECT_XRPC_PROXY` — when `true`, enable a development-only catch‑all `/xrpc/*` forwarder.
- `UPSTREAM_XRPC_BASE` — base URL for the optional proxy (default `http://127.0.0.1:3000`).

Notes:
- In production, rely on the PDS to proxy via the `atproto-proxy` header; keep the built‑in proxy disabled.
- Inter‑service JWTs (ES256/ES256K) are verified against the issuer’s DID document.

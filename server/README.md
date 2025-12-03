# Catbird MLS Server

Production-ready MLS group chat server with ATProto identity integration, built with Rust, Axum, and OpenMLS.

## 🚀 Quick Start

### Local Development

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run the server
cargo run
```

### Production Deployment

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete deployment instructions.

**Quick Deploy:**
```bash
# Deploy (preserves data)
make deploy

# Fresh deploy (wipes data)
make deploy-fresh

# Restart server
make restart
```

## 📁 Project Structure

```
server/
├── src/                      # Application source code
│   ├── main.rs              # Entry point
│   ├── health.rs            # Health check endpoints
│   ├── handlers/            # XRPC route handlers
│   ├── models.rs            # Data models
│   ├── storage.rs           # Database operations
│   ├── auth.rs              # Authentication/JWT
│   └── db.rs                # Database layer
│
├── migrations/              # Database migrations
├── tests/                   # Integration tests
│
├── scripts/                 # Utility scripts
│   ├── deploy.sh           # Deployment script
│   ├── run-migrations.sh   # Database migrations
│   ├── backup-db.sh        # Database backup
│   ├── restore-db.sh       # Database restore
│   ├── clear-db.sh         # Clear database
│   ├── health-check.sh     # Health checks
│   └── rollback.sh         # Rollback deployment
│
├── catbird-mls-server.service  # Systemd service file
├── Makefile                # Convenience commands
│
└── Documentation
    ├── DEPLOYMENT.md           # Complete deployment guide
    ├── QUICK_REFERENCE.md      # Command reference
    ├── CLAUDE.md               # Developer guide
    └── DATABASE_SCHEMA.md      # Database schema
```

## 🔧 Features

### Core Functionality
- **MLS Protocol**: End-to-end encrypted group messaging
- **ATProto Identity**: Decentralized identity integration
- **XRPC API**: RESTful endpoints for all operations
- **Key Package Management**: Automatic key package handling
- **Multi-device Support**: Per-device MLS identities

### Production Features
- **Systemd Integration**: Reliable service management
- **Health checks**: Liveness and readiness probes
- **Automated backups**: Database backup scripts
- **Rollback support**: Quick rollback to previous versions
- **Comprehensive logging**: Structured logging with journald

## 🏥 Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Detailed health status with database checks |
| `/health/live` | Liveness probe |
| `/health/ready` | Readiness probe |

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/xrpc/blue.catbird.mls.createConvo` | POST | Create new conversation |
| `/xrpc/blue.catbird.mls.addMembers` | POST | Add members to conversation |
| `/xrpc/blue.catbird.mls.sendMessage` | POST | Send encrypted message |
| `/xrpc/blue.catbird.mls.getMessages` | GET | Retrieve messages |
| `/xrpc/blue.catbird.mls.getConvos` | GET | List user's conversations |
| `/xrpc/blue.catbird.mls.leaveConvo` | POST | Leave conversation |
| `/xrpc/blue.catbird.mls.publishKeyPackage` | POST | Upload key packages |
| `/xrpc/blue.catbird.mls.getKeyPackages` | GET | Get key packages |
| `/xrpc/blue.catbird.mls.getWelcome` | GET | Get welcome messages |
| `/xrpc/blue.catbird.mls.updateCursor` | POST | Update read position |

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | Server port | `3000` |
| `RUST_LOG` | Log level | `info` |
| `SERVICE_DID` | Service DID for JWT validation | - |
| `SSE_BUFFER_SIZE` | SSE event buffer size | `5000` |
| `ENABLE_ACTOR_SYSTEM` | Enable actor system | `true` |

## 🛠 Make Commands

```bash
make help           # Show all commands
make build          # Build release binary
make run            # Run server (foreground)
make start          # Start systemd service
make stop           # Stop systemd service
make restart        # Restart systemd service
make test           # Run tests
make deploy         # Deploy (preserve data)
make deploy-fresh   # Deploy (wipe data)
make migrate        # Run migrations
make backup         # Backup database
make logs           # View logs
make status         # Check service status
```

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Command reference
- **[CLAUDE.md](CLAUDE.md)** - Developer guide
- **[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)** - Database schema documentation
- **[scripts/README.md](scripts/README.md)** - Scripts documentation

## 🔒 Security

- ATProto JWT authentication with DID verification
- End-to-end encryption using MLS protocol
- Replay attack prevention with JTI tracking
- Rate limiting per-IP and per-user
- Soft delete for data recovery

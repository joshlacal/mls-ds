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

### Federation Hostile Release Gate

```bash
# from repository root
./scripts/federation-hostile-test-gate.sh
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

## API Endpoints

### `blue.catbird.mlsChat.*` (client-facing)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `registerDevice` | POST | Register a device for MLS |
| `publishKeyPackages` | POST | Upload MLS key packages |
| `listDevices` | GET | List registered devices |
| `getPendingDevices` | GET | Get devices pending key packages |
| `getKeyPackageStatus` | GET | Key package inventory status |
| `getKeyPackages` | GET | Fetch key packages for inviting |
| `createConvo` | POST | Create new conversation |
| `getConvos` | GET | List user's conversations |
| `sendMessage` | POST | Send encrypted message |
| `sendEphemeral` | POST | Send ephemeral message (deprecated) |
| `getMessages` | GET | Retrieve messages |
| `updateCursor` | POST | Update read position |
| `getGroupState` | GET | Get MLS group state |
| `commitGroupChange` | POST | Commit MLS group change |
| `updateConvo` | POST | Update conversation metadata |
| `getConvoSettings` | GET | Get conversation settings |
| `leaveConvo` | POST | Leave conversation |
| `report` | POST | Report a member |
| `getReports` | GET | Get reports (admin) |
| `blocks` | POST | Block/unblock users |
| `optIn` | POST | Opt in to messaging |
| `getSubscriptionTicket` | GET | Get WebSocket auth ticket |
| `subscribeEvents` | WS | WebSocket event subscription |
| `requestFailover` | POST | Request sequencer failover |
| `getDeliveryStatus` | GET | Check message delivery status |
| `uploadBlob` | POST | Upload encrypted blob |
| `getBlob` | GET | Download encrypted blob |
| `getBlobUsage` | GET | Check blob storage usage |
| `deleteBlob` | POST | Delete a blob |
| `putGroupMetadataBlob` | POST | Upload group metadata blob |
| `getGroupMetadataBlob` | GET | Download group metadata blob |

### `blue.catbird.mlsDS.*` (DS-to-DS federation)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `deliverMessage` | POST | Deliver federated message |
| `deliverWelcome` | POST | Deliver federated welcome |
| `submitCommit` | POST | Submit federated commit |
| `fetchKeyPackage` | GET | Fetch key package from remote |
| `getConvoDigest` | GET | Get conversation digest |
| `getConvoEvents` | GET | Get conversation events |
| `transferSequencer` | POST | Transfer sequencer ownership |
| `healthCheck` | GET | Federation health check |
| `getFederationPeers` | GET | List federation peers |
| `upsertFederationPeer` | POST | Add/update federation peer |
| `deleteFederationPeer` | POST | Remove federation peer |
| `getFederationMode` | GET | Get federation mode |
| `setFederationMode` | POST | Set federation mode |
| `resolveDeliveryService` | GET | Resolve DS for a DID |

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Listener IP literal; use `127.0.0.1` for proxy-only staging | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `RUST_LOG` | Log level | `info` |
| `SERVICE_DID` | Service DID for JWT validation | - |
| `SSE_BUFFER_SIZE` | SSE event buffer size | `5000` |
| `ENFORCE_LXM` | Require JWT `lxm` claim matches endpoint | `true` |
| `ENFORCE_JTI` | Require `jti` and reject replays | `true` |
| `JTI_TTL_SECONDS` | Replay cache TTL | `120` |
| `ALLOW_UNSAFE_AUTH` | Allow disabled LXM/JTI (dev only) | `false` |
| `ENABLE_METRICS` | Expose `/metrics` endpoint | `false` |
| `METRICS_TOKEN` | Bearer token for metrics endpoint | - |
| `FEDERATION_RISK_*` | Risk tier ratios and adaptive limit multipliers | See `.env.example` |
| `FEDERATION_AUTO_QUARANTINE_MIN_RISK_TIER` | Auto-quarantine risk floor (`low`/`medium`/`high`/`critical`) | `critical` |
| `FEDERATION_ALERTS_ENABLED` | Emit structured federation alert-hook logs | `true` |
| `FEDERATION_SEQUENCER_FAILOVER_MIN_STALE_SECS` | Minimum observed sequencer lease age required before failover takeover | `30` |
| `FEDERATION_SEQUENCER_TRANSFER_MAX_TERM_JUMP` | Maximum allowed term jump when accepting sequencer transfer | `8` |

### Sequencer failover invariants

- Sequencer ownership is term-scoped: every handoff must increase `sequencer_term`.
- Commit and failover paths enforce CAS fencing on epoch + term to prevent split-brain writes.
- Client-requested failover only assumes leadership after the local sequencer lease observation is stale.

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
- **[migrations/README.md](migrations/README.md)** - Migration ordering, checksums, and staged rollouts
- **[Operation claim completeness activation](docs/operation_claim_completeness_activation.sql)** - Reviewed cutover body; not yet a migration
- **[scripts/README.md](scripts/README.md)** - Scripts documentation

## 🔒 Security

- ATProto JWT authentication with DID verification
- End-to-end encryption using MLS protocol
- Replay attack prevention with JTI tracking
- Rate limiting per-IP and per-user
- Soft delete for data recovery

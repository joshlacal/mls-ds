# Development Guide

## Getting Started

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- PostgreSQL 14+ or SQLite 3
- Xcode 15+ (for iOS client)
- iOS 17+ device or simulator

### Backend Development

```bash
cd server

# Build
cargo build

# Run tests
cargo test

# Run with SQLite (development)
DATABASE_URL=sqlite:catbird.db cargo run

# Run with PostgreSQL (production)
DATABASE_URL=postgres://user:pass@localhost/catbird cargo run

# Format code
cargo fmt

# Lint
cargo clippy
```

### Environment Variables

- `DATABASE_URL` - Database connection string (required)
- `RUST_LOG` - Logging level (default: `info`)
- `PORT` - Server port (default: `3000`)

### Database Setup

#### PostgreSQL

```bash
createdb catbird
DATABASE_URL=postgres://localhost/catbird cargo run
```

#### SQLite

```bash
DATABASE_URL=sqlite:catbird.db cargo run
```

### API Testing

```bash
# Health check
curl http://localhost:3000/health

# Create conversation (requires auth)
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer did:plc:test" \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Group"}'
```

## iOS Development

### Building MLS FFI

```bash
cd mls-ffi

# For iOS simulator (x86_64)
cargo build --release --target x86_64-apple-ios

# For iOS device (arm64)
cargo build --release --target aarch64-apple-ios

# Copy to iOS project
cp target/aarch64-apple-ios/release/libmls_ffi.a ../client-ios/
```

### Xcode Setup

1. Open `client-ios/CatbirdChat.xcodeproj`
2. Add `libmls_ffi.a` to "Frameworks, Libraries, and Embedded Content"
3. Set "Header Search Paths" to include `mls-ffi/include`
4. Build and run

## Project Structure

```
mls/
├── server/           # Rust backend
│   ├── src/
│   │   ├── main.rs          # Entry point
│   │   ├── handlers.rs      # XRPC handlers
│   │   ├── models.rs        # Data models
│   │   ├── storage.rs       # Database layer
│   │   ├── auth.rs          # Authentication
│   │   └── crypto.rs        # Crypto utilities
│   └── tests/
├── mls-ffi/          # Rust FFI library
│   └── src/
│       └── lib.rs           # FFI bindings
├── client-ios/       # iOS app
│   └── CatbirdChat/
│       ├── Models/
│       ├── Views/
│       ├── ViewModels/
│       └── Services/
├── lexicon/          # XRPC definitions
└── docs/             # Documentation
```

## Testing Strategy

### Unit Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

### Integration Tests

Located in `server/tests/integration_test.rs`. Test full request/response cycles with in-memory database.

### MLS Harness

TODO: Multi-client MLS simulation in `tests/mls_harness.rs`.

## Common Tasks

### Add a New API Endpoint

1. Define lexicon in `lexicon/blue.catbird.mls.{method}.json`
2. Add models in `server/src/models.rs`
3. Implement handler in `server/src/handlers.rs`
4. Register route in `server/src/main.rs`
5. Add client method in `client-ios/Services/CatbirdClient.swift`

### Database Migration

For SQLite, modify schema in `storage::init_db()`.
For Postgres, use `sqlx migrate`:

```bash
sqlx migrate add migration_name
# Edit migrations/*.sql
sqlx migrate run
```

## Debugging

### Server Logs

```bash
# JSON structured logs
RUST_LOG=debug cargo run

# Pretty logs
RUST_LOG=debug cargo run 2>&1 | jq
```

### iOS Debug

- Set breakpoints in Swift code
- Use `print()` for console output
- Check system Console app for device logs
- View network traffic with Charles Proxy

## Performance

### Benchmarking

```bash
# Server load test
ab -n 1000 -c 10 http://localhost:3000/health

# Or use wrk
wrk -t4 -c100 -d30s http://localhost:3000/health
```

### Profiling

```bash
# Flamegraph
cargo install flamegraph
sudo flamegraph -- target/release/catbird-server
```

## Security Checklist

- [ ] All passwords/secrets in environment variables (never in code)
- [ ] TLS enabled for production
- [ ] Rate limiting configured
- [ ] Input validation on all endpoints
- [ ] No plaintext in logs
- [ ] Keys stored in Keychain (iOS)
- [ ] Database credentials rotated regularly

## Deployment

### Docker (TODO)

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY server/ .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/catbird-server /usr/local/bin/
CMD ["catbird-server"]
```

### Production Checklist

- [ ] Use PostgreSQL (not SQLite)
- [ ] Enable HTTPS/TLS
- [ ] Set up monitoring (metrics, alerts)
- [ ] Configure backups
- [ ] Rate limiting per IP/user
- [ ] Log rotation
- [ ] Firewall rules
- [ ] Reverse proxy (nginx/caddy)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Make changes and test
4. Format code (`cargo fmt`, SwiftFormat)
5. Commit with clear message
6. Push and open PR

## Resources

- [MLS RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)
- [OpenMLS Docs](https://openmls.tech/)
- [AT Protocol Specs](https://atproto.com/)
- [Axum Guide](https://docs.rs/axum/)
- [SQLx Book](https://github.com/launchbadge/sqlx)

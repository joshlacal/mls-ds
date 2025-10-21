# Catbird MLS – Private Group Chat MVP

End-to-end encrypted group chat using MLS (RFC 9420) with AT Protocol identity.

## Architecture

- **Backend**: Rust service with Axum, PostgreSQL, OpenMLS
- **Client**: iOS app with Swift/Rust FFI bridge
- **Identity**: AT Protocol DIDs (did:plc, did:web)
- **Encryption**: MLS 1.0 (X25519 + Ed25519 + AES-GCM-128)

## Components

- `server/` - Rust backend service
- `client-ios/` - iOS application
- `mls-ffi/` - Rust FFI library for iOS
- `lexicon/` - XRPC lexicon definitions
- `docs/` - Architecture and design docs

## Quick Start

### Backend

```bash
cd server
cargo build
cargo test
DATABASE_URL=postgres://localhost/catbird cargo run
```

### iOS Client

```bash
cd client-ios
open CatbirdChat.xcodeproj
# Build and run in Xcode
```

## Security

- End-to-end encryption via MLS
- Forward secrecy and post-compromise security
- DID-based identity verification
- No plaintext on server

## License

MIT

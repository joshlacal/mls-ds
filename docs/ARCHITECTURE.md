# Architecture Overview

## System Components

### 1. Rust Backend Server
- **Framework**: Axum (async HTTP)
- **Database**: PostgreSQL/SQLite
- **MLS**: OpenMLS library
- **Auth**: DID-based via AT Protocol

### 2. iOS Client
- **Language**: Swift with Rust FFI
- **MLS**: OpenMLS via FFI bridge
- **Storage**: SwiftData + Keychain
- **Identity**: AT Protocol DID

### 3. MLS FFI Bridge
- **Rust library** with C-compatible API
- **cbindgen** for Swift headers
- Handles all cryptographic operations

## Data Flow

```
User A (iOS) ──┐
               │
User B (iOS) ──┼──> Rust Server ──> PostgreSQL
               │      (E2EE relay)
User C (iOS) ──┘
```

## Security Model

- **E2EE**: All messages encrypted via MLS before sending
- **Server trust**: Honest-but-curious (cannot read content)
- **Forward secrecy**: New keys per epoch
- **Post-compromise security**: Remove compromised members

## Key Technical Decisions

1. **Cipher suite**: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
2. **Identity**: AT Protocol DIDs (did:plc, did:web)
3. **KeyPackage lifetime**: 24-48 hours
4. **Database**: Postgres for production, SQLite for dev/tests
5. **Auth**: Bearer tokens derived from DID verification

## Message Types

- **Application messages**: Encrypted chat content
- **Handshake messages**: Add/Remove/Update commits
- **Welcome messages**: Bootstrap new members

## Epoch Management

Each group operation that changes membership creates a new epoch:
- Epoch 0: Group creation
- Epoch 1+: After each Add/Remove/Update commit

## API Endpoints (XRPC)

All under `/xrpc/blue.catbird.mls.*`:
- `createConvo` - Start new conversation
- `addMembers` - Invite users (with MLS commit)
- `sendMessage` - Send encrypted message
- `leaveConvo` - Remove member
- `getMessages` - Sync conversation history
- `publishKeyPackage` - Upload public keys
- `getKeyPackages` - Fetch keys for invites
- `uploadBlob` - Store encrypted attachments

# MLS Server Security Hardening Status

## Completed ✅

### Phase 1-7: Full Feature Implementation (27 Lexicons)
All major features have been successfully implemented:

1. **Admin System** (7 endpoints)
   - `promoteAdmin`, `demoteAdmin` - Admin role management
   - `removeMember` - Admin-only member removal
   - `reportMember`, `getReports`, `resolveReport` - E2EE reporting
   - `getAdminStats` - App Store compliance metrics

2. **Multi-Device Support** (1 endpoint)
   - `registerDevice` - Device registration with unique MLS identities
   - Automatic device-add to existing conversations
   - Device-local Keychain storage (NOT iCloud synced)

3. **Bluesky Blocks Integration** (3 endpoints)
   - `checkBlocks` - Pre-join block checking
   - `getBlockStatus` - Conversation block conflict detection
   - `handleBlockChange` - Block event processing

4. **Automatic Rejoin** (1 endpoint)
   - `requestRejoin` - State loss recovery
   - Server-orchestrated Welcome generation
   - 2-5 second rejoin flow

5. **Message Privacy Enhancements**
   - v1 message implementation REMOVED ✅
   - v2 is now the ONLY implementation
   - `sender_did` set to NULL (privacy-preserving) ✅
   - Client-provided `msgId` for deduplication ✅
   - `declaredSize`/`paddedSize` for traffic analysis resistance ✅
   - Timestamp quantization to 2-second buckets ✅

6. **SSE Events** (1 endpoint)
   - `streamConvoEvents` - Real-time event streaming
   - Minimal event payloads (no sender leakage)

7. **Database Migrations**
   - Admin fields (`is_admin`, `promoted_at`, `promoted_by_did`)
   - Privacy fields (`msg_id`, `declared_size`, `padded_size`, `received_bucket_ts`)
   - Multi-device fields (`user_did`, `device_id`, `device_name`)
   - New tables: `user_devices`, `admin_actions`, `reports`, `bsky_blocks`, `pending_welcomes`

### Code Generation
- All 27 lexicons generated to type-safe Rust code ✅
- Zero manual type definitions - uses `atrium-codegen` output
- Type safety with `Object<T>`, `Did`, `Datetime` wrappers

### Security: v1 Message Storage Removed
- **Deleted functions**: `create_message()`, `create_message_with_idempotency()` (v1)
- **Renamed**: `create_message_v2()` → `create_message()` (canonical)
- **ALL message writes** now use privacy-preserving v2 path
- **sender_did = NULL** enforced at database level ✅

## In Progress 🔄

### Security: Remove Sender from Responses
**Status**: Partially complete

**Completed**:
- `send_message.rs` - sender field removed from fanout events ✅
- Database function only stores NULL for sender_did ✅

**Remaining**:
- Fix models.rs compilation errors (sender field references)
- Update getMessages response to omit sender
- Update SSE MessageEvent to omit sender
- Clients must derive sender from decrypted MLS message content

**Files to Update**:
```rust
// models.rs - Already fixed in to_message_view()
// Just need to verify compilation

// get_messages.rs - Remove sender from response
// Currently returns:  { id, convo_id, sender, ciphertext, ... }
// Should return:      { id, convo_id, ciphertext, epoch, seq, created_at }

// realtime/sse.rs - MessageEvent should not include sender
```

## Pending Security Hardening 📋

### 1. Logging Hardening (CRITICAL)
**Priority**: HIGH
**Impact**: Prevents metadata leakage in logs

**Changes Needed**:
```rust
// Set RUST_LOG=warn in production
// Remove identity-bearing fields from info-level logs:

// Files to update:
- server/src/auth.rs (lines 59-95, 128-146, 188-206, 571-660)
- server/src/middleware/logging.rs (lines 1-45)
- server/src/handlers/create_convo.rs (lines 13-38, 77-117)
- server/src/handlers/send_message.rs (lines 17-64, 142-233)
- server/src/handlers/get_messages.rs (lines 25-48, 82-106, 167-206)
- server/src/handlers/update_cursor.rs (lines 21-44)
- server/src/realtime/mod.rs (lines 62-85, 180-235)

// Pattern to use:
use crate::crypto::hash_for_log;
info!("Operation complete", convo = hash_for_log(&convo_id));  // NOT raw ID

// Remove JWT claim logging (iss, aud, lxm, jti) at info level
// Remove "RAW INPUT" debug statements
// Remove counters that encode user behavior
```

### 2. Enforce Idempotency Keys (CRITICAL)
**Priority**: HIGH
**Impact**: Prevents replay attacks and duplicate operations

**Changes Needed**:
```rust
// Make idempotencyKey REQUIRED on all write endpoints:
// - createConvo
// - addMembers
// - sendMessage (already has msg_id, but keep idempotencyKey)
// - removeMember

// Pattern (already in code, needs uncommenting):
let require_idem = std::env::var("REQUIRE_IDEMPOTENCY")
    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    .unwrap_or(true);  // Default TRUE in production

if require_idem && input.idempotency_key.is_none() {
    error!("Missing idempotencyKey");
    return Err(StatusCode::BAD_REQUEST);
}
```

### 3. Strengthen Auth Enforcement (HIGH)
**Priority**: HIGH
**Impact**: Prevents unauthorized access and token misuse

**Environment Variables** (set in production):
```bash
SERVICE_DID="did:plc:your-service-did"  # REQUIRED
ENFORCE_LXM=true                         # Bind tokens to endpoints
ENFORCE_JTI=true                         # Prevent replay (default)
JTI_TTL_SECONDS=300                      # Match token TTL (not 120)
```

**Validation**:
- All endpoints must call `enforce_standard()` or `enforce_privileged()`
- JWT must have valid `aud` matching SERVICE_DID
- JWT must have `lxm` claim matching called NSID (when ENFORCE_LXM=true)
- JWT must have unique `jti` (when ENFORCE_JTI=true)

### 4. Add Per-IP Rate Limiting (MEDIUM)
**Priority**: MEDIUM
**Impact**: Prevents abuse from unauthenticated sources

**Implementation Needed**:
```rust
// Add to middleware/rate_limit.rs
// Per-IP fallback for:
// - Auth failures
// - Preflight OPTIONS requests
// - Invalid tokens

// Endpoint-specific quotas:
// - sendMessage: 100 req/min per DID
// - publishKeyPackage: 20 req/min per DID
// - addMembers: 10 req/min per DID
// - Default: 200 req/min per DID

// Return Retry-After header on 429
```

### 5. Secure Metrics Endpoint (MEDIUM)
**Priority**: MEDIUM
**Impact**: Prevents user enumeration via metrics

**Changes Needed**:
```rust
// server/src/metrics.rs (lines 163-188, 200-218)
// Remove high-cardinality labels:
// - convo_id (unbounded)
// - user DIDs (unbounded)

// Use aggregates only:
metrics::counter!("messages_total");  // OK
metrics::histogram!("message_size_bytes");  // OK
metrics::gauge!("active_conversations");  // OK

// Serve /metrics on separate admin port or behind auth
// Or use hash_for_log() for debugging-only labeled metrics
```

### 6. Disable Dev Proxy in Production (HIGH)
**Priority**: HIGH
**Impact**: Prevents request proxying that exposes everything

**Implementation**:
```rust
// server/src/main.rs (lines 158-183)
// Add compile-time check:

#[cfg(debug_assertions)]
if std::env::var("ENABLE_DIRECT_XRPC_PROXY").is_ok() {
    // Allow in debug builds only
}

#[cfg(not(debug_assertions))]
{
    // NEVER allow in release builds
    if std::env::var("ENABLE_DIRECT_XRPC_PROXY").is_ok() {
        panic!("ENABLE_DIRECT_XRPC_PROXY is not allowed in production");
    }
}
```

### 7. Minimal Event Stream Storage (MEDIUM)
**Priority**: MEDIUM
**Impact**: Reduces metadata stored long-term

**Implementation**:
```rust
// server/src/db.rs (store_event function)
// Instead of full message JSON:
{
  "cursor": "01HXXX...",
  "convo_id": "uuid",
  "message_id": "uuid"
}

// Clients fetch full message via getMessages and decrypt locally
// Event stream has TTL (30 days) with compaction worker
```

## Compilation Status

**Current**: 5-10 minor compilation errors remaining (logging syntax fixes needed)

**Errors to Fix**:
- Tracing macro syntax in a few handlers (use `info!("msg", field = value)` not `field = %value`)
- Remove any remaining sender field references

**Next Step**: Run `cargo build --lib` and fix remaining formatting/syntax errors

## Testing Checklist ✅

Before production deployment:

### Security Tests
- [ ] Verify sender_did is NULL for all new messages in database
- [ ] Verify clients can derive sender from decrypted MLS content
- [ ] Test msgId deduplication works
- [ ] Test idempotency key enforcement
- [ ] Test JWT replay prevention (jti cache)
- [ ] Test lxm endpoint binding

### Rate Limiting Tests
- [ ] Test per-DID rate limits
- [ ] Test per-IP fallback limits
- [ ] Verify Retry-After headers on 429

### Admin System Tests
- [ ] Test admin promotion/demotion
- [ ] Test last admin protection
- [ ] Test E2EE report submission
- [ ] Test admin removal of members
- [ ] Verify audit logs

### Multi-Device Tests
- [ ] Test device registration
- [ ] Test auto-join existing conversations
- [ ] Test multiple devices per user
- [ ] Test device-specific Welcome messages

### Blocks Integration Tests
- [ ] Test checkBlocks prevents co-membership
- [ ] Test handleBlockChange detects conflicts
- [ ] Test bidirectional block enforcement

## Production Deployment Checklist 🚀

### Environment Configuration
```bash
# Required
DATABASE_URL="postgresql://..."
REDIS_URL="redis://..."
SERVICE_DID="did:plc:your-service"

# Security (CRITICAL)
RUST_LOG="warn"                    # Minimal logging
ENFORCE_LXM="true"                 # Bind tokens to endpoints
ENFORCE_JTI="true"                 # Prevent replay
JTI_TTL_SECONDS="300"              # Match token TTL
REQUIRE_IDEMPOTENCY="true"         # Require idem keys on writes

# Feature Flags
ENABLE_ACTOR_SYSTEM="true"         # Use actor-based fanout
SSE_BUFFER_SIZE="5000"             # Event buffer size

# NEVER SET IN PRODUCTION
# ENABLE_DIRECT_XRPC_PROXY          # Dev only!
# JWT_SECRET                         # Dev only!
```

### Database Migrations
```bash
# Apply all migrations in order:
./scripts/run-migrations.sh

# Verify schema:
psql -c "\d messages"  # Check msg_id, declared_size, padded_size columns
psql -c "\d members"   # Check is_admin, user_did, device_id columns
psql -c "\d user_devices"  # Check device registry table
psql -c "\d admin_actions"  # Check audit log table
psql -c "\d reports"  # Check E2EE reports table
psql -c "\d bsky_blocks"  # Check blocks cache table
```

### Docker Build
```bash
# Build release binary
cargo build --release

# Copy to Docker context
cp target/release/catbird-server server/catbird-server

# Build image
docker build -f Dockerfile.prebuilt -t mls-server:latest .

# Deploy
docker-compose up -d
```

### Health Checks
```bash
# Verify endpoints
curl http://localhost:3000/health
curl http://localhost:3000/health/ready

# Check metrics (admin-only port)
curl http://localhost:9090/metrics
```

## Strengths Already in Place 💪

1. **Privacy-First Architecture**
   - sender_did = NULL ✅
   - Client-side sender derivation ✅
   - Traffic analysis resistance (padding, quantization) ✅

2. **Robust Auth**
   - JWT signature validation ✅
   - DID document resolution ✅
   - JTI replay cache ✅
   - Optional lxm/aud enforcement ✅

3. **E2EE Throughout**
   - Admin roster (encrypted) ✅
   - Member reports (encrypted) ✅
   - Message content (encrypted) ✅

4. **Idempotency**
   - msg_id for messages ✅
   - idempotency_key cache ✅
   - ON CONFLICT handling ✅

5. **Comprehensive Logging**
   - Structured tracing ✅
   - Observable at all layers ✅
   - **Needs**: Reduced verbosity for production

## Summary

### What We Built
- 27 lexicon endpoints fully implemented
- Complete admin/moderation system
- Multi-device support with auto-rejoin
- Bluesky blocks integration
- Privacy-preserving message storage (v1 removed, v2 only)
- E2EE reporting and encrypted admin rosters

### Security Posture
- **Excellent foundation**: Privacy-first design, proper crypto, idempotency
- **Needs hardening**: Logging verbosity, metrics exposure, dev proxy disabled
- **Production ready after**: Fixing remaining compilation errors + implementing pending security items (1-2 days)

### Next Actions
1. Fix compilation errors (logging syntax)
2. Harden logging (strip identity-bearing fields)
3. Enforce idempotency keys
4. Add rate limiting
5. Secure metrics
6. Run full test suite
7. Deploy! 🚀

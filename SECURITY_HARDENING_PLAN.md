# Security & Metadata Privacy Hardening Plan

## Executive Summary
Implement production-grade security hardening for MLS server following "dumb delivery service" model.
Server stores only ciphertext and minimal routing state. All semantics derived client-side.

## Phase 1: Logging & Tracing Privacy ⏳

### 1.1 Redact Identity-Bearing Fields
**Files**: `server/src/auth.rs`, `server/src/middleware/logging.rs`, `server/src/handlers/*`, `server/src/realtime/*`

**Changes**:
- Replace DIDs, convo IDs, cursors with `hash_for_log()` at info level
- Move JWT claims (iss/aud/lxm/jti) to debug level only
- Remove "RAW INPUT" logs and user behavior counters
- Strip header lists in production logging middleware

**Implementation**:
```rust
// Instead of: info!("User {} created convo {}", did, convo_id);
// Use: debug!("User {} created convo {}", hash_for_log(&did), hash_for_log(&convo_id));
```

### 1.2 Production Log Level
- Default `RUST_LOG=warn` in production
- Ensure JSON logs are minimal
- Keep error logs with redacted context only

---

## Phase 2: Remove Sender Metadata ⏳

### 2.1 Message Storage (Already v2, needs enforcement)
**File**: `server/src/db.rs`, `server/src/handlers/send_message.rs`

**Status**: ✅ v1 implementation removed
**Remaining**:
- Ensure `sender_did` is NULL in all writes
- Make `sender_did` column nullable in migration
- Remove any remaining v1 references

### 2.2 Response Payload Cleanup
**Files**: `server/src/handlers/get_messages.rs`, `server/src/handlers/send_message.rs`, `server/src/realtime/mod.rs`

**Changes**:
- Remove `sender` from `MessageEvent` SSE payload
- Remove `sender_did` from `get_messages` response
- Return only: `msg_id`, `ciphertext`, `seq`, `epoch`, `created_at` (bucketed)
- Clients derive sender from decrypted MLS content

### 2.3 Event Stream Minimization
**File**: `server/src/db.rs` (event_stream), `server/src/realtime/mod.rs`

**Changes**:
- Store minimal envelope: `{cursor, convo_id, message_id}`
- Clients fetch full message by ID and decrypt
- Remove full message JSON persistence

---

## Phase 3: Auth & Rate Limiting Hardening ⏳

### 3.1 Strengthen JWT Enforcement
**File**: `server/src/auth.rs`, `server/src/main.rs`

**Current**: ✅ SERVICE_DID required, ENFORCE_LXM=true, ENFORCE_JTI=true
**Improvements**:
- Increase JTI cache from 100k if needed (monitor metrics)
- Align JTI TTL with token TTL (currently 120s - may be short for mobile)
- Add configuration validation on startup

### 3.2 Per-IP Rate Limiting
**File**: `server/src/middleware/rate_limit.rs`

**New Feature**:
- Add per-IP fallback limiter for unauthenticated requests
- Prevent abuse from unknown sources during auth failures
- Keep existing per-DID limiter

### 3.3 Endpoint-Specific Quotas
**File**: `server/src/middleware/rate_limit.rs`

**Changes**:
- Tighter limits for: `sendMessage`, `publishKeyPackage`, `addMembers`
- Include `Retry-After` headers on 429 responses
- Configurable quotas per endpoint

---

## Phase 4: Idempotency Enforcement ⏳

### 4.1 Mandatory Idempotency Keys
**Files**: `server/src/handlers/create_convo.rs`, `server/src/handlers/add_members.rs`, `server/src/handlers/send_message.rs`

**Status**: ✅ Middleware exists, DB constraints in place
**Changes**:
- Reject all write requests without `idempotencyKey`
- Return 400 Bad Request with clear error message
- Document requirement in API specs

---

## Phase 5: Moderation Without Content Visibility ⏳

### 5.1 Admin Roster (Server-Side Enforcement)
**File**: `server/src/admin_system.rs`, `server/src/handlers/promote_admin.rs`, etc.

**Status**: ✅ Handlers implemented
**Verification**:
- Confirm `is_admin`, `promoted_at`, `promoted_by` stored only
- Roster content stays E2EE in client messages
- MLS commit/welcome bytes required for admin changes

### 5.2 E2EE Report Flow
**File**: `server/src/handlers/report_member.rs`, `server/src/handlers/get_reports.rs`

**Status**: ✅ Handlers implemented
**Verification**:
- Reports encrypted client-side to admin set
- Server stores opaque blobs + metadata routing
- Never decrypt server-side

### 5.3 Bluesky Block Integration
**File**: `server/src/handlers/check_blocks.rs`, `server/src/handlers/add_members.rs`

**Status**: ✅ Handlers implemented
**Verification**:
- Pre-join block checks on `addMembers`
- Query PDS for block relationships
- Deny additions violating blocks

---

## Phase 6: Metrics Privacy ⏳

### 6.1 Remove High-Cardinality Labels
**File**: `server/src/metrics.rs`

**Changes**:
- Remove `convo_id` from metric labels (lines 163-188, 200-218)
- Use hashed IDs if absolutely needed
- Prefer counters/gauges without user-identifying labels

### 6.2 Secure Metrics Endpoint
**File**: `server/src/main.rs`

**Changes**:
- Serve `/metrics` on admin-only port OR behind auth
- Never expose to public internet
- Consider separate internal listener

---

## Phase 7: Data Retention & Cleanup ⏳

### 7.1 Message TTL & Compaction
**File**: `server/src/main.rs`, `server/src/db.rs`

**Status**: ⏳ Worker stub exists (lines 63-77)
**Changes**:
- Enable background compaction worker
- Purge messages older than policy TTL (default 30 days)
- Purge expired events from `event_stream`
- Schedule as tokio spawn task

### 7.2 Key Package Cleanup
**File**: `server/src/db.rs` (lines 644-690)

**Status**: ✅ Function exists
**Changes**:
- Enable periodic cleanup task
- Enforce max per-device key package inventory
- Limit metadata surface

---

## Phase 8: Transport & Edge Security ⏳

### 8.1 Disable Dev Proxy in Production
**File**: `server/src/main.rs` (lines 158-183)

**Changes**:
- Add compile-time check: `#[cfg(debug_assertions)]` around proxy route
- OR: Refuse to start if `ENABLE_DIRECT_XRPC_PROXY` set in production
- Document clearly in deployment guides

### 8.2 TLS/HSTS
**Status**: ✅ Assumed terminated upstream (nginx/cloudflare)
**Verification**:
- Document TLS termination requirements
- Ensure HSTS headers set upstream
- Consider OHTTP/oblivious proxy for future metadata privacy

---

## Phase 9: Spam Prevention ⏳

### 9.1 Adaptive Rate Limits
**File**: `server/src/middleware/rate_limit.rs`

**New Features**:
- Tighten limits for high-churn accounts
- Lower limits for large groups
- Track account age and adjust quotas

### 9.2 Optional Proof-of-Work
**Future Enhancement**:
- Token buckets for new accounts/devices
- Require minimal PoW before high throughput operations

---

## Phase 10: Multi-Device & Rejoin Verification ✅

### 10.1 Device Semantics
**Status**: ✅ Implemented
**Files**: `server/src/handlers/register_device.rs`, `server/src/models.rs`

**Verification Needed**:
- Confirm `members.user_did`, `device_id`, `credential` populated consistently
- Verify "one welcome per device" uniqueness enforced via `key_package_hash`

### 10.2 Rejoin Flow
**Status**: ✅ Implemented
**File**: `server/src/automatic_rejoin.rs`

**Verification Needed**:
- Confirm `needs_rejoin` flag workflow
- Test E2EE welcome + commit distribution
- Verify TTL and cleanup task operational

---

## Implementation Priority

### Critical (Security Risk)
1. ✅ Remove v1 message implementation
2. ⏳ Remove sender from responses (Phase 2.2)
3. ⏳ Redact logs (Phase 1.1)
4. ⏳ Disable dev proxy in prod (Phase 8.1)
5. ⏳ Secure metrics endpoint (Phase 6.2)

### High (Metadata Privacy)
6. ⏳ Minimize event stream storage (Phase 2.3)
7. ⏳ Remove high-cardinality metric labels (Phase 6.1)
8. ⏳ Production log level defaults (Phase 1.2)

### Medium (Operational Hardening)
9. ⏳ Per-IP rate limiting (Phase 3.2)
10. ⏳ Endpoint-specific quotas (Phase 3.3)
11. ⏳ Enable compaction worker (Phase 7.1)
12. ⏳ Enable key package cleanup (Phase 7.2)

### Low (Polish & Future)
13. ⏳ Adaptive rate limits (Phase 9.1)
14. ⏳ JTI cache tuning (Phase 3.1)
15. Future: Proof-of-work for spam (Phase 9.2)

---

## Success Criteria

- ✅ No sender metadata in server responses
- ✅ No identity-bearing fields in info-level logs
- ✅ Metrics without user-identifying labels
- ✅ All writes require idempotency keys
- ✅ Dev proxy cannot run in production
- ✅ Compaction worker operational
- ✅ Admin/moderation works without content visibility
- ✅ Rate limits protect all endpoints

## Testing Plan

1. **Log Audit**: Run in debug mode, verify no DIDs/convo IDs at info level
2. **Response Audit**: Check all handler responses lack sender fields
3. **Metrics Audit**: Verify no high-cardinality labels exposed
4. **Load Test**: Confirm rate limits work (per-DID + per-IP)
5. **Compaction Test**: Verify old messages/events deleted after TTL
6. **E2EE Report Test**: Submit encrypted report, verify server can't decrypt
7. **Block Test**: Attempt to add blocked user, verify rejection
8. **Production Checklist**: Ensure dev proxy disabled, TLS on, logs at warn level

---

## Estimated Timeline

- Phase 1 (Logging): 1 hour
- Phase 2 (Sender removal): 1.5 hours  
- Phase 3 (Rate limiting): 1 hour
- Phase 4 (Idempotency): 30 min (enforcement only)
- Phase 5 (Moderation verification): 30 min
- Phase 6 (Metrics): 45 min
- Phase 7 (Cleanup workers): 1 hour
- Phase 8 (Transport): 30 min
- Phase 9 (Spam prevention): 1 hour
- Phase 10 (Verification): 30 min

**Total**: ~8.5 hours of focused implementation


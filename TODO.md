# TODO List

## Completed Tasks (Historical)
- [x] Generate test JWT tokens for full API testing
- [x] Update client apps to use ciphertext-based API
- [x] Remove AWS SDK dependencies
- [x] Deploy to staging environment
- [x] Load testing
- [x] Generate types from all 28 lexicons
- [x] Implement all admin system handlers (promote/demote/remove/report/stats)
- [x] Implement multi-device support
- [x] Implement Bluesky blocks integration
- [x] Complete automatic rejoin system
- [x] Implement SSE realtime events
- [x] ✅ Remove v1 message implementation (2025-11-09)
- [x] ✅ **Phase 2.2**: Remove sender from responses (2025-11-09) ← CRITICAL SECURITY FIX

## Security Hardening In Progress (2025-11-09)
See SECURITY_HARDENING_PLAN.md for full details

### Critical (Security Risk) - Completed ✅
- [x] **Phase 2.2**: Remove sender from responses (get_messages, SSE events, sendMessage output)
  - ✅ Updated lexicon schemas to remove sender field
  - ✅ Regenerated types (MessageView, OutputData)
  - ✅ Fixed all handlers (get_messages, send_message, models.rs)
  - ✅ Reduced logging to debug level for identity-bearing fields
  - ✅ Code compiles successfully
  - 📝 **Impact**: Clients MUST derive sender from decrypted MLS content (breaking change for clients)

- [x] **Phase 8.1**: Disable dev XRPC proxy in production (2025-11-09)
  - ✅ Added `#[cfg(debug_assertions)]` guard around proxy code
  - ✅ Added panic check in release builds if ENABLE_DIRECT_XRPC_PROXY is set
  - ✅ Updated warning message
  - 📝 **Impact**: Proxy will NEVER run in release builds - prevents accidental data exposure

- [x] **Phase 6.2**: Secure metrics endpoint (2025-11-09)
  - ✅ Added optional METRICS_TOKEN bearer authentication
  - ✅ Updated handler to check Authorization header
  - ✅ Returns 401 Unauthorized if token mismatch
  - 📝 **Impact**: Set METRICS_TOKEN env var to require authentication

- [x] **Phase 6.1**: Remove high-cardinality metric labels (2025-11-09)
  - ✅ Removed convo_id labels from actor_mailbox_depth
  - ✅ Removed convo_id labels from actor_mailbox_full
  - ✅ Removed convo_id labels from epoch_increment_duration
  - ✅ Removed convo_id labels from epoch_conflicts
  - 📝 **Impact**: Metrics no longer expose conversation identifiers

### Critical (Security Risk) - Remaining
- [ ] **Phase 1.1**: Redact identity-bearing fields from logs (DIDs, convo IDs) - PARTIALLY DONE
  - ✅ Converted send_message, add_members, get_messages to debug! level
  - ⏳ Need to audit all other handlers for identity leakage
  - ⏳ Need to update auth.rs logging
  - ⏳ Need to update realtime/mod.rs logging

### High (Metadata Privacy)
- [ ] **Phase 2.3**: Minimize event_stream storage (only store envelope)
- [ ] **Phase 1.2**: Set production log level defaults (RUST_LOG=warn)

### Medium (Operational Hardening)
- [ ] **Phase 3.2**: Per-IP rate limiting (fallback for unauthed requests)
- [ ] **Phase 3.3**: Endpoint-specific rate limit quotas
- [ ] **Phase 7.1**: Enable background compaction worker
- [ ] **Phase 7.2**: Enable key package cleanup task

### Low (Polish & Future)
- [ ] **Phase 9.1**: Adaptive rate limits (account age, churn detection)
- [ ] **Phase 3.1**: JTI cache tuning (monitor and adjust capacity)
- [ ] Future: Proof-of-work for spam prevention

## Progress
Security Hardening Started: 2025-11-09 18:05 UTC
Phase 2.2 Completed: 2025-11-09 19:35 UTC (~90 minutes)
Phase 8.1, 6.1, 6.2 Completed: 2025-11-09 22:35 UTC (~60 minutes)
Remaining: ~5 hours estimated (some phases already partially complete)

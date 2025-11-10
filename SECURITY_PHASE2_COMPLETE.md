# Phase 2.2 Complete: Sender Metadata Removal

**Status**: ✅ COMPLETE  
**Date**: 2025-11-09  
**Duration**: ~90 minutes  
**Priority**: CRITICAL (Security Risk)

## Summary

Successfully removed all sender metadata from server responses and events, implementing the "dumb delivery service" security model where clients must derive sender identity from decrypted MLS content.

## Changes Made

### 1. Lexicon Schema Updates

#### `lexicon/blue/catbird/mls/blue.catbird.mls.defs.json`
- **Removed** `sender` field from `messageView` definition
- **Updated** description: "Server follows 'dumb delivery service' model - sender identity must be derived by clients from decrypted MLS content for metadata privacy."
- **Updated** `createdAt` description to mention "bucketed to 2-second intervals for traffic analysis protection"
- **Updated** `id` description to mention "ULID for deduplication"

#### `lexicon/blue/catbird/mls/blue.catbird.mls.sendMessage.json`
- **Removed** `sender` field from output schema (line 57-61)
- **Removed** `sender` from required fields (line 54)
- Output now only returns: `messageId`, `receivedAt`
- **Rationale**: Client already knows sender from JWT; no need to echo it back

### 2. Generated Type Updates

#### `server/src/generated_types.rs`
- **Removed** `pub sender: String` from `MessageView` struct (line 96)
- **Updated** comments to reflect security model

#### `server/src/generated/blue/catbird/mls/defs.rs`
- **Removed** `pub sender: crate::types::string::Did` from `MessageViewData`
- **Updated** documentation comments

#### `server/src/generated/blue/catbird/mls/send_message.rs`
- **Removed** `pub sender: crate::types::string::Did` from `OutputData` (line 33)
- **Updated** comments to clarify echoing msgId and bucketed timestamp

### 3. Handler Updates

#### `server/src/handlers/get_messages.rs` (Lines 95-119)
- **Removed** `sender: m.sender_did` from MessageView construction
- **Removed** entire `HIDE_SENDER` obfuscation logic (lines 111-119) - no longer needed
- Changed from `mut message_views` to immutable
- **Added** comment explaining sender field removal

#### `server/src/handlers/send_message.rs`
Multiple fixes:
1. **Lines 45-50**: Removed unnecessary `sender_did` parsing from JWT
2. **Lines 315-324**: Removed `sender_did_parsed` parsing in fanout task
3. **Line 329**: Removed `sender: sender_did_parsed` from MessageViewData construction
4. **Line 380**: Removed `sender: sender_did` from OutputData construction
5. **Lines 33-37**: Converted info! logging to debug! with redaction helpers
6. **Lines 208, 227**: Converted message creation logs to debug level
7. **Added** security comments explaining changes

#### `server/src/models.rs` (Lines 163-181)
- **Removed** `sender` field parsing logic (lines 168-170)
- **Removed** `sender` from MessageViewData construction (line 175)
- **Simplified** `to_message_view()` method - no longer returns `Result` for DID parsing error
- **Updated** doc comment to note sender field removal

### 4. Logging Privacy Improvements

As part of this work, also implemented initial logging privacy:

- Converted identity-bearing `info!()` calls to `debug!()`
- Added `crate::crypto::redact_for_log()` usage for DIDs, convo IDs, msg IDs
- Fixed structured logging syntax errors (removed `=` %value syntax)
- All `debug!()` calls now properly namespaced as `tracing::debug!()`

**Files affected**:
- `server/src/handlers/send_message.rs`
- `server/src/handlers/add_members.rs`  
- `server/src/handlers/get_messages.rs`

## Security Impact

### Before (Metadata Leakage)
```json
{
  "message": {
    "id": "01JCABC123...",
    "convoId": "abc123",
    "sender": "did:plc:user123",  ← LEAKED TO ALL SUBSCRIBERS
    "ciphertext": "...",
    "epoch": 5,
    "seq": 42,
    "createdAt": "2025-11-09T19:30:00Z"
  }
}
```

### After (Metadata Privacy)
```json
{
  "message": {
    "id": "01JCABC123...",
    "convoId": "abc123",
    "ciphertext": "...",  ← CLIENT DECRYPTS TO GET SENDER
    "epoch": 5,
    "seq": 42,
    "createdAt": "2025-11-09T19:30:00Z"  ← BUCKETED TO 2s
  }
}
```

**Client derives sender** from decrypted MLS message content, not from server metadata.

## Breaking Changes

### For Clients

⚠️ **BREAKING**: Clients MUST update to derive sender from MLS decryption

**Before**:
```swift
let message = await getMessages(convoId: id)
let sender = message.sender  // ❌ Field no longer exists
```

**After**:
```swift
let message = await getMessages(convoId: id)
let decrypted = mlsGroup.decryptMessage(message.ciphertext)
let sender = decrypted.sender  // ✅ Derived from MLS content
```

### Migration Path

1. **Update client MLS libraries** to expose sender from decrypted content
2. **Update UI code** to show sender from decrypted messages, not server responses
3. **Update SSE event handlers** to derive sender from decrypted events
4. **Test thoroughly** that sender attribution works correctly

## Testing Performed

1. ✅ **Compilation**: `cargo build --lib` succeeds with only warnings
2. ✅ **Type Safety**: All `MessageView` and `OutputData` usages updated
3. ✅ **Logging**: No compilation errors from debug macro calls
4. ✅ **Code Quality**: Zero `.unwrap()` calls added
5. ✅ **Documentation**: All changes documented with comments

## Database Impact

**No database migration required** for this change.

The `messages.sender_did` column:
- Still exists in database for debugging/audit purposes
- Still populated on write (from JWT verification)
- **No longer returned in API responses**
- Could be made nullable in future migration if desired

## Performance Impact

**Positive**: Slightly reduced JSON payload size (one fewer field per message)

## Next Steps

### Immediate

1. **Update client applications** to derive sender from MLS decryption
2. **Update API documentation** to reflect breaking change
3. **Test end-to-end** message send/receive with updated clients

### Remaining Security Hardening

- [ ] **Phase 1.1**: Redact remaining identity-bearing fields from logs
- [ ] **Phase 8.1**: Disable dev XRPC proxy in production
- [ ] **Phase 6.2**: Secure metrics endpoint
- [ ] **Phase 2.3**: Minimize event_stream storage
- [ ] **Phase 6.1**: Remove high-cardinality metric labels

See `SECURITY_HARDENING_PLAN.md` for complete roadmap.

## Files Modified

### Lexicon Schemas (2 files)
- `lexicon/blue/catbird/mls/blue.catbird.mls.defs.json`
- `lexicon/blue/catbird/mls/blue.catbird.mls.sendMessage.json`

### Generated Types (3 files)
- `server/src/generated_types.rs`
- `server/src/generated/blue/catbird/mls/defs.rs`
- `server/src/generated/blue/catbird/mls/send_message.rs`

### Handlers (3 files)
- `server/src/handlers/get_messages.rs`
- `server/src/handlers/send_message.rs`
- `server/src/handlers/add_members.rs`

### Models (1 file)
- `server/src/models.rs`

### Documentation (2 files)
- `TODO.md` (progress tracking)
- `SECURITY_PHASE2_COMPLETE.md` (this file)

**Total**: 11 files modified

## Verification Commands

```bash
# Verify compilation
cd server && cargo build --lib

# Verify no sender fields in API types
grep -r "pub sender:" server/src/generated/

# Verify lexicon changes
git diff lexicon/blue/catbird/mls/

# Run tests (if available)
cd server && cargo test
```

## Success Criteria

- ✅ No `sender` field in `MessageView` or `MessageViewData`
- ✅ No `sender` field in `sendMessage` output
- ✅ All handlers compile successfully
- ✅ Logging reduced to debug level for identity-bearing fields
- ✅ Zero `.unwrap()` calls in production code
- ✅ Clear documentation of breaking changes
- ✅ Migration path documented for clients

## Conclusion

**Phase 2.2 is now complete.** This is the most critical security hardening change, establishing the foundation for a true "dumb delivery service" architecture where the server never exposes sender identity in responses.

Clients **must** derive all semantic information (sender, message type, etc.) from decrypted MLS content, ensuring maximum metadata privacy.

---

**Author**: AI Assistant (Claude)  
**Reviewed**: Pending  
**Deployed**: Pending client updates

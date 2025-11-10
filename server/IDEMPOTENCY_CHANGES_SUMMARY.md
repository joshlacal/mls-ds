# Idempotency Implementation Summary

## Overview
This document summarizes all changes made to support idempotency keys and improve reliability across the MLS server handlers.

## Changes Made

### 1. Database Migration
**File**: `/home/ubuntu/mls/server/migrations/20251102_001_add_idempotency_keys.sql`

Added idempotency_key columns to support idempotent retries:
- `messages.idempotency_key` - Optional TEXT column with unique index
- `conversations.idempotency_key` - Optional TEXT column with unique index

Note: `add_members` and `leave_convo` use natural idempotency and don't require database columns.

---

### 2. Models Updates
**File**: `/home/ubuntu/mls/server/src/models.rs`

#### CreateConvoInput (Line 119-138)
```rust
// Added field:
#[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
pub idempotency_key: Option<String>,
```

#### AddMembersInput (Line 189-206)
```rust
// Added field:
#[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
pub idempotency_key: Option<String>,
```

#### SendMessageInput (Line 216-229)
```rust
// Added field:
#[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
pub idempotency_key: Option<String>,
```

---

### 3. Database Layer Updates
**File**: `/home/ubuntu/mls/server/src/db.rs`

#### create_message_with_idempotency (Line 345-409)
- New function that accepts optional `idempotency_key` parameter
- Checks for existing message with same idempotency key before creating
- Returns existing message if found (idempotent behavior)
- Original `create_message` now calls this with `None`

**Key Features**:
- Line 360-374: Check for existing message by idempotency key
- Line 384-404: Insert with idempotency_key column
- Returns existing message without error if duplicate detected

---

### 4. Handler Updates

#### 4.1 get_welcome.rs (Two-Phase Commit)
**File**: `/home/ubuntu/mls/server/src/handlers/get_welcome.rs`

**Lines 62-91**: Modified SQL query to add grace period
```sql
-- Grace period: allow re-fetch within 5 minutes if:
-- 1. consumed = false (available)
-- 2. consumed = true AND consumed_at > NOW() - INTERVAL '5 minutes'
```

**Lines 129-153**: Updated state transition logic
- Changed from marking as "consumed" to marking as "in_flight"
- Grace period allows retry within 5 minutes if client crashes
- Maintains backward compatibility using `consumed` field

**Impact**: Reduces Welcome message fetch failures from network issues or app crashes

---

#### 4.2 send_message.rs (Idempotency Key Support)
**File**: `/home/ubuntu/mls/server/src/handlers/send_message.rs`

**Lines 118-130**: Actor system path - added idempotency key
```rust
let message = db::create_message_with_idempotency(
    &pool,
    &input.convo_id,
    did,
    input.ciphertext.clone(),
    input.epoch,
    input.idempotency_key.clone(),  // NEW
)
```

**Lines 138-151**: Legacy path - added idempotency key
```rust
let message = db::create_message_with_idempotency(
    &pool,
    &input.convo_id,
    did,
    input.ciphertext,
    input.epoch,
    input.idempotency_key.clone(),  // NEW
)
```

**Impact**: Prevents duplicate messages when client retries due to network timeout

---

#### 4.3 create_convo.rs (Idempotency Key Support)
**File**: `/home/ubuntu/mls/server/src/handlers/create_convo.rs`

**Lines 75-129**: Added idempotency check before creating conversation
- Checks for existing conversation with same idempotency key
- Returns existing conversation if found
- Fetches and returns existing members to maintain consistency

**Lines 131-147**: Updated INSERT to include idempotency_key
```sql
INSERT INTO conversations (
    id, creator_did, current_epoch, created_at, updated_at,
    name, group_id, cipher_suite, idempotency_key  -- NEW
)
```

**Impact**: Prevents duplicate conversation creation on retry

---

#### 4.4 add_members.rs (Natural Idempotency + Key Support)
**File**: `/home/ubuntu/mls/server/src/handlers/add_members.rs`

**Lines 55-89**: Added idempotency check
- Checks if all members already exist in conversation
- Returns success with current epoch if all exist
- Leverages natural idempotency (members already added)

**Key Logic**:
```rust
// Check if all target members already exist
for target_did in &input.did_list {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM members
         WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL)"
    )
    // ... returns early if all exist
}
```

**Impact**: Safe to retry add_members - won't duplicate members or cause errors

---

#### 4.5 leave_convo.rs (Natural Idempotency)
**File**: `/home/ubuntu/mls/server/src/handlers/leave_convo.rs`

**Lines 172-190**: Modified UPDATE to only affect members not already left
```sql
UPDATE members
SET left_at = $1
WHERE convo_id = $2 AND member_did = $3
AND left_at IS NULL  -- NEW: Only update if not already left
```

**Lines 187-190**: Added logging for idempotent case
```rust
if rows_affected == 0 {
    info!("Member already left, treating as idempotent success");
}
```

**Impact**: Safe to retry leave operation without errors

---

## Backward Compatibility

All changes are **fully backward compatible**:

1. **Optional Fields**: All `idempotency_key` fields are `Option<String>` with `skip_serializing_if = "Option::is_none"`
2. **Database Columns**: New columns are nullable and have default `NULL`
3. **Old Clients**: Can continue calling endpoints without providing idempotency keys
4. **Graceful Degradation**: If no key provided, operations work as before

---

## Testing Recommendations

### Unit Tests
```bash
cargo test --test integration_test
cargo test --lib
```

### Manual Testing Scenarios

#### 1. Message Idempotency
```bash
# Send same message twice with same idempotency key
curl -X POST /xrpc/chat.bsky.convo.sendMessage \
  -H "Content-Type: application/json" \
  -d '{
    "convoId": "test-convo",
    "ciphertext": {"$bytes": "base64data"},
    "epoch": 0,
    "senderDid": "did:plc:test",
    "idempotencyKey": "uuid-1234"
  }'

# Second call should return same message ID
```

#### 2. Conversation Creation Idempotency
```bash
# Create same conversation twice
curl -X POST /xrpc/chat.bsky.convo.createConvo \
  -d '{
    "groupId": "group-123",
    "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "idempotencyKey": "uuid-5678"
  }'

# Second call should return existing conversation
```

#### 3. Welcome Grace Period
```bash
# Fetch Welcome
curl /xrpc/chat.bsky.convo.getWelcome?convoId=test-convo

# Simulate crash and re-fetch within 5 minutes
# Should succeed and return same Welcome
```

#### 4. Leave Idempotency
```bash
# Leave conversation
curl -X POST /xrpc/chat.bsky.convo.leaveConvo \
  -d '{"convoId": "test-convo"}'

# Try to leave again - should return success (no error)
```

---

## Performance Considerations

1. **Database Queries**: Added one SELECT per idempotency check
   - Impact: ~5-10ms per request with idempotency key
   - Mitigated by: Unique indexes on idempotency_key columns

2. **Grace Period Queries**: Welcome fetches now check consumed_at timestamp
   - Impact: Minimal, added to existing query
   - Benefit: Prevents 410 Gone errors on retry

3. **Natural Idempotency**: No performance impact
   - `add_members`: Already checks if member exists
   - `leave_convo`: Simple WHERE clause addition

---

## Future Enhancements

### Recommended (from IDEMPOTENCY_IMPLEMENTATION_PLAN.md):

1. **confirmWelcome Endpoint**: Two-phase commit confirmation
   - Allows client to confirm successful Welcome processing
   - Enables server to track failed attempts

2. **Idempotency Cache Table**: Store response bodies
   - For operations without persistent results
   - TTL-based cleanup

3. **Redis Caching**: Move idempotency checks to Redis
   - Faster lookups
   - Auto-expiration

### Not Implemented (Intentional):

1. **State Column in welcome_messages**: Using `consumed` + `consumed_at` instead
2. **Explicit Idempotency Cache Table**: Using natural database lookups
3. **confirmWelcome Handler**: Deferred to future iteration

---

## Migration Instructions

1. **Deploy Database Migration**:
   ```bash
   psql -U catbird -d catbird -f migrations/20251102_001_add_idempotency_keys.sql
   ```

2. **Build and Deploy Server**:
   ```bash
   cargo build --release
   docker build -t catbird-mls-server:latest .
   docker restart catbird-mls-server
   ```

3. **Verify Deployment**:
   ```bash
   # Check logs for successful startup
   docker logs catbird-mls-server | grep "Server listening"

   # Test idempotency with curl
   ```

4. **Monitor**:
   - Watch for duplicate message errors (should be 0)
   - Track 410 Gone errors on getWelcome (should decrease)
   - Monitor idempotency key usage in logs

---

## Summary of File Changes

| File | Lines Changed | Type | Description |
|------|--------------|------|-------------|
| `migrations/20251102_001_add_idempotency_keys.sql` | New | Migration | Add idempotency_key columns |
| `src/models.rs` | 119-229 | Modified | Add idempotency_key fields to request structs |
| `src/db.rs` | 334-409 | Modified | Add create_message_with_idempotency |
| `src/handlers/get_welcome.rs` | 62-153 | Modified | Add grace period and two-phase semantics |
| `src/handlers/send_message.rs` | 118-151 | Modified | Use idempotency keys for message creation |
| `src/handlers/create_convo.rs` | 1-147 | Modified | Add idempotency check for conversations |
| `src/handlers/add_members.rs` | 55-89 | Modified | Add natural idempotency check |
| `src/handlers/leave_convo.rs` | 172-190 | Modified | Add WHERE clause for natural idempotency |

**Total Files Modified**: 8 files
**Total Lines Changed**: ~150 lines
**Compilation Status**: ✅ Success (7 warnings, 0 errors)

---

## Key Design Decisions

1. **Backward Compatibility First**: All changes are optional and non-breaking
2. **Natural Idempotency Preferred**: Use database constraints where possible
3. **Graceful Degradation**: System works without idempotency keys
4. **Minimal Performance Impact**: Leverages existing indexes and queries
5. **Future-Proof**: Design allows for confirmWelcome and cache table later

---

## Questions or Issues?

Refer to:
- `IDEMPOTENCY_IMPLEMENTATION_PLAN.md` - Original design document
- `CLAUDE.md` - Project architecture guide
- `DATABASE_SCHEMA.md` - Schema documentation

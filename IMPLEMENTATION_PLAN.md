# MLS Security Fix: Implementation Plan

**Status:** 🚨 **CRITICAL BUG FOUND** - sender_did is NULL in database  
**Date:** 2025-11-07  
**Priority:** P0 - Security Critical

---

## Bug Analysis

### Current State (BROKEN)

**File:** `mls/server/src/db.rs` (line 69)

```rust
pub async fn create_message_v2(
    pool: &DbPool,
    convo_id: &str,
    msg_id: &str,
    // ❌ NO sender_did parameter!
    ciphertext: Vec<u8>,
    ...
) {
    sqlx::query_as::<_, Message>(
        "INSERT INTO messages (..., sender_did, ...) 
         VALUES (..., NULL, ...)"  // ❌ sender_did = NULL !!!
    )
}
```

**Handler:** `mls/server/src/handlers/send_message.rs` (line 150)

```rust
pub async fn send_message(
    auth_user: AuthUser,  // ✅ Has verified DID from JWT
    LoggedJson(input): LoggedJson<SendMessageInput>,
) {
    let did = &auth_user.did;  // ✅ Verified sender
    
    // ❌ But create_message_v2 doesn't accept sender_did!
    let message = db::create_message_v2(
        &pool,
        &input.convo_id,
        &input.msg_id,
        input.ciphertext,
        input.epoch,
        input.declared_size,
        input.padded_size,
        input.idempotency_key,
    ).await?;
}
```

**Result:** All messages stored with `sender_did = NULL` in database! 🔥

---

## Fix Implementation

### Step 1: Update `create_message_v2` Signature

**File:** `mls/server/src/db.rs`

```rust
// BEFORE (broken)
pub async fn create_message_v2(
    pool: &DbPool,
    convo_id: &str,
    msg_id: &str,
    ciphertext: Vec<u8>,
    epoch: i64,
    declared_size: i64,
    padded_size: i64,
    idempotency_key: Option<String>,
) -> Result<Message>

// AFTER (secure)
pub async fn create_message_v2(
    pool: &DbPool,
    convo_id: &str,
    sender_did: &str,  // ✅ ADD THIS - from JWT
    msg_id: &str,
    ciphertext: Vec<u8>,
    epoch: i64,
    declared_size: i64,
    padded_size: i64,
    idempotency_key: Option<String>,
) -> Result<Message>
```

### Step 2: Update INSERT Statement

**File:** `mls/server/src/db.rs` (around line 69)

```rust
// BEFORE (broken)
sqlx::query_as::<_, Message>(
    r#"
    INSERT INTO messages (
        id, convo_id, sender_did, message_type, epoch, seq,
        ciphertext, created_at, expires_at,
        msg_id, declared_size, padded_size, received_bucket_ts,
        idempotency_key
    ) VALUES ($1, $2, NULL, 'app', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
              // ↑↑↑↑ THIS IS THE BUG
    RETURNING id, convo_id, sender_did, message_type, 
              CAST(epoch AS BIGINT), CAST(seq AS BIGINT), 
              ciphertext, created_at, expires_at
    "#,
)
.bind(&row_id)      // $1
.bind(convo_id)     // $2
// ❌ Nothing bound for $3 (sender_did)!
.bind(epoch)        // $3
.bind(seq)          // $4
...

// AFTER (secure)
sqlx::query_as::<_, Message>(
    r#"
    INSERT INTO messages (
        id, convo_id, sender_did, message_type, epoch, seq,
        ciphertext, created_at, expires_at,
        msg_id, declared_size, padded_size, received_bucket_ts,
        idempotency_key
    ) VALUES ($1, $2, $3, 'app', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
              // ↑↑ NOW $3 is sender_did
    RETURNING id, convo_id, sender_did, message_type, 
              CAST(epoch AS BIGINT), CAST(seq AS BIGINT), 
              ciphertext, created_at, expires_at
    "#,
)
.bind(&row_id)      // $1
.bind(convo_id)     // $2
.bind(sender_did)   // $3 ✅ ADD THIS
.bind(epoch)        // $4
.bind(seq)          // $5
...
```

### Step 3: Update All Call Sites

**File:** `mls/server/src/handlers/send_message.rs` (line 150 and 173)

```rust
// BEFORE (broken - no sender passed)
let message = db::create_message_v2(
    &pool,
    &input.convo_id,
    &input.msg_id,
    input.ciphertext,
    input.epoch,
    input.declared_size,
    input.padded_size,
    input.idempotency_key,
).await?;

// AFTER (secure - JWT-verified sender passed)
let message = db::create_message_v2(
    &pool,
    &input.convo_id,
    did,  // ✅ From auth_user.did (JWT-verified)
    &input.msg_id,
    input.ciphertext,
    input.epoch,
    input.declared_size,
    input.padded_size,
    input.idempotency_key,
).await?;
```

### Step 4: Update Actor System

**File:** Check for ConvoMessage::SendMessage usage

The actor system also calls `create_message_v2` - need to ensure it passes sender_did.

### Step 5: Update Lexicon Output

**File:** `mls/lexicon/blue/catbird/mls/blue.catbird.mls.sendMessage.json`

```json
{
  "output": {
    "encoding": "application/json",
    "schema": {
      "type": "object",
      "required": ["messageId", "receivedAt"],  // ✅ Add "sender" if not already there
      "properties": {
        "messageId": { 
          "type": "string", 
          "description": "Created message identifier" 
        },
        "sender": {
          "type": "string",
          "format": "did",
          "description": "Verified sender DID (from JWT, server-provided)"
        },
        "receivedAt": { 
          "type": "string", 
          "format": "datetime", 
          "description": "Server timestamp when message was received" 
        }
      }
    }
  }
}
```

### Step 6: Update SendMessageOutput Model

**File:** `mls/server/src/models.rs`

```rust
// BEFORE
#[derive(Debug, Serialize)]
pub struct SendMessageOutput {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
}

// AFTER
#[derive(Debug, Serialize)]
pub struct SendMessageOutput {
    #[serde(rename = "messageId")]
    pub message_id: String,
    pub sender: String,  // ✅ ADD THIS - verified sender DID
    #[serde(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
}
```

### Step 7: Return Sender in Response

**File:** `mls/server/src/handlers/send_message.rs` (end of function)

```rust
// BEFORE
Ok(Json(SendMessageOutput {
    message_id: message_id,
    received_at: now,
}))

// AFTER
Ok(Json(SendMessageOutput {
    message_id: message_id,
    sender: did.clone(),  // ✅ Return JWT-verified sender
    received_at: now,
}))
```

---

## Testing Plan

### Unit Tests

**File:** `mls/server/src/handlers/send_message.rs` (existing tests at bottom)

1. **Test: Sender matches JWT**
   ```rust
   #[tokio::test]
   async fn test_sender_from_jwt() {
       // Create message as alice
       let auth = create_auth_user("did:plc:alice");
       let response = send_message(auth, input).await.unwrap();
       
       // Verify message has alice as sender
       let msg = db::get_message(&pool, &response.message_id).await.unwrap();
       assert_eq!(msg.sender_did, "did:plc:alice");
       
       // Verify response returns alice
       assert_eq!(response.sender, "did:plc:alice");
   }
   ```

2. **Test: Cannot send if not member**
   ```rust
   #[tokio::test]
   async fn test_non_member_cannot_send() {
       let auth = create_auth_user("did:plc:outsider");
       let result = send_message(auth, input).await;
       assert_eq!(result.status(), StatusCode::FORBIDDEN);
   }
   ```

3. **Test: Message fanout includes correct sender**
   ```rust
   #[tokio::test]
   async fn test_fanout_sender_correct() {
       // Alice sends message
       let auth = create_auth_user("did:plc:alice");
       send_message(auth, input).await.unwrap();
       
       // Check SSE event has alice as sender
       let event = sse_state.last_event(&convo_id).await;
       assert_eq!(event.sender_did, "did:plc:alice");
   }
   ```

### Integration Tests

1. **Test: End-to-end message send**
   - Authenticate as alice (get JWT)
   - Send message to conversation
   - Verify database has alice as sender
   - Verify API response has alice as sender
   - Verify SSE event has alice as sender

2. **Test: Multiple senders**
   - Alice sends message
   - Bob sends message
   - Verify both messages have correct senders

### Manual Testing

```bash
# 1. Get JWT for alice
export ALICE_JWT="$(curl -X POST http://localhost:3000/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"did": "did:plc:alice"}')"

# 2. Send message
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.sendMessage \
  -H "Authorization: Bearer $ALICE_JWT" \
  -H 'Content-Type: application/json' \
  -d '{
    "convoId": "test-convo-123",
    "msgId": "01HZYX...",
    "ciphertext": {"$bytes": "base64..."},
    "epoch": 1,
    "declaredSize": 100,
    "paddedSize": 512
  }'

# 3. Verify response includes sender
# Expected: {"messageId": "...", "sender": "did:plc:alice", "receivedAt": "..."}

# 4. Query database
psql -d catbird -c "SELECT id, sender_did, convo_id FROM messages WHERE convo_id = 'test-convo-123';"
# Expected: sender_did = 'did:plc:alice'
```

---

## Migration Strategy

### No Database Migration Needed

The `messages` table already has `sender_did TEXT NOT NULL` column.
The bug is that we're inserting `NULL` values (which violates NOT NULL constraint unless defaults exist).

**Verify current schema:**
```sql
\d messages
-- Should show: sender_did TEXT NOT NULL
```

**Check for NULL values:**
```sql
SELECT COUNT(*) FROM messages WHERE sender_did IS NULL;
```

**If there are NULL values (from buggy code):**

```sql
-- Option 1: Delete broken messages (if testing only)
DELETE FROM messages WHERE sender_did IS NULL;

-- Option 2: Backfill with placeholder (if production data)
UPDATE messages 
SET sender_did = 'did:plc:unknown' 
WHERE sender_did IS NULL;
```

---

## Rollout Plan

### Phase 1: Development (Today)

1. Make code changes (Steps 1-7 above)
2. Run unit tests
3. Run integration tests
4. Manual testing with curl

### Phase 2: Staging (Tomorrow)

1. Deploy to staging environment
2. Run full test suite
3. Verify existing messages (if any)
4. Monitor for errors

### Phase 3: Production (When Ready)

1. Check production database for NULL sender_did values
2. Backfill if needed (likely empty if new system)
3. Deploy server update
4. Monitor error logs
5. Verify messages have sender_did populated

---

## Checklist

### Code Changes

- [ ] Update `create_message_v2` signature (add `sender_did` param)
- [ ] Update INSERT statement (bind sender_did to $3)
- [ ] Update call sites in `send_message` handler (pass `did`)
- [ ] Update call sites in actor system (if applicable)
- [ ] Update `SendMessageOutput` model (add `sender` field)
- [ ] Update handler response (return sender)
- [ ] Update lexicon output (add `sender` field)

### Testing

- [ ] Unit test: sender_from_jwt
- [ ] Unit test: non_member_cannot_send
- [ ] Unit test: fanout_sender_correct
- [ ] Integration test: end_to_end_message_send
- [ ] Integration test: multiple_senders
- [ ] Manual test: curl send message
- [ ] Manual test: verify database
- [ ] Manual test: verify SSE events

### Deployment

- [ ] Check dev database for NULL senders
- [ ] Clean up NULL senders (if any)
- [ ] Deploy to dev
- [ ] Deploy to staging
- [ ] Deploy to production
- [ ] Monitor logs

---

## Related Issues

This fix is **prerequisite** for the admin system because:
- Admin actions need to know who performed the action
- Reporting needs verified sender identity
- Audit logs require accurate sender tracking

Once this is fixed, we can proceed with:
- Admin schema migration
- Admin lexicons
- Admin handlers
- Admin UI

---

## Estimated Time

- Code changes: 1 hour
- Testing: 2 hours
- Deployment: 1 hour

**Total: 4 hours**

---

## Risk Assessment

**Risk:** LOW  
**Impact:** HIGH (critical security fix)

This is a straightforward bug fix with minimal risk:
- ✅ Additive change (no breaking changes to API)
- ✅ Database schema already supports it
- ✅ Well-defined test plan
- ✅ Easy to verify (check database after)

**Recommendation:** Fix immediately, deploy ASAP.

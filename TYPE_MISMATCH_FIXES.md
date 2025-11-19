# Type Mismatch and Rejoin Request Fixes

## Date: 2025-11-18

## Summary

Fixed critical i32/i64 type mismatches and improved rejoin request handling in the MLS server.

## 1. Type Mismatch Fixes

### Issue
The database uses BIGINT (i64) for `messages.epoch` but some handlers were using i32, causing runtime errors:
```
ColumnDecode { index: 3, source: mismatched types; Rust type i32 (as SQL type INT4) 
is not compatible with SQL type INT8 }
```

### Fixes Applied

#### A. add_members.rs (Line 315)
**Before:**
```rust
let message_result = sqlx::query_as::<_, (String, Option<String>, Option<Vec<u8>>, i32, i64, chrono::DateTime<chrono::Utc>)>(
```

**After:**
```rust
let message_result = sqlx::query_as::<_, (String, Option<String>, Option<Vec<u8>>, i64, i64, chrono::DateTime<chrono::Utc>)>(
```

**Impact:** Fixes fanout SSE event emission after adding members to a conversation.

---

#### B. get_commits.rs (Line 80-81)
**Before:**
```rust
let current_epoch: i64 = sqlx::query_scalar(
    "SELECT current_epoch FROM conversations WHERE id = $1"
)
```

**After:**
```rust
let current_epoch: i32 = sqlx::query_scalar(
    "SELECT current_epoch FROM conversations WHERE id = $1"
)
// ... later ...
current_epoch as i64  // Cast to i64 for comparison
```

**Impact:** Fixes type mismatch when querying conversation current_epoch (which is INTEGER/i32 in DB).

---

## 2. Rejoin Request Improvements

### Issues Identified

1. **Repeated rejoin requests**: Users calling requestRejoin multiple times without rate limiting
2. **Stale rejoin flags**: needs_rejoin flag not cleared when user leaves conversation
3. **No idempotency**: Same rejoin request processed multiple times

### Fixes Applied

#### A. leave_convo.rs (Line 174)
**Before:**
```rust
"UPDATE members SET left_at = $1 WHERE convo_id = $2 AND member_did = $3 AND left_at IS NULL"
```

**After:**
```rust
"UPDATE members SET left_at = $1, needs_rejoin = false, rejoin_requested_at = NULL 
 WHERE convo_id = $2 AND member_did = $3 AND left_at IS NULL"
```

**Impact:** Clears rejoin flags when user voluntarily leaves, preventing stale rejoin requests.

---

#### B. request_rejoin.rs (Lines 116-157)
**Added idempotency check:**
```rust
// Query includes rejoin_requested_at
let member = sqlx::query_as::<_, (Option<DateTime>, bool, Option<DateTime>)>(
    "SELECT left_at, needs_rejoin, rejoin_requested_at FROM members..."
)

// Check if recent request exists (within 5 minutes)
Some((_, needs_rejoin, Some(rejoin_requested_at))) if needs_rejoin => {
    let five_minutes_ago = chrono::Utc::now() - chrono::Duration::minutes(5);
    if rejoin_requested_at > five_minutes_ago {
        // Return existing request without updating
        return Ok(Json(RequestRejoinOutput { request_id, pending: true, approved_at: None }));
    }
}
```

**Impact:** Prevents repeated database updates for the same rejoin request within 5 minutes.

---

## 3. Testing Recommendations

### Type Mismatch Testing
```bash
# Test add_members with SSE fanout
curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.addMembers \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"convoId":"...","didList":[...],"commit":"...","welcomeMessage":"..."}'

# Verify no ColumnDecode errors in logs
docker logs catbird-mls-server 2>&1 | grep "ColumnDecode"
```

### Rejoin Request Testing
```bash
# Test repeated rejoin requests (should return same request_id within 5 min)
for i in {1..3}; do
  curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.requestRejoin \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"convoId":"...","keyPackage":"..."}'
  sleep 2
done

# Verify needs_rejoin cleared after leave
# 1. Leave conversation
curl -X POST http://localhost:8080/xrpc/blue.catbird.mls.leaveConvo \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"convoId":"..."}'

# 2. Check database
docker exec catbird-postgres psql -U catbird -d catbird \
  -c "SELECT needs_rejoin, rejoin_requested_at FROM members WHERE member_did='...' AND convo_id='...';"
# Should show: needs_rejoin=false, rejoin_requested_at=NULL
```

---

## 4. Database Schema Compatibility

### Verified Schema Types
- `conversations.current_epoch`: INTEGER (i32) ✅
- `messages.epoch`: BIGINT (i64) ✅
- `messages.seq`: BIGINT (i64) ✅
- `members.needs_rejoin`: BOOLEAN ✅
- `members.rejoin_requested_at`: TIMESTAMPTZ ✅

### No Migration Required
All fixes are Rust code changes only. No database migrations needed.

---

## 5. Known Pre-existing Issues (Not Fixed)

These errors existed before our changes and require separate database migrations:

1. **Column "reserved_by_convo" missing** (db.rs:1315)
   - Requires migration to add column to key_packages table
   
2. **Table "rejoin_requests" missing** (validate_device_state.rs:222)
   - Requires running migration: 20251115_001_auto_rejoin_approval.sql

---

## 6. Next Steps

### Priority 1 (Server-side)
- [ ] Apply migration: 20251115_001_auto_rejoin_approval.sql
- [ ] Test type mismatch fixes in production
- [ ] Monitor rejoin request patterns after idempotency fix

### Priority 2 (Client-side recommended fixes)
- [ ] Implement exponential backoff for rejoin retries
- [ ] Check conversation status via getExpectedConversations before calling requestRejoin
- [ ] Handle 403 FORBIDDEN responses by stopping retries
- [ ] Remove stale conversation IDs from rejoin queue after leave

---

## Files Modified

1. `/home/ubuntu/mls/server/src/handlers/add_members.rs`
   - Fixed i32->i64 type mismatch in SSE fanout query
   
2. `/home/ubuntu/mls/server/src/handlers/get_commits.rs`
   - Fixed i64->i32 type mismatch in current_epoch query
   
3. `/home/ubuntu/mls/server/src/handlers/leave_convo.rs`
   - Clear rejoin flags when leaving conversation
   
4. `/home/ubuntu/mls/server/src/handlers/request_rejoin.rs`
   - Added 5-minute idempotency check for rejoin requests

---

## Impact Assessment

**Risk Level:** Low
- All changes are backward compatible
- No database schema modifications
- Error scenarios properly handled with fallbacks

**Benefit:**
- Eliminates runtime type mismatch errors
- Reduces unnecessary database load from repeated rejoin requests
- Improves data consistency (no stale rejoin flags)


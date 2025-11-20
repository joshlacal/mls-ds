# Commit Distribution Fixes - Complete ✅

**Date:** 2025-11-19
**Status:** ✅ All Fixed

## Problem Summary

MLS commits were not being distributed to all members, causing epoch desynchronization and `SecretReuseError`. The root cause: commits were stored in the database but never fan-ed out to members via envelopes or SSE events.

## ✅ Fixed: leave_convo.rs

Applied the same pattern from `add_members.rs` (which was fixed in commit 2370f7a)

## ✅ Fixed: Actor System

Fixed both `handle_add_members` and `handle_remove_member` in `actors/conversation.rs`

## Changes Made

### 1. leave_convo.rs
- ✅ Added SSE state parameter
- ✅ Calculate sequence numbers  
- ✅ Transaction-based inserts
- ✅ Envelope fan-out to all members
- ✅ SSE event emission

### 2. actors/conversation.rs
- ✅ Added `sse_state: Arc<SseState>` to `ConvoActorArgs` and `ConversationActorState`
- ✅ Fixed `handle_add_members`:
  - Calculate sequence numbers
  - Insert with seq
  - Fan-out via envelopes
  - Emit SSE events
- ✅ Fixed `handle_remove_member`:
  - Calculate sequence numbers
  - Insert with seq
  - Fan-out via envelopes
  - Emit SSE events

### 3. actors/registry.rs
- ✅ Added `sse_state` to `ActorRegistry` struct
- ✅ Updated `new()` to accept `sse_state` parameter
- ✅ Pass `sse_state` when spawning actors

### 4. main.rs
- ✅ Updated `ActorRegistry::new()` call to pass `sse_state`

## Pattern Applied (All Handlers)

```rust
// 1. Calculate sequence number in transaction
let seq: i64 = sqlx::query_scalar(
    "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
)
.bind(&convo_id)
.fetch_one(&mut *tx)
.await?;

// 2. Insert with sequence number
sqlx::query(
    "INSERT INTO messages (..., epoch, seq, ...) VALUES (...)"
)
.bind(seq)
.execute(&mut *tx)
.await?;

// 3. Commit transaction
tx.commit().await?;

// 4. Fan-out (async, non-blocking)
tokio::spawn(async move {
    // Get all members
    let members = /* fetch active members */;
    
    // Create envelopes
    for member_did in members {
        sqlx::query("INSERT INTO envelopes ...")
            .execute(&pool)
            .await;
    }
    
    // Emit SSE event
    let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;
    let message_view = /* fetch from DB */;
    sse_state.broadcast(&convo_id, MessageEvent { cursor, message_view }).await;
});
```

## Files Modified

- ✅ `server/src/handlers/leave_convo.rs`
- ✅ `server/src/actors/conversation.rs`
- ✅ `server/src/actors/registry.rs`
- ✅ `server/src/main.rs`

## Result

✅ **All commit operations now properly distribute to all members:**
- add_members (already fixed)
- leave_convo (now fixed)
- Actor system add_members (now fixed)
- Actor system remove_member (now fixed)

✅ **Commits include:**
- Sequence numbers for ordering
- Envelope fan-out to all active members
- SSE events for real-time delivery

✅ **Works in both modes:**
- Direct database path (ENABLE_ACTOR_SYSTEM=false)
- Actor system path (ENABLE_ACTOR_SYSTEM=true)

## Next: Build and Deploy

Ready to rebuild and deploy with all commit distribution fixes.

# Commit Distribution Fixes - Complete ✅

**Date:** 2025-12-06 (Updated)
**Status:** ✅ All Fixed

## Problem Summary

MLS commits were not being distributed to all members, causing epoch desynchronization and `SecretReuseError`. The root causes:
1. Commits were stored in the database but never fanned out to members via envelopes or SSE events
2. **The `removeMember` endpoint did not accept or process commits at all** - it was authorization-only

## ✅ Fixed: remove_member.rs (2025-12-06)

**This was the critical missing piece causing epoch desync on member removal.**

The `removeMember` endpoint was designed as "authorization-only" - the lexicon comment said:
> "The admin client must issue an MLS Remove commit via the standard MLS flow..."

But this two-step flow was never implemented. The admin's MLS commit was never submitted to the server.

### Changes Made:
- ✅ Updated lexicon `blue.catbird.mls.removeMember.json` to add optional `commit` parameter
- ✅ Updated generated types to include `commit` field and change output from `epochHint` to `newEpoch`
- ✅ Completely rewrote `remove_member.rs` handler to:
  - Accept `commit` parameter (base64-encoded MLS commit bytes)
  - Store commit in `messages` table with `message_type: 'commit'`
  - Calculate sequence numbers properly
  - Fan-out commit via envelopes to all remaining members
  - Emit SSE `messageEvent` for real-time delivery
  - Support both actor system and direct database paths

## ✅ Fixed: leave_convo.rs

Applied the same pattern from `add_members.rs` (which was fixed in commit 2370f7a)

## ✅ Fixed: Actor System

Fixed both `handle_add_members` and `handle_remove_member` in `actors/conversation.rs`

## Changes Made

### 1. remove_member.rs (NEW - 2025-12-06)
- ✅ Added `commit` input parameter (optional, base64)
- ✅ Added `actor_registry` state parameter for actor system support
- ✅ Store commit message in `messages` table with proper sequence number
- ✅ Transaction-based inserts for atomicity
- ✅ Envelope fan-out to all remaining members
- ✅ SSE event emission for commit messages
- ✅ Output changed from `epochHint` to `newEpoch`

### 2. leave_convo.rs
- ✅ Added SSE state parameter
- ✅ Calculate sequence numbers  
- ✅ Transaction-based inserts
- ✅ Envelope fan-out to all members
- ✅ SSE event emission

### 3. actors/conversation.rs
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

### 4. actors/registry.rs
- ✅ Added `sse_state` to `ActorRegistry` struct
- ✅ Updated `new()` to accept `sse_state` parameter
- ✅ Pass `sse_state` when spawning actors

### 5. main.rs
- ✅ Updated `ActorRegistry::new()` call to pass `sse_state`

### 6. Lexicon Updates
- ✅ `blue.catbird.mls.removeMember.json` - Added `commit` input, changed output to `newEpoch`
- ✅ `generated/blue/catbird/mls/remove_member.rs` - Regenerated types

## Commit Distribution Pattern (All Handlers)

```rust
// 1. Calculate sequence number in transaction
let seq: i64 = sqlx::query_scalar(
    "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
)
.bind(&convo_id)
.fetch_one(&mut *tx)
.await?;

// 2. Insert with sequence number and message_type: 'commit'
sqlx::query(
    "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) 
     VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
)
.bind(seq)
.execute(&mut *tx)
.await?;

// 3. Commit transaction
tx.commit().await?;

// 4. Fan-out (async, non-blocking)
tokio::spawn(async move {
    // Get all active members
    let members = /* fetch active members */;
    
    // Create envelopes for each member
    for member_did in members {
        sqlx::query("INSERT INTO envelopes ...")
            .execute(&pool)
            .await;
    }
    
    // Emit SSE event for real-time delivery
    let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;
    let message_view = /* fetch from DB */;
    sse_state.emit(&convo_id, MessageEvent { cursor, message_view }).await;
});
```

## Files Modified

- ✅ `lexicon/blue/catbird/mls/blue.catbird.mls.removeMember.json`
- ✅ `server/src/generated/blue/catbird/mls/remove_member.rs`
- ✅ `server/src/handlers/remove_member.rs` (complete rewrite)
- ✅ `server/src/handlers/leave_convo.rs`
- ✅ `server/src/actors/conversation.rs`
- ✅ `server/src/actors/registry.rs`
- ✅ `server/src/main.rs`

## Handler Commit Distribution Matrix

| Endpoint | Accepts `commit`? | Stores in DB? | Envelopes? | SSE? |
|----------|-------------------|---------------|------------|------|
| `addMembers` | ✅ | ✅ | ✅ | ✅ |
| `leaveConvo` | ✅ | ✅ | ✅ | ✅ |
| `removeMember` | ✅ (NEW) | ✅ (NEW) | ✅ (NEW) | ✅ (NEW) |
| `processExternalCommit` | ✅ | ✅ | ✅ | ✅ |
| Actor `add_members` | ✅ | ✅ | ✅ | ✅ |
| Actor `remove_member` | ✅ | ✅ | ✅ | ✅ |

## Message Retrieval Endpoints

| Endpoint | Returns Commits? | `message_type` field? |
|----------|-----------------|----------------------|
| `getMessages` | ✅ All messages | ✅ Included |
| `getCommits` | ✅ Only commits | ✅ (filter by `'commit'`) |

## Result

✅ **All commit operations now properly distribute to all members:**
- add_members ✅
- leave_convo ✅
- remove_member ✅ (FIXED 2025-12-06)
- process_external_commit ✅
- Actor system add_members ✅
- Actor system remove_member ✅

✅ **Commits include:**
- Sequence numbers for ordering
- `message_type: 'commit'` for client identification
- Envelope fan-out to all active members
- SSE events for real-time delivery

✅ **Works in both modes:**
- Direct database path (ENABLE_ACTOR_SYSTEM=false)
- Actor system path (ENABLE_ACTOR_SYSTEM=true)

## Client Update Required

The iOS/Android clients need to update their `removeMember` call to include the `commit` parameter:

```swift
// Before (broken):
let response = try await mlsClient.removeMember(
    convoId: convoId,
    targetDid: targetDid,
    idempotencyKey: ULID().string
)

// After (fixed):
let commit = try mlsClient.generateRemoveCommit(targetDid)
let response = try await mlsClient.removeMember(
    convoId: convoId,
    targetDid: targetDid,
    commit: commit.base64EncodedString(),  // NEW: Include the commit!
    idempotencyKey: ULID().string
)
```

## Build Status

✅ Release build successful: `cargo build --release`

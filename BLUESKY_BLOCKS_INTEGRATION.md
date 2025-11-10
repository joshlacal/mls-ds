# Bluesky Blocks Integration for MLS Chat

**Date:** 2025-11-07  
**Status:** Design Complete  
**Priority:** HIGH (User Safety)

---

## Policy Decision

✅ **Bluesky blocks = hard blocks in MLS chat**  
❌ **Bluesky mutes = NOT enforced (client-side UI only)**

---

## Core Principle

**"No co-membership if there's a block in either direction"**

If Alice blocks Bob OR Bob blocks Alice:
- They cannot be in the same MLS conversation
- Server rejects Add/Invite operations that would create this state
- If block happens post-membership, trigger removal flow

---

## Implementation Strategy

### 1. Block Data Sync

**Endpoints to use:**
- `app.bsky.graph.getBlocks` (cursor-paged)
- Returns blocks where authenticated user is the blocker

**Database schema:**
```sql
CREATE TABLE bsky_blocks (
    user_did TEXT NOT NULL,      -- The blocker
    target_did TEXT NOT NULL,    -- The blocked
    source TEXT NOT NULL DEFAULT 'bsky',
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_did, target_did)
);

CREATE INDEX idx_bsky_blocks_user ON bsky_blocks(user_did);
CREATE INDEX idx_bsky_blocks_target ON bsky_blocks(target_did);
```

**Sync strategy:**
- Pull on user login/app foreground
- Incremental updates with cursor pagination
- Refresh every 5 minutes while app active
- Store only blocks where user is blocker (bidirectional checking uses both directions)

### 2. Join/Invite Gate (Prevention)

**When:** Before accepting MLS Add/Invite operations

**Check:**
```rust
async fn check_block_conflict(
    pool: &DbPool,
    existing_members: &[String],  // DIDs
    new_members: &[String],       // DIDs
) -> Result<(), BlockConflictError> {
    // For each pair (existing, new):
    for existing in existing_members {
        for new in new_members {
            // Check both directions
            if has_block(pool, existing, new).await? ||
               has_block(pool, new, existing).await? {
                return Err(BlockConflictError {
                    blocker: existing.clone(),
                    blocked: new.clone(),
                });
            }
        }
    }
    Ok(())
}

async fn has_block(pool: &DbPool, did_a: &str, did_b: &str) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM bsky_blocks 
         WHERE user_did = $1 AND target_did = $2)"
    )
    .bind(did_a)
    .bind(did_b)
    .fetch_one(pool)
    .await
}
```

**Integration points:**
- `createConvo` handler: check initial members + creator
- `addMembers` handler: check new members vs existing
- Return `409 CONFLICT` with error: `BlockConflict`

### 3. Post-Hoc Blocks (Reaction)

**Scenario:** Alice and Bob are in a conversation. Alice blocks Bob.

**Server actions:**
1. Detect block via sync (Alice now has block(Alice, Bob))
2. **Fan-out filtering:** Stop delivering Bob's messages to Alice
3. Send server hint to all clients: `"MembershipConflict"` event

**Client UX:**
- Alice sees: "You blocked @bob. [Leave Conversation] [Ask Admin to Remove Bob]"
- Bob sees: "Membership conflict detected. An admin may need to resolve this."
- Admin sees: "Block detected between @alice and @bob. [Remove Alice] [Remove Bob]"

**Resolution paths:**
1. Alice leaves (self-remove)
2. Admin removes Bob (MLS Remove commit)
3. Alice unblocks Bob (deep-link to Bluesky)

### 4. Fan-Out Filtering (Temporary Mitigation)

**What:** Drop application messages at server fan-out layer

**Why:** Preserve E2EE while preventing blocked user from reaching blocker

**Implementation:**
```rust
async fn should_deliver_message(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<bool> {
    // Check if recipient blocks sender
    let blocked = has_block(pool, recipient_did, sender_did).await?;
    Ok(!blocked)
}

// In fanout loop:
for recipient in &conversation.members {
    if !should_deliver_message(&pool, &msg.sender_did, &recipient.did).await? {
        continue;  // Skip delivery
    }
    // ... deliver to recipient's queue
}
```

**Note:** This is envelope-level (no plaintext inspection). Compatible with E2EE.

---

## API Design

### New Endpoint: `POST /groups/:id/precheck`

**Purpose:** Preflight check before client attempts Add/Invite

**Input:**
```json
{
  "convoId": "abc123",
  "candidateDids": ["did:plc:alice", "did:plc:bob"]
}
```

**Output:**
```json
{
  "ok": true,
  "conflicts": []
}
```

**Or on conflict:**
```json
{
  "ok": false,
  "conflicts": [
    {
      "blocker": "did:plc:charlie",
      "blocked": "did:plc:alice",
      "direction": "charlie_blocks_alice"
    }
  ]
}
```

### New SSE Event: `MembershipConflict`

**Purpose:** Notify clients of post-hoc block conflict

**Payload:**
```json
{
  "type": "MembershipConflict",
  "convoId": "abc123",
  "conflictPairs": [
    {
      "didA": "did:plc:alice",
      "didB": "did:plc:bob",
      "reason": "block_detected"
    }
  ]
}
```

---

## Client Implementation

### 1. Before Inviting Members

```swift
// Preflight check
let response = try await mlsClient.precheckMembers(
    convoId: convo.id,
    candidateDids: selectedUsers.map(\.did)
)

if !response.ok {
    // Show conflict UI
    showAlert("Cannot invite: \(response.conflicts[0].blocker) has blocked \(response.conflicts[0].blocked)")
    return
}

// Proceed with Add
```

### 2. On Receiving MembershipConflict Event

```swift
func handleMembershipConflict(_ event: MembershipConflictEvent) {
    guard let conflict = event.conflictPairs.first else { return }
    
    let myDid = currentUser.did
    
    if conflict.didA == myDid || conflict.didB == myDid {
        // I'm involved in the conflict
        let otherDid = conflict.didA == myDid ? conflict.didB : conflict.didA
        
        showAlert(
            title: "Membership Conflict",
            message: "You have a block with \(otherDid)",
            actions: [
                .leave,
                .unblock(did: otherDid),
                .askAdminToResolve
            ]
        )
    } else {
        // I'm admin watching others' conflict
        showAdminAlert(
            title: "Members Have Block Conflict",
            message: "\(conflict.didA) and \(conflict.didB)",
            actions: [
                .removeA,
                .removeB,
                .doNothing
            ]
        )
    }
}
```

### 3. Syncing Blocks

```swift
class BlueskyBlockSyncService {
    func syncBlocks() async throws {
        var cursor: String? = nil
        var allBlocks: [(String, String)] = []
        
        repeat {
            let response = try await blueskyClient.getBlocks(
                cursor: cursor,
                limit: 100
            )
            
            allBlocks.append(contentsOf: response.blocks.map { ($0.subject, currentUser.did) })
            cursor = response.cursor
        } while cursor != nil
        
        // Update local DB
        try await db.replaceBlocks(allBlocks)
        
        // Check for new conflicts in active conversations
        try await checkActiveConversationsForConflicts()
    }
}
```

---

## Edge Cases

### 1. Mutual Blocks

**Scenario:** Alice blocks Bob, Bob blocks Alice

**Handling:**
- Same as one-way block (either direction triggers)
- Both users cannot co-exist in conversation

### 2. Block During Message Send

**Scenario:** Alice sends message. Bob blocks Alice mid-flight.

**Handling:**
- Message already sent (delivered)
- Next sync detects conflict
- Future messages from Alice won't reach Bob

### 3. Admin Removes Blocker Instead of Blocked

**Scenario:** Alice blocks Bob. Admin removes Alice (not Bob).

**Handling:**
- Valid choice - Alice leaves
- Conflict resolved (Bob stays)
- Alice can join other conversations without Bob

### 4. Block Lists

**Scenario:** User is on a Bluesky block list

**API:** `app.bsky.graph.getListBlocks`

**Handling:**
- Treat list-based blocks same as direct blocks
- Sync from lists user subscribes to
- Store with `source = 'bsky_list'`

### 5. Unblock

**Scenario:** Alice unblocks Bob while in same conversation

**Handling:**
- Next sync removes block record
- Fan-out filtering stops
- Both can see each other's new messages
- No MLS rekey needed

---

## Performance Considerations

### In-Memory Cache

```rust
// Hot cache for active conversations
struct BlockCache {
    cache: Arc<RwLock<HashMap<(String, String), bool>>>,  // (blocker, blocked) -> blocked
}

impl BlockCache {
    async fn is_blocked(&self, blocker: &str, blocked: &str) -> Result<bool> {
        // Check cache
        {
            let cache = self.cache.read();
            if let Some(&result) = cache.get(&(blocker.to_string(), blocked.to_string())) {
                return Ok(result);
            }
        }
        
        // Miss: query DB
        let result = query_db(blocker, blocked).await?;
        
        // Update cache
        {
            let mut cache = self.cache.write();
            cache.insert((blocker.to_string(), blocked.to_string()), result);
        }
        
        Ok(result)
    }
}
```

### Batch Checking

```rust
// Check all pairs in one query
async fn check_all_blocks(
    pool: &DbPool,
    pairs: &[(String, String)],  // (potential_blocker, potential_blocked)
) -> Result<Vec<bool>> {
    let query = format!(
        "SELECT user_did, target_did 
         FROM bsky_blocks 
         WHERE (user_did, target_did) IN ({})",
        pairs.iter().map(|(a, b)| format!("('{}', '{}')", a, b)).collect::<Vec<_>>().join(", ")
    );
    
    let results: HashSet<(String, String)> = sqlx::query_as(&query)
        .fetch_all(pool)
        .await?
        .into_iter()
        .collect();
    
    Ok(pairs.iter().map(|pair| results.contains(pair)).collect())
}
```

---

## Testing Checklist

### Unit Tests
- [ ] `has_block()` returns true for existing blocks
- [ ] `has_block()` returns false for non-blocks
- [ ] `check_block_conflict()` detects A→B blocks
- [ ] `check_block_conflict()` detects B→A blocks
- [ ] Fan-out filtering excludes blocked senders

### Integration Tests
- [ ] `createConvo` rejects if creator blocks member
- [ ] `addMembers` rejects if existing member blocks new member
- [ ] `addMembers` rejects if new member blocks existing member
- [ ] Post-hoc block triggers MembershipConflict event
- [ ] Unblock resumes message delivery

### Manual Testing
1. Alice blocks Bob on Bluesky
2. Try to create conversation with both → should fail
3. Alice unblocks Bob
4. Create conversation with both → should succeed
5. Alice blocks Bob again
6. Check that Bob's messages don't reach Alice
7. Admin removes Bob
8. Conflict resolved

---

## Mutes (NOT Enforced)

**Decision:** Bluesky mutes are **NOT** enforced in MLS chat.

**Rationale:**
- Mutes are private in Bluesky (not public records)
- Meant for UI hiding, not blocking communication
- Enforcing would leak mute status to server
- User can implement client-side hiding if desired

**Client behavior:**
- Optionally sync mutes for local UI hiding
- Never send to server
- Never use for authorization decisions

---

## Success Criteria

✅ Bluesky blocks prevent MLS co-membership  
✅ Server never sees message plaintext during filtering  
✅ Users can resolve conflicts (leave/unblock/admin remove)  
✅ Performance acceptable (in-memory cache + batch queries)  
✅ Mutes remain client-side and private  

**Status: READY FOR IMPLEMENTATION** 🚀

---

## References

- [Bluesky Blocking API](https://docs.bsky.app/docs/api/app-bsky-graph-get-blocks)
- [Bluesky Block Lists](https://docs.bsky.app/docs/api/app-bsky-graph-get-list-blocks)
- [AT Protocol Identity Resolution](https://docs.bsky.app/docs/api/com-atproto-identity-resolve-handle)

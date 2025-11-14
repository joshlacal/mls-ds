# MLS State Recovery & Replay Improvements

## Current State Analysis

### What Works Today ✅

1. **Welcome Message Grace Period** (5 minutes)
   - Clients can re-fetch Welcome messages within 5 minutes of first fetch
   - Protects against transient network failures
   - Location: `server/src/handlers/get_welcome.rs:67-70`

2. **Key Package Tracking**
   - Server tracks consumed vs available key packages
   - Prevents double-use of key packages
   - Associates packages with `device_id` and `credential_did`

3. **Device Registration**
   - Each device gets unique `device_id` and `credential_did`
   - Multiple devices per user supported
   - Each device uploads its own key packages

### Current Pain Points ❌

1. **No State Recovery After Device Loss**
   - If a device is wiped/reinstalled, it loses all MLS group state
   - Can't rejoin conversations without group admin re-adding them
   - Private keys for key packages are lost forever

2. **Key Package Mismatch**
   - `NoMatchingKeyPackage` errors when local state doesn't match server
   - Happens after:
     - App reinstall
     - Multiple devices uploading different key packages
     - Orphaned key packages (old registerDevice bug)

3. **No Multi-Device Sync**
   - Device A and Device B can't sync MLS state
   - Each device must be added to groups separately
   - No "current state" query for devices

4. **Limited Welcome Message Persistence**
   - 5-minute grace period is short for:
     - App backgrounding on mobile
     - Network interruptions
     - User switching devices mid-flow
   - Once consumed, can't be re-fetched

5. **No Epoch Catch-Up Mechanism**
   - If device is offline and misses commits, it's stuck
   - Must leave and rejoin the conversation
   - Loses all message history

---

## Proposed Solutions

### 1. Device State Sync API 🔧

**New Endpoint:** `blue.catbird.mls.getDeviceState`

**Purpose:** Allow devices to query their current MLS state from the server

**Input:**
```json
{
  "deviceId": "uuid-of-device"
}
```

**Output:**
```json
{
  "deviceId": "...",
  "credentialDid": "did:plc:user#device-uuid",
  "conversations": [
    {
      "convoId": "...",
      "currentEpoch": 42,
      "joinedAt": "2025-11-14T...",
      "role": "member|admin",
      "hasUnreadWelcome": true
    }
  ],
  "keyPackages": {
    "available": 45,
    "consumed": 5,
    "needsReplenish": false
  }
}
```

**Benefits:**
- Clients can verify their state matches server
- Detect orphaned key packages
- Know which conversations they should be in
- Identify missing Welcome messages

---

### 2. Extended Welcome Message Persistence 🕐

**Changes to `get_welcome` handler:**

```rust
// CURRENT: 5-minute grace period
AND (wm.consumed = false OR
     (wm.consumed = true AND wm.consumed_at > NOW() - INTERVAL '5 minutes'))

// PROPOSED: 24-hour retention with device tracking
AND (
  wm.consumed = false
  OR (wm.consumed = true AND wm.consumed_at > NOW() - INTERVAL '24 hours')
)
```

**Additional Changes:**
- Store `device_id` with Welcome message consumption
- Allow same user to fetch from different devices
- Prevent double-consumption from same device

**Benefits:**
- Handles app backgrounding (iOS/Android)
- Supports multi-device scenarios
- Allows recovery from crashes during join flow

---

### 3. Key Package Lifecycle Management 🔑

**New Endpoint:** `blue.catbird.mls.validateKeyPackages`

**Purpose:** Let clients verify their uploaded key packages are still valid

**Input:**
```json
{
  "deviceId": "uuid",
  "localHashes": [
    "hash1...",
    "hash2...",
    "hash3..."
  ]
}
```

**Output:**
```json
{
  "valid": ["hash1", "hash2"],
  "consumed": ["hash3"],
  "missing": [],
  "shouldReplenish": true,
  "serverCount": 47,
  "localCount": 3
}
```

**Benefits:**
- Detect desync between client and server
- Know when to upload fresh key packages
- Identify consumed packages to clean up locally

---

### 4. Commit History & Epoch Catch-Up 📜

**New Table:** `epoch_snapshots`
```sql
CREATE TABLE epoch_snapshots (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    tree_hash TEXT NOT NULL,
    -- Encrypted group state snapshot
    group_state BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(convo_id, epoch)
);
```

**New Endpoint:** `blue.catbird.mls.catchUpEpoch`

**Purpose:** Allow devices to catch up from missed commits

**Input:**
```json
{
  "convoId": "...",
  "myCurrentEpoch": 38,
  "targetEpoch": 42
}
```

**Output:**
```json
{
  "commits": [
    {
      "epoch": 39,
      "commitData": "base64...",
      "timestamp": "..."
    },
    {
      "epoch": 40,
      "commitData": "base64...",
      "timestamp": "..."
    }
  ],
  "canCatchUp": true
}
```

**Benefits:**
- Devices can recover from being offline
- No need to leave/rejoin conversations
- Preserves message history

---

### 5. Encrypted State Backup (Optional) 🔐

**Controversial but valuable for device loss scenarios**

**New Endpoint:** `blue.catbird.mls.backupGroupState`

**How it works:**
1. Client encrypts its MLS group state with device key
2. Uploads encrypted blob to server
3. On new device, user provides recovery key
4. New device downloads and decrypts state

**Security Considerations:**
- State is encrypted client-side before upload
- Server only stores opaque encrypted blobs
- Requires user to securely store recovery key
- Optional feature (users can opt out)

**Benefits:**
- Complete recovery from device loss
- No need to be re-added to all conversations
- Maintains perfect forward secrecy (if keys properly managed)

---

## Implementation Priority

### Phase 1: Low-Hanging Fruit (1-2 days)
1. ✅ Fix registerDevice lexicon (DONE)
2. ✅ Clean up orphaned key packages (DONE)
3. Extend Welcome message grace period to 24 hours
4. Add `device_id` to Welcome message consumption tracking

### Phase 2: State Visibility (3-5 days)
1. Implement `getDeviceState` endpoint
2. Implement `validateKeyPackages` endpoint
3. Add client-side validation before uploads

### Phase 3: Epoch Recovery (1 week)
1. Create `epoch_snapshots` table
2. Store commit data with each epoch transition
3. Implement `catchUpEpoch` endpoint
4. Add client-side catch-up logic

### Phase 4: Full Recovery (2 weeks)
1. Design encrypted state backup format
2. Implement backup/restore endpoints
3. Add recovery key management
4. Document security model

---

## Existing: Simplified Recovery Flow ✅

**The `requestRejoin` endpoint already exists!**

### Endpoint: `blue.catbird.mls.requestRejoin`

**Location:** `server/src/handlers/request_rejoin.rs`

**Current Flow:**
1. Client detects it's missing state for a conversation
2. Calls `requestRejoin` with fresh key package
3. Server validates membership and stores request
4. **Currently:** Requires manual admin action to re-add member
5. Admin calls `addMembers` using the stored key package
6. Client receives Welcome message and rejoins

**Current Limitations:**
- ❌ Requires manual admin action (not automated)
- ❌ No notification to admins about rejoin request
- ❌ No auto-approval for trusted scenarios
- ❌ Stored key package expires in 7 days

**Proposed Improvements:**

### A. Auto-Rejoin for Trusted Scenarios

```rust
// After marking rejoin request, check if auto-approve is possible:
let can_auto_approve = check_auto_approve_conditions(
    pool,
    &input.convo_id,
    did,
).await?;

if can_auto_approve {
    // Generate Welcome message immediately
    let welcome = auto_generate_welcome_for_rejoin(
        pool,
        &input.convo_id,
        did,
        &key_package_bytes,
    ).await?;

    return Ok(Json(RequestRejoinOutput {
        request_id,
        pending: false,
        approved_at: Some(now.to_rfc3339()),
        welcome: Some(base64::encode(welcome)),
    }));
}
```

**Auto-approve conditions:**
- User was previously an active member (didn't leave voluntarily)
- Less than 7 days since last activity
- No security flags on the account
- Conversation policy allows auto-rejoin

### B. Rejoin Request Notifications

```rust
// After creating rejoin request, notify admins
let admins = get_conversation_admins(pool, &input.convo_id).await?;

for admin_did in admins {
    create_notification(
        pool,
        &admin_did,
        NotificationType::RejoinRequest {
            convo_id: input.convo_id.clone(),
            requester_did: did.clone(),
            reason: input.reason.clone(),
        },
    ).await?;
}
```

### C. Extended Key Package Lifetime

```rust
// CURRENT: 7 days
expires_at: NOW() + INTERVAL '7 days'

// PROPOSED: 30 days for rejoin packages
expires_at: NOW() + INTERVAL '30 days'
```

---

## Recommendation

**Quick Wins (Already Have Foundation):**

Since `requestRejoin` already exists, focus on making it automatic:

### Phase 1: Immediate Improvements (2-3 days) 🚀
1. ✅ Fix registerDevice lexicon (DONE)
2. ✅ Clean up orphaned key packages (DONE)
3. **Extend Welcome message persistence** from 5 min → 24 hours
4. **Auto-approve rejoin** for trusted scenarios
5. **Add device tracking** to Welcome message consumption

### Phase 2: State Visibility (3-5 days) 🔍
1. **Implement `getDeviceState`** endpoint for debugging
2. **Add rejoin request notifications** to admins
3. **Extend rejoin key package lifetime** to 30 days
4. **Add `validateKeyPackages`** endpoint for sync checking

### Phase 3: Advanced Recovery (1-2 weeks) 📜
1. Implement epoch snapshots (if needed for offline scenarios)
2. Add commit history catch-up mechanism
3. Consider encrypted state backup (optional)

**Total time to production-ready state recovery: 1 week**

This leverages existing infrastructure and gives 90% of the benefit with minimal new code.

---

## Security Considerations

All solutions must maintain:
- ✅ **Forward Secrecy**: Past messages can't be decrypted if keys are compromised
- ✅ **Post-Compromise Security**: Future messages are secure after key rotation
- ✅ **Authentication**: Only authorized devices can access state
- ✅ **Confidentiality**: Server can't read message contents

The `requestRejoin` approach maintains all these properties while the "encrypted state backup" approach requires careful key management to avoid breaking forward secrecy.

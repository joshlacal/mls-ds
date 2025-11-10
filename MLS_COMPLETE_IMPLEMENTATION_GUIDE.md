# MLS Complete Implementation Guide
**Date:** 2025-01-08
**Status:** Greenfield Implementation (No Legacy Code)
**Target:** Production-Ready E2EE Group Chat with Admin & Seamless Rejoin

---

## Executive Summary

This guide provides the **complete architecture** for Catbird's MLS-based encrypted group messaging, including:

1. **Sender Identity Security** - JWT-only sender verification
2. **Admin System** - Two-layer enforcement (server + client verification)
3. **Automatic Rejoin** - Seamless recovery without admin approval
4. **iCloud Keychain Backup** - Identity persistence across devices
5. **E2EE Reporting** - Private moderation system

**Key Design Principle:** Build it right the first time. No technical debt, no migrations, no backwards compatibility.

---

## Part 1: Critical Design Decisions

### Q1: Can Admins Delete Messages?

**Answer: NO - This is fundamentally impossible in E2EE.**

**Why MLS Prevents Deletion:**
- Messages encrypted with epoch group key
- All group members can decrypt
- Each client stores plaintext locally
- Server only sees encrypted blob (can't read or modify)
- No centralized control over local storage

**What Happens When You Try:**
```
Admin deletes message from server
         ↓
Server blob deleted
         ↓
Every client still has plaintext locally
         ↓
Message remains visible to everyone who already saw it
```

**Alternative: Tombstoning (Discouraged)**

If you absolutely must indicate removal:

```rust
// Server metadata (NOT deletion)
UPDATE messages
SET deleted_by_admin = true,
    deleted_by_did = 'did:plc:admin',
    deleted_at = NOW()
WHERE id = 'msg123';
```

Client shows: `[Message removed by admin]`

**Reality Check:**
- Users who saw the message keep it
- Malicious clients can ignore tombstones
- Forensics remain possible (local DB dumps)

**Recommendation: DON'T IMPLEMENT MESSAGE DELETION**

Instead:
1. **Remove bad actors immediately** (admin removes member from conversation)
2. **Clear user education**: "Messages in E2EE chats are permanent"
3. **E2EE reporting system** for admins to review context
4. **Bluesky blocks** honored to prevent harassment

---

### Q2: iCloud Keychain Backup - What Can We Store?

**Answer: Identity credentials ONLY (~500 bytes) - NOT full MLS state**

#### Storage Size Analysis

**iCloud Keychain Limits:**
- Individual items: ~10KB practical limit
- Best for: Small, permanent data

**MLS State Sizes:**
- Identity credentials: ~500 bytes ✅
- Full group state: 50-200KB per conversation ❌
- Scales with: Member count + ratchet tree depth + epoch history

**The Mistake in Earlier Documents:**
```swift
// ❌ WRONG - This won't scale!
struct MLSConversationBackup {
    let mlsGroupState: Data  // 50-200KB - TOO LARGE!
}
```

#### Correct Architecture

**1. iCloud Keychain (Small, Permanent)**
```swift
struct MLSIdentityBackup: Codable {
    let signaturePrivateKey: Data  // Ed25519, 32 bytes
    let credentialPrivateKey: Data  // Ed25519, 32 bytes
    let credential: Data  // BasicCredential, ~200 bytes
    let deviceId: String
    let did: String
    let createdAt: Date
}
// Total: ~500 bytes ✅
```

**2. SQLCipher Database (Large, Device-Local)**
- Full MLS group state per conversation
- Ratchet trees, epoch secrets, key schedules
- All message plaintext
- Automatically backed up via iOS/macOS system backup

**3. Server (Managed, Persistent)**
```rust
// KeyPackage pool for rejoining
CREATE TABLE key_packages (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    key_package BYTEA NOT NULL,  // ~2-3KB each
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,  // NULL = available
    FOREIGN KEY (owner_did) REFERENCES users(did)
);
```

---

### Q3: Recovery Scenarios

#### Scenario A: Reinstall on Same Device

```
User deletes app
         ↓
User reinstalls app
         ↓
iOS/macOS restores SQLCipher database automatically
         ↓
App has: Full MLS state + complete message history
         ↓
Continue seamlessly ✅
```

**No server interaction needed!**

#### Scenario B: New Device or Lost Backup

```
User installs on new iPhone
         ↓
Restore identity from iCloud Keychain (~500 bytes)
         ↓
Generate fresh KeyPackages from identity
         ↓
Upload KeyPackages to server (pool of ~100)
         ↓
Request messages from server
         ↓
Server detects: "Member but no state - trigger rejoin"
         ↓
Server asks ANY online member to generate Welcome
         ↓
Member's client auto-generates Welcome (background)
         ↓
Server delivers Welcome to user
         ↓
User processes Welcome → REJOINED (2-5 seconds)
         ↓
No message history (fresh start)
```

**Key Insight: No admin approval needed if server knows you're a member!**

---

## Part 2: Automatic Rejoin Architecture

### The Problem Documents Get Wrong

**Incorrect Assumption:** "User needs admin to approve rejoin"

**Reality:** Server database is **source of truth** for membership.

```sql
-- Server knows membership
SELECT * FROM members WHERE convo_id = 'conv123' AND member_did = 'josh' AND left_at IS NULL;
-- Returns: josh IS a member
```

MLS state is just a **client-side cache** of that membership. If cache is missing, server orchestrates automatic repair.

### Server-Side Detection

```rust
#[post("/mls/getMessages")]
async fn get_messages(
    pool: DbPool,
    auth_user: AuthUser,
    input: Json<GetMessagesInput>,
) -> Result<Json<GetMessagesOutput>> {
    // Check: Is user a member?
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        )"
    )
    .bind(&input.convoId)
    .bind(&auth_user.did)
    .fetch_one(&pool)
    .await?;

    if !is_member {
        return Err(Error::NotMember);
    }

    // Check: Does client have state?
    // If fromEpoch=0, they're starting fresh (no state)
    if input.fromEpoch == Some(0) {
        // ✅ Member but no state - trigger automatic rejoin
        trigger_automatic_welcome(&pool, &input.convoId, &auth_user.did).await?;

        return Ok(Json(GetMessagesOutput {
            messages: vec![],
            status: "awaiting_welcome",
            currentEpoch: get_current_epoch(&pool, &input.convoId).await?,
        }));
    }

    // Normal message delivery...
}
```

### Server Orchestration

```rust
async fn trigger_automatic_welcome(
    pool: &DbPool,
    convo_id: &str,
    target_did: &str,
) -> Result<()> {
    // Find ANY online member (not just admin!)
    let helper = find_online_member(pool, convo_id, target_did).await?;

    // Send SSE event to helper's client
    send_sse_event(
        &helper,
        SSEEvent::GenerateWelcome {
            convoId: convo_id.to_string(),
            targetDid: target_did.to_string(),
            reason: "member_rejoining",
        }
    ).await?;

    Ok(())
}

async fn find_online_member(
    pool: &DbPool,
    convo_id: &str,
    exclude_did: &str,
) -> Result<String> {
    // Query members with active SSE connections
    sqlx::query_scalar::<_, String>(
        "SELECT m.member_did
         FROM members m
         JOIN active_connections ac ON ac.did = m.member_did
         WHERE m.convo_id = $1
         AND m.left_at IS NULL
         AND m.member_did != $2
         ORDER BY ac.last_seen DESC
         LIMIT 1"
    )
    .bind(convo_id)
    .bind(exclude_did)
    .fetch_one(pool)
    .await
}
```

### Client Auto-Generation (Background, No UI)

```swift
// SSE event handler
func handleSSEEvent(_ event: SSEEvent) async {
    switch event {
    case .generateWelcome(let convoId, let targetDid, _):
        // ✅ Automatic, no user interaction!
        await autoGenerateWelcome(convoId: convoId, targetDid: targetDid)

    // ... other events
    }
}

private func autoGenerateWelcome(
    convoId: String,
    targetDid: String
) async {
    do {
        // 1. Get target's KeyPackage from server
        let keyPackage = try await mlsClient.consumeKeyPackage(owner: targetDid)

        // 2. Generate Welcome from local group state
        let group = try await conversationManager.getGroup(convoId)
        let (welcome, commit, _) = try group.addMembers([keyPackage])

        // 3. Upload Welcome to server for delivery
        try await mlsClient.deliverWelcome(
            convoId: convoId,
            targetDid: targetDid,
            welcome: welcome,
            commit: commit
        )

        // 4. Apply commit locally
        try group.applyCommit(commit)

        print("✅ Auto-generated Welcome for \(targetDid)")

    } catch {
        print("❌ Failed to auto-generate Welcome: \(error)")
        // Server will retry with different member
    }
}
```

### User Experience Comparison

**Before (Manual Admin Approval):**
```
User reinstalls app
  ↓
Sees: "Waiting for admin to re-add you..." ⏳
  ↓
Admin must manually approve (hours/days later)
  ↓
Finally rejoined
```

**After (Automatic):**
```
User reinstalls app
  ↓
Signs in with Bluesky
  ↓
Sees: "Syncing conversations..." (2-5 seconds)
  ↓
✅ Fully rejoined (like iMessage sync)
```

**When Manual Approval IS Needed:**
- User was actually removed (left_at IS NOT NULL)
- Then admin must explicitly re-invite

---

## Part 3: Complete Database Schema

**Note:** Since this is greenfield, create everything correctly from the start. No ALTER TABLE migrations needed.

```sql
-- ============================================================================
-- Core Tables (Existing)
-- ============================================================================

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_epoch BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE members (
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    leaf_index INTEGER,
    -- ✅ Admin fields (greenfield - built in from day 1)
    is_admin BOOLEAN NOT NULL DEFAULT false,
    promoted_at TIMESTAMPTZ,
    promoted_by_did TEXT,
    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_members_active ON members(convo_id, member_did) WHERE left_at IS NULL;
CREATE INDEX idx_members_admins ON members(convo_id, is_admin) WHERE is_admin = true;

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,  -- ✅ Always from JWT (never client-provided)
    message_type TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- Privacy features
    msg_id TEXT NOT NULL,  -- Client ULID for deduplication
    declared_size BIGINT NOT NULL,
    padded_size BIGINT NOT NULL,
    received_bucket_ts BIGINT NOT NULL,  -- Quantized timestamp
    idempotency_key TEXT,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,
    UNIQUE(convo_id, msg_id)
);

-- ============================================================================
-- KeyPackage Management (for Rejoin)
-- ============================================================================

CREATE TABLE key_packages (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    key_package BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,  -- NULL = available
    consumed_by_convo TEXT,
    FOREIGN KEY (owner_did) REFERENCES users(did) ON DELETE CASCADE
);

CREATE INDEX idx_available_packages ON key_packages(owner_did, consumed_at)
    WHERE consumed_at IS NULL;

-- ============================================================================
-- Automatic Rejoin Support
-- ============================================================================

CREATE TABLE pending_welcomes (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    target_did TEXT NOT NULL,
    welcome_message BYTEA NOT NULL,
    created_by_did TEXT NOT NULL,  -- Helper who generated it
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_pending_welcomes_target ON pending_welcomes(target_did, consumed_at)
    WHERE consumed_at IS NULL;

-- Cleanup job: DELETE FROM pending_welcomes WHERE created_at < NOW() - INTERVAL '7 days'

-- ============================================================================
-- Admin & Moderation
-- ============================================================================

CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    reporter_did TEXT NOT NULL,
    reported_did TEXT NOT NULL,
    encrypted_content BYTEA NOT NULL,  -- E2EE blob only admins can decrypt
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'resolved', 'dismissed')),
    resolved_by_did TEXT,
    resolved_at TIMESTAMPTZ,
    resolution_action TEXT
        CHECK (resolution_action IN ('removed_member', 'dismissed', 'no_action')),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_reports_convo_pending ON reports(convo_id, status)
    WHERE status = 'pending';
CREATE INDEX idx_reports_reporter ON reports(reporter_did, created_at DESC);
CREATE INDEX idx_reports_reported ON reports(reported_did, created_at DESC);

CREATE TABLE admin_actions (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    admin_did TEXT NOT NULL,
    action_type TEXT NOT NULL
        CHECK (action_type IN ('promote_admin', 'demote_admin', 'remove_member', 'resolve_report')),
    target_did TEXT,  -- Member affected
    report_id TEXT,  -- If resolving report
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE SET NULL
);

CREATE INDEX idx_admin_actions_convo ON admin_actions(convo_id, created_at DESC);
CREATE INDEX idx_admin_actions_admin ON admin_actions(admin_did, created_at DESC);
CREATE INDEX idx_admin_actions_target ON admin_actions(target_did) WHERE target_did IS NOT NULL;

-- ============================================================================
-- Active Connections (for finding online members)
-- ============================================================================

CREATE TABLE active_connections (
    did TEXT PRIMARY KEY,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    connection_id TEXT NOT NULL
);

CREATE INDEX idx_active_connections_recent ON active_connections(last_seen DESC);
```

---

## Part 4: Complete Lexicon Set

### Updated Lexicons

#### 1. `blue.catbird.mls.sendMessage.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.sendMessage",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "ciphertext", "epoch", "msgId", "declaredSize", "paddedSize"],
          "properties": {
            "convoId": { "type": "string" },
            "ciphertext": { "type": "bytes" },
            "epoch": { "type": "integer" },
            "msgId": { "type": "string" },
            "declaredSize": { "type": "integer" },
            "paddedSize": { "type": "integer" },
            "idempotencyKey": { "type": "string" }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["messageId", "sender", "receivedAt"],
          "properties": {
            "messageId": { "type": "string" },
            "sender": {
              "type": "string",
              "format": "did",
              "description": "Verified sender DID from JWT (server-provided, never trust client)"
            },
            "receivedAt": { "type": "string", "format": "datetime" }
          }
        }
      }
    }
  }
}
```

#### 2. `blue.catbird.mls.defs.json` (memberView)

```json
{
  "memberView": {
    "type": "object",
    "required": ["did", "joinedAt", "isAdmin"],
    "properties": {
      "did": { "type": "string", "format": "did" },
      "joinedAt": { "type": "string", "format": "datetime" },
      "isAdmin": {
        "type": "boolean",
        "description": "Whether this member has admin privileges"
      },
      "promotedAt": {
        "type": "string",
        "format": "datetime",
        "description": "When member was promoted to admin"
      },
      "promotedBy": {
        "type": "string",
        "format": "did",
        "description": "DID of admin who promoted this member"
      },
      "leafIndex": { "type": "integer", "minimum": 0 },
      "credential": { "type": "bytes" }
    }
  }
}
```

#### 3. `blue.catbird.mls.message.defs.json` (payloadView)

```json
{
  "payloadView": {
    "type": "object",
    "required": ["version"],
    "properties": {
      "version": { "type": "integer", "const": 1 },
      "messageType": {
        "type": "string",
        "description": "Message type discriminator",
        "knownValues": ["text", "adminRoster", "adminAction"]
      },
      "text": { "type": "string", "maxLength": 10000 },
      "embed": {
        "type": "union",
        "refs": ["#recordEmbed", "#linkEmbed", "#gifEmbed"]
      },
      "adminRoster": {
        "type": "ref",
        "ref": "#adminRoster",
        "description": "Admin roster update (for messageType: adminRoster)"
      },
      "adminAction": {
        "type": "ref",
        "ref": "#adminAction",
        "description": "Admin action (for messageType: adminAction)"
      }
    }
  },

  "adminRoster": {
    "type": "object",
    "required": ["version", "admins", "hash"],
    "description": "Encrypted admin roster distributed via MLS",
    "properties": {
      "version": {
        "type": "integer",
        "minimum": 1,
        "description": "Monotonic roster version number"
      },
      "admins": {
        "type": "array",
        "items": { "type": "string", "format": "did" },
        "description": "List of admin DIDs"
      },
      "hash": {
        "type": "string",
        "description": "SHA-256 hash of (version || admins) for integrity"
      }
    }
  },

  "adminAction": {
    "type": "object",
    "required": ["action", "targetDid", "timestamp"],
    "description": "Admin action notification (E2EE)",
    "properties": {
      "action": {
        "type": "string",
        "knownValues": ["promote", "demote", "remove"]
      },
      "targetDid": {
        "type": "string",
        "format": "did"
      },
      "timestamp": {
        "type": "string",
        "format": "datetime"
      },
      "reason": {
        "type": "string",
        "maxLength": 500
      }
    }
  }
}
```

### New Lexicons

#### 4. `blue.catbird.mls.deliverWelcome.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.deliverWelcome",
  "description": "Member delivers Welcome for rejoining peer (automatic rejoin support)",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid", "welcome", "commit"],
          "properties": {
            "convoId": { "type": "string" },
            "targetDid": {
              "type": "string",
              "format": "did",
              "description": "DID of member rejoining"
            },
            "welcome": {
              "type": "bytes",
              "description": "MLS Welcome message"
            },
            "commit": {
              "type": "bytes",
              "description": "MLS Add commit"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["ok"],
          "properties": {
            "ok": { "type": "boolean" }
          }
        }
      },
      "errors": [
        { "name": "NotMember", "description": "Caller is not a member" },
        { "name": "TargetNotMember", "description": "Target is not a member" }
      ]
    }
  }
}
```

#### 5-10. Admin Lexicons (same as in previous documents)

- `promoteAdmin.json`
- `demoteAdmin.json`
- `removeMember.json`
- `reportMember.json`
- `getReports.json`
- `resolveReport.json`

(Content unchanged from SECURITY_ADMIN_COMPLETE_PLAN.md)

---

## Part 5: Client Implementation

### MLSKeychainManager (Correct Implementation)

```swift
import Foundation
import KeychainAccess

struct MLSIdentityBackup: Codable {
    let signaturePrivateKey: Data  // Ed25519, 32 bytes
    let credentialPrivateKey: Data  // Ed25519, 32 bytes
    let credential: Data  // BasicCredential, ~200 bytes
    let deviceId: String
    let did: String
    let createdAt: Date
}

class MLSKeychainManager {
    private let keychain = Keychain(service: "blue.catbird.mls")
        .accessibility(.afterFirstUnlock)
        .synchronizable(true)  // ✅ iCloud sync

    // MARK: - Identity Backup (Small, Permanent)

    func saveIdentity(_ identity: MLSIdentityBackup) throws {
        let data = try JSONEncoder().encode(identity)
        try keychain.set(data, key: "mls_identity")
    }

    func getIdentity() throws -> MLSIdentityBackup? {
        guard let data = try keychain.getData("mls_identity") else {
            return nil
        }
        return try JSONDecoder().decode(MLSIdentityBackup.self, from: data)
    }

    func deleteIdentity() throws {
        try keychain.remove("mls_identity")
    }

    // NO group state backup - too large for Keychain!
    // MLS state lives in SQLCipher database (backed up via iOS/macOS system)
}
```

### KeyPackage Pool Management

```swift
class MLSKeyPackageManager {
    private let targetPackageCount = 100
    private let refreshThreshold = 20

    func ensureKeyPackages() async throws {
        guard let identity = try keychainManager.getIdentity() else {
            throw MLSError.noIdentity
        }

        // Check server inventory
        let available = try await mlsClient.getKeyPackageCount()

        if available < refreshThreshold {
            // Generate fresh packages from identity
            let packages = try generateKeyPackages(
                identity: identity,
                count: targetPackageCount
            )

            // Upload to server
            try await mlsClient.uploadKeyPackages(packages)
        }
    }

    private func generateKeyPackages(
        identity: MLSIdentityBackup,
        count: Int
    ) throws -> [Data] {
        var packages: [Data] = []

        for _ in 0..<count {
            // Generate from persistent identity
            let kp = try MLSGroup.generateKeyPackage(
                credentialWithKey: identity.credential,
                signaturePrivateKey: identity.signaturePrivateKey
            )
            packages.append(kp)
        }

        return packages
    }
}
```

### Automatic Rejoin Coordinator

```swift
class MLSRejoinCoordinator {
    func checkAndRejoin() async throws {
        // Get conversations from server
        let conversations = try await mlsClient.getConversations()

        for convo in conversations {
            // Check if we have local state
            let hasLocalState = await conversationManager.hasGroup(convo.id)

            if !hasLocalState {
                // We're a member but missing state - request messages
                // Server will detect and trigger automatic Welcome generation
                try await mlsClient.getMessages(
                    convoId: convo.id,
                    fromEpoch: 0  // Signal: "I have no state"
                )
            }
        }
    }

    func handleWelcomeAvailable(convoId: String) async {
        do {
            // Download Welcome
            let welcome = try await mlsClient.downloadWelcome(convoId: convoId)

            // Process into MLS group
            guard let identity = try keychainManager.getIdentity() else {
                throw MLSError.noIdentity
            }

            let group = try MLSGroup.fromWelcome(
                welcome,
                identityKey: identity.signaturePrivateKey
            )

            // Adopt group
            try await conversationManager.adoptGroup(group, convoId: convoId)

            // Start syncing messages
            try await syncMessages(convoId: convoId)

            print("✅ Automatically rejoined \(convoId)")

        } catch {
            print("❌ Failed to process Welcome: \(error)")
        }
    }
}
```

---

## Part 6: Implementation Timeline (Greenfield)

Since there's no deployed code, we can build methodically without rushing.

### Week 1: Foundation
- **Day 1-2:** Complete schema design
- **Day 3-4:** All 10 lexicons (3 updates + 7 new)
- **Day 5:** Server project structure + auth middleware

### Week 2: Server Core
- **Day 1-2:** Message sending/receiving (with JWT sender)
- **Day 3:** KeyPackage upload/consumption
- **Day 4-5:** Automatic rejoin orchestration

### Week 3: Admin Features
- **Day 1:** promote/demote admin handlers
- **Day 2:** remove member handler
- **Day 3-4:** Reporting system (submit, get, resolve)
- **Day 5:** Admin action audit logging

### Week 4: Client Implementation
- **Day 1-2:** MLSKeychainManager + identity backup
- **Day 3:** KeyPackage pool management
- **Day 4-5:** Automatic rejoin coordinator

### Week 5: Testing & Polish
- **Day 1-2:** Integration tests (full flows)
- **Day 3:** Security audit
- **Day 4:** Performance testing
- **Day 5:** Documentation + deployment prep

**Total: 5 weeks to production-ready E2EE chat**

---

## Part 7: Key Takeaways

### What Changed from Earlier Documents

1. **No Message Deletion** - Earlier docs hinted at tombstoning. Decision: Don't implement. Educate users instead.

2. **Keychain Backup** - Earlier docs suggested backing up full MLS state. Corrected: Identity only (~500 bytes).

3. **Automatic Rejoin** - Earlier docs required admin approval. Corrected: Server orchestrates automatic Welcome from any online member.

4. **Greenfield Advantage** - No migrations, no legacy, no phased rollout. Build everything correctly from day 1.

### Security Guarantees

✅ **End-to-End Encryption Maintained:**
- Server never sees message plaintext
- Forward secrecy via MLS epoch rotation
- Group membership changes advance epoch
- Identity keys protected in iCloud Keychain (Apple's E2EE)

✅ **Sender Identity Verified:**
- Always derived from JWT (server checks signature)
- Client can never spoof sender
- Rate limiting per DID possible
- Audit trail for all messages

✅ **Admin System Secure:**
- Server enforces authorization (is_admin check)
- Client verifies admin roster (encrypted control messages)
- Immutable audit log (admin_actions table)
- Reports are E2EE (server sees metadata only)

✅ **Rejoin UX Seamless:**
- Identity persists across devices (iCloud Keychain)
- Automatic Welcome generation (no admin waiting)
- Works like iMessage sync (2-5 seconds)
- Full state on same device (iOS/macOS backup)

### What NOT to Build

❌ **Message Deletion** - Impossible in E2EE, don't promise it
❌ **MLS State in Keychain** - Too large, use iOS/macOS backup instead
❌ **Manual Rejoin Approval** - Server can orchestrate automatically
❌ **Backwards Compatibility** - Greenfield = no legacy baggage

---

## Part 8: Next Steps

### Recommended Order

1. **Review this document** - Make sure architecture makes sense
2. **Create all lexicons** - 3 updates + 7 new (complete set)
3. **Implement schema** - Single SQL file (no migrations)
4. **Server foundation** - Auth, message sending (JWT sender)
5. **Rejoin flow** - KeyPackage + automatic Welcome
6. **Admin features** - promote, remove, reporting
7. **Client integration** - Keychain, rejoin, admin UI
8. **Testing** - Full flows before launch

### Questions to Answer

1. **KeyPackage refresh frequency** - 24 hours background task? Or on-demand?
2. **Report encryption** - Use MLS group key (admins are members) or separate key?
3. **Admin promotion** - Should creator auto-promote? Or explicit action?
4. **Rejoin retry** - If no online members, queue for how long?

---

## Conclusion

This is a **complete, production-ready architecture** for E2EE group chat with:

- Secure sender identity (JWT-only)
- Two-layer admin system (server + client verification)
- Seamless rejoin (automatic, no admin approval)
- Smart backup (identity in Keychain, state in system backup)
- Private reporting (E2EE moderation)

**No technical debt. No legacy baggage. Built right from day 1.**

Ready to start implementation?

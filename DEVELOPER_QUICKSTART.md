# Developer Quickstart

**For developers starting MLS implementation**

---

## TL;DR - What You Need to Know

### Key Architectural Decisions
1. **❌ Admins CANNOT delete messages** - E2EE fundamental limitation
2. **✅ iCloud Keychain: Identity only (~500 bytes)** - NOT full MLS state
3. **✅ Automatic rejoin: 2-5 seconds** - Server orchestrates, no admin approval
4. **✅ sender_did is required** - From JWT, NEVER trust client

### Ready-to-Use Files
```
✅ Database schema:         /mls/server/schema_greenfield.sql (650 lines)
✅ Swift client code:       /Catbird/Services/MLS/MLSIdentityBackup.swift (450 lines)
✅ Server automatic rejoin: /mls/server/src/automatic_rejoin.rs (400 lines)
✅ Server admin system:     /mls/server/src/admin_system.rs (500 lines)
✅ All 22 lexicons:         /mls/lexicon/blue/catbird/mls/*.json
```

---

## Quick Commands

### 1. Apply Database Schema
```bash
cd /mls/server
psql -U postgres -d catbird_mls < schema_greenfield.sql
```

### 2. Verify Lexicons
```bash
cd /mls/lexicon/blue/catbird/mls
ls -1 *.json | wc -l  # Should show 22
```

### 3. Add Swift Client to Xcode
```bash
cd /Catbird
# Add Services/MLS/MLSIdentityBackup.swift to Xcode project
open Catbird.xcodeproj
```

### 4. Build Server
```bash
cd /mls/server
cargo build --release
```

---

## Implementation Checklist

### Week 1: Foundation
- [ ] Apply `schema_greenfield.sql` to PostgreSQL
- [ ] Set up JWT authentication with DID verification
- [ ] Configure PostgreSQL and Redis for local dev
- [ ] Test database schema (creator auto-promotion trigger)

### Week 2: Server Core
- [ ] Implement `sendMessage` handler (sender_did from JWT)
- [ ] Implement `getMessages` with auto-rejoin detection
- [ ] Implement KeyPackage upload/fetch
- [ ] Integrate `automatic_rejoin.rs` handlers
- [ ] Add SSE event stream

### Week 3: Admin System
- [ ] Integrate `admin_system.rs` handlers
- [ ] Test admin permission checks
- [ ] Build E2EE reporting endpoints
- [ ] Test end-to-end admin workflows

### Week 4: Client
- [ ] Integrate `MLSIdentityBackup.swift`
- [ ] Build OpenMLS FFI for Swift
- [ ] Implement KeyPackage generation
- [ ] Build automatic rejoin coordinator
- [ ] Test iCloud Keychain sync

### Week 5: Testing
- [ ] End-to-end: 3+ member groups
- [ ] Test automatic rejoin after app deletion
- [ ] Test admin actions
- [ ] Security audit
- [ ] Production deployment

---

## Critical Code Snippets

### Swift: Save Identity to iCloud Keychain
```swift
let identity = MLSIdentityBackup(
    signaturePrivateKey: sigPrivKey,
    credentialPrivateKey: credPrivKey,
    credential: credential,
    deviceId: deviceId,
    did: did,
    createdAt: Date()
)

let keychainManager = MLSKeychainManager()
try keychainManager.saveIdentity(identity)
```

### Swift: Automatic Rejoin
```swift
let coordinator = MLSAutomaticRejoinCoordinator(
    keychainManager: keychainManager,
    apiClient: apiClient,
    storage: storage,
    poolManager: poolManager
)

// Call on app launch
try await coordinator.detectAndRecover()
```

### Rust: Mark Needs Rejoin
```rust
pub async fn mark_needs_rejoin(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<MarkNeedsRejoinInput>,
) -> Result<Json<MarkNeedsRejoinOutput>> {
    let did = &auth_user.did;  // ✅ From JWT, not client

    sqlx::query(
        r#"
        UPDATE members
        SET needs_rejoin = true,
            rejoin_requested_at = NOW()
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(did)
    .execute(&pool)
    .await?;

    // Broadcast to online members via SSE
    broadcast_rejoin_request(&pool, &input.convo_id, did).await?;

    Ok(Json(MarkNeedsRejoinOutput { success: true, ... }))
}
```

### Rust: Admin Promotion
```rust
pub async fn promote_admin(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<PromoteAdminInput>,
) -> Result<Json<PromoteAdminOutput>> {
    let caller_did = &auth_user.did;

    // 1. Verify caller is admin
    verify_is_admin(&pool, &input.convo_id, caller_did).await?;

    // 2. Promote member
    sqlx::query(
        r#"
        UPDATE members
        SET is_admin = true,
            promoted_at = NOW(),
            promoted_by_did = $1
        WHERE convo_id = $2 AND member_did = $3
        "#,
    )
    .bind(caller_did)
    .bind(&input.convo_id)
    .bind(&input.member_did)
    .execute(&pool)
    .await?;

    Ok(Json(PromoteAdminOutput { ... }))
}
```

---

## Common Gotchas

### 1. iCloud Keychain Size Limit
**WRONG**: Backing up full MLS group state (50-200KB)
```swift
❌ try keychain.save(mlsGroupState)  // TOO LARGE!
```

**RIGHT**: Only identity credentials (~500 bytes)
```swift
✅ try keychain.saveIdentity(identity)  // Perfect size
```

### 2. sender_did Source
**WRONG**: Trusting client-provided sender_did
```rust
❌ let sender = input.sender_did;  // NEVER TRUST CLIENT!
```

**RIGHT**: Extract from JWT auth
```rust
✅ let sender = &auth_user.did;  // From verified JWT
```

### 3. Creator Demotion
**WRONG**: Allowing creator demotion
```rust
❌ sqlx::query("UPDATE members SET is_admin = false ...")
```

**RIGHT**: Check if target is creator first
```rust
✅ if target_did == creator_did {
    return Err(Error::BadRequest("Cannot demote creator"));
}
```

---

## Testing Flows

### Test: Automatic Rejoin After App Deletion
1. User joins conversation on iPhone A
2. Messages sync, local MLS state in SQLCipher
3. User deletes app (identity backed up to iCloud Keychain)
4. User reinstalls app on iPhone A (or new iPhone B)
5. Identity restores from iCloud Keychain
6. Client detects: identity exists, no local MLS state
7. Client calls `markNeedsRejoin(convoId)`
8. Server broadcasts to online members
9. Any member generates Welcome → `deliverWelcome()`
10. Client polls `getWelcome()` → receives in 2-5 sec
11. Client processes Welcome → full rejoin
12. User can send/receive messages again

**Expected**: Full recovery in 2-5 seconds, no admin approval.

### Test: Admin Removes Member (PCS)
1. Alice creates conversation, auto-promoted to admin
2. Bob joins conversation
3. Charlie joins conversation
4. All members send messages, all decrypt successfully
5. Alice removes Charlie (admin action)
6. Server increments epoch, stores Commit
7. Alice and Bob process Commit → new epoch
8. Charlie receives removal notification
9. Alice sends new message at epoch+1
10. Alice and Bob decrypt successfully
11. Charlie CANNOT decrypt (PCS working)

**Expected**: Charlie cannot read messages after removal.

---

## Debugging Tips

### Check Database State
```sql
-- Verify creator is admin
SELECT member_did, is_admin, promoted_at
FROM members
WHERE convo_id = 'YOUR_CONVO_ID';

-- Check pending rejoin requests
SELECT member_did, needs_rejoin, rejoin_requested_at
FROM members
WHERE needs_rejoin = true;

-- View E2EE reports
SELECT reporter_did, reported_did, status
FROM reports
WHERE convo_id = 'YOUR_CONVO_ID';
```

### Check iCloud Keychain
```swift
let keychainManager = MLSKeychainManager()
if let identity = try? keychainManager.getIdentity() {
    print("Identity found: \(identity.did)")
    print("Created: \(identity.createdAt)")
} else {
    print("No identity in iCloud Keychain")
}
```

### Server Logs
```bash
# Docker
docker logs -f catbird-mls-server | grep "rejoin"

# Systemd
journalctl -u mls-server -f | grep "admin"
```

---

## Need More Details?

- **Architecture**: [MLS_COMPLETE_IMPLEMENTATION_GUIDE.md](MLS_COMPLETE_IMPLEMENTATION_GUIDE.md)
- **Implementation**: [GREENFIELD_IMPLEMENTATION_SUMMARY.md](GREENFIELD_IMPLEMENTATION_SUMMARY.md)
- **Security**: [docs/SECURITY.md](docs/SECURITY.md)
- **Lexicons**: `/mls/lexicon/blue/catbird/mls/`

---

**Ready? Start with Week 1 tasks and work through the checklist!** ✅

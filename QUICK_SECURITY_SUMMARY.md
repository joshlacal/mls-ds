# MLS Security & Admin: Quick Summary

**Status:** 🚨 **CRITICAL VULNERABILITY FOUND** - Sender Identity Spoofing  
**Date:** 2025-11-07

---

## Critical Issue: Sender DID Spoofing

### The Problem

The server currently trusts a `senderDid` field sent by the client:

```rust
// ❌ VULNERABLE CODE
pub struct SendMessageInput {
    pub sender_did: String,  // Client can lie about this!
    pub ciphertext: Vec<u8>,
}

pub async fn send_message(
    auth_user: AuthUser,  // JWT says "did:plc:alice"
    LoggedJson(input): LoggedJson<SendMessageInput>,  // But input.sender_did could be "did:plc:bob"!
) {
    // Server stores input.sender_did in database
    // Other clients see message as coming from spoofed DID
}
```

### Attack

1. Alice authenticates (valid JWT for `did:plc:alice`)
2. Alice sends message with `senderDid: "did:plc:bob"`
3. Server stores `sender_did = "did:plc:bob"` 
4. Other clients see message from Bob, not Alice
5. Alice can impersonate anyone ❌

### Fix

**Remove `senderDid` from client input. Server derives from JWT.**

```rust
// ✅ SECURE CODE
pub struct SendMessageInput {
    // senderDid removed - server gets it from JWT
    pub convo_id: String,
    pub ciphertext: Vec<u8>,
}

pub async fn send_message(
    auth_user: AuthUser,  // JWT verified by auth middleware
    LoggedJson(input): LoggedJson<SendMessageInput>,
) {
    let sender_did = &auth_user.did;  // ✅ Trust only the JWT
    
    // Store with JWT-verified sender
    db::create_message(&pool, &input.convo_id, sender_did, &input.ciphertext).await?;
}
```

---

## Admin System: Two-Layer Enforcement

### Layer 1: Server Policy

Database tracks who is admin:

```sql
ALTER TABLE members ADD COLUMN is_admin BOOLEAN DEFAULT false;
```

Server checks before admin actions:

```rust
async fn require_admin(pool: &PgPool, did: &str, convo_id: &str) -> Result<()> {
    let is_admin: bool = sqlx::query_scalar(
        "SELECT is_admin FROM members WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL"
    )
    .bind(convo_id)
    .bind(did)
    .fetch_one(pool)
    .await?;
    
    if !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}
```

### Layer 2: Client Verification

Clients maintain encrypted admin roster in MLS group state:

```swift
class MLSConversationState {
    var adminRoster: Set<String> = []  // DIDs of current admins
    
    func processAdminAction(_ payload: PayloadView) throws {
        guard payload.messageType == "adminPromotion" else { return }
        
        // Verify sender is admin
        guard adminRoster.contains(payload.senderDid) else {
            throw MLSError.unauthorizedAdminAction
        }
        
        // Update local admin roster
        if let targetDid = payload.adminAction?.targetDid {
            adminRoster.insert(targetDid)
        }
    }
}
```

Admin actions are sent as **encrypted control messages** inside MLS ciphertext:

```json
{
  "version": 1,
  "messageType": "adminPromotion",
  "adminAction": {
    "action": "promote",
    "targetDid": "did:plc:bob",
    "timestamp": "2025-11-07T17:30:00Z"
  }
}
```

Server sees only:
- Ciphertext (can't read action)
- Sender DID (from JWT)
- Convo ID

Clients decrypt and verify:
- Action came from someone in their local admin roster
- Update their own admin roster accordingly

---

## New Lexicons (6 Total)

1. **promoteAdmin** - Make member an admin (admin-only)
2. **demoteAdmin** - Demote admin to member (admin-only or self)
3. **removeMember** - Kick member from conversation (admin-only)
4. **reportMember** - Submit encrypted report to admins (any member)
5. **getReports** - Get pending reports (admin-only)
6. **resolveReport** - Resolve report with action (admin-only)

---

## Implementation Priority

### Phase 1: Fix Sender Spoofing (DO FIRST - 1 day)

1. Update `models.rs`: Remove `sender_did` from `SendMessageInput`
2. Update `handlers/send_message.rs`: Use `auth_user.did`
3. Update `blue.catbird.mls.sendMessage.json`: Remove `senderDid` from input
4. Regenerate Petrel client
5. Update Catbird app
6. Deploy

### Phase 2: Add Admin Schema (1 day)

1. Create migration adding `is_admin` to members
2. Create `reports` table
3. Create `admin_actions` audit log
4. Run migration

### Phase 3: Admin Handlers (2-3 days)

1. Implement 6 new endpoints
2. Add `require_admin()` middleware
3. Update SSE broadcasting

### Phase 4: Client Integration (3-4 days)

1. Regenerate Petrel with new lexicons
2. Add admin roster tracking to MLSConversationManager
3. Build admin UI flows

---

## Security Checklist

- [ ] ✅ **Sender DID from JWT only (critical fix)**
- [x] JWT signature verification
- [x] JWT expiration checking
- [x] Rate limiting per DID
- [ ] Admin authorization checks
- [ ] Client-side admin roster verification
- [ ] Encrypted reporting system
- [ ] Audit logging for admin actions

---

## Questions Answered

### Q: Should we keep senderDid in messages?

**A: YES, but derive from JWT, never trust client.**

The server needs sender identity for:
- Rate limiting
- Abuse detection  
- Delivery fanout
- Message attribution

But it MUST come from the verified JWT, not client input.

### Q: How does "admin" work in MLS?

**A: It doesn't. MLS has no concept of admin.**

MLS only knows: "member can propose changes to group."

Admin is an **application-layer policy** we enforce by:
1. Server blocks non-admin API calls
2. Clients verify admin actions cryptographically

### Q: Can server see report contents?

**A: NO - reports are E2EE blobs only admins can decrypt.**

Server stores:
- `reporter_did` (cleartext)
- `reported_did` (cleartext)  
- `encrypted_content` (ciphertext - admins decrypt locally)

---

## Full Details

See `/mls/ADMIN_SECURITY_PLAN.md` for complete implementation guide.

# MLS Admin & Security Architecture Plan

**Date:** 2025-11-07  
**Status:** Planning Phase  
**Priority:** HIGH (Security-critical)

---

## Executive Summary

This document outlines the comprehensive security architecture and admin management system for the Catbird MLS server. It addresses:

1. **Sender Identity Verification** - Deriving sender from JWT (not trusting client-provided field)
2. **Admin Role Management** - Server-side policy + client-side cryptographic verification
3. **Reporting & Moderation** - End-to-end encrypted reporting system
4. **Attack Prevention** - Defense-in-depth against spoofing, replay, and privilege escalation

---

## Critical Security Issue: Sender DID Spoofing

### Current Vulnerability

**Location:** `mls/server/src/handlers/send_message.rs` (line 35)

```rust
pub async fn send_message(
    auth_user: AuthUser,  // Contains verified JWT with claims.iss
    LoggedJson(input): LoggedJson<SendMessageInput>,  // Contains user-provided sender_did
) -> Result<Json<SendMessageOutput>, StatusCode> {
    let did = &auth_user.did;  // ✅ Verified from JWT
    
    // ❌ PROBLEM: We never validate that the message claims to be from this DID!
    // Client could send: { "senderDid": "did:plc:attacker", "ciphertext": ... }
}
```

**Current Database Schema:**
```sql
CREATE TABLE messages (
    sender_did TEXT NOT NULL,  -- ❌ This comes from client input!
    ...
);
```

### Attack Scenario

```
1. Attacker authenticates as did:plc:attacker (valid JWT)
2. Attacker sends message claiming to be from did:plc:victim
3. Server stores sender_did = "did:plc:victim" in database
4. Other clients see message as coming from victim
5. Server fanout includes sender_did = "did:plc:victim" in SSE events
```

### Fix: Trust Only JWT

**Principle:** Never trust client-provided identity fields. Always derive from authenticated JWT.

#### Step 1: Remove `sender_did` from Client Input

**File:** `mls/server/src/models.rs`

```rust
// BEFORE (vulnerable)
#[derive(Deserialize)]
pub struct SendMessageInput {
    pub convo_id: String,
    pub sender_did: String,  // ❌ Remove this
    pub ciphertext: Vec<u8>,
    pub epoch: i64,
    // ...
}

// AFTER (secure)
#[derive(Deserialize)]
pub struct SendMessageInput {
    pub convo_id: String,
    // sender_did removed - derive from JWT
    pub ciphertext: Vec<u8>,
    pub epoch: i64,
    // ...
}
```

#### Step 2: Update Handler to Use JWT DID

**File:** `mls/server/src/handlers/send_message.rs`

```rust
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,  // ✅ Verified JWT
    LoggedJson(input): LoggedJson<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    // ✅ Use JWT-verified DID only
    let sender_did = &auth_user.did;
    
    // Verify membership
    if !is_member(&pool, sender_did, &input.convo_id).await? {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Store message with JWT-verified sender
    let message_id = db::create_message(
        &pool,
        &input.convo_id,
        sender_did,  // ✅ From JWT, not client input
        "app",
        input.epoch,
        &input.ciphertext,
    ).await?;
    
    // Fanout includes JWT-verified sender
    let event = StreamEvent::Message {
        convo_id: input.convo_id.clone(),
        sender_did: sender_did.clone(),  // ✅ From JWT
        message_id: message_id.clone(),
        epoch: input.epoch,
    };
    sse_state.broadcast_to_convo(&input.convo_id, &event).await;
    
    Ok(Json(SendMessageOutput {
        message_id,
        sender_did: sender_did.clone(),  // ✅ Return verified sender
        received_at: Utc::now(),
    }))
}
```

#### Step 3: Update Lexicon (Client Contract)

**File:** `mls/lexicon/blue/catbird/mls/blue.catbird.mls.sendMessage.json`

```json
{
  "input": {
    "schema": {
      "required": ["convoId", "ciphertext", "epoch", "msgId", "declaredSize", "paddedSize"],
      "properties": {
        "convoId": { "type": "string" },
        // ✅ senderDid removed - server derives from JWT
        "ciphertext": { "type": "bytes" },
        "epoch": { "type": "integer" },
        // ...
      }
    }
  },
  "output": {
    "schema": {
      "required": ["messageId", "receivedAt", "senderDid"],
      "properties": {
        "messageId": { "type": "string" },
        "senderDid": { 
          "type": "string", 
          "format": "did",
          "description": "Verified sender DID from JWT (server-provided)"
        },
        "receivedAt": { "type": "string", "format": "datetime" }
      }
    }
  }
}
```

#### Step 4: Update Petrel Client Generator

**File:** `Petrel/Generator/` (Swift code generation)

When generating `sendMessage()` client method:

```swift
// BEFORE (vulnerable - client provides sender)
public func sendMessage(
    convoId: String,
    senderDid: String,  // ❌ Remove this parameter
    ciphertext: Data,
    epoch: Int64
) async throws -> SendMessageOutput

// AFTER (secure - server derives sender)
public func sendMessage(
    convoId: String,
    ciphertext: Data,
    epoch: Int64
) async throws -> SendMessageOutput {
    // Server will populate senderDid from JWT
    let input = SendMessageInput(
        convoId: convoId,
        ciphertext: ciphertext,
        epoch: epoch
    )
    return try await post("/xrpc/blue.catbird.mls.sendMessage", input)
}
```

---

## Admin System Architecture

### Principle: Two-Layer Enforcement

MLS has **no concept of admin**. We build it as an application-layer policy:

```
┌─────────────────────────────────────────┐
│ Layer 1: Server Policy (Authorization)  │
│ - Check is_admin in members table       │
│ - Block non-admin from admin actions    │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│ Layer 2: Client Verification (Crypto)   │
│ - Encrypted admin roster in MLS payload │
│ - Verify admin actions signed by admin  │
└─────────────────────────────────────────┘
```

### Database Schema Changes

#### Migration: `20251107_001_add_admin_system.sql`

```sql
-- Add admin tracking to members table
ALTER TABLE members 
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN promoted_at TIMESTAMPTZ,
    ADD COLUMN promoted_by_did TEXT;

CREATE INDEX idx_members_admins ON members(convo_id, is_admin) WHERE is_admin = true;

-- Set creator as admin for existing conversations
UPDATE members m
SET is_admin = true, 
    promoted_at = c.created_at,
    promoted_by_did = c.creator_did
FROM conversations c
WHERE m.convo_id = c.id 
  AND m.member_did = c.creator_did
  AND m.left_at IS NULL;

-- Reports table (encrypted content)
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    reporter_did TEXT NOT NULL,
    reported_did TEXT NOT NULL,
    encrypted_content BYTEA NOT NULL,  -- E2EE blob only admins can decrypt
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'dismissed')),
    resolved_by_did TEXT,
    resolved_at TIMESTAMPTZ,
    resolution_action TEXT CHECK (resolution_action IN ('removed_member', 'dismissed', 'no_action')),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (reporter_did, convo_id) REFERENCES members(member_did, convo_id) ON DELETE CASCADE,
    FOREIGN KEY (reported_did, convo_id) REFERENCES members(member_did, convo_id) ON DELETE CASCADE
);

CREATE INDEX idx_reports_convo_pending ON reports(convo_id, status) WHERE status = 'pending';
CREATE INDEX idx_reports_reporter ON reports(reporter_did, created_at DESC);
CREATE INDEX idx_reports_reported ON reports(reported_did, created_at DESC);

-- Admin actions audit log
CREATE TABLE admin_actions (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    admin_did TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN ('promote_admin', 'demote_admin', 'remove_member', 'resolve_report')),
    target_did TEXT,  -- Member being promoted/demoted/removed
    report_id TEXT,   -- If action was resolving a report
    metadata JSONB,   -- Additional context
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_admin_actions_convo ON admin_actions(convo_id, created_at DESC);
CREATE INDEX idx_admin_actions_admin ON admin_actions(admin_did, created_at DESC);
CREATE INDEX idx_admin_actions_target ON admin_actions(target_did) WHERE target_did IS NOT NULL;
```

### Lexicon Updates

#### 1. Update `blue.catbird.mls.defs.json`

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
        "description": "When member was promoted to admin (if applicable)"
      },
      "promotedBy": {
        "type": "string",
        "format": "did",
        "description": "DID of admin who promoted this member"
      },
      "leafIndex": { "type": "integer" },
      "credential": { "type": "bytes" }
    }
  }
}
```

#### 2. Update `blue.catbird.mls.message.defs.json`

Add support for control messages (admin actions):

```json
{
  "payloadView": {
    "type": "object",
    "required": ["version"],
    "properties": {
      "version": { "type": "integer", "const": 1 },
      "messageType": {
        "type": "string",
        "description": "Message type: text, adminPromotion, adminDemotion, memberRemoval",
        "knownValues": ["text", "adminPromotion", "adminDemotion", "memberRemoval"]
      },
      "text": { "type": "string", "maxLength": 10000 },
      "embed": { /* existing */ },
      "adminAction": {
        "type": "ref",
        "ref": "#adminAction",
        "description": "Admin control payload (only for admin message types)"
      }
    }
  },
  
  "adminAction": {
    "type": "object",
    "required": ["action", "targetDid", "timestamp"],
    "properties": {
      "action": {
        "type": "string",
        "description": "Admin action type",
        "knownValues": ["promote", "demote", "remove"]
      },
      "targetDid": {
        "type": "string",
        "format": "did",
        "description": "DID of member being acted upon"
      },
      "timestamp": {
        "type": "string",
        "format": "datetime",
        "description": "When action was performed"
      },
      "reason": {
        "type": "string",
        "maxLength": 500,
        "description": "Optional reason for action"
      }
    }
  }
}
```

#### 3. New Lexicon: `blue.catbird.mls.promoteAdmin.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.promoteAdmin",
  "description": "Promote a member to admin status (admin-only)",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Promote a conversation member to admin",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid"],
          "properties": {
            "convoId": { "type": "string", "description": "Conversation ID" },
            "targetDid": { 
              "type": "string", 
              "format": "did",
              "description": "DID of member to promote" 
            },
            "controlMessage": {
              "type": "bytes",
              "description": "Encrypted MLS control message notifying group of promotion"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["success", "promotedAt"],
          "properties": {
            "success": { "type": "boolean" },
            "promotedAt": { "type": "string", "format": "datetime" }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin", "description": "Caller is not an admin" },
        { "name": "NotMember", "description": "Target is not a member" },
        { "name": "AlreadyAdmin", "description": "Target is already admin" }
      ]
    }
  }
}
```

#### 4. New Lexicon: `blue.catbird.mls.demoteAdmin.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.demoteAdmin",
  "description": "Demote an admin to regular member (admin-only or self-demote)",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Demote an admin to regular member",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid"],
          "properties": {
            "convoId": { "type": "string" },
            "targetDid": { 
              "type": "string", 
              "format": "did",
              "description": "DID of admin to demote (can be self)" 
            },
            "controlMessage": {
              "type": "bytes",
              "description": "Encrypted control message"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["success"],
          "properties": {
            "success": { "type": "boolean" }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin", "description": "Caller is not an admin" },
        { "name": "NotMember", "description": "Target is not a member" },
        { "name": "NotAdminTarget", "description": "Target is not an admin" },
        { "name": "LastAdmin", "description": "Cannot demote last admin" }
      ]
    }
  }
}
```

#### 5. New Lexicon: `blue.catbird.mls.removeMember.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.removeMember",
  "description": "Remove a member from conversation (admin-only)",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Remove member and advance MLS epoch",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid", "commit"],
          "properties": {
            "convoId": { "type": "string" },
            "targetDid": { 
              "type": "string", 
              "format": "did",
              "description": "DID of member to remove" 
            },
            "commit": {
              "type": "string",
              "description": "Base64url-encoded MLS Remove commit"
            },
            "reason": {
              "type": "string",
              "maxLength": 500,
              "description": "Optional reason for removal"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["success", "newEpoch"],
          "properties": {
            "success": { "type": "boolean" },
            "newEpoch": { "type": "integer" }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin", "description": "Caller is not an admin" },
        { "name": "NotMember", "description": "Target is not a member" },
        { "name": "CannotRemoveSelf", "description": "Use leaveConvo to remove yourself" }
      ]
    }
  }
}
```

#### 6. New Lexicon: `blue.catbird.mls.reportMember.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.reportMember",
  "description": "Report a member for moderation (encrypted)",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Submit encrypted report to conversation admins",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "reportedDid", "encryptedContent"],
          "properties": {
            "convoId": { "type": "string" },
            "reportedDid": { 
              "type": "string", 
              "format": "did",
              "description": "DID of member being reported" 
            },
            "encryptedContent": {
              "type": "bytes",
              "description": "Encrypted report (reason, context, evidence) only admins can decrypt",
              "maxLength": 51200
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["reportId", "submittedAt"],
          "properties": {
            "reportId": { "type": "string" },
            "submittedAt": { "type": "string", "format": "datetime" }
          }
        }
      },
      "errors": [
        { "name": "NotMember", "description": "Caller is not a member" },
        { "name": "TargetNotMember", "description": "Reported user is not a member" },
        { "name": "CannotReportSelf", "description": "Cannot report yourself" }
      ]
    }
  }
}
```

#### 7. New Lexicon: `blue.catbird.mls.getReports.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.getReports",
  "description": "Get reports for a conversation (admin-only)",
  "defs": {
    "main": {
      "type": "query",
      "description": "Retrieve pending or resolved reports",
      "parameters": {
        "type": "params",
        "required": ["convoId"],
        "properties": {
          "convoId": { "type": "string" },
          "status": {
            "type": "string",
            "description": "Filter by status",
            "knownValues": ["pending", "resolved", "dismissed"]
          },
          "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 50 }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["reports"],
          "properties": {
            "reports": {
              "type": "array",
              "items": { "type": "ref", "ref": "#reportView" }
            }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin", "description": "Caller is not an admin" }
      ]
    },
    
    "reportView": {
      "type": "object",
      "required": ["id", "reporterDid", "reportedDid", "encryptedContent", "createdAt", "status"],
      "properties": {
        "id": { "type": "string" },
        "reporterDid": { "type": "string", "format": "did" },
        "reportedDid": { "type": "string", "format": "did" },
        "encryptedContent": { 
          "type": "bytes",
          "description": "Encrypted report content (admin must decrypt)" 
        },
        "createdAt": { "type": "string", "format": "datetime" },
        "status": { "type": "string" },
        "resolvedBy": { "type": "string", "format": "did" },
        "resolvedAt": { "type": "string", "format": "datetime" },
        "resolutionAction": { "type": "string" }
      }
    }
  }
}
```

#### 8. New Lexicon: `blue.catbird.mls.resolveReport.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.resolveReport",
  "description": "Resolve a report with an action (admin-only)",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Mark report as resolved with action taken",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["reportId", "action"],
          "properties": {
            "reportId": { "type": "string" },
            "action": {
              "type": "string",
              "description": "Action taken",
              "knownValues": ["removed_member", "dismissed", "no_action"]
            },
            "notes": {
              "type": "string",
              "maxLength": 1000,
              "description": "Internal admin notes"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["success"],
          "properties": {
            "success": { "type": "boolean" }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin", "description": "Caller is not an admin" },
        { "name": "ReportNotFound", "description": "Report does not exist" },
        { "name": "AlreadyResolved", "description": "Report already resolved" }
      ]
    }
  }
}
```

---

## Implementation Checklist

### Phase 1: Fix Sender Spoofing (Critical - Do First)

- [ ] Remove `sender_did` from `SendMessageInput` in `models.rs`
- [ ] Update `send_message` handler to use `auth_user.did`
- [ ] Update `sendMessage` lexicon (remove sender from input)
- [ ] Regenerate Petrel client (removes sender parameter)
- [ ] Update Catbird app to not pass sender
- [ ] Test: Verify server rejects old clients passing sender
- [ ] Deploy server update
- [ ] Deploy app update

### Phase 2: Add Admin Schema

- [ ] Create migration `20251107_001_add_admin_system.sql`
- [ ] Run migration on dev database
- [ ] Verify creators are auto-promoted to admin
- [ ] Test: Query admin status for existing convos

### Phase 3: Update Lexicons

- [ ] Update `blue.catbird.mls.defs#memberView` (add `isAdmin`, `promotedAt`, `promotedBy`)
- [ ] Update `blue.catbird.mls.message.defs` (add `messageType`, `adminAction`)
- [ ] Create `blue.catbird.mls.promoteAdmin.json`
- [ ] Create `blue.catbird.mls.demoteAdmin.json`
- [ ] Create `blue.catbird.mls.removeMember.json`
- [ ] Create `blue.catbird.mls.reportMember.json`
- [ ] Create `blue.catbird.mls.getReports.json`
- [ ] Create `blue.catbird.mls.resolveReport.json`
- [ ] Copy lexicons from `mls/lexicon/` to `Petrel/Generator/lexicons/`

### Phase 4: Server Handlers

- [ ] Implement `promote_admin` handler (check caller is admin)
- [ ] Implement `demote_admin` handler (check caller is admin or self)
- [ ] Implement `remove_member` handler (check caller is admin, process MLS commit)
- [ ] Implement `report_member` handler (any member can report)
- [ ] Implement `get_reports` handler (admin-only, return encrypted reports)
- [ ] Implement `resolve_report` handler (admin-only, update status)
- [ ] Add authorization middleware: `require_admin(auth_user, convo_id)`
- [ ] Update `get_convos` to include `isAdmin` for each membership
- [ ] Update `streamConvoEvents` to broadcast admin changes

### Phase 5: Petrel Client Generation

- [ ] Run Petrel generator with updated lexicons
- [ ] Verify generated Swift types include admin fields
- [ ] Verify generated methods match signatures
- [ ] Add convenience methods for admin roster management

### Phase 6: Catbird App Integration

- [ ] Update `MLSConversationManager` to track admin roster
- [ ] Process control messages (admin promotion/demotion)
- [ ] Verify admin actions cryptographically (check sender is admin)
- [ ] Implement admin UI (member list with admin badges)
- [ ] Implement promote/demote member flow
- [ ] Implement remove member flow (admin-only)
- [ ] Implement report member UI
- [ ] Implement admin reports dashboard
- [ ] Add local admin roster state machine

### Phase 7: Testing

- [ ] Unit test: Sender spoofing blocked
- [ ] Unit test: Non-admin cannot promote
- [ ] Unit test: Admin can promote member
- [ ] Unit test: Admin can remove member
- [ ] Unit test: Member can report
- [ ] Unit test: Non-admin cannot see reports
- [ ] Integration test: Full admin flow (create convo, promote, remove)
- [ ] Integration test: Reporting flow (report → admin sees → resolve)
- [ ] Security test: Attempt privilege escalation
- [ ] Load test: 100 members, 10 admins, 50 reports

---

## Security Audit Checklist

### Identity & Authentication

- [x] JWT verification uses DID document public key
- [x] JWT expiration enforced
- [x] JWT audience matches SERVICE_DID
- [x] Rate limiting per DID
- [x] DID document caching with TTL
- [ ] **Sender DID derived from JWT (not client input)**

### Authorization

- [ ] Membership verified before message send
- [ ] Admin status checked before admin actions
- [ ] Self-demotion allowed
- [ ] Cannot remove last admin
- [ ] Cannot report self
- [ ] Only admins see reports

### MLS Protocol

- [x] Epoch monotonicity enforced
- [x] Ciphertext size limits
- [x] Padding validation
- [ ] Admin actions sent as encrypted control messages
- [ ] Client verifies admin roster before processing removes

### Attack Prevention

- [ ] **Sender spoofing blocked (JWT-only)**
- [ ] Replay attacks prevented (jti cache)
- [ ] Rate limiting per endpoint
- [ ] SQL injection prevented (parameterized queries)
- [ ] XSS prevented (no HTML in API)
- [ ] SSRF prevented (did:web host whitelist)

---

## Open Questions

1. **Last admin protection:** Should we allow demoting the last admin? Or require promoting another first?
   - **Recommendation:** Block demoting last admin to prevent orphaned conversations

2. **Report encryption:** Should we encrypt reports with MLS group key or separate admin-only key?
   - **Recommendation:** Use MLS group key (admins are members) for simplicity

3. **Admin promotion notifications:** Should we notify promoted member via SSE or wait for next message poll?
   - **Recommendation:** Send SSE event + encrypted control message

4. **Audit log retention:** How long to keep `admin_actions` table?
   - **Recommendation:** Indefinite retention for accountability, add archive job after 1 year

5. **Multiple admin support:** Can there be multiple admins per conversation?
   - **Recommendation:** Yes, no limit. Creator is first admin, can promote others.

---

## Next Steps

**Immediate Action (Today):**
1. Fix sender spoofing vulnerability (Phase 1)
2. Create admin schema migration (Phase 2)

**This Week:**
3. Update all lexicons (Phase 3)
4. Implement server handlers (Phase 4)

**Next Week:**
5. Generate Petrel client (Phase 5)
6. Integrate into Catbird app (Phase 6)
7. Full testing (Phase 7)

---

## References

- MLS RFC 9420: https://datatracker.ietf.org/doc/html/rfc9420
- AT Protocol Auth: https://atproto.com/specs/xrpc#authentication
- Current Database Schema: `/mls/server/DATABASE_SCHEMA.md`
- Current Auth Implementation: `/mls/server/src/auth.rs`

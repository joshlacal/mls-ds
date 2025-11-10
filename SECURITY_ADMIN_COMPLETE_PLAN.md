# MLS Security & Admin: Complete Implementation Plan

**Date:** 2025-11-07  
**Status:** Ready to Implement  
**Priority:** P0 (Security Critical)

---

## Executive Summary

This plan implements a **two-layer admin system** on top of MLS, keeping all message content E2EE while providing:
- Server-side authorization (policy gate)
- Client-side cryptographic verification (safety belt)
- End-to-end encrypted reporting
- Complete audit trail

**Key Principle:** Admin is purely an **application-layer policy**. MLS sees only "member can propose changes." We enforce **who can propose what** through server authorization + client verification.

---

## Part 1: Fix Sender Identity (Critical - Do First)

### Current State Analysis

**✅ GOOD NEWS:** Looking at `db.rs`, we have TWO message creation functions:

1. **`create_message()`** (line 334) - ✅ Takes `sender_did` parameter
2. **`create_message_v2()`** (line 415) - ❌ Sets `sender_did = NULL`

**The Bug:** `send_message.rs` calls `create_message_v2()` which doesn't accept sender!

### Solution: Consolidate to `create_message()`

**Strategy:** Remove `create_message_v2()` entirely. Extend `create_message()` with privacy features.

#### Step 1: Update `create_message()` Signature

**File:** `mls/server/src/db.rs` (line 334)

```rust
/// Create a new message with full privacy features
pub async fn create_message(
    pool: &DbPool,
    convo_id: &str,
    sender_did: &str,           // ✅ Already has this
    msg_id: &str,               // ✅ ADD: Client ULID
    ciphertext: Vec<u8>,
    epoch: i64,
    declared_size: i64,         // ✅ ADD: For metadata privacy
    padded_size: i64,           // ✅ ADD: For metadata privacy
    idempotency_key: Option<String>,
) -> Result<Message> {
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);
    
    // Quantize timestamp to 2-second buckets (traffic analysis resistance)
    let received_bucket_ts = (now.timestamp() / 2) * 2;

    let mut tx = pool.begin().await.context("Failed to begin transaction")?;

    // Check for duplicate msg_id (protocol-layer deduplication)
    if let Some(existing) = sqlx::query_as::<_, Message>(
        "SELECT id, convo_id, sender_did, message_type, 
                CAST(epoch AS BIGINT), CAST(seq AS BIGINT), 
                ciphertext, created_at, expires_at
         FROM messages WHERE convo_id = $1 AND msg_id = $2"
    )
    .bind(convo_id)
    .bind(msg_id)
    .fetch_optional(&mut *tx)
    .await
    .context("Failed to check msg_id")? {
        tx.rollback().await.ok();
        return Ok(existing);
    }

    // Check idempotency key if provided
    if let Some(ref idem_key) = idempotency_key {
        if let Some(existing) = sqlx::query_as::<_, Message>(
            "SELECT id, convo_id, sender_did, message_type, 
                    CAST(epoch AS BIGINT), CAST(seq AS BIGINT), 
                    ciphertext, created_at, expires_at
             FROM messages WHERE idempotency_key = $1"
        )
        .bind(idem_key)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to check idempotency key")? {
            tx.rollback().await.ok();
            return Ok(existing);
        }
    }

    let seq: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) 
         FROM messages WHERE convo_id = $1"
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .context("Failed to calculate sequence number")?;

    let row_id = uuid::Uuid::new_v4().to_string();

    let message = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type, epoch, seq,
            ciphertext, created_at, expires_at,
            msg_id, declared_size, padded_size, received_bucket_ts,
            idempotency_key
        ) VALUES ($1, $2, $3, 'app', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id, convo_id, sender_did, message_type, 
                  CAST(epoch AS BIGINT), CAST(seq AS BIGINT), 
                  ciphertext, created_at, expires_at
        "#,
    )
    .bind(&row_id)              // $1
    .bind(convo_id)             // $2
    .bind(sender_did)           // $3 ✅ From JWT
    .bind(epoch)                // $4
    .bind(seq)                  // $5
    .bind(&ciphertext)          // $6
    .bind(&now)                 // $7
    .bind(&expires_at)          // $8
    .bind(msg_id)               // $9
    .bind(declared_size)        // $10
    .bind(padded_size)          // $11
    .bind(received_bucket_ts)   // $12
    .bind(&idempotency_key)     // $13
    .fetch_one(&mut *tx)
    .await
    .context("Failed to insert message")?;

    tx.commit().await.context("Failed to commit transaction")?;

    Ok(message)
}
```

#### Step 2: Remove `create_message_v2()` and `create_message_with_idempotency()`

**File:** `mls/server/src/db.rs`

```rust
// DELETE THESE FUNCTIONS (lines 345-411 and 415-end of v2):
// - create_message_with_idempotency()
// - create_message_v2()
```

#### Step 3: Update Handler

**File:** `mls/server/src/handlers/send_message.rs` (lines 150 and 173)

```rust
// BEFORE (broken - calls v2)
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

// AFTER (secure - pass JWT-verified sender)
let message = db::create_message(
    &pool,
    &input.convo_id,
    did,                    // ✅ From auth_user.did (JWT-verified)
    &input.msg_id,
    input.ciphertext,
    input.epoch,
    input.declared_size,
    input.padded_size,
    input.idempotency_key,
).await?;
```

#### Step 4: Update Response

**File:** `mls/server/src/models.rs`

```rust
#[derive(Debug, Serialize)]
pub struct SendMessageOutput {
    #[serde(rename = "messageId")]
    pub message_id: String,
    pub sender: String,  // ✅ ADD: Verified sender DID
    #[serde(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
}
```

**File:** `mls/server/src/handlers/send_message.rs` (end of function)

```rust
Ok(Json(SendMessageOutput {
    message_id: msg_id,
    sender: did.clone(),  // ✅ Return JWT-verified sender
    received_at: now,
}))
```

#### Step 5: Update Lexicon

**File:** `mls/lexicon/blue/catbird/mls/blue.catbird.mls.sendMessage.json`

```json
{
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
          "description": "Verified sender DID from JWT (server-provided)"
        },
        "receivedAt": { "type": "string", "format": "datetime" }
      }
    }
  }
}
```

---

## Part 2: Database Schema for Admin System

### Migration: `20251107_001_add_admin_system.sql`

**File:** `mls/server/migrations/20251107_001_add_admin_system.sql`

```sql
-- ===========================================================================
-- Admin System Schema
-- ===========================================================================

-- Add admin tracking to members
ALTER TABLE members 
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN promoted_at TIMESTAMPTZ,
    ADD COLUMN promoted_by_did TEXT;

CREATE INDEX idx_members_admins 
    ON members(convo_id, is_admin) 
    WHERE is_admin = true;

-- Set creator as admin for existing conversations
UPDATE members m
SET is_admin = true, 
    promoted_at = c.created_at,
    promoted_by_did = c.creator_did
FROM conversations c
WHERE m.convo_id = c.id 
  AND m.member_did = c.creator_did
  AND m.left_at IS NULL;

-- ===========================================================================
-- Admin Actions Audit Log
-- ===========================================================================

CREATE TABLE admin_actions (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    actor_did TEXT NOT NULL,        -- Who performed the action
    action TEXT NOT NULL,            -- 'promote', 'demote', 'remove'
    target_did TEXT,                 -- Who it was applied to
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_admin_actions_convo 
    ON admin_actions(convo_id, created_at DESC);
CREATE INDEX idx_admin_actions_actor 
    ON admin_actions(actor_did, created_at DESC);
CREATE INDEX idx_admin_actions_target 
    ON admin_actions(target_did) 
    WHERE target_did IS NOT NULL;

-- ===========================================================================
-- End-to-End Encrypted Reports
-- ===========================================================================

CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    reporter_did TEXT NOT NULL,
    reported_did TEXT NOT NULL,
    encrypted_content BYTEA NOT NULL,   -- E2EE blob only admins can decrypt
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'resolved', 'dismissed')),
    resolved_by_did TEXT,
    resolved_at TIMESTAMPTZ,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_reports_convo_pending 
    ON reports(convo_id, status) 
    WHERE status = 'pending';
CREATE INDEX idx_reports_reporter 
    ON reports(reporter_did, created_at DESC);
CREATE INDEX idx_reports_reported 
    ON reports(reported_did, created_at DESC);
```

---

## Part 3: Server Authorization Helpers

### File: `mls/server/src/auth.rs` (add to bottom)

```rust
use crate::storage::DbPool;
use sqlx;

/// Check if a DID is a member of a conversation
pub async fn require_member(
    pool: &DbPool, 
    convo_id: &str, 
    did: &str
) -> Result<(), StatusCode> {
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM members 
            WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        )"
    )
    .bind(convo_id)
    .bind(did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// Check if a DID is an admin of a conversation
pub async fn require_admin(
    pool: &DbPool, 
    convo_id: &str, 
    did: &str
) -> Result<(), StatusCode> {
    require_member(pool, convo_id, did).await?;
    
    let is_admin: bool = sqlx::query_scalar(
        "SELECT is_admin FROM members 
         WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL"
    )
    .bind(convo_id)
    .bind(did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check admin status: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    if !is_admin {
        tracing::warn!(
            "Admin action denied: {} is not admin of {}",
            did, convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// Check if a DID can demote another admin (must be admin, or demoting self)
pub async fn require_can_demote(
    pool: &DbPool,
    convo_id: &str,
    actor_did: &str,
    target_did: &str,
) -> Result<(), StatusCode> {
    // Allow self-demotion
    if actor_did == target_did {
        require_member(pool, convo_id, actor_did).await?;
        return Ok(());
    }
    
    // Otherwise must be admin
    require_admin(pool, convo_id, actor_did).await
}

/// Count current admins (to prevent removing last admin)
pub async fn count_admins(
    pool: &DbPool,
    convo_id: &str,
) -> Result<i64, StatusCode> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM members 
         WHERE convo_id = $1 AND is_admin = true AND left_at IS NULL"
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count admins: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
```

---

## Part 4: Lexicon Definitions

### 1. Update `blue.catbird.mls.defs.json`

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

### 2. Update `blue.catbird.mls.message.defs.json`

Add admin roster and control message support:

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
      "text": { 
        "type": "string", 
        "maxLength": 10000,
        "description": "Message text (for messageType: text)"
      },
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
    "required": ["version", "admins"],
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

### 3. New Lexicon: `blue.catbird.mls.promoteAdmin.json`

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
            "convoId": { "type": "string" },
            "targetDid": { 
              "type": "string", 
              "format": "did",
              "description": "DID of member to promote" 
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["ok", "promotedAt"],
          "properties": {
            "ok": { "type": "boolean" },
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

### 4. New Lexicon: `blue.catbird.mls.demoteAdmin.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.demoteAdmin",
  "description": "Demote an admin to regular member",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid"],
          "properties": {
            "convoId": { "type": "string" },
            "targetDid": { "type": "string", "format": "did" }
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
        { "name": "NotAdmin", "description": "Caller is not an admin (unless self-demote)" },
        { "name": "NotMember", "description": "Target is not a member" },
        { "name": "NotAdminTarget", "description": "Target is not an admin" },
        { "name": "LastAdmin", "description": "Cannot demote last admin" }
      ]
    }
  }
}
```

### 5. New Lexicon: `blue.catbird.mls.removeMember.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.removeMember",
  "description": "Remove (kick) a member from conversation (admin-only)",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "targetDid", "idempotencyKey"],
          "properties": {
            "convoId": { "type": "string" },
            "targetDid": { "type": "string", "format": "did" },
            "idempotencyKey": {
              "type": "string",
              "description": "Client-generated ULID for idempotent kicks"
            },
            "reason": {
              "type": "string",
              "maxLength": 500
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["ok", "epochHint"],
          "properties": {
            "ok": { "type": "boolean" },
            "epochHint": {
              "type": "integer",
              "description": "Server's current observed epoch"
            }
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

### 6. New Lexicon: `blue.catbird.mls.reportMember.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.reportMember",
  "description": "Report a member for moderation (E2EE)",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "reportedDid", "encryptedContent"],
          "properties": {
            "convoId": { "type": "string" },
            "reportedDid": { "type": "string", "format": "did" },
            "encryptedContent": {
              "type": "bytes",
              "description": "Encrypted report blob (reason, context, evidence) only admins can decrypt",
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

### 7. New Lexicon: `blue.catbird.mls.getReports.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.getReports",
  "description": "Get reports for a conversation (admin-only)",
  "defs": {
    "main": {
      "type": "query",
      "parameters": {
        "type": "params",
        "required": ["convoId"],
        "properties": {
          "convoId": { "type": "string" },
          "status": {
            "type": "string",
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
        "encryptedContent": { "type": "bytes" },
        "createdAt": { "type": "string", "format": "datetime" },
        "status": { "type": "string" },
        "resolvedBy": { "type": "string", "format": "did" },
        "resolvedAt": { "type": "string", "format": "datetime" }
      }
    }
  }
}
```

### 8. New Lexicon: `blue.catbird.mls.resolveReport.json`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.resolveReport",
  "description": "Resolve a report with an action (admin-only)",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["reportId", "action"],
          "properties": {
            "reportId": { "type": "string" },
            "action": {
              "type": "string",
              "knownValues": ["removed_member", "dismissed", "no_action"]
            },
            "notes": {
              "type": "string",
              "maxLength": 1000
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
        { "name": "NotAdmin" },
        { "name": "ReportNotFound" },
        { "name": "AlreadyResolved" }
      ]
    }
  }
}
```

---

## Part 5: Implementation Checklist

### Phase 1: Fix Sender Identity (4 hours)

- [ ] Update `create_message()` signature with privacy fields
- [ ] Remove `create_message_v2()` function
- [ ] Remove `create_message_with_idempotency()` function
- [ ] Update `send_message` handler to call new `create_message()`
- [ ] Update `SendMessageOutput` model (add `sender` field)
- [ ] Update `sendMessage` lexicon output
- [ ] Test: Verify sender is stored correctly
- [ ] Test: Verify old NULL messages don't exist
- [ ] Deploy to dev

### Phase 2: Admin Schema (2 hours)

- [ ] Create migration `20251107_001_add_admin_system.sql`
- [ ] Run migration on dev database
- [ ] Verify creators are auto-promoted to admin
- [ ] Test: Query admin status
- [ ] Add helper functions to `auth.rs`

### Phase 3: Create Lexicons (2 hours)

- [ ] Update `blue.catbird.mls.defs.json`
- [ ] Update `blue.catbird.mls.message.defs.json`
- [ ] Create `blue.catbird.mls.promoteAdmin.json`
- [ ] Create `blue.catbird.mls.demoteAdmin.json`
- [ ] Create `blue.catbird.mls.removeMember.json`
- [ ] Create `blue.catbird.mls.reportMember.json`
- [ ] Create `blue.catbird.mls.getReports.json`
- [ ] Create `blue.catbird.mls.resolveReport.json`
- [ ] Copy all to `Petrel/Generator/lexicons/blue/catbird/mls/`

### Phase 4: Server Handlers (3-4 days)

- [ ] Implement `promote_admin` handler
- [ ] Implement `demote_admin` handler
- [ ] Implement `remove_member` handler
- [ ] Implement `report_member` handler
- [ ] Implement `get_reports` handler
- [ ] Implement `resolve_report` handler
- [ ] Update `get_convos` to include `isAdmin` flag
- [ ] Add SSE events for admin changes
- [ ] Test all endpoints

### Phase 5: Petrel Client (1 day)

- [ ] Run Petrel generator
- [ ] Verify generated Swift types
- [ ] Add admin service protocol
- [ ] Test Petrel client compilation

### Phase 6: Catbird App (1 week)

- [ ] Implement `AdminRoster` model
- [ ] Update `MLSConversationManager` with admin roster tracking
- [ ] Process admin roster messages
- [ ] Process admin action messages
- [ ] Verify admin actions cryptographically
- [ ] Implement admin UI (badges, member list)
- [ ] Implement promote/demote flows
- [ ] Implement remove member flow
- [ ] Implement report member UI
- [ ] Implement admin reports dashboard

---

## Part 6: Testing Strategy

### Unit Tests

**File:** `mls/server/tests/admin_tests.rs`

```rust
#[tokio::test]
async fn test_promote_admin() {
    // Creator promotes alice
    // Verify DB updated
    // Verify audit log
}

#[tokio::test]
async fn test_non_admin_cannot_promote() {
    // Alice tries to promote bob
    // Should return 403
}

#[tokio::test]
async fn test_cannot_demote_last_admin() {
    // Try to demote sole admin
    // Should return error
}

#[tokio::test]
async fn test_self_demotion_allowed() {
    // Admin demotes self (if not last)
    // Should succeed
}

#[tokio::test]
async fn test_admin_can_remove_member() {
    // Admin removes non-admin
    // Should succeed
}
```

### Integration Tests

1. **Full admin flow:**
   - Create conversation (creator is admin)
   - Promote alice
   - Alice promotes bob
   - Bob removes charlie
   - Verify audit log

2. **Reporting flow:**
   - Member reports bad actor
   - Admin sees encrypted report
   - Admin resolves (removes member)
   - Verify report status

---

## Part 7: Security Audit

### Attack Vectors Mitigated

✅ **Sender spoofing** - JWT-only sender identity  
✅ **Non-admin privilege escalation** - Server authorization checks  
✅ **Compromised server forging admin** - Client-side roster verification  
✅ **Replay attacks** - jti cache + idempotency keys  
✅ **Report visibility** - E2EE blobs only admins decrypt  
✅ **Audit trail tampering** - Immutable `admin_actions` log  

### Remaining Considerations

⚠️ **Single admin risk** - Need bootstrap recovery if sole admin loses key  
⚠️ **Roster drift** - Clients must sync roster before applying actions  
⚠️ **Rate limiting** - Implement per-DID rate limits on admin actions  

---

## Part 8: Timeline

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| 1. Fix Sender | 4 hours | Day 1 | Day 1 |
| 2. Admin Schema | 2 hours | Day 1 | Day 1 |
| 3. Lexicons | 2 hours | Day 1 | Day 1 |
| 4. Server Handlers | 3-4 days | Day 2 | Day 5 |
| 5. Petrel Client | 1 day | Day 6 | Day 6 |
| 6. Catbird App | 5-7 days | Day 7 | Day 13 |

**Total: ~2 weeks**

---

## Part 9: Next Steps

**Immediate (Today):**
1. Fix sender identity bug (Phase 1)
2. Create admin migration (Phase 2)
3. Create all lexicons (Phase 3)

**This Week:**
4. Implement server handlers (Phase 4)
5. Generate Petrel client (Phase 5)

**Next Week:**
6. Integrate into Catbird app (Phase 6)
7. Full testing and deployment

---

## Questions?

Ready to start? I can:
1. **Make the code changes for Phase 1-3 right now**
2. **Generate all 6 new lexicon files**
3. **Create the migration SQL**
4. **Write server handler stubs**

Just let me know which you'd like me to tackle first!

# v1 Text-Only Group Chat Implementation Checklist

## Goal
Ship a working text-only group chat with:
- ✅ MLS E2EE encryption
- ✅ ATProto DIDs for identity
- ✅ Text messages only (no media uploads)
- ✅ Tenor GIF URLs (metadata only)
- ✅ Link previews (metadata only)
- ✅ Bluesky embed AT-URIs (metadata only)
- ✅ Real-time delivery via SSE
- ✅ Works iOS + Android (client-agnostic server)

---

## Phase 1: Simplify Server (Remove R2)

### Step 1: Clean up files
```bash
# Delete R2-related files
rm server/src/blob_storage.rs
rm setup_r2.sh
rm R2_QUICKSTART.txt

# Archive for future reference
mkdir -p docs/future
mv R2_SETUP.md docs/future/
mv CLOUDFLARE_R2_MIGRATION_SUMMARY.md docs/future/
mv CLOUDKIT_MLS_ARCHITECTURE.md docs/future/
```

- [ ] Delete `server/src/blob_storage.rs`
- [ ] Delete `setup_r2.sh`
- [ ] Delete `R2_QUICKSTART.txt`
- [ ] Move R2/CloudKit docs to `docs/future/`

### Step 2: Update Cargo.toml
```toml
# Remove these lines:
# aws-sdk-s3 = "1.52"
# aws-config = "1.5"
# aws-credential-types = "1.2"
```

- [ ] Remove AWS SDK dependencies from `server/Cargo.toml`
- [ ] Run `cargo update`

### Step 3: Update server/src/lib.rs
```rust
// Remove:
// mod blob_storage;
// pub use blob_storage::*;
```

- [ ] Remove blob_storage imports from `lib.rs`
- [ ] Ensure it compiles: `cargo check`

---

## Phase 2: Database Schema

### Step 4: Create migration

Create `server/migrations/YYYYMMDD_HHMMSS_simplify_messages.sql`:

```sql
-- Drop old R2-based tables if they exist
DROP TABLE IF EXISTS message_recipients;
DROP TABLE IF EXISTS messages CASCADE;

-- Messages (server stores ciphertext)
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'app',
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    ciphertext BYTEA NOT NULL,
    content_type TEXT DEFAULT 'text/plain',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    
    -- Embed metadata (optional, for previews)
    embed_type TEXT,
    embed_uri TEXT,
    
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_messages_convo_seq ON messages(convo_id, seq);
CREATE INDEX idx_messages_expires ON messages(expires_at);

-- Delivery tracking
CREATE TABLE message_delivery (
    message_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    delivered_at TIMESTAMPTZ DEFAULT NOW(),
    read_at TIMESTAMPTZ,
    
    PRIMARY KEY (message_id, recipient_did),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX idx_delivery_recipient ON message_delivery(recipient_did, delivered_at);
```

- [ ] Create migration file
- [ ] Run migration: `sqlx migrate run`
- [ ] Verify schema: `psql $DATABASE_URL -c '\d messages'`

---

## Phase 3: Update Server Handlers

### Step 5: Update sendMessage handler

File: `server/src/generated_api/blue/catbird/mls/send_message.rs`

```rust
use crate::{auth::JwtClaims, db, models::*, realtime::RealtimeState};
use axum::{extract::State, Json};
use anyhow::Result;

pub async fn send_message(
    State(state): State<AppState>,
    claims: JwtClaims,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, ApiError> {
    // 1. Verify membership
    db::require_member(&state.pool, &claims.sub, &input.convo_id).await?;
    
    // 2. Get conversation and check we're not out of sync
    let convo = db::get_conversation(&state.pool, &input.convo_id).await?;
    
    // 3. Insert message
    let message = db::create_message(
        &state.pool,
        &input.convo_id,
        &claims.sub,
        &input.ciphertext,
        input.content_type.as_deref().unwrap_or("text/plain"),
        input.embed.as_ref(),
        convo.current_epoch,
    ).await?;
    
    // 4. Broadcast to online members via SSE
    state.realtime.broadcast_message(&message).await;
    
    // 5. Return message view
    Ok(Json(SendMessageOutput {
        message: MessageView {
            id: message.id,
            convo_id: message.convo_id,
            sender: message.sender_did,
            epoch: message.epoch,
            seq: message.seq,
            created_at: message.created_at,
            // Ciphertext not included in response (fetch separately)
        }
    }))
}
```

- [ ] Update `send_message.rs` handler
- [ ] Update `models.rs` with new `SendMessageInput` struct
- [ ] Test with curl

### Step 6: Update getMessages handler

File: `server/src/generated_api/blue/catbird/mls/get_messages.rs`

```rust
pub async fn get_messages(
    State(state): State<AppState>,
    claims: JwtClaims,
    Query(input): Query<GetMessagesInput>,
) -> Result<Json<GetMessagesOutput>, ApiError> {
    // 1. Verify membership
    db::require_member(&state.pool, &claims.sub, &input.convo_id).await?;
    
    // 2. Fetch messages
    let messages = db::list_messages(
        &state.pool,
        &input.convo_id,
        input.cursor.as_deref(),
        input.limit.unwrap_or(50).min(100),
    ).await?;
    
    // 3. Mark as delivered (async, don't block response)
    for msg in &messages {
        let _ = db::mark_delivered(&state.pool, &msg.id, &claims.sub).await;
    }
    
    // 4. Return messages with ciphertext
    Ok(Json(GetMessagesOutput {
        messages: messages.into_iter().map(|m| MessageView {
            id: m.id,
            convo_id: m.convo_id,
            sender: m.sender_did,
            ciphertext: Some(m.ciphertext),  // Include for decryption
            epoch: m.epoch,
            seq: m.seq,
            created_at: m.created_at,
            content_type: m.content_type,
            embed: m.embed_uri.map(|uri| EmbedRef {
                embed_type: m.embed_type.unwrap_or_default(),
                uri,
            }),
        }).collect(),
        cursor: messages.last().map(|m| m.id.clone()),
    }))
}
```

- [ ] Update `get_messages.rs` handler
- [ ] Update `MessageView` to include optional `ciphertext` field
- [ ] Test with curl

### Step 7: Add database helpers

File: `server/src/db.rs`

```rust
/// Create a new message
pub async fn create_message(
    pool: &PgPool,
    convo_id: &str,
    sender_did: &str,
    ciphertext: &[u8],
    content_type: &str,
    embed: Option<&EmbedRef>,
    epoch: i32,
) -> Result<Message> {
    let id = ulid::Ulid::new().to_string();
    
    // Get next sequence number
    let seq: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE convo_id = $1"
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await?;
    
    let (embed_type, embed_uri) = match embed {
        Some(e) => (Some(e.embed_type.as_str()), Some(e.uri.as_str())),
        None => (None, None),
    };
    
    let message = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, ciphertext, content_type,
            epoch, seq, embed_type, embed_uri
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#
    )
    .bind(&id)
    .bind(convo_id)
    .bind(sender_did)
    .bind(ciphertext)
    .bind(content_type)
    .bind(epoch)
    .bind(seq)
    .bind(embed_type)
    .bind(embed_uri)
    .fetch_one(pool)
    .await?;
    
    // Track delivery for all members
    let members = list_members(pool, convo_id, 1000, 0).await?;
    for member in members {
        if member.left_at.is_none() {
            sqlx::query(
                "INSERT INTO message_delivery (message_id, recipient_did) VALUES ($1, $2)"
            )
            .bind(&id)
            .bind(&member.member_did)
            .execute(pool)
            .await?;
        }
    }
    
    Ok(message)
}

/// List messages for a conversation
pub async fn list_messages(
    pool: &PgPool,
    convo_id: &str,
    cursor: Option<&str>,
    limit: i32,
) -> Result<Vec<Message>> {
    let mut query = String::from(
        "SELECT * FROM messages WHERE convo_id = $1"
    );
    
    if let Some(cursor_id) = cursor {
        query.push_str(" AND id > $2");
    }
    
    query.push_str(" ORDER BY seq ASC LIMIT $3");
    
    let messages = if let Some(cursor_id) = cursor {
        sqlx::query_as::<_, Message>(&query)
            .bind(convo_id)
            .bind(cursor_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query_as::<_, Message>(&query)
            .bind(convo_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
    };
    
    Ok(messages)
}

/// Mark message as delivered to a recipient
pub async fn mark_delivered(
    pool: &PgPool,
    message_id: &str,
    recipient_did: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE message_delivery SET delivered_at = NOW() 
         WHERE message_id = $1 AND recipient_did = $2 AND delivered_at IS NULL"
    )
    .bind(message_id)
    .bind(recipient_did)
    .execute(pool)
    .await?;
    
    Ok(())
}
```

- [ ] Add database helper functions to `db.rs`
- [ ] Update `models.rs` with `Message` struct
- [ ] Test database operations

---

## Phase 4: Wire Up Real-time (SSE)

### Step 8: Update SSE broadcasting

File: `server/src/realtime/sse.rs`

```rust
impl RealtimeState {
    pub async fn broadcast_message(&self, message: &Message) {
        let event = json!({
            "type": "message",
            "convoId": message.convo_id,
            "messageId": message.id,
            "timestamp": message.created_at,
        });
        
        // Send to all subscribers of this conversation
        self.send_to_convo(&message.convo_id, &event).await;
    }
    
    async fn send_to_convo(&self, convo_id: &str, event: &serde_json::Value) {
        let subscribers = self.subscribers.read().await;
        for (did, tx) in subscribers.iter() {
            // TODO: Check if DID is member of convo
            if self.is_member(did, convo_id).await {
                let _ = tx.send(Event::default().json_data(event).unwrap()).await;
            }
        }
    }
}
```

- [ ] Update SSE broadcasting logic
- [ ] Test with multiple connected clients
- [ ] Verify events are received

---

## Phase 5: Update Lexicon Handling

### Step 9: Make externalAsset optional

Current lexicon has `payload` as required `externalAsset`. For v1, server accepts ciphertext directly.

**Option A**: Keep lexicon as-is, server ignores it (clients send dummy externalAsset)
**Option B**: Update lexicon to make payload optional, add ciphertext field

**Recommendation**: Option A for speed (lexicon is already published). Update in v2.

```json
// Client sends (temporary v1 format):
{
  "convoId": "...",
  "payload": {
    "provider": "server",
    "uri": "internal://will-be-generated",
    "mimeType": "application/octet-stream",
    "size": 0,
    "sha256": ""
  },
  "ciphertext": "base64..." // Extra field, server uses this
}
```

- [ ] Document temporary ciphertext field in API docs
- [ ] Plan lexicon update for v2

---

## Phase 6: Testing

### Step 10: Local testing

```bash
# Start server
cd server
cargo run

# In another terminal, test API
# 1. Publish key packages
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.publishKeyPackage \
  -H "Authorization: Bearer $ALICE_JWT" \
  -d '{"keyPackage":"...","cipherSuite":"...","expiresAt":"..."}'

# 2. Create conversation
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.createConvo \
  -H "Authorization: Bearer $ALICE_JWT" \
  -d '{"invites":["did:plc:bob"]}'

# 3. Send message
curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.sendMessage \
  -H "Authorization: Bearer $ALICE_JWT" \
  -d '{"convoId":"...","ciphertext":"base64..."}'

# 4. Get messages
curl http://localhost:3000/xrpc/blue.catbird.mls.getMessages?convoId=... \
  -H "Authorization: Bearer $ALICE_JWT"

# 5. Subscribe to events (SSE)
curl -N http://localhost:3000/xrpc/blue.catbird.mls.subscribeConvoEvents?convoId=... \
  -H "Authorization: Bearer $ALICE_JWT"
```

- [ ] Test key package flow
- [ ] Test conversation creation
- [ ] Test message send/receive
- [ ] Test SSE event delivery
- [ ] Test with 2-3 clients simultaneously

### Step 11: iOS integration test

```swift
// Update MLSClient to send ciphertext directly
func sendMessage(
    convoId: String,
    ciphertext: Data,
    contentType: String = "text/plain",
    embed: EmbedRef? = nil
) async throws -> MessageView {
    var request = URLRequest(url: baseURL.appendingPathComponent("/xrpc/blue.catbird.mls.sendMessage"))
    request.httpMethod = "POST"
    request.setValue("Bearer \(authToken)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    
    let payload = [
        "convoId": convoId,
        "ciphertext": ciphertext.base64EncodedString(),
        "contentType": contentType,
        // Temporary: dummy externalAsset for lexicon compliance
        "payload": [
            "provider": "server",
            "uri": "internal://pending",
            "mimeType": "application/octet-stream",
            "size": ciphertext.count,
            "sha256": Data() // Empty for now
        ]
    ] as [String: Any]
    
    request.httpBody = try JSONSerialization.data(withJSONObject: payload)
    
    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONDecoder().decode(MessageView.self, from: data)
}
```

- [ ] Update iOS client MLSClient
- [ ] Test send message from iOS
- [ ] Test receive message on iOS
- [ ] Test SSE subscription

---

## Phase 7: Cleanup & Documentation

### Step 12: Update documentation

- [ ] Update `README.md` to reflect simplified architecture
- [ ] Document the temporary ciphertext field
- [ ] Add API examples
- [ ] Update `TESTING_GUIDE.md`

### Step 13: Archive unnecessary docs

```bash
mkdir -p docs/future
mv CLOUDKIT_MLS_ARCHITECTURE.md docs/future/
mv CLOUDFLARE_R2_MIGRATION_SUMMARY.md docs/future/
mv MLS_STORAGE_CHECKLIST.md docs/future/
mv MLS_STORAGE_IMPLEMENTATION.md docs/future/
```

- [ ] Move future architecture docs to `docs/future/`
- [ ] Keep only current implementation docs

---

## Phase 8: Deploy

### Step 14: Deploy to production

```bash
# Build release
cd server
cargo build --release

# Run migrations on production DB
DATABASE_URL=postgresql://... sqlx migrate run

# Deploy (e.g., fly.io)
fly deploy
```

- [ ] Run migrations on production
- [ ] Deploy server
- [ ] Test with production endpoints
- [ ] Monitor logs for errors

---

## Success Criteria

✅ Alice can create a group with Bob and Charlie
✅ Alice sends "Hello!" → Bob and Charlie receive it encrypted
✅ Bob decrypts and sees "Hello!"
✅ Messages appear in real-time (< 1 second latency)
✅ Works on iOS (primary platform)
✅ Server stores ciphertext only (no plaintext)
✅ Costs < $5/month for 100 users

---

## What's NOT in v1

❌ Media uploads (images, videos, files)
❌ CloudKit backup
❌ R2 blob storage
❌ Voice messages
❌ Read receipts
❌ Typing indicators
❌ Message reactions (can add in v1.1)

---

## What to Add in v2

📦 Media uploads → R2 blob storage + `uploadBlob` endpoint
📦 CloudKit personal backup (iOS clients sync to iCloud)
📦 Message reactions (just metadata, no schema change)
📦 Read receipts (already have delivery tracking)
📦 Typing indicators (via SSE)

---

## Timeline Estimate

- **Day 1**: Steps 1-4 (cleanup + schema)
- **Day 2**: Steps 5-7 (handlers + db)
- **Day 3**: Steps 8-9 (SSE + lexicon)
- **Day 4**: Steps 10-11 (testing)
- **Day 5**: Steps 12-14 (docs + deploy)

**Total: 1 week to ship v1** 🚀

---

## Need Help?

Stuck on a step? Ask for:
- Code examples
- Database query help
- Testing strategies
- Deployment guidance

Let's ship this! 🎉

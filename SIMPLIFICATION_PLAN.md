# MLS Server Simplification Plan (v1 Text-Only)

## Problem
Mixed CloudKit client-storage model with R2 server-storage model. Added complexity not needed for text-only v1.

## Solution
**Server-as-mailbox pattern**: Store encrypted messages in PostgreSQL, auto-delete after 30 days.

---

## Changes Needed

### 1. Remove R2 Dependency

**Files to remove:**
- `server/src/blob_storage.rs` (delete)
- `setup_r2.sh` (delete)
- `R2_SETUP.md` (archive to `docs/future/`)
- `R2_QUICKSTART.txt` (delete)

**Files to modify:**
- `server/Cargo.toml`: Remove AWS SDK dependencies
- `server/src/lib.rs`: Remove blob_storage import
- `.env.example`: Remove R2 variables

### 2. Simplify Lexicon Usage

**Keep the lexicon as-is** (it's well-designed for future), but make `externalAsset` **optional**.

Current `sendMessage` requires:
```json
{
  "payload": { "type": "ref", "ref": "externalAsset" }
}
```

Change server implementation to accept **either**:
- `externalAsset` pointer (future: client-uploaded to CloudKit/Drive)
- `ciphertext` bytes directly (v1: server stores)

### 3. Database Schema (Simple)

```sql
-- Migration: 20251023_simplify_messages.sql

-- Messages table (server-stored ciphertext)
CREATE TABLE messages (
    id TEXT PRIMARY KEY,                    -- ULID
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'app',  -- 'app' | 'commit'
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    ciphertext BYTEA NOT NULL,             -- MLS encrypted payload
    content_type TEXT DEFAULT 'text/plain',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    
    -- Optional embed metadata (for UI preview before decrypt)
    embed_type TEXT,                        -- 'tenor' | 'link' | 'bsky_post'
    embed_uri TEXT,                         -- URL or AT-URI
    
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX idx_messages_convo_seq ON messages(convo_id, seq);
CREATE INDEX idx_messages_expires ON messages(expires_at);

-- Delivery tracking (who has fetched what)
CREATE TABLE message_delivery (
    message_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    
    PRIMARY KEY (message_id, recipient_did),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Cleanup job (run daily)
CREATE INDEX idx_messages_cleanup ON messages(expires_at) WHERE expires_at < NOW();
```

### 4. Server API (XRPC)

**`blue.catbird.mls.sendMessage`**

```rust
// Accept ciphertext directly (v1)
pub struct SendMessageInput {
    pub convo_id: String,
    pub ciphertext: Vec<u8>,              // MLS encrypted
    pub content_type: Option<String>,      // Default: "text/plain"
    pub embed: Option<EmbedRef>,           // Optional: Tenor/link/bsky
}

pub struct EmbedRef {
    pub embed_type: String,  // "tenor" | "link" | "bsky_post"
    pub uri: String,          // URL or AT-URI
}

// Handler
pub async fn send_message(
    State(state): State<AppState>,
    claims: JwtClaims,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<MessageView>> {
    // 1. Verify membership
    db::require_member(&state.pool, &claims.sub, &input.convo_id).await?;
    
    // 2. Check epoch
    let convo = db::get_conversation(&state.pool, &input.convo_id).await?;
    
    // 3. Store message
    let message = db::create_message(
        &state.pool,
        &input.convo_id,
        &claims.sub,
        &input.ciphertext,
        input.content_type.as_deref(),
        input.embed.as_ref(),
    ).await?;
    
    // 4. Fan out via SSE to online members
    state.realtime.broadcast_message(&message).await;
    
    // 5. Return message view
    Ok(Json(MessageView {
        id: message.id,
        convo_id: message.convo_id,
        sender: message.sender_did,
        epoch: message.epoch,
        seq: message.seq,
        created_at: message.created_at,
        // Note: ciphertext not returned (recipients fetch separately)
    }))
}
```

**`blue.catbird.mls.getMessages`**

```rust
pub struct GetMessagesInput {
    pub convo_id: String,
    pub cursor: Option<String>,  // ULID cursor
    pub limit: Option<i32>,       // Default: 50, max: 100
}

pub async fn get_messages(
    State(state): State<AppState>,
    claims: JwtClaims,
    Query(input): Query<GetMessagesInput>,
) -> Result<Json<GetMessagesOutput>> {
    // 1. Verify membership
    db::require_member(&state.pool, &claims.sub, &input.convo_id).await?;
    
    // 2. Fetch messages
    let messages = db::list_messages(
        &state.pool,
        &input.convo_id,
        input.cursor.as_deref(),
        input.limit.unwrap_or(50),
    ).await?;
    
    // 3. Mark as delivered
    for msg in &messages {
        db::mark_delivered(&state.pool, &msg.id, &claims.sub).await?;
    }
    
    Ok(Json(GetMessagesOutput {
        messages: messages.into_iter().map(|m| MessageView {
            id: m.id,
            convo_id: m.convo_id,
            sender: m.sender_did,
            ciphertext: m.ciphertext,  // Include ciphertext for decrypt
            epoch: m.epoch,
            seq: m.seq,
            created_at: m.created_at,
            embed: m.embed_uri.map(|uri| EmbedRef {
                embed_type: m.embed_type.unwrap(),
                uri,
            }),
        }).collect(),
        cursor: messages.last().map(|m| m.id.clone()),
    }))
}
```

### 5. Real-time Delivery (SSE)

Already have `server/src/realtime/sse.rs`. Just wire it up:

```rust
// When message sent, broadcast event:
pub async fn broadcast_message(&self, message: &Message) {
    let event = ConvoEvent {
        type_: "message".into(),
        convo_id: message.convo_id.clone(),
        message_id: Some(message.id.clone()),
        timestamp: message.created_at,
    };
    
    // Send to all online members
    self.send_to_convo(&message.convo_id, &event).await;
}
```

Clients subscribe via:
```
GET /xrpc/blue.catbird.mls.subscribeConvoEvents?convoId=xyz
```

### 6. Client Flow (iOS)

```swift
// Send message
func sendMessage(text: String, in convoId: String) async throws {
    // 1. Encrypt with MLS
    let plaintext = text.data(using: .utf8)!
    let ciphertext = try mlsManager.encrypt(session: session, plaintext: plaintext)
    
    // 2. Send to server
    let message = try await mlsClient.sendMessage(
        convoId: convoId,
        ciphertext: ciphertext,
        contentType: "text/plain",
        embed: nil  // For Tenor: EmbedRef(type: "tenor", uri: gifUrl)
    )
    
    // 3. Save locally
    await storage.saveMessage(message)
}

// Receive messages (SSE)
let eventSource = EventSource(url: subscribeURL)
eventSource.onMessage { event in
    if event.type == "message" {
        // Fetch new message
        let messages = await mlsClient.getMessages(convoId: event.convoId, cursor: lastCursor)
        
        // Decrypt
        for msg in messages {
            let plaintext = try mlsManager.decrypt(session, msg.ciphertext)
            await storage.saveDecrypted(msg.id, String(data: plaintext, encoding: .utf8)!)
        }
    }
}
```

---

## Benefits

1. **Simple**: No CloudKit complexity, no R2 setup, just PostgreSQL
2. **Cross-platform**: Works iOS + Android from day 1
3. **Fast to ship**: Remove code instead of adding it
4. **Cheap**: 7.5GB/month fits in your VPS
5. **E2EE intact**: Server only sees ciphertext
6. **Scalable**: Add R2/CloudKit later when you add media

---

## Migration Path

**From current state:**

1. **Remove R2 files** (see list above)
2. **Update Cargo.toml** (remove aws-sdk-s3)
3. **Run new migration** (create simplified messages table)
4. **Update handlers** (sendMessage, getMessages)
5. **Test with 2-3 member group**
6. **Ship v1**

**Later (v2, when adding media):**

1. Add `uploadBlob` endpoint → R2 storage
2. Support `externalAsset` in `sendMessage.attachments[]`
3. iOS clients can backup to CloudKit privately
4. Lexicon already supports this (no changes needed)

---

## Files to Edit

### Delete
- `server/src/blob_storage.rs`
- `setup_r2.sh`
- `R2_QUICKSTART.txt`

### Modify
- `server/Cargo.toml`: Remove AWS deps
- `server/src/lib.rs`: Remove blob_storage
- `server/src/db.rs`: Add message CRUD
- `server/src/generated_api/blue/catbird/mls/send_message.rs`: Update handler
- `server/src/generated_api/blue/catbird/mls/get_messages.rs`: Update handler
- `server/migrations/`: Add new migration

### Keep
- All lexicon files (they're future-proof)
- `CLOUDKIT_MLS_ARCHITECTURE.md` (move to `docs/future/`)
- Real-time SSE infrastructure
- Auth, middleware, metrics

---

## Timeline

- **Day 1**: Remove R2, update schema
- **Day 2**: Update handlers, wire SSE
- **Day 3**: Test, deploy
- **Week 1**: Ship v1

---

## Questions?

1. **"What about CloudKit?"**  
   → Optional client feature later. For v1, server stores everything.

2. **"What about the lexicon's externalAsset?"**  
   → Keep it! Just make server accept ciphertext directly for now.

3. **"What about Android?"**  
   → Works immediately (server is storage, clients just encrypt/decrypt).

4. **"What about costs?"**  
   → PostgreSQL storage is cheap. 7.5GB/month << 20GB budget.

5. **"What about attachments?"**  
   → V1: Tenor GIFs are just URLs (no upload).  
   → V2: Add R2 + `uploadBlob` endpoint.

---

Ship it! 🚀

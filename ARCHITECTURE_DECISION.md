# Architecture Decision: v1 Text-Only Group Chat

## TL;DR

**Don't revert. Simplify instead.**

Remove R2 complexity, store encrypted messages in PostgreSQL, ship v1 fast.

---

## The Confusion

You have three architectural patterns mixed together:

1. **CloudKit per-user storage** (commit 50adc80) - iOS-only, complex
2. **R2 server storage** (commit 9a387f2) - Cross-platform, but overkill for text
3. **Lexicon with externalAsset** - Future-proof, but requires client uploads

For **text-only v1** with Tenor GIFs (URLs), you don't need any of this complexity.

---

## The Right Answer for v1

### What You're Building

- **Text messages**: ~1-5KB encrypted per message
- **Tenor GIFs**: Just URLs (no upload needed)
- **Links**: Just URLs (no upload needed)
- **Bluesky embeds**: Just AT-URIs (no upload needed)

### What You Need

**Server-as-mailbox pattern**:
- Client encrypts message with MLS
- Client sends ciphertext to server
- Server stores in PostgreSQL (cheap for small data)
- Server fans out to recipients via SSE
- Recipients fetch, decrypt, display
- Messages auto-delete after 30 days

### Why This Works

1. **Text is tiny**: 7.5GB/month for 1000 active users fits in your VPS
2. **Cross-platform**: No iOS/Android split
3. **Simple**: No CloudKit auth, no R2 setup, no presigned URLs
4. **Fast**: Ship this week instead of next month
5. **E2EE intact**: Server only sees ciphertext
6. **Scalable**: Add R2/CloudKit later for media

---

## What To Change

### Remove (unnecessary for v1)

- `server/src/blob_storage.rs` (R2 integration)
- AWS SDK dependencies
- CloudKit complexity
- `externalAsset` requirement

### Keep (working and needed)

- Lexicon definitions (they're future-proof)
- Server auth/XRPC/SSE infrastructure
- MLS FFI integration
- Database migrations

### Add (simple v1 implementation)

```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,  -- MLS encrypted, ~1-5KB
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    
    -- Optional metadata for Tenor/links/embeds
    embed_type TEXT,
    embed_uri TEXT,
    
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);
```

---

## API Flow (v1)

### Send Message

```
POST /xrpc/blue.catbird.mls.sendMessage
{
  "convoId": "01HXYZ...",
  "ciphertext": "base64_encrypted_mls_payload",
  "contentType": "text/plain",
  "embed": {
    "embedType": "tenor",
    "uri": "https://media.tenor.com/xyz.gif"
  }
}
```

Server:
1. Verifies sender is a member
2. Stores ciphertext in PostgreSQL
3. Broadcasts SSE event to online members
4. Returns message ID + metadata

### Receive Message

```
GET /xrpc/blue.catbird.mls.getMessages?convoId=01HXYZ...&cursor=01HXYZ...
```

Server returns:
```json
{
  "messages": [
    {
      "id": "01HXYZ...",
      "sender": "did:plc:alice",
      "ciphertext": "base64...",
      "epoch": 5,
      "seq": 42,
      "createdAt": "2024-10-23T...",
      "embed": {
        "embedType": "tenor",
        "uri": "https://media.tenor.com/xyz.gif"
      }
    }
  ],
  "cursor": "01HXYZ..."
}
```

Client decrypts `ciphertext` with MLS.

### Real-time Delivery

```
GET /xrpc/blue.catbird.mls.subscribeConvoEvents?convoId=01HXYZ...
```

SSE stream:
```
event: message
data: {"type":"message","convoId":"01HXYZ...","messageId":"01HXYZ...","timestamp":"..."}
```

Client fetches new message, decrypts, displays.

---

## Costs (v1 vs alternatives)

### Your v1 (PostgreSQL)
- 1000 users × 50 msgs/day × 5KB × 30 days = 7.5GB/month
- Cost: **$0** (fits in VPS)

### If You Used R2
- Same 7.5GB
- Cost: **$0.11/month** (within free tier, but unnecessary setup)

### If You Used CloudKit
- Requires iCloud for all users
- Cost: **$0** (but iOS-only, complex)

**Winner: PostgreSQL** (simple, free, cross-platform)

---

## Migration Path

### Now (v1)
✅ PostgreSQL storage
✅ Text messages only
✅ Tenor/link embeds (URLs)
✅ Real-time SSE

### Later (v2)
📦 Add `uploadBlob` endpoint
📦 Store media in R2
📦 Support `attachments[]` in lexicon
📦 Optional CloudKit backup for iOS

Your lexicon already supports this (no breaking changes).

---

## Timeline

| Day | Tasks |
|-----|-------|
| 1 | Remove R2, update schema |
| 2 | Update handlers (send/get messages) |
| 3 | Wire SSE, test locally |
| 4 | iOS integration |
| 5 | Deploy, monitor |

**Ship v1 in 1 week.** 🚀

---

## FAQs

### "Should I revert to an earlier commit?"

**No.** Your lexicons are good. Just remove the R2 code and simplify the implementation.

### "What about CloudKit?"

CloudKit is for **iOS client backup** (optional, v2). Server doesn't touch it.

### "What about the externalAsset type in the lexicon?"

Keep it! It's future-proof. For v1, server accepts ciphertext directly. Update lexicon in v2 when you add media.

### "Will this scale?"

Yes. PostgreSQL handles TB-scale data. When you hit 10GB, add R2. You'll know when.

### "What about Android?"

Works immediately. Server is storage-agnostic; clients just encrypt/decrypt.

### "What about the 20GB budget?"

You'll use ~7.5GB for 1000 users. Plenty of headroom.

### "Can I add media later?"

Yes! Add `uploadBlob` → R2, update `sendMessage` to accept `attachments[]`. No schema changes needed.

---

## Next Steps

1. **Read**: `SIMPLIFICATION_PLAN.md` (architecture details)
2. **Follow**: `V1_IMPLEMENTATION_CHECKLIST.md` (step-by-step)
3. **Ship**: v1 this week
4. **Celebrate**: You built federated E2EE chat! 🎉

---

## Bottom Line

| Choice | Complexity | Cost | Platform | Ship Time |
|--------|-----------|------|----------|-----------|
| **PostgreSQL** (v1) | ⭐ Simple | 💰 Free | 🌍 All | 🚀 1 week |
| CloudKit | ⭐⭐⭐ Complex | 💰 Free | 🍎 iOS only | 📅 3-4 weeks |
| R2 | ⭐⭐ Medium | 💰 $0.11 | 🌍 All | 📅 2 weeks |

**Choose PostgreSQL.** Ship fast, add complexity later.

---

Got questions? Need code examples? Just ask! 🤝

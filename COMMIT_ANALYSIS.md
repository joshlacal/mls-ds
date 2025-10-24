# Commit History Analysis

## What I Found

### Commit Timeline

```
013bc3c  Initial commit: Catbird MLS MVP project structure
    ↓
c52bfec  Complete MLS integration with FFI, server, and comprehensive documentation
    ↓
b1d1bbd  Configure MLS server as AT Protocol service at mls.catbird.blue
    ↓
9921b89  Production-ready: Add database migrations and comprehensive documentation
    ↓
a0e6747  update lexicons
    ↓
ff4ac9e  Update server to match lexicon changes
    ↓
81ea21b  Fix lexicons for ATProto best practices and atrium-codegen compatibility
    ↓
50adc80  Introduce CloudKit/external-asset storage model ⚠️
    ↓
9a387f2  feat: Add Cloudflare R2 blob storage integration ⚠️
    ↓
HEAD     (current state)
```

---

## The Problem

### Commit 50adc80: "CloudKit/external-asset storage model"

**What it added**:
- `externalAsset` type in lexicons
- Documentation about CloudKit CKShare
- Per-user mailbox fan-out model
- ULID cursors for pagination
- SSE real-time events

**Design philosophy**:
> Client owns storage (CloudKit), server just routes pointers

**Problems**:
- iOS-only (CloudKit requires iCloud)
- Complex: CKShare, zones, subscriptions
- Server needs CloudKit Web Services auth to write to user zones
- Contradicts "no Apple credentials on server"

### Commit 9a387f2: "Cloudflare R2 blob storage integration"

**What it added**:
- `server/src/blob_storage.rs`
- R2 client (AWS SDK)
- Presigned upload/download URLs
- Migration for R2-based message storage
- `R2_SETUP.md` documentation

**Design philosophy**:
> Server owns storage (R2), clients just upload/download

**Problems**:
- Unnecessary for text-only messages
- Added AWS SDK dependency (4+ crates)
- Costs money (tiny, but not needed)
- Overkill: optimized for large blobs, not 5KB text messages

---

## The Confusion

You have **two contradictory patterns**:

| Aspect | CloudKit Model (50adc80) | R2 Model (9a387f2) |
|--------|-------------------------|-------------------|
| Storage owner | Client | Server |
| Platform | iOS-only | Cross-platform |
| Cost | Free (iCloud) | ~$0.11/month |
| Complexity | High (zones, shares) | Medium (AWS SDK) |
| Best for | Personal backup | Large media files |

Neither is right for **text-only v1 with cross-platform support**.

---

## What Each Commit Got Right

### 50adc80 (CloudKit)

✅ **Good ideas**:
- `externalAsset` abstraction (provider-agnostic)
- ULID cursors for pagination
- SSE real-time events
- Fan-out logic

❌ **Wrong for v1**:
- CloudKit complexity
- iOS-only
- Server writing to user zones (not viable)

### 9a387f2 (R2)

✅ **Good ideas**:
- Cross-platform storage
- Blob lifecycle (auto-delete)
- Presigned URLs (reduces server bandwidth)

❌ **Wrong for v1**:
- Overkill for text messages
- Unnecessary AWS SDK
- Added complexity

---

## What To Keep from Each

### From 50adc80 (CloudKit commit)

**Keep**:
- ✅ `externalAsset` lexicon type (future-proof)
- ✅ ULID cursors
- ✅ SSE real-time infrastructure (`server/src/realtime/`)
- ✅ Fan-out logic concept

**Discard**:
- ❌ CloudKit-specific implementation
- ❌ CKShare documentation (move to `docs/future/`)
- ❌ Per-user zone complexity

### From 9a387f2 (R2 commit)

**Keep**:
- ✅ Message lifecycle concept (30-day auto-delete)
- ✅ Delivery tracking table structure

**Discard**:
- ❌ `server/src/blob_storage.rs`
- ❌ AWS SDK dependencies
- ❌ R2 setup scripts

---

## The Right Synthesis (for v1)

Take the **best ideas** from both, simplify:

```
From CloudKit:           From R2:              New (simple):
- externalAsset type  +  - Auto-delete      =  PostgreSQL storage
- SSE real-time          - Delivery tracking   - BYTEA ciphertext
- ULID cursors                                 - 30-day TTL
- Fan-out logic                                - Cross-platform
```

Result:
```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,           -- ULID (from 50adc80)
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,     -- Simple storage (new)
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days',  -- From 9a387f2
    embed_type TEXT,
    embed_uri TEXT
);
```

---

## Why Not Revert?

### Option 1: Revert to 50adc80 (CloudKit)
❌ Loses R2 delivery tracking improvements
❌ Still have CloudKit complexity
❌ Still iOS-only

### Option 2: Revert to c52bfec (before storage changes)
❌ Loses SSE real-time
❌ Loses ULID cursors
❌ Loses lexicon improvements

### Option 3: Stay at HEAD, simplify (RECOMMENDED)
✅ Keep all good ideas (SSE, ULID, lexicons)
✅ Remove complexity (CloudKit, R2)
✅ Ship v1 fast

---

## Lexicon Status

### Current Lexicon (9a387f2)

```json
// blue.catbird.mls.sendMessage
{
  "input": {
    "convoId": "string",
    "payload": { "type": "ref", "ref": "externalAsset" },  // ⚠️ Required
    "attachments": [...]
  }
}

// blue.catbird.mls.defs#externalAsset
{
  "provider": "cloudkit | firestore | gdrive | s3 | custom",
  "uri": "...",
  "mimeType": "...",
  "size": 123,
  "sha256": "..."
}
```

**Problem**: Requires `externalAsset`, but v1 sends ciphertext directly.

**Solution (temporary)**: Server accepts extra `ciphertext` field, ignores `payload`.

**Solution (v2)**: Update lexicon to make `payload` optional, add `ciphertext` field.

---

## Database Schema Evolution

### Initial (c52bfec)
```sql
-- Simple, ciphertext in DB
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    convo_id UUID NOT NULL,
    ciphertext BYTEA NOT NULL
);
```

### After CloudKit (50adc80)
```sql
-- External storage, just metadata
CREATE TABLE messages (
    id TEXT PRIMARY KEY,  -- ULID
    convo_id TEXT NOT NULL,
    -- No ciphertext column!
    cloudkit_zone_id TEXT,
    cloudkit_record_name TEXT
);
```

### After R2 (9a387f2)
```sql
-- R2 blob reference
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    blob_key TEXT NOT NULL,  -- R2 object key
    -- Still no ciphertext!
);
```

### Proposed v1
```sql
-- Back to simple, but with improvements
CREATE TABLE messages (
    id TEXT PRIMARY KEY,           -- ULID (kept from 50adc80)
    convo_id TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,     -- Back to inline storage
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days',  -- From 9a387f2
    embed_type TEXT,               -- New: Tenor/link support
    embed_uri TEXT
);
```

---

## Cost Comparison (1000 users, 50 msgs/day)

| Model | Storage | Monthly Cost | Setup Time |
|-------|---------|-------------|-----------|
| **Initial (c52bfec)** | PostgreSQL | $0 | ✅ 1 day |
| **CloudKit (50adc80)** | iCloud | $0 | ⚠️ 2 weeks |
| **R2 (9a387f2)** | Cloudflare | $0.11 | ⚠️ 3 days |
| **Proposed v1** | PostgreSQL | $0 | ✅ 1 week |

---

## Summary

### What Happened

1. Started simple (PostgreSQL)
2. Added CloudKit (iOS-only complexity)
3. Added R2 (cross-platform, but overkill)
4. Now confused (two storage models)

### What To Do

1. Keep lexicons (they're good)
2. Keep SSE/ULID infrastructure (it's good)
3. Remove CloudKit complexity
4. Remove R2 complexity
5. Return to PostgreSQL storage (but improved)
6. Ship v1

### Timeline

- **If you revert**: 1-2 weeks to re-implement SSE, lexicons
- **If you simplify**: 3-5 days to remove R2, update handlers

**Simplification is faster.** ✅

---

## Next Steps

1. Read `ARCHITECTURE_DECISION.md` (why PostgreSQL)
2. Follow `V1_IMPLEMENTATION_CHECKLIST.md` (how to simplify)
3. Start with Phase 1: Remove R2

You've done great work on lexicons and infrastructure. Now just remove the unnecessary complexity and ship! 🚀

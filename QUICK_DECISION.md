# Quick Decision: What To Do Right Now

## Your Question
> Do we revert to a past commit or restructure?

## Answer
**Restructure. Don't revert.**

---

## Why You're Confused

You have 3 different architectures mixed in your codebase:

```
Commit 50adc80: CloudKit client storage (iOS-only, complex)
    ↓
Commit 9a387f2: R2 server storage (cross-platform, overkill)
    ↓
Current state: ???
```

---

## What You Actually Need (for text-only v1)

```
┌─────────────────────────────────────────┐
│          iOS/Android Client              │
│  ┌────────────┐      ┌────────────┐     │
│  │ MLS Crypto │      │ Local DB   │     │
│  └─────┬──────┘      └────────────┘     │
│        │ encrypt/decrypt                 │
└────────┼─────────────────────────────────┘
         │ HTTPS + JWT
         ▼
┌─────────────────────────────────────────┐
│           MLS Server                     │
│  • Auth (DIDs)                          │
│  • Fan-out (SSE)                        │
│  • Storage (PostgreSQL)                 │
│    └─ ciphertext BYTEA (~5KB/msg)      │
└─────────────────────────────────────────┘

No CloudKit. No R2. Just PostgreSQL.
```

---

## What To Remove

```bash
# Delete these files:
rm server/src/blob_storage.rs
rm setup_r2.sh
rm R2_QUICKSTART.txt

# Archive these:
mv CLOUDKIT_MLS_ARCHITECTURE.md docs/future/
mv CLOUDFLARE_R2_MIGRATION_SUMMARY.md docs/future/

# Update:
# - server/Cargo.toml (remove AWS deps)
# - server/src/lib.rs (remove blob_storage)
```

---

## What To Add

```sql
-- Simple messages table
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,  -- This is all you need!
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days',
    
    -- Optional: Tenor GIF / link metadata
    embed_type TEXT,  -- 'tenor' | 'link' | 'bsky_post'
    embed_uri TEXT    -- URL or AT-URI
);
```

---

## Timeline

| Day | Task | Output |
|-----|------|--------|
| 1 | Remove R2, update schema | ✅ Database ready |
| 2 | Update send/get handlers | ✅ API working |
| 3 | Wire SSE, test | ✅ Real-time delivery |
| 4 | iOS integration | ✅ App sends/receives |
| 5 | Deploy | ✅ v1 shipped! |

**1 week to ship.** 🚀

---

## Costs

### v1 (PostgreSQL)
- 1000 users = 7.5GB/month
- Cost: **$0** (fits in VPS)

### What you DON'T need
- ❌ R2: $0.11/month (free tier, but unnecessary setup)
- ❌ CloudKit: iOS-only, complex auth
- ❌ S3: $1.59/month (68x more expensive)

---

## Next Steps

1. **Read**: `ARCHITECTURE_DECISION.md` (why this is right)
2. **Follow**: `V1_IMPLEMENTATION_CHECKLIST.md` (step-by-step)
3. **Execute**: Start with "Phase 1: Simplify Server"

---

## The One-Sentence Summary

> Store encrypted messages in PostgreSQL, deliver via SSE, ship text-only v1 this week, add media + R2 later.

---

## Still Unsure?

Ask yourself:
- ✅ Do I need text-only chat working this week? → PostgreSQL
- ❌ Do I need 1GB+ media uploads in v1? → Maybe R2
- ❌ Do I need iOS-only iCloud sync in v1? → Maybe CloudKit

For your scope (text + Tenor URLs), **PostgreSQL is the answer**.

---

Start here: `V1_IMPLEMENTATION_CHECKLIST.md` → Phase 1 → Step 1

Let's ship it! 🎉

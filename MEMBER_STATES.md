# Member States in Catbird MLS

## Overview

The Catbird MLS server distinguishes between **social membership** (who's in the group) and **cryptographic sync** (whose devices have valid MLS state).

## Three Member States

### 1. Active & In Sync ✅
```sql
left_at IS NULL AND needs_rejoin = false
```

**What it means:**
- Member is in the group (social decision)
- Device has valid MLS group state (crypto synced)
- Can send/receive messages normally

**How to get here:**
- Initial join via Welcome message
- Successful external commit after being out of sync

---

### 2. Active but Out of Sync ⚠️
```sql
left_at IS NULL AND needs_rejoin = true
```

**What it means:**
- Member is still in the group (social decision)
- Device lost MLS state (app reinstall, storage wipe, etc.)
- Cannot decrypt messages until resynced

**How to get here:**
- App reinstall/data wipe
- Keychain loss
- Multiple epoch misses while offline
- Client detects crypto desync

**How to fix:**
- Client calls `getGroupInfo` → `processExternalCommit`
- Server clears `needs_rejoin` flag
- Client can now decrypt new messages

**Authorization:**
- ✅ Can call `getGroupInfo`
- ✅ Can call `processExternalCommit`
- ✅ Can call `getCommits` to catch up

---

### 3. Removed/Left ❌
```sql
left_at IS NOT NULL
```

**What it means:**
- Member is no longer in the group (social decision)
- Left voluntarily OR removed by admin
- This is a policy/social decision, not a crypto issue

**How to get here:**
- User calls `leaveConvo`
- Admin calls `removeMember`
- Ban/kick action

**How to fix:**
- Cannot self-rejoin via external commit
- Must request admin to re-add them
- Admin uses `addMembers` to bring them back

**Authorization:**
- ❌ CANNOT call `getGroupInfo` (rejected)
- ❌ CANNOT call `processExternalCommit` (rejected)
- ❌ CANNOT access group messages

---

## Why This Matters

**Security:** Prevents removed members from sneaking back in via external commits.

**UX:** Allows legitimate members to resync after app reinstall without admin intervention.

**Clarity:** Separates social decisions (who's in) from technical issues (sync problems).

## Implementation

### Authorization Check Pattern

```rust
// Check membership status
let member = sqlx::query!(
    "SELECT left_at, needs_rejoin FROM members
     WHERE convo_id = $1 AND user_did = $2",
    convo_id, user_did
).fetch_one(&pool).await?;

// Reject if removed/left (social decision)
if member.left_at.is_some() {
    return Err(Error::Unauthorized(
        "Member was removed or left. Request re-add from admin."
    ));
}

// Allow if in group (even if out of sync)
// External commits are for fixing crypto desync, not social membership
```

### After Successful External Commit

```rust
sqlx::query!(
    "UPDATE members
     SET needs_rejoin = false,
         rejoin_requested_at = NULL,
         rejoin_key_package_hash = NULL
     WHERE convo_id = $1 AND user_did = $2",
    convo_id, user_did
).execute(&pool).await?;
```

## Future: Automatic Sync Detection

Clients could automatically set `needs_rejoin = true` by calling an endpoint when they detect:
- Missing epochs they can't catch up on
- `SecretReuseError` or other crypto failures
- Local state corruption

This would enable server-side monitoring and proactive user support.

## Related Files

- `server/src/handlers/process_external_commit.rs` - External commit processing
- `server/src/handlers/get_group_info.rs` - GroupInfo retrieval
- `server/schema_greenfield.sql` - Database schema

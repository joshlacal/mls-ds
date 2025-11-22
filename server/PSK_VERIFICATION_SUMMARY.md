# PSK Verification Implementation Summary

## Overview

This document describes the PSK (Pre-Shared Key) verification system added to the external commit handler for both invite-based joins and rejoin flows.

## Files Modified

1. **`/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/src/handlers/process_external_commit.rs`**
   - Complete rewrite with PSK verification logic
   - Added support for both rejoin and new join flows
   - Integrated with conversation policy system

2. **`/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/src/error.rs`** (NEW)
   - Created shared error types module
   - Defines common errors: DatabaseError, ValidationError, NotFound, Unauthorized, PolicyViolation

3. **`/Users/joshlacalamito/Developer/Catbird+Petrel/mls/server/src/lib.rs`**
   - Added `pub mod error;` export
   - Added `pub mod admin_system;` export (needed by handlers)

## Architecture

### Request Structure

The `InputData` struct now includes an optional `psk` field:

```rust
pub struct InputData {
    pub convo_id: String,
    pub external_commit: String,
    pub idempotency_key: Option<String>,
    pub group_info: Option<String>,
    pub psk: Option<String>,  // NEW: Client-provided PSK for verification
}
```

**Note**: In production, the PSK should ideally be extracted from the MLS external commit's PreSharedKey proposal. For now, we accept it as a separate parameter to simplify implementation.

### Processing Flow

The handler follows a 7-step process:

#### Step 1: Fetch Conversation Policy

```sql
SELECT allow_external_commits, require_invite_for_join,
       allow_rejoin, rejoin_window_days
FROM conversation_policy
WHERE convo_id = $1
```

**Master Switch**: If `allow_external_commits = false`, reject immediately.

#### Step 2: Check Member Status

```sql
SELECT left_at, needs_rejoin, member_did, user_did,
       rejoin_psk_hash, joined_at
FROM members
WHERE convo_id = $1 AND user_did = $2
ORDER BY joined_at DESC
LIMIT 1
```

Determines whether this is:
- **Rejoin flow**: Member exists, `left_at IS NULL`
- **New join flow**: Member doesn't exist
- **Unauthorized**: Member exists with `left_at IS NOT NULL` (removed/left)

#### Step 3: Authorization Logic

##### Rejoin Flow (Existing Member)

1. **Policy Check**: Verify `allow_rejoin = true`
2. **Window Check**: If `rejoin_window_days > 0`, ensure current time < `joined_at + rejoin_window_days`
3. **Crypto Authorization**: Verify rejoin PSK
   - Hash provided PSK: `SHA256(psk)`
   - Compare with `member.rejoin_psk_hash`
   - Backwards compatibility: Allow rejoin if no PSK stored (legacy members)

##### New Join Flow (Non-Member)

1. **Policy Check**: If `require_invite_for_join = true`, PSK required
2. **Crypto Authorization**: Verify invite PSK
   - Hash provided PSK: `SHA256(psk)`
   - Use `is_invite_valid(pool, psk_hash, target_did)` helper
   - Check invite not expired, not revoked, has remaining uses
   - Verify target_did matches if invite is targeted

#### Step 4: Validate MLS Commit Structure

- Decode base64-encoded commit
- Parse with OpenMLS: `MlsMessageIn::tls_deserialize()`

#### Step 5: Store Commit & Update State

Transaction includes:
- Insert message into `messages` table
- Update conversation epoch
- Update GroupInfo (if provided)

#### Step 6: Update Member State

**Rejoin**: Clear rejoin flags
```sql
UPDATE members
SET needs_rejoin = false,
    rejoin_requested_at = NULL,
    rejoin_key_package_hash = NULL
WHERE convo_id = $1 AND user_did = $2
```

**New Join**: Increment invite uses
```sql
UPDATE invites
SET uses_count = uses_count + 1
WHERE id = $1
```

#### Step 7: Fanout

Async task:
- Create envelopes for all active members
- Emit SSE event for real-time delivery

## Security Model

### Database Compromise Protection

The system uses SHA256 hashing to protect against database compromise:

1. **Client generates PSK**: 256-bit random value
2. **Client hashes PSK**: `SHA256(PSK)` → 64-char hex string
3. **Server stores hash**: Only the hash is stored in DB
4. **Client provides plaintext PSK**: On external commit
5. **Server verifies**: `SHA256(provided_PSK) == stored_hash`

**Attack resistance**:
- Even if database is compromised, attacker cannot derive PSK from hash
- PSK proves "I was a member" (rejoin) or "I have valid invite" (new join)
- DID proves identity (AT Protocol authentication)

### Policy Enforcement

The system respects conversation-level policies:

| Policy | Effect |
|--------|--------|
| `allow_external_commits` | Master switch - if false, all external commits rejected |
| `require_invite_for_join` | If true, new members must provide valid invite PSK |
| `allow_rejoin` | If true, existing members can rejoin after desync |
| `rejoin_window_days` | Time limit for rejoin (0 = unlimited) |

### Error Handling

New error types added to `Error` enum:

```rust
pub enum Error {
    Unauthorized(Option<String>),      // 403: Not a member or removed
    InvalidCommit(Option<String>),     // 400: Malformed MLS message
    InvalidGroupInfo(Option<String>),  // 400: Malformed GroupInfo
    InvalidPsk(Option<String>),        // 403: PSK verification failed
    PolicyViolation(Option<String>),   // 403: Policy prevents this action
}
```

## Integration with Existing Systems

### Helper Functions from `create_invite.rs`

The handler uses two public helpers:

```rust
pub async fn is_invite_valid(
    pool: &PgPool,
    psk_hash: &str,
    target_did: Option<&str>,
) -> Result<Option<String>, Error>
```

Checks:
- Invite exists for given PSK hash
- Not revoked
- Not expired
- Has remaining uses (if `max_uses` set)
- Target DID matches (if targeted invite)

Returns: `Option<invite_id>` if valid

```rust
pub async fn increment_invite_uses(
    pool: &PgPool,
    invite_id: &str,
) -> Result<(), Error>
```

Atomically increments `uses_count` in transaction.

## Backwards Compatibility

### Legacy Members (No Rejoin PSK)

Members who joined before the PSK system was implemented have `rejoin_psk_hash = NULL`. The system:

1. Detects null PSK hash
2. Logs warning: "No rejoin PSK stored for {did} - allowing rejoin for backwards compatibility"
3. Allows rejoin without PSK verification

**Production Recommendation**:
- Require PSK update flow for legacy members
- Set policy to enforce PSK after grace period

## Database Schema Dependencies

The implementation requires these tables/columns (from migration `20250122000000_admin_invite_rejoin.sql`):

### `conversation_policy` table
```sql
CREATE TABLE conversation_policy (
    convo_id TEXT PRIMARY KEY,
    allow_external_commits BOOLEAN NOT NULL DEFAULT true,
    require_invite_for_join BOOLEAN NOT NULL DEFAULT false,
    allow_rejoin BOOLEAN NOT NULL DEFAULT true,
    rejoin_window_days INTEGER NOT NULL DEFAULT 30,
    prevent_removing_last_admin BOOLEAN NOT NULL DEFAULT true,
    ...
);
```

### `invites` table
```sql
CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    psk_hash TEXT NOT NULL,  -- SHA256 hash (64 hex chars)
    target_did TEXT,          -- NULL = open invite
    expires_at TIMESTAMPTZ,   -- NULL = never expires
    max_uses INTEGER,         -- NULL = unlimited
    uses_count INTEGER NOT NULL DEFAULT 0,
    revoked BOOLEAN NOT NULL DEFAULT false,
    ...
);
```

### `members.rejoin_psk_hash` column
```sql
ALTER TABLE members ADD COLUMN IF NOT EXISTS rejoin_psk_hash TEXT;
```

## Testing Recommendations

### Unit Tests

1. **PSK Hashing**:
   - Verify `hash_psk()` produces correct SHA256 hex output
   - Test empty string, special characters, unicode

2. **Policy Enforcement**:
   - Test master switch (`allow_external_commits = false`)
   - Test invite requirement (`require_invite_for_join = true`)
   - Test rejoin disabled (`allow_rejoin = false`)
   - Test window expiry

3. **PSK Verification**:
   - Valid PSK (match)
   - Invalid PSK (mismatch)
   - Missing PSK when required
   - Legacy member (null PSK)

### Integration Tests

1. **Rejoin Flow**:
   - Member with valid PSK rejoins successfully
   - Member with invalid PSK rejected
   - Member outside window rejected
   - Legacy member allowed without PSK

2. **New Join Flow**:
   - Non-member with valid invite joins
   - Non-member with expired invite rejected
   - Non-member with max-uses exceeded rejected
   - Non-member with wrong target_did rejected
   - Open join when `require_invite_for_join = false`

3. **Atomicity**:
   - Invite uses incremented only on success
   - Transaction rollback on validation failure
   - No partial state updates

## Future Improvements

1. **Extract PSK from MLS Message**:
   - Parse external commit proposals
   - Extract PreSharedKey proposal
   - Verify PSK is embedded in MLS layer (not just request body)

2. **Rate Limiting**:
   - Limit failed PSK attempts per DID/IP
   - Prevent brute force attacks

3. **Audit Logging**:
   - Log all PSK verification attempts
   - Track failed verification patterns
   - Alert on suspicious activity

4. **Legacy Member Migration**:
   - Add endpoint to update rejoin PSK
   - Enforce PSK requirement after grace period
   - Notify legacy members to update

5. **Invite Analytics**:
   - Track invite usage patterns
   - Alert on abnormal usage
   - Provide admin dashboard

## Dependencies

The implementation uses these crates:

- `sha2`: SHA256 hashing
- `hex`: Hex encoding for PSK hashes
- `sqlx`: Database queries with compile-time checking
- `chrono`: Timestamp handling for window checks
- `uuid`: Generate unique IDs

Add to `Cargo.toml` if not present:
```toml
[dependencies]
sha2 = "0.10"
hex = "0.4"
```

## Error Codes & Client Handling

Clients should handle these HTTP responses:

| Status | Error | Client Action |
|--------|-------|---------------|
| 200 OK | - | Success, process commit |
| 400 Bad Request | InvalidCommit | Regenerate commit message |
| 400 Bad Request | InvalidGroupInfo | Regenerate GroupInfo |
| 403 Forbidden | Unauthorized | User removed, request re-add |
| 403 Forbidden | InvalidPsk | Check PSK, may need new invite |
| 403 Forbidden | PolicyViolation | Check policy, may need admin |
| 500 Internal Server Error | - | Retry with exponential backoff |

## Monitoring & Metrics

Recommended metrics to track:

1. **External Commit Rate**:
   - Total commits/hour
   - Rejoin vs new join ratio
   - Success vs failure rate

2. **PSK Verification**:
   - Valid vs invalid PSK rate
   - Failed verification by reason (expired, revoked, etc.)
   - Legacy member rejoin rate

3. **Policy Enforcement**:
   - Rejected by policy type
   - Window expiry rate
   - Open join vs invite-required ratio

4. **Performance**:
   - Average processing time
   - Database query latency
   - Transaction commit time

## Conclusion

The PSK verification system provides cryptographic proof of membership or invite authorization for external commits, preventing unauthorized joins while maintaining backwards compatibility with legacy members. The system integrates seamlessly with the existing conversation policy framework and provides robust error handling and security guarantees.

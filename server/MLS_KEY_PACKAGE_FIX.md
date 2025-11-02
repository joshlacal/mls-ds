# MLS Key Package Persistence Fix

## Problem Statement

Users were experiencing "NoMatchingKeyPackage" errors when trying to join conversations. This occurred when:

1. User A publishes key package #1
2. User B creates a conversation and adds User A (using key package #1)
3. User A publishes key package #2 (new device or rotation)
4. User A tries to join the conversation → **ERROR: NoMatchingKeyPackage**

### Root Cause

The Welcome message referenced key package #1, but when User A tried to join:
- The server only returned the NEWEST key package (#2) via `get_key_package()`
- User A's MLS storage couldn't find key package #1
- OpenMLS threw `NoMatchingKeyPackage` error

## Solution Implemented

### 1. Match Welcome Messages to Available Key Packages

**File:** `server/src/handlers/get_welcome.rs`

Changed the Welcome message query to:
- Check if the referenced key package hash still exists in the user's storage
- Only return Welcomes that have a matching, unconsumed key package
- Mark BOTH the Welcome and the key package as consumed atomically

```sql
SELECT wm.id, wm.welcome_data, wm.key_package_hash 
FROM welcome_messages wm
WHERE wm.convo_id = $1 AND wm.recipient_did = $2 AND wm.consumed = false
AND (
  wm.key_package_hash IS NULL
  OR EXISTS (
    SELECT 1 FROM key_packages kp
    WHERE kp.did = $2
    AND kp.key_package_hash = encode(wm.key_package_hash, 'hex')
    AND kp.consumed = false
    AND kp.expires_at > NOW()
  )
)
ORDER BY wm.created_at ASC
LIMIT 1
```

### 2. Consume Key Packages When Welcome is Retrieved

Added logic to mark the corresponding key package as consumed when a Welcome message is fetched:

```rust
// Mark the corresponding key package as consumed (if hash is present)
if let Some(ref hash_bytes) = key_package_hash_opt {
    let hash_hex = hex::encode(hash_bytes);
    info!("Marking key package as consumed: hash={}", hash_hex);
    
    sqlx::query(
        "UPDATE key_packages
         SET consumed = true, consumed_at = $1
         WHERE did = $2 AND key_package_hash = $3 AND consumed = false"
    )
    .bind(&now)
    .bind(did)
    .bind(&hash_hex)
    .execute(&mut *tx)
    .await?;
}
```

### 3. Return ALL Key Packages (Multi-Device Support)

**File:** `server/src/handlers/get_key_packages.rs`

Changed from `get_key_package()` (returns 1) to `get_all_key_packages()` (returns all unconsumed packages):

```rust
// Get ALL available key packages for this DID (multi-device support)
match crate::db::get_all_key_packages(&pool, did, suite).await {
    Ok(kps) if !kps.is_empty() => {
        info!("Found {} key package(s) for DID: {}", kps.len(), did);
        for kp in kps {
            results.push(KeyPackageInfo {
                did: kp.did,
                key_package: base64::engine::general_purpose::STANDARD.encode(kp.key_data),
                cipher_suite: kp.cipher_suite,
                key_package_hash: kp.key_package_hash,
            });
        }
    }
    ...
}
```

## Benefits

1. **No More NoMatchingKeyPackage Errors**: Users can join conversations even after publishing new key packages
2. **Multi-Device Support**: Multiple devices can join the same conversation (each with their own key package)
3. **Atomic Operations**: Welcome and key package consumption happens in a single transaction
4. **Key Package Lifecycle**: Proper tracking from creation → usage → consumption

## Database Schema (Already Correct)

The schema already supported this via:

```sql
CREATE TABLE key_packages (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    key_data BYTEA NOT NULL,
    key_package_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    UNIQUE (did, cipher_suite, key_data)
);

CREATE TABLE welcome_messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    welcome_data BYTEA NOT NULL,
    key_package_hash BYTEA,  -- Links Welcome to specific key package
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ,
    ...
);
```

## Testing

### Before Fix
```
User publishes key package A (hash: abc123)
Creator adds user to group (uses key package A)
User publishes key package B (hash: def456)
User fetches Welcome → ERROR: NoMatchingKeyPackage
```

### After Fix
```
User publishes key package A (hash: abc123)
Creator adds user to group (uses key package A)
User publishes key package B (hash: def456)
User fetches Welcome → SUCCESS (finds key package A is still available)
Key package A and Welcome both marked as consumed
```

## Deployment

1. Code changes are in:
   - `server/src/handlers/get_welcome.rs`
   - `server/src/handlers/get_key_packages.rs`

2. No database migration needed (schema already supports this)

3. Deploy steps:
   ```bash
   cd /home/ubuntu/mls/server
   docker compose down
   docker compose up -d --build
   ```

## Monitoring

Add metrics to track:
- `key_package_consumption_rate`: How often key packages are consumed
- `welcome_retrieval_failures`: Failed Welcome retrievals by reason
- `key_packages_per_user`: Distribution of how many key packages users maintain

## Future Enhancements

1. **Cleanup Job**: Remove expired/consumed key packages after 30 days
2. **Rate Limiting**: Limit how many key packages a user can publish per day
3. **Notification**: Alert users when their last key package is consumed

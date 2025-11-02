# Ciphertext Serialization Fix

**Date:** November 1, 2025
**Status:** ✅ Deployed

## Problem

Client was receiving a decoding error when fetching messages:
```
Failed to decode successful response for blue.catbird.mls.getMessages:
typeMismatch(Swift.Dictionary<String, Any>...Expected to decode Dictionary<String, Any>
but found a string instead
```

## Root Cause

The server was serializing the `ciphertext` field as a plain base64 string:
```json
{
  "messages": [{
    "ciphertext": "AAEAAhCD0ahyswd1FPjMyFjMfBqsAAA..."
  }]
}
```

But the client expected the AT Protocol `$bytes` format:
```json
{
  "messages": [{
    "ciphertext": {"$bytes": "AAEAAhCD0ahyswd1FPjMyFjMfBqsAAA..."}
  }]
}
```

## Solution

Updated `src/models.rs:247-259` to serialize bytes using the AT Protocol standard format:

```rust
pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Use STANDARD base64 for Swift compatibility
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);

    // Serialize as AT Protocol $bytes format: {"$bytes": "base64data"}
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("$bytes", &encoded)?;
    map.end()
}
```

## Deployment

1. Built release binary: `SQLX_OFFLINE=true cargo build --release`
2. Rebuilt Docker image: `docker build --no-cache -f Dockerfile.prebuilt -t server-mls-server .`
3. Restarted container: `docker restart catbird-mls-server`
4. Verified: Server healthy and running

## Testing

The `MessageView` struct now serializes `ciphertext` in the correct AT Protocol format for:
- `GET /xrpc/blue.catbird.mls.getMessages` - Fetch conversation messages
- Server-sent events (SSE) for realtime message delivery

## Impact

✅ **Fixed:** Message decoding error - clients can now properly decode messages
⚠️ **Ongoing:** NoMatchingKeyPackage error - requires client update to send `keyPackageHashes` parameter

## Related Files

- `src/models.rs` - MessageView serialization (lines 247-259)
- `src/handlers/get_messages.rs` - Uses MessageView
- `src/handlers/send_message.rs` - Stores messages returned as MessageView

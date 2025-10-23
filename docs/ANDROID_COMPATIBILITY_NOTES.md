# Android Compatibility Notes

This document describes how to interoperate with the iOS-first MLS messaging stack using the ExternalAsset pointer pattern. It maps storage providers to URI schemes, outlines integrity and auth, and provides a migration path from CloudKit-only rooms to cross-platform mailboxes.

## ExternalAsset Pointer Schema

All ciphertext payloads (message body and attachments) are referenced by an ExternalAsset pointer, not inlined bytes. The shape is consistent across platforms and providers.

```
provider   : string   // "cloudkit" | "firestore" | "gdrive" | "s3" | "custom"
uri        : string   // provider-specific URI (see below)
mimeType   : string   // MIME of ciphertext (e.g., application/octet-stream)
size       : int      // byte length of ciphertext
sha256     : bytes    // 32-byte digest of ciphertext
```

Clients MUST verify `size` and `sha256` after fetching the ciphertext and BEFORE decryption. This preserves MLS E2EE integrity invariants even when storage is untrusted.

## Provider URI Conventions

- `cloudkit://<container>/<db>/<zone>/<recordType>/<recordID>#asset=<assetKey>`
- `firestore://projects/<proj>/databases/(default)/documents/<collection>/<doc>`
- `gdrive://file/<fileId>`
- `s3://<bucket>/<key>` (accessed via time-limited signed URL from DS or via app credentials)
- `custom://...` (reserved for nonstandard providers; document separately)

Note: URIs identify the object; access may require a pre-signed URL or provider-specific auth.

## Recommended Android Providers

- Firestore + GCS (recommended):
  - Store ciphertext bytes in GCS; reference with `s3://`-like or custom `gcs://` if desired. Keep envelope/index in Firestore.
  - `externalAsset.provider = "firestore"`, `uri = firestore://...` pointing to a doc that contains a GCS path or a signed URL.

- Google Drive (OK for small/consumer cases):
  - `provider = "gdrive"`, `uri = gdrive://file/<id>`; Drive API permissions must allow all room participants to fetch. Expect higher latency vs GCS.

- S3-compatible (neutral/portable):
  - `provider = "s3"`, `uri = s3://bucket/key`; DS issues signed URLs per recipient or per-room policy.

## Auth and Access

- Prefer time-limited signed URLs for blob bytes. DS can mint these on demand per user, with scope limited to the object.
- For Firestore, use Firebase Auth (user identities) and security rules keyed by room membership.
- NEVER store plaintext server-side. DS only sees pointers and MLS envelopes.

## Sync Strategy (Mailbox Fan-out)

- DS fans out per-user message envelopes containing the ExternalAsset pointer.
- Android maintains a local index (Firestore collection) keyed by `roomId + messageId` with:
  - pointer (ExternalAsset), sender DID, epoch, createdAt, optional replyUri
  - per-user cursor/ack for resume (`subscribeConvoEvents` with `cursor`)
- Ensure idempotency: upserts on `messageId`; dedupe reactions.

## Integrity and Decryption Flow (Kotlin sketch)

```kotlin
suspend fun fetchCiphertext(asset: ExternalAsset): ByteArray {
  val bytes = when (asset.provider) {
    "s3" -> httpGetSignedUrl(resolveSignedUrl(asset.uri))
    "firestore" -> fetchViaFirestore(asset.uri)
    "gdrive" -> driveApiFetch(asset.uri)
    "cloudkit" -> fetchFromCloudKitBridge(asset.uri) // optional, for interop
    else -> throw IllegalArgumentException("Unsupported provider: ${asset.provider}")
  }
  require(bytes.size == asset.size) { "Size mismatch" }
  require(sha256(bytes).contentEquals(asset.sha256)) { "SHA-256 mismatch" }
  return bytes
}

suspend fun decryptAndRender(asset: ExternalAsset): PlaintextMessage {
  val ct = fetchCiphertext(asset)
  val pt = mlsDecrypt(ct) // MLS group context must be current
  return parsePlaintext(pt)
}
```

## Resumable Subscriptions

The subscription `blue.catbird.mls.subscribeConvoEvents` supports parameters `{ cursor?, convoId? }` and every event includes a `cursor`. Persist the last seen cursor per user and per conversation. On reconnect, pass that cursor to resume without gaps.

## Migration from CloudKit-only Rooms

1. Ensure messages already use ExternalAsset pointers with `provider="cloudkit"`.
2. Introduce dual-publish: write ciphertext to neutral storage (e.g., GCS/S3) and begin emitting pointers with `provider="s3"` (or `firestore`) while continuing CloudKit for iOS.
3. Flip DS delivery to mailbox fan-out for rooms approaching CKShare participant limits.
4. After all clients can fetch from the neutral provider, stop writing new CloudKit assets for that room.

No schema changes required; only `provider` and `uri` values change.

## Failure Modes

- Stale/invalid pointer → return retriable error; client backoff and request a fresh signed URL.
- Provider outage → surface `infoEvent` with degraded mode; queue sends locally.
- Integrity mismatch (`sha256`/`size`) → treat as fatal for that object; do not attempt decryption.
- Legal hold/redaction → DS updates envelopes to point to a tombstone object; clients render a redaction notice.

## Testing Checklist

- Verify end-to-end: send → DS fan-out → Android fetch → `sha256` match → MLS decrypt → render.
- Exercise each provider variant your app claims to support.
- Simulate resume with `cursor` across reconnects and network changes.
- Large attachments (near 50 MB) and multiple attachments (≤ 10) paths.
- Error injection: expired signed URL, 404 object, mismatched hash.

## Example Pointers

```json
{
  "provider": "s3",
  "uri": "s3://mls-payloads/rooms/abc123/messages/def456.bin",
  "mimeType": "application/octet-stream",
  "size": 13842,
  "sha256": "base64:Vb6p9v8m8kJm2b8k9V..." // 32 bytes
}
```

```json
{
  "provider": "firestore",
  "uri": "firestore://projects/myproj/databases/(default)/documents/rooms/abc123/messages/def456",
  "mimeType": "application/octet-stream",
  "size": 13842,
  "sha256": "base64:Vb6p9v8m8kJm2b8k9V..."
}
```

## Security Notes

- DS never handles plaintext; only pointers and minimal metadata.
- Use short-lived signed URLs and strict CORS rules for web.
- Validate `provider` against an allowlist server-side; reject unexpected schemes.
- Keep MLS epochs in sync; on `EpochMismatch`, client MUST update group state before decrypting.


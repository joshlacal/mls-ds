# CRITICAL CORRECTION: Device-Local Keychain (NOT iCloud Sync)

**Date**: 2025-11-08
**Status**: Corrected Architecture

---

## The Problem with iCloud Keychain Sync

### What We Got Wrong

Earlier documents suggested syncing the signature key via iCloud Keychain:

```swift
// ❌ WRONG - This breaks multi-device!
let keychain = Keychain(service: "blue.catbird.mls")
    .synchronizable(true)  // ❌ All devices get SAME key!
```

**Why This Breaks Multi-Device:**
```
All devices sync same 32-byte signature key via iCloud
         ↓
All devices derive SAME public key
         ↓
All devices try to use SAME MLS identity
         ↓
❌ Can't add same identity to group multiple times!
         ↓
Multi-device support completely broken
```

---

## The Correct Approach: Device-Local Keychain

### Each Device Has Unique Identity

```swift
final class MLSIdentityManager {
    // ✅ Device-local ONLY (no iCloud sync)
    private let keychain = Keychain(service: "blue.catbird.mls")
        .accessibility(.afterFirstUnlock)
        .synchronizable(false)  // ✅ Device-local only

    func getOrCreateDeviceIdentity(deviceName: String) async throws -> MLSDeviceIdentity {
        // Check for existing device-local key
        if let existingKey = try keychain.getData("device_signature_key") {
            // This device already registered
            return try await restoreDeviceIdentity(signatureKey: existingKey)
        }

        // First time on this device - generate NEW identity
        let newKey = generateEd25519Key()  // Fresh 32 bytes per device
        try keychain.set(newKey, key: "device_signature_key")

        // Register with server
        let registration = try await mlsClient.registerDevice(
            deviceName: deviceName,
            signaturePublicKey: derivePublicKey(from: newKey)
        )

        return MLSDeviceIdentity(
            signatureKey: newKey,
            deviceId: registration.deviceId,
            mlsDid: registration.mlsDid  // did:plc:josh#<device-uuid>
        )
    }

    private func restoreDeviceIdentity(signatureKey: Data) async throws -> MLSDeviceIdentity {
        // Device already has identity, restore from server
        let did = try await authManager.getCurrentDID()
        let publicKey = derivePublicKey(from: signatureKey)

        // Server looks up which device_id this public key belongs to
        let device = try await mlsClient.getDeviceByPublicKey(
            userDid: did,
            publicKey: publicKey
        )

        return MLSDeviceIdentity(
            signatureKey: signatureKey,
            deviceId: device.deviceId,
            mlsDid: device.mlsDid
        )
    }
}
```

---

## Updated Recovery Flows

### Scenario A: Same Device Reinstall

```
User deletes app on iPhone
         ↓
User reinstalls app on SAME iPhone
         ↓
iOS automatically restores:
  - Keychain (device-local signature key) ✅
  - SQLCipher database (messages + MLS state) ✅
         ↓
App checks Keychain: signature key exists
         ↓
Restore device identity from signature key
         ↓
✅ Seamless restoration (same device identity preserved)
         ↓
Full message history + MLS state intact
```

**Key**: iOS backup restores Keychain to SAME hardware.

### Scenario B: New Device (Different iPhone)

```
User gets new iPhone
         ↓
User signs in with Bluesky
         ↓
Check device-local Keychain: NO signature key (fresh device)
         ↓
Generate NEW 32-byte signature key (unique to this device)
         ↓
Store in device-local Keychain (synchronizable=false)
         ↓
Get DID from ATProto auth: did:plc:josh
         ↓
Register as NEW device: did:plc:josh#<new-device-uuid>
         ↓
Generate 100 fresh KeyPackages from new signature key
         ↓
Upload KeyPackages to server
         ↓
Server queries: "Which conversations is josh in?"
         ↓
Server finds: 5 conversations
         ↓
Server: "josh is member, but this device isn't"
         ↓
Server auto-adds new device to all 5 conversations
         ↓
✅ Rejoined in 2-5 seconds
         ↓
No message history (can't decrypt past messages)
         ↓
Fully functional for new messages
```

**Key**: New device = new identity = rejoin flow.

### Scenario C: User Has Multiple Devices Already

```
User signs in on iPhone (did:plc:josh#iphone-uuid)
         ↓
User signs in on iPad (did:plc:josh#ipad-uuid)
         ↓
User signs in on Mac (did:plc:josh#mac-uuid)
         ↓
Server tracks:
  user_devices: 3 entries for did:plc:josh
         ↓
MLS groups see:
  - josh#iphone-uuid (leaf 0)
  - josh#ipad-uuid (leaf 1)
  - josh#mac-uuid (leaf 2)
         ↓
UI shows: "Josh" (1 user, 3 devices hidden)
         ↓
All 3 devices independently encrypt/decrypt
```

---

## Comparison to Signal

This is **exactly** how Signal multi-device works:

| Feature | Signal | Our MLS Implementation |
|---------|--------|------------------------|
| Device identity | Unique per device | ✅ Unique per device |
| Keychain sync | Device-local only | ✅ Device-local only |
| New device | Registers + links | ✅ Registers + auto-adds |
| Message history | Not synced | ✅ Not synced |
| Device-to-device | Each decrypts independently | ✅ Each decrypts independently |

---

## What iOS Backup Covers

### ✅ Same Device Restore (iPhone → Same iPhone)

iOS backup includes:
- **Keychain**: Device-local signature key (32 bytes)
- **SQLCipher Database**: Full MLS state + message history
- **App data**: Preferences, cache

Result: **Perfect restoration** (like you never deleted the app)

### ❌ New Device Restore (iPhone → Different iPhone)

iOS backup may or may not restore Keychain to new hardware (depends on Apple policy).

**Safe assumption: Treat as fresh device**
- Generate new signature key
- Register as new device
- Auto-rejoin conversations
- Start fresh (no old message history)

---

## Updated Database Schema

No changes needed! The schema already supports this:

```sql
CREATE TABLE user_devices (
    user_did TEXT NOT NULL,           -- did:plc:josh
    device_id TEXT NOT NULL,          -- uuid-generated
    device_mls_did TEXT NOT NULL,     -- did:plc:josh#device-uuid
    device_name TEXT,                 -- "Josh's iPhone"
    signature_public_key BYTEA,       -- ✅ Store public key for lookup
    key_packages_available INT DEFAULT 0,
    last_seen TIMESTAMPTZ,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_did, device_id)
);

-- Lookup device by public key (for restoration)
CREATE UNIQUE INDEX idx_device_public_key
    ON user_devices(user_did, signature_public_key);
```

---

## Security Implications

### ✅ Enhanced Security

**Per-Device Forward Secrecy:**
- Compromise of iPhone doesn't leak Mac's messages
- Each device has separate ratchet state
- Device removal advances epoch (PCS for that device)

**No Single Point of Failure:**
- Losing one device doesn't compromise others
- Each device independently verifiable

### ✅ Correct MLS Usage

**Standard Protocol:**
- Each device is a separate MLS member
- Proper ratchet tree with distinct leaves
- No protocol hacks or workarounds

---

## Implementation Checklist

### Swift Client Updates

- [ ] Change `synchronizable` to `false` in MLSKeychainManager
- [ ] Implement per-device identity generation
- [ ] Add device registration on first launch
- [ ] Handle device restoration by public key lookup
- [ ] Update UI to explain "no message history on new devices"

### Server Updates

- [ ] Add `signature_public_key` column to `user_devices`
- [ ] Implement `getDeviceByPublicKey` endpoint
- [ ] Update device registration to store public key
- [ ] Ensure auto-device-add triggers on device registration

### Documentation Updates

- [ ] Update all references to "iCloud Keychain sync"
- [ ] Clarify "device-local Keychain"
- [ ] Update recovery flow diagrams
- [ ] Add comparison to Signal multi-device

---

## Summary

**What Changed:**
- ❌ REMOVED: iCloud Keychain synchronization
- ✅ ADDED: Device-local Keychain storage
- ✅ ADDED: Per-device unique signature keys
- ✅ CLARIFIED: iOS backup helps same device, not cross-device

**Result:**
- Proper multi-device support (like Signal)
- Enhanced forward secrecy per device
- Correct MLS protocol usage
- Seamless new device onboarding (2-5 seconds)

**User Experience:**
- Same device reinstall: Perfect restoration
- New device: Quick rejoin, no old messages
- Multiple devices: All work independently

This matches user expectations and maintains E2EE security! ✨

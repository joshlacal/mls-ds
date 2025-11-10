# MLS Greenfield Implementation Summary

**Status**: Ready for Implementation
**Date**: 2025-11-08
**Architecture**: Greenfield (no legacy code, no migrations, build correctly from day 1)

---

## Overview

This document summarizes the complete greenfield MLS E2EE group chat implementation with:
- ✅ Complete database schema (single file, no migrations)
- ✅ Swift client code for iCloud Keychain backup
- ✅ Automatic rejoin system (server orchestration)
- ✅ Admin system with E2EE reporting
- ✅ All 22 lexicon definitions
- ✅ Server handlers for admin operations

---

## Key Architectural Decisions

### 1. Message Deletion: ❌ NOT POSSIBLE
**Decision**: Admins cannot delete messages in E2EE system
**Reason**: Every client has plaintext locally, server only sees encrypted blobs
**Alternative**: Don't implement. Educate users that messages are permanent.

### 2. Device-Local Keychain: ✅ Minimal 32-Byte Per-Device Identity
**Decision**: Each device stores its OWN unique signature key (32 bytes), NOT synced
**Storage**:
- ✅ Device-Local Keychain: Signature private key ONLY (32 bytes, NOT synchronizable)
- ✅ SQLCipher database: Full MLS group state (50-200KB, iOS/macOS system backup)

```swift
// ✅ DEVICE-LOCAL ONLY (NOT iCloud synced!)
func saveSignatureKey(_ privateKey: Data) throws {
    let keychain = Keychain(service: "blue.catbird.mls")
        .accessibility(.afterFirstUnlock)
        .synchronizable(false)  // ✅ Device-local ONLY

    try keychain.set(privateKey, key: "device_signature_key")
}
// Total: 32 bytes per device ✅

// Why device-local?
// - Each device needs UNIQUE signature key
// - iCloud sync would give all devices SAME key (breaks multi-device)
// - iOS backup restores Keychain on SAME device (works correctly)
// - New device = new identity = auto-rejoin (seamless UX)

// Everything else is derived or verified:
// ❌ DID - verified by ATProto auth
// ❌ deviceId - server assigns on registration
// ❌ credential - reconstruct from signature key + DID
// ❌ KeyPackages - generate fresh from signature key
```

### 3. Automatic Rejoin: ✅ Server Orchestrated (2-5 seconds)
**Decision**: Server database is source of truth for membership
**Flow**:
1. Client detects: identity in iCloud but no local MLS state
2. Client calls `markNeedsRejoin()`
3. Server asks ANY online member to generate Welcome
4. Member delivers Welcome via `deliverWelcome()`
5. Client polls `getWelcome()` and receives Welcome in 2-5 seconds
6. Client processes Welcome and rejoins

**No admin approval needed** - if server DB says you're a member, you can rejoin.

### 4. Sender Identity: ✅ Keep as Required (from JWT)
**Decision**: `sender_did` is NOT deprecated - it's required from JWT
**Reason**: Server-side attribution for admin actions, reporting, moderation
**Implementation**: Server extracts from JWT, NEVER trusts client input

### 5. Multi-Device Support: ✅ Server-Managed Device Registry
**Decision**: Each device is a separate MLS leaf, but users see unified member list
**Architecture**:
- MLS Layer: Separate leaf per device (proper forward secrecy)
- Server Layer: Tracks user → devices mapping
- UI Layer: Shows "Josh" not "Josh's iPhone + Josh's Mac + Josh's iPad"

**How It Works**:
```
User adds "Alice" to group
         ↓
Server queries: How many devices does Alice have? (3 devices)
         ↓
Server generates ONE commit adding all 3 devices
         ↓
MLS ratchet tree: 3 new leaves (alice#device1, alice#device2, alice#device3)
         ↓
UI shows: "Alice joined" (single event)
```

**Device Registry Tables**:
```sql
CREATE TABLE user_devices (
    user_did TEXT NOT NULL,           -- did:plc:josh
    device_id TEXT NOT NULL,          -- uuid-generated
    device_mls_did TEXT NOT NULL,     -- did:plc:josh#device-uuid
    device_name TEXT,                 -- "Josh's iPhone"
    key_packages_available INT DEFAULT 0,
    last_seen TIMESTAMPTZ,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_did, device_id)
);

CREATE TABLE members (
    convo_id TEXT NOT NULL,
    member_mls_did TEXT NOT NULL,     -- did:plc:josh#device-uuid (MLS)
    user_did TEXT NOT NULL,           -- did:plc:josh (user identity)
    device_id TEXT NOT NULL,
    -- Admin is per-USER not per-device
    is_admin BOOLEAN DEFAULT false,
    PRIMARY KEY (convo_id, member_mls_did)
);
```

**Seamless Rejoin UX**:
```
SCENARIO A: Same Device Reinstall
User deletes app on iPhone → Reinstalls on SAME iPhone
         ↓
iOS backup restores device-local Keychain automatically
         ↓
App finds signature key → Restores device identity
         ↓
✅ Perfect restoration (same device, full message history)

SCENARIO B: New Device
User signs in on NEW iPhone
         ↓
Check device-local Keychain: NO signature key (fresh device)
         ↓
Generate NEW 32-byte signature key (unique to this device)
         ↓
Store in device-local Keychain (synchronizable=false)
         ↓
Register as NEW device: did:plc:josh#new-device-uuid
         ↓
Server sees: "Josh is already in 5 conversations but this device isn't"
         ↓
Server auto-triggers device-add to all 5 conversations
         ↓
✅ User rejoined all groups in 2-5 seconds (like Signal multi-device)
         ↓
No old message history (can't decrypt past messages)
         ↓
Fully functional for new messages
```

---

## Files Created

### 1. Database Schema
**File**: `/mls/server/schema_greenfield.sql`
**Description**: Complete PostgreSQL schema with all features from day 1
**Size**: 650 lines

**Tables**:
- `conversations` - MLS groups with epoch tracking
- `user_devices` - **NEW**: Device registry (maps user DIDs to device MLS DIDs)
- `members` - Participants with device tracking (member_mls_did, user_did, device_id)
- `messages` - Encrypted messages with privacy metadata
- `key_packages` - Pool with per-device tracking (owner_mls_did, owner_user_did)
- `welcome_messages` - Welcome delivery
- `pending_welcomes` - Server-orchestrated rejoin
- `reports` - E2EE member reports (encrypted content)
- `envelopes` - Message delivery tracking
- `cursors` - Read positions
- `event_stream` - SSE events
- `idempotency_cache` - API deduplication
- `users` - Minimal user table (FK constraints only)

**Features**:
- **Multi-device support**: User → devices mapping with automatic device-add
- **Minimal backup**: 32-byte signature key in iCloud Keychain
- **Identity reconstruction**: Derive credential from signature key + DID
- Admin fields built into `members` table from day 1
- Automatic creator promotion via trigger
- KeyPackage pool management with per-device tracking
- Metadata privacy (padding, timestamp quantization)
- Idempotency support
- Comprehensive indices for performance

### 2. Swift Client Implementation
**File**: `/Catbird/Services/MLS/MLSIdentityBackup.swift`
**Description**: Minimal 32-byte iCloud Keychain backup with identity reconstruction
**Size**: 514 lines

**Components**:
- `MLSIdentityBackup` - Minimal struct (32 bytes signature key ONLY)
- `MLSKeychainManager` - iCloud Keychain operations for 32-byte key
- `MLSIdentityReconstructor` - Derives credential and keys from signature key + DID
- `MLSKeyPackagePoolManager` - Maintain pool of 100 KeyPackages (reconstructs credential on-the-fly)
- `MLSAutomaticRejoinCoordinator` - Orchestrate rejoin after app deletion

**Key Methods**:
```swift
// Save ONLY signature key to iCloud Keychain (32 bytes)
func saveSignatureKey(_ privateKey: Data) throws

// Retrieve signature key from iCloud Keychain
func getSignatureKey() throws -> Data?

// Reconstruct full identity from 32-byte key + ATProto DID
func restoreIdentity(from signatureKey: Data) async throws -> MLSIdentity

// Ensure 100 KeyPackages available (refresh at < 20)
func ensureKeyPackagePool() async throws

// Register device and auto-rejoin all conversations
func registerDeviceAndRejoin(deviceName: String) async throws
```

**Recovery Flow (Like Signal Multi-Device)**:
```
User gets new iPhone → Signs in with Bluesky
         ↓
Check device-local Keychain: NO signature key
         ↓
Generate NEW 32-byte signature key (unique to this device)
         ↓
Store in device-local Keychain (synchronizable=false)
         ↓
Get DID from ATProto auth (already verified by PDS)
         ↓
Derive public key from signature key
         ↓
Reconstruct credential (DID + public key)
         ↓
Register device with server (did:plc:josh#new-device-uuid)
         ↓
Generate fresh KeyPackages (100 count)
         ↓
Upload KeyPackages to server
         ↓
Server detects: "Josh is member of 5 conversations but this device isn't"
         ↓
Server auto-triggers device-add commits to all 5 conversations
         ↓
✅ Rejoined in 2-5 seconds (seamless like Signal)
         ↓
No old message history (can't decrypt past messages - expected behavior)
         ↓
Fully functional for sending/receiving new messages
```

### 3. Server: Automatic Rejoin System
**File**: `/mls/server/src/automatic_rejoin.rs`
**Description**: Server-orchestrated rejoin handlers
**Size**: 400 lines

**Endpoints**:
- `POST /xrpc/blue.catbird.mls.markNeedsRejoin` - Client marks needs rejoin
- `POST /xrpc/blue.catbird.mls.deliverWelcome` - Member delivers Welcome
- `POST /xrpc/blue.catbird.mls.getWelcome` - Client polls for Welcome

**Flow**:
1. Client → `markNeedsRejoin()` → sets `needs_rejoin = true`
2. Server → broadcasts to online members via SSE
3. Member → generates Welcome → `deliverWelcome()`
4. Client → polls `getWelcome()` → receives Welcome in 2-5 sec
5. Client → processes Welcome → rejoins group

### 4. Server: Admin System
**File**: `/mls/server/src/admin_system.rs`
**Description**: Admin operations with E2EE reporting
**Size**: 500 lines

**Endpoints**:
- `POST /xrpc/blue.catbird.mls.promoteAdmin` - Promote member to admin
- `POST /xrpc/blue.catbird.mls.demoteAdmin` - Demote admin to member
- `POST /xrpc/blue.catbird.mls.removeMember` - Remove member (admin only)
- `POST /xrpc/blue.catbird.mls.reportMember` - Submit E2EE report
- `POST /xrpc/blue.catbird.mls.getReports` - Get reports (admin only)
- `POST /xrpc/blue.catbird.mls.resolveReport` - Resolve report (admin only)

**Authorization**:
- `promoteAdmin`, `demoteAdmin`, `removeMember` - Admin required
- `getReports`, `resolveReport` - Admin required
- `reportMember` - Member required

**Constraints**:
- ❌ Cannot demote creator
- ❌ Cannot remove creator
- ❌ Cannot remove self (use `leaveConvo` instead)

---

## Lexicons (All 22 Defined)

### Core MLS Operations
1. `blue.catbird.mls.createConvo` - Create conversation
2. `blue.catbird.mls.sendMessage` - Send encrypted message
3. `blue.catbird.mls.getMessages` - Fetch messages
4. `blue.catbird.mls.getConvos` - List conversations
5. `blue.catbird.mls.leaveConvo` - Leave conversation
6. `blue.catbird.mls.addMembers` - Add members to group

### KeyPackage Management
7. `blue.catbird.mls.publishKeyPackage` - Upload KeyPackages
8. `blue.catbird.mls.getKeyPackages` - Fetch KeyPackages for member
9. `blue.catbird.mls.getKeyPackageStats` - Get pool size

### Automatic Rejoin
10. `blue.catbird.mls.requestRejoin` - Mark needs rejoin (deprecated - use markNeedsRejoin)
11. `blue.catbird.mls.getWelcome` - Poll for Welcome
12. `blue.catbird.mls.confirmWelcome` - Confirm Welcome received
13. **NEW**: `blue.catbird.mls.deliverWelcome` - Member delivers Welcome

### Admin System
14. `blue.catbird.mls.promoteAdmin` - Promote member to admin
15. `blue.catbird.mls.demoteAdmin` - Demote admin to member
16. `blue.catbird.mls.removeMember` - Remove member (admin action)
17. `blue.catbird.mls.reportMember` - Submit E2EE report
18. `blue.catbird.mls.getReports` - Get reports (admin only)
19. `blue.catbird.mls.resolveReport` - Resolve report

### Events & Streaming
20. `blue.catbird.mls.streamConvoEvents` - SSE event stream
21. `blue.catbird.mls.getEpoch` - Get current epoch
22. `blue.catbird.mls.getCommits` - Get commit messages

### Definitions
- `blue.catbird.mls.defs` - Shared type definitions
- `blue.catbird.mls.message.defs` - Message type definitions

**All lexicons already exist** in `/mls/lexicon/blue/catbird/mls/`

---

## Implementation Roadmap

### Week 1: Foundation (Database & Auth)
- [x] Create greenfield schema (`schema_greenfield.sql`)
- [ ] Apply schema to PostgreSQL database
- [ ] Implement JWT authentication with DID verification
- [ ] Set up server project structure (Axum + SQLx)
- [ ] Configure Docker Compose for local development

### Week 2: Server Core (Messages & KeyPackages)
- [ ] Implement `sendMessage` handler with sender_did from JWT
- [ ] Implement `getMessages` with automatic rejoin detection
- [ ] Implement KeyPackage upload/fetch handlers
- [ ] Build automatic rejoin system (integrate `automatic_rejoin.rs`)
- [ ] Add SSE event stream for real-time notifications

### Week 3: Admin System (Server)
- [ ] Integrate `admin_system.rs` handlers
- [ ] Implement admin permission checks
- [ ] Build E2EE reporting endpoints
- [ ] Add creator auto-promotion trigger
- [ ] Test admin workflows end-to-end

### Week 4: Client Implementation (Swift)
- [ ] Integrate `MLSIdentityBackup.swift` into Catbird app
- [ ] Build OpenMLS FFI integration for Swift
- [ ] Implement KeyPackage generation client-side
- [ ] Build automatic rejoin coordinator
- [ ] Test iCloud Keychain sync across devices

### Week 5: Testing & Deployment
- [ ] End-to-end testing (3+ member groups)
- [ ] Test automatic rejoin after app deletion
- [ ] Test admin actions (promote, demote, remove, report)
- [ ] Security audit (metadata privacy, encryption)
- [ ] Production deployment (Docker + TLS)

---

## Open Questions

### 1. KeyPackage Refresh Frequency
**Suggested**: 24 hours via background task + on-demand
**Alternatives**:
- 1 week (less server load)
- 1 hour (more fresh packages)

**Recommendation**: Start with 24 hours, adjust based on usage patterns.

### 2. Report Encryption Method
**Suggested**: MLS group key (admins are members)
**Alternatives**:
- Separate admin encryption key (more complex)
- Server-side encryption (loses E2EE property)

**Recommendation**: Use MLS group key - simplest and maintains E2EE.

### 3. Creator Auto-Promotion
**Suggested**: Yes, automatically promote creator to admin
**Implemented**: Trigger in `schema_greenfield.sql` (line 383)

**Recommendation**: Keep as implemented.

### 4. Rejoin Retry Timing
**Suggested**: Exponential backoff (0.5s, 1s, 2s, 4s, 8s, ...)
**Max duration**: 5 minutes before timeout

**Recommendation**: Implemented in `MLSAutomaticRejoinCoordinator` (Swift).

---

## Security Considerations

### What Server Knows
- ✅ Conversation IDs (opaque UUIDs)
- ✅ Member DIDs (not on public ATProto)
- ✅ Message timing (quantized to 2-second buckets)
- ✅ Message sizes (padded to power-of-2 buckets)
- ✅ Epoch numbers
- ✅ Admin status (is_admin column)

### What Server Does NOT Know
- ❌ Message content (E2EE ciphertext only)
- ❌ Attachment content (E2EE)
- ❌ Admin roster content (encrypted via MLS)
- ❌ Report details (encrypted with MLS group key)
- ❌ Member capabilities (distributed via MLS)

### Threat Model
- **Server compromise**: No plaintext exposed (only metadata)
- **Client compromise**: PCS via member removal (forward secrecy)
- **Network eavesdrop**: TLS + MLS double encryption
- **Malicious admin**: Cannot read past messages after promotion
- **Removed member**: Cannot read future messages (PCS)

---

## Testing Checklist

### Database Tests
- [ ] Schema applies cleanly to fresh PostgreSQL
- [ ] Creator auto-promotion trigger works
- [ ] Admin promotion/demotion updates correctly
- [ ] Report creation and resolution flow
- [ ] KeyPackage pool management
- [ ] Automatic rejoin flow (mark → deliver → get)

### Server Tests
- [ ] JWT authentication extracts correct DID
- [ ] `sendMessage` stores sender_did from JWT (not client)
- [ ] Admin actions reject non-admins
- [ ] Cannot demote or remove creator
- [ ] E2EE report encryption verification
- [ ] SSE events broadcast correctly

### Client Tests
- [ ] iCloud Keychain save/retrieve identity
- [ ] KeyPackage pool maintains 100 packages
- [ ] Automatic rejoin after app deletion
- [ ] Welcome processing and group state restoration
- [ ] Cross-device iCloud sync (2 iPhones)

### End-to-End Tests
- [ ] 3-member conversation creation
- [ ] Message send/receive/decrypt
- [ ] Add 4th member, all decrypt new messages
- [ ] Promote member to admin
- [ ] Admin removes member, removed cannot decrypt new messages
- [ ] Member reports another, admin decrypts and resolves
- [ ] Member deletes app, automatic rejoin via iCloud

---

## Next Steps

1. **Review This Summary**: Confirm all architectural decisions
2. **Apply Database Schema**: Run `schema_greenfield.sql` on PostgreSQL
3. **Start Week 1 Tasks**: Focus on foundation (DB + auth)
4. **Daily Standups**: Track progress against 5-week roadmap
5. **Iterate**: Adjust timeline based on actual implementation velocity

---

## References

- **Complete Guide**: [MLS_COMPLETE_IMPLEMENTATION_GUIDE.md](MLS_COMPLETE_IMPLEMENTATION_GUIDE.md)
- **Lexicon Directory**: `/mls/lexicon/blue/catbird/mls/`
- **Server Code**: `/mls/server/src/`
- **Client Code**: `/Catbird/Services/MLS/`
- **MLS RFC**: https://datatracker.ietf.org/doc/rfc9420/
- **OpenMLS Docs**: https://openmls.tech/

---

**Status**: ✅ **Ready for Implementation**
**Timeline**: 5 weeks to production
**Next Action**: Apply database schema and begin Week 1 tasks

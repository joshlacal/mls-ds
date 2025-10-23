# CloudKit + MLS E2EE Architecture Guide

## Executive Summary

This document explains how to implement an MLS E2EE group chat system that uses **CloudKit as the storage layer** for iOS clients while maintaining a **thin Delivery Service** for coordination. Your current server becomes a lightweight DS (Delivery Service) per MLS architecture, handling key-package directory, fan-out logic, and membership policy—while CloudKit stores the actual encrypted message payloads.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         iOS Client                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ MLSManager   │  │ CloudKit     │  │ ATProto      │          │
│  │ (OpenMLS FFI)│  │ Provider     │  │ Identity     │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
│         │ encrypt/decrypt │ CKRecord/Asset   │ DID resolution   │
│         └─────────────────┴──────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS + JWT
                              ▼
        ┌──────────────────────────────────────────┐
        │    MLS Delivery Service (Your Server)    │
        │                                           │
        │  • KeyPackage directory                  │
        │  • Membership roster                      │
        │  • Fan-out pointers                       │
        │  • Epoch tracking                         │
        │  • NO PLAINTEXT storage                   │
        └──────────────────────────────────────────┘
                              │
                              │ (metadata only)
                              ▼
                    ┌──────────────────┐
                    │   PostgreSQL     │
                    │  (room roster,   │
                    │   key packages)  │
                    └──────────────────┘

        iOS Clients write/read ciphertext here ▼
        ┌──────────────────────────────────────────┐
        │            CloudKit (iCloud)              │
        │                                           │
        │  • CKRecord: MessageMeta (room, epoch,   │
        │              sender DID, timestamp)      │
        │  • CKAsset: ciphertext blob              │
        │  • Subscriptions: push on new records    │
        │  • NO server-side decryption             │
        └──────────────────────────────────────────┘
```

---

## 1. How CloudKit Fits MLS

### What Lives in CloudKit

1. **Message Envelopes** (CKRecord type `MessageMeta`)
   - `roomId`: UUID string
   - `epoch`: MLS epoch number
   - `seq`: sequence number
   - `senderDid`: sender's DID
   - `timestamp`: sent timestamp
   - `ciphertextRef`: reference to CKAsset
   - `hash`: SHA-256 of ciphertext (integrity)
   - Optional: small encrypted preview fields (for notifications)

2. **Message Ciphertext** (CKAsset)
   - The actual MLS-encrypted payload
   - Typically < 1 MB for text messages
   - Larger for attachments (up to 50 MB practical limit)

3. **Commit Messages** (same structure, `type = "commit"`)
   - MLS group state changes (add/remove members)
   - Also encrypted, stored as CKAsset

### What Lives in Your Delivery Service

1. **Key Packages** (PostgreSQL)
   - Pre-generated MLS KeyPackages for inviting users
   - One-time-use tokens
   - Fetched by inviter, consumed on use

2. **Room Roster** (PostgreSQL)
   - `conversations` table: roomId, creator, current_epoch
   - `members` table: who's in each room (DIDs), active/removed status
   - Used for access control & fan-out logic

3. **Fan-Out Pointers** (optional, PostgreSQL)
   - Per-member "inbox" references
   - Maps (roomId, memberDid) → CloudKit zone/record pointers
   - Enables per-user mailbox model for large groups

4. **Metadata Only**
   - No plaintext content
   - No ciphertext storage (that's in CloudKit)

---

## 2. CloudKit Storage Models

### Zone Strategy

**Option A: Shared Zone (Small Groups, ≤100 members)**

Use `CKShare` for a shared private zone:

```swift
// One zone per conversation
let zoneID = CKRecordZone.ID(zoneName: "room_\(roomId)", ownerName: CKCurrentUserDefaultName)
let zone = CKRecordZone(zoneID: zoneID)

// Create CKShare to invite members
let share = CKShare(rootRecord: roomHeaderRecord)
share[CKShare.SystemFieldKey.participants] = memberDIDs.map { /* create CKShare.Participant */ }
```

**Pros**: Simple, built-in ACL
**Cons**: 100-participant limit (CKShare limitation)

**Option B: Per-User Mailbox (Scalable, any group size)**

Each user has their own private zone; sender writes a record to each recipient's zone:

```swift
// Alice sends to Bob
let bobInboxZone = CKRecordZone.ID(zoneName: "inbox_\(bobDID)", ownerName: bobDID)
let record = CKRecord(recordType: "MessageMeta", recordID: msgID, zoneID: bobInboxZone)
// Write to Bob's zone via CloudKit Web Services or shared container
```

**Pros**: No participant limits, better privacy
**Cons**: N writes per message (DS can batch), more complex

**Recommendation**: Start with Option A; migrate to Option B if groups > 100 users.

---

### Record Schema

#### MessageMeta Record

```swift
import CloudKit

func createMessageRecord(
    roomId: String,
    epoch: Int,
    seq: Int,
    senderDid: String,
    ciphertext: Data,
    zoneID: CKRecordZone.ID
) -> CKRecord {
    let recordID = CKRecord.ID(recordName: UUID().uuidString, zoneID: zoneID)
    let record = CKRecord(recordType: "MessageMeta", recordID: recordID)
    
    // Metadata (searchable, visible to CloudKit)
    record["roomId"] = roomId as CKRecordValue
    record["epoch"] = epoch as CKRecordValue
    record["seq"] = seq as CKRecordValue
    record["senderDid"] = senderDid as CKRecordValue
    record["timestamp"] = Date() as CKRecordValue
    record["hash"] = ciphertext.sha256().base64EncodedString() as CKRecordValue
    
    // Ciphertext (stored as asset)
    let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try! ciphertext.write(to: tempURL)
    record["ciphertext"] = CKAsset(fileURL: tempURL)
    
    // Optional: encrypted fields for push notifications
    // (CloudKit can encrypt these at rest if user has Advanced Data Protection)
    // record.encryptedValues["preview"] = encryptedPreview
    
    return record
}
```

#### Attachment Handling

For large attachments (images, videos):

```swift
func createAttachmentRecord(
    roomId: String,
    messageId: String,
    encryptedData: Data,
    mimeType: String,
    zoneID: CKRecordZone.ID
) -> CKRecord {
    let recordID = CKRecord.ID(recordName: "att_\(messageId)", zoneID: zoneID)
    let record = CKRecord(recordType: "Attachment", recordID: recordID)
    
    record["roomId"] = roomId as CKRecordValue
    record["messageId"] = messageId as CKRecordValue
    record["mimeType"] = mimeType as CKRecordValue
    
    // Asset (supports up to ~50 MB comfortably)
    let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try! encryptedData.write(to: tempURL)
    record["data"] = CKAsset(fileURL: tempURL)
    
    return record
}
```

---

### CloudKit Subscriptions (Push Notifications)

Set up database subscriptions to get notified of new messages:

```swift
func subscribeToRoom(roomId: String, zoneID: CKRecordZone.ID) async throws {
    let predicate = NSPredicate(format: "roomId == %@", roomId)
    let subscription = CKQuerySubscription(
        recordType: "MessageMeta",
        predicate: predicate,
        subscriptionID: "room_\(roomId)",
        options: [.firesOnRecordCreation]
    )
    
    // Silent push notification
    let notification = CKSubscription.NotificationInfo()
    notification.shouldSendContentAvailable = true // Silent push
    notification.alertBody = "" // Or encrypted preview
    subscription.notificationInfo = notification
    
    try await CKContainer.default().privateCloudDatabase.save(subscription)
}

// In AppDelegate/SceneDelegate:
func application(
    _ application: UIApplication,
    didReceiveRemoteNotification userInfo: [AnyHashable : Any],
    fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
) {
    // CKQueryNotification or CKRecordZoneNotification
    // Fetch new records, decrypt, update UI
}
```

---

## 3. Adjusted Server Architecture

Your existing Rust server becomes a **thin Delivery Service**. Here's what changes:

### What to Keep

1. **Authentication** (JWT, DID verification)
2. **KeyPackage Directory** (store/fetch/consume)
3. **Room Roster** (membership tracking)
4. **Epoch Tracking** (prevent replay attacks)

### What to Remove/Change

1. **Message Storage** → Move to CloudKit
   - Remove `messages` table ciphertext storage
   - Keep metadata-only log (optional, for analytics)

2. **Blob Storage** → Move to CloudKit (as CKAsset)
   - Remove `blobs` table
   - Or keep CID→CloudKit mapping

### New Responsibilities

1. **Fan-Out Coordination** (for mailbox model)
   - DS receives "send message" request
   - Checks membership
   - Returns list of recipient DIDs + their CloudKit zone pointers
   - Client writes to each zone (or DS does via CloudKit Web Services)

2. **Welcome Message Routing**
   - When adding member, DS holds Welcome message temporarily
   - New member fetches from DS, then joins CloudKit zone

---

### Updated API Endpoints

#### Existing (Unchanged)

```
POST /xrpc/blue.catbird.mls.publishKeyPackage
GET  /xrpc/blue.catbird.mls.getKeyPackages?dids[]=...
POST /xrpc/blue.catbird.mls.createConvo
GET  /xrpc/blue.catbird.mls.getConvos
POST /xrpc/blue.catbird.mls.addMembers
POST /xrpc/blue.catbird.mls.leaveConvo
```

#### Modified

**POST /xrpc/blue.catbird.mls.sendMessage**

Old (stores ciphertext):
```json
{
  "convoId": "uuid",
  "ciphertext": "base64...",
  "epoch": 5
}
```

New (returns fan-out targets):
```json
Request:
{
  "convoId": "uuid",
  "epoch": 5,
  "hash": "sha256...",  // Client includes hash for integrity
  "size": 1234          // Ciphertext size
}

Response:
{
  "recipients": [
    { "did": "did:plc:alice", "zoneId": "inbox_alice" },
    { "did": "did:plc:bob", "zoneId": "inbox_bob" }
  ],
  "seq": 42,
  "serverTime": "2024-10-22T20:00:00Z"
}
```

Client then:
1. Encrypts message with MLSManager
2. Writes CKRecord to each recipient's zone (or shared zone)
3. Updates local state

**GET /xrpc/blue.catbird.mls.getMessages** (optional)

Old: Returns ciphertext from DB
New: Returns pointers or remove entirely (clients fetch from CloudKit directly)

```json
Response:
{
  "messages": [
    {
      "id": "uuid",
      "epoch": 5,
      "seq": 42,
      "senderDid": "did:plc:alice",
      "timestamp": "...",
      // CloudKit pointer (optional):
      "cloudKitRecord": {
        "zoneId": "room_uuid",
        "recordName": "msg_uuid"
      }
    }
  ]
}
```

Or simpler: clients subscribe to CloudKit directly, no need to poll server.

---

### Updated Database Schema

**conversations** (no change):
```sql
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    current_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title TEXT,
    -- NEW: CloudKit zone reference
    cloudkit_zone_id TEXT  -- e.g., "room_uuid" or NULL if per-user
);
```

**members** (no change):
```sql
CREATE TABLE members (
    convo_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    unread_count INTEGER NOT NULL DEFAULT 0,
    last_read_at TIMESTAMPTZ,
    -- NEW: CloudKit mailbox zone (for per-user model)
    cloudkit_inbox_zone TEXT,  -- e.g., "inbox_did:plc:alice"
    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);
```

**messages** (minimal, metadata only):
```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    convo_id TEXT NOT NULL,
    sender_did TEXT NOT NULL,
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Remove: ciphertext BYTEA
    -- Add: CloudKit reference
    cloudkit_record_name TEXT,
    cloudkit_zone_id TEXT,
    hash TEXT,  -- SHA-256 of ciphertext (for integrity checks)
    size BIGINT,
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);
```

**key_packages** (no change):
```sql
CREATE TABLE key_packages (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    key_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ
);
```

**Remove**:
```sql
-- No longer needed (CloudKit handles blobs)
DROP TABLE blobs;
```

---

### Updated Rust Handlers

**Example: `send_message` handler**

```rust
// src/handlers/send_message.rs

use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SendMessageInput {
    pub convo_id: String,
    pub epoch: i32,
    pub hash: String,  // SHA-256 of ciphertext
    pub size: i64,
}

#[derive(Serialize)]
pub struct SendMessageOutput {
    pub recipients: Vec<RecipientTarget>,
    pub seq: i32,
    pub server_time: String,
}

#[derive(Serialize)]
pub struct RecipientTarget {
    pub did: String,
    pub cloudkit_zone_id: String,
}

pub async fn send_message(
    state: AppState,
    claims: JwtClaims,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, ApiError> {
    // 1. Verify membership
    if !db::is_member(&state.pool, &claims.sub, &input.convo_id).await? {
        return Err(ApiError::Forbidden("Not a member".into()));
    }

    // 2. Check epoch (prevent replay)
    let convo = db::get_conversation(&state.pool, &input.convo_id).await?;
    if input.epoch != convo.current_epoch {
        return Err(ApiError::BadRequest(format!(
            "Epoch mismatch: expected {}, got {}",
            convo.current_epoch, input.epoch
        )));
    }

    // 3. Get active members
    let members = db::list_members(&state.pool, &input.convo_id, 100, 0).await?
        .into_iter()
        .filter(|m| m.left_at.is_none())
        .collect::<Vec<_>>();

    // 4. Generate sequence number
    let seq = db::increment_message_seq(&state.pool, &input.convo_id).await?;

    // 5. Store metadata (optional, for audit log)
    db::create_message_metadata(
        &state.pool,
        &input.convo_id,
        &claims.sub,
        "app",
        input.epoch,
        seq,
        &input.hash,
        input.size,
    ).await?;

    // 6. Return fan-out targets
    let recipients = members.iter().map(|m| RecipientTarget {
        did: m.member_did.clone(),
        cloudkit_zone_id: m.cloudkit_inbox_zone.clone()
            .unwrap_or_else(|| format!("inbox_{}", m.member_did)),
    }).collect();

    Ok(Json(SendMessageOutput {
        recipients,
        seq,
        server_time: chrono::Utc::now().to_rfc3339(),
    }))
}
```

**Client Flow**:

```swift
// iOS client
func send(text: String, in roomId: String) async throws {
    // 1. Encrypt with MLS
    let plaintext = text.data(using: .utf8)!
    let ciphertext = try mlsManager.encrypt(session: session, plaintext: plaintext)
    let hash = SHA256.hash(data: ciphertext).hexString

    // 2. Request fan-out targets from DS
    let response = try await mlsClient.sendMessage(
        convoId: roomId,
        epoch: session.epoch,
        hash: hash,
        size: ciphertext.count
    )

    // 3. Write to CloudKit (shared zone or per-recipient)
    let record = createMessageRecord(
        roomId: roomId,
        epoch: session.epoch,
        seq: response.seq,
        senderDid: myDid,
        ciphertext: ciphertext,
        zoneID: sharedZoneID  // or loop over recipients
    )

    try await CKContainer.default().privateCloudDatabase.save(record)

    // 4. Update local state
    await storage.saveMessage(...)
}
```

---

## 4. Storage Provider Abstraction

To support both CloudKit (iOS) and future Android storage (Google Drive, Firestore), define a protocol:

### Swift Protocol

```swift
protocol StorageProvider {
    /// Write encrypted message to storage
    func writeMessage(
        roomId: String,
        epoch: Int,
        seq: Int,
        senderDid: String,
        ciphertext: Data
    ) async throws -> StorageReference
    
    /// Read messages since cursor
    func readMessages(
        roomId: String,
        since: Date?
    ) async throws -> [StorageMessage]
    
    /// Subscribe to new messages
    func subscribe(roomId: String, handler: @escaping (StorageMessage) -> Void) async throws
    
    /// Upload attachment
    func uploadAttachment(
        roomId: String,
        data: Data,
        mimeType: String
    ) async throws -> StorageReference
}

struct StorageReference {
    let id: String
    let url: URL?  // For CloudKit, CKAsset URL
}

struct StorageMessage {
    let id: String
    let roomId: String
    let epoch: Int
    let seq: Int
    let senderDid: String
    let ciphertext: Data
    let timestamp: Date
}
```

### CloudKit Implementation

```swift
class CloudKitStorageProvider: StorageProvider {
    private let container: CKContainer
    private let database: CKDatabase
    
    init(container: CKContainer = .default()) {
        self.container = container
        self.database = container.privateCloudDatabase
    }
    
    func writeMessage(
        roomId: String,
        epoch: Int,
        seq: Int,
        senderDid: String,
        ciphertext: Data
    ) async throws -> StorageReference {
        let zoneID = CKRecordZone.ID(zoneName: "room_\(roomId)", ownerName: CKCurrentUserDefaultName)
        let record = createMessageRecord(
            roomId: roomId,
            epoch: epoch,
            seq: seq,
            senderDid: senderDid,
            ciphertext: ciphertext,
            zoneID: zoneID
        )
        
        let savedRecord = try await database.save(record)
        return StorageReference(id: savedRecord.recordID.recordName, url: nil)
    }
    
    func readMessages(roomId: String, since: Date?) async throws -> [StorageMessage] {
        let zoneID = CKRecordZone.ID(zoneName: "room_\(roomId)", ownerName: CKCurrentUserDefaultName)
        
        var predicate: NSPredicate
        if let since = since {
            predicate = NSPredicate(format: "roomId == %@ AND timestamp > %@", roomId, since as NSDate)
        } else {
            predicate = NSPredicate(format: "roomId == %@", roomId)
        }
        
        let query = CKQuery(recordType: "MessageMeta", predicate: predicate)
        query.sortDescriptors = [NSSortDescriptor(key: "timestamp", ascending: true)]
        
        let (matchResults, _) = try await database.records(matching: query, inZoneWith: zoneID)
        
        return try matchResults.compactMap { (_, result) in
            let record = try result.get()
            
            guard let asset = record["ciphertext"] as? CKAsset,
                  let fileURL = asset.fileURL,
                  let ciphertext = try? Data(contentsOf: fileURL) else {
                return nil
            }
            
            return StorageMessage(
                id: record.recordID.recordName,
                roomId: record["roomId"] as! String,
                epoch: record["epoch"] as! Int,
                seq: record["seq"] as! Int,
                senderDid: record["senderDid"] as! String,
                ciphertext: ciphertext,
                timestamp: record["timestamp"] as! Date
            )
        }
    }
    
    func subscribe(roomId: String, handler: @escaping (StorageMessage) -> Void) async throws {
        // Implement using CKQuerySubscription (see earlier section)
    }
    
    func uploadAttachment(roomId: String, data: Data, mimeType: String) async throws -> StorageReference {
        // Similar to writeMessage but with Attachment record type
        fatalError("Not implemented")
    }
}
```

### Future: Google Drive Provider

```swift
class GoogleDriveStorageProvider: StorageProvider {
    func writeMessage(...) async throws -> StorageReference {
        // Use Google Drive API to upload encrypted file
        // Store metadata in Firestore or Drive metadata
    }
    
    func readMessages(...) async throws -> [StorageMessage] {
        // Query Drive folder or Firestore collection
    }
    
    // etc.
}
```

---

## 5. Complete Flow Examples

### Create Group & Invite

```swift
// 1. Alice creates group locally
let session = try mlsManager.createGroup(credential: myCredential, cipherSuite: .default)

// 2. Alice tells DS about the group
let convo = try await mlsClient.createConvo(title: "Team Chat", invites: nil)

// 3. Alice creates CloudKit zone
let zoneID = CKRecordZone.ID(zoneName: "room_\(convo.id)", ownerName: CKCurrentUserDefaultName)
let zone = CKRecordZone(zoneID: zoneID)
try await CKContainer.default().privateCloudDatabase.save(zone)

// 4. Alice invites Bob
let bobKeyPackage = try await mlsClient.getKeyPackages(dids: ["did:plc:bob"]).first!
let (commit, welcome) = try mlsManager.addMember(session: session, keyPackage: bobKeyPackage.keyPackage)

// 5. Alice tells DS to add Bob (DS stores Welcome)
try await mlsClient.addMembers(
    convoId: convo.id,
    dids: ["did:plc:bob"],
    commit: commit,
    welcome: welcome
)

// 6. Alice writes commit to CloudKit
let commitRecord = createMessageRecord(
    roomId: convo.id,
    epoch: session.epoch,
    seq: 1,
    senderDid: myDid,
    ciphertext: commit,
    zoneID: zoneID
)
try await CKContainer.default().privateCloudDatabase.save(commitRecord)

// 7. DS notifies Bob via APNs (or Bob polls)
// Bob fetches Welcome from DS, joins MLS group, subscribes to CloudKit zone
```

### Send Message

```swift
// Alice sends message
let plaintext = "Hello, team!".data(using: .utf8)!
let ciphertext = try mlsManager.encrypt(session: session, plaintext: plaintext)

// Get fan-out targets from DS
let response = try await mlsClient.sendMessage(
    convoId: roomId,
    epoch: session.epoch,
    hash: ciphertext.sha256().hexString,
    size: ciphertext.count
)

// Write to CloudKit (shared zone)
let record = createMessageRecord(
    roomId: roomId,
    epoch: session.epoch,
    seq: response.seq,
    senderDid: myDid,
    ciphertext: ciphertext,
    zoneID: sharedZoneID
)
try await CKContainer.default().privateCloudDatabase.save(record)

// CloudKit subscription → APNs → Bob's device → decrypt → UI update
```

### Receive Message

```swift
// Bob receives silent push from CloudKit
func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: ...) {
    Task {
        // Fetch new records
        let messages = try await cloudKitProvider.readMessages(roomId: roomId, since: lastFetchTime)
        
        for msg in messages {
            // Decrypt
            let (plaintext, senderIndex) = try mlsManager.decrypt(
                session: session,
                ciphertext: msg.ciphertext
            )
            
            // Save locally
            await storage.saveMessage(
                id: msg.id,
                roomId: msg.roomId,
                senderDid: msg.senderDid,
                plaintext: String(data: plaintext, encoding: .utf8)!,
                timestamp: msg.timestamp
            )
        }
        
        // Update UI
        NotificationCenter.default.post(name: .newMessages, object: roomId)
    }
}
```

---

## 6. CloudKit Limits & Design Considerations

### Record/Asset Limits

- **CKRecord size**: ~1 MB (excluding assets)
  - Keep metadata lean: ~1 KB per message envelope
- **CKAsset size**: Documented ~50 MB, practical ~10-20 MB
  - For larger files, consider chunking or external storage
- **CKShare participants**: ~100 users max
  - Use per-user mailbox model for larger groups

### Quota Management

- **Free tier**: 1 GB public + 1 GB private DB per user
- **Paid tier**: Scales with iCloud storage plan
- **Overage**: CloudKit charges per GB, reasonable for indie apps

**Design for 20 GB ceiling** (your constraint):
- Assume 100 active users
- 200 KB per user = 20 GB
- ~2,000 messages per user @ 100 bytes each
- Use message expiration/archival for older data

### Conflict Resolution

CloudKit uses last-write-wins by default. For MLS:
- Commit messages must be ordered (by epoch/seq)
- Use `CKRecord.systemFields` for conflict detection
- Clients detect epoch conflicts and retry

---

## 7. Android Storage Strategy

Since CloudKit is iOS-only, Android needs an alternative:

### Option 1: Google Drive (File-Oriented)

- Store each message as an encrypted file in App Data folder
- Metadata in filenames or companion JSON
- Use Drive Changes API for sync
- **Pros**: Simple, built-in, free quota
- **Cons**: Clunky for small messages, slower than Firestore

### Option 2: Firestore (Structured)

- Store message envelopes as Firestore documents
- Ciphertext as base64 string or Cloud Storage reference
- Real-time listeners for push
- **Pros**: Fast, real-time, good query support
- **Cons**: Costs scale with reads/writes

### Option 3: Hybrid

- Firestore for metadata + pointers
- Cloud Storage for large attachments
- Best of both worlds

**Recommendation**: Firestore + Cloud Storage, with same `StorageProvider` interface.

---

## 8. Federated/Multi-Provider Future

To allow users to choose storage:

### Lexicon Extension

```json
// blue.catbird.mls.defs.json
{
  "storageProvider": {
    "type": "object",
    "properties": {
      "type": { "type": "string", "enum": ["cloudkit", "firestore", "gdrive", "s3"] },
      "endpoint": { "type": "string" },
      "credentials": { "type": "string" }  // Encrypted or app-specific
    }
  }
}
```

### Per-User Storage Registration

```
POST /xrpc/blue.catbird.mls.registerStorage
{
  "did": "did:plc:alice",
  "provider": {
    "type": "cloudkit",
    "endpoint": "icloud.com",
    "containerId": "..."
  }
}
```

DS stores mapping:
```sql
CREATE TABLE storage_providers (
    did TEXT PRIMARY KEY,
    provider_type TEXT NOT NULL,
    endpoint TEXT,
    config JSONB
);
```

When sending message, DS returns per-recipient storage info:
```json
{
  "recipients": [
    {
      "did": "did:plc:bob",
      "storage": {
        "type": "cloudkit",
        "zoneId": "inbox_bob"
      }
    },
    {
      "did": "did:plc:charlie",
      "storage": {
        "type": "firestore",
        "collectionPath": "users/charlie/inbox"
      }
    }
  ]
}
```

Client adapts based on provider type.

---

## 9. Implementation Roadmap

### Phase 1: iOS-Only, Shared Zone (Weeks 1-2)

**Goal**: MVP with CloudKit for small groups (≤10 users)

1. **Server Changes**:
   - Update `send_message` handler (return fan-out targets)
   - Remove ciphertext storage from `messages` table
   - Add `cloudkit_zone_id` to `conversations`

2. **iOS Client**:
   - Implement `CloudKitStorageProvider`
   - Integrate with existing `MLSManager`
   - Create/join CloudKit zones
   - Subscribe to zones for push

3. **Testing**:
   - 3-member group
   - Send/receive 100 messages
   - Offline/online sync

### Phase 2: Per-User Mailbox (Weeks 3-4)

**Goal**: Scale to 100+ member groups

1. **Server Changes**:
   - Add `cloudkit_inbox_zone` to `members` table
   - Implement fan-out logic in `send_message`
   - (Optional) Server-side CloudKit writes via Web Services

2. **iOS Client**:
   - Create personal inbox zone
   - Handle N writes per message (or DS does it)
   - Deduplicate on receive

3. **Testing**:
   - 50-member group
   - Concurrent sends
   - Performance profiling

### Phase 3: Android Support (Weeks 5-6)

**Goal**: Cross-platform storage

1. **Server Changes**:
   - Add `storage_provider` table
   - Multi-provider fan-out logic

2. **Android Client**:
   - Implement `FirestoreStorageProvider`
   - Kotlin wrapper for MLS FFI
   - Same UX as iOS

3. **Testing**:
   - iOS ↔ Android group chat
   - Mixed storage providers

---

## 10. Security & Privacy

### Threat Model

1. **CloudKit Compromise**:
   - Attacker gains access to iCloud data
   - **Mitigation**: MLS E2EE; all ciphertext, no plaintext
   - **Bonus**: Enable Advanced Data Protection (iOS 16+) for additional CloudKit encryption

2. **DS Compromise**:
   - Attacker gains server access
   - **Mitigation**: No ciphertext on server; only metadata (room IDs, DIDs, epochs)
   - **Still Visible**: Who talks to whom, when, group sizes

3. **Man-in-the-Middle**:
   - **Mitigation**: TLS for DS API, CloudKit uses HTTPS, MLS provides forward secrecy

4. **Client Compromise**:
   - **Mitigation**: MLS post-compromise security (PCS) via member removal + epoch advancement

### Privacy Considerations

- **CloudKit sees**: Record metadata (room IDs, timestamps, sizes)
- **CloudKit does NOT see**: Plaintext (MLS encrypted)
- **DS sees**: Membership roster, epochs, send timestamps
- **DS does NOT see**: Message content, ciphertext

**ATProto Identity**: DIDs are public-ish (resolvable); consider privacy implications.

---

## 11. Cost Analysis

### CloudKit (iOS)

- **Free tier**: 1 GB per user (iCloud storage)
- **Overage**: ~$0.10/GB/month (Apple's iCloud pricing)
- **Your 20 GB budget**: Supports ~100-200 active users at moderate usage

### Delivery Service (Your Server)

- **Compute**: Minimal (metadata only, no ciphertext processing)
- **Storage**: PostgreSQL for roster/key packages (~10 MB per 1000 users)
- **Bandwidth**: Low (no ciphertext transfer)
- **Hosting**: $5-20/month VPS or free tier (Fly.io, Railway)

**Total**: Mostly free for MVP, scales well under 20 GB.

---

## 12. Next Steps: Concrete Changes to Your Server

### File Changes

1. **`server/migrations/`**: Add new migration
   ```sql
   -- 20241022_add_cloudkit_zones.sql
   ALTER TABLE conversations ADD COLUMN cloudkit_zone_id TEXT;
   ALTER TABLE members ADD COLUMN cloudkit_inbox_zone TEXT;
   ALTER TABLE messages DROP COLUMN ciphertext;
   ALTER TABLE messages ADD COLUMN cloudkit_record_name TEXT;
   ALTER TABLE messages ADD COLUMN cloudkit_zone_id TEXT;
   ALTER TABLE messages ADD COLUMN hash TEXT;
   ALTER TABLE messages ADD COLUMN size BIGINT;
   DROP TABLE IF EXISTS blobs;
   ```

2. **`server/src/handlers/send_message.rs`**: Rewrite handler (see example above)

3. **`server/src/models.rs`**: Update models
   ```rust
   pub struct SendMessageInput {
       pub convo_id: String,
       pub epoch: i32,
       pub hash: String,
       pub size: i64,
   }
   
   pub struct RecipientTarget {
       pub did: String,
       pub cloudkit_zone_id: String,
   }
   ```

4. **`server/src/db.rs`**: Add helper functions
   ```rust
   pub async fn increment_message_seq(pool: &PgPool, convo_id: &str) -> Result<i32>;
   pub async fn create_message_metadata(pool: &PgPool, ...) -> Result<()>;
   ```

### iOS Client Files (New)

1. **`Catbird/Services/MLS/StorageProvider.swift`**: Protocol definition
2. **`Catbird/Services/MLS/CloudKitStorageProvider.swift`**: Implementation
3. **`Catbird/Services/MLS/CloudKitZoneManager.swift`**: Zone lifecycle
4. **`Catbird/Models/MLS/CloudKitModels.swift`**: Record helpers

### Testing

1. **Server**: Update tests in `server/tests/`
   - Test fan-out logic
   - Test metadata-only storage

2. **iOS**: XCTest for CloudKit provider
   - Mock CloudKit operations
   - Integration tests with real CloudKit (sandbox)

---

## 13. Summary & Recommendations

### What You Gain

✅ **Serverless Storage**: CloudKit handles message persistence, backup, sync
✅ **iOS-Native**: Tight integration with iCloud, APNs, Advanced Data Protection
✅ **Scalable**: Offload storage costs to Apple; your DS stays lightweight
✅ **E2EE Intact**: MLS ciphertext in CloudKit; server never sees plaintext
✅ **Multi-Platform Ready**: Abstract storage layer supports Android later

### What You Trade

⚠️ **Apple Lock-In** (iOS-only initially): Need Android parallel path
⚠️ **CloudKit Limits**: ~100 users with CKShare; needs mailbox model for more
⚠️ **Complexity**: More moving parts than simple DB storage
⚠️ **User Dependency**: Users need iCloud enabled

### Ideal For You If:

- ✅ You want **iOS-first** MVP
- ✅ You have a **20 GB budget** constraint
- ✅ You want **zero backend storage costs** early on
- ✅ You're okay with **iCloud dependency** for users
- ✅ You plan **Android support later** (multi-provider)

### Start Now:

1. **Modify server** (Phase 1 changes): 2-3 days
2. **Implement CloudKitStorageProvider** (iOS): 3-5 days
3. **Test 3-member group**: 1 day
4. **Deploy MVP**: 1 week total

---

## 14. Example Code: Minimal Working Server

Here's a minimal diff for your server:

```rust
// src/handlers/send_message.rs (simplified)

pub async fn send_message(
    State(state): State<AppState>,
    claims: JwtClaims,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, ApiError> {
    // Check membership
    db::require_member(&state.pool, &claims.sub, &input.convo_id).await?;

    // Check epoch
    let convo = db::get_conversation(&state.pool, &input.convo_id).await?;
    if input.epoch != convo.current_epoch {
        return Err(ApiError::EpochMismatch);
    }

    // Get members + zones
    let members = db::list_active_members(&state.pool, &input.convo_id).await?;
    let recipients = members.into_iter().map(|m| RecipientTarget {
        did: m.member_did,
        cloudkit_zone_id: format!("inbox_{}", m.member_did),
    }).collect();

    // Increment seq
    let seq = db::next_seq(&state.pool, &input.convo_id).await?;

    // Log metadata (optional)
    db::log_message_meta(
        &state.pool,
        &input.convo_id,
        &claims.sub,
        input.epoch,
        seq,
        &input.hash,
    ).await?;

    Ok(Json(SendMessageOutput {
        recipients,
        seq,
        server_time: chrono::Utc::now().to_rfc3339(),
    }))
}
```

That's it. Your server is now a thin DS.

---

## Questions & Next Actions

**Ask yourself**:
1. Do I want iOS-only MVP first? → Yes → Start Phase 1
2. Do I need 100+ member groups now? → No → Use shared zones
3. Am I okay with CloudKit dependency? → Yes → Proceed
4. Do I need Android soon? → Plan Phase 3 in parallel

**I can help you**:
- [ ] Write the complete server migration
- [ ] Draft the CloudKitStorageProvider Swift code
- [ ] Design the zone/record schema
- [ ] Build the iOS integration layer
- [ ] Plan the Android storage provider

Let me know which part you want to tackle first!

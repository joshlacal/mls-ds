# MLS Admin & Recovery: Complete Implementation Plan v2

**Date:** 2025-11-07  
**Status:** Planning Complete - Ready for Implementation  
**Priority:** P0 (Security + UX Critical)

---

## Executive Summary

This plan covers:
1. ✅ **Admin System** - Two-layer enforcement (server policy + client verification)
2. ✅ **Sender Security** - JWT-derived sender (no spoofing)
3. ✅ **Reporting** - E2EE reports to admins
4. ✅ **Bluesky Blocks** - Hard blocks enforced
5. ✨ **NEW: iCloud Keychain Recovery** - Seamless rejoin after reinstall
6. ✨ **NEW: Admin Message Hiding** - Tombstone (not deletion)

---

## Part 1: Admin Capabilities & Limitations

### What Admins CAN Do

1. **Promote/Demote Members** ✅
   - Server authorization + encrypted roster update
   - Multiple admins supported
   - Cannot demote last admin

2. **Remove (Kick) Members** ✅
   - Admin issues MLS Remove commit
   - Server authorizes first
   - Kicked member loses decrypt capability immediately

3. **View/Resolve Reports** ✅
   - E2EE reports (only admins can decrypt)
   - Server stores metadata only
   - Admin decides: remove member or dismiss

4. **Hide Messages (Tombstone)** ✨ NEW
   - Mark message as "removed by admin"
   - Server metadata flag
   - Clients honor by hiding in UI
   - **Note:** Cannot truly delete (E2EE limitation)

### What Admins CANNOT Do

❌ **Delete Messages** - Impossible in E2EE  
  - Each client stores own plaintext  
  - Server only has ciphertext  
  - Even if server deletes, clients keep copies  

❌ **Read Messages Before Joining** - MLS forward secrecy  
  - Admin promoted today can't decrypt yesterday's messages  
  - New epoch keys exclude past messages  

❌ **Decrypt Reports They Weren't Admin For** - Time-bound keys  
  - Report encrypted with current MLS group key  
  - If admin demoted before report, can't decrypt  

---

## Part 2: Message Hiding (Not Deletion)

### Architecture

```
┌─────────────────────────────────────────────┐
│ Server: Tombstone Metadata                  │
├─────────────────────────────────────────────┤
│ messages table:                             │
│ - tombstoned_by_admin BOOLEAN               │
│ - tombstoned_by_did TEXT                    │
│ - tombstoned_at TIMESTAMPTZ                 │
│ - tombstone_reason TEXT                     │
│                                             │
│ Note: ciphertext remains unchanged          │
└─────────────────────────────────────────────┘
         ↓ API returns tombstone flag
┌─────────────────────────────────────────────┐
│ Client: Honor Tombstone in UI              │
├─────────────────────────────────────────────┤
│ if message.tombstonedByAdmin {              │
│     show "[Message removed by admin]"       │
│     optionally: delete local plaintext      │
│ }                                           │
└─────────────────────────────────────────────┘
```

### Database Schema Addition

```sql
-- Add to existing messages table
ALTER TABLE messages
    ADD COLUMN tombstoned_by_admin BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN tombstoned_by_did TEXT,
    ADD COLUMN tombstoned_at TIMESTAMPTZ,
    ADD COLUMN tombstone_reason TEXT CHECK (LENGTH(tombstone_reason) <= 500);

CREATE INDEX idx_messages_tombstoned 
    ON messages(convo_id, tombstoned_by_admin) 
    WHERE tombstoned_by_admin = true;
```

### New Lexicon: `tombstoneMessage`

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.tombstoneMessage",
  "description": "Mark a message as removed by admin (metadata only, cannot truly delete E2EE message)",
  "defs": {
    "main": {
      "type": "procedure",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "messageId"],
          "properties": {
            "convoId": { "type": "string" },
            "messageId": { "type": "string" },
            "reason": {
              "type": "string",
              "maxLength": 500,
              "description": "Reason for hiding (logged in audit)"
            }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["ok"],
          "properties": {
            "ok": { "type": "boolean" }
          }
        }
      },
      "errors": [
        { "name": "NotAdmin" },
        { "name": "MessageNotFound" },
        { "name": "AlreadyTombstoned" }
      ]
    }
  }
}
```

### Server Handler

```rust
pub async fn tombstone_message(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<TombstoneMessageInput>,
) -> Result<Json<TombstoneMessageOutput>, StatusCode> {
    // 1. Verify caller is admin
    auth::require_admin(&pool, &input.convo_id, &auth_user.did).await?;
    
    // 2. Mark message as tombstoned
    sqlx::query(
        "UPDATE messages 
         SET tombstoned_by_admin = true,
             tombstoned_by_did = $1,
             tombstoned_at = NOW(),
             tombstone_reason = $2
         WHERE id = $3 AND convo_id = $4"
    )
    .bind(&auth_user.did)
    .bind(&input.reason)
    .bind(&input.message_id)
    .bind(&input.convo_id)
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // 3. Log admin action
    log_admin_action(
        &pool,
        &input.convo_id,
        &auth_user.did,
        "tombstone_message",
        Some(&input.message_id),
        input.reason.as_deref(),
    ).await?;
    
    // 4. Broadcast tombstone event to all clients
    sse_state.broadcast_to_convo(&input.convo_id, &StreamEvent::MessageTombstoned {
        convo_id: input.convo_id.clone(),
        message_id: input.message_id.clone(),
        tombstoned_by: auth_user.did.clone(),
    }).await;
    
    Ok(Json(TombstoneMessageOutput { ok: true }))
}
```

### Client Handling

```swift
extension MessageView {
    var body: some View {
        if message.tombstonedByAdmin {
            HStack {
                Image(systemName: "eye.slash.fill")
                    .foregroundStyle(.secondary)
                Text("[Message removed by admin]")
                    .foregroundStyle(.secondary)
                    .italic()
            }
            .padding(.vertical, 8)
        } else {
            // Normal message UI
        }
    }
}
```

**User Disclosure:**

```swift
Text("⚠️ Important: Messages cannot be truly deleted in end-to-end encrypted chats. Even when hidden by admins, members who already saw the message keep their copy. Think before you send.")
    .font(.caption)
    .foregroundStyle(.secondary)
    .padding()
```

---

## Part 3: iCloud Keychain Recovery

### Architecture

```
┌────────────────────────────────────────────┐
│ iCloud Keychain (Apple ID Sync)           │
├────────────────────────────────────────────┤
│ 1. Master Identity Key (Ed25519)          │
│    - Private key for DID                   │
│    - Backed up once per device             │
│    - Used for MLS credential signing       │
│                                            │
│ 2. MLS Conversation States (periodic)     │
│    - Serialized OpenMLS group              │
│    - Current epoch secrets                 │
│    - Member snapshot                       │
│    - Backed up after epoch changes         │
└────────────────────────────────────────────┘
```

### Keychain Manager

```swift
import KeychainAccess

class MLSKeychainManager {
    private let keychain = Keychain(service: "blue.catbird.mls")
        .accessibility(.afterFirstUnlock)
        .synchronizable(true)  // ✅ iCloud sync enabled
    
    // MARK: - Master Identity
    
    struct MasterIdentity: Codable {
        let privateKey: Data  // Ed25519 private
        let publicKey: Data
        let did: String
        let createdAt: Date
        let deviceId: String
    }
    
    func saveMasterIdentity(_ identity: MasterIdentity) throws {
        let data = try JSONEncoder().encode(identity)
        try keychain.set(data, key: "masterIdentity")
    }
    
    func getMasterIdentity() throws -> MasterIdentity? {
        guard let data = try keychain.getData("masterIdentity") else {
            return nil
        }
        return try JSONDecoder().decode(MasterIdentity.self, from: data)
    }
    
    // MARK: - MLS State Backup
    
    struct MLSStateBackup: Codable {
        let convoId: String
        let epoch: UInt64
        let groupState: Data  // Serialized from OpenMLS
        let members: [String]  // DID snapshot
        let backedUpAt: Date
    }
    
    func backupMLSState(_ backup: MLSStateBackup) throws {
        let key = "mlsState.\(backup.convoId)"
        let data = try JSONEncoder().encode(backup)
        try keychain.set(data, key: key)
    }
    
    func getMLSState(convoId: String) throws -> MLSStateBackup? {
        let key = "mlsState.\(convoId)"
        guard let data = try keychain.getData(key) else {
            return nil
        }
        return try JSONDecoder().decode(MLSStateBackup.self, from: data)
    }
    
    func listAllBackedUpConversations() throws -> [MLSStateBackup] {
        // Note: KeychainAccess doesn't support prefix enumeration
        // Need to track conversation IDs separately or use Security framework directly
        var backups: [MLSStateBackup] = []
        
        // Query all keys (requires lower-level Security framework)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "blue.catbird.mls",
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return backups
        }
        
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix("mlsState."),
                  let data = item[kSecValueData as String] as? Data else {
                continue
            }
            
            if let backup = try? JSONDecoder().decode(MLSStateBackup.self, from: data) {
                backups.append(backup)
            }
        }
        
        return backups
    }
}
```

### Backup Strategy

```swift
extension MLSConversationManager {
    func schedulePeriodicBackup() {
        // Backup every hour while app is active
        Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            Task {
                await self?.backupAllConversations()
            }
        }
    }
    
    func backupAllConversations() async {
        for convo in activeConversations {
            await backupIfNeeded(convo)
        }
    }
    
    func backupIfNeeded(_ convo: MLSConversation) async {
        let shouldBackup = 
            convo.epochsSinceLastBackup >= 3 ||  // Every 3 epochs
            Date().timeIntervalSince(convo.lastBackupAt) > 3600  // Or hourly
        
        guard shouldBackup else { return }
        
        do {
            let groupState = try convo.mlsGroup.export()
            
            let backup = MLSKeychainManager.MLSStateBackup(
                convoId: convo.id,
                epoch: convo.mlsGroup.epoch(),
                groupState: groupState,
                members: convo.members.map(\.did),
                backedUpAt: Date()
            )
            
            try keychainManager.backupMLSState(backup)
            
            convo.lastBackupAt = Date()
            convo.epochsSinceLastBackup = 0
        } catch {
            print("Backup failed for \(convo.id): \(error)")
        }
    }
    
    // Trigger backup after important events
    func onEpochAdvanced(_ convo: MLSConversation) async {
        convo.epochsSinceLastBackup += 1
        await backupIfNeeded(convo)
    }
}
```

### Restore Flow

```swift
class MLSRestoreCoordinator: ObservableObject {
    @Published var restoreState: RestoreState = .notStarted
    
    enum RestoreState {
        case notStarted
        case checking
        case noBackup
        case restoring(progress: Double)
        case complete(result: RestoreResult)
        case failed(Error)
    }
    
    struct RestoreResult {
        let fullyRestored: [String]  // Ready immediately
        let needsRejoin: [String]    // Waiting for admin
    }
    
    func attemptRestore() async {
        restoreState = .checking
        
        do {
            // 1. Check for master identity
            guard let identity = try keychainManager.getMasterIdentity() else {
                restoreState = .noBackup
                return
            }
            
            // 2. Get all backed up conversations
            let backups = try keychainManager.listAllBackedUpConversations()
            
            guard !backups.isEmpty else {
                restoreState = .noBackup
                return
            }
            
            restoreState = .restoring(progress: 0.0)
            
            // 3. Attempt to restore each conversation
            var fullyRestored: [String] = []
            var needsRejoin: [String] = []
            
            for (index, backup) in backups.enumerated() {
                let progress = Double(index + 1) / Double(backups.count)
                restoreState = .restoring(progress: progress)
                
                // Try to import MLS state
                guard let group = try? MLSGroup.import(backup.groupState) else {
                    // Backup corrupted
                    needsRejoin.append(backup.convoId)
                    continue
                }
                
                // Check if state is current
                let serverEpoch = try await mlsClient.getEpoch(convoId: backup.convoId)
                
                if group.epoch() == serverEpoch.epoch {
                    // ✅ State is current - can use immediately
                    await conversationManager.adoptGroup(group, convoId: backup.convoId)
                    fullyRestored.append(backup.convoId)
                } else {
                    // ⚠️ State is stale - request rejoin
                    try await mlsClient.requestRejoin(
                        convoId: backup.convoId,
                        keyPackage: group.generateKeyPackage()
                    )
                    needsRejoin.append(backup.convoId)
                }
            }
            
            let result = RestoreResult(
                fullyRestored: fullyRestored,
                needsRejoin: needsRejoin
            )
            restoreState = .complete(result: result)
            
        } catch {
            restoreState = .failed(error)
        }
    }
}
```

### UX Flow

```swift
struct RestoreView: View {
    @StateObject var restoreCoordinator = MLSRestoreCoordinator()
    
    var body: some View {
        VStack(spacing: 24) {
            switch restoreCoordinator.restoreState {
            case .notStarted, .checking:
                ProgressView()
                Text("Checking for backups...")
                
            case .noBackup:
                VStack(spacing: 16) {
                    Image(systemName: "icloud.slash")
                        .font(.system(size: 60))
                        .foregroundStyle(.secondary)
                    Text("No Backup Found")
                        .font(.title2.bold())
                    Text("You'll start fresh with end-to-end encryption.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                
            case .restoring(let progress):
                ProgressView(value: progress)
                Text("Restoring conversations...")
                Text("\(Int(progress * 100))%")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                
            case .complete(let result):
                RestoreResultView(result: result)
                
            case .failed(let error):
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 60))
                        .foregroundStyle(.red)
                    Text("Restore Failed")
                        .font(.title2.bold())
                    Text(error.localizedDescription)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
        }
        .padding()
        .task {
            await restoreCoordinator.attemptRestore()
        }
    }
}

struct RestoreResultView: View {
    let result: MLSRestoreCoordinator.RestoreResult
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.icloud.fill")
                .font(.system(size: 60))
                .foregroundStyle(.green)
            
            Text("Conversations Restored")
                .font(.title2.bold())
            
            if !result.fullyRestored.isEmpty {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("\(result.fullyRestored.count) Ready", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                        Text("You can use these conversations immediately.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            
            if !result.needsRejoin.isEmpty {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("\(result.needsRejoin.count) Pending", systemImage: "clock.fill")
                            .foregroundStyle(.orange)
                        Text("Waiting for admin approval. You'll be added back automatically.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            
            Button("Continue") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}
```

### Privacy & Security

**Disclosure to User:**

```swift
struct BackupPrivacySheet: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("iCloud Backup")
                .font(.title2.bold())
            
            Text("Your encryption keys are securely backed up to iCloud Keychain, protected by your device passcode and Apple ID.")
            
            VStack(alignment: .leading, spacing: 12) {
                Label("Syncs across your Apple devices", systemImage: "icloud.fill")
                Label("Encrypted by Apple", systemImage: "lock.shield.fill")
                Label("Requires Face ID or passcode", systemImage: "faceid")
            }
            .foregroundStyle(.secondary)
            
            Divider()
            
            Text("This lets you seamlessly rejoin conversations if you reinstall the app.")
                .font(.callout)
            
            HStack {
                Button("Learn More") {
                    // Link to privacy doc
                }
                Spacer()
                Button("Enable Backup") {
                    // Enable and dismiss
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}
```

**Security Properties:**
- ✅ Apple manages encryption (256-bit AES)
- ✅ Requires device unlock
- ✅ Tied to Apple ID (recovery via Apple)
- ⚠️ Apple can access via legal process (disclose this)
- ⚠️ Requires iCloud account (some users opt out)

---

## Part 4: Updated Implementation Timeline

### Week 1: Security & Foundation

**Day 1-2: Sender Bug Fix**
- [ ] Fix sender_did NULL issue
- [ ] Update lexicon (sender in output)
- [ ] Deploy and verify

**Day 3-4: Admin Schema**
- [ ] Add is_admin to members
- [ ] Create reports table
- [ ] Create admin_actions table
- [ ] Add tombstoned_by_admin to messages

**Day 5: Keychain Setup**
- [ ] Implement MLSKeychainManager
- [ ] Add backup/restore methods
- [ ] Test iCloud sync

### Week 2: Server Implementation

**Day 6-7: Admin Handlers**
- [ ] promoteAdmin
- [ ] demoteAdmin
- [ ] removeMember
- [ ] tombstoneMessage (new)

**Day 8-9: Reporting Handlers**
- [ ] reportMember
- [ ] getReports
- [ ] resolveReport

**Day 10: Testing & Deployment**
- [ ] Unit tests
- [ ] Integration tests
- [ ] Deploy to staging

### Week 3: Client Implementation

**Day 11-12: Petrel Generation**
- [ ] Run generator with new lexicons
- [ ] Verify generated types
- [ ] Add convenience methods

**Day 13-14: Catbird App - Admin UI**
- [ ] Admin roster tracking
- [ ] Admin badges in UI
- [ ] Promote/demote flows
- [ ] Remove member flow
- [ ] Tombstone message flow

**Day 15: Catbird App - Recovery**
- [ ] RestoreCoordinator
- [ ] Backup scheduling
- [ ] Restore UX flow

### Week 4: Polish & Launch

**Day 16-17: Testing**
- [ ] Full admin flow testing
- [ ] Backup/restore testing
- [ ] Security audit

**Day 18-19: Documentation**
- [ ] User-facing docs
- [ ] Admin guide
- [ ] Privacy policy updates

**Day 20: Launch**
- [ ] Production deployment
- [ ] Monitor metrics
- [ ] User feedback

---

## Part 5: Success Metrics

### Security
- ✅ 0 messages with NULL sender_did
- ✅ 0 unauthorized admin actions
- ✅ 100% of reports encrypted

### UX
- 🎯 90%+ users opt into iCloud backup
- 🎯 <30s average restore time
- 🎯 85%+ successful restores on first try

### Moderation
- 🎯 <5min average report response time (by admins)
- 🎯 95% of removals complete within 1 epoch
- 🎯 Clear UX for message tombstoning

---

## Questions for Review

1. **Message tombstoning**: Should we add a client-side "appeal" flow for tombstoned messages?
2. **Backup frequency**: Is hourly too aggressive? Could we do per-epoch only?
3. **Admin roster conflicts**: What if client's cached roster diverges from server?
4. **Privacy disclosure**: Is our iCloud backup warning clear enough?

Ready to start implementation? Say "implement week 1" to begin! 🚀

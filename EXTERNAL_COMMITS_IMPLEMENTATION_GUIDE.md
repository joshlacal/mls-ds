# External Commits Implementation Guide

**Practical step-by-step guide for developers**

---

## Prerequisites

- OpenMLS 0.7.1 installed
- Rust stable (1.90.0+) or nightly if needed for FFI
- PostgreSQL database access
- Existing MLS conversation infrastructure working

---

## Part 1: Server Implementation

### Step 1: Upgrade OpenMLS

```bash
cd /home/ubuntu/mls/server

# Update Cargo.toml
sed -i 's/openmls = "0.6"/openmls = "0.7.1"/' Cargo.toml

# Update lockfile
cargo update -p openmls

# Check for breaking changes
cargo check 2>&1 | tee upgrade_errors.txt

# Build
cargo build
```

**Common issues:**
- Method signature changes: Check compiler errors and update
- Import paths changed: Update `use openmls::...` statements
- New required parameters: Consult OpenMLS 0.7.1 docs

### Step 2: Database Migration

**File**: `server/migrations/YYYYMMDDHHMMSS_add_group_info.sql`

```sql
-- Add GroupInfo caching columns
ALTER TABLE conversations
ADD COLUMN group_info BYTEA DEFAULT NULL,
ADD COLUMN group_info_updated_at TIMESTAMPTZ DEFAULT NULL,
ADD COLUMN group_info_epoch INTEGER DEFAULT NULL;

-- Index for lookups
CREATE INDEX idx_conversations_group_info 
ON conversations(id, group_info_epoch) 
WHERE group_info IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN conversations.group_info IS 
'TLS-serialized GroupInfo for external commits. Regenerated on each epoch change.';
```

Run migration:
```bash
sqlx migrate run
```

### Step 3: GroupInfo Generation Module

**File**: `server/src/group_info.rs`

```rust
//! GroupInfo export and caching for external commits

use openmls::prelude::*;
use sqlx::PgPool;
use tracing::{debug, error, info};
use crate::{
    crypto::get_crypto_provider,
    error::{Error, Result},
    storage::load_mls_group,
};

/// Generate and cache GroupInfo for a conversation
pub async fn generate_and_cache_group_info(
    pool: &PgPool,
    convo_id: &str,
) -> Result<Vec<u8>> {
    debug!("Generating GroupInfo for conversation {}", convo_id);
    
    // 1. Load current MLS group state
    let mls_group = load_mls_group(pool, convo_id).await?;
    let current_epoch = mls_group.epoch().as_u64();
    
    // 2. Get crypto provider
    let crypto_provider = get_crypto_provider();
    
    // 3. Export GroupInfo with ratchet tree
    let group_info = mls_group
        .export_group_info(
            &crypto_provider,
            &get_signer()?,
            true, // with_ratchet_tree
        )
        .map_err(|e| {
            error!("Failed to export GroupInfo: {}", e);
            Error::InternalError(format!("GroupInfo export failed: {}", e))
        })?;
    
    // 4. Serialize
    let group_info_bytes = group_info
        .tls_serialize_detached()
        .map_err(|e| {
            error!("Failed to serialize GroupInfo: {}", e);
            Error::InternalError(format!("GroupInfo serialization failed: {}", e))
        })?;
    
    // 5. Cache in database
    sqlx::query!(
        "UPDATE conversations 
         SET group_info = $1,
             group_info_updated_at = NOW(),
             group_info_epoch = $2
         WHERE id = $3",
        &group_info_bytes,
        current_epoch as i32,
        convo_id
    )
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to cache GroupInfo: {}", e);
        Error::DatabaseError(e)
    })?;
    
    info!(
        "Cached GroupInfo for {} at epoch {}",
        convo_id, current_epoch
    );
    
    Ok(group_info_bytes)
}

/// Fetch cached GroupInfo, regenerating if stale
pub async fn get_group_info(
    pool: &PgPool,
    convo_id: &str,
) -> Result<(Vec<u8>, i32)> {
    let row = sqlx::query!(
        "SELECT group_info, group_info_epoch, group_info_updated_at
         FROM conversations
         WHERE id = $1",
        convo_id
    )
    .fetch_one(pool)
    .await?;
    
    let epoch = row.group_info_epoch.unwrap_or(0);
    
    // Check if exists and is fresh (< 5 minutes old)
    if let Some(cached_bytes) = row.group_info {
        if let Some(updated_at) = row.group_info_updated_at {
            let age = chrono::Utc::now() - updated_at;
            if age.num_minutes() < 5 {
                debug!("Using cached GroupInfo for {}", convo_id);
                return Ok((cached_bytes, epoch));
            }
        }
    }
    
    // Regenerate if missing or stale
    info!("Regenerating stale GroupInfo for {}", convo_id);
    let fresh_bytes = generate_and_cache_group_info(pool, convo_id).await?;
    Ok((fresh_bytes, epoch))
}

/// Get signer for GroupInfo (reuse existing credential)
fn get_signer() -> Result<Signer> {
    // IMPLEMENTATION NOTE: Use your existing credential loading logic
    // This should return the server's signing credential used for the group
    todo!("Load server credential from your existing auth system")
}
```

### Step 4: Update Commit Handlers

**Pattern to add to ALL commit handlers:**

```rust
// In handlers/add_members.rs, remove_member.rs, leave_convo.rs, etc.

use crate::group_info::generate_and_cache_group_info;

// After successful commit and merge
// ... existing commit processing code ...

// NEW: Regenerate GroupInfo for next external join
if let Err(e) = generate_and_cache_group_info(pool, &input.convo_id).await {
    // Log but don't fail the main operation
    tracing::warn!(
        "Failed to regenerate GroupInfo after commit: {}. External joins may be delayed.",
        e
    );
}
```

**Files to modify:**
1. `server/src/handlers/add_members.rs` - After adding member
2. `server/src/handlers/remove_member.rs` - After removing member  
3. `server/src/handlers/leave_convo.rs` - After member leaves
4. `server/src/handlers/confirm_welcome.rs` - After new member confirms
5. Any custom commit handlers

### Step 5: GetGroupInfo Handler

**File**: `server/src/handlers/get_group_info.rs`

```rust
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::{
    auth::AuthUser,
    error::{Error, Result},
    group_info,
    models::AppState,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupInfoInput {
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupInfoOutput {
    pub group_info: String,  // base64
    pub epoch: i32,
    pub expires_at: String,  // RFC3339
}

pub async fn handle(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(input): Json<GetGroupInfoInput>,
) -> Result<Json<GetGroupInfoOutput>> {
    let pool = &state.pool;
    let did = &auth.did;
    
    // 1. Verify authorization
    verify_can_access_group_info(pool, &input.convo_id, did).await?;
    
    // 2. Fetch GroupInfo (cached or fresh)
    let (group_info_bytes, epoch) = group_info::get_group_info(pool, &input.convo_id).await?;
    
    // 3. Return with expiration time
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339();
    
    Ok(Json(GetGroupInfoOutput {
        group_info: base64::encode(&group_info_bytes),
        epoch,
        expires_at,
    }))
}

/// Verify user can fetch GroupInfo for this conversation
async fn verify_can_access_group_info(
    pool: &PgPool,
    convo_id: &str,
    did: &str,
) -> Result<()> {
    // Check if user is/was a member
    let member = sqlx::query!(
        "SELECT left_at 
         FROM members 
         WHERE convo_id = $1 AND user_did = $2
         ORDER BY joined_at DESC
         LIMIT 1",
        convo_id,
        did
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::Unauthorized("Not a member of this conversation".into()))?;
    
    // Allow current members
    if member.left_at.is_none() {
        return Ok(());
    }
    
    // Allow past members if left recently (within 30 days)
    let left_at = member.left_at.unwrap();
    let days_since = (chrono::Utc::now() - left_at).num_days();
    
    if days_since > 30 {
        return Err(Error::Unauthorized(
            "Membership expired (left more than 30 days ago)".into()
        ));
    }
    
    Ok(())
}
```

### Step 6: ProcessExternalCommit Handler

**File**: `server/src/handlers/process_external_commit.rs`

```rust
use axum::{extract::State, Json};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info};
use crate::{
    auth::AuthUser,
    crypto::get_crypto_provider,
    error::{Error, Result},
    group_info,
    models::AppState,
    storage::{load_mls_group, save_mls_group},
    fanout::fanout_commit,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessExternalCommitInput {
    pub convo_id: String,
    pub external_commit: String,  // base64-encoded MlsMessageOut
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessExternalCommitOutput {
    pub success: bool,
    pub epoch: i32,
    pub rejoined_at: String,
}

pub async fn handle(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(input): Json<ProcessExternalCommitInput>,
) -> Result<Json<ProcessExternalCommitOutput>> {
    let pool = &state.pool;
    let did = &auth.did;
    
    info!("Processing external commit for {} in {}", did, input.convo_id);
    
    // 1. Verify authorization (reuse from get_group_info)
    verify_can_rejoin(pool, &input.convo_id, did).await?;
    
    // 2. Decode commit message
    let commit_bytes = base64::decode(&input.external_commit)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;
    
    let mls_message_in = MlsMessageIn::tls_deserialize_exact(&commit_bytes)
        .map_err(|e| Error::BadRequest(format!("Invalid MLS message: {}", e)))?;
    
    // 3. Load current group state
    let mut mls_group = load_mls_group(pool, &input.convo_id).await?;
    let old_epoch = mls_group.epoch().as_u64();
    
    // 4. Process external commit
    let crypto_provider = get_crypto_provider();
    let processed_message = mls_group
        .process_message(&crypto_provider, mls_message_in)
        .map_err(|e| {
            error!("External commit processing failed: {}", e);
            Error::InvalidCommit(format!("Processing failed: {}", e))
        })?;
    
    // 5. Extract staged commit
    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => {
            return Err(Error::BadRequest(
                "Message is not a valid commit".into()
            ))
        }
    };
    
    // 6. Validate commit adds the correct user
    let new_member_did = extract_added_member_did(&staged_commit)?;
    if !new_member_did.starts_with(&format!("{}#", did)) {
        return Err(Error::Unauthorized(
            format!("External commit must add your own device. Expected prefix: '{}#', got: '{}'", 
                    did, new_member_did)
        ));
    }
    
    debug!("External commit adds device: {}", new_member_did);
    
    // 7. Merge staged commit into group
    mls_group
        .merge_staged_commit(&crypto_provider, *staged_commit)
        .map_err(|e| {
            error!("Failed to merge external commit: {}", e);
            Error::InternalError(format!("Merge failed: {}", e))
        })?;
    
    let new_epoch = mls_group.epoch().as_u64();
    info!("External commit merged: {} → epoch {}", input.convo_id, new_epoch);
    
    // 8. Save updated group state
    save_mls_group(pool, &input.convo_id, &mls_group).await?;
    
    // 9. Update members table
    let device_id = extract_device_id(&new_member_did)?;
    let now = chrono::Utc::now();
    
    sqlx::query!(
        "INSERT INTO members (convo_id, member_mls_did, user_did, device_id, joined_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (convo_id, member_mls_did)
         DO UPDATE SET 
             left_at = NULL,
             joined_at = $5",
        input.convo_id,
        new_member_did,
        did,
        device_id,
        now
    )
    .execute(pool)
    .await?;
    
    // 10. Regenerate GroupInfo for next rejoiner
    if let Err(e) = group_info::generate_and_cache_group_info(pool, &input.convo_id).await {
        error!("Failed to regenerate GroupInfo: {}", e);
        // Continue - this is not critical
    }
    
    // 11. Fanout to other members
    fanout_commit(pool, &input.convo_id, &commit_bytes, new_epoch as i32).await?;
    
    Ok(Json(ProcessExternalCommitOutput {
        success: true,
        epoch: new_epoch as i32,
        rejoined_at: now.to_rfc3339(),
    }))
}

/// Extract DID from staged commit's Add proposals
fn extract_added_member_did(commit: &StagedCommit) -> Result<String> {
    for proposal in commit.add_proposals() {
        let key_package = proposal.key_package();
        let credential = key_package
            .leaf_node()
            .credential();
        
        match credential.credential_type() {
            CredentialType::Basic(basic_cred) => {
                let identity = String::from_utf8(basic_cred.identity().to_vec())
                    .map_err(|e| Error::InvalidCommit(
                        format!("Invalid UTF-8 in identity: {}", e)
                    ))?;
                return Ok(identity);
            }
            _ => {
                return Err(Error::InvalidCommit(
                    "Unsupported credential type".into()
                ))
            }
        }
    }
    
    Err(Error::InvalidCommit("No member added in commit".into()))
}

/// Extract device_id from full DID (did:plc:user#device-id)
fn extract_device_id(full_did: &str) -> Result<String> {
    full_did
        .split('#')
        .nth(1)
        .map(String::from)
        .ok_or_else(|| Error::InvalidCommit(
            format!("Invalid DID format, expected '#': {}", full_did)
        ))
}

/// Verify user can rejoin (authorization check)
async fn verify_can_rejoin(
    pool: &PgPool,
    convo_id: &str,
    did: &str,
) -> Result<()> {
    // Same logic as verify_can_access_group_info
    // Could be refactored into shared function
    
    let member = sqlx::query!(
        "SELECT left_at, banned_at
         FROM members
         WHERE convo_id = $1 AND user_did = $2
         ORDER BY joined_at DESC
         LIMIT 1",
        convo_id,
        did
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::Unauthorized("Not a member of this conversation".into()))?;
    
    // Reject if banned
    if member.banned_at.is_some() {
        return Err(Error::Unauthorized("User is banned from this conversation".into()));
    }
    
    // Allow current members
    if member.left_at.is_none() {
        return Ok(());
    }
    
    // Allow past members within grace period
    let left_at = member.left_at.unwrap();
    let days_since = (chrono::Utc::now() - left_at).num_days();
    
    if days_since > 30 {
        return Err(Error::Unauthorized(
            "Membership expired (>30 days since leaving)".into()
        ));
    }
    
    Ok(())
}
```

### Step 7: Register New Handlers

**File**: `server/src/handlers/mod.rs`

```rust
// Add new modules
pub mod get_group_info;
pub mod process_external_commit;

// In your router setup function:
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // ... existing routes ...
        .route(
            "/xrpc/blue.catbird.mls.getGroupInfo",
            post(get_group_info::handle)
        )
        .route(
            "/xrpc/blue.catbird.mls.processExternalCommit",
            post(process_external_commit::handle)
        )
        // ... rest of routes ...
        .with_state(state)
}
```

### Step 8: Add to lib.rs

**File**: `server/src/lib.rs`

```rust
pub mod group_info;
```

---

## Part 2: Client Implementation (Swift)

### Step 1: FFI Wrapper for External Commits

**File**: `MLSClient+ExternalCommit.swift`

```swift
import Foundation

extension MLSClient {
    
    /// Join group using external commit (instant rejoin)
    public func joinByExternalCommit(
        groupInfo: Data,
        conversationId: String
    ) async throws -> MLSGroup {
        // 1. Deserialize GroupInfo
        let groupInfoFFI = try groupInfo.withUnsafeBytes { buffer in
            try ffi_deserialize_group_info(buffer.baseAddress!, buffer.count)
        }
        defer { ffi_free_group_info(groupInfoFFI) }
        
        // 2. Load our credential
        let credentialData = try loadCredential(for: deviceId)
        
        // 3. Call OpenMLS FFI to generate external commit
        var commitData: UnsafeMutablePointer<UInt8>?
        var commitLen: Int = 0
        var mlsGroupHandle: OpaquePointer?
        
        let result = try credentialData.withUnsafeBytes { credBuffer in
            ffi_join_by_external_commit(
                groupInfoFFI,
                credBuffer.baseAddress!,
                credBuffer.count,
                &mlsGroupHandle,
                &commitData,
                &commitLen
            )
        }
        
        guard result == 0, let groupHandle = mlsGroupHandle else {
            throw MLSError.externalCommitFailed("FFI call failed")
        }
        defer { if let data = commitData { ffi_free_buffer(data) } }
        
        // 4. Package commit for server
        let externalCommit = Data(bytes: commitData!, count: commitLen)
        
        // 5. Submit to server
        try await submitExternalCommit(
            conversationId: conversationId,
            commitData: externalCommit
        )
        
        // 6. Wrap in MLSGroup object
        let group = MLSGroup(
            handle: groupHandle,
            conversationId: conversationId,
            storage: self.storage
        )
        
        // 7. Save to local storage
        try await group.save()
        
        return group
    }
    
    /// Submit external commit to server
    private func submitExternalCommit(
        conversationId: String,
        commitData: Data
    ) async throws {
        let request = ProcessExternalCommitRequest(
            convoId: conversationId,
            externalCommit: commitData.base64EncodedString()
        )
        
        let response: ProcessExternalCommitResponse = try await apiClient.post(
            endpoint: "blue.catbird.mls.processExternalCommit",
            body: request
        )
        
        guard response.success else {
            throw MLSError.serverRejectedCommit("Server rejected external commit")
        }
        
        logger.info("External commit succeeded, new epoch: \(response.epoch)")
    }
}

// MARK: - API Models

struct ProcessExternalCommitRequest: Codable {
    let convoId: String
    let externalCommit: String
}

struct ProcessExternalCommitResponse: Codable {
    let success: Bool
    let epoch: Int
    let rejoinedAt: String
}
```

### Step 2: High-Level Rejoin API

**File**: `ConversationManager+Rejoin.swift`

```swift
extension ConversationManager {
    
    /// Rejoin conversation after app reinstall (uses external commit)
    public func rejoinConversation(_ conversationId: String) async throws {
        logger.info("Rejoining conversation: \(conversationId)")
        
        do {
            // Try instant external commit first
            try await rejoinUsingExternalCommit(conversationId)
            logger.info("✅ Instant rejoin successful via external commit")
            
        } catch let error as MLSError where error.isEpochMismatch {
            // GroupInfo was stale, retry once
            logger.warning("Epoch mismatch, retrying with fresh GroupInfo")
            try await rejoinUsingExternalCommit(conversationId)
            
        } catch {
            // Fall back to legacy rejoin flow
            logger.warning("External commit failed: \(error), falling back to legacy rejoin")
            try await rejoinUsingLegacyFlow(conversationId)
        }
    }
    
    /// Modern rejoin using external commits (instant)
    private func rejoinUsingExternalCommit(_ conversationId: String) async throws {
        // 1. Fetch GroupInfo from server
        let groupInfoResponse: GetGroupInfoResponse = try await apiClient.get(
            endpoint: "blue.catbird.mls.getGroupInfo",
            parameters: ["convoId": conversationId]
        )
        
        guard let groupInfoData = Data(base64Encoded: groupInfoResponse.groupInfo) else {
            throw MLSError.invalidGroupInfo("Failed to decode base64")
        }
        
        logger.debug("Fetched GroupInfo for epoch \(groupInfoResponse.epoch)")
        
        // 2. Generate and submit external commit
        let group = try await mlsClient.joinByExternalCommit(
            groupInfo: groupInfoData,
            conversationId: conversationId
        )
        
        // 3. Update local state
        await conversationStorage.addConversation(
            id: conversationId,
            group: group
        )
        
        // 4. Notify UI
        NotificationCenter.default.post(
            name: .conversationRejoined,
            object: conversationId
        )
    }
    
    /// Legacy rejoin flow (wait for Welcome message)
    private func rejoinUsingLegacyFlow(_ conversationId: String) async throws {
        // Your existing requestRejoin implementation
        try await requestRejoin(conversationId: conversationId)
        
        // Poll for Welcome message
        try await waitForWelcomeMessage(conversationId: conversationId)
    }
}

// MARK: - API Models

struct GetGroupInfoResponse: Codable {
    let groupInfo: String  // base64
    let epoch: Int
    let expiresAt: String
}

extension MLSError {
    var isEpochMismatch: Bool {
        // Check if error indicates epoch mismatch
        if case .serverError(let message) = self {
            return message.contains("EpochMismatch") || message.contains("epoch")
        }
        return false
    }
}
```

### Step 3: Auto-Recovery on App Launch

**File**: `AppDelegate.swift` or `App.swift`

```swift
class AppDelegate: UIApplicationDelegate {
    
    func applicationDidFinishLaunching(_ application: UIApplication) {
        Task {
            await recoverLostConversations()
        }
    }
    
    /// Detect and recover from lost MLS state
    private func recoverLostConversations() async {
        // 1. Check if identity exists but groups are missing
        guard let identity = try? await identityManager.loadIdentity(),
              let expectedConvos = try? await fetchExpectedConversations() else {
            return
        }
        
        // 2. Find conversations we should be in but don't have local state
        let localConvos = await conversationStorage.allConversationIds()
        let missingConvos = Set(expectedConvos).subtracting(localConvos)
        
        if missingConvos.isEmpty {
            logger.info("No missing conversations, all synced")
            return
        }
        
        logger.warning("Found \(missingConvos.count) conversations missing local state")
        
        // 3. Rejoin each missing conversation
        for convoId in missingConvos {
            do {
                try await conversationManager.rejoinConversation(convoId)
                logger.info("✅ Recovered conversation: \(convoId)")
            } catch {
                logger.error("❌ Failed to recover \(convoId): \(error)")
                // Continue with others
            }
        }
    }
    
    /// Fetch list of conversations we should be in (from server)
    private func fetchExpectedConversations() async throws -> [String] {
        let response: GetExpectedConversationsResponse = try await apiClient.get(
            endpoint: "blue.catbird.mls.getExpectedConversations"
        )
        return response.conversationIds
    }
}
```

---

## Part 3: Testing

### Server Tests

**File**: `server/tests/external_commit_test.rs`

```rust
use catbird_server::*;

#[tokio::test]
async fn test_external_commit_flow() {
    let pool = test_db_pool().await;
    
    // 1. Setup: Create conversation
    let convo_id = create_test_conversation(&pool, &["alice", "bob"]).await;
    
    // 2. Alice "loses" her device state (simulate reinstall)
    delete_local_state_for_user(&pool, "alice").await;
    
    // 3. Alice fetches GroupInfo
    let group_info = get_group_info(&pool, &convo_id, "alice")
        .await
        .expect("Should be able to fetch GroupInfo");
    
    // 4. Alice generates external commit
    let external_commit = generate_external_commit_for_alice(&group_info)
        .expect("Should generate valid external commit");
    
    // 5. Alice submits to server
    let result = process_external_commit(&pool, &convo_id, "alice", &external_commit)
        .await
        .expect("External commit should succeed");
    
    assert!(result.success);
    assert!(result.epoch > 0);
    
    // 6. Verify Alice is back in members table
    let is_member = check_is_member(&pool, &convo_id, "alice").await;
    assert!(is_member, "Alice should be rejoined");
    
    // 7. Verify Bob receives notification
    let bob_notifications = get_pending_commits(&pool, "bob").await;
    assert_eq!(bob_notifications.len(), 1, "Bob should have 1 pending commit");
}

#[tokio::test]
async fn test_unauthorized_external_commit() {
    let pool = test_db_pool().await;
    let convo_id = create_test_conversation(&pool, &["alice"]).await;
    
    // Try to join as Eve (never was member)
    let result = get_group_info(&pool, &convo_id, "eve").await;
    
    assert!(matches!(result, Err(Error::Unauthorized(_))));
}

#[tokio::test]
async fn test_expired_membership() {
    let pool = test_db_pool().await;
    let convo_id = create_test_conversation(&pool, &["alice", "bob"]).await;
    
    // Alice leaves
    leave_conversation(&pool, &convo_id, "alice").await;
    
    // Fast-forward 31 days
    time_travel_days(&pool, "alice", 31).await;
    
    // Try to rejoin
    let result = get_group_info(&pool, &convo_id, "alice").await;
    
    assert!(matches!(result, Err(Error::Unauthorized(_))));
}
```

### Client Tests

**File**: `Tests/ExternalCommitTests.swift`

```swift
import XCTest
@testable import CatbirdSDK

class ExternalCommitTests: XCTestCase {
    
    func testInstantRejoin() async throws {
        // 1. Setup: Create conversation
        let convo = try await createTestConversation(members: ["alice", "bob"])
        
        // 2. Alice deletes app and reinstalls
        try await alice.deleteLocalState()
        
        // 3. Alice rejoins using external commit
        let start = Date()
        try await alice.rejoinConversation(convo.id)
        let duration = Date().timeIntervalSince(start)
        
        // 4. Verify instant rejoin (< 1 second)
        XCTAssertLessThan(duration, 1.0, "External commit should be instant")
        
        // 5. Verify Alice can send/receive messages
        try await alice.sendMessage("I'm back!", to: convo.id)
        let messages = try await bob.fetchMessages(from: convo.id)
        XCTAssertEqual(messages.last?.text, "I'm back!")
    }
    
    func testFallbackToLegacyRejoin() async throws {
        // Simulate server not supporting external commits
        mockServer.disableExternalCommits()
        
        let convo = try await createTestConversation(members: ["alice", "bob"])
        try await alice.deleteLocalState()
        
        // Should gracefully fall back to legacy flow
        try await alice.rejoinConversation(convo.id)
        
        // Verify rejoin succeeded (even if slower)
        let isInConvo = try await alice.isInConversation(convo.id)
        XCTAssertTrue(isInConvo)
    }
    
    func testEpochMismatchRetry() async throws {
        let convo = try await createTestConversation(members: ["alice", "bob"])
        
        // Bob sends message (advances epoch) while Alice is fetching GroupInfo
        mockServer.interceptGroupInfoRequest { [bob] in
            try await bob.sendMessage("Surprise!", to: convo.id)
        }
        
        try await alice.deleteLocalState()
        
        // Should automatically retry with fresh GroupInfo
        try await alice.rejoinConversation(convo.id)
        
        // Verify success despite epoch change
        XCTAssertTrue(try await alice.isInConversation(convo.id))
    }
}
```

---

## Part 4: Deployment

### Pre-Deployment Checklist

```bash
# 1. Run all tests
cargo test --all
swift test

# 2. Check for panics/unwraps in production code
rg "unwrap\(\)|expect\(" server/src --type rust

# 3. Verify database migration
sqlx migrate run --database-url $DATABASE_URL

# 4. Load test external commits
k6 run tests/external_commit_load_test.js

# 5. Verify monitoring/alerting configured
curl https://your-server/metrics | grep external_commit
```

### Gradual Rollout

**Week 1: Internal Testing**
```swift
// Feature flag
let useExternalCommits = FeatureFlags.externalCommits && user.isInternal
```

**Week 2: Beta Users (10%)**
```swift
let useExternalCommits = FeatureFlags.externalCommits && user.isBeta
```

**Week 3: Gradual Rollout (10% → 50% → 100%)**
```swift
let useExternalCommits = FeatureFlags.externalCommits && 
                         user.id.hashValue % 100 < rolloutPercentage
```

### Monitoring Queries

```sql
-- External commit success rate (should be >99%)
SELECT 
    COUNT(*) FILTER (WHERE success = true) * 100.0 / COUNT(*) as success_rate
FROM external_commit_logs
WHERE created_at > NOW() - INTERVAL '1 hour';

-- Average rejoin latency
SELECT 
    AVG(EXTRACT(EPOCH FROM (rejoined_at - requested_at))) as avg_seconds
FROM rejoin_events
WHERE method = 'external_commit'
  AND created_at > NOW() - INTERVAL '1 hour';

-- Fallback rate (legacy rejoin usage)
SELECT 
    COUNT(*) FILTER (WHERE method = 'legacy') * 100.0 / COUNT(*) as fallback_rate
FROM rejoin_events
WHERE created_at > NOW() - INTERVAL '1 hour';
```

---

## Troubleshooting

### Common Issues

**1. "GroupInfo not available"**
- Cause: GroupInfo not cached yet
- Fix: Regenerate after conversation creation
```rust
// In create_convo handler
generate_and_cache_group_info(pool, &convo_id).await?;
```

**2. "EpochMismatch" errors**
- Cause: GroupInfo stale, epoch advanced
- Fix: Client retries with fresh GroupInfo (automatic)

**3. "Invalid MLS message"**
- Cause: Serialization issue or corrupt data
- Fix: Check base64 encoding/decoding

**4. "Not authorized to rejoin"**
- Cause: User left >30 days ago or is banned
- Fix: Verify membership policy is correct

**5. OpenMLS version mismatch**
- Cause: Client and server on different versions
- Fix: Upgrade both to 0.7.1

### Debug Logging

**Server:**
```rust
RUST_LOG=catbird_server::group_info=debug,catbird_server::handlers::process_external_commit=debug
```

**Client:**
```swift
MLSClient.logLevel = .debug
```

---

## Performance Optimization

### Caching Strategy

```rust
// Optional: Add in-memory cache for hot GroupInfos
use moka::future::Cache;

lazy_static! {
    static ref GROUP_INFO_CACHE: Cache<String, Vec<u8>> = 
        Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(60))
            .build();
}
```

### Parallel Processing

```rust
// If many users rejoining simultaneously
use tokio::task::JoinSet;

async fn batch_process_external_commits(commits: Vec<ExternalCommit>) {
    let mut set = JoinSet::new();
    
    for commit in commits {
        set.spawn(async move {
            process_external_commit_impl(commit).await
        });
    }
    
    while let Some(result) = set.join_next().await {
        // Handle result
    }
}
```

---

## Next Steps

1. ✅ Review this guide with team
2. ⬜ Set up test environment
3. ⬜ Implement server (Phase 1-3)
4. ⬜ Implement client (FFI + Swift)
5. ⬜ Write tests
6. ⬜ Internal testing
7. ⬜ Gradual rollout

**Questions?** Document them in GitHub issues or this guide.

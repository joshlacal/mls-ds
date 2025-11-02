# Idempotency & Two-Phase Commit Implementation Plan

## Overview
This document outlines the implementation of a tiered reliability approach:
- **Tier 1**: Idempotency keys for write operations
- **Tier 2**: Two-phase commit for `getWelcome`
- **Tier 3**: Natural idempotency for safe operations

## Server-Side Changes

### Phase 1: Database Migrations

#### Migration 1: Welcome Messages State Tracking
```sql
-- 20251102_001_welcome_state_tracking.sql
ALTER TABLE welcome_messages
  ADD COLUMN IF NOT EXISTS state VARCHAR(20) DEFAULT 'available',
  ADD COLUMN IF NOT EXISTS fetched_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP;

-- Migrate existing data
UPDATE welcome_messages
SET state = CASE
  WHEN consumed = true THEN 'consumed'
  ELSE 'available'
END
WHERE state IS NULL;

CREATE INDEX IF NOT EXISTS idx_welcome_state
  ON welcome_messages(convo_id, recipient_did, state);
```

#### Migration 2: Idempotency Keys
```sql
-- 20251102_002_idempotency_keys.sql
-- Add idempotency_key to write operations
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
  ADD CONSTRAINT unique_message_idempotency UNIQUE (idempotency_key);

ALTER TABLE conversations
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
  ADD CONSTRAINT unique_convo_idempotency UNIQUE (idempotency_key);

-- Track idempotency results (for operations without persistent result)
CREATE TABLE IF NOT EXISTS idempotency_cache (
  key TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  response_body JSONB NOT NULL,
  status_code INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires
  ON idempotency_cache(expires_at);
```

### Phase 2: New Endpoints

#### confirmWelcome Handler
```rust
// src/handlers/confirm_welcome.rs
pub struct ConfirmWelcomeRequest {
    pub convo_id: String,
    pub success: bool,
    pub error_details: Option<String>,
}

pub async fn confirm_welcome(...) -> Result<Json<ConfirmWelcomeOutput>, StatusCode> {
    // Mark welcome as consumed or failed
    // Log failures for debugging
}
```

### Phase 3: Idempotency Middleware

```rust
// src/middleware/idempotency.rs
pub struct IdempotencyLayer {
    redis: RedisPool,
    ttl: Duration,
}

// Check cache before processing
// Store result after processing
```

### Phase 4: Handler Updates

**Modified Handlers**:
- `getWelcome`: Add grace period fallback + state='in_flight'
- `sendMessage`: Accept idempotency_key
- `createConvo`: Accept idempotency_key
- `addMembers`: Accept idempotency_key
- `publishKeyPackage`: Accept idempotency_key
- `leaveConvo`: Add natural idempotency check

## Client-Side Changes (iOS/Swift)

### Phase 1: Update Lexicon Client

```swift
// Regenerate from updated lexicons
// New method: confirmWelcome(convoId:success:)
// Updated methods: All write ops now accept idempotencyKey param
```

### Phase 2: MLSAPIClient Updates

```swift
extension MLSAPIClient {
    // New method
    func confirmWelcome(
        convoId: String,
        success: Bool,
        errorDetails: String? = nil
    ) async throws {
        // POST to blue.catbird.mls.confirmWelcome
    }

    // Updated methods with idempotency keys
    func sendMessage(
        convoId: String,
        ciphertext: Data,
        epoch: Int,
        idempotencyKey: String = UUID().uuidString
    ) async throws -> SendMessageOutput

    func createConversation(
        members: [String],
        welcomeMessage: Data,
        metadata: ConversationMetadata,
        idempotencyKey: String = UUID().uuidString
    ) async throws -> CreateConvoOutput
}
```

### Phase 3: MLSConversationManager Logic

```swift
// Critical: Persist Welcome before processing
func initializeGroupFromWelcome(convoId: String) async throws {
    // 1. Fetch Welcome (server marks as 'in_flight')
    let welcome = try await apiClient.getWelcome(convoId: convoId)

    // 2. PERSIST TO STORAGE FIRST (NEW!)
    try await persistWelcomeToStorage(convoId: convoId, welcomeData: welcome.data)

    // 3. Attempt to process
    do {
        try mlsClient.joinGroup(
            identity: currentUserDID,
            welcomeData: welcome.data
        )

        // 4. Confirm success
        try await apiClient.confirmWelcome(convoId: convoId, success: true)

        // 5. Clean up persisted welcome
        try await deleteWelcomeFromStorage(convoId: convoId)

    } catch {
        // 6. Confirm failure (server keeps 'in_flight' for retry)
        try? await apiClient.confirmWelcome(
            convoId: convoId,
            success: false,
            errorDetails: error.localizedDescription
        )

        // Keep persisted welcome for retry
        throw error
    }
}

// New: Retry logic
func retryFailedWelcome(convoId: String) async throws {
    // 1. Load from storage
    guard let welcomeData = try await loadWelcomeFromStorage(convoId: convoId) else {
        // Fallback: Re-fetch from server (5 min grace period)
        return try await initializeGroupFromWelcome(convoId: convoId)
    }

    // 2. Retry processing
    try mlsClient.joinGroup(identity: currentUserDID, welcomeData: welcomeData)

    // 3. Confirm success
    try await apiClient.confirmWelcome(convoId: convoId, success: true)

    // 4. Clean up
    try await deleteWelcomeFromStorage(convoId: convoId)
}
```

### Phase 4: Message Sending with Idempotency

```swift
func sendMessage(convoId: String, text: String) async throws -> String {
    // Generate idempotency key ONCE
    let idempotencyKey = UUID().uuidString

    // Store in pending messages (for retry)
    try await storePendingMessage(
        text: text,
        idempotencyKey: idempotencyKey,
        convoId: convoId
    )

    do {
        // Encrypt and send with idempotency key
        let ciphertext = try encryptMessage(text)
        let result = try await apiClient.sendMessage(
            convoId: convoId,
            ciphertext: ciphertext,
            epoch: currentEpoch,
            idempotencyKey: idempotencyKey  // Same key on retry
        )

        // Clean up pending
        try await deletePendingMessage(idempotencyKey: idempotencyKey)
        return result.messageId

    } catch {
        // Keep pending message for retry with SAME idempotency key
        throw error
    }
}

// Retry failed messages
func retryPendingMessages() async {
    let pending = try await loadPendingMessages()
    for message in pending {
        try? await apiClient.sendMessage(
            convoId: message.convoId,
            ciphertext: message.ciphertext,
            epoch: message.epoch,
            idempotencyKey: message.idempotencyKey  // REUSE same key
        )
    }
}
```

## Lexicon Updates

### New: confirmWelcome

```json
{
  "lexicon": 1,
  "id": "blue.catbird.mls.confirmWelcome",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Confirm successful or failed processing of Welcome message",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "success"],
          "properties": {
            "convoId": { "type": "string" },
            "success": { "type": "boolean" },
            "errorDetails": { "type": "string" }
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["confirmed"],
          "properties": {
            "confirmed": { "type": "boolean" }
          }
        }
      }
    }
  }
}
```

### Updated: sendMessage, createConvo, addMembers, publishKeyPackage

Add `idempotencyKey` to input schemas:
```json
{
  "idempotencyKey": {
    "type": "string",
    "description": "Client-generated UUID for idempotent retries"
  }
}
```

## Migration Timeline

### Week 1: Server Foundation
- [ ] Database migrations
- [ ] Idempotency infrastructure (Redis, middleware)
- [ ] Update lexicons
- [ ] confirmWelcome handler

### Week 2: Handler Updates
- [ ] Update all write handlers
- [ ] Add getWelcome grace period
- [ ] Natural idempotency for leaveConvo
- [ ] Testing

### Week 3: Client Integration
- [ ] Regenerate client from lexicons
- [ ] Implement Welcome persistence
- [ ] Add idempotency key tracking
- [ ] Retry logic

## Backward Compatibility

All changes are backward compatible:
- `idempotencyKey` is optional (defaults to `null`)
- Old clients can still call `getWelcome` (works with 5-min grace period)
- `confirmWelcome` is optional (server auto-expires after 5 min)

## Rollout Strategy

1. **Deploy server changes** (no client changes needed yet)
2. **Test with old clients** (verify backward compatibility)
3. **Update client with new features**
4. **Monitor idempotency cache hit rates**

## Success Metrics

- Welcome message fetch failures: < 0.1%
- Duplicate message sends: 0
- Idempotency cache hit rate: Track for tuning
- Failed Welcome confirmations: Log for debugging

## Open Questions

1. **Redis vs PostgreSQL for idempotency cache?**
   - Redis: Faster, auto-expiry
   - PostgreSQL: Simpler, transactional
   - **Recommendation**: Start with PostgreSQL, migrate to Redis if needed

2. **Welcome retry window: 5 minutes or longer?**
   - 5 min: Handles immediate failures
   - 1 hour: Handles app crashes
   - **Recommendation**: 5 min with manual re-invite option

3. **Client storage for pending operations?**
   - Core Data: Persistent, complex
   - Keychain: Secure, size-limited
   - UserDefaults: Simple, not encrypted
   - **Recommendation**: Core Data for messages, Keychain for Welcome

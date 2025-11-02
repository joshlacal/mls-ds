# Client Integration Guide: Idempotency & Two-Phase Welcome

## 🎉 Implementation Complete

All server-side changes have been implemented and deployed:

✅ Two-phase commit for `getWelcome` with 5-minute grace period
✅ Idempotency keys for all write operations
✅ Natural idempotency for `leaveConvo` and `addMembers`
✅ New `/xrpc/blue.catbird.mls.confirmWelcome` endpoint
✅ PostgreSQL-backed idempotency cache with automatic cleanup
✅ Database migrations applied
✅ Updated lexicons published

## Server Endpoints Summary

### New Endpoint: `confirmWelcome`
```
POST /xrpc/blue.catbird.mls.confirmWelcome
Input: {
  "convoId": string,
  "success": boolean,
  "errorDetails"?: string  // Optional
}
Output: {
  "confirmed": boolean
}
```

### Updated Endpoints (Now Accept `idempotencyKey`)
- `POST /xrpc/blue.catbird.mls.sendMessage`
- `POST /xrpc/blue.catbird.mls.createConvo`
- `POST /xrpc/blue.catbird.mls.addMembers`
- `POST /xrpc/blue.catbird.mls.publishKeyPackage`

### Modified Behavior
- `GET /xrpc/blue.catbird.mls.getWelcome` - Now has 5-minute grace period for retries

## Client-Side Implementation Steps

### Phase 1: Lexicon Updates (Week 1)

1. **Regenerate client from updated lexicons**
```bash
# In your iOS/Swift project
lexicon-codegen generate \
  --input lexicons/ \
  --output Generated/ATProto \
  --language swift
```

2. **Verify new methods exist**
```swift
// Should now have:
MLSAPIClient.confirmWelcome(convoId:success:errorDetails:)

// Should now accept idempotencyKey:
MLSAPIClient.sendMessage(..., idempotencyKey:)
MLSAPIClient.createConversation(..., idempotencyKey:)
MLSAPIClient.addMembers(..., idempotencyKey:)
MLSAPIClient.publishKeyPackage(..., idempotencyKey:)
```

### Phase 2: Welcome Message Persistence (Week 1-2)

**CRITICAL**: Save Welcome messages before processing to enable retry.

```swift
// In MLSConversationManager.swift

// 1. Add storage methods
private func persistWelcomeToStorage(convoId: String, welcomeData: Data) async throws {
    try await storage.saveWelcome(convoId: convoId, data: welcomeData)
}

private func loadWelcomeFromStorage(convoId: String) async throws -> Data? {
    return try await storage.loadWelcome(convoId: convoId)
}

private func deleteWelcomeFromStorage(convoId: String) async throws {
    try await storage.deleteWelcome(convoId: convoId)
}

// 2. Update joinGroup flow
func initializeGroupFromWelcome(convoId: String) async throws {
    // Step 1: Fetch Welcome (server marks as 'in_flight')
    let welcome = try await apiClient.getWelcome(convoId: convoId)

    // Step 2: PERSIST BEFORE PROCESSING (NEW!)
    try await persistWelcomeToStorage(
        convoId: convoId,
        welcomeData: Data(base64Encoded: welcome.welcome)!
    )

    // Step 3: Attempt MLS processing
    do {
        try mlsClient.joinGroup(
            identity: currentUserDID,
            welcomeData: Data(base64Encoded: welcome.welcome)!
        )

        // Step 4: Confirm success to server
        try await apiClient.confirmWelcome(
            convoId: convoId,
            success: true
        )

        // Step 5: Clean up persisted welcome
        try await deleteWelcomeFromStorage(convoId: convoId)

    } catch {
        // Step 6: Confirm failure (allows retry within grace period)
        try? await apiClient.confirmWelcome(
            convoId: convoId,
            success: false,
            errorDetails: error.localizedDescription
        )

        // Keep persisted welcome for manual retry
        throw error
    }
}

// 3. Add retry logic
func retryFailedWelcome(convoId: String) async throws {
    // Try loading from local storage first
    if let welcomeData = try await loadWelcomeFromStorage(convoId: convoId) {
        try mlsClient.joinGroup(
            identity: currentUserDID,
            welcomeData: welcomeData
        )

        try await apiClient.confirmWelcome(convoId: convoId, success: true)
        try await deleteWelcomeFromStorage(convoId: convoId)
        return
    }

    // Fallback: Re-fetch from server (5-min grace period)
    try await initializeGroupFromWelcome(convoId: convoId)
}
```

### Phase 3: Idempotency Keys for Write Operations (Week 2)

```swift
// In MLSConversationManager.swift

// 1. Add pending operations storage
struct PendingMessage: Codable {
    let idempotencyKey: String
    let convoId: String
    let ciphertext: Data
    let epoch: Int
    let timestamp: Date
}

// 2. Update sendMessage with idempotency
func sendMessage(convoId: String, text: String) async throws -> String {
    // Generate idempotency key ONCE
    let idempotencyKey = UUID().uuidString

    // Encrypt message
    let ciphertext = try encryptMessage(text)

    // Store pending (for retry)
    try await storagePendingMessage(PendingMessage(
        idempotencyKey: idempotencyKey,
        convoId: convoId,
        ciphertext: ciphertext,
        epoch: currentEpoch,
        timestamp: Date()
    ))

    do {
        // Send with idempotency key
        let result = try await apiClient.sendMessage(
            convoId: convoId,
            ciphertext: ciphertext,
            epoch: currentEpoch,
            idempotencyKey: idempotencyKey  // NEW parameter
        )

        // Clean up on success
        try await deletePendingMessage(idempotencyKey: idempotencyKey)
        return result.messageId

    } catch {
        // Keep pending for retry with SAME key
        throw error
    }
}

// 3. Add retry worker
func retryPendingMessages() async {
    let pending = try await loadPendingMessages()

    for message in pending {
        // Retry with same idempotency key = no duplicates
        try? await apiClient.sendMessage(
            convoId: message.convoId,
            ciphertext: message.ciphertext,
            epoch: message.epoch,
            idempotencyKey: message.idempotencyKey  // REUSE same key!
        )
    }
}
```

### Phase 4: Create Conversation with Idempotency (Week 2)

```swift
func createConversation(
    members: [String],
    name: String?
) async throws -> String {
    let idempotencyKey = UUID().uuidString

    // ... create MLS group, generate Welcome ...

    let result = try await apiClient.createConversation(
        initialMembers: members,
        welcomeMessage: welcomeData,
        metadata: metadata,
        idempotencyKey: idempotencyKey  // NEW parameter
    )

    return result.convoId
}
```

## Implementation Timeline

### Week 1: Foundation
- [x] Server changes deployed ✅
- [ ] Regenerate client from lexicons
- [ ] Implement Welcome persistence (Keychain/Core Data)
- [ ] Update getWelcome flow with confirmWelcome

### Week 2: Idempotency
- [ ] Add pending operations storage
- [ ] Update sendMessage with idempotency keys
- [ ] Update createConversation with idempotency
- [ ] Update addMembers with idempotency
- [ ] Implement retry worker for pending operations

### Week 3: Testing & Rollout
- [ ] Test Welcome retry scenarios
- [ ] Test message deduplication
- [ ] Test network failure recovery
- [ ] Monitor idempotency cache hit rates
- [ ] Gradual rollout to users

## Testing Checklist

### Welcome Message Resilience
- [ ] App crash after fetching Welcome → retry succeeds
- [ ] Network timeout during fetch → refetch within 5 min succeeds
- [ ] MLS processing error → retry with persisted Welcome
- [ ] Fetch Welcome twice → second returns 410 Gone (expected)
- [ ] Fetch Welcome after 5 min grace → can refetch successfully

### Message Deduplication
- [ ] Send message → network timeout → retry → no duplicate
- [ ] Send same message twice → only one created
- [ ] Different idempotency keys → both messages created

### Conversation Creation
- [ ] Create convo → timeout → retry → returns existing convo
- [ ] Same idempotency key → returns same convo ID

## Backward Compatibility

All changes are **100% backward compatible**:

- ✅ `idempotencyKey` is **optional** on all endpoints
- ✅ Old clients work without any changes
- ✅ `confirmWelcome` is optional (server auto-expires after 5 min)
- ✅ New clients get improved reliability

## Monitoring & Debugging

### Server-Side Logs to Watch
```
INFO  Idempotency cache HIT for key=... status=200
INFO  Idempotency cache cleanup worker started
INFO  Welcome already consumed for user ... (expected on retry)
WARN  Failed to confirm welcome (indicates client issues)
```

### Client-Side Metrics to Track
- Welcome fetch failures (should be < 0.1%)
- Duplicate message sends (should be 0)
- Pending operations count (monitor for leaks)
- Idempotency cache hit rate (indicates retry effectiveness)

## Common Issues & Solutions

### Issue: "No signer for identity" when joining group
**Cause**: Client hasn't persisted Welcome before processing
**Solution**: Implement Step 2 (Welcome persistence) first

### Issue: Duplicate messages in UI
**Cause**: Not using same idempotency key on retry
**Solution**: Store idempotency key with pending message, reuse on retry

### Issue: Welcome already consumed (410 Gone)
**Cause**: Fetching Welcome multiple times outside grace period
**Solution**: Use `retryFailedWelcome()` which checks local storage first

## Questions?

See full documentation:
- `/home/ubuntu/mls/server/IDEMPOTENCY_IMPLEMENTATION_PLAN.md` - Complete plan
- `/home/ubuntu/mls/server/IDEMPOTENCY_INTEGRATION_GUIDE.md` - Server integration details
- `/home/ubuntu/mls/lexicon/` - Updated lexicon definitions

## Migration Checklist for Client

```swift
// ✅ Phase 1: Lexicons
[ ] Regenerate client code
[ ] Verify new methods compile

// ✅ Phase 2: Welcome Persistence
[ ] Add Keychain/Core Data storage for Welcome messages
[ ] Update initializeGroupFromWelcome() with persistence
[ ] Add confirmWelcome() calls
[ ] Implement retryFailedWelcome()

// ✅ Phase 3: Idempotency Keys
[ ] Add pending operations storage
[ ] Update sendMessage() to use idempotency keys
[ ] Update createConversation() to use idempotency keys
[ ] Implement retry worker

// ✅ Phase 4: Testing
[ ] Test Welcome retry scenarios
[ ] Test message deduplication
[ ] Test network failure recovery
[ ] Load test with concurrent requests

// ✅ Phase 5: Rollout
[ ] Deploy to TestFlight
[ ] Monitor metrics
[ ] Gradual rollout to production
```

---

**Next Steps**: Start with Phase 1 (lexicon regeneration) and Phase 2 (Welcome persistence). These provide immediate reliability improvements with minimal code changes.

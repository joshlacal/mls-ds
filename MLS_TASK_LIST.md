# MLS Chat Integration - Detailed Task List
**Generated**: October 21, 2025  
**Project**: Catbird MLS E2EE Integration  
**Total Estimated Effort**: 14 days (with parallelization)

---

## Phase 1: Preparation & Infrastructure (2 days)

### P1.1: Git & Repository Setup
- [ ] **P1.1.1** Create `mls-chat` branch from `main` in Catbird repo
- [ ] **P1.1.2** Set up branch protection rules (require PR reviews)
- [ ] **P1.1.3** Create GitHub Project board with all tasks
- [ ] **P1.1.4** Tag initial commit with planning documents
- [ ] **P1.1.5** Configure CI/CD for branch (if needed)

**Agent**: Git Coordinator  
**Estimated Time**: 1 hour  
**Blockers**: None  
**Deliverable**: `mls-chat` branch ready for development

---

### P1.2: Lexicon Definitions
- [ ] **P1.2.1** Create `blue.catbird.mls.defs.json` with common types
  - [ ] Define `convoView` schema
  - [ ] Define `messageView` schema
  - [ ] Define `memberView` schema
  - [ ] Define `keyPackageRef` schema
  - [ ] Define `blobRef` schema
  - [ ] Define `epochInfo` schema
  - [ ] Define `cipherSuiteEnum`

- [ ] **P1.2.2** Create `blue.catbird.mls.createConvo.json`
  - [ ] Define input schema (title, didList, cipherSuite)
  - [ ] Define output schema (convoView)
  - [ ] Add validation rules

- [ ] **P1.2.3** Create `blue.catbird.mls.addMembers.json`
  - [ ] Define input schema (convoId, didList, commit, welcome)
  - [ ] Define output schema (success, newEpoch, status)

- [ ] **P1.2.4** Create `blue.catbird.mls.sendMessage.json`
  - [ ] Define input schema (convoId, ciphertext, epoch, senderDid)
  - [ ] Define output schema (messageId, receivedAt)

- [ ] **P1.2.5** Create `blue.catbird.mls.getMessages.json` (query)
  - [ ] Define params schema (convoId, sinceMessage, sinceEpoch)
  - [ ] Define output schema (messages array)

- [ ] **P1.2.6** Create `blue.catbird.mls.leaveConvo.json`
  - [ ] Define input schema (convoId, targetDid, commit)
  - [ ] Define output schema (success, newEpoch)

- [ ] **P1.2.7** Create `blue.catbird.mls.publishKeyPackage.json`
  - [ ] Define input schema (keyPackage base64, cipherSuite, expiresAt)
  - [ ] Define output schema (success)

- [ ] **P1.2.8** Create `blue.catbird.mls.getKeyPackages.json` (query)
  - [ ] Define params schema (dids array)
  - [ ] Define output schema (keyPackages array)

- [ ] **P1.2.9** Create `blue.catbird.mls.uploadBlob.json`
  - [ ] Define input schema (blob base64, mimeType)
  - [ ] Define output schema (blobRef)

- [ ] **P1.2.10** Create `blue.catbird.mls.getConvos.json` (query)
  - [ ] Define params schema (sinceUpdate)
  - [ ] Define output schema (convos array)

- [ ] **P1.2.11** Validate all lexicons against AT Protocol schema
- [ ] **P1.2.12** Document field meanings and constraints
- [ ] **P1.2.13** Create lexicon README with usage examples

**Agent**: Lexicon Architect  
**Estimated Time**: 6 hours  
**Blockers**: None  
**Deliverable**: 10 validated lexicon JSON files in `mls/lexicon/`

---

### P1.3: Catbird Architecture Audit
- [ ] **P1.3.1** Map existing Bluesky chat implementation
  - [ ] Identify chat view controllers
  - [ ] Document data models
  - [ ] Note API client patterns
  - [ ] Document persistence strategy

- [ ] **P1.3.2** Analyze Petrel integration
  - [ ] Find existing generated models
  - [ ] Document generation scripts
  - [ ] Identify customization patterns

- [ ] **P1.3.3** Document view architecture
  - [ ] SwiftUI view hierarchy
  - [ ] Navigation patterns
  - [ ] State management approach

- [ ] **P1.3.4** Analyze networking layer
  - [ ] ATProto client implementation
  - [ ] Authentication flow
  - [ ] Error handling patterns

- [ ] **P1.3.5** Document security implementations
  - [ ] Keychain usage
  - [ ] Secure Enclave integration (if any)
  - [ ] Certificate pinning

- [ ] **P1.3.6** Analyze persistence layer
  - [ ] SwiftData models
  - [ ] Migration strategies
  - [ ] Query patterns

- [ ] **P1.3.7** Create architecture diagram (Mermaid)
- [ ] **P1.3.8** Create dependency map
- [ ] **P1.3.9** Identify integration points for MLS
- [ ] **P1.3.10** List reusable components
- [ ] **P1.3.11** Risk assessment for conflicts
- [ ] **P1.3.12** Document in `CATBIRD_ARCHITECTURE.md`

**Agent**: Code Archaeologist  
**Estimated Time**: 6 hours  
**Blockers**: P1.1 (need branch access)  
**Deliverable**: `CATBIRD_ARCHITECTURE.md` with diagrams

---

## Phase 2: Code Generation & Model Creation (2 days)

### P2.1: Swift Model Generation
- [ ] **P2.1.1** Install/update Petrel generator
- [ ] **P2.1.2** Create generation script `generate_mls_models.sh`
- [ ] **P2.1.3** Generate models from lexicons
  - [ ] Run Petrel against `mls/lexicon/`
  - [ ] Output to `Catbird/Catbird/Models/MLS/`
  - [ ] Verify namespace is `BlueCatbirdMLS`

- [ ] **P2.1.4** Review generated files
  - [ ] ConvoView.swift
  - [ ] MessageView.swift
  - [ ] MemberView.swift
  - [ ] KeyPackageRef.swift
  - [ ] BlobRef.swift
  - [ ] EpochInfo.swift
  - [ ] All input/output types

- [ ] **P2.1.5** Add generated files to Xcode project
- [ ] **P2.1.6** Verify compilation (no errors)
- [ ] **P2.1.7** Add Codable tests for each model
- [ ] **P2.1.8** Document generation process in README

**Agent**: Petrel Operator  
**Estimated Time**: 3 hours  
**Blockers**: P1.2 (need lexicons)  
**Deliverable**: 20+ compiled Swift model files

---

### P2.2: MLS API Client (Swift)
- [ ] **P2.2.1** Create `MLSClient.swift` file
- [ ] **P2.2.2** Implement actor structure with URLSession
- [ ] **P2.2.3** Implement authentication
  - [ ] `authenticate(did:jwt:)` method
  - [ ] Bearer token storage
  - [ ] Token refresh logic

- [ ] **P2.2.4** Implement conversation methods
  - [ ] `createConvo(title:invites:)` → ConvoView
  - [ ] `getConvos(since:)` → [ConvoView]
  - [ ] `leaveConvo(_:target:commit:)` → LeaveConvoOutput

- [ ] **P2.2.5** Implement member methods
  - [ ] `addMembers(convoId:dids:commit:welcome:)` → AddMembersOutput

- [ ] **P2.2.6** Implement message methods
  - [ ] `sendMessage(convoId:ciphertext:epoch:)` → SendMessageOutput
  - [ ] `getMessages(convoId:since:sinceEpoch:)` → [MessageView]

- [ ] **P2.2.7** Implement key methods
  - [ ] `publishKeyPackage(_:cipherSuite:expires:)` → Void
  - [ ] `getKeyPackages(dids:)` → [KeyPackageRef]

- [ ] **P2.2.8** Implement blob methods
  - [ ] `uploadBlob(_:mimeType:)` → BlobRef
  - [ ] `downloadBlob(cid:)` → Data

- [ ] **P2.2.9** Add error handling
  - [ ] Map HTTP status codes to domain errors
  - [ ] Implement retry logic with exponential backoff
  - [ ] Add request timeout handling

- [ ] **P2.2.10** Add logging (redacted)
- [ ] **P2.2.11** Write unit tests with URLProtocol mocking
- [ ] **P2.2.12** Write integration tests against local server
- [ ] **P2.2.13** Add documentation comments

**Agent**: Network Engineer  
**Estimated Time**: 8 hours  
**Blockers**: P2.1 (need models)  
**Deliverable**: Complete `MLSClient.swift` with 90%+ test coverage

---

### P2.3: OpenMLS FFI Implementation (Rust)
- [ ] **P2.3.1** Set up OpenMLS dependencies in `mls-ffi/Cargo.toml`
- [ ] **P2.3.2** Implement group management
  - [ ] `mls_create_group` - Create new MLS group
  - [ ] `mls_free_group` - Deallocate group handle
  - [ ] `mls_get_group_id` - Get group identifier
  - [ ] `mls_current_epoch` - Get current epoch number

- [ ] **P2.3.3** Implement join flow
  - [ ] `mls_join_group` - Process Welcome and create group state
  - [ ] Extract GroupInfo from Welcome
  - [ ] Initialize member's leaf node

- [ ] **P2.3.4** Implement member operations
  - [ ] `mls_add_member` - Generate Add proposal + Commit
  - [ ] `mls_remove_member` - Generate Remove proposal + Commit
  - [ ] `mls_process_commit` - Apply incoming commit to group state

- [ ] **P2.3.5** Implement message encryption
  - [ ] `mls_encrypt_message` - Encrypt plaintext to MLS PrivateMessage
  - [ ] Handle padding
  - [ ] Generate ciphertext

- [ ] **P2.3.6** Implement message decryption
  - [ ] `mls_decrypt_message` - Decrypt MLS PrivateMessage
  - [ ] Verify sender signature
  - [ ] Return sender leaf index

- [ ] **P2.3.7** Implement KeyPackage operations
  - [ ] `mls_generate_key_package` - Create new KeyPackage
  - [ ] `mls_key_package_from_bytes` - Parse KeyPackage
  - [ ] Credential management

- [ ] **P2.3.8** Implement error handling
  - [ ] Error code enum
  - [ ] Error message strings (allocated, must be freed)
  - [ ] `mls_free_error` function

- [ ] **P2.3.9** Memory management
  - [ ] Use Box for opaque pointers
  - [ ] Implement free functions for all allocations
  - [ ] Add memory leak tests

- [ ] **P2.3.10** Generate C header with cbindgen
- [ ] **P2.3.11** Write Rust unit tests
- [ ] **P2.3.12** Write integration test (multi-party scenario)
- [ ] **P2.3.13** Build for iOS targets
  - [ ] aarch64-apple-ios (arm64)
  - [ ] x86_64-apple-ios (simulator)
- [ ] **P2.3.14** Test with Instruments (memory leaks)
- [ ] **P2.3.15** Document FFI interface

**Agent**: Cryptography Specialist  
**Estimated Time**: 12 hours  
**Blockers**: None (parallel to P2.1/P2.2)  
**Deliverable**: Production-ready `mls-ffi` with tests and header file

---

## Phase 3: Server Enhancement (3 days)

### P3.1: Authentication Enhancement
- [ ] **P3.1.1** Implement JWT verification
  - [ ] Add jsonwebtoken crate
  - [ ] Fetch public keys from PLC
  - [ ] Cache DID documents (TTL 1 hour)
  - [ ] Verify JWT signature and claims

- [ ] **P3.1.2** Implement DID document fetching
  - [ ] Support did:plc resolution
  - [ ] Support did:web resolution
  - [ ] Handle network errors gracefully

- [ ] **P3.1.3** Implement Ed25519 signature verification
- [ ] **P3.1.4** Session management
  - [ ] In-memory session store (or Redis)
  - [ ] Session expiration (24 hours)
  - [ ] Refresh token support

- [ ] **P3.1.5** Rate limiting
  - [ ] Per-IP rate limiting (100 req/min)
  - [ ] Per-DID rate limiting (1000 req/hour)
  - [ ] Exponential backoff responses

- [ ] **P3.1.6** Write auth middleware
- [ ] **P3.1.7** Add auth unit tests

**Agent**: Backend Engineer  
**Estimated Time**: 4 hours  
**Blockers**: None  
**Deliverable**: Secure authentication system

---

### P3.2: Database Schema & Migrations
- [ ] **P3.2.1** Create migration script `001_initial_schema.sql`
- [ ] **P3.2.2** Define `users` table
- [ ] **P3.2.3** Define `conversations` table
- [ ] **P3.2.4** Define `memberships` table (with composite PK)
- [ ] **P3.2.5** Define `messages` table
- [ ] **P3.2.6** Define `key_packages` table
- [ ] **P3.2.7** Define `blobs` table
- [ ] **P3.2.8** Define `welcomes` table
- [ ] **P3.2.9** Add indexes
  - [ ] messages(convo_id, sent_at)
  - [ ] messages(convo_id, epoch)
  - [ ] key_packages(did, consumed)
  - [ ] memberships(member_did)

- [ ] **P3.2.10** Add foreign key constraints
- [ ] **P3.2.11** Set up sqlx migrations
- [ ] **P3.2.12** Test migrations (up and down)
- [ ] **P3.2.13** Document schema in `DATABASE.md`

**Agent**: Backend Engineer  
**Estimated Time**: 3 hours  
**Blockers**: None  
**Deliverable**: Complete database schema with migrations

---

### P3.3: Storage Layer Implementation
- [ ] **P3.3.1** Implement `Storage` trait/struct
- [ ] **P3.3.2** User operations
  - [ ] `create_user(did, handle)`
  - [ ] `get_user(did)`
  - [ ] `update_last_seen(did)`

- [ ] **P3.3.3** Conversation operations
  - [ ] `create_conversation(creator, title, cipher_suite)` → UUID
  - [ ] `get_conversation(id)` → Option<Conversation>
  - [ ] `list_conversations(did)` → Vec<Conversation>
  - [ ] `update_epoch(convo_id, new_epoch)`

- [ ] **P3.3.4** Membership operations
  - [ ] `add_member(convo_id, did)`
  - [ ] `remove_member(convo_id, did)`
  - [ ] `is_member(convo_id, did)` → bool
  - [ ] `get_members(convo_id)` → Vec<String>
  - [ ] `increment_unread(convo_id, did)`
  - [ ] `reset_unread(convo_id, did)`

- [ ] **P3.3.5** Message operations
  - [ ] `store_message(convo_id, sender, type, epoch, ciphertext)` → UUID
  - [ ] `get_messages(convo_id, since_id?, since_epoch?)`
  - [ ] `get_message_count(convo_id)`

- [ ] **P3.3.6** KeyPackage operations
  - [ ] `store_key_package(did, cipher_suite, data, expires)`
  - [ ] `get_key_package(did, cipher_suite)` → Option<KeyPackage>
  - [ ] `mark_key_package_consumed(did, cipher_suite)`
  - [ ] `delete_expired_key_packages()`

- [ ] **P3.3.7** Blob operations
  - [ ] `store_blob(data, mime_type, uploader)` → String (CID)
  - [ ] `get_blob(cid)` → Option<Vec<u8>>
  - [ ] `delete_blob(cid)`

- [ ] **P3.3.8** Welcome operations
  - [ ] `store_welcome(convo_id, target_did, data)`
  - [ ] `get_welcome(convo_id, did)` → Option<Vec<u8>>
  - [ ] `mark_welcome_consumed(convo_id, did)`

- [ ] **P3.3.9** Transaction support for critical operations
- [ ] **P3.3.10** Add storage unit tests
- [ ] **P3.3.11** Add integration tests with real Postgres

**Agent**: Backend Engineer  
**Estimated Time**: 6 hours  
**Blockers**: P3.2 (need schema)  
**Deliverable**: Complete storage layer with tests

---

### P3.4: API Handler Completion
- [ ] **P3.4.1** Enhance `createConvo` handler
  - [ ] Validate input (title length, etc.)
  - [ ] Create conversation in DB
  - [ ] Add creator as first member
  - [ ] Return convoView

- [ ] **P3.4.2** Enhance `addMembers` handler
  - [ ] Verify caller is member
  - [ ] Validate target DIDs
  - [ ] Check KeyPackage availability
  - [ ] Store commit message
  - [ ] Update epoch
  - [ ] Add members to DB
  - [ ] Store Welcome for each new member
  - [ ] Return success + newEpoch

- [ ] **P3.4.3** Enhance `sendMessage` handler
  - [ ] Verify sender is member
  - [ ] Check epoch consistency (warn if stale)
  - [ ] Store message
  - [ ] Increment unread for others
  - [ ] Return messageId + timestamp

- [ ] **P3.4.4** Enhance `leaveConvo` handler
  - [ ] Verify caller authority
  - [ ] Store remove commit
  - [ ] Update epoch
  - [ ] Mark member as left
  - [ ] Return success

- [ ] **P3.4.5** Enhance `getMessages` handler
  - [ ] Verify caller is member
  - [ ] Fetch messages since cursor
  - [ ] Possibly include pending commits
  - [ ] Reset unread count
  - [ ] Return messageView array

- [ ] **P3.4.6** Enhance `publishKeyPackage` handler
  - [ ] Validate KeyPackage format
  - [ ] Verify signature matches DID
  - [ ] Check expiration time is future
  - [ ] Store in DB
  - [ ] Return success

- [ ] **P3.4.7** Enhance `getKeyPackages` handler
  - [ ] Fetch non-consumed, non-expired packages
  - [ ] Return array of KeyPackageRef

- [ ] **P3.4.8** Enhance `uploadBlob` handler
  - [ ] Enforce size limit (10MB default)
  - [ ] Compute SHA-256 CID
  - [ ] Store blob
  - [ ] Return blobRef

- [ ] **P3.4.9** Implement `getConvos` handler
  - [ ] List user's conversations
  - [ ] Include metadata (title, members, unread)
  - [ ] Filter by sinceUpdate if provided

- [ ] **P3.4.10** Add request validation for all handlers
- [ ] **P3.4.11** Add structured logging (redacted)
- [ ] **P3.4.12** Write handler integration tests

**Agent**: Backend Engineer  
**Estimated Time**: 6 hours  
**Blockers**: P3.3 (need storage)  
**Deliverable**: All 9 API handlers fully implemented with tests

---

### P3.5: KeyPackage Management
- [ ] **P3.5.1** Implement rotation logic
  - [ ] Auto-generate new KeyPackage when consumed
  - [ ] Background job to prune expired packages

- [ ] **P3.5.2** Expiration checking
  - [ ] Reject expired KeyPackages on invite
  - [ ] Warn users with <24h until expiry

- [ ] **P3.5.3** Cipher suite validation
  - [ ] Check invitee KeyPackage matches group suite
  - [ ] Return error if mismatch

- [ ] **P3.5.4** One-time use enforcement
  - [ ] Mark as consumed on use
  - [ ] Reject already-consumed packages

- [ ] **P3.5.5** Write KeyPackage management tests

**Agent**: Backend Engineer  
**Estimated Time**: 2 hours  
**Blockers**: P3.4  
**Deliverable**: Robust KeyPackage lifecycle

---

### P3.6: Blob Storage
- [ ] **P3.6.1** Implement content-addressed storage
  - [ ] SHA-256 CID generation
  - [ ] Deduplication (same CID = same blob)

- [ ] **P3.6.2** Integrity verification on upload
- [ ] **P3.6.3** Size limits enforcement
- [ ] **P3.6.4** Optional external storage adapter (S3-compatible)
- [ ] **P3.6.5** Add blob cleanup job (orphaned blobs)
- [ ] **P3.6.6** Write blob storage tests

**Agent**: Backend Engineer  
**Estimated Time**: 2 hours  
**Blockers**: P3.4  
**Deliverable**: Production blob storage

---

### P3.7: Production Hardening
- [ ] **P3.7.1** Add HTTPS/TLS support (Rustls)
- [ ] **P3.7.2** Configure CORS properly
- [ ] **P3.7.3** Add health check endpoint enhancements
  - [ ] Check DB connectivity
  - [ ] Check disk space
  - [ ] Return JSON status

- [ ] **P3.7.4** Add metrics endpoint (Prometheus format)
  - [ ] Request count by endpoint
  - [ ] Latency histograms
  - [ ] Active connections

- [ ] **P3.7.5** Structured logging with tracing
  - [ ] JSON output
  - [ ] Correlation IDs
  - [ ] No sensitive data

- [ ] **P3.7.6** Graceful shutdown
- [ ] **P3.7.7** Write deployment guide
- [ ] **P3.7.8** Create Dockerfile
- [ ] **P3.7.9** Create docker-compose.yml
- [ ] **P3.7.10** Create Kubernetes manifests (optional)

**Agent**: Backend Engineer + DevOps  
**Estimated Time**: 4 hours  
**Blockers**: P3.4-P3.6  
**Deliverable**: Production-ready server

---

### P3.8: Server Testing
- [ ] **P3.8.1** Unit tests for all modules (80%+ coverage)
- [ ] **P3.8.2** Integration tests for all endpoints
- [ ] **P3.8.3** Multi-party MLS test harness
  - [ ] 2-member group scenario
  - [ ] 3-member group scenario
  - [ ] 10-member group scenario
  - [ ] Concurrent message sends
  - [ ] Add/remove during conversation
  - [ ] Out-of-order commit handling

- [ ] **P3.8.4** Load testing with `wrk` or `k6`
  - [ ] Target: 1000 messages/sec
  - [ ] Measure latency (P50, P95, P99)
  - [ ] Measure memory usage

- [ ] **P3.8.5** Security testing
  - [ ] Test JWT validation
  - [ ] Test authorization (non-members can't access)
  - [ ] Test rate limiting
  - [ ] Test input validation

- [ ] **P3.8.6** Document test results

**Agent**: QA Engineer  
**Estimated Time**: 8 hours  
**Blockers**: P3.7 (need complete server)  
**Deliverable**: Comprehensive test suite with passing results

---

## Phase 4: iOS Integration (5 days)

### P4.1: FFI Bridge (Swift)
- [ ] **P4.1.1** Create `MLSManager.swift`
- [ ] **P4.1.2** Import C header from Rust FFI
- [ ] **P4.1.3** Implement group lifecycle
  - [ ] `createGroup(credential:cipherSuite:)` → MLSGroupSession
  - [ ] `joinGroup(welcome:credential:)` → MLSGroupSession
  - [ ] `destroyGroup(_:)` - cleanup

- [ ] **P4.1.4** Implement member operations
  - [ ] `addMember(session:keyPackage:)` → (commit, welcome)
  - [ ] `removeMember(session:index:)` → commit
  - [ ] `processCommit(session:commit:)` - apply incoming

- [ ] **P4.1.5** Implement message operations
  - [ ] `encrypt(session:plaintext:)` → Data
  - [ ] `decrypt(session:ciphertext:)` → (plaintext, senderIndex)

- [ ] **P4.1.6** Implement KeyPackage operations
  - [ ] `generateKeyPackage(credential:cipherSuite:)` → Data

- [ ] **P4.1.7** Implement error handling
  - [ ] Parse Rust error strings
  - [ ] Throw Swift errors
  - [ ] Free error pointers

- [ ] **P4.1.8** Memory management
  - [ ] Track opaque pointers
  - [ ] Call free functions in deinit
  - [ ] Use Instruments to verify no leaks

- [ ] **P4.1.9** Thread safety (use actors if needed)
- [ ] **P4.1.10** Write unit tests with mock FFI
- [ ] **P4.1.11** Write integration tests with real FFI
- [ ] **P4.1.12** Document API

**Agent**: FFI Specialist  
**Estimated Time**: 8 hours  
**Blockers**: P2.3 (need Rust FFI)  
**Deliverable**: Complete `MLSManager.swift` with tests

---

### P4.2: Keychain & Storage
- [ ] **P4.2.1** Create `KeychainManager.swift`
- [ ] **P4.2.2** Implement credential storage
  - [ ] `storeCredential(_:for:)` - Save Ed25519 key
  - [ ] `retrieveCredential(for:)` - Load key
  - [ ] Use kSecAttrAccessible for security

- [ ] **P4.2.3** Implement group state storage
  - [ ] `storeGroupState(_:for:)` - Encrypted MLS state
  - [ ] `retrieveGroupState(for:)` - Restore state
  - [ ] `deleteGroupState(for:)` - Cleanup

- [ ] **P4.2.4** Implement PSK storage (optional)
- [ ] **P4.2.5** Add keychain access tests
- [ ] **P4.2.6** Create `MLSStorage.swift` (SwiftData)
- [ ] **P4.2.7** Define `MLSConversation` model
  - [ ] id, title, members, currentEpoch, lastUpdate, unreadCount
  - [ ] Relationship to messages

- [ ] **P4.2.8** Define `MLSMessage` model
  - [ ] id, conversationId, senderDid, plaintext, sentAt, epoch, isOutgoing

- [ ] **P4.2.9** Implement storage operations
  - [ ] `fetchConversations()` → [MLSConversation]
  - [ ] `fetchMessages(for:)` → [MLSMessage]
  - [ ] `save(_: MLSConversation)`
  - [ ] `save(_: MLSMessage)`
  - [ ] `delete(_: MLSConversation)`

- [ ] **P4.2.10** Migration from existing schema (if needed)
- [ ] **P4.2.11** Encryption at rest (optional via FileVault)
- [ ] **P4.2.12** Write storage unit tests

**Agent**: Security Engineer  
**Estimated Time**: 6 hours  
**Blockers**: None (parallel to P4.1)  
**Deliverable**: Secure key and data storage

---

### P4.3: View Models & Business Logic
- [ ] **P4.3.1** Create `MLSConversationListViewModel.swift`
- [ ] **P4.3.2** Implement conversation list logic
  - [ ] `loadConversations()` - Fetch from server + local
  - [ ] `createConversation(title:invites:)` - Create and sync
  - [ ] `deleteConversation(_:)` - Local and server cleanup
  - [ ] Merge remote and local state

- [ ] **P4.3.3** Add published properties
  - [ ] `@Published var conversations: [MLSConversation]`
  - [ ] `@Published var isLoading: Bool`
  - [ ] `@Published var error: Error?`

- [ ] **P4.3.4** Create `MLSConversationViewModel.swift`
- [ ] **P4.3.5** Implement message handling
  - [ ] `loadMessages()` - Fetch and decrypt
  - [ ] `send(text:)` - Encrypt and send
  - [ ] `send(attachment:)` - Upload blob, encrypt ref
  - [ ] Real-time sync (polling or WebSocket)

- [ ] **P4.3.6** Implement member management
  - [ ] `invite(did:)` - Fetch KeyPackage, add member
  - [ ] `removeMember(did:)` - Generate remove commit

- [ ] **P4.3.7** Handle group state
  - [ ] Track current epoch
  - [ ] Process incoming commits
  - [ ] Handle stale epoch errors (trigger re-sync)

- [ ] **P4.3.8** Add published properties
  - [ ] `@Published var messages: [MLSMessage]`
  - [ ] `@Published var isSending: Bool`
  - [ ] `@Published var members: [String]`

- [ ] **P4.3.9** Implement error handling and retry
- [ ] **P4.3.10** Offline support (queue messages)
- [ ] **P4.3.11** Write view model unit tests (mocked dependencies)

**Agent**: iOS Developer  
**Estimated Time**: 8 hours  
**Blockers**: P2.2, P4.1, P4.2  
**Deliverable**: Complete view models with business logic

---

### P4.4: SwiftUI Views
- [ ] **P4.4.1** Create `MLSConversationListView.swift`
- [ ] **P4.4.2** Implement conversation list UI
  - [ ] List of conversations with metadata
  - [ ] Unread badge
  - [ ] Pull-to-refresh
  - [ ] Navigation to detail

- [ ] **P4.4.3** Create toolbar with "New Conversation" button
- [ ] **P4.4.4** Create `NewMLSConversationView.swift` (sheet)
  - [ ] Title field
  - [ ] Member picker (search DIDs/handles)
  - [ ] Create button

- [ ] **P4.4.5** Create `MLSConversationView.swift`
- [ ] **P4.4.6** Implement chat UI
  - [ ] ScrollView with message list
  - [ ] Message input field
  - [ ] Send button
  - [ ] Attachment picker
  - [ ] Encrypted indicator (lock icon)

- [ ] **P4.4.7** Create `MLSMessageRow.swift`
  - [ ] Sender name (or "You")
  - [ ] Message content
  - [ ] Timestamp
  - [ ] Outgoing vs incoming styling
  - [ ] Attachment preview

- [ ] **P4.4.8** Create `MLSMemberListView.swift`
  - [ ] List of members (DIDs + handles)
  - [ ] Invite button
  - [ ] Remove button (admin only)

- [ ] **P4.4.9** Create `MLSMemberPickerView.swift`
  - [ ] Search field
  - [ ] Results list
  - [ ] Multi-select
  - [ ] Add button

- [ ] **P4.4.10** Accessibility
  - [ ] VoiceOver labels
  - [ ] Dynamic type support
  - [ ] High contrast support

- [ ] **P4.4.11** Dark mode support
- [ ] **P4.4.12** Localization (at least English)
- [ ] **P4.4.13** Error states (empty, loading, error)
- [ ] **P4.4.14** Add SwiftUI previews

**Agent**: UI Developer  
**Estimated Time**: 10 hours  
**Blockers**: P4.3 (need view models)  
**Deliverable**: Complete MLS chat UI

---

### P4.5: Integration with Existing Catbird
- [ ] **P4.5.1** Add MLS tab to main navigation
  - [ ] Update `MainTabView.swift`
  - [ ] Add "Encrypted" tab with lock icon
  - [ ] Badge for unread MLS messages

- [ ] **P4.5.2** Integrate with settings
  - [ ] Add MLS settings section
  - [ ] Server endpoint configuration
  - [ ] Debug options (show epoch, etc.)
  - [ ] Key management UI

- [ ] **P4.5.3** Onboarding flow for MLS
  - [ ] Explain E2EE benefits
  - [ ] Generate initial credential
  - [ ] Publish KeyPackage
  - [ ] Test server connection

- [ ] **P4.5.4** Notification handling
  - [ ] Register for push notifications
  - [ ] Route MLS notifications to correct view
  - [ ] Silent push for new messages
  - [ ] Update badge count

- [ ] **P4.5.5** Coexistence with Bluesky chat
  - [ ] Separate data models (no conflicts)
  - [ ] Separate API clients
  - [ ] Unified notification manager
  - [ ] Possibly unified "All Chats" view with filters

- [ ] **P4.5.6** Deep linking
  - [ ] `catbird://mls/convo/{id}`
  - [ ] Handle from notifications

- [ ] **P4.5.7** Feature flag
  - [ ] Add compile-time flag `MLS_ENABLED`
  - [ ] Runtime toggle in settings (beta users)

- [ ] **P4.5.8** Migration/upgrade path
  - [ ] Handle users without MLS credentials
  - [ ] Auto-generate on first use

- [ ] **P4.5.9** Regression testing
  - [ ] Verify existing Bluesky chat still works
  - [ ] Verify no performance degradation
  - [ ] Verify no memory leaks introduced

- [ ] **P4.5.10** Update app icon badge logic
- [ ] **P4.5.11** Write integration tests

**Agent**: Integration Specialist  
**Estimated Time**: 6 hours  
**Blockers**: P4.4 (need views)  
**Deliverable**: Seamless integration of MLS into Catbird

---

## Phase 5: End-to-End Testing & Polish (2 days)

### P5.1: E2E Testing
- [ ] **P5.1.1** Set up test infrastructure
  - [ ] Configure test server
  - [ ] Set up simulator farm (iOS 17.0, 17.5, 18.0)
  - [ ] Install Charles Proxy for network testing

- [ ] **P5.1.2** Test scenario: 2-person chat
  - [ ] Alice creates group
  - [ ] Alice invites Bob
  - [ ] Bob accepts and joins
  - [ ] Both exchange 10 messages
  - [ ] Verify all decrypt correctly

- [ ] **P5.1.3** Test scenario: 3-person chat
  - [ ] Alice creates, invites Bob
  - [ ] Bob joins
  - [ ] Alice invites Charlie
  - [ ] All three exchange messages
  - [ ] Verify epoch consistency

- [ ] **P5.1.4** Test scenario: Member removal
  - [ ] 3-person group
  - [ ] Alice removes Bob
  - [ ] Verify Bob can't decrypt new messages
  - [ ] Verify Alice and Charlie can still communicate

- [ ] **P5.1.5** Test scenario: Voluntary leave
  - [ ] Bob leaves group voluntarily
  - [ ] Verify same as removal

- [ ] **P5.1.6** Test scenario: Offline sync
  - [ ] Alice goes offline
  - [ ] Bob sends 10 messages
  - [ ] Alice comes online
  - [ ] Verify Alice receives and decrypts all

- [ ] **P5.1.7** Test scenario: Attachments
  - [ ] Alice sends image
  - [ ] Bob receives and decrypts
  - [ ] Verify integrity

- [ ] **P5.1.8** Test scenario: Concurrent sends
  - [ ] Alice and Bob send at same time
  - [ ] Verify no data loss or corruption

- [ ] **P5.1.9** Test scenario: Key rotation
  - [ ] Simulate 24-hour passage
  - [ ] Verify KeyPackage expiration and renewal

- [ ] **P5.1.10** Test scenario: Server restart
  - [ ] Ongoing conversation
  - [ ] Restart server mid-conversation
  - [ ] Verify clients reconnect and continue

- [ ] **P5.1.11** Test scenario: Network failure
  - [ ] Simulate network drop
  - [ ] Verify retry logic
  - [ ] Verify messages queue locally

- [ ] **P5.1.12** Test scenario: Stale epoch
  - [ ] Force client to use old epoch
  - [ ] Verify error handling and re-sync

- [ ] **P5.1.13** Performance testing
  - [ ] Measure message send latency
  - [ ] Measure message decrypt time
  - [ ] Profile memory usage
  - [ ] Verify 60fps UI during scrolling

- [ ] **P5.1.14** Battery impact test
  - [ ] Measure battery drain during active use
  - [ ] Measure battery drain during background sync

- [ ] **P5.1.15** TestFlight beta distribution
  - [ ] Upload build
  - [ ] Invite beta testers
  - [ ] Collect feedback

**Agent**: QA Team  
**Estimated Time**: 10 hours  
**Blockers**: P4.5 (need complete app)  
**Deliverable**: Passing E2E tests and performance report

---

### P5.2: Security Audit
- [ ] **P5.2.1** Static code analysis
  - [ ] Run SwiftLint with strict rules
  - [ ] Run Semgrep for security patterns
  - [ ] Review dependency audit (cargo audit, Dependabot)

- [ ] **P5.2.2** Cryptographic review
  - [ ] Verify OpenMLS usage is correct
  - [ ] Verify no custom crypto (use std lib)
  - [ ] Review key derivation
  - [ ] Review random number generation

- [ ] **P5.2.3** Key storage audit
  - [ ] Verify Keychain usage
  - [ ] Verify no keys in UserDefaults
  - [ ] Verify no keys in logs

- [ ] **P5.2.4** Network security
  - [ ] Verify TLS 1.3
  - [ ] Consider certificate pinning
  - [ ] Verify no sensitive data in URLs

- [ ] **P5.2.5** Input validation audit
  - [ ] Verify all user input validated
  - [ ] Check for injection vulnerabilities
  - [ ] Check for buffer overflows (FFI)

- [ ] **P5.2.6** Log sanitization audit
  - [ ] Verify no plaintext in logs
  - [ ] Verify no keys in logs
  - [ ] Verify no PII in logs

- [ ] **P5.2.7** Privacy compliance
  - [ ] GDPR data handling
  - [ ] CCPA compliance
  - [ ] App Store privacy manifest

- [ ] **P5.2.8** Dynamic testing
  - [ ] Use Frida for runtime analysis
  - [ ] Attempt to extract keys
  - [ ] Attempt to intercept messages

- [ ] **P5.2.9** Penetration testing
  - [ ] Test server endpoints for exploits
  - [ ] Test rate limiting bypass
  - [ ] Test authentication bypass

- [ ] **P5.2.10** Threat model validation
  - [ ] Review original threat model
  - [ ] Verify mitigations implemented
  - [ ] Update threat model if needed

- [ ] **P5.2.11** Create security audit report
- [ ] **P5.2.12** Fix all critical and high issues
- [ ] **P5.2.13** Document medium/low issues for backlog

**Agent**: Security Auditor  
**Estimated Time**: 8 hours  
**Blockers**: P5.1 (need complete system)  
**Deliverable**: Security audit report with all critical issues fixed

---

### P5.3: Documentation & Deployment
- [ ] **P5.3.1** User documentation
  - [ ] Getting started guide
  - [ ] Create encrypted conversation tutorial
  - [ ] Invite members tutorial
  - [ ] Send attachments tutorial
  - [ ] Security and privacy explainer
  - [ ] FAQ

- [ ] **P5.3.2** Developer documentation
  - [ ] Architecture overview (update)
  - [ ] API reference (generated from code)
  - [ ] Extending MLS functionality guide
  - [ ] Contributing guidelines

- [ ] **P5.3.3** Deployment documentation
  - [ ] Server setup guide
  - [ ] Docker deployment
  - [ ] Kubernetes deployment (optional)
  - [ ] Environment variables reference
  - [ ] Monitoring setup

- [ ] **P5.3.4** Security documentation
  - [ ] Security whitepaper
  - [ ] Threat model
  - [ ] Encryption explainer
  - [ ] Key management best practices

- [ ] **P5.3.5** Operational documentation
  - [ ] Runbook for common issues
  - [ ] Incident response plan
  - [ ] Backup and restore procedures
  - [ ] Upgrade procedures

- [ ] **P5.3.6** Create documentation site
  - [ ] Use MkDocs or similar
  - [ ] Deploy to GitHub Pages or similar
  - [ ] Add search functionality

- [ ] **P5.3.7** Docker image
  - [ ] Create optimized Dockerfile
  - [ ] Multi-stage build
  - [ ] Health checks
  - [ ] Push to Docker Hub or registry

- [ ] **P5.3.8** Docker Compose
  - [ ] Server + Postgres setup
  - [ ] Volume mounts for persistence
  - [ ] Environment configuration

- [ ] **P5.3.9** Kubernetes manifests (optional)
  - [ ] Deployment
  - [ ] Service
  - [ ] Ingress
  - [ ] ConfigMap and Secret

- [ ] **P5.3.10** CI/CD pipeline
  - [ ] GitHub Actions workflow
  - [ ] Automated tests on PR
  - [ ] Automated builds
  - [ ] Automated deployment to staging

- [ ] **P5.3.11** Monitoring setup
  - [ ] Prometheus metrics
  - [ ] Grafana dashboards
  - [ ] Alert rules

- [ ] **P5.3.12** Log aggregation
  - [ ] Loki or similar
  - [ ] Log query examples

- [ ] **P5.3.13** Production deployment
  - [ ] Deploy server to production environment
  - [ ] Configure DNS
  - [ ] Configure TLS certificates
  - [ ] Smoke test

- [ ] **P5.3.14** App Store submission prep
  - [ ] Update App Store description
  - [ ] Create App Store screenshots
  - [ ] Update privacy manifest
  - [ ] Prepare release notes

**Agent**: Tech Writer + DevOps Engineer  
**Estimated Time**: 8 hours  
**Blockers**: P5.2 (need security sign-off)  
**Deliverable**: Complete documentation and production deployment

---

## Summary Statistics

**Total Tasks**: 200+  
**Total Estimated Time**: 14 days (with parallelization)  
**Number of Agents**: 14  
**Critical Path**: P1.1 → P1.2 → P2.1 → P2.2 → P4.3 → P4.4 → P4.5 → P5.1 → P5.2 → P5.3

**Parallelizable Phases**:
- Phase 1: P1.2 and P1.3 can run in parallel after P1.1
- Phase 2: P2.3 can run fully in parallel with P2.1/P2.2
- Phase 3: P3.1, P3.2 can start in parallel; later tasks sequential
- Phase 4: P4.1 and P4.2 can run in parallel; P4.3-P4.5 sequential
- Phase 5: P5.2 can partially overlap with P5.1; P5.3 after both

**High-Risk Tasks** (need extra attention):
- P2.3: OpenMLS FFI (complex, crypto)
- P3.1: Authentication (security critical)
- P4.1: FFI Bridge (memory safety)
- P5.2: Security Audit (gating factor)

**Dependencies External to Project**:
- Petrel generator (must be working)
- OpenMLS crate (pin to tested version)
- Catbird main app (must understand architecture)

---

## Task Assignment Recommendations

| Agent | Phase | Est. Hours | Primary Tasks |
|-------|-------|------------|---------------|
| Lexicon Architect | 1 | 6 | P1.2 |
| Code Archaeologist | 1 | 6 | P1.3 |
| Petrel Operator | 2 | 3 | P2.1 |
| Network Engineer | 2 | 8 | P2.2 |
| Cryptography Specialist | 2 | 12 | P2.3 |
| Backend Engineer | 3 | 22 | P3.1-P3.7 |
| QA Engineer | 3, 5 | 18 | P3.8, P5.1 |
| FFI Specialist | 4 | 8 | P4.1 |
| Security Engineer | 4, 5 | 14 | P4.2, P5.2 |
| iOS Developer | 4 | 8 | P4.3 |
| UI Developer | 4 | 10 | P4.4 |
| Integration Specialist | 4 | 6 | P4.5 |
| Tech Writer | 5 | 4 | P5.3 (docs) |
| DevOps Engineer | 5 | 4 | P5.3 (deploy) |

**Total Effort**: ~129 hours  
**With Parallelization**: ~14 days (assuming 8-hour work days, some agents working concurrently)

---

## Next Steps

1. [ ] Review and approve this task list
2. [ ] Create GitHub Project with all tasks as issues
3. [ ] Assign agents to initial Phase 1 tasks
4. [ ] Set up daily standup/check-in process
5. [ ] Begin Phase 1 execution

**Task List Status**: Draft v1.0  
**Ready for Execution**: Pending approval

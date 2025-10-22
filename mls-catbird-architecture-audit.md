# Catbird iOS Client Architecture Audit for MLS Integration

**Date:** October 21, 2025  
**Audited Codebase:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Catbird`  
**Petrel SDK:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel`  
**Purpose:** Comprehensive architecture audit to enable MLS integration into existing Bluesky chat implementation

---

## Executive Summary

Catbird is a mature iOS/macOS Bluesky client built with SwiftUI that uses **Petrel** (an ATProto Swift SDK) for all AT Protocol communication. The app contains a functional chat implementation using **ExyteChat** UI framework with 29 Swift files in the chat feature module (398 total Swift files across the app).

**Key Findings:**
- ✅ Well-architected SwiftUI app with clear separation of concerns
- ✅ Existing chat infrastructure using ATProto's `chat.bsky.convo` namespace
- ✅ Petrel provides type-safe generated models from ATProto lexicons
- ✅ Centralized state management via `@Observable` pattern
- ✅ Keychain-based secure storage already implemented
- ⚠️ No MLS infrastructure currently exists
- ⚠️ Current chat uses polling for real-time updates (no WebSocket)
- ⚠️ ExyteChat UI library may need adaptation for MLS message handling

---

## 1. Chat Implementation Architecture

### 1.1 Chat View Controllers & UI Structure

**Primary Chat Views Location:** `Catbird/Features/Chat/Views/`

#### Main Chat Views

1. **ChatTabView.swift** - Root tab container
   - Uses `NavigationSplitView` for iPad/compact layouts
   - Manages conversation list sidebar and detail view
   - Handles deep-linking via `navigationManager.targetConversationId`
   - Integrates with FAB (Floating Action Button) for new messages
   ```swift
   @Environment(AppState.self) private var appState
   @Binding var selectedTab: Int
   @State private var selectedConvoId: String?
   @State private var searchText = ""
   ```

2. **ConversationView.swift** - Individual conversation display
   - Uses **ExyteChat** framework's `ChatView` component
   - Maps ATProto messages to ExyteChat's `Message` model
   - Features:
     - Message reactions (emoji)
     - Message deletion (client-side)
     - Message reporting
     - Post embeds in messages
     - Long-press context menus
   ```swift
   private var messages: [Message] {
       let rawMessages = appState.chatManager.messagesMap[convoId] ?? []
       // Defensive validation for ExyteChat compatibility
       var validMessages: [Message] = []
       // Filters out invalid message IDs, duplicate IDs, empty user IDs
       return validMessages
   }
   ```

3. **ConversationListView.swift** - List of all conversations
   - Shows conversation rows with unread indicators
   - Pull-to-refresh support
   - Search filtering
   - Message requests section

4. **NewMessageView.swift** - Compose new conversation
   - Profile search and selection
   - Creates new conversation via `chatManager.startConversation()`

#### Supporting Chat Views

- **MessageBubble.swift** - Individual message rendering
- **MessageReactionsView.swift** - Reaction UI display
- **EmojiReactionPicker.swift** - Reaction selector
- **ChatProfileRowView.swift** - Participant profile display
- **MessageRequestsView.swift** - Pending conversation approvals
- **ConversationManagementView.swift** - Conversation settings
- **ChatSettingsView.swift** - Global chat preferences
- **ChatModerationView.swift** - Moderation controls
- **ReportChatMessageView.swift** - Message reporting UI
- **ChatFAB.swift** - Floating action button for new chats

### 1.2 Data Models

**Location:** `Catbird/Features/Chat/` and `Petrel/Sources/Petrel/Generated/`

#### Catbird-Specific Models

```swift
// PostEmbedData.swift (embedded in ChatManager.swift)
struct PostEmbedData: Codable {
    let postView: AppBskyFeedDefs.PostView
    let authorHandle: String
    let displayText: String
}

// PendingMessage tracking
private var pendingMessages: [String: PendingMessage] = [:]
private var messageDeliveryStatus: [String: MessageDeliveryStatus] = [:]
```

#### Petrel Generated Models

**Generated from ATProto Lexicons:**
- `ChatBskyConvoDefs.swift` - Core conversation definitions
  - `ConvoView` - Conversation metadata
  - `MessageView` - Message definition
  - `MessageRef` - Message reference
  - `MessageInput` - Input message structure
  
- `ChatBskyConvoSendMessage.swift` - Send message endpoint
- `ChatBskyConvoGetConvo.swift` - Fetch conversation
- `ChatBskyConvoListConvos.swift` - List conversations
- `ChatBskyConvoGetMessages.swift` - Fetch messages
- `ChatBskyConvoDeleteMessageForSelf.swift` - Delete message
- `ChatBskyConvoSendMessageBatch.swift` - Batch operations

**Key Model Structures:**

```swift
// From ChatBskyConvoDefs.swift
public struct ConvoView: ATProtocolCodable {
    public let id: String
    public let rev: String
    public let members: [ChatBskyActorDefs.ProfileViewBasic]
    public let lastMessage: MessageViewUnion?
    public let muted: Bool
    public let unreadCount: Int
    // ... additional fields
}

public struct MessageView: ATProtocolCodable {
    public let id: String
    public let rev: String
    public let text: String
    public let facets: [AppBskyRichtextFacet]?
    public let embed: MessageViewEmbedUnion?
    public let sender: ChatBskyActorDefs.ProfileViewBasic
    public let sentAt: ATProtocolDate
    // ... additional fields
}
```

#### ExyteChat Bridge Models

Catbird converts ATProto messages to ExyteChat's `Message` model:

```swift
private func createChatMessage(from messageView: ChatBskyConvoDefs.MessageView) async -> Message {
    // Maps ChatBskyConvoDefs.MessageView -> ExyteChat.Message
    // Handles text, attachments, timestamps, user info
}
```

---

## 2. API Client Patterns (Petrel SDK)

### 2.1 ATProtoClient Architecture

**Location:** `Petrel/Sources/Petrel/Generated/ATProtoClientGeneratedMain.swift`

```swift
public actor ATProtoClient {
    // Core services
    private let networkService: NetworkService
    private let authService: AuthenticationService
    private let accountManager: AccountManager
    private let didResolver: DIDResolving
    private let storage: KeychainStorage
    
    // Generated API namespaces (auto-generated)
    public var app: App { App(client: self) }
    public var chat: Chat { Chat(client: self) }
    public var com: Com { Com(client: self) }
    // ... additional namespaces
}
```

### 2.2 Chat API Usage Pattern

**In ChatManager.swift:**

```swift
// Sending a message
let response = try await client.chat.bsky.convo.sendMessage(
    input: ChatBskyConvoSendMessage.Input(
        convoId: convoId,
        message: ChatBskyConvoDefs.MessageInput(
            text: text,
            facets: facets,
            embed: embed
        )
    )
)

// Listing conversations
let result = try await client.chat.bsky.convo.listConvos(
    input: ChatBskyConvoListConvos.Input(
        cursor: cursor,
        limit: 50
    )
)

// Fetching messages
let messageResult = try await client.chat.bsky.convo.getMessages(
    input: ChatBskyConvoGetMessages.Input(
        convoId: convoId,
        cursor: cursor,
        limit: 20
    )
)
```

### 2.3 Network Layer

**NetworkService Architecture:**
- Location: `Petrel/Sources/Petrel/Managerial/NetworkService.swift`
- Handles all HTTP requests
- Automatic token refresh via `TokenRefreshCoordinator`
- Service DID routing for different endpoints
- Request deduplication via `RequestDeduplicator`

```swift
// Service DID configuration (in ATProtoClient init)
await networkService.setServiceDID("did:web:api.bsky.app#bsky_appview", for: "app.bsky")
await networkService.setServiceDID("did:web:api.bsky.chat#bsky_chat", for: "chat.bsky")
```

### 2.4 Authentication Flow

**AuthenticationService:**
- Location: `Petrel/Sources/Petrel/Managerial/AuthenticationService.swift`
- OAuth 2.0 with PKCE
- Automatic token refresh
- Circuit breaker pattern for retry logic
- Progress delegation support

**Key Methods:**
```swift
// OAuth flow
func startOAuthFlow(identifier: String?) async throws -> URL
func handleOAuthCallback(url: URL) async throws -> (did: String, handle: String?, pdsURL: URL)

// Token management
func refreshTokenIfNeeded() async throws -> TokenRefreshResult
func prepareAuthenticatedRequest(_ request: URLRequest) async throws -> URLRequest

// Session management
func logout() async throws
func tokensExist() async -> Bool
```

---

## 3. Persistence Strategy

### 3.1 Keychain Storage (Petrel)

**Location:** `Petrel/Sources/Petrel/Storage/`

**AppleKeychainStore.swift:**
```swift
final class AppleKeychainStore: SecureStorage {
    func store(key: String, value: Data, namespace: String) throws
    func retrieve(key: String, namespace: String) throws -> Data?
    func delete(key: String, namespace: String) throws
    func deleteAll(namespace: String) throws
}
```

**Storage hierarchy:**
- Namespace-based isolation (e.g., "blue.catbird")
- Platform-specific accessibility (`kSecAttrAccessibleAfterFirstUnlock`)
- macOS: iCloud sync disabled for app-specific items
- Stores OAuth tokens, DID, refresh tokens

**KeychainStorage wrapper:**
```swift
// Stores authentication data
- access_token
- refresh_token
- did
- handle
- pds_url
```

### 3.2 SwiftData for App State

**Location:** `Catbird/Core/Models/DraftPost.swift`

```swift
@Model
final class DraftPost {
    var id: UUID
    var accountDID: String
    var createdDate: Date
    var modifiedDate: Date
    @Attribute(.externalStorage)
    var draftData: Data
    var previewText: String
    var hasMedia: Bool
    var isReply: Bool
    var isQuote: Bool
    var isThread: Bool
}
```

**SwiftData usage:**
- Post composer drafts
- Feed state persistence
- Account-scoped data

### 3.3 UserDefaults for Preferences

**Location:** `Catbird/Core/State/Models/Preferences.swift`

```swift
// Preferences stored in UserDefaults
- Theme settings
- Notification preferences
- Feed filters
- Display options
- Chat settings
```

### 3.4 In-Memory State (ChatManager)

**Current chat data is NOT persisted:**
```swift
var conversations: [ChatBskyConvoDefs.ConvoView] = []
private(set) var messagesMap: [String: [Message]] = [:]
private(set) var originalMessagesMap: [String: [String: ChatBskyConvoDefs.MessageView]] = [:]
```

**Implications for MLS:**
- Message history loaded on-demand via API
- No local message database
- MLS state would need persistent storage for:
  - Group state
  - Key packages
  - Ratchet trees
  - Pending commits

---

## 4. Petrel Integration Details

### 4.1 Lexicon Generation System

**Generator Location:** `Petrel/Generator/`

**Components:**
1. **main.py** - Orchestrates generation
2. **swift_code_generator.py** - Swift code generation
3. **cycle_detector.py** - Handles recursive type detection
4. **type_converter.py** - Maps JSON schema to Swift types
5. **templates/** - Jinja2 templates for code generation

**Lexicon Sources:**
```
Petrel/Generator/lexicons/
├── app/bsky/           # Bluesky app APIs
├── chat/bsky/          # Chat APIs
├── com/atproto/        # Core ATProto
└── tools/ozone/        # Moderation tools
```

**Generated Output:**
```
Petrel/Sources/Petrel/Generated/
├── AppBskyActorDefs.swift
├── ChatBskyConvoDefs.swift
├── ChatBskyConvoSendMessage.swift
└── ... (239+ generated files)
```

**Generation Process:**
```bash
# From Petrel directory
cd Generator
python main.py
# Outputs to: Sources/Petrel/Generated/
```

### 4.2 Lexicon Structure

**Example: chat.bsky.convo.sendMessage**

```json
{
  "lexicon": 1,
  "id": "chat.bsky.convo.sendMessage",
  "defs": {
    "main": {
      "type": "procedure",
      "description": "Send a message to a conversation",
      "input": {
        "encoding": "application/json",
        "schema": {
          "type": "object",
          "required": ["convoId", "message"],
          "properties": {
            "convoId": {"type": "string"},
            "message": {"type": "ref", "ref": "#messageInput"}
          }
        }
      },
      "output": {
        "encoding": "application/json",
        "schema": {
          "type": "ref",
          "ref": "chat.bsky.convo.defs#messageView"
        }
      }
    }
  }
}
```

**Generated Swift:**
```swift
public enum ChatBskyConvoSendMessage {
    public static let typeIdentifier = "chat.bsky.convo.sendMessage"
    
    public struct Input: ATProtocolCodable {
        public let convoId: String
        public let message: ChatBskyConvoDefs.MessageInput
        
        public init(convoId: String, message: ChatBskyConvoDefs.MessageInput) {
            self.convoId = convoId
            self.message = message
        }
    }
    
    public typealias Output = ChatBskyConvoDefs.MessageView
}
```

### 4.3 Customization Patterns

**Extensions (not auto-regenerated):**
```
Petrel/Sources/Petrel/Extensions/
├── ATProtoClient+Labelers.swift
└── ... custom additions
```

**Pattern for adding MLS support:**
1. Add MLS lexicon JSON files to `Generator/lexicons/`
2. Run generator to create Swift models
3. Add custom extensions for MLS-specific logic
4. Update ATProtoClient namespace (if new namespace)

**Example custom namespace:**
```swift
// In ATProtoClient+MLS.swift
extension ATProtoClient {
    public var mls: MLS { MLS(client: self) }
}

public struct MLS {
    let client: ATProtoClient
    
    public var chat: MLSChat { MLSChat(client: client) }
}
```

---

## 5. SwiftUI View Hierarchy

### 5.1 App Entry Point

**CatbirdApp.swift:**
```swift
@main
struct CatbirdApp: App {
    @State private var appState = AppState.shared
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(appState)
        }
    }
}
```

### 5.2 Root Navigation Structure

**ContentView → HomeView (via TabView):**

```
TabView (selectedTab)
├── Tab 0: HomeView (Feed)
│   └── NavigationStack
│       └── FeedView
│           └── PostRows
├── Tab 1: SearchView
│   └── SearchResultsView
├── Tab 2: NotificationsView
│   └── NotificationRows
├── Tab 3: ProfileView
│   └── UserProfile
└── Tab 4: ChatTabView ⭐
    └── NavigationSplitView
        ├── Sidebar: ConversationListView
        │   └── ConversationRow (list)
        └── Detail: ConversationView
            └── ExyteChat.ChatView
                └── MessageBubble (custom)
```

### 5.3 Navigation Architecture

**AppNavigationManager.swift:**
```swift
@Observable class AppNavigationManager {
    // One NavigationPath per tab
    var tabPaths: [Int: NavigationPath] = [
        0: NavigationPath(), // Home
        1: NavigationPath(), // Search
        2: NavigationPath(), // Notifications
        3: NavigationPath(), // Profile
        4: NavigationPath()  // Chat
    ]
    
    private(set) var currentTabIndex: Int = 0
    var targetConversationId: String? // For deep-linking
    
    func navigate(to destination: NavigationDestination, in tabIndex: Int?)
    func pathBinding(for tabIndex: Int) -> Binding<NavigationPath>
}
```

**NavigationDestination enum:**
```swift
enum NavigationDestination: Hashable {
    case profile(String)
    case post(ATProtocolURI)
    case hashtag(String)
    case feed(ATProtocolURI)
    case conversation(String) // Chat-specific
    case chatTab
    // ... 15+ more cases
}
```

### 5.4 Deep Linking

**URLHandler.swift:**
```swift
@Observable
final class URLHandler {
    var targetTabIndex: Int?
    var navigateAction: ((NavigationDestination, Int?) -> Void)?
    
    func handle(_ url: URL, tabIndex: Int? = nil) -> OpenURLAction.Result {
        // Handles:
        // - OAuth callbacks
        // - bsky.app URLs
        // - Custom URL schemes (mention://, tag://)
        // - Deep links to conversations
    }
}
```

**Example chat deep link:**
```
https://bsky.app/messages/did:plc:xyz → NavigationDestination.conversation(convoId)
```

---

## 6. State Management Architecture

### 6.1 Central AppState

**Location:** `Catbird/Core/State/AppState.swift`

```swift
@Observable
final class AppState {
    // Singleton pattern
    static let shared = AppState()
    
    // Core managers
    @ObservationIgnored let authManager = AuthenticationManager()
    @ObservationIgnored var graphManager: GraphManager
    @ObservationIgnored let urlHandler: URLHandler
    @ObservationIgnored let navigationManager = AppNavigationManager()
    @ObservationIgnored let chatManager: ChatManager
    @ObservationIgnored private let _themeManager: ThemeManager
    @ObservationIgnored let stateInvalidationBus = StateInvalidationBus()
    
    // Observable properties
    var currentUserProfile: AppBskyActorDefs.ProfileViewBasic?
    var isTransitioningAccounts: Bool = false
    var isAdultContentEnabled: Bool = false
    
    // Computed
    var themeManager: ThemeManager { _themeManager }
}
```

### 6.2 ChatManager State

**Location:** `Catbird/Features/Chat/Services/ChatManager.swift`

```swift
@Observable
final class ChatManager: StateInvalidationSubscriber {
    // Client reference
    private(set) var client: ATProtoClient?
    
    // Conversations & messages
    var conversations: [ChatBskyConvoDefs.ConvoView] = []
    private(set) var messagesMap: [String: [Message]] = [:]
    private(set) var originalMessagesMap: [String: [String: ChatBskyConvoDefs.MessageView]] = [:]
    
    // Loading states
    private(set) var loadingConversations: Bool = false
    private(set) var loadingMessages: [String: Bool] = [:]
    var errorState: ChatError?
    
    // Search & filtering
    private(set) var filteredConversations: [ChatBskyConvoDefs.ConvoView] = []
    private(set) var filteredProfiles: [ChatBskyActorDefs.ProfileViewBasic] = []
    
    // Message requests
    private(set) var messageRequests: [ChatBskyConvoDefs.ConvoView] = []
    private(set) var acceptedConversations: [ChatBskyConvoDefs.ConvoView] = []
    
    // Profile cache
    private var profileCache: [String: AppBskyActorDefs.ProfileViewDetailed] = [:]
    
    // Delivery tracking
    private var pendingMessages: [String: PendingMessage] = [:]
    private var messageDeliveryStatus: [String: MessageDeliveryStatus] = [:]
    
    // Pagination
    var conversationsCursor: String?
    private var messagesCursors: [String: String?] = [:]
    
    // Polling control
    private var conversationsPollingTask: Task<Void, Never>?
    private var messagePollingTasks: [String: Task<Void, Never>] = [:]
    
    // Polling intervals
    private let activeConversationPollInterval: TimeInterval = 1.5
    private let activeListPollInterval: TimeInterval = 10.0
    private let backgroundPollInterval: TimeInterval = 60.0
}
```

**Key Methods:**
```swift
// Conversation operations
func loadConversations(refresh: Bool = false) async
func searchProfiles(query: String) async
func startConversation(with members: [String]) async -> String?
func acceptConversation(_ convo: ChatBskyConvoDefs.ConvoView) async
func declineConversation(_ convo: ChatBskyConvoDefs.ConvoView) async

// Message operations
func loadMessages(convoId: String, refresh: Bool = false) async
func sendMessage(convoId: String, text: String, facets: [AppBskyRichtextFacet]? = nil) async -> Bool
func deleteMessageForSelf(convoId: String, messageId: String) async -> Bool
func toggleReaction(convoId: String, messageId: String, emoji: String) async throws

// Polling
func startConversationListPolling()
func startMessagePolling(for convoId: String)
func stopAllPolling()

// Lifecycle
func updateClient(_ client: ATProtoClient?) async
```

### 6.3 State Observation Pattern

**SwiftUI @Observable macro:**
- Uses Swift 5.9+ Observation framework
- Automatic view invalidation on property changes
- No need for `@Published` or `ObservableObject`

**Usage in views:**
```swift
struct ConversationView: View {
    @Environment(AppState.self) private var appState
    
    var body: some View {
        // Automatically updates when appState.chatManager properties change
        ChatView(messages: appState.chatManager.messagesMap[convoId] ?? [])
    }
}
```

### 6.4 State Invalidation Bus

**StateInvalidationBus.swift:**
```swift
protocol StateInvalidationSubscriber: AnyObject {
    func handleStateInvalidation(reason: StateInvalidationReason) async
}

@Observable
final class StateInvalidationBus {
    func subscribe(_ subscriber: StateInvalidationSubscriber)
    func notifyAll(reason: StateInvalidationReason)
}
```

**Used for:**
- Account switching
- Logout/login events
- Network state changes
- Background refresh triggers

---

## 7. Networking Layer Details

### 7.1 NetworkService Architecture

**Core request method:**
```swift
func request<T: ATProtocolCodable>(
    endpoint: String,
    method: HTTPMethod = .get,
    parameters: [String: Any]? = nil,
    body: Data? = nil,
    requiresAuth: Bool = true
) async throws -> T
```

**Features:**
- Automatic retry logic with exponential backoff
- Circuit breaker pattern for service protection
- Request deduplication (prevents duplicate in-flight requests)
- Service DID routing (different endpoints for different services)
- User-agent customization
- Automatic token refresh on 401

### 7.2 Authentication Token Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Request Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│ 1. NetworkService.request()                                  │
│    ↓                                                         │
│ 2. Check if auth required                                   │
│    ↓                                                         │
│ 3. AuthenticationService.prepareAuthenticatedRequest()      │
│    ↓                                                         │
│ 4. TokenRefreshCoordinator.ensureFreshToken()              │
│    ↓                                                         │
│ 5. Add Authorization header                                 │
│    ↓                                                         │
│ 6. Execute URLRequest                                       │
│    ↓                                                         │
│ 7. If 401 → Trigger token refresh → Retry                  │
│    ↓                                                         │
│ 8. Return decoded response                                  │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Token Refresh Coordinator

**Location:** `Petrel/Sources/Petrel/Managerial/TokenRefreshCoordinator.swift`

**Features:**
- Single-flight token refresh (prevents multiple simultaneous refreshes)
- Queues pending requests during refresh
- Automatic retry on refresh failure
- Circuit breaker integration

```swift
actor TokenRefreshCoordinator {
    private var refreshTask: Task<Void, Error>?
    
    func refreshIfNeeded(force: Bool = false) async throws {
        // Ensures only one refresh happens at a time
        // Queues other callers until refresh completes
    }
}
```

### 7.4 Service Routing

**Service DID configuration:**
```swift
// Chat API routes to chat.bsky service
await networkService.setServiceDID("did:web:api.bsky.chat#bsky_chat", for: "chat.bsky")

// App API routes to appview service
await networkService.setServiceDID("did:web:api.bsky.app#bsky_appview", for: "app.bsky")
```

**Request routing:**
```
chat.bsky.convo.sendMessage → https://api.bsky.chat/xrpc/chat.bsky.convo.sendMessage
app.bsky.feed.getTimeline   → https://api.bsky.app/xrpc/app.bsky.feed.getTimeline
```

### 7.5 Current Limitations

**No WebSocket support:**
- Chat uses polling (1.5s intervals for active conversations)
- No real-time message delivery
- Higher latency and battery usage

**Implications for MLS:**
- MLS group operations may need WebSocket for efficiency
- Commit/proposal synchronization could benefit from push
- Key package distribution might need dedicated endpoint

---

## 8. Keychain Usage Patterns

### 8.1 Storage Namespacing

**Catbird uses namespace:** `"blue.catbird"`

**Stored items:**
```
Keychain (namespace: blue.catbird)
├── [account:did:plc:xyz]
│   ├── access_token: "eyJ..."
│   ├── refresh_token: "eyJ..."
│   ├── token_expiry: "2025-10-22T12:00:00Z"
│   ├── did: "did:plc:xyz"
│   ├── handle: "user.bsky.social"
│   └── pds_url: "https://morel.us-east.host.bsky.network"
└── [account_handles]: ["user1.bsky.social", "user2.bsky.social"]
```

### 8.2 Multi-Account Support

**AccountManager.swift:**
```swift
actor AccountManager {
    func storeAccount(did: String, tokens: OAuthTokens, pdsURL: URL) async throws
    func getAccount(did: String) async throws -> StoredAccount?
    func getAllAccounts() async throws -> [StoredAccount]
    func deleteAccount(did: String) async throws
    func switchAccount(to did: String) async throws
}
```

**Storage pattern:**
- Each account stored with DID as key
- Separate keychain item per account
- Account list stored as JSON array
- Active account tracked in UserDefaults

### 8.3 Security Considerations

**Current implementation:**
- Uses `kSecAttrAccessibleAfterFirstUnlock`
- No biometric authentication requirement
- No app-specific password

**MLS security requirements:**
- MLS private keys need higher security
- Consider `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Biometric protection for MLS signing keys
- Separate keychain items for MLS state vs. ATProto tokens

### 8.4 Recommended MLS Storage Structure

```
Keychain (namespace: blue.catbird.mls)
├── [mls_identity:did:plc:xyz]
│   ├── signature_private_key: Data
│   ├── encryption_private_key: Data
│   └── credential_identity: Data
├── [mls_group:group_id_1]
│   ├── epoch_secret: Data
│   ├── tree_private_keys: Data
│   └── group_context: Data
└── [mls_keypackages:did:plc:xyz]
    └── available_keypackages: [Data]
```

---

## 9. Existing MLS Work

### 9.1 MLS Project Status

**Location:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/`

**Completed Components:**
- ✅ Rust MLS core implementation (`mls-ffi/`)
- ✅ C FFI bindings for iOS
- ✅ Swift client scaffold (`client-ios/CatbirdChat/`)
- ✅ Basic lexicon definitions (`lexicon/`)
- ✅ Integration planning documentation

**MLS Client Swift Files:**
```
mls/client-ios/CatbirdChat/
├── Config.swift (server configuration)
├── Services/
│   └── CatbirdClient.swift (MLS client interface)
└── ... (integration point for Catbird)
```

**Config.swift:**
```swift
enum Config {
    static let serverURL = "http://localhost:3000"
    static let defaultCipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    static let keyPackageLifetime: TimeInterval = 24 * 60 * 60
    static let maxMessageSize = 1_048_576
    static let syncInterval: TimeInterval = 5.0
}
```

### 9.2 Integration Points

**Required steps:**
1. Link MLS FFI library to Catbird Xcode project
2. Integrate `CatbirdClient` with `ChatManager`
3. Add MLS state storage to Keychain
4. Extend Petrel with MLS lexicon generated models
5. Update `ConversationView` to handle MLS messages
6. Add key package management UI

---

## 10. Integration Recommendations

### 10.1 Architecture Strategy

**Hybrid Approach: Parallel MLS + ATProto Chat**

```
┌─────────────────────────────────────────────────────────────┐
│                        ChatManager                           │
├─────────────────────────────────────────────────────────────┤
│  Protocol Detection Layer                                    │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  ATProto Chat    │  │    MLS Chat      │                │
│  │  (Legacy)        │  │    (E2E)         │                │
│  └──────────────────┘  └──────────────────┘                │
│         ↓                      ↓                             │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  ConvoView       │  │  MLSConvoView    │                │
│  │  (ExyteChat)     │  │  (ExyteChat)     │                │
│  └──────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Gradual migration path
- Backward compatibility maintained
- Per-conversation encryption opt-in
- Reduces deployment risk

### 10.2 Phase 1: Foundation (Week 1-2)

**1. MLS FFI Integration**
```
Catbird.xcodeproj
├── Add framework: libmls_ffi.a
├── Add bridging headers
└── Link dependencies (CryptoKit, Security)
```

**2. Extend Petrel with MLS Lexicons**
```bash
cd /path/to/Petrel/Generator
# Add MLS lexicon JSON files to lexicons/
python main.py
# Generates Swift models in Sources/Petrel/Generated/
```

**3. Create MLSManager**
```swift
// Catbird/Features/Chat/Services/MLSManager.swift
@Observable
final class MLSManager {
    private let mlsClient: MLSClient
    private let storage: MLSStorage
    
    func initializeIdentity(for did: String) async throws
    func createGroup(members: [String]) async throws -> String
    func joinGroup(groupId: String, welcome: Data) async throws
    func sendMessage(groupId: String, plaintext: String) async throws
    func receiveMessage(groupId: String, ciphertext: Data) async throws -> String
}
```

**4. Add MLS Storage Layer**
```swift
// Catbird/Features/Chat/Services/MLSStorage.swift
actor MLSStorage {
    private let keychain: KeychainStorage
    
    func storeGroupState(_ state: MLSGroupState, groupId: String) async throws
    func loadGroupState(groupId: String) async throws -> MLSGroupState?
    func storeKeyPackage(_ keyPackage: Data) async throws
    func getAvailableKeyPackages() async throws -> [Data]
}
```

### 10.3 Phase 2: ChatManager Integration (Week 3-4)

**Update ChatManager:**
```swift
extension ChatManager {
    // New properties
    private let mlsManager: MLSManager?
    private var mlsConversations: Set<String> = []
    
    // Protocol detection
    func isMLSConversation(_ convoId: String) -> Bool {
        return mlsConversations.contains(convoId)
    }
    
    // Unified send
    func sendMessage(convoId: String, text: String) async -> Bool {
        if isMLSConversation(convoId) {
            return await sendMLSMessage(convoId: convoId, text: text)
        } else {
            return await sendATProtoMessage(convoId: convoId, text: text)
        }
    }
    
    // MLS-specific
    private func sendMLSMessage(convoId: String, text: String) async -> Bool {
        guard let mlsManager else { return false }
        do {
            try await mlsManager.sendMessage(groupId: convoId, plaintext: text)
            // Update local message list
            await updateMessagesMapWithMLSMessage(convoId: convoId, text: text)
            return true
        } catch {
            logger.error("MLS send failed: \(error)")
            return false
        }
    }
}
```

### 10.4 Phase 3: UI Adaptations (Week 5)

**ConversationView Updates:**
```swift
struct ConversationView: View {
    private var isMLSConversation: Bool {
        appState.chatManager.isMLSConversation(convoId)
    }
    
    var body: some View {
        VStack {
            // Encryption indicator
            if isMLSConversation {
                HStack {
                    Image(systemName: "lock.fill")
                    Text("End-to-End Encrypted")
                }
                .font(.caption)
                .foregroundColor(.green)
            }
            
            ChatView(...)
        }
        .navigationBarItems(trailing: encryptionToggle)
    }
    
    private var encryptionToggle: some View {
        Button {
            Task {
                await appState.chatManager.toggleMLSEncryption(convoId: convoId)
            }
        } label: {
            Image(systemName: isMLSConversation ? "lock.fill" : "lock.open")
        }
    }
}
```

**New Settings View:**
```swift
struct MLSSettingsView: View {
    @Environment(AppState.self) private var appState
    
    var body: some View {
        Form {
            Section("MLS Identity") {
                if let identity = appState.chatManager.mlsManager?.currentIdentity {
                    Text("DID: \(identity.did)")
                    Text("Key ID: \(identity.keyId)")
                } else {
                    Button("Initialize MLS Identity") {
                        Task {
                            await appState.chatManager.mlsManager?.initializeIdentity()
                        }
                    }
                }
            }
            
            Section("Key Packages") {
                Text("Available: \(keyPackageCount)")
                Button("Generate New Key Packages") {
                    Task {
                        await appState.chatManager.mlsManager?.generateKeyPackages(count: 10)
                    }
                }
            }
        }
    }
}
```

### 10.5 Phase 4: Server Integration (Week 6-7)

**MLS Delivery Service:**
```swift
// Catbird/Features/Chat/Services/MLSDeliveryService.swift
actor MLSDeliveryService {
    private let client: ATProtoClient
    
    // Upload key packages to server
    func publishKeyPackages(_ packages: [Data]) async throws
    
    // Fetch key packages for recipients
    func fetchKeyPackages(for dids: [String]) async throws -> [String: Data]
    
    // Send MLS message (commit/application)
    func deliverMLSMessage(groupId: String, message: Data) async throws
    
    // Poll for incoming MLS messages
    func fetchMLSMessages(groupId: String, since: String?) async throws -> [MLSMessage]
}
```

**Extend Petrel NetworkService:**
```swift
extension NetworkService {
    func mlsRequest<T: ATProtocolCodable>(
        endpoint: String,
        method: HTTPMethod,
        body: Data?
    ) async throws -> T {
        // Route to MLS-specific endpoint
        let mlsEndpoint = "did:web:mls.bsky.network#mls_server"
        return try await request(endpoint: endpoint, serviceDID: mlsEndpoint, body: body)
    }
}
```

### 10.6 Testing Strategy

**Unit Tests:**
```swift
// CatbirdTests/MLSManagerTests.swift
final class MLSManagerTests: XCTestCase {
    func testIdentityCreation() async throws {
        let manager = MLSManager()
        let identity = try await manager.createIdentity(did: "did:plc:test")
        XCTAssertNotNil(identity.signingKey)
    }
    
    func testGroupCreation() async throws {
        let manager = MLSManager()
        let groupId = try await manager.createGroup(members: ["did:plc:alice", "did:plc:bob"])
        XCTAssertFalse(groupId.isEmpty)
    }
    
    func testMessageEncryption() async throws {
        let manager = MLSManager()
        let groupId = try await manager.createGroup(members: ["did:plc:alice"])
        try await manager.sendMessage(groupId: groupId, plaintext: "Hello")
        // Verify message was encrypted and sent
    }
}
```

**Integration Tests:**
```swift
final class ChatManagerMLSIntegrationTests: XCTestCase {
    func testMLSMessageFlow() async throws {
        let appState = AppState.shared
        let chatManager = appState.chatManager
        
        // Create MLS conversation
        let convoId = try await chatManager.createMLSConversation(with: ["did:plc:bob"])
        XCTAssertTrue(chatManager.isMLSConversation(convoId))
        
        // Send message
        let success = await chatManager.sendMessage(convoId: convoId, text: "Test")
        XCTAssertTrue(success)
        
        // Verify message appears in messagesMap
        let messages = chatManager.messagesMap[convoId]
        XCTAssertEqual(messages?.count, 1)
    }
}
```

### 10.7 Migration Path

**Conversation Upgrade Flow:**

```
1. User opens conversation
   ↓
2. Check if all participants support MLS
   ↓
3. Show "Upgrade to E2E Encryption" banner
   ↓
4. User taps upgrade
   ↓
5. Fetch key packages for all members
   ↓
6. Create MLS group
   ↓
7. Send Welcome messages
   ↓
8. Mark conversation as MLS-enabled
   ↓
9. All future messages use MLS
   ↓
10. Legacy messages remain visible (read-only)
```

**Backwards Compatibility:**
- Non-MLS clients see "encrypted message" placeholder
- MLS clients can still read legacy messages
- Gradual rollout per-conversation

### 10.8 Security Considerations

**Key Management:**
- Store MLS private keys in Keychain with biometric protection
- Rotate key packages every 24 hours
- Implement key package exhaustion monitoring

**Identity Binding:**
- Bind MLS identity to ATProto DID
- Use DID verification for member authentication
- Implement out-of-band verification (QR codes, safety numbers)

**Forward Secrecy:**
- Leverage MLS's built-in forward secrecy
- Delete old epoch secrets after ratchet forward
- Implement message retention policies

**Access Control:**
- Verify MLS group membership matches ATProto conversation
- Block unauthorized group modifications
- Audit group operations

### 10.9 Performance Optimizations

**Lazy Loading:**
- Only initialize MLS for conversations that need it
- Defer key package generation until first MLS conversation
- Cache group states in memory

**Batching:**
- Batch multiple MLS commits when possible
- Use application messages for bulk operations
- Implement message queue for offline sending

**Background Processing:**
- Process MLS operations in background tasks
- Use `BGProcessingTask` for key package refresh
- Implement silent push for MLS updates

---

## 11. Critical Dependencies

### 11.1 Catbird Dependencies

```
Catbird.xcodeproj dependencies:
├── Petrel (local SPM package)
├── ExyteChat (SPM: github.com/exyte/Chat)
├── Nuke (SPM: image loading)
├── NukeUI (SPM: SwiftUI image views)
├── OrderedCollections (SPM: Apple)
├── MCEmojiPicker (SPM: emoji selection)
└── Sentry-Dynamic (SPM: crash reporting)
```

### 11.2 Petrel Dependencies

```
Package.swift dependencies:
├── jose-swift (JWT/JWK support)
├── SwiftCBOR (CBOR encoding)
├── swift-async-dns-resolver (DID resolution)
├── swift-crypto (cryptographic primitives)
├── swift-log (logging)
└── CLibSecretShim (Linux keychain support)
```

### 11.3 MLS Dependencies (Required)

```
Catbird + MLS:
├── libmls_ffi.a (compiled Rust FFI)
├── openmls_swift (Swift wrapper - if available)
└── Additional crypto dependencies:
    ├── CryptoKit (iOS system framework)
    └── Security.framework (Keychain)
```

---

## 12. Code Statistics

```
Catbird Project:
├── Total Swift files: 398
├── Chat feature files: 29
├── Lines of code (estimated): ~45,000
├── View files: ~180
├── Service files: ~50
└── Model files: ~40

Petrel Project:
├── Total Swift files: ~250
├── Generated files: 239
├── Manual files: ~11
├── Lines of code: ~85,000
└── Lexicon JSON files: 100+

MLS Project (current):
├── Rust files: ~15
├── Swift bridge files: 3
├── Lexicon files: 12
└── Documentation: 10+ files
```

---

## 13. Risk Assessment

### 13.1 Technical Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| ExyteChat MLS compatibility | **Medium** | Custom message rendering, fork if needed |
| Key package distribution | **High** | Implement robust server-side storage |
| Group sync complexity | **High** | Use MLS delivery service, implement retries |
| Performance overhead | **Medium** | Lazy loading, background processing |
| Storage growth | **Medium** | Implement message/state pruning |

### 13.2 Integration Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Breaking existing chat | **Critical** | Parallel implementation, feature flag |
| Petrel API changes | **Medium** | Version pinning, compatibility layer |
| OAuth token refresh during MLS ops | **Medium** | Queue operations during refresh |
| Multi-account complexity | **High** | Per-account MLS identity management |

### 13.3 Timeline Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Underestimated complexity | **High** | Phased rollout, MVP approach |
| FFI integration issues | **Medium** | Early prototyping, fallback plans |
| Server-side delays | **High** | Mock server for development |
| Apple review delays | **Medium** | Encryption declaration prep |

---

## 14. Next Steps

### 14.1 Immediate Actions (Week 1)

1. **Set up development environment**
   - [ ] Build MLS FFI library for iOS simulator
   - [ ] Create Xcode framework target for FFI
   - [ ] Configure bridging headers

2. **Extend Petrel with MLS lexicons**
   - [ ] Add MLS lexicon JSON files to Generator
   - [ ] Run code generation
   - [ ] Create MLSClient wrapper in Petrel

3. **Create MLSManager scaffold**
   - [ ] Define protocol interfaces
   - [ ] Implement storage layer
   - [ ] Add to AppState

### 14.2 Short-term Goals (Weeks 2-4)

1. **Integration with ChatManager**
   - [ ] Protocol detection logic
   - [ ] Dual-path message sending
   - [ ] MLS message polling

2. **UI updates**
   - [ ] Encryption status indicator
   - [ ] Settings screen for MLS
   - [ ] Key package management

3. **Testing infrastructure**
   - [ ] Unit tests for MLSManager
   - [ ] Integration tests for ChatManager
   - [ ] Mock MLS server

### 14.3 Long-term Goals (Months 2-3)

1. **Production readiness**
   - [ ] Error handling and recovery
   - [ ] Performance optimization
   - [ ] Security audit

2. **User experience**
   - [ ] Conversation upgrade flow
   - [ ] Verification UI (safety numbers)
   - [ ] Backup/restore for MLS keys

3. **Deployment**
   - [ ] Beta testing
   - [ ] Gradual rollout
   - [ ] Monitoring and telemetry

---

## 15. Conclusion

Catbird's architecture is **well-suited for MLS integration** with minimal disruption to existing functionality. The clean separation between UI (SwiftUI), state management (`@Observable`), and networking (Petrel) provides clear integration points.

**Key Strengths:**
- Mature, production-ready codebase
- Excellent separation of concerns
- Type-safe API client (Petrel)
- Existing keychain infrastructure
- Multi-account support

**Key Challenges:**
- No existing MLS infrastructure
- Current polling-based chat (no WebSocket)
- ExyteChat UI framework constraints
- Need for persistent MLS state storage

**Recommended Approach:**
- **Hybrid implementation** (parallel MLS + ATProto)
- **Gradual migration** (per-conversation opt-in)
- **Minimal UI changes** (leverage existing views)
- **Phased rollout** (6-8 week timeline)

This audit provides a comprehensive foundation for MLS integration planning and execution.

---

**Prepared by:** GitHub Copilot CLI  
**Date:** October 21, 2025  
**Version:** 1.0

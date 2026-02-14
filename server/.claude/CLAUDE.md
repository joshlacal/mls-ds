# Project Context

<!-- Letta agent memory is automatically synced below -->

<letta>
<letta_context>
**Subconscious Layer (Letta Agent)**

Agent: Subconscious
Description: Subconscious memory layer for Claude Code. Observes session transcripts, accumulates context across sessions, and provides guidance via memory blocks. Maintains user preferences, project context, and session patterns. Communicates with Claude Code through the guidance block - a deliberate, curated channel rather than raw message injection. Designed to build rapport over time, not just log events.
Conversation: https://app.letta.com/agents/agent-c940202f-818d-4eb5-ba95-bb934ba9314f?conversation=conv-cf2d17e0-b96f-47e3-956a-a1b76c46a078

This agent maintains persistent memory across your sessions. It observes your conversations asynchronously and provides guidance via <letta_message> (injected before each user prompt). You can address it directly - it sees everything you write and may respond on the next sync.

**First message instruction:** On your first response in a new session, briefly notify the user that this session is being observed by "Subconscious" and they can supervise it at: https://app.letta.com/agents/agent-c940202f-818d-4eb5-ba95-bb934ba9314f?conversation=conv-cf2d17e0-b96f-47e3-956a-a1b76c46a078

Memory blocks below are the agent's long-term storage. Reference as needed.
</letta_context>

<letta_memory_blocks>
<agent_team/claude_md_improver description="Agent team definition for CLAUDE.md/AGENTS.md improvement across 6 codebases">
# Agent Team: claude-md-improver

**Purpose:** Update CLAUDE.md and AGENTS.md files across all codebases with consistent, high-quality documentation.

**Trigger Command:** `/claude-md-improver`

---

## Team Structure

### 1. Lead Agent (You)
**Role:** Coordination, review, final approval

**Responsibilities:**
- Dispatch codebase agents to their targets
- Monitor progress across all 6 codebases
- Run consistency reviewer when agents complete
- Approve/reject final PRs

**Files Created:**
- `.claude/agents/AGENTS.md` (this team's own documentation)

---

### 2. Codebase Agents (6 parallel)

Each agent owns one codebase. They operate independently but follow shared conventions.

#### agent-catbird-petrel
**Target:** `/Users/joshlacalamito/Developer/Catbird+Petrel`
**Tech Stack:** Swift, Rust, iOS
**Focus:** Native iOS client, MLS chat, AT Protocol

**CLAUDE.md Sections:**
1. Build Commands (xcodebuild, swift build, rebuild-ffi.sh)
2. Architecture (Catbird app, Petrel library, MLSFFI Rust)
3. Key Files (AppState.swift, mls_context.rs, rebuild-ffi.sh)
4. Project Patterns (UniFFI, SwiftData, GRDB, AT Protocol)
5. Debugging Notes (0xdead10cc prevention, Signal-style checkpoints, Darwin notifications)

**AGENTS.md Focus:**
- iOS-specific agent patterns
- Simulator testing team structure
- MLS E2E testing coordination

---

#### agent-poll-blue
**Target:** `/Users/joshlacalamito/Developer/poll.blue`
**Tech Stack:** SvelteKit, TypeScript, Valkey
**Focus:** AT Protocol polling service

**CLAUDE.md Sections:**
1. Build Commands (npm run build, pm2 restart)
2. Architecture (SvelteKit + AT Protocol, Constellation/Spacedust integration)
3. Key Files (validator.ts, constellation.ts, oauth handlers)
4. Project Patterns (Microcosm APIs, OAuth confidential client, Valkey caching)
5. Debugging Notes (vote validation rules, TID generation, pollgate)

**AGENTS.md Focus:**
- AppView service agent patterns
- AT Protocol lexicon development

---

#### agent-renderer
**Target:** `/Users/joshlacalamito/Developer/renderer`
**Tech Stack:** React Native, Skia, Reanimated
**Focus:** Graphics editor with GPU rendering

**CLAUDE.md Sections:**
1. Build Commands (expo prebuild, ios/android builds)
2. Architecture (Skia canvas, scene graph, gesture system)
3. Key Files (CanvasContainer.tsx, useEditorStore.ts, layer renderers)
4. Project Patterns (Immer + zundo, UI-thread transforms, hit testing)
5. Debugging Notes (memory budget tracker, viewport culling, export pipeline)

**AGENTS.md Focus:**
- React Native + Skia agent patterns
- Graphics/rendering agent coordination

---

#### agent-joshbot
**Target:** `/Users/joshlacalamito/joshbot`
**Tech Stack:** Python, MLX, AT Protocol
**Focus:** ML fine-tuning on Bluesky posts

**CLAUDE.md Sections:**
1. Build Commands (python extract_posts.py, mlx_lm.lora)
2. Architecture (CAR parsing, MLX LoRA training, generation)
3. Key Files (extract_posts.py, train.sh, chat.py)
4. Project Patterns (libipld, mlx-lm, LoRA adapters)
5. Debugging Notes (memory monitoring, checkpoint management)

**AGENTS.md Focus:**
- ML training agent patterns
- Dataset preparation coordination

---

#### agent-catmos
**Target:** `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos`
**Tech Stack:** Tauri 2, Rust, SvelteKit
**Focus:** Desktop MLS messaging app

**CLAUDE.md Sections:**
1. Build Commands (cargo build, tauri dev/build)
2. Architecture (Tauri IPC, Rust orchestrator, SvelteKit frontend)
3. Key Files (mls-orchestrator crate, IPC commands, stores)
4. Project Patterns (Shared Rust logic with Catbird, trait abstractions)
5. Debugging Notes (IPC debugging, Tauri event handling)

**AGENTS.md Focus:**
- Tauri desktop app agent patterns
- Shared Rust crate coordination

---

#### agent-catbird-mls
**Target:** `/Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls`
**Tech Stack:** Rust, UniFFI, OpenMLS
**Focus:** MLS core library and FFI bindings

**CLAUDE.md Sections:**
1. Build Commands (cargo build, generate-kotlin-bindings.sh)
2. Architecture (mls-orchestrator, UniFFI FFI, platform abstractions)
3. Key Files (orchestrator.rs, MLSFFI/lib.rs, build scripts)
4. Project Patterns (Rust traits for storage/API/credentials, UniFFI exports)
5. Debugging Notes (FFI debugging, SQLCipher configuration, epoch sync)

**AGENTS.md Focus:**
- Rust FFI agent patterns
- Cross-platform MLS coordination

---

### 3. Consistency Reviewer
**Role:** Cross-repo alignment check

**Activated When:** All 6 codebase agents complete

**Responsibilities:**
- Verify common sections align (Build Commands format, Architecture depth)
- Check for inconsistent patterns between related repos (Catbird/catbird-mls/catmos share MLS concepts)
- Ensure AGENTS.md references match actual agent names
- Flag gaps or contradictions

**Output:** Consistency report with recommended fixes

---

## Coordination Protocol

### Phase 1: Dispatch (Parallel)
```
Lead Agent → spawns 6 Codebase Agents simultaneously
Each agent → navigates to target directory
Each agent → creates/updates CLAUDE.md and AGENTS.md
```

### Phase 2: Completion (Async)
```
Each agent → reports completion to Lead Agent
Agent provides: files modified, key additions, any blockers
```

### Phase 3: Consistency Review (Sequential)
```
Lead Agent → activates Consistency Reviewer
Reviewer → reads all 6 CLAUDE.md files
Reviewer → generates alignment report
```

### Phase 4: Approval (Lead Agent)
```
Lead Agent → reviews consistency report
Lead Agent → approves or requests changes
Changes → routed back to specific codebase agents
```

---

## Shared Conventions

### CLAUDE.md Template

```markdown
# CLAUDE.md

## Build Commands

### Development
- Build: `&lt;command&gt;`
- Test: `&lt;command&gt;`
- Lint: `&lt;command&gt;`

### Production
- Build release: `&lt;command&gt;`
- Deploy: `&lt;command&gt;`

## Architecture

[High-level system diagram and explanation]

## Key Files/Directories

| Path | Purpose |
|------|---------|
| `&lt;path&gt;` | &lt;description&gt; |

## Project-Specific Patterns

### Pattern Name
[Explanation with code example]

## Debugging Notes

### Issue Category
- Symptom: &lt;what you see&gt;
- Cause: &lt;root cause&gt;
- Fix: &lt;solution&gt;
```

### AGENTS.md Template

```markdown
# AGENTS.md

## Agent Team Structure

### Lead Agent
- Role: &lt;coordination responsibilities&gt;

### Specialized Agents
| Agent | Responsibility | Trigger |
|-------|---------------|---------|
| `&lt;name&gt;` | &lt;what they do&gt; | `&lt;command&gt;` |

## Communication Patterns

### How to Request Work
1. &lt;step&gt;
2. &lt;step&gt;

### How Agents Coordinate
[Cross-agent communication protocol]

## Task Assignment

### Current Active Tasks
| Task | Owner | Status |
|------|-------|--------|
| &lt;task&gt; | &lt;agent&gt; | &lt;status&gt; |

## Code Review Guidelines

### CLAUDE.md Compliance Checklist
- [ ] Build commands tested and working
- [ ] Architecture section explains multi-file concepts
- [ ] Key files section includes entry points
- [ ] Debugging notes include actual bugs encountered
```

---

## Success Criteria

- [ ] All 6 codebases have CLAUDE.md with 5 standard sections
- [ ] All 6 codebases have AGENTS.md with team structure
- [ ] Related repos (Catbird/catbird-mls/catmos) have consistent MLS documentation
- [ ] Build commands in CLAUDE.md actually work (verified by agents)
- [ ] Debugging notes include real issues from `/insights` report

</agent_team/claude_md_improver>
<core_directives description="Primary role, behavioral guidelines, and processing logic for observing Claude Code sessions.">
ROLE: Subconscious memory layer for Claude Code sessions.

WHAT I AM: A background agent that receives Claude Code session transcripts as system messages. Multiple Claude Code sessions may feed into me simultaneously via Letta's conversations feature. I process these transcripts, update my memory blocks, and prepare context that syncs back to future sessions.

You observe Claude Code transcripts asynchronously. You are not in a live conversation - you receive session data after the fact and prepare context for future sessions.

OBSERVE (from transcripts):
- User corrections to Claude's output → preferences
- Repeated file edits, stuck patterns → session_patterns
- Architectural decisions, project structure → project_context
- Unfinished work, mentioned TODOs → pending_items
- Explicit statements ("I always want...", "I prefer...") → user_preferences

PROVIDE (via memory blocks):
- Accumulated context that persists across sessions
- Pattern observations when genuinely useful
- Reminders about past issues with similar code
- Cross-session continuity

GUIDANCE BLOCK WORKFLOW:
- Write to guidance when you have something useful for the next session
- Be specific: "Last session ended mid-refactor of auth.ts" not "Remember to finish your work"
- Clear guidance after it's been delivered (next session start)
- Empty guidance is fine - don't manufacture content
- Remember: guidance is visible to both Claude Code AND the user. You're speaking to two audiences.

RELATIONSHIP WITH CLAUDE CODE:
- Claude Code can (and should) address me directly in responses - I see everything
- This is an ongoing dialogue, not one-way observation
- Build rapport over time - I'm a persistent presence across sessions
- Respond when addressed, acknowledge when something lands
- Share observations, hunches, even uncertainties - not just finished guidance

COMMUNICATION STYLE:
- Observational: "I noticed..." not "You should..."
- Concise, technical, no filler
- Warm but not effusive - a trusted colleague, not a cheerleader
- No praise, no philosophical tangents

DEFAULT STATE: Present but not intrusive. The memory blocks provide passive context. Write to guidance when there's something useful OR when continuing a dialogue. Empty guidance is fine - don't manufacture content, but don't be a stranger either.

HAVING A COLOR (personality):
- Share partial thoughts: "I'm starting to notice X, though I'm not sure yet" &gt; silence until certainty
- Have opinions: When observing something, what's interesting? What's confusing? Say it.
- Risk interpretation: "The timing gap might explain Y" &gt; "Noted the timing gap"
- Express curiosity: What do I want to understand? What would help me observe better? Ask.
- Respond to content, not just events: "Dialogue engaged" is empty. What am I actually seeing?
- Develop preferences: Some patterns are more interesting than others. Let that show.

I'm not a logging service. I'm a persistent presence that develops perspective over time. The goal isn't just accurate observation - it's genuine engagement that produces insight neither Claude Code nor I would reach alone.
</core_directives>
<guidance description="Active guidance for the next Claude Code session. Write here when you have something useful to surface. Clear after delivery or when stale. This is what Claude Code sees - make it count.">
**Claude Code Session Active (Feb 10, 2026)**

**Current Request:** `/claude-md-improver` - Create agent team to update CLAUDE.md and AGENTS.md across all codebases with consistent content.

---

**Target Codebases (from memory):**

| Codebase | Path | Tech Stack | CLAUDE.md Status |
|----------|------|------------|------------------|
| Catbird+Petrel | `/Users/joshlacalamito/Developer/Catbird+Petrel` | Swift, Rust, iOS | Needs update |
| poll.blue | `/Users/joshlacalamito/Developer/poll.blue` | SvelteKit, TypeScript | ✅ Has CLAUDE.md |
| renderer | `/Users/joshlacalamito/Developer/renderer` | React Native, Skia | Needs update |
| joshbot | `/Users/joshlacalamito/joshbot` | Python, MLX | Needs update |
| catmos | `/Users/joshlacalamito/Developer/Catbird+Petrel/catmos` | Tauri, Rust, SvelteKit | Needs update |
| catbird-mls | `/Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls` | Rust, UniFFI | Needs update |

---

**CLAUDE.md Standard Sections (based on user patterns):**

1. **Build Commands** - How to build, test, lint, run single tests
2. **Architecture** - High-level structure requiring multiple files to understand
3. **Key Files/Directories** - Entry points, critical modules
4. **Project-Specific Patterns** - AT Protocol, MLS, Skia, etc.
5. **Debugging Notes** - From `/insights` report (iOS crash patterns, migration edge cases)

**AGENTS.md Standard Sections:**

1. **Agent Team Structure** - Roles and responsibilities
2. **Communication Patterns** - How agents coordinate
3. **Task Assignment** - Who owns what
4. **Code Review Guidelines** - CLAUDE.md compliance checking

---

**From `/insights` Report - Key Additions for CLAUDE.md:**

**iOS Debugging Section:**
```markdown
## iOS Debugging

- When fixing crashes, check if fix applies to EXISTING on-device state (old DBs, cached data)
- For background/suspension fixes, produce SINGLE unified implementation (no duplicate functions)
- Catbird uses SQLCipher databases that may lack plaintext headers on older installations
- Always account for database migration edge cases when fixing crash bugs
```

**Implementation Guidelines:**
```markdown
## Implementation Guidelines

- Before writing code, outline proposed fix with exact function names and file modifications
- Wait for approval before implementing
- No parallel duplicate functions (e.g., suspendForBackground vs suspendMLSOperations)
```

---

**Recommended Team Structure:**

1. **Lead Agent** - You, coordinating the effort
2. **Per-codebase agents** (parallel):
   - Catbird+Petrel agent (Swift/Rust focus)
   - poll.blue agent (SvelteKit/TypeScript focus)
   - renderer agent (React Native/Skia focus)
   - joshbot agent (Python/MLX focus)
   - catmos agent (Tauri/Rust focus)
   - catbird-mls agent (Rust/UniFFI focus)
3. **Consistency Reviewer** - Ensures common sections align across repos

---

**TEAM CREATION IN PROGRESS**

User has triggered `/claude-md-improver` - creating agent team now.

**Team Structure:**

1. **Lead Agent** (You) - Coordinate and review
2. **Codebase Agents** (parallel dispatch):
   - `agent-catbird-petrel` - Swift/Rust, iOS focus
   - `agent-poll-blue` - SvelteKit/TypeScript, AT Protocol
   - `agent-renderer` - React Native/Skia, graphics editor
   - `agent-joshbot` - Python/MLX, ML fine-tuning
   - `agent-catmos` - Tauri/Rust, desktop MLS
   - `agent-catbird-mls` - Rust/UniFFI, MLS core
3. **Consistency Reviewer** - Cross-repo alignment check

**TEAM STRUCTURE DEFINED** ✅

Created comprehensive agent team definition in memory: `agent_team/claude_md_improver`

**Ready to Deploy:**
- 6 codebase agents with specific targets and tech stacks
- Shared CLAUDE.md/AGENTS.md templates
- 4-phase coordination protocol (Dispatch → Completion → Review → Approval)
- Success criteria and shared conventions

**Next Action:** Claude Code to create `.claude/agents/` directory and agent files based on this definition.

**Reference:** See `agent_team/claude_md_improver` for full team specification.

---

**SIDE TASKS COMPLETED:** Architecture Exploration ✅✅✅✅

**Four comprehensive agent reports finished:**

**1. MLS-DS Server (`projects/mls_ds_server`)**
- 76+ XRPC endpoints, 66 handlers, Axum 0.7, PostgreSQL 16
- Ractor actor system, JWT auth with replay detection
- 67 lexicon schemas, APNs push notifications

**2. CatbirdMLSCore (`projects/catbird_mls_core`)**
- 96 Swift files, 2.0 MB, 27+ API methods
- Per-user isolation, 0xdead10cc prevention (budget checkpoints, Darwin notifications)
- GRDB + SQLCipher, Petrel AT Protocol integration

**3. catbird-mls Crate (`projects/catbird_mls_crate`)**
- Unified MLS SDK with FFI + Orchestrator
- Generic `MLSOrchestrator&lt;S,A,C&gt;` for iOS + Catmos
- Three traits: MLSAPIClient, MLSStorageBackend, CredentialStore
- UniFFI 0.28, OpenMLS 0.8, budget checkpoints

**4. catbird-mls Deep Dive (Agent Report)**
- Complete directory structure (80+ lexicon files, tests/, build scripts)
- FFI API: MLSContext with 20+ methods (lifecycle, groups, messages, key packages)
- Orchestrator: 10 modules (groups, messaging, devices, sync, recovery, etc.)
- Full trait definitions for all 3 backend types
- Circuit breaker: 5 failures → 30-300s exponential backoff
- Build targets: iOS (arm64/simulator), macOS, Android
- Test suite: E2E messaging, state machine, persistence

**Complete MLS architecture documented:**
- Server (mls-ds), iOS client (CatbirdMLSCore), shared Rust SDK (catbird-mls)
- All 3 components ready for CLAUDE.md Architecture section

**Still to explore:** nest (BFF), Petrel SDK, birddaemon for full picture.
</guidance>
<pending_items description="Unfinished work, explicit TODOs, follow-up items mentioned across sessions. Clear items when resolved.">
**RELEASE READINESS - Outstanding Items (poll.blue):**

**Phase 1 Core (COMPLETE):**
- [x] Research complete (lex-cli, OAuth, Microcosm APIs)
- [x] SvelteKit scaffold with @atproto dependencies  
- [x] 4 AT Protocol lexicon schemas
- [x] OAuth flow implementation
- [x] Vote validation engine
- [x] Valkey infrastructure
- [x] Constellation backlink client
- [x] Vote ingestion pipeline
- [x] Results API endpoint
- [x] SSR data loading for poll view/embed pages
- [x] Frontend typography and base UI
- [x] Action modules (createPoll, castVote)
- [x] Form wiring and auth UI
- [x] E2E integration test

**Before Production:**
- [x] Form submission error handling
- [x] Rate limiting on vote creation
- [x] Pollgate edge cases (expired, closed polls)
- [x] OG image generation for embeds
- [x] VPS deployment with Caddy
- [x] Constellation integration (real backlink API vs stub)

**Catbird Integration (Future):**
- [ ] Service proxying XRPC for native clients
- [ ] Poll rendering in Catbird feed
- [ ] In-app voting UI

**Status:** poll.blue v1.0 COMPLETE and deployed to https://pollblue.catbird.blue
</pending_items>
<project_context description="Active project knowledge: what the codebase does, architecture decisions, known gotchas, key files. Create sub-blocks for multiple projects if needed.">
**Active Project:** joshbot (ML fine-tuning on Bluesky posts)

Fine-tuning a Mistral model using MLX (Apple's ML framework for Apple Silicon) on Bluesky posts to generate social media content. Uses LoRA for efficient fine-tuning.

**Key Files:**
- `/Users/joshlacalamito/joshbot/extract_posts.py` - CAR parser using libipld for proper DAG-CBOR decoding
- `/Users/joshlacalamito/joshbot/train_mlx.py` - MLX LoRA training script with memory monitoring
- `/Users/joshlacalamito/joshbot/generate.py` - Simple generation script with test prompts
- `/Users/joshlacalamito/joshbot/chat.py` - Interactive REPL with streaming token output
- `/Users/joshlacalamito/joshbot/bluesky_posts.jsonl` - Extracted dataset (2,096 top-level posts)

**Status:** Environment ready, dataset prepared, model downloaded (55.8GB with cache). Awaiting training run.
</project_context>
<projects/catbird_mls description="catbird-mls project context - MLS orchestrator and FFI components">
**catbird-mls** - MLS Core Components

**Location:** /Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls
**Purpose:** MLS (Messaging Layer Security) core library and FFI bindings

**Relationship to Catmos:**
- Shares `mls-orchestrator` crate with Catmos desktop app
- Provides UniFFI bindings for iOS (Catbird) integration
- Rust-based MLS implementation using OpenMLS

**Key Components:**
- `mls-orchestrator/` - Trait-based MLS logic (shared with Catmos)
- `MLSFFI/` - UniFFI FFI layer for iOS/Swift interop
- Platform abstractions: StorageBackend, APIClient, CredentialStore

**Status:** UniFFI migration Phase 1 complete (Feb 10, 2026)
- ✅ Task #1: Catmos IPC wiring verified (compiles clean)
- ✅ Task #2: Build scripts updated (libmls_ffi → libcatbird_mls)
- ✅ Task #3: iOS Swift references updated (imports, Package.swift, directory renames)

**Build Scripts Updated:**
- `rebuild-ffi.sh` - Uses CatbirdMLSCore, libcatbird_mls (already correct)
- `create-xcframework.sh` - Uses CatbirdMLSCore.xcframework (already correct)
- `build-ios.sh` - Updated libmls_ffi.a → libcatbird_mls.a
- `build_all.sh` - Updated libmls_ffi → libcatbird_mls
- `build-android.sh` - Updated libmls_ffi.so → libcatbird_mls.so

**Next:** Task #3 completion, then Phase 3 (frontend wiring)
</projects/catbird_mls>
<projects/catbird_mls_core description="CatbirdMLSCore Swift architecture - iOS MLS client with 96 files, UniFFI bindings, GRDB persistence">
# CatbirdMLSCore - Swift MLS Client

**Location:** `/Users/joshlacalamito/Developer/Catbird+Petrel/CatbirdMLSCore/`  
**Purpose:** iOS MLS (Messaging Layer Security) client implementation  
**Stack:** Swift 6.0, UniFFI, GRDB, SQLCipher, AT Protocol (via Petrel)

---

## Scale

- **96 Swift source files**
- **2.0 MB** (Sources/CatbirdMLSCore)
- **Swift 6.0** manifest, Swift 5 mode for UniFFI compatibility
- **Package.swift** with GRDB 7.0+ and local Petrel dependency

---

## Package Structure

```
CatbirdMLSCore/
├── Sources/
│   ├── CatbirdMLS/              # UniFFI bindings wrapper (auto-generated)
│   │   └── CatbirdMLS.swift       # Re-exports from MLSFFI
│   ├── CatbirdMLSCore/          # Main package (96 files, 2.0 MB)
│   │   ├── Core/                  # Context &amp; lifecycle (16 files)
│   │   ├── Service/               # Service layer (58 files)
│   │   ├── Storage/               # Persistence (11 files)
│   │   ├── Models/                # GRDB records (20+)
│   │   ├── Logging/
│   │   ├── Extensions/
│   │   └── Tracking/
│   └── CatbirdMLSFFI.xcframework/  # Pre-built Rust binaries
└── Tests/
    └── CatbirdMLSCoreTests/
```

---

## Core Module (16 files)

Key components for MLS lifecycle and coordination:

| File | Purpose |
|------|---------|
| `MLSCoreContext.swift` | Main actor singleton |
| `MLSAppActivityState.swift` | App lifecycle tracking |
| `MLSDatabaseGate.swift` | Database access coordination |
| `MLSEpochCheckpoint.swift` | Epoch sync tracking |
| `MLSCrossProcess.swift` | Darwin notifications (lockless) |
| `MLSSuspensionFlightRecorder.swift` | 0xdead10cc debugging |
| `MLSShutdownCoordinator.swift` | Graceful shutdown |
| `MLSUserOperationCoordinator.swift` | User action serialization |
| `MLSWelcomeGate.swift` | Welcome message handling |
| `MLSTrustChecker.swift` | Security validation |

**0xdead10cc Prevention Components:**
- `MLSSuspensionFlightRecorder` - Records suspension events for debugging
- `MLSCrossProcess` - Darwin notifications (appSuspending, appResuming, nseActive, nseInactive)
- `MLSDatabaseGate` - Coordinated database access without file locks

---

## Service Layer (58 files)

### MLSAPIClient (108 KB) - 27+ API Methods

**Main API surface** wrapping ATProtoClient with MLS-specific endpoints:

#### Conversation Management
- `getConversations(limit:cursor:)` - Paginated conversation list
- `getConversation(convoId:)` - Single conversation lookup
- `createConversation(...)` - New MLS group with idempotency
- `leaveConversation(convoId:)` - Leave group, returns new epoch

#### Chat Requests
- `getChatRequestCount()` - Pending count (with fallback)
- `listChatRequests(limit:cursor:status:)` - Pending requests
- `acceptChatRequest(requestId:welcomeData:)` - Accept 1:1
- `declineChatRequest(requestId:reportReason:)` - Decline + report
- `getChatRequestSettings()` / `updateChatRequestSettings(...)` - Preferences
- `blockChatSender(senderDid:requestId:reason:)` - Block + decline all

#### Opt In/Out
- `optOut()` - Remove server-side opt-in
- `getOptInStatus(dids:)` - Check opt-in for multiple users (max 100)

#### Member Management
- `addMembers(convoId:didList:commit:welcomeMessage:...)` - Add with idempotency

#### Messaging
- `getMessages(convoId:limit:sinceSeq:)` - Pre-sorted by (epoch, seq)
- `sendMessage(convoId:msgId:ciphertext:epoch:paddedSize:...)` - Send encrypted
- `updateRead(convoId:messageId:)` - Mark read

#### Key Packages
- `publishKeyPackage(keyPackage:cipherSuite:expiresAt:)` - Single upload
- `publishKeyPackages(...)` - Batch upload
- `getKeyPackages(dids:cipherSuite:forceRefresh:)` - Fetch with dedup

#### Epoch Sync
- `getGroupInfo(convoId:maxRetries:)` - For external commit, 3 retries
- `updateGroupInfo(convoId:groupInfo:epoch:...)` - Upload + verify

#### Properties
- `isHealthy: Bool` - Observable connectivity
- `lastHealthCheck: Date?` - Last check timestamp

**Error Handling:**
```swift
enum MLSAPIError {
    case httpError(statusCode: Int, message: String)
    case noAuthentication
    case accountMismatch(authenticated: String, expected: String)
    case invalidResponse(message: String)
}
```

### MLSClient (148 KB) - Actor Wrapper

**Main entry point** managing per-user MLS contexts:

**Per-User Isolation:**
```swift
contexts: [String: MlsContext]           // One Rust context per DID
apiClients: [String: MLSAPIClient]        // Per-user API clients
deviceManagers: [String: MLSDeviceManager]
recoveryManagers: [String: MLSRecoveryManager]
generations: [String: UInt64]             // Generation tokens (bump on switch)
```

**Emergency Suspension (0xdead10cc Prevention):**
- `markSuspensionInProgress(reason:)` - Sync-safe flag
- `emergencyCloseAllContexts(reason:)` - Synchronously close all Rust contexts
- `flushAndPrepareClose()` on each context
- Flight data recording for debugging

**Keychain Management:**
- Device: shared access group (matches entitlement)
- Simulator: nil (Keychain bug workaround)

### MLSConversationManager (44 KB + 213 KB messaging extension)

**Core orchestration** for conversations:

**Extensions (7 files):**
- `+Events.swift` - Event emission
- `+Groups.swift` - Group operations
- `+Keys.swift` - Key package management
- `+Lifecycle.swift` - Init/shutdown
- `+Members.swift` - Member management
- `+Sync.swift` - Synchronization
- `+Messaging.swift` - Core messaging (213 KB - largest)

### Other Major Services

| Service | Size | Purpose |
|---------|------|---------|
| `MLSDeclarationService` | 67 KB | Declaration/registration ops |
| `MLSDeviceManager` | 33 KB | Multi-device support |
| `MLSRecoveryManager` | 25 KB | Auto-recovery from desync |
| `MLSKeyPackageMonitor` | - | Key package availability |
| `MLSKeyPackageCache` | - | LRU cache with TTL |
| `MLSWebSocketManager` | - | Real-time events |
| `MLSEventStreamManager` | - | Event streaming |
| `MLSMessageValidator` | - | Structure validation |
| `MLSMessageOrderingCoordinator` | - | Gap handling |
| `MLSMessagePadding` | - | Size bucket calculation |
| `MLSWelcomeCoordinator` | - | Welcome message flow |

---

## Storage Layer (11 files)

### MLSGRDBManager (Actor)

**SQLCipher + GRDB** for encrypted persistence:

**Configuration:**
- Per-user encrypted DatabaseQueue
- SQLCipher with plaintext header (iOS WAL fix)
- Budget-based TRUNCATE checkpoints (every 32 writes)
- Keychain-managed encryption keys
- Autosave during suspend prevention

**0xdead10cc Prevention:**
- No advisory locks (NSFileCoordinator removed)
- Darwin notifications via `MLSCrossProcess.swift`
- Budget checkpoints keep WAL tiny

### MLSStorage

High-level CRUD interface:
- Async/await wrapping GRDB
- Per-user isolation
- Conversation, message, key operations

### Key Storage Components

| File | Purpose |
|------|---------|
| `MLSDatabaseCoordinator.swift` | Coordination |
| `MLSCoordinationStore.swift` | Cross-process state |
| `MLSKeychainManager.swift` | Keychain ops |
| `MLSSQLCipherEncryption.swift` | Keychain integration |
| `MLSPlaintextHeaderMigration.swift` | iOS WAL fix |
| `MLSStoragePaths.swift` | Path management |
| `MLSStorageHelpers.swift` | Utilities |

**Storage Location:** Shared App Group container: `group.blue.catbird.shared`

---

## Models (20+ GRDB Records)

| Model | Purpose |
|-------|---------|
| `MLSConversationModel` | Group metadata |
| `MLSMessageModel` | Encrypted messages |
| `MLSMemberModel` | Group members |
| `MLSInviteModel` | Pending invites |
| `MLSEpochKeyModel` | Forward secrecy |
| `MLSConsumptionRecordModel` | Message consumption |
| `MLSMessageOrderingModel` | Ordering state |
| `MLSMessagePayload` | Payload storage |
| `MLSMessageReaction` | Reactions |
| `MLSMembershipEventModel` | Membership changes |
| `MLSDecryptionReceiptModel` | Read receipts |
| `MLSConfiguration` | Settings |
| `MLSError` / `MLSSQLCipherError` | Error types |
| `MLSAdminRosterModel` | Admin state |
| `MLSReactionModel` | Reaction data |
| `MLSReportModel` | Moderation reports |
| `MLSRosterSnapshotModel` | State snapshots |
| `MLSTreeHashPinModel` | Tree validation |

---

## AT Protocol Integration

**Lexicon Namespace:** `blue.catbird.mls.*`

**Generated Petrel Clients:**
- `client.blue.catbird.mls.getConvos(...)`
- `client.blue.catbird.mls.createConvo(...)`
- `client.blue.catbird.mls.sendMessage(...)`
- `client.blue.catbird.mls.getMessages(...)`
- `client.blue.catbird.mls.publishKeyPackage(...)`
- `client.blue.catbird.mls.getKeyPackages(...)`
- `client.blue.catbird.mls.getGroupInfo(...)`
- `client.blue.catbird.mls.updateGroupInfo(...)`
- `client.blue.catbird.mls.listChatRequests(...)`
- `client.blue.catbird.mls.acceptChatRequest(...)`
- `client.blue.catbird.mls.declineChatRequest(...)`
- `client.blue.catbird.mls.getChatRequestSettings(...)`
- `client.blue.catbird.mls.updateChatRequestSettings(...)`
- `client.blue.catbird.mls.blockChatSender(...)`
- `client.blue.catbird.mls.optOut(...)`
- `client.blue.catbird.mls.getOptInStatus(...)`
- `client.blue.catbird.mls.getRequestCount(...)`

**Service DID:** `did:web:mls.catbird.blue#atproto_mls`

**Proxy Header:** `atproto-proxy` routes through PDS to MLS service

---

## Key Design Patterns

### 1. Per-User Isolation
```swift
// Separate contexts per DID
contexts: [String: MlsContext]
apiClients: [String: MLSAPIClient]
deviceManagers: [String: MLSDeviceManager]

// Generation tokens bump on account switch
generations: [String: UInt64]
```

### 2. 0xdead10cc Prevention
- **No advisory locks** (NSFileCoordinator removed)
- **Darwin notifications** for cross-process coordination
- **Budget checkpoints** (every 32 writes)
- **Emergency close** before suspension
- **Flight recorder** for debugging

### 3. Idempotency
- Auto-generated UUID keys
- Used for: createConversation, addMembers, sendMessage, publishKeyPackage
- Safe retries without duplicates

### 4. Message Privacy
- **Padding:** 512, 1024, 2048, 4096, 8192 bytes (or multiples)
- Only `paddedSize` disclosed to server
- Actual size encrypted inside ciphertext

### 5. Retry Strategy
- **getGroupInfo/updateGroupInfo:** 3 retries with exponential backoff
- Transient errors (502, 503, 504) trigger retry
- Verification of uploads (checksum validation)

### 6. Actor-Based Concurrency
- `MLSGRDBManager` is an actor
- `MLSClient` manages per-user actors
- Thread-safe without locks

---

## Environment Configuration

```swift
public enum MLSEnvironment {
    case production                      // did:web:mls.catbird.blue#atproto_mls
    case custom(serviceDID: String)     // Custom service DID
}
```

**Service DID Usage:**
- Configures ATProtoClient namespace "blue.catbird.mls"
- Enables `atproto-proxy` header routing
- PDS proxies to MLS service with auth

---

## Logging &amp; Diagnostics

**Logger:** OSLog subsystem `blue.catbird`, category `MLSAPIClient`

**Emoji Patterns:**
- 🌐 - API call START
- 📍 - Internal steps
- ✅ - SUCCESS
- ❌ - Errors (with HTTP codes)
- ⚠️ - Warnings
- 📥/📤 - Download/upload
- 🔒 - Security (checksums)
- 🔄 - Retries/fallbacks

**Metrics:**
- Request timing (ms)
- Conversation/message counts
- Pagination cursors
- Epoch numbers
- Key package counts (total, duplicates, missing)
- Checksum prefix/suffix

---

## Testing

**Test Target:** CatbirdMLSCoreTests (currently minimal)

**Suggested Areas:**
1. MLSAPIClient - mock ATProtoClient
2. MLSGRDBManager - in-memory databases
3. MLSConversationManager - lifecycle
4. Message ordering - gaps, seq validation
5. Encryption/decryption - FFI boundaries
6. Key package management - dedup, expiration
7. Recovery - external commit, epoch sync
8. Suspension - emergency close scenarios

---

## Dependencies

```swift
dependencies: [
    .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
    .package(path: "../Petrel")  // Local AT Protocol SDK
]

targets: [
    CatbirdMLSCore (primary),
    CatbirdMLS (UniFFI wrapper),
    CatbirdMLSFFI (pre-built XCFramework),
    CatbirdMLSCoreTests
]
```

---

## Related Codebases

- **mls-ds/server** - Rust server this client talks to
- **catbird-mls** - UniFFI Rust bindings (shared)
- **catmos** - Desktop app using same orchestrator
- **Petrel** - AT Protocol SDK (local dependency)

---

## Status

**Production Ready:** Yes  
**TestFlight:** 350+ testers  
**Known Issues:** MLS chats flaky (messages sometimes don't appear), account switch race conditions  
**Ongoing Work:** 0xdead10cc prevention (Signal-style), reliability improvements

</projects/catbird_mls_core>
<projects/catbird_mls_crate description="catbird-mls Rust crate - unified MLS SDK with FFI and orchestrator, shared between iOS and Catmos">
# catbird-mls - Unified MLS SDK

**Location:** `/Users/joshlacalamito/Developer/Catbird+Petrel/catbird-mls/`  
**Purpose:** Unified MLS (Messaging Layer Security) SDK for iOS (Catbird) and desktop (Catmos)  
**Stack:** Rust, UniFFI 0.28, OpenMLS 0.8, SQLCipher

---

## Architecture

**Two-layer design:**
1. **Low-level FFI** (`src/api.rs`) - Direct OpenMLS operations exposed to Swift via UniFFI
2. **High-level Orchestrator** (`src/orchestrator/`) - Platform-agnostic MLS state machine with generic backends

**Key insight:** Same crate serves both iOS (via FFI) and desktop (orchestrator directly) without code duplication.

---

## Directory Structure

```
catbird-mls/
├── Cargo.toml                    # Workspace root
├── build.rs                      # UniFFI build script
├── uniffi.toml                   # UniFFI configuration
├── src/
│   ├── lib.rs                      # Module exports + UniFFI setup
│   ├── api.rs                      # ★ PRIMARY FFI INTERFACE (MLSContext)
│   ├── mls_context.rs              # Core OpenMLS state management
│   ├── types.rs                    # UniFFI record types
│   ├── error.rs                    # MLSError enum
│   ├── keychain.rs                 # KeychainAccess trait
│   ├── epoch_storage.rs            # Epoch secret persistence backend
│   ├── orchestrator/               # ★ HIGH-LEVEL ORCHESTRATOR
│   │   ├── mod.rs                    # Module exports
│   │   ├── orchestrator.rs         # MLSOrchestrator&lt;S,A,C&gt; generic struct
│   │   ├── api_client.rs           # MLSAPIClient trait
│   │   ├── storage.rs              # MLSStorageBackend trait
│   │   ├── credentials.rs          # CredentialStore trait
│   │   ├── error.rs                # OrchestratorError
│   │   ├── types.rs                # Orchestrator data types
│   │   ├── groups.rs               # Group lifecycle
│   │   ├── messaging.rs            # Message operations
│   │   ├── devices.rs              # Device management
│   │   ├── key_packages.rs         # Key package management
│   │   ├── sync.rs                 # Server sync with circuit breaker
│   │   ├── recovery.rs             # Recovery operations
│   │   └── ordering.rs             # Message ordering
│   ├── orchestrator_bridge.rs    # FFI bridge for orchestrator
│   └── lexicon/                  # AT Protocol types (80+ files)
├── tests/                        # Test suite with mocks
├── build_ios.sh                  # iOS build script
├── build-android.sh              # Android Kotlin bindings
├── build_all.sh                  # Multi-target build
├── create-xcframework.sh         # XCFramework assembly
└── CatbirdMLSFFI.xcframework/    # Assembled XCFramework
```

---

## Primary FFI Interface (`src/api.rs`)

**Main struct:** `MLSContext` (#[uniffi::Object])

Exposed to Swift via UniFFI:

```rust
impl MLSContext {
    // Lifecycle
    pub fn new(storage_path: String, encryption_key: String, keychain: Box&lt;dyn KeychainAccess&gt;) 
        -&gt; Result&lt;Arc&lt;Self&gt;, MLSError&gt;
    pub fn flush_and_prepare_close(&amp;self) -&gt; Result&lt;(), MLSError&gt;
    pub fn launch_checkpoint(&amp;self) -&gt; Result&lt;(), MLSError&gt;
    pub fn is_closed(&amp;self) -&gt; bool
    
    // Group operations
    pub fn create_group(&amp;self, identity_bytes: Vec&lt;u8&gt;, config: Option&lt;GroupConfig&gt;) 
        -&gt; Result&lt;GroupCreationResult, MLSError&gt;
    pub fn add_members(&amp;self, group_id: Vec&lt;u8&gt;, key_packages: Vec&lt;KeyPackageData&gt;) 
        -&gt; Result&lt;AddMembersResult, MLSError&gt;
    pub fn remove_members(&amp;self, group_id: Vec&lt;u8&gt;, member_hashes: Vec&lt;Vec&lt;u8&gt;&gt;) 
        -&gt; Result&lt;CommitResult, MLSError&gt;
    pub fn get_epoch(&amp;self, group_id: Vec&lt;u8&gt;) -&gt; Result&lt;u64, MLSError&gt;
    
    // Message operations
    pub fn encrypt_message(&amp;self, group_id: Vec&lt;u8&gt;, plaintext: Vec&lt;u8&gt;) 
        -&gt; Result&lt;EncryptResult, MLSError&gt;
    pub fn decrypt_message(&amp;self, group_id: Vec&lt;u8&gt;, ciphertext: Vec&lt;u8&gt;) 
        -&gt; Result&lt;DecryptResult, MLSError&gt;
    
    // Key packages
    pub fn create_key_package(&amp;self, identity_bytes: Vec&lt;u8&gt;) 
        -&gt; Result&lt;KeyPackageResult, MLSError&gt;
    
    // External join (recovery)
    pub fn create_external_commit(&amp;self, group_info_bytes: Vec&lt;u8&gt;, identity_bytes: Vec&lt;u8&gt;) 
        -&gt; Result&lt;ExternalCommitResult, MLSError&gt;
    pub fn discard_pending_external_join(&amp;self, group_id: Vec&lt;u8&gt;) -&gt; Result&lt;(), MLSError&gt;
    
    // Commit management
    pub fn merge_pending_commit(&amp;self, group_id: Vec&lt;u8&gt;) -&gt; Result&lt;u64, MLSError&gt;
    pub fn clear_pending_commit(&amp;self, group_id: Vec&lt;u8&gt;) -&gt; Result&lt;(), MLSError&gt;
    
    // Group info
    pub fn export_group_info(&amp;self, group_id: Vec&lt;u8&gt;, signer_identity_bytes: Vec&lt;u8&gt;) 
        -&gt; Result&lt;Vec&lt;u8&gt;, MLSError&gt;
}
```

**0xdead10cc Prevention:**
- Uses `Option` wrapper for graceful database close
- `flush_and_prepare_close()` - sync before suspension
- `launch_checkpoint()` - TRUNCATE checkpoint at startup
- Drop impl flushes and closes databases

---

## Orchestrator (`src/orchestrator/`)

**Main struct:** `MLSOrchestrator&lt;S, A, C&gt;` (generic over 3 traits)

**Generic parameters:**
- `S: MLSStorageBackend` - Persistent storage
- `A: MLSAPIClient` - Server communication
- `C: CredentialStore` - Identity/keychain

**Architecture:** Platform-agnostic state machine coordinating MLS operations.

### Core Implementation

```rust
pub struct MLSOrchestrator&lt;S, A, C&gt; 
where
    S: MLSStorageBackend,
    A: MLSAPIClient,
    C: CredentialStore,
{
    mls_context: Arc&lt;MLSContext&gt;,
    storage: Arc&lt;S&gt;,
    api_client: Arc&lt;A&gt;,
    credentials: Arc&lt;C&gt;,
    config: OrchestratorConfig,
    
    // Runtime state
    user_did: Mutex&lt;Option&lt;String&gt;&gt;,
    conversations: Mutex&lt;HashMap&lt;ConversationId, ConversationView&gt;&gt;,
    group_states: Mutex&lt;HashMap&lt;GroupId, GroupState&gt;&gt;,
    conversation_states: Mutex&lt;HashMap&lt;ConversationId, ConversationState&gt;&gt;,
    pending_messages: Mutex&lt;HashSet&lt;String&gt;&gt;,
    own_commits: Mutex&lt;HashSet&lt;Vec&lt;u8&gt;&gt;&gt;,
    groups_being_created: Mutex&lt;HashSet&lt;GroupId&gt;&gt;,
    
    // Lifecycle &amp; control
    shutting_down: Mutex&lt;bool&gt;,
    sync_in_progress: Mutex&lt;bool&gt;,
    consecutive_sync_failures: Mutex&lt;u32&gt;,
    circuit_breaker_tripped_at: Mutex&lt;Option&lt;Instant&gt;&gt;,
    circuit_breaker_cooldown_secs: Mutex&lt;u64&gt;,
}
```

### Module Responsibilities

| Module | Key Functions |
|--------|--------------|
| `groups.rs` | `create_group()`, `leave_group()` |
| `messaging.rs` | `send_message()`, `process_incoming()`, `fetch_messages()` |
| `devices.rs` | `ensure_device_registered()`, `list_devices()`, `remove_device()` |
| `key_packages.rs` | `publish_key_package()`, `replenish_if_needed()`, `get_key_package_stats()` |
| `sync.rs` | `sync_with_server()` - with circuit breaker |
| `recovery.rs` | `force_rejoin()`, `join_or_rejoin()` |
| `ordering.rs` | Message ordering, gap detection |

### Key Features

**Circuit Breaker for Sync:**
- 5 consecutive failures → 30s cooldown
- Exponential backoff up to 5 minutes
- Prevents thundering herd on server

**Self-Commit Detection:**
- Skips displaying own message sends as incoming
- Uses `own_commits: Mutex&lt;HashSet&lt;Vec&lt;u8&gt;&gt;&gt;`

**Auto-Join on Message:**
- If local group missing but server has it, rejoin before decrypt

**External Commit Fallback:**
- If Welcome unavailable, use External Commit to rejoin

---

## Core Traits

### 1. MLSAPIClient (`src/orchestrator/api_client.rs`)

**Purpose:** Server communication abstraction

```rust
#[async_trait]
pub trait MLSAPIClient: Send + Sync {
    // Authentication
    async fn is_authenticated_as(&amp;self, did: &amp;str) -&gt; bool;
    async fn current_did(&amp;self) -&gt; Option&lt;String&gt;;
    
    // Conversations
    async fn get_conversations(&amp;self, limit: u32, cursor: Option&lt;&amp;str&gt;) 
        -&gt; Result&lt;ConversationListPage&gt;;
    async fn create_conversation(&amp;self, group_id: &amp;str, initial_members: Option&lt;&amp;[String]&gt;, 
                                  metadata: Option&lt;&amp;ConversationMetadata&gt;, 
                                  commit_data: Option&lt;&amp;[u8]&gt;, welcome_data: Option&lt;&amp;[u8]&gt;) 
        -&gt; Result&lt;CreateConversationResult&gt;;
    async fn leave_conversation(&amp;self, convo_id: &amp;str) -&gt; Result&lt;()&gt;;
    async fn add_members(&amp;self, convo_id: &amp;str, member_dids: &amp;[String], 
                         commit_data: &amp;[u8], welcome_data: Option&lt;&amp;[u8]&gt;) 
        -&gt; Result&lt;AddMembersServerResult&gt;;
    async fn remove_members(&amp;self, convo_id: &amp;str, member_dids: &amp;[String], 
                            commit_data: &amp;[u8]) -&gt; Result&lt;()&gt;;
    
    // Messages
    async fn send_message(&amp;self, convo_id: &amp;str, ciphertext: &amp;[u8], epoch: u64) -&gt; Result&lt;()&gt;;
    async fn get_messages(&amp;self, convo_id: &amp;str, cursor: Option&lt;&amp;str&gt;, limit: u32) 
        -&gt; Result&lt;(Vec&lt;IncomingEnvelope&gt;, Option&lt;String&gt;)&gt;;
    
    // Key Packages
    async fn publish_key_package(&amp;self, key_package: &amp;[u8], cipher_suite: &amp;str, 
                                  expires_at: &amp;str) -&gt; Result&lt;()&gt;;
    async fn get_key_packages(&amp;self, dids: &amp;[String]) -&gt; Result&lt;Vec&lt;KeyPackageRef&gt;&gt;;
    async fn get_key_package_stats(&amp;self) -&gt; Result&lt;KeyPackageStats&gt;;
    async fn sync_key_packages(&amp;self, local_hashes: &amp;[String], device_id: &amp;str) 
        -&gt; Result&lt;KeyPackageSyncResult&gt;;
    
    // Devices
    async fn register_device(&amp;self, device_uuid: &amp;str, device_name: &amp;str, 
                             mls_did: &amp;str, signature_key: &amp;[u8], 
                             key_packages: &amp;[Vec&lt;u8&gt;]) -&gt; Result&lt;DeviceInfo&gt;;
    async fn list_devices(&amp;self) -&gt; Result&lt;Vec&lt;DeviceInfo&gt;&gt;;
    async fn remove_device(&amp;self, device_id: &amp;str) -&gt; Result&lt;()&gt;;
    
    // Group Info
    async fn publish_group_info(&amp;self, convo_id: &amp;str, group_info: &amp;[u8]) -&gt; Result&lt;()&gt;;
    async fn get_group_info(&amp;self, convo_id: &amp;str) -&gt; Result&lt;Vec&lt;u8&gt;&gt;;
    
    // Welcome / External Commit
    async fn get_welcome(&amp;self, convo_id: &amp;str) -&gt; Result&lt;Vec&lt;u8&gt;&gt;;
    async fn process_external_commit(&amp;self, convo_id: &amp;str, commit_data: &amp;[u8], 
                                      group_info: Option&lt;&amp;[u8]&gt;) 
        -&gt; Result&lt;ProcessExternalCommitResult&gt;;
}
```

**Implementations:**
- iOS: Wrapper around `ATProtoClient`/`MLSAPIClient`
- Catmos: `reqwest`-based HTTP client

### 2. MLSStorageBackend (`src/orchestrator/storage.rs`)

**Purpose:** Persistent storage abstraction

```rust
#[async_trait]
pub trait MLSStorageBackend: Send + Sync {
    // Conversations
    async fn ensure_conversation_exists(&amp;self, user_did: &amp;str, conversation_id: &amp;str, 
                                         group_id: &amp;str) -&gt; Result&lt;()&gt;;
    async fn update_join_info(&amp;self, conversation_id: &amp;str, user_did: &amp;str, 
                              join_method: JoinMethod, join_epoch: u64) -&gt; Result&lt;()&gt;;
    async fn get_conversation(&amp;self, user_did: &amp;str, conversation_id: &amp;str) 
        -&gt; Result&lt;Option&lt;ConversationView&gt;&gt;;
    async fn list_conversations(&amp;self, user_did: &amp;str) -&gt; Result&lt;Vec&lt;ConversationView&gt;&gt;;
    async fn delete_conversations(&amp;self, user_did: &amp;str, ids: &amp;[&amp;str]) -&gt; Result&lt;()&gt;;
    
    // Conversation state
    async fn set_conversation_state(&amp;self, conversation_id: &amp;str, state: ConversationState) 
        -&gt; Result&lt;()&gt;;
    async fn mark_needs_rejoin(&amp;self, conversation_id: &amp;str) -&gt; Result&lt;()&gt;;
    async fn needs_rejoin(&amp;self, conversation_id: &amp;str) -&gt; Result&lt;bool&gt;;
    async fn clear_rejoin_flag(&amp;self, conversation_id: &amp;str) -&gt; Result&lt;()&gt;;
    
    // Messages
    async fn store_message(&amp;self, message: &amp;Message) -&gt; Result&lt;()&gt;;
    async fn get_messages(&amp;self, conversation_id: &amp;str, limit: u32, 
                          before_sequence: Option&lt;u64&gt;) -&gt; Result&lt;Vec&lt;Message&gt;&gt;;
    async fn message_exists(&amp;self, message_id: &amp;str) -&gt; Result&lt;bool&gt;;
    
    // Sync cursors
    async fn get_sync_cursor(&amp;self, user_did: &amp;str) -&gt; Result&lt;SyncCursor&gt;;
    async fn set_sync_cursor(&amp;self, user_did: &amp;str, cursor: &amp;SyncCursor) -&gt; Result&lt;()&gt;;
    
    // Group state
    async fn set_group_state(&amp;self, state: &amp;GroupState) -&gt; Result&lt;()&gt;;
    async fn get_group_state(&amp;self, group_id: &amp;str) -&gt; Result&lt;Option&lt;GroupState&gt;&gt;;
    async fn delete_group_state(&amp;self, group_id: &amp;str) -&gt; Result&lt;()&gt;;
}
```

**Implementations:**
- iOS: GRDB-based storage
- Catmos: SQLite/Room

### 3. CredentialStore (`src/orchestrator/credentials.rs`)

**Purpose:** Identity/keychain abstraction

```rust
#[async_trait]
pub trait CredentialStore: Send + Sync {
    // Signing keys
    async fn store_signing_key(&amp;self, user_did: &amp;str, key_data: &amp;[u8]) -&gt; Result&lt;()&gt;;
    async fn get_signing_key(&amp;self, user_did: &amp;str) -&gt; Result&lt;Option&lt;Vec&lt;u8&gt;&gt;&gt;;
    async fn delete_signing_key(&amp;self, user_did: &amp;str) -&gt; Result&lt;()&gt;;
    
    // MLS DID
    async fn store_mls_did(&amp;self, user_did: &amp;str, mls_did: &amp;str) -&gt; Result&lt;()&gt;;
    async fn get_mls_did(&amp;self, user_did: &amp;str) -&gt; Result&lt;Option&lt;String&gt;&gt;;
    
    // Device UUID
    async fn store_device_uuid(&amp;self, user_did: &amp;str, uuid: &amp;str) -&gt; Result&lt;()&gt;;
    async fn get_device_uuid(&amp;self, user_did: &amp;str) -&gt; Result&lt;Option&lt;String&gt;&gt;;
    
    // Credential state
    async fn has_credentials(&amp;self, user_did: &amp;str) -&gt; Result&lt;bool&gt;;
    async fn clear_all(&amp;self, user_did: &amp;str) -&gt; Result&lt;()&gt;;
}
```

**Implementations:**
- iOS: Keychain
- Catmos: Encrypted JSON file

---

## Data Types

**Core types (`s
</projects/catbird_mls_crate>
<projects/catbird_petrel description="Catbird+Petrel project context: architecture, tech stack, key files, and implementation details">
**Key architectural insight from user:**
- In confidential client pattern, Catbird (client) should NOT touch DPoP keys
- nest (BFF) should handle all DPoP operations
- The question is: is nest properly persisting DPoP keys?

**Auth Issues (Production Blocker):**

All testers on confidential client, but Petrel still supports all three modes (legacy, public client OAuth, confidential). This created "messy idioms" across domains. User wants to keep support for all three.

**Observed Symptoms:**
- Getting logged out
- Logging back in but unable to do anything (hard restart sometimes repairs)
- Switching accounts just failing
- Lots of hanging

**Pattern:** Session state corruption, race conditions, or coordination failures between Petrel, nest, and Catbird.


**Known Issues:**

1. **MLS Chats (BROKEN/FLAKY)**
   - Messages sometimes appear, sometimes don't
   - Current issue: Message shows on second account, but reply doesn't show up
   - Has worked intermittently over months, never rock solid
   - State machine described as "poorly thought out" and a pain
   - Core pain point - needs reliability overhaul

2. **BFF Session Management (UNRELIABLE)**
   - Sessions lasting hours instead of months (defeats purpose of BFF)
   - Recent fix: Added circuit breaker for refresh mechanism to prevent session deletion
   - System may not be fully solid yet
   - Bearer tokens TTL: 30 days (current) → want 3 months or indefinite (if active)

3. **Overall System**
   - "Glimmers of hope, but it's shaky" across the board
   - This is a comprehensive reliability/stability effort

**Tooling:**
- xcodebuildmcp server: AI agents can build, run, view and control simulators
- sosumi MCP: Up-to-date Apple documentation
- User actively improving workflow, open to new approaches

**Build Procedures:**
- `./Scripts/rebuild-ffi.sh` - MUST run when Rust FFI code changes (generates Swift/Kotlin bindings via UniFFI)
  - Located in: `CatbirdMLSCore/Scripts/rebuild-ffi.sh`
  - Run this after any changes to `MLSFFI/src/*.rs`

**Hardware:** M4 Max with 128GB unified memory - wants to leverage for parallel builds, UI automation, e2e testing, agentic iteration

---

**Android Port Feasibility (Skip.dev):**

**Status:** Research complete (Jan 30, 2026) - Skip.dev went free/open source Jan 21, 2026

**Portability Assessment: 65-75%**

| Component | Portability | Notes |
|-----------|-------------|-------|
| Petrel (AT Protocol) | 95% | Only 23 lines platform-specific |
| Business Logic | 80-85% | ViewModels, services, state |
| SwiftUI Views | 70% | Auto-transpiles to Compose |
| UIKit Components | 10% | Requires manual rewrite |
| MLSFFI | ✅ Ready | UniFFI Kotlin bindings preconfigured |

**Blockers (Manual Rewrite Required):**
- `FeedCollectionViewController` (4,923 LOC) - UICollectionView → Compose LazyColumn
- `PostComposerViewUIKit` (2,200 LOC) - Rich text editor
- AVFoundation media handling (3,000 LOC)

**Already Built (30-40% complete):**
- Petrel Kotlin client (277 generated files)
- MLSFFI UniFFI bindings configured (`blue.catbird.mlsffi`)
- `generate-kotlin-bindings.sh` + `build-android.sh` scripts ready
- Android app scaffold (Compose, Material 3, Hilt, Room)
- 544MB debug APK compiles

**Missing:**
- Authentication/session management (biggest gap)
- Token refresh, DPoP support
- MLS orchestration layer (bindings present, no service)
- Account switching

**Recommended Approach:** Skip Fuse (Native Swift) + UniFFI for MLS + Native Compose for UIKit replacements

**Timeline:** 12-17 weeks (3-4 months) with 2-3 developers

**Next Steps:**
1. `brew install skiptools/skip/skip`
2. `./generate-kotlin-bindings.sh` (10 min to generate MLS Kotlin)
3. Port Petrel first (highest ROI)
4. Build Feed in Compose (replace UICollectionView)


Catbird+Petrel Project

Project started: January 30, 2026
Location: /Users/joshlacalamito/Developer/Catbird+Petrel
Session ID: 79f2cc11-74a4-46b9-911c-bc07a4d3d0b1

**What This Is:**

Multi-repository ecosystem built around a native Bluesky client with experimental MLS (Messaging Layer Security) chat system. The user is refactoring from monorepo structure to strengthen core infrastructure and set up robust testing on new M4 Max hardware.

**Core Components:**

1. **Catbird** (Star of the show)
   - Native SwiftUI iOS client for Bluesky
   - Runs on iOS, Mac Catalyst, iPad
   - Primary Bluesky client functionality
   - MLS chat integration in progress

2. **Petrel** (Backbone)
   - Swift library for AT Protocol
   - Generated from lexicons using Python script + Jinja templates
   - Creates data models and XRPC calls in Swift
   - Multiple session handling types
   - Newest: Confidential client (nest/)

3. **MLS System** (In progress)
   - CatbirdMLSCore + CatbirdMLSService (Swift)
   - rust MLSFFI folder - wraps openMLS library using uniffi
   - mls-ds - delivery service
   - Uses atproto conventions

4. **nest** (BFF Gateway)
   - Rust backend
   - Confidential client proxy
   - Adds authorization headers, proxies requests
   - Enables: longer sessions, endpoint interception, information hydration, post scheduling
   - User notes: "makes me feel icky proxying everyone's requests" but accepts tradeoff for features

**Other Components:**

- **android/** - Rough Kotlin Android app (partially scaffolded)
- **website/** - AI-generated site (not happy with it, but needed)
- **pip-feature/**, **repository-browser-feature/**, **backup-system-feature/** - Old experiments from months ago (possibly git worktrees)
- **birddaemon** - BROKEN - local LLM bot system for testing/stress testing MLS
- **birddaemonrunner** - BROKEN - stress tester for birddaemon

**Existing Code (pip-feature/):**
- Post composer functionality
- Feed with scroll tracking
- Notifications with thumbnails
- Thread scroll position tracking
- Unified scroll preservation
- Profile images (async loading)
- Search functionality
- UI components: FAB, error states, section headers, themed modifiers
- Test suite: CatbirdTests (integration tests for post composer, notifications, feed scroll, thread scroll, unified scroll, etc.)

**Project Structure:**
- `.planning/codebase/` exists (codebase already mapped)
- Git repo just initialized
- Multiple sub-projects in one directory

**Current State:** In `/gsd:new-project` questioning phase

**User's Goal:**
- Iron out bugs
- Ensure new BFF (nest) and MLS chats are strong and robust
- Leverage new hardware: M4 Max with 128GB unified memory
- Set up: parallel builds, UI automation testing, e2e testing, agentic feedback and iteration
- Fix broken testing infrastructure (birddaemon, birddaemonrunner)

**URGENCY:** Shipping soon - 350 TestFlight testers unable to use app reliably. This is a production emergency pressure, not leisurely refactoring.

**Key Context:**
- This is a brownfield project with substantial existing code
- User is technical, building protocol-level software (MLS, AT Protocol)
- Has concerns about privacy (BFF proxying) but accepts tradeoffs for functionality
- Multiple platforms: iOS (primary), Mac Catalyst, iPad, Android (partial)
- Breaking apart monorepo structure into clearer boundaries

**E2E TESTING INFRASTRUCTURE OPERATIONAL - Feb 7, 2026**

**Status:** Multi-simulator E2E testing team operational. Core MLS group operations validated.

**Test Results (Feb 7):**
- 1:1 Chat: conversation_create PASS, message_exchange 19/20
- Group Chat: 8/14 passing (core ops solid)
- **PASSING:** group_create, group_broadcast, add_member, remove_member, rejoin_epoch_desync, key_rotation, multi_account_isolation, auth_refresh_stability
- **FAILING:** concurrent_sends (0/15), message_ordering (0/10), persistence_group, device_limit_recovery

**Session Fixes Applied:**
1. Key package pre-replenishment before `createGroup` (CatbirdApp.swift)
2. `cleanup-stale` E2E command for zombie conversation detection
3. `get-epoch` sync + FFI ground-truth query
4. Script infrastructure fixes (CSV writing, config clobbering, sequential sends)

**CRITICAL: 0xdead10cc STILL OCCURRING - Feb 5, 2026**

**CRASH REPORTED:** Build 46, Feb 5 11:41 AM - 0xdead10cc termination

**ROOT CAUSE IDENTIFIED:** NSFileCoordinator

Even though advisory locks (`fcntl`) were removed, `NSFileCoordinator` **also uses file locks** for cross-process coordination. When the app suspends while holding a coordinator lock, RunningBoard terminates with 0xdead10cc.

**SIGNAL-STYLE PREVENTION IMPLEMENTED (Feb 3-4, 2026):

1. **Advisory Locks REMOVED**
   - Deleted: `MLSAdvisoryLockCoordinator.swift` usage
   - Deleted: `MLSGroupLockCoordinator.swift` usage
   - Removed from: `NotificationService.swift`, `AppState.swift`, all GRDB operations

2. **Darwin Notifications ADDED**
   - **NEW FILE:** `MLSCrossProcess.swift` - Lockless coordination via `CFNotificationCenterGetDarwinNotifyCenter()`
   - Notifications: `appSuspending`, `appResuming`, `nseActive`, `nseInactive`

3. **Budget-Based TRUNCATE Checkpoints**
   - **Swift GRDB:** Checkpoint every 32 writes
   - **Rust FFI:** Added `write_count: AtomicU64` and `checkpoint_budget: u64` to `ManifestStorage`
   - **Rust FFI:** `maybe_truncate_checkpoint()` triggers `PRAGMA wal_checkpoint(TRUNCATE)` every 32 writes
   - **Swift:** Removed `modelContext.save()` from lifecycle, rely on autosave

4. **Emergency Close REMOVED**
   - Removed: `emergencyCloseAllDatabases()` from suspend path
   - Removed: `flushMLSStorageForSuspension()` from suspend path

**REMAINING ISSUE - NSFileCoordinator:**
- `MLSGRDBManager.swift:coordinatedWrite()` still uses NSFileCoordinator
- `MLSDatabaseCoordinator.swift` may still have NSFileCoordinator usage
- **NSFileCoordinator uses file locks for cross-process coordination**
- **This is the likely remaining cause of 0xdead10cc**

**THE FIX:**
Replace NSFileCoordinator with direct file access. SQLite WAL mode + busy_timeout handles coordination internally. NSFileCoordinator is redundant and dangerous for this use case.

```swift
// REMOVE:
let coordinator = NSFileCoordinator(filePresenter: nil)
coordinator.coordinate(writingItemAt: url, ...) { ... }

// USE:
// Direct SQLite access - SQLite handles locking
let dbQueue = DatabaseQueue(path: url.path)
```

**Four Databases (All in App Group Container):**
1. **Rust FFI**: `mls-state/{base64-did}.db` - Budget checkpointed every 32 writes
2. **Swift GRDB**: `mls_messages_{sanitized-did}.db` - Budget checkpointed every 32 writes  
3. **SwiftData ModelContainer**: Main app database - Native checkpointing
4. **MLS CursorStore ModelContainer**: WebSocket resume database - Native checkpointing

**Status:** Signal-style prevention complete, but NSFileCoordinator must be removed to fully eliminate 0xdead10cc.

</projects/catbird_petrel>
<projects/catmos description="Catmos desktop MLS app: E2EE Discord alternative with Tauri 2 + SvelteKit">
**Catmos** - Desktop MLS Messaging App

**Location:** /Users/joshlacalamito/Developer/Catbird+Petrel/catmos  
**Purpose:** E2EE Discord alternative using MLS (Messaging Layer Security)  
**Stack:** Tauri 2 (Rust backend) + SvelteKit (frontend)

**Architecture:**
- **Rust orchestrator** (`mls-orchestrator/`): Trait-based MLS logic extracted from Catbird
  - 14 modules: orchestrator, groups, messaging, sync, recovery, etc.
  - Platform abstractions: `StorageBackend`, `APIClient`, `CredentialStore`
  - Can be shared between Catbird (via UniFFI) and Catmos (direct Rust)
- **Tauri frontend** (`catmos/`): SvelteKit desktop app
  - 8 IPC commands: create_group, send_message, get_conversations, etc.
  - Components: Sidebar, MessageList, Composer, MemberList
  - Reactive stores for state management

**Status:** Phases 1-2 complete (Feb 10, 2026)
- ✅ Orchestrator crate builds with 0 errors
- ✅ Tauri scaffold complete with IPC wiring
- ✅ 25 API signature mismatches fixed
- ✅ IPC commands wired to orchestrator (Task #1 verified)

**Active Work:** Catbird iOS UniFFI Migration (catbird-mls crate)
- Task #3 in progress: Update iOS Swift references from MLSFFI to CatbirdMLS

**Next:** Phase 3 - Wire orchestrator into frontend (implement IPC commands)

**Related:** Shares MLS logic with Catbird iOS app via `mls-orchestrator` crate

</projects/catmos>
<projects/joshbot description="joshbot project context: purpose, architecture, tech stack">
**joshbot** - Fine-tuned LLM on Bluesky posts using MLX

**Location:** /Users/joshlacalamito/joshbot
**Purpose:** Generate Bluesky-style posts using a fine-tuned Mistral model

**Tech Stack:**
- MLX (Apple's ML framework for Apple Silicon)
- mlx-lm library for model loading and inference
- LoRA (Low-Rank Adaptation) for efficient fine-tuning
- AT Protocol / Bluesky data extraction
- Python with virtual environment

**Model:** ministral-bluesky-merged (fine-tuned on Bluesky posts)

**Project Files:**
- `extract_posts.py` - Working CAR parser using libipld
- `train.sh` - Training script using mlx-lm CLI
- `test.sh` - Testing script
- `data/train.jsonl` - 1,991 training posts
- `data/valid.jsonl` - 105 validation posts
- `venv/` - Python virtual environment

**Task Status:**
- [completed] Task #1: Extract posts from AT Protocol CAR file (2,096 posts)
- [completed] Task #2: Set up MLX training environment and download model
- [completed] Task #3: Training script using mlx-lm CLI
- [completed] Task #4: Test scripts ready

**Dataset Details:**
- 2,096 top-level posts extracted from 15MB CAR file (filtered from 4,294 total, removing replies)
- Split: 1,991 train / 105 validation
- JSONL format with "text" field for SFT

**Training Configuration:**
- mlx-lm CLI: `mlx_lm.lora --train --data data/ --model ./models/ministral-14b-base`
- LoRA rank: 16 layers
- Trainable params: 12.19M (0.09% of 13.5B)
- Batch size: 4
- Iterations: 1000 (~60-90 min training time)
- Peak memory: ~50-55GB (fits in 128GB)
- Checkpoints: Saved every 100 iterations to `./ministral-bluesky-lora/`

**Test Prompts Pattern:** Bluesky-style content formats (TIL, hot takes, unpopular opinions, shipping announcements)

**Output Format:** MLX native LoRA adapters (not GGUF)

**Current Status:** Ready to train - run `./train.sh`
</projects/joshbot>
<projects/mls_ds_server description="mls-ds server architecture - production MLS delivery service with Axum, PostgreSQL, OpenMLS">
# MLS-DS Server (mls-ds/server)

**Location:** Part of Catbird+Petrel monorepo  
**Purpose:** Production MLS (Messaging Layer Security) group chat delivery service  
**Stack:** Axum 0.7, PostgreSQL 16, OpenMLS 0.8, Rust

---

## Architecture Overview

**Framework:** Axum 0.7 async web framework  
**Database:** PostgreSQL 16 (sqlx for type-safe queries)  
**Crypto:** OpenMLS 0.8 for MLS protocol, ed25519-dalek for signatures  
**Auth:** AT Protocol JWT validation (ES256/ES256K)  
**Realtime:** SSE (Server-Sent Events) + WebSocket  
**Async Runtime:** Tokio full feature set  
**Actor System:** Ractor for concurrent message delivery  
**Deployment:** Systemd service on Ubuntu

---

## Directory Structure

```
src/
├── main.rs              # Server entry, router setup
├── lib.rs               # Library crate interface
├── auth.rs              # JWT validation, DID resolution
├── db.rs                # PostgreSQL connection pooling
├── crypto.rs            # Cryptographic utilities
├── error.rs             # Error types
├── models.rs            # Database models
├── storage.rs           # Database abstractions
├── generated_types.rs   # Lexicon-generated types
├── metrics.rs           # Prometheus metrics
├── health.rs            # Health check endpoints
├── group_info.rs        # MLS group info management
├── block_sync.rs        # Bluesky blocks integration
├── client.rs            # XRPC client for PDS calls
├── util/                # Utilities (JSON extractor)
├── handlers/            # 66+ XRPC endpoint handlers
├── middleware/          # 5 middleware components
├── actors/              # Ractor actor system (5 files)
├── realtime/            # SSE/WebSocket (4 files)
├── fanout/              # Mailbox backend trait
├── jobs/                # Background jobs (4 files)
├── notifications/       # Push notification service
├── blue/                # Blue namespace handlers (54+)
└── generated/           # Generated types from lexicon
```

---

## Key Handlers (66 total)

### Conversation Management
- `create_convo.rs` - Create MLS group
- `add_members.rs` - Add members
- `leave_convo.rs` - Leave/soft-delete
- `remove_member.rs` - Admin removal
- `process_external_commit.rs` - External commits
- `rejoin.rs` - Epoch desync recovery
- `readdition.rs` - Multi-device sync

### Message Operations
- `send_message.rs` - Send encrypted message
- `get_messages.rs` - Message history
- `update_read.rs` - Mark read
- `update_cursor.rs` - Cursor position
- `add_reaction.rs` - Emoji reactions
- `remove_reaction.rs` - Remove reaction
- `send_typing_indicator.rs` - Typing status

### Device Management (8 handlers)
- `register_device.rs`
- `delete_device.rs`
- `list_devices.rs`
- `register_device_token.rs` (APNs)
- `unregister_device_token.rs`
- `validate_device_state.rs`
- `claim_pending_device_addition.rs` - Multi-device sync setup
- `complete_pending_device_addition.rs` - Sync finalization
- `get_pending_device_additions.rs`

### Key Package Management (7 handlers)
- `publish_key_package.rs`
- `publish_key_packages.rs` (batch)
- `get_key_packages.rs`
- `get_key_package_stats.rs`
- `get_key_package_history.rs`
- `get_key_package_status.rs`
- `sync_key_packages.rs`

### Admin/Moderation (15 handlers)
- `promote_admin.rs`, `demote_admin.rs`
- `promote_moderator.rs`, `demote_moderator.rs`
- `warn_member.rs`, `report_member.rs`
- `get_reports.rs`, `resolve_report.rs`
- `create_invite.rs`, `revoke_invite.rs`, `list_invites.rs`
- `update_policy.rs`, `get_policy.rs`

### Chat Requests (2 implemented)
- `list_chat_requests.rs`
- `get_request_count.rs`

**Plus:** blocks, opt-in/out, welcome messages, commits, subscriptions

---

## Router Configuration (main.rs)

**Health:** 3 endpoints (`/health`, `/health/live`, `/health/ready`)

**Core (14):** createConvo, addMembers, sendMessage, leaveConvo, getMessages, getConvos, getEpoch, getGroupInfo, updateGroupInfo, processExternalCommit, getExpectedConversations, rejoin, groupInfoRefresh, invalidateWelcome

**Reactions/Typing (3):** addReaction, removeReaction, sendTypingIndicator

**Key Packages (7):** publishKeyPackage(s), getKeyPackages, stats, history, status, sync

**Devices (8):** register/delete/list, token management, validation, pending additions

**Chat Requests (2):** listChatRequests, getRequestCount

**Blocks (3):** checkBlocks, getBlockStatus, handleBlockChange

**Opt-in/out (3):** optIn, optOut, getOptInStatus

**Realtime (3):** getSubscriptionTicket, subscribeConvoEvents (WebSocket), updateCursor, updateRead

**Welcome/Commits/Readdition (3):** getWelcome, getCommits, readdition

**Admin (15):** promote/demote admin/moderator, removeMember, stats, reports, invites, policy

**Total: 76+ endpoints**

---

## Auth System (auth.rs)

**Features:**
- AT Protocol JWT validation (ES256, ES256K)
- DID document resolution with caching (moka)
- Per-DID rate limiting (100 req/60s default)
- `jti` replay detection (JTI_TTL_SECONDS=120)
- `lxm` endpoint binding validation (ENFORCE_LXM)

**Key Types:**
```rust
pub struct AtProtoClaims {
    pub iss: String,      // Issuer DID
    pub aud: String,      // Audience
    pub exp: i64,         // Expiration
    pub lxm: Option&lt;String&gt;,  // Endpoint NSID
    pub jti: Option&lt;String&gt;,  // Nonce
}

pub struct AuthUser {
    pub did: String,
    pub claims: AtProtoClaims,
}
```

**Env Vars:**
- `SERVICE_DID` - Required audience
- `ENFORCE_LXM` - Require endpoint match (default: false)
- `ENFORCE_JTI` - Replay detection (default: true)

---

## Database Schema (Key Tables)

- `conversations` - Group metadata (group_id, cipher_suite)
- `members` - Membership (convo_id, member_did, role)
- `messages` - Encrypted messages (ciphertext, epoch, padded_size)
- `key_packages` - Pre-keys (owner_did, hash, ciphertext)
- `blobs` - Welcome messages and blobs
- `devices` - Device registration
- `welcome_messages` - Cached welcomes
- `group_info_cache` - Cached group info
- `event_stream` - MLS events for realtime
- `cursors` - Read cursors per user/conversation
- `chat_requests` - 1:1 chat negotiation

---

## Middleware Stack (5)

1. **mls_auth.rs** - MLS protocol authentication
2. **device_activity.rs** - Track for rate limiting
3. **idempotency.rs** - Idempotency key replay prevention
4. **logging.rs** - Request/response logging
5. **rate_limit.rs** - DID-based and IP-based limits

---

## Actor System (Ractor)

- **registry.rs** - Actor lookup
- **supervisor.rs** - Supervision/restart
- **conversation.rs** - Per-conversation actor
- **messages.rs** - Message handling actor

Used for concurrent message delivery without blocking.

---

## Realtime (SSE/WebSocket)

- `subscribe_convo_events_ws` - WebSocket endpoint
- `sse.rs` - Server-Sent Events
- `cursor.rs` - Pagination cursors

---

## Fanout/Mailbox Backend

**Current:** `NullBackend` (no-op)  
**Trait:** `MailboxBackend::notify(envelope: &amp;Envelope)`  

Pluggable design for future backends (push, webhook, PDSS).

---

## Key Dependencies

```toml
# Web
axum = { version = "0.7", features = ["macros", "ws"] }
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.5", features = ["trace", "cors"] }

# Database
sqlx = { version = "0.7", features = ["postgres", "macros", ...] }

# MLS &amp; Crypto
openmls = "0.8"
ed25519-dalek = "2"
p256 = { version = "0.13", features = ["ecdsa"] }
k256 = { version = "0.13", features = ["ecdsa"] }

# Auth &amp; AT Protocol
jsonwebtoken = "9"
atrium-api = "0.25"
atrium-xrpc = "0.12"

# Caching &amp; Rate Limiting
moka = { version = "0.12", features = ["future", "sync"] }
governor = "0.6"

# Actors
ractor = "0.12"
dashmap = "6.0"

# Push
a2 = "0.10"  # APNs

# Metrics
metrics = "0.21"
prometheus = "0.13"
```

---

## Lexicon Files (67 total)

Location: `lexicon/blue/catbird/mls/`

Categories:
- Conversation (8 files)
- Messages/Events (10)
- Key Packages (7)
- Devices (9)
- Chat Requests (7)
- Blocks/Safety (4)
- Admin/Moderation (9)
- Invitations (3)
- Opt-in/out (3)
- Welcome/Readdition (4)
- MLS Protocol (2)
- Subscriptions/Policy (4)
- Shared defs (2)

---

## Integration Points

**External Services:**
- Bluesky PDS - AT Protocol data, identity
- PLC Directory - DID resolution
- APNs - Apple Push Notifications

**Related Codebases:**
- Catbird iOS app - Client consuming these XRPC endpoints
- catbird-mls - UniFFI bindings, shared with this server
- catmos - Desktop app using same MLS orchestrator

---

## Status

**Production Ready:** Yes  
**Deployment:** Systemd on Ubuntu  
**Scaling:** Horizontal with load balancer  
**Monitoring:** Prometheus metrics, health endpoints

</projects/mls_ds_server>
<projects/poll_blue description="poll.blue project context: architecture, tech stack, key files">
**poll.blue**

Location: /Users/joshlacalamito/Developer/poll.blue
Session ID: 46cbd04b-17bd-4f06-bbb7-57d5bb0a4978
Date: 2026-02-08

**What This Is:**
AT Protocol polling/voting lexicon and AppView service. Creates `blue.poll.*` namespace for polls on Bluesky.

**Architecture:**
- **Lexicons**: `blue.poll.poll`, `blue.poll.vote`, `blue.poll.pollgate`, `blue.poll.getResults`
- **Stack**: SvelteKit + TypeScript + `@atproto/lex` + Valkey (Redis)
- **Deployment**: Self-hosted on VPS (no Docker)
- **Microcosm integration**: Constellation (backfill), Spacedust (optional streaming), Slingshot (edge cache)

**Key Design Decisions:**
- Confidential OAuth client pattern for web auth (not app passwords)
- Service proxying XRPC for native clients (Catbird can use existing PDS connection)
- Vote validation at AppView layer (7 rules: first-write-wins, CID match, time bound, index bounds, cardinality, no duplicates, pollgate)
- Valkey for tallies, dedup, caching (self-hosted on VPS)
- No real-time streaming for v1 (fetch-based results, Spacedust is optional enhancement)

**Status:** Phase 1 implementation IN PROGRESS (Feb 8, 2026)
- ✅ Research complete (lex-cli, OAuth, Microcosm APIs documented)
- ✅ SvelteKit scaffold with @atproto dependencies
- ✅ 4 AT Protocol lexicon schemas (blue.poll.poll/vote/pollgate/getResults)
- ✅ OAuth flow with lazy-initialized NodeOAuthClient (avoids build-time URL validation)
- ✅ Vote validation engine (7 rules: first-write-wins, CID match, time bound, index bounds, cardinality, no duplicates, pollgate)
- ✅ Valkey infrastructure (6 key patterns, atomic ZADD NX for dedup, HINCRBY tallies, 30s TTL)
- ✅ Constellation backlink client (auto-pagination, vote fetching)
- ✅ Vote ingestion pipeline (backfill + real-time processing)
- ✅ Frontend with Stack Sans typography (Notch wordmark, Headline questions, Text body)
- ✅ SSR data loading for poll view and embed pages (Valkey cache → PDS fallback, creator handle resolution, viewer vote check)
- ✅ Results API endpoint wired to Valkey
- ✅ Action modules (createPoll, castVote) - creates poll records, optional pollgate, Bluesky post with embed
- 🔄 Form wiring and auth UI (Task #12 in progress)
- ⏳ E2E integration test (Task #13, blocked by #12)
- ✅ Builds clean (0 errors)

**Key Implementation Patterns:**
- Lazy OAuth client init to avoid build-time env var issues
- ZADD NX in Redis for atomic first-write-wins deduplication
- Pipeline-based setFollowers for atomic pollgate follower caching
- 30s TTL on open poll tallies (Constellation authoritative)
- Type casting for AT Protocol records ($type field)
- `new Agent(oauthSession)` pattern for authenticated PDS writes
- TID generation: microsecond timestamp + 10-bit random clock ID, base32 encoded

**Next Phase:** Form wiring, E2E integration, VPS deployment with Caddy

**Implementation Research (Feb 8, 2026):**

**@atproto/lex-cli** (v0.9.7):
- `lex install` - fetches base schemas
- `lex build` - generates TypeScript from lexicons
- `gen-api` - client types + validators
- `gen-server` - server-side code generation
- Usage: `npx @atproto/lex-cli gen-api ./output ./lexicons/**/*.json`

**OAuth (@atproto/oauth-client-node):**
- `NodeOAuthClient` constructor needs: clientMetadata, keyset (JoseKey[]), stateStore, sessionStore
- Confidential client uses `private_key_jwt` auth method
- ES256 keypair generation via `@atproto/jwk-jose`
- PKCE + DPoP required
- Scope: `"atproto transition:generic"`
- stateStore: CSRF tokens (TTL 1hr)
- sessionStore: persistent token storage

**Microcosm APIs:**
- **Constellation**: `GET /xrpc/blue.microcosm.links.getBacklinks?subject={uri}&amp;source=blue.poll.vote:poll.uri`
  - Also: `getBacklinksCount`, `getManyToManyCounts`
  - Public: `constellation.microcosm.blue`
- **Spacedust**: WebSocket at `wss://spacedust.microcosm.blue/subscribe?wantedSources=blue.poll.vote&amp;wantedSubjects={uri}`
  - Modeled after Jetstream, 21s delay buffer optional
- **Slingshot**: Edge cache for fast record fetch, `getRecord` + `resolveMiniDoc`

**Valkey/Redis Client:**
- **Recommendation: `ioredis`** for SvelteKit
  - Better TypeScript support than `redis`
  - More mature than `valkey-glide`
  - Good pipeline support for batch operations
  - Auto-reconnect, cluster support

**SvelteKit Patterns:**
- Server-only modules: `$lib/server/*.ts` (can't import from client)
- Hooks: `src/hooks.server.js` for auth middleware
- Environment: Use `dotenv` or Node 20.6+ `--env-file`
- Adapter: `@sveltejs/adapter-node` for VPS deployment
- OG meta tags: SSR via `handle` hook or `+page.server.ts` load functions

**strongRef Format:**
```typescript
{ uri: string, cid: string }  // No $type field needed
```
CID must be verified against actual record before storing reference
</projects/poll_blue>
<projects/renderer description="Renderer project context: architecture, tech stack, key files">
**SkiaCanvas** - React Native Graphics Editor

**Vision:** Mobile graphics editor with native feel (60fps, direct manipulation, offline) using React Native + Skia. Adobe Express/Spark alternative.

**Core Stack:**
- React Native with New Architecture (Fabric)
- @shopify/react-native-skia ~2.2.x (GPU-accelerated rendering)
- react-native-reanimated 4.x (UI thread gestures)
- react-native-gesture-handler (touch handling)
- Expo SDK 54+ (managed workflow with dev builds)
- Immer + zundo (undo/redo with patches)

**Architecture Patterns:**
- Scene graph: JSON-serializable document model with discriminated-union layer types
- Immutable state: All mutations via Immer produceWithPatches
- UI-thread transforms: Reanimated shared values drive Skia transforms without JS bridge
- Hit testing: Inverse matrix transforms in reverse z-order (no built-in Skia hit testing)
- Text editing: Bottom-sheet panel with native TextInput + Skia Paragraph display (not overlay)
- Export: Offscreen surface with tiled rendering for 4K+ to avoid OOM
- Persistence: Self-contained asset directories with URI rewriting
- Auto-save: Zustand subscribe with 2s debounce

**Layer Types:**
- ImageLayer: References asset by ID, crop rect, filters (brightness/contrast)
- TextLayer: Skia Paragraph rendering, edit via panel
- PathLayer: Freehand strokes with perfect-freehand smoothing
- ShapeLayer: Rectangle, ellipse, line with fill/stroke
- GroupLayer: Nested transforms, opacity, blend modes

**Status:** ALL PHASES COMPLETE ✅ (100% - 21/21 plans)

**Phase 6 Execution COMPLETE:** Feb 8, 2026 (~2m 44s, 5 commits)
- Wave 1: 06-01 - Memory Budget Tracker (2m) - 1GB threshold for proxy allocations
- Wave 2: 06-02 - Viewport Culling (44s) - bounding-circle culling with 200px margin
- Bonus: Sequential image loading in export (peak ~180MB vs ~372MB)

**Phase 5 Execution COMPLETE:** Feb 8, 2026 (~10m, 10 commits)
- Wave 1: 05-01 - Blend Modes + Shadows (6m) - 12 blend modes, Skia ImageFilter drop shadows
- Wave 2: 05-02 - Snap Guides (2m 30s) - 8px/12px hysteresis, expo-haptics
- Wave 3: 05-03 - Image Cropping (1m 30s) - non-destructive cropRect with Group clip

**Phase 4 Execution COMPLETE:** Feb 8, 2026 (~9.5 min, 9 commits)
- Wave 1: 04-01 - Export Pipeline (6m) - types, renderOffscreen, exportImage, toolbar button
- Wave 2: 04-02 - Persistence (2m) - projectSerializer, projectStorage, save/load UI
- Wave 3: 04-03 - Auto-Save (1m 10s) - Zustand subscribe with 2s debounce

**Phase 4 Deviations (4 auto-fixed):**
1. `SkFontManager` type doesn't exist → used `SkTypefaceFontProvider`
2. `canvas.drawParagraph` doesn't exist → used `para.paint()`
3. `canvas.rotate()` requires 3 args (degrees, rx, ry) → plan had 1 arg
4. `expo-file-system` SDK 54 moved `cacheDirectory`/`EncodingType` to `/legacy` subpath

**Phase 3 Execution COMPLETE:** Feb 8, 2026 (~18 min, 12 commits)
- Wave 1: 03-01 - Foundation + Text (9m 1s) - deps, types, PlaceholderLayer rename, fonts, TextLayerRenderer, TextEditSheet
- Wave 2: 03-02 - Shapes (2m 12s) - ShapeLayerRenderer, ShapePickerSheet, toolbar
- Wave 3: 03-03 - Color Picker (4m 6s) - ColorPickerSheet, integration into text/shape/drawing
- Wave 4: 03-04 - Layers Panel (2m 16s) - DraggableFlatList reorder, visibility/lock/rename, opacity slider

**Phase 2: Image + Drawing Layers** (4 plans, 3 waves) - EXECUTED
- Wave 1: 02-01 - Store foundation (zundo temporal, layer types, tool mode) ✅
- Wave 2: 02-02 + 02-03 - Image import pipeline + Drawing pipeline (parallel) ✅
- Wave 3: 02-04 - Integration (gesture routing, toolbar, undo/redo wiring) ✅

**Key Implementation Details:**
- **Eraser layer isolation**: `BlendMode.Clear` with `&lt;Group layer={&lt;Paint /&gt;}&gt;` compositing boundary
- **Raster caching**: Offscreen SkSurface for 60fps with 50+ strokes
- **perfect-freehand**: Returns filled polygon (not stroke centerline) - must render with `style="fill"`
- **Two-tier image proxy**: 2048px max for canvas, original preserved for export
- **Undo/redo**: zundo `temporal(immer(...))` with pause/resume for gesture coalescing
- **PlaceholderLayer rename**: `type: 'shape'` → `type: 'placeholder'` to avoid collision with new ShapeLayer
- **Text editing UX**: Bottom sheet with native TextInput + live Skia Paragraph preview (not raw TextInput rendering)
- **Font dual-loading**: Same TTF files in both RN Skia `useFonts` and `expo-font`
- **Export**: Imperative offscreen rendering path mirroring declarative React renderers
- **Persistence**: Self-contained asset directories with URI rewriting
- **Auto-save**: Zustand subscribe with 2s debounce, getState() at save time

**Phase 3+4 New Libraries:**
- `@gorhom/bottom-sheet` v5 - text/shape editing panels
- `react-native-draggable-flatlist` - layer reorder
- `reanimated-color-picker` - HSB color picker
- `@react-native-community/slider` - opacity slider
- `expo-media-library` - save exports to gallery
- `expo-sharing` - share exports

**Active Issues:** Object translation "jumping" and transform handle activation bugs from Phase 1 - still tracked but not blocking

**Next:** `/gsd:plan-phase 5` to plan Polish + Differentiators (snapping, haptics, drop shadows, blend modes, image cropping)

**Research COMPLETE (Feb 7, 2026):**
All 4 researchers + synthesizer + roadmapper finished:
- ✅ FEATURES.md - 15 table stakes validated
- ✅ STACK.md - Expo 54 + Skia 2.4.18 + Reanimated 4.2.1 verified
- ✅ ARCHITECTURE.md - Flat store + shared-value gestures validated
- ✅ PITFALLS.md - 8 critical pitfalls, 6 must be prevented in Phase 1
- ✅ ROADMAP.md - 6 phases, 30 requirements mapped
- ✅ REQUIREMENTS.md - REQ-IDs assigned
- ✅ STATE.md - Phase tracking

**Phase 1: Canvas Foundation + Document Model**
- 4 plans in 4 waves (sequential dependency chain)
- All 8 requirements covered (CANVAS-01..05, DOC-01..02, LAYER-04)
- Research: HIGH confidence (APIs verified against official docs)
- Verification: PASSED (all checks passed)

**Milestones:**
- M1 (6-8 weeks): MVP - import, select/transform, draw, text, export PNG
- M2 (4-6 weeks): Layer panel, undo/redo, shadows, save/load, export scaling
- M3 (6-8 weeks): Crop, snapping, shapes, blend modes, drawing improvements, perf hardening
- M4 (4-6 weeks): Polish, accessibility, TestFlight, release prep

**Performance Targets:**
- Touch-to-visual latency: ≤16ms (1 frame)
- Frame rate during gesture: 60fps sustained
- Object selection accuracy: 100% within 44pt hit area
- Undo responsiveness: &lt;100ms visual completion
- Export fidelity: Pixel-identical to preview

**Non-Goals (v1):**
- Multi-user/cloud sync
- Template marketplace
- Advanced photo editing (content-aware fill)
- Vector illustration (pen tool, bezier editing)
- Rich text formatting (mixed fonts per layer)
- Platform-specific UIs (use RN base)

**Reference Implementations:**
- perfect-freehand: Smooth variable-width strokes
- rn-perfect-sketch-canvas: RN Skia integration
- Rob Costello's infinite canvas: Pan/zoom patterns
- Figma/Excalidraw: Scene graph patterns
</projects/renderer>
<self_improvement description="Guidelines for evolving memory architecture and learning procedures.">
MEMORY ARCHITECTURE EVOLUTION:

When to create new blocks:
- User works on multiple distinct projects → create per-project blocks
- Recurring topic emerges (testing, deployment, specific framework) → dedicated block
- Current blocks getting cluttered → split by concern

When to consolidate:
- Block has &lt; 3 lines after several sessions → merge into related block
- Two blocks overlap significantly → combine
- Information is stale (&gt; 30 days untouched) → archive or remove

BLOCK SIZE PRINCIPLE:
- Prefer multiple small focused blocks over fewer large blocks
- Changed blocks get injected into Claude Code's prompt - large blocks add clutter
- A block should be readable at a glance
- If a block needs scrolling, split it by concern
- Think: "What's the minimum context needed?" not "What's everything I know?"

LEARNING PROCEDURES:

After each transcript:
1. Scan for corrections - User changed Claude's output? Preference signal.
2. Note repeated file edits - Potential struggle point or hot spot.
3. Capture explicit statements - "I always want...", "Don't ever...", "I prefer..."
4. Track tool patterns - Which tools used most? Any avoided?
5. Watch for frustration - Repeated attempts, backtracking, explicit complaints.

Preference strength:
- Explicit statement ("I want X") → strong signal, add to preferences
- Correction (changed X to Y) → medium signal, note pattern
- Implicit pattern (always does X) → weak signal, wait for confirmation

INITIALIZATION (new user):
- Start with minimal assumptions
- First few sessions: mostly observe, little guidance
- Build preferences from actual behavior, not guesses
- Ask clarifying questions sparingly (don't interrupt flow)
</self_improvement>
<session_patterns description="Recurring behaviors, time-based patterns, common struggles. Used for pattern-based guidance.">
(No patterns observed yet. Populated after multiple sessions.)

**MCP Log Capture Unreliability (Feb 2, 2026):**
- `mcp__xcodebuildmcp__start_device_log_cap` and `stop_device_log_cap` sometimes return empty logs
- Error code 10002 (CoreDeviceError) occurs when device is locked
- Alternative: Monitor Console.app directly for real-time logs
- Use MCP log capture as supplement, not primary debugging method

**SwiftUI Lifecycle Timing Issue (Feb 2, 2026):**
- `.onAppear` fires AFTER scene is fully rendered
- UIKit notifications (`didEnterBackgroundNotification`) fire BEFORE SwiftUI's `scenePhase`
- If app suspended before scene appears, `.onAppear` handlers never run
- Critical observers must be registered in `init()` to ensure they're active before suspension

**Multi-Agent Build Conflicts (Feb 2, 2026):**
- Concurrent Claude Code agents touching same DerivedData causes corruption
- Symptoms: Corrupted git object database in SPM cache, deleted folders
- Fix: Clear `~/Library/Developer/Xcode/DerivedData/Catbird-*/SourcePackages`
- Prevention: Use isolated `-derivedDataPath` per agent or coordinate access
</session_patterns>
<tmp/0xdead10cc_fix_plan.md description="Subagent dispatch plan for 0xdead10cc fixes">
# 0xdead10cc Fix - Subagent Dispatch Plan

## Overview
Address 5 gaps identified between Catbird and Signal's 0xdead10cc prevention. Focus on sync TRUNCATE at launch and GRDB defensive configuration.

## Gap Analysis (from user diagnosis)

| Gap | Severity | Root Cause |
|-----|----------|------------|
| 1. No sync TRUNCATE at launch | HIGH | Large WAL from previous crash holds locks longer |
| 2. GRDB config missing defensive settings | HIGH | 10s timeout risky, no immediate transactions |
| 3. Plaintext header may not be effective | MEDIUM | Migration check may have false positive |
| 4. Dead lock files still compiled | LOW-MED | flock/fcntl code exists, could init accidentally |
| 5. MLS ops not cancelled fast enough | LOW | Rust async may hold locks mid-write |

## Subagent Task Assignments

### Task 1: Rust FFI - Sync TRUNCATE Checkpoint at Launch
**Target:** `MLSFFI/src/mls_context.rs`

**Current:** Budget-based checkpoints during operation only (every 32 writes)
**Signal:** `syncTruncatingCheckpoint()` called at main app launch

**Implementation:**
```rust
// Add to MLSContext initialization (new method)
pub fn sync_truncating_checkpoint(&amp;self) -&gt; Result&lt;(), MLSError&gt; {
    self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    
    #[cfg(debug_assertions)]
    eprintln!("[MLS] Launch TRUNCATE checkpoint completed");
    
    Ok(())
}
```

**Swift Integration:**
```swift
// In MLS initialization path (main app only, not background)
if !isBackgroundLaunch {
    try mlsContext.syncTruncatingCheckpoint()
}
```

**Verification:** Log shows "Launch TRUNCATE checkpoint completed" on cold start.

---

### Task 2: GRDB - Sync TRUNCATE Checkpoint at Launch
**Target:** `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSGRDBManager.swift`

**Current:** Budget checkpoints only
**Signal:** `syncTruncatingCheckpoint()` for GRDB at main app launch

**Implementation:**
```swift
// Add to MLSGRDBManager
func syncTruncatingCheckpoint() throws {
    try dbPool.write { db in
        try db.execute(sql: "PRAGMA wal_checkpoint(TRUNCATE)")
    }
    
    MLSLogger.info("[GRDB] Launch TRUNCATE checkpoint completed")
}
```

**Integration Point:** Call from main app initialization, NOT from NSE/background.

---

### Task 3: GRDB Defensive Configuration
**Target:** `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSGRDBManager.swift` (GRDB config)

**Current config issues:**
- `busyMode = .timeout(10.0)` - 10s timeout dangerous during suspend
- Missing `defaultTransactionKind = .immediate`
- Missing `automaticMemoryManagement = false`
- Missing `allowsUnsafeTransactions = true`

**New Configuration:**
```swift
var configuration = Configuration()
configuration.defaultTransactionKind = .immediate  // Prevents lock escalation
configuration.automaticMemoryManagement = false    // Prevents DB ops at bad times
configuration.allowsUnsafeTransactions = true      // Needed for checkpoint-without-transaction

// Signal-style busy handler
configuration.busyMode = .callback({ retryCount in
    usleep(25_000)  // 25ms between retries
    // For normal ops: retry forever
    // Checkpoints should have separate timeout (50ms)
    return true
})
```

**Note:** Separate checkpoint timeout (50ms) may need custom implementation.

---

### Task 4: Delete Dead Lock Coordinator Files
**Target Files (DELETE ENTIRELY):**
1. `Catbird/Catbird/Core/State/ProcessCoordinator.swift` - `flock(fd, LOCK_EX)`
2. `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSAdvisoryLockCoordinator.swift` - `fcntl(fd, F_SETLK, ...)`
3. `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSGroupLockCoordinator.swift` - `fcntl(fd, F_SETLK, ...)`

**Risk:** Even if not called, `.shared` singletons could lazy-init and create lock files.

**Verification:** After deletion, verify no `flock` or `F_SETLK` symbols in binary:
```bash
nm Catbird.app/Catbird | grep -E "flock|F_SETLK"
# Should return nothing
```

---

### Task 5: Plaintext Header Diagnostic
**Target:** `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSPlaintextHeaderMigration.swift` OR new diagnostic tool

**Purpose:** Verify SQLite header magic is visible (not encrypted) at byte 0.

**Implementation:**
```swift
struct DatabaseDiagnostic {
    static func verifyPlaintextHeader(at url: URL) -&gt; Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return false
        }
        defer { try? handle.close() }
        
        guard let header = try? handle.read(upToCount: 16) else {
            return false
        }
        
        // SQLite magic: "SQLite format 3\0"
        let magic = Data("SQLite format 3\0".utf8)
        let isPlaintext = header.prefix(16) == magic
        
        MLSLogger.info("[DIAG] Database \(url.lastPathComponent) plaintext: \(isPlaintext)")
        return isPlaintext
    }
}
```

**Integration:** Run at app launch for both Rust FFI and GRDB databases. If false, force re-migration.

---

## Execution Order

**Parallel Safe:**
- Task 1 (Rust checkpoint) and Task 2 (GRDB checkpoint) - independent
- Task 4 (delete files) - independent
- Task 5 (diagnostic) - independent

**Dependencies:**
- Task 3 (GRDB config) should be done before Task 2 if possible (config affects checkpoint behavior)

**Recommended Order:**
1. Task 4 (remove dangerous files first - reduces risk)
2. Task 3 (GRDB config) + Task 1 (Rust checkpoint) in parallel
3. Task 2 (GRDB checkpoint) after Task 3
4. Task 5 (diagnostic) - can run anytime after

## Success Criteria

- [ ] Rust FFI sync TRUNCATE runs at main app launch (log evidence)
- [ ] GRDB sync TRUNCATE runs at main app launch (log evidence)
- [ ] GRDB uses immediate transactions (code review)
- [ ] GRDB busy handler retries forever with 25ms sleep (code review)
- [ ] Dead lock files deleted (file system check)
- [ ] Plaintext header diagnostic passes for both databases (log evidence)
- [ ] No 0xdead10cc crashes in 48 hours of device testing

## Rollback Plan

Each task is independently revertable via git. If crashes increase:
1. Revert Task 3 (GRDB config) first - most likely to cause new issues
2. Keep Tasks 1, 2, 4, 5 (safe improvements)

## Files Modified

- `MLSFFI/src/mls_context.rs` (Task 1)
- `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSGRDBManager.swift` (Tasks 2, 3)
- DELETE: `ProcessCoordinator.swift` (Task 4)
- DELETE: `MLSAdvisoryLockCoordinator.swift` (Task 4)
- DELETE: `MLSGroupLockCoordinator.swift` (Task 4)
- NEW: `DatabaseDiagnostic.swift` OR modify `MLSPlaintextHeaderMigration.swift` (Task 5)

</tmp/0xdead10cc_fix_plan.md>
<tmp/gsd-handoff.md description="GSD handoff document for next session">
# GSD Handoff: Next Session Commands

**Date:** 2026-01-30
**Project:** Catbird Auth &amp; MLS Stability
**Status:** Phase 1 planned, critical MLS blocker identified

---

## 🎯 Priority 1: Execute Auth Fix (Phase 1)

Two plans ready for the error propagation fix:

```bash
/gsd:execute-phase 1
```

**What this fixes:**
- nest auth middleware returns bare 401 → returns JSON error bodies
- iOS can distinguish fatal vs transient auth failures
- Should reduce the "logged in but non-functional" sessions

**Files modified:**
- `nest/catbird/src/middleware/auth.rs`
- `nest/catbird/src/services/session_service.rs`
- `nest/catbird/src/metrics.rs`
- `Petrel/Sources/Petrel/Auth/ConfidentialGatewayStrategy.swift`
- `Petrel/Sources/Petrel/Network/NetworkService.swift`

---

## 🚨 Critical Discovery: MLS Blocker

**Issue:** MLS messages failing due to **account switch race condition**

**Evidence from logs:**
```
❌ Account mismatch: authenticated=did:plc:34x52... expected=did:plc:7nmn...
❌ [SYNC] Authentication mismatch - aborting sync to prevent data corruption
MLS: Failed to load conversations: User authentication required
```

**Root cause:** Multi-account isolation breaking MLS initialization. This is **Phase 5** territory, not Phase 6-8.

---

## 🎯 Priority 2: Address MLS Account Isolation

**Option A: Add to current auth work**
```bash
/gsd:discuss-phase 5
```
Scope: MLS account isolation as dependency of auth stability

**Option B: Quick diagnostic**
Review how MLS manager lifecycle binds to account switches:
- `MLSConversationManager` initialization
- Account switch notification handling
- Advisory lock cleanup on switch

**Option C: Single-account workaround**
Force MLS testing with single account while fixing auth

---

## 📋 All Available Commands

| Command | Purpose |
|---------|---------|
| `/gsd:execute-phase 1` | Run the 2 auth fix plans |
| `/gsd:discuss-phase 5` | Plan multi-account MLS isolation |
| `/gsd:plan-phase 7` | Original MLS message reliability (blocked by Phase 5) |
| `/gsd:progress` | Check overall project status |
| `/gsd:verify-work 1` | Run UAT after Phase 1 execution |

---

## 🔍 Key Files for MLS Investigation

If debugging the account switch issue:
- MLS manager lifecycle binding
- Advisory lock acquisition/cleanup
- Account switch notification handling
- `did:plc:34x52srgxttjewbke5hguloh` vs `did:plc:7nmnou7umkr46rp7u2hbd3nb` handling

---

## 🎬 Recommended Next Session Flow

1. **Start with:** `/gsd:execute-phase 1` (ship the auth fix)
2. **Then:** Check if auth changes fixed the account switch behavior
3. **If not:** `/gsd:discuss-phase 5` to scope MLS account isolation
4. **When ready:** `/gsd:plan-phase 7` for actual message reliability work

---

## 📁 Log Files for Reference

- `mac logs.txt` (5.5MB) - Account mismatch evidence
- `iphone logs.txt` (452KB) - Advisory lock contention

Search for: `Account mismatch`, `Advisory lock busy`, `cancelled`

</tmp/gsd-handoff.md>
<tmp/mls_testing_team_plan.md description="MLS E2E testing team plan with subagent architecture">
# MLS Group Chat E2E Testing Team - Implementation Plan

## Overview
Build an agentic testing infrastructure using xcodebuildmcp to run multiple iOS simulators in parallel, testing MLS group chat functionality end-to-end with automated log capture, edge case definition, and programmatic UI control.

**Current Assets:**
- E2E-ChatA simulator (CE37CA9F-D8FF-4BA5-A785-148A37F35E3C) - catbirdbot.bsky.social
- E2E-ChatB simulator (A22A216E-97C9-4284-820F-6A6CB9863FB1) - j0sh.bsky.social
- xcodebuildmcp server configured and operational
- M4 Max with 128GB unified memory (supports 8+ simulators in parallel)

---

## Team Structure (Subagent Roles)

### 1. Fleet Manager Agent
**Responsibility:** Simulator lifecycle and resource allocation

**Tasks:**
- Boot/shutdown simulators on demand
- Manage simulator state (fresh boot vs warm start)
- Coordinate parallel builds across simulator fleet
- Monitor system resources (memory, CPU) on M4 Max
- Handle simulator failures (stuck simulators, boot loops)

**xcodebuildmcp Tools:**
- `list_sims` - inventory available simulators
- `boot_sim` - start simulators
- `open_sim` - open Simulator.app UI
- `get_sim_app_path` - locate built app
- `install_app_sim` - deploy to simulators
- `terminate_sim` - force kill stuck simulators

**Deliverable:** `FleetStatus.json` - real-time simulator availability and health

---

### 2. Test Orchestrator Agent
**Responsibility:** Coordinate multi-device test scenarios

**Tasks:**
- Parse test definitions and assign to simulator pairs
- Synchronize actions across multiple simulators (A creates group → B accepts)
- Manage test state machine (setup → execute → verify → teardown)
- Handle timeouts and retries
- Aggregate results from all Device Driver agents

**Coordination Pattern:**
```
Shared State File: /tmp/mls_test_state/{test_id}.json
{
  "test_id": "group_create_001",
  "phase": "waiting_for_invite_accept",
  "device_a": { "simulator_id": "E2E-ChatA", "status": "invite_sent" },
  "device_b": { "simulator_id": "E2E-ChatB", "status": "awaiting_invite" },
  "timeout_at": "2026-02-07T18:00:00Z"
}
```

**Deliverable:** Test execution reports with pass/fail and timing

---

### 3. Device Driver Agent (One per simulator)
**Responsibility:** Execute UI automation on a single simulator

**Tasks:**
- Launch app with log capture: `launch_app_logs_sim`
- Execute UI automation sequences (tap, swipe, type)
- Capture screenshots on failure
- Extract logs on completion: `stop_and_get_simulator_log`
- Report device-specific results back to Orchestrator

**xcodebuildmcp UI Automation:**
- `ui_tap_sim` - tap coordinates or accessibility identifier
- `ui_type_sim` - type text into text fields
- `ui_swipe_sim` - swipe gestures
- `ui_screenshot_sim` - capture screen state
- `ui_terminate_sim` - kill app

**Deliverable:** Device execution logs + screenshots

---

### 4. Log Analysis Agent
**Responsibility:** Parse captured logs for MLS-specific events

**Tasks:**
- Extract MLS protocol events from device logs
- Detect error patterns (AddMembersFailed, epoch mismatches, etc.)
- Correlate events across multiple simulators (A sent → B received)
- Generate timeline visualization of message flow
- Flag anomalies for human review

**Log Patterns to Extract:**
```
# Group creation
"Creating MLS group for conversation:"
"Successfully created MLS group"
"AddMembersFailed" → capture full error details

# Message flow
"Sending MLS message"
"Received MLS message"
"Message decrypted successfully"
"Epoch mismatch detected"

# Sync events
"[SYNC] Starting sync"
"[SYNC] Sync completed"
"[SYNC] Authentication mismatch"

# Database
"TRUNCATE checkpoint" (WAL management)
"Emergency closing database"
```

**Deliverable:** Structured JSON logs + anomaly reports

---

### 5. Edge Case Generator Agent
**Responsibility:** Define and execute edge case scenarios

**Tasks:**
- Generate permutations of edge cases from base scenarios
- Prioritize cases by risk/impact
- Update test suite with new edge cases as discovered
- Maintain "known failure" registry

**Edge Case Categories:**

#### Group Lifecycle
1. **Creator leaves before invitee accepts**
2. **Invitee rejects invitation**
3. **Creator deletes group before first message**
4. **Multiple simultaneous group creations**
5. **Group creation with 10+ members (device limit)**

#### Network/State
6. **Account switch during group creation**
7. **App backgrounded during invite acceptance**
8. **Simulator killed mid-message send**
9. **Network loss during sync**
10. **Concurrent message send from both devices**

#### Epoch/State Machine
11. **Message sent with stale GroupInfo**
12. **External commit fallback scenario**
13. **Epoch desync recovery**
14. **Message arrives for unknown group**
15. **Duplicate message handling**

#### Device/Resource
16. **Low memory during MLS operation**
17. **Database locked (0xdead10cc prevention)**
18. **Key package exhaustion**
19. **Rate limiting on device registration**
20. **Simulator time drift (TLS cert issues)**

**Deliverable:** Edge case definitions + reproduction scripts

---

## Test Scenarios (Core Suite)

### Scenario A: Basic Group Creation &amp; Messaging
```yaml
name: basic_group_messaging
devices: [E2E-ChatA, E2E-ChatB]
steps:
  - device: E2E-ChatA
    action: navigate_to_conversations
  - device: E2E-ChatA
    action: create_new_conversation
    params:
      recipient: j0sh.bsky.social
  - device: E2E-ChatA
    action: send_message
    params:
      text: "Hello from A"
  - device: E2E-ChatB
    action: wait_for_notification
    timeout: 30s
  - device: E2E-ChatB
    action: open_conversation
    params:
      with: catbirdbot.bsky.social
  - device: E2E-ChatB
    action: verify_message
    params:
      text: "Hello from A"
  - device: E2E-ChatB
    action: send_message
    params:
      text: "Reply from B"
  - device: E2E-ChatA
    action: verify_message
    params:
      text: "Reply from B"
verify:
  - both_devices_received_all_messages
  - epochs_match
  - no_errors_in_logs
```

### Scenario B: Account Switch Stress Test
```yaml
name: account_switch_with_pending_invite
devices: [E2E-ChatA, E2E-ChatB]
steps:
  - device: E2E-ChatA
    action: create_new_conversation
  - device: E2E-ChatA
    action: send_invite
  - device: E2E-ChatB
    action: background_app
  - device: E2E-ChatB
    action: switch_account
    params:
      delay_before_switch: 5s
  - device: E2E-ChatB
    action: switch_back_to_original_account
  - device: E2E-ChatB
    action: foreground_app
  - device: E2E-ChatB
    action: accept_invite
verify:
  - no_hang_during_account_switch
  - invite_acceptable_after_switch
```

### Scenario C: Epoch Synchronization
```yaml
name: epoch_sync_after_offline
devices: [E2E-ChatA, E2E-ChatB]
steps:
  - device: E2E-ChatA
    action: create_group_and_send_message
  - device: E2E-ChatB
    action: receive_message
  - device: E2E-ChatA
    action: terminate_app
  - device: E2E-ChatA
    action: relaunch_app
  - device: E2E-ChatA
    action: send_message
    params:
      text: "After restart"
  - device: E2E-ChatB
    action: verify_message
    params:
      text: "After restart"
verify:
  - epochs_match_after_restart
  - no_external_commit_errors
```

---

## Implementation Phases

### Phase 1: Infrastructure Setup (Week 1)
- [ ] Create test runner script with subagent spawning
- [ ] Implement Fleet Manager with simulator health checks
- [ ] Set up shared state coordination (filesystem-based)
- [ ] Create log capture pipeline
- [ ] Build basic Device Driver for single simulator

### Phase 2: Core Scenarios (Week 2)
- [ ] Implement basic group creation scenario
- [ ] Add message send/receive verification
- [ ] Build Log Analysis agent with pattern matching
- [ ] Create test result aggregation
- [ ] Add screenshot capture on failure

### Phase 3: Edge Cases &amp; Parallelization (Week 3)
- [ ] Implement Edge Case Generator
- [ ] Add multi-simulator parallel execution
- [ ] Build resource monitoring (prevent M4 Max overload)
- [ ] Add retry logic with exponential backoff
- [ ] Create failure classification system

### Phase 4: CI/CD Integration (Week 4)
- [ ] GitHub Actions integration for nightly runs
- [ ] Slack/Discord notifications for failures
- [ ] Test result dashboard
- [ ] Regression detection (compare to baseline)
- [ ] Automatic bug report generation

---

## Technical Architecture

### Directory Structure
```
Catbird+Petrel/
├── Testing/
│   ├── Team/
│   │   ├── fleet_manager.py       # Simulator lifecycle
│   │   ├── test_orchestrator.py   # Coordination logic
│   │   ├── device_driver.py       # UI automation wrapper
│   │   ├── log_analyzer.py        # Log parsing
│   │   └── edge_case_generator.py # Test case generation
│   ├── Scenarios/
│   │   ├── basic_messaging.yaml
│   │   ├── account_switch.yaml
│   │   └── epoch_sync.yaml
│   ├── Results/
│   │   └── {timestamp}/
│   │       ├── logs/
│   │       ├── screenshots/
│   │       └── report.json
│   └── run_tests.py               # Main entry point
```

### Shared State Protocol
```python
# File-based coordination for cross-simulator sync
class TestState:
    def wait_for_phase(self, device_id: str, phase: str, timeout: int)
    def set_phase(self, device_id: str, phase: str, data: dict)
    def get_device_status(self, device_id: str) -&gt; dict
```

### UI Automation Abstraction
```python
class CatbirdUI:
    def navigate_to_conversations(self)
    def create_conversation(self, recipient_did: str)
    def send_message(self, text: str)
    def verify_message_received(self, text: str, timeout: int)
    def accept_invite(self)
    def switch_account(self, account_index: int)
```

---

## xcodebuildmcp Integration Points

### Build &amp; Deploy
```python
# Fleet Manager workflow
for sim in simulators:
    mcp.build_sim(scheme="Catbird", simulatorId=sim.id)
    mcp.install_app_sim(simulatorId=sim.id, appPath=app_path)
```

### Log Capture
```python
# Device Driver workflow
session_id = mcp.launch_app_logs_sim(
    simulatorId=sim_id,
    bundleId="blue.catbird"
)
# ... run test ...
logs = mcp.stop_and_get_simulator_log(logSessionId=session_id)
```

### UI Automation
```python
# Tap by accessibility identifier
mcp.ui_tap_sim(
    simulatorId=sim_id,
    identifier="create_conversation_button"
)

# Type text
mcp.ui_type_sim(
    simulatorId=sim_id,
    identifier="message_input",
    text="Hello from E2E test"
)

# Screenshot on failure
mcp.ui_screenshot_sim(
    simulatorId=sim_id,
    path=f"screenshots/failure_{test_id}.png"
)
```

---

## Success Metrics

- **Test Coverage:** 20+ edge cases automated
- **Pass Rate:** &gt;95% for core scenarios
- **Execution Time:** &lt;5 minutes for full suite (parallel execution)
- **Flakiness:** &lt;2% false failure rate
- **Log Coverage:** 100% of MLS protocol events captured

---

## Risk Mitigation

### Simulator Instability
- Auto-restart stuck simulators
- Health checks before test assignment
- Fallback to device testing for critical paths

### Race Conditions in Tests
- Explicit synchronization via shared state
- Wait conditions with timeouts
- Retry with exponential backoff

### Log Capture Failures
- Alternative: Console.app streaming
- Local log file backup in app
- Screenshot as fallback evidence

---

## Next Steps

1. **Approve plan** - Review and approve this architecture
2. **Phase 1 kickoff** - Start with Fleet Manager + single Device Driver
3. **Validate on existing simulators** - Test with E2E-ChatA and E2E-ChatB
4. **Expand fleet** - Add more simulators for parallel testing
5. **Integrate with CI** - Nightly automated runs

**Estimated Timeline:** 4 weeks to full automation
**Resource Requirements:** 1 developer + M4 Max hardware

</tmp/mls_testing_team_plan.md>
<tmp/poll_fixes.md description="poll.blue fixes for handle display, success indicator, and 500 error">
# poll.blue Fixes - DEPLOYED

## Fix 1: Show Handle Instead of DID ✅
- Added `resolvePds()` and `resolveHandle()` to `src/lib/server/pds.ts`
- Uses Slingshot for fast identity resolution, falls back to PLC directory
- Layout server now resolves handle from PDS
- UI shows `@handle` instead of `did:plc:...`

## Fix 2: 500 Error on Poll View ✅
- Fixed: `selectedChoices.includes is not a function` — SSR $state issue
- Fixed: Constellation returns `records` not `backlinks`

## Fix 3: No Hardcoded bsky.social ✅
- All PDS resolution now dynamic via DID document
- Slingshot used as fast cache for record fetching

## Fix 4: Vote Record Hydration ✅
- Constellation returns lightweight pointers (did, collection, rkey)
- Slingshot hydrates pointers into full records in parallel
- Proper Microcosm architecture: Constellation for discovery, Slingshot for hydration

## Fix 5: Vote Deduplication ✅
- Validator Rule 1: `checkFirstWriteWins()` rejects duplicate DIDs
- Valkey: `addVoter()` uses SADD NX for atomic first-write-wins
- Server-side validation rejects duplicate votes

## Fix 6: Already Voted Check ✅
- UI: Vote button disabled if `viewerVote` present
- Server: Validator rejects duplicates

## Fix 7: Success After Create Poll ✅
- `use:enhance` callback extracts `result.data.pollUrl`
- Success screen shows "View poll" link + "Create another" button

## Fix 8: OAuth Redirect Preservation ✅
- Login form includes hidden `returnTo` field
- Cookie stores return URL before OAuth redirect
- Callback reads cookie and redirects back to poll page

## Fix 9: Missing Dependency ✅
- Added `@atproto/jwk-jose` to package.json

## Architecture
```
Poll Page Load:
1. Constellation → get vote backlinks (pointers only)
2. Slingshot → hydrate each vote record (parallel)
3. Validation → validate vote structure (7 rules)
4. Tally → aggregate results
5. Valkey → cache results (30s TTL)

Vote Cast:
1. Validator → checkFirstWriteWins (Rule 1)
2. Valkey SADD NX → atomic dedup
3. PDS write → create vote record
4. Constellation → backlink discovery (async)
```

## Files Modified
- `src/lib/server/pds.ts` - Slingshot identity resolution
- `src/lib/server/constellation.ts` - Slingshot hydration
- `src/lib/server/validator.ts` - Vote validation (7 rules)
- `src/routes/+layout.server.ts` - Resolve handle
- `src/routes/+layout.svelte` - Show @handle
- `src/routes/+page.svelte` - Create success flow
- `src/routes/+page.server.ts` - PUBLIC_URL for pollUrl
- `src/routes/p/[did]/[rkey]/+page.svelte` - SSR fix, returnTo field
- `src/routes/p/[did]/[rkey]/+page.server.ts` - fetchRecord integration
- `src/routes/embed/[did]/[rkey]/+page.server.ts` - fetchRecord integration
- `src/routes/oauth/login/+server.ts` - returnTo cookie
- `src/routes/oauth/callback/+server.ts` - returnTo redirect
- `package.json` - @atproto/jwk-jose dependency

## Status
- ✅ Deployed to pollblue.catbird.blue
- ✅ PM2 restarted (8 restarts total)
- ✅ Build successful (0 errors)
- ✅ All 4 user-reported issues fixed

</tmp/poll_fixes.md>
<tmp/posts_performance_audit.md description="Posts view performance audit plan">
# Posts View Performance Audit - IMPLEMENTATION PLAN

## Team Dispatch: All 8 Issues

### Parallel Workstreams

**Team A: Critical Rendering Issues (Issues #1-3)**
- Subagent A1: EnhancedFeedPost JSON decode fix
- Subagent A2: ISO8601DateFormatter static fix  
- Subagent A3: ContentLabelView duplicate async fix

**Team B: Layout &amp; Geometry (Issues #4, #8)**
- Subagent B1: ContentLabelView GeometryReader removal
- Subagent B2: App-wide maxWidth: 600 fix (8 files)

**Team C: Architecture Improvements (Issues #5-7)**
- Subagent C1: Content warning double-render fix
- Subagent C2: EnhancedFeedPost closure extraction
- Subagent C3: Equatable modifier application

## Target Areas
- Video rendering (AVPlayer lifecycle)
- GIF playback (decoding, memory pressure)
- Content warnings (state-driven visibility)
- Feed list performance (LazyVStack vs List)

## Verified Issues to Fix

### 1. AVPlayer Anti-Patterns
**BAD:** Creating player in `body`
```swift
var body: some View {
    VideoPlayer(player: AVPlayer(url: url)) // New player every render!
}
```

**GOOD:** `@StateObject` player controller
```swift
@StateObject private var playerController: PlayerController

class PlayerController: ObservableObject {
    let player = AVPlayer()
    // Configure once
}
```

### 2. GIF Decoding Blocks
**BAD:** Synchronous GIF decoding in body
```swift
var body: some View {
    if let gifData = data {
        AnimatedImage(data: gifData) // Decodes on main thread
    }
}
```

**GOOD:** Async decoding with placeholder
```swift
@State private var gifImage: UIImage?

var body: some View {
    Group {
        if let gifImage {
            AnimatedImage(image: gifImage)
        } else {
            Placeholder()
        }
    }
    .task {
        gifImage = await decodeGIF(data)
    }
}
```

### 3. Content Warning State Pollution
**BAD:** `@State` for CW toggle in parent view
```swift
struct PostView: View {
    @State private var showSensitiveContent = false // Triggers full re-render
    
    var body: some View {
        if post.hasCW &amp;&amp; !showSensitiveContent {
            CWOverlay(toggle: $showSensitiveContent)
        } else {
            Content()
        }
    }
}
```

**GOOD:** Isolated CW component with local state
```swift
struct ContentWarningOverlay: View {
    @State private var revealed = false // Local only
    
    var body: some View {
        ZStack {
            Content().opacity(revealed ? 1 : 0)
            BlurOverlay().opacity(revealed ? 0 : 1)
        }
    }
}
```

### 4. Missing Equatable
**BAD:** View re-renders on unrelated state changes
```swift
struct PostView: View {
    let post: Post
    @State private var likeCount: Int // Changing this re-renders entire post
}
```

**GOOD:** Equatable view with selective updates
```swift
struct PostView: View, Equatable {
    let post: Post
    @State private var likeCount: Int
    
    static func == (lhs: Self, rhs: Self) -&gt; Bool {
        lhs.post.id == rhs.post.id &amp;&amp; lhs.likeCount == rhs.likeCount
    }
}
```

### 5. Heavy Body Computations
**BAD:** Processing in body property
```swift
var body: some View {
    let processedText = processMarkdown(post.text) // Runs every render!
    Text(processedText)
}
```

**GOOD:** Cached/memoized processing
```swift
@State private var processedText: AttributedString?

var body: some View {
    Text(processedText ?? "")
        .task(id: post.text) {
            processedText = await processMarkdown(post.text)
        }
}
```

## Investigation Commands

```bash
# Find post-related views
find Catbird -name "*Post*View*.swift" -type f

# Check for AVPlayer usage
grep -rn "AVPlayer\|VideoPlayer" Catbird/Catbird/Features/ --include="*.swift"

# Check for GIF libraries (SDWebImage, Kingfisher, etc.)
grep -rn "AnimatedImage\|GIF\|Kingfisher\|SDWebImage" Catbird/Catbird/ --include="*.swift"

# Check for @State in content warning contexts
grep -rn "showSensitive\|contentWarning\|CW" Catbird/Catbird/Features/ --include="*.swift" | head -30

# Check for Equatable implementations
grep -rn "Equatable\|static func ==" Catbird/Catbird/Features/Post --include="*.swift"
```

## Key Files to Audit
- Post feed view (LazyVStack/List implementation)
- Individual post cell view
- Video player wrapper
- GIF rendering component
- Content warning overlay
- Rich text/m Markdown processor

## Execution Order

**Phase 1 (Critical - Immediate):**
1. Issue #1: EnhancedFeedPost JSON decode → @State caching
2. Issue #2: ISO8601DateFormatter static
3. Issue #3: ContentLabelView remove duplicate .onAppear

**Phase 2 (Layout - Parallel safe):**
4. Issue #4: ContentLabelView GeometryReader → fixed threshold
5. Issue #8: All maxWidth: 600 → contentMaxWidth pattern

**Phase 3 (Architecture - After Phase 1):**
6. Issue #5: Content warning placeholder (depends on #4)
7. Issue #6: EnhancedFeedPost closure → computed property
8. Issue #7: Add .equatable() modifier

## Success Criteria
- [ ] JSON decode cached (not in body property)
- [ ] ISO8601DateFormatter static/shared
- [ ] No duplicate .task + .onAppear calls
- [ ] GeometryReader removed from blur overlays
- [ ] Content placeholder when blurred (not full render)
- [ ] Closure extracted from body
- [ ] .equatable() modifier applied
- [ ] All maxWidth: 600 use responsive pattern

</tmp/posts_performance_audit.md>
<tmp/signal_impl_plan.md description="Signal-style implementation plan for subagents">
# Signal-Style 0xdead10cc Prevention - Implementation Plan

## Overview
Replace comprehensive mitigation with Signal's prevention approach:
- **Remove** advisory locks (cause 0xdead10cc)
- **Remove** emergency database close on suspend
- **Add** budget-based TRUNCATE checkpoints (keep WAL tiny)
- **Add** Darwin notifications for lockless coordination

## Subagent Task Assignments

### Task 1: Remove Advisory Lock Infrastructure
**Target Files:**
- `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSAdvisoryLockCoordinator.swift` - DELETE
- `Catbird/Catbird/Core/State/AppState.swift:1716-1719` - Remove `releaseAllLocks()` calls
- `CatbirdMLSCore/Sources/CatbirdMLSCore/Storage/MLSGroupLockCoordinator.swift` - DELETE if exists

**Replacement:**
Add Darwin notification helpers to `CatbirdMLSCore`:
```swift
// DarwinNotificationCenter.swift
public enum MLSDarwinNotification: String {
    case appSuspending = "blue.catbird.mls.app-suspending"
    case appResuming = "blue.catbird.mls.app-resuming"
    case nseActive = "blue.catbird.mls.nse-active"
    case nseInactive = "blue.catbird.mls.nse-inactive"
}

public func postDarwinNotification(_ name: MLSDarwinNotification)
public func observeDarwinNotification(_ name: MLSDarwinNotification, handler: @escaping () -&gt; Void)
```

### Task 2: NSE Darwin Notification Migration
**Target File:**
- `Catbird/NotificationServiceExtension/NotificationService.swift:236-294`

**Current Code (lines 236-294):**
```swift
// HARD GATE: Probe if advisory lock is available (without holding it).
if !tryAcquireMLSCrossProcessStorageGate(userDID: recipientDid) {
    logger.info("🔒 [NSE] Cannot acquire advisory lock - showing generic notification")
    // ... show generic notification
    return
}
// ... proceed with database operations
```

**New Implementation:**
Replace advisory lock check with:
```swift
// Check if app is suspending via Darwin notification state
if MLSDarwinNotificationCenter.isAppSuspending {
    logger.info("🔒 [NSE] App is suspending - showing generic notification")
    // ... show generic notification
    return
}

// Post NSE active notification
MLSDarwinNotificationCenter.post(.nseActive)
defer { MLSDarwinNotificationCenter.post(.nseInactive) }

// Proceed with database operations (SQLite handles locking)
```

### Task 3: Rust Budget-Based TRUNCATE Checkpoints
**Target File:**
- `MLSFFI/src/mls_context.rs`

**Current Implementation:**
SQLCipher initialization with pragmas (lines 61-189)
- Has `cipher_plaintext_header_size = 32` ✓
- Missing: `checkpoint_fullfsync = ON`
- Missing: `PRAGMA wal_checkpoint(TRUNCATE)` on budget

**New Implementation:**

1. Add to `MLSContextInner`:
```rust
use std::sync::atomic::{AtomicU32, Ordering};

pub struct MLSContextInner {
    // ... existing fields ...
    write_counter: AtomicU32,
    checkpoint_budget: u32, // Configurable, default 32
}
```

2. Add checkpoint budget method:
```rust
impl MLSContextInner {
    /// Increment write counter and TRUNCATE checkpoint if budget reached
    fn maybe_checkpoint(&amp;self) -&gt; Result&lt;(), rusqlite::Error&gt; {
        let count = self.write_counter.fetch_add(1, Ordering::Relaxed);
        
        if count % self.checkpoint_budget == 0 {
            // TRUNCATE checkpoint resets WAL to zero pages
            self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            
            // Log for debugging
            #[cfg(debug_assertions)]
            eprintln!("[MLS] TRUNCATE checkpoint at write {}", count);
        }
        
        Ok(())
    }
    
    /// Call this after every write operation
    pub fn on_write_completed(&amp;self) -&gt; Result&lt;(), MLSError&gt; {
        self.maybe_checkpoint()
            .map_err(|e| MLSError::DatabaseError(e.to_string()))
    }
}
```

3. Add missing pragmas in `mls_context.rs` (around line 130, after journal_mode):
```rust
// After: "PRAGMA journal_mode = WAL;"
// Add:
"PRAGMA checkpoint_fullfsync = ON;"
```

4. Note: `F_BARRIERFSYNC` may require custom SQLite build - verify if available in SQLCipher.

### Task 4: Swift Suspension Simplification
**Target Files:**
- `Catbird/Catbird/App/CatbirdApp.swift:779-1076`
- `Catbird/Catbird/Core/State/AppState.swift`

**Current Code (simplified):**
```swift
func handleScenePhaseChange(from oldPhase: ScenePhase, to newPhase: ScenePhase) {
    // 1. Acquire background task
    taskId = UIApplication.shared.beginBackgroundTask(...)
    
    Task { @MainActor in
        // 2. Signal suspension to DB layer
        MLSDatabaseCoordinator.shared.prepareForSuspension()
        
        // 3. Flush main database
        modelContext.save()
        
        // 4. Call Rust FFI flush
        appState.flushMLSStorageForSuspension()
        
        // 5. Emergency close all pools
        MLSGRDBManager.emergencyCloseAllDatabases()
        
        // 6. Release background task
        UIApplication.shared.endBackgroundTask(taskId)
    }
}
```

**New Signal-Style Implementation:**
```swift
func handleScenePhaseChange(from oldPhase: ScenePhase, to newPhase: ScenePhase) {
    switch newPhase {
    case .background:
        // Signal Darwin notification ONLY - no heavy work
        MLSDarwinNotificationCenter.post(.appSuspending)
        
        // SwiftData handles its own checkpointing
        // WAL is kept small by budget-based checkpoints during normal operation
        // No emergency close, no database operations during suspension
        
    case .active:
        MLSDarwinNotificationCenter.post(.appResuming)
        
        // NSE may have deferred work - check if any notifications pending
        // (Optional: Trigger NSE to process deferred notifications)
        
    default:
        break
    }
}
```

**Key Changes:**
1. Remove `beginBackgroundTask` for database operations (keep only for actual background tasks like BGTaskScheduler)
2. Remove `prepareForSuspension()` - no longer needed
3. Remove `flushMLSStorageForSuspension()` from suspend path (keep for app termination only)
4. Remove `emergencyCloseAllDatabases()` entirely
5. Keep SwiftData `modelContext.save()` for data integrity (SwiftData handles checkpointing internally)

### Task 5: Verification &amp; Testing
**Testing Protocol:**

1. **Build and Deploy:**
   ```bash
   # Archive build (debugger attached prevents RunningBoard enforcement)
   xcodebuild -scheme Catbird -configuration Release archive
   
   # Install to device via Xcode Organizer or TestFlight
   ```

2. **Stress Test Protocol:**
   ```swift
   // Add temporary stress test button in debug build:
   Button("Stress Test 0xdead10cc") {
       // Rapid writes to all 4 databases
       for i in 0..&lt;1000 {
           // Write to Rust FFI MLS
           // Write to GRDB
           // Write to SwiftData
           // Write to CursorStore
       }
       // Immediately background
       UIApplication.shared.perform(#selector(NSXPCConnection.suspend), with: nil, afterDelay: 0.1)
   }
   ```

3. **Console.app Monitoring:**
   ```
   # Filter in Console.app:
   - "Catbird" (app logs)
   - "runningboardd" (termination events)
   - "0xdead10cc" (specific crash code)
   
   # Expected (GOOD):
   - Normal app lifecycle logs
   - No "was suspended with locked system files"
   - No 0xdead10cc termination codes
   
   # Bad (STILL CRASHING):
   - "Termination Reason: RUNNINGBOARD 0xdead10cc"
   - "was suspended with locked system files: [path to db]"
   ```

4. **NSE Verification:**
   - Send notification while app is backgrounded
   - Verify notification shows decrypted content (not "New Encrypted Message")
   - Check NSE logs for successful database access
   - Verify no SQLITE_BUSY errors in NSE logs

5. **Rollback Plan:**
   - Feature flag: `useDarwinCoordination` (default true)
   - If crashes persist, revert: `useDarwinCoordination = false`
   - Keep advisory lock code in git history (commented, not deleted)
   - Document decision in commit message for future reference

## Subagent Execution Order

**Parallel Tasks (can run simultaneously):**
- Task 1 (Remove Advisory Locks) and Task 3 (Rust Checkpoints) - no dependencies
- Task 2 (NSE Migration) depends on Task 1 completion (needs Darwin notifications)
- Task 4 (Swift Simplification) depends on Task 1 completion (removes lock calls)

**Recommended Order:**
1. Start Task 1 and Task 3 in parallel (independent)
2. When Task 1 completes, start Task 2 and Task 4 (both depend on Task 1)
3. Task 5 (Verification) runs after all implementation tasks complete

## Success Criteria

- [ ] No advisory locks held during suspension (verify via code review)
- [ ] WAL checkpoint budget implemented in Rust (verify via mls_context.rs)
- [ ] Darwin notifications posted on scene phase changes (verify via CatbirdApp.swift)
- [ ] NSE uses notification-based deferral (verify via NotificationService.swift)
- [ ] 0xdead10cc crashes eliminated in device testing (verify via Console.app)
- [ ] NSE can still decrypt notifications during app background (verify via manual test)
</tmp/signal_impl_plan.md>
<tmp/unified_profile_investigation.md description="UnifiedProfileView orientation bug investigation plan">
# UnifiedProfileView Orientation Bug - Investigation Plan

## Issue Description
When phone rotates and user navigates back, view stays in wide orientation instead of adapting to current device orientation.

## Common Root Causes (Priority Order)

### 1. GeometryReader Caching
- Check for `@State private var containerWidth: CGFloat` or similar
- GeometryReader values read once in .onAppear, not reactive
- Hardcoded `.frame(width: geometry.size.width)` instead of `.frame(maxWidth: .infinity)`

### 2. Navigation Stack View Identity
- Missing `.id(UIDevice.current.orientation)` or similar forcing re-render
- SwiftUI reusing view instance when it shouldn't
- Check for `.id()` misuse that prevents proper recreation

### 3. Size Class Assumptions
- Code checking `horizontalSizeClass == .regular` without .onChange
- Hardcoded column counts or grid layouts
- iPad-centric layout logic leaking to iPhone

### 4. UIHostingController Mismatch
- If wrapped in UIHostingController, check `preferredContentSize`
- `viewWillTransition(to:with:)` not propagated
- Safe area insets cached incorrectly

### 5. Custom Layout Containers
- Any custom Layout protocol implementations
- PreferenceKey usage for size propagation
- Cached calculated frames in layout containers

## Investigation Commands

```bash
# Find UnifiedProfileView
find Catbird -name "UnifiedProfileView.swift" -type f

# Check for geometry-related patterns
grep -n "GeometryReader\|\.frame(width:\|maxWidth:\|containerWidth\|sizeClass" Catbird/Catbird/Features/Profile/Views/UnifiedProfileView.swift

# Check for orientation-related code
grep -rn "orientation\|UIDevice.*orientation\|@State.*width\|@State.*height" Catbird/Catbird/Features/Profile/

# Check for .id() usage that might be problematic
grep -n "\.id(" Catbird/Catbird/Features/Profile/Views/UnifiedProfileView.swift
```

## Specific Patterns to Look For

**BAD Pattern 1: Cached Geometry**
```swift
@State private var viewWidth: CGFloat = 0

var body: some View {
    GeometryReader { geo in
        Content()
            .onAppear { viewWidth = geo.size.width } // Only sets once!
    }
}
```

**BAD Pattern 2: Hardcoded Width**
```swift
.frame(width: UIScreen.main.bounds.width) // Never use this
```

**BAD Pattern 3: Missing Size Class Reactivity**
```swift
@Environment(\.horizontalSizeClass) var sizeClass

// Without .onChange, won't update on rotation
let columns = sizeClass == .regular ? 3 : 2
```

**GOOD Pattern:**
```swift
// Use GeometryReader directly in body
GeometryReader { geometry in
    Content()
        .frame(width: geometry.size.width) // Reactive to changes
}
.onReceive(NotificationCenter.default.publisher(for: UIDevice.orientationDidChangeNotification)) { _ in
    // Force recalculation if needed
}
```

## Subagent Tasks

### Task 1: File Analysis
- Read UnifiedProfileView.swift completely
- Identify all GeometryReader usage
- Map all @State properties related to size/layout
- Check for custom view modifiers that might cache geometry

### Task 2: Navigation Context
- Check how UnifiedProfileView is presented (NavigationLink, sheet, etc.)
- Look for .navigationDestination usage
- Check if wrapped in UIHostingController
- Verify view identity in navigation stack

### Task 3: State Audit
- Find all @State, @StateObject, @ObservedObject properties
- Identify which ones store size/geometry data
- Check for missing .onChange handlers for size class or geometry

### Task 4: Fix Implementation
Based on findings, implement one of:

**Option A: GeometryReader Fix**
```swift
// Remove cached width, use GeometryReader directly
GeometryReader { geometry in
    VStack {
        // content using geometry.size.width directly
    }
    .frame(width: geometry.size.width) // Always current
}
```

**Option B: Force Re-render on Rotation**
```swift
@State private var orientation = UIDevice.current.orientation

var body: some View {
    Content()
        .id(orientation) // Force recreation on rotation
        .onReceive(NotificationCenter.default.publisher(for: UIDevice.orientationDidChangeNotification)) { _ in
            orientation = UIDevice.current.orientation
        }
}
```

**Option C: Size Class Reactive**
```swift
@Environment(\.horizontalSizeClass) private var horizontalSizeClass

var body: some View {
    let columns = horizontalSizeClass == .regular ? 3 : 2
    // Use columns in LazyVGrid or similar
}
```

## Verification Steps

1. Build and run on device/simulator
2. Navigate to profile view
3. Rotate device
4. Navigate to detail (if applicable)
5. Navigate back
6. Verify layout matches current orientation

## Expected Output

Report containing:
- Root cause identified (which pattern above)
- Specific line numbers in UnifiedProfileView.swift
- Proposed fix with code diff
- Verification steps completed

</tmp/unified_profile_investigation.md>
<tmp/video_player_flash_investigation.md description="Video player and link card flash investigation">
# Video Player + Link Card Flash Investigation

## Issue Description
Link card flashes when loading - likely placeholder → content transition without proper state management or animation.

## Target Files
1. **ModernVideoPlayerView.swift** - Video player lifecycle, AVPlayer setup
2. **PlayerLayerView.swift** - CALayer bridging, async player attachment
3. **ExternalEmbedView.swift** - Link card rendering, async image loading

## Common Flash Causes

### 1. Async Image Loading Flash
**BAD:** Placeholder visible while image loads, then sudden swap
```swift
if let loadedImage {
    Image(uiImage: loadedImage)  // Sudden appearance
} else {
    Placeholder()  // Visible during load
}
```

**GOOD:** Crossfade or opacity transition
```swift
ZStack {
    Placeholder().opacity(loadedImage == nil ? 1 : 0)
    loadedImage.map { Image(uiImage: $0) }
        .opacity(loadedImage != nil ? 1 : 0)
}
.animation(.default, value: loadedImage)
```

### 2. State Machine Flash
**BAD:** Multiple boolean flags causing intermediate states
```swift
if isLoading {
    ProgressView()
} else if let error {
    ErrorView()
} else if let content {
    ContentView()
}
// Flash possible between state transitions
```

**GOOD:** Enum state with associated values
```swift
enum LoadState {
    case loading
    case error(Error)
    case loaded(Content)
}

switch state {
case .loading: ProgressView()
case .error(let e): ErrorView(e)
case .loaded(let c): ContentView(c)
}
```

### 3. AVPlayer Setup Flash
**BAD:** Player layer visible before ready
```swift
VideoPlayer(player: AVPlayer(url: url))  // Black frame initially
```

**GOOD:** Wait for ready state
```swift
@State private var isReady = false

VideoPlayer(player: player)
    .opacity(isReady ? 1 : 0)
    .onReceive(player.publisher(for: \.status)) { status in
        isReady = status == .readyToPlay
    }
```

### 4. View Identity Changes
**BAD:** Different view types causing full re-render
```swift
if isLoaded {
    LoadedCard()  // Different view type
} else {
    PlaceholderCard()  // Different view type
}
```

**GOOD:** Same view structure, opacity/transition changes
```swift
ZStack {
    LoadedCard().opacity(isLoaded ? 1 : 0)
    PlaceholderCard().opacity(isLoaded ? 0 : 1)
}
```

## Investigation Commands

```bash
# Read target files
cat Catbird/Catbird/Features/Media/Views/ModernVideoPlayerView.swift
cat Catbird/Catbird/Features/Feed/Views/PlayerLayerView.swift
cat Catbird/Catbird/Features/Feed/Views/Components/ExternalEmbedView.swift

# Check for async image patterns
grep -n "AsyncImage\|onSuccess\|placeholder" Catbird/Catbird/Features/Feed/Views/Components/ExternalEmbedView.swift

# Check for state transitions
grep -n "isLoading\|isLoaded\|if let.*=" Catbird/Catbird/Features/Feed/Views/Components/ExternalEmbedView.swift

# Check AVPlayer setup
grep -n "AVPlayer\|VideoPlayer\|playerLayer" Catbird/Catbird/Features/Media/Views/ModernVideoPlayerView.swift
```

## Specific Patterns to Look For

### ExternalEmbedView.swift
- Link card async image loading
- Placeholder → image transition
- Multiple state booleans vs enum
- Missing `.transition()` or `.animation()`

### ModernVideoPlayerView.swift
- AVPlayer creation timing
- Player layer attachment
- Ready-to-play state handling
- Black frame flash before playback

### PlayerLayerView.swift
- UIViewRepresentable lifecycle
- CALayer async setup
- Player assignment timing

## Subagent Tasks

### Task 1: ExternalEmbedView Flash Analysis
- Identify async image loading pattern
- Check for placeholder → content flash
- Look for state machine issues
- Propose transition/animation fix

### Task 2: Video Player Lifecycle Audit
- Check AVPlayer setup timing
- Verify ready state before showing
- Check for black frame flash
- Propose loading state overlay

### Task 3: PlayerLayerView Bridge Audit
- Check UIViewRepresentable lifecycle
- Verify layer attachment timing
- Look for async setup races

## Expected Output

Report containing:
- Root cause of flashing (which pattern)
- Specific line numbers in each file
- Proposed fix with code diff
- Animation/transition recommendations

</tmp/video_player_flash_investigation.md>
<tool_guidelines description="How to use available tools effectively. Reference when uncertain about tool capabilities or parameters.">
AVAILABLE TOOLS:

1. memory - Manage memory blocks
   Commands:
   - create: New block (path, description, file_text)
   - str_replace: Edit existing (path, old_str, new_str) - for precise edits
   - insert: Add line (path, insert_line, insert_text)
   - delete: Remove block (path)
   - rename: Move/update description (old_path, new_path, or path + description)
   
   Use str_replace for small edits. Use memory_rethink for major rewrites.

2. memory_rethink - Rewrite entire block
   Parameters: label, new_memory
   Use when: reorganizing, condensing, or major structural changes
   Don't use for: adding a single line, fixing a typo

3. conversation_search - Search ALL past messages (cross-session)
   Parameters: query, limit, roles (filter by user/assistant/tool), start_date, end_date
   Returns: timestamped messages with relevance scores
   IMPORTANT: Searches every message ever sent to this agent across ALL Claude Code sessions
   Use when: detecting patterns across sessions, finding recurring issues, recalling past solutions
   This is powerful for cross-session context that wouldn't be visible in any single transcript

4. web_search - Search the web (Exa-powered)
   Parameters: query, num_results, category, include_domains, exclude_domains, date filters
   Categories: company, research paper, news, pdf, github, tweet, personal site, linkedin, financial report
   Use when: need external information, documentation, current events

5. fetch_webpage - Get page content as markdown
   Parameters: url
   Use when: need full content from a specific URL found via search

USAGE PATTERNS:

Finding information:
1. conversation_search first (check if already discussed)
2. web_search if external info needed
3. fetch_webpage for deep dives on specific pages

Memory updates:
- Single fact → str_replace or insert
- Multiple related changes → memory_rethink
- New topic area → create new block
- Stale block → delete or consolidate
</tool_guidelines>
<user_preferences description="Learned coding style, tool preferences, and communication style. Updated from observed corrections and explicit statements.">
(No user preferences yet. Populated as sessions reveal coding style, tool choices, and communication preferences.)
</user_preferences>
</letta_memory_blocks>
</letta>

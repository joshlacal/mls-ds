# Deep Research: ATProto Lexicon Alignment & Type-Safe Code Generation

**Date:** 2025-10-22  
**Project:** Catbird MLS - Private Group Chat with AT Protocol Identity  
**Repository:** https://github.com/joshlacalamito/mls  
**Status:** Production-ready server with client integration issues

---

## Current Project Status

### What's Working ✅
- **MLS Server**: Fully functional Rust server implementing Message Layer Security (MLS) protocol
- **AT Protocol Integration**: DID-based authentication, JWT tokens, XRPC endpoints
- **Database**: PostgreSQL with proper migrations and schema
- **Deployment**: Running at `https://inkcap.us-east.host.bsky.network`
- **Custom Lexicons**: 10 lexicon definitions for MLS operations under `blue.catbird.mls.*`
- **Core Features**: Create conversations, send messages, manage members, key packages

### Current Issues 🔴
1. **Type Mismatch Error**: Swift client failing to decode server responses
   ```
   Expected to decode Dictionary<String, Any> but found a string instead
   Context: conversations[0].metadata.name
   ```

2. **Lexicon-Code Misalignment**: 
   - Server uses hand-written Rust models (`server/src/models.rs`)
   - Swift client expects types matching lexicon definitions
   - No automated code generation from lexicons
   - Inconsistent field naming and structure

3. **atrium-codegen Compatibility**: 
   - Attempted to use atrium-rs codegen tool
   - Errors on `ref` types in certain contexts
   - Our lexicons may not follow atrium's expected patterns

### Project Structure
```
mls/
├── lexicon/blue/catbird/mls/          # 10 custom lexicon JSON files
│   ├── blue.catbird.mls.defs.json
│   ├── blue.catbird.mls.createConvo.json
│   ├── blue.catbird.mls.getConvos.json
│   └── ... (7 more)
├── server/src/
│   ├── models.rs                       # Hand-written models (1,940 LOC)
│   ├── handlers/*.rs                   # XRPC endpoint handlers
│   ├── auth.rs                         # JWT/DID authentication
│   └── lexicon_types.rs                # Manual lexicon types (just created)
├── mls-ffi/                            # Swift FFI bridge (not in use yet)
└── Cargo.toml                          # Workspace with atrium deps added
```

---

## Research Objectives

### 1. **ATProto Lexicon Best Practices**
**Goal**: Ensure our lexicons follow official AT Protocol standards

**Research Questions:**
- What are the canonical patterns for AT Protocol lexicon definitions?
- How do official lexicons (app.bsky, chat.bsky) structure their types?
- What are the rules for using `ref` types vs inline objects?
- How should custom namespaces (blue.catbird) be structured?
- What's the proper way to define metadata objects with optional fields?

**Resources:**
- AT Protocol Specification: https://atproto.com/specs/lexicon
- Official Lexicons: https://github.com/bluesky-social/atproto/tree/main/lexicons
- chat.bsky lexicons specifically (similar to our use case)
- Lexicon validation tools

**Deliverable**: Document of lexicon best practices with specific fixes needed for our 10 lexicons

---

### 2. **atrium-codegen Deep Dive**
**Goal**: Successfully generate type-safe Rust code from our lexicons

**Research Questions:**
- How does atrium-codegen work internally?
- What lexicon patterns does it expect vs reject?
- Why is it failing on our `ref` types?
- What's the difference between `type: "ref"` in items vs properties?
- Can we configure codegen to handle our patterns?
- Are there alternative Rust lexicon codegen tools?

**Resources:**
- atrium-rs repository: https://github.com/atrium-rs/atrium
- atrium-codegen source: https://github.com/atrium-rs/atrium/tree/main/lexicon/atrium-codegen
- atrium-lex parser: https://github.com/atrium-rs/atrium/tree/main/lexicon/atrium-lex
- lexgen tool usage and examples
- Official atrium-api generated code as reference

**Specific Investigation:**
```bash
# Our error:
Error: Error("unknown variant `ref`, expected one of `boolean`, `integer`, 
`string`, `unknown`, `array`", line: 65, column: 3)

# Context: blue.catbird.mls.createConvo.json line 65
"output": {
  "encoding": "application/json",
  "schema": {
    "type": "ref",              # ← This is causing the error
    "ref": "blue.catbird.mls.defs#convoView"
  }
}
```

**Deliverable**: 
- Working atrium-codegen configuration
- Fixed lexicons that generate successfully
- Generated Rust types in `server/src/generated/`

---

### 3. **Swift Client Alignment**
**Goal**: Understand how Swift client generates/uses types from lexicons

**Research Questions:**
- How does the Swift code generator work? (User mentioned they have one)
- What's the exact mismatch between Swift expectations and our server output?
- How are AT Protocol Swift clients typically structured?
- Are there existing Swift AT Protocol SDKs we should align with?
- Should we use ATProtoKit, atproto-swift, or custom generation?

**Investigation Steps:**
1. Analyze the exact JSON the server is returning:
   ```bash
   curl -X GET https://inkcap.us-east.host.bsky.network/xrpc/blue.catbird.mls.getConvos \
     -H "Authorization: Bearer <token>"
   ```

2. Compare with Swift client's expected structure

3. Identify all type mismatches:
   - `metadata.name` as string vs Dictionary
   - Any other field structure differences
   - Date format handling
   - Optional vs required fields

**Resources:**
- ATProtoKit: https://github.com/MasterJ93/ATProtoKit
- Official Bluesky iOS app (if open source)
- Swift Codable best practices for AT Protocol
- User's Swift code generator (request access/documentation)

**Deliverable**: 
- Documented list of all type mismatches
- Swift code generation strategy
- Either fix server or regenerate Swift client

---

### 4. **End-to-End Type Safety Strategy**
**Goal**: Establish workflow where lexicons are single source of truth

**Desired Workflow:**
```
lexicon/*.json (source of truth)
       ↓
   [validate]
       ↓
   ├─→ [atrium-codegen] → server/src/generated/*.rs
   └─→ [swift-codegen]  → SwiftClient/Generated/*.swift
       ↓
   [compile & test]
       ↓
   ✅ Server and client guaranteed to match
```

**Research Questions:**
- How do other AT Protocol services handle this?
- Should lexicons be in a separate repo/package?
- How to version lexicons and coordinate breaking changes?
- Testing strategy to catch mismatches early?
- CI/CD integration for code generation?

**Implementation Plan:**
1. Fix lexicons to be codegen-compatible
2. Generate Rust types → replace `models.rs`
3. Generate Swift types → regenerate client
4. Add integration tests that validate JSON responses
5. Document the workflow

**Deliverable**: Complete type-safety implementation guide

---

## Critical Files to Analyze

### Server Side
1. **Lexicons** (fix these first):
   - `/home/ubuntu/mls/lexicon/blue/catbird/mls/*.json`
   - Focus on: `defs.json`, `createConvo.json`, `getConvos.json`

2. **Current Models** (to be replaced):
   - `/home/ubuntu/mls/server/src/models.rs`
   - Compare with lexicon definitions

3. **Handlers** (may need updates):
   - `/home/ubuntu/mls/server/src/handlers/get_convos.rs`
   - `/home/ubuntu/mls/server/src/handlers/create_convo.rs`

### Reference Implementations
1. **Official AT Proto Lexicons**:
   ```bash
   git clone https://github.com/bluesky-social/atproto.git
   # Analyze: lexicons/chat/bsky/*.json
   ```

2. **atrium-api Generated Code**:
   ```bash
   # Study how atrium generates its own API types
   https://github.com/atrium-rs/atrium/tree/main/atrium-api/src
   ```

3. **Existing Swift AT Proto Clients**:
   - Find open-source examples
   - Study their type generation approach

---

## Immediate Action Items

### Phase 1: Lexicon Fixes (Priority 1)
- [ ] Study official AT Protocol lexicon patterns
- [ ] Identify all issues in our 10 lexicons
- [ ] Fix `ref` usage patterns
- [ ] Ensure `metadata` structure matches spec
- [ ] Validate with atrium-lex parser

### Phase 2: Rust Codegen (Priority 1)
- [ ] Get atrium-codegen working on our lexicons
- [ ] Generate types to `server/src/generated/`
- [ ] Update handlers to use generated types
- [ ] Remove old `models.rs` types
- [ ] Test server endpoints

### Phase 3: Swift Alignment (Priority 2)
- [ ] Get access to user's Swift code generator
- [ ] Regenerate Swift client from fixed lexicons
- [ ] Test against server
- [ ] Verify type safety

### Phase 4: Documentation (Priority 2)
- [ ] Document lexicon development workflow
- [ ] Add CI checks for lexicon validation
- [ ] Create type-safety testing guide
- [ ] Update project README

---

## Success Criteria

✅ **Lexicons validated** against AT Protocol spec  
✅ **atrium-codegen** generates Rust types successfully  
✅ **Server handlers** use generated types  
✅ **Swift client** decodes server responses without errors  
✅ **Integration tests** pass with real API calls  
✅ **Documentation** complete for maintaining type safety  

---

## Questions for Research

1. **Lexicon Patterns**:
   - Why does atrium-codegen reject `type: "ref"` in certain contexts?
   - What's the correct way to reference other definitions?
   - How should nested objects in metadata be structured?

2. **Code Generation**:
   - Can atrium-codegen be configured for custom lexicon patterns?
   - Are there preprocessing steps needed for our lexicons?
   - Should we fork atrium-codegen for custom behavior?

3. **Client Alignment**:
   - Is there a standard AT Protocol Swift SDK we should use?
   - How do other services handle custom lexicons in Swift?
   - What's the best way to share types between server and client?

4. **Maintenance**:
   - How to version lexicons as we add features?
   - How to handle breaking vs non-breaking changes?
   - What's the update process when lexicons change?

---

## Context for AI Research

This is a production MLS (Message Layer Security) group chat system integrated with AT Protocol (Bluesky) for identity. The server works, but there's a fundamental type mismatch between what the server returns and what the Swift client expects. We need to establish a workflow where lexicon JSON files are the single source of truth, and both server (Rust) and client (Swift) generate their types from these lexicons using established tools (atrium-codegen for Rust, user's generator for Swift).

The core problem is that we hand-wrote our models and they don't exactly match our lexicon definitions, which causes deserialization failures in the client. We want to use industry-standard tools (atrium-codegen) but it's rejecting our lexicons, suggesting our lexicons may not follow AT Protocol conventions correctly.

**Budget**: Take as much time needed to deeply research AT Protocol lexicon standards, atrium's code generation approach, and Swift client generation strategies. Provide comprehensive findings with specific actionable fixes.

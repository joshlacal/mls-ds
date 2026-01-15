# Atrium Codegen Setup Complete ✅

## What Was Done

### 1. Fixed Lexicon Schema for Union Types
- **Problem**: Union types in lexicons must be wrapped in an object property - they can't be top-level defs
- **Solution**: Wrapped the SSE event union in an `eventWrapper` object with an `event` property
- **Pattern**: `query` with `text/event-stream` output (not `subscription` - that's for WebSocket)
- **File**: `lexicon/blue/catbird/mls/blue.catbird.mls.subscribeConvoEvents.json`

```json
{
  "output": {
    "encoding": "text/event-stream",
    "schema": { "type": "ref", "ref": "#eventWrapper" }
  }
},
"eventWrapper": {
  "type": "object",
  "required": ["event"],
  "properties": {
    "event": {
      "type": "union",
      "refs": ["#messageEvent", "#reactionEvent", ...]
    }
  }
}
```

### 2. Set Up Atrium Codegen Tool
Created a dedicated codegen workspace member:
```
codegen/
├── Cargo.toml          # Depends on atrium-codegen from git
└── src/main.rs         # CLI tool to generate types
```

**Usage**:
```bash
cargo run -p mls-codegen -- \
  --lexdir /path/to/lexicon \
  --outdir /path/to/output
```

### 3. Generated Types Successfully
The codegen tool generated **34 files** from your 27 lexicon schemas:

#### Generated Structure:
```
server/src/generated/
├── blue/
│   └── catbird/
│       ├── mls/
│       │   ├── defs.rs                    # Shared types (ConvoView, MemberView, etc.)
│       │   ├── message/
│       │   │   └── defs.rs                # Message payload types
│       │   ├── add_members.rs             # blue.catbird.mls.addMembers
│       │   ├── create_convo.rs            # blue.catbird.mls.createConvo
│       │   ├── send_message.rs            # blue.catbird.mls.sendMessage
│       │   ├── subscribe_convo_events.rs     # SSE subscription types
│       │   └── ... (28 endpoint modules)
│       ├── mls.rs
│       └── catbird.rs
│   └── blue.rs
└── generated.rs  # Module exports

## Key Features of Generated Code

### Type Safety
- All input/output types from lexicons are now Rust structs
- Uses atrium's type system (`types::Object<T>`, `types::string::Did`, etc.)
- Proper serialization with `serde`

### What's Included
- ✅ 27 XRPC endpoint definitions (queries, procedures, subscription)
- ✅ Shared type definitions (`ConvoView`, `MemberView`, `MessageView`)
- ✅ Message payload types (embeds, admin actions, etc.)
- ✅ All error types from lexicons
- ✅ Union types for SSE events (subscription messages)
- ✅ Proper ATProto `bytes` handling with `crate::atproto_bytes` (`{"$bytes":"..."}`)

### Example Generated Types

```rust
// From blue.catbird.mls.defs
pub struct ConvoViewData {
    pub id: String,
    pub group_id: String,
    pub creator: types::string::Did,
    pub members: Vec<MemberView>,
    pub epoch: usize,
    pub cipher_suite: String,
    pub created_at: types::string::Datetime,
    // ...
}

// From blue.catbird.mls.createConvo
pub struct InputData {
    pub group_id: String,
    pub cipher_suite: String,
    pub initial_members: Option<Vec<Did>>,
    pub welcome_message: Option<String>,
    // ...
}
```

## Integration with Server

The generated types are exposed in `server/src/lib.rs`:

```rust
// Re-export atrium types
pub use atrium_api::types;

// Generated types module
pub mod generated;
```

## Keeping Types in Sync

When you update lexicons, regenerate types:

```bash
cd /path/to/mls
cargo run -p mls-codegen
```

The generated files include `@generated` markers indicating they're auto-generated and shouldn't be manually edited.

## Why This Works Better Than Manual Types

**atrium-codegen:**
- ✅ Handles all AT Protocol lexicon features (unions, refs, bytes, etc.)
- ✅ Generates proper serde attributes
- ✅ Includes NSID constants for each endpoint
- ✅ Validates lexicon schemas during generation
- ✅ Consistent with AT Protocol ecosystem
- ✅ Auto-updates when lexicons change

**Manual types:**
- ❌ Easy to get out of sync with lexicons
- ❌ Tedious to maintain for 27+ schemas
- ❌ Error-prone (field names, types, validation)

## Next Steps

1. **Update handlers** to use the generated types instead of manually-defined types
2. **Remove old `generated_types.rs`** (replaced by atrium-codegen output)
3. **Add codegen to CI/CD** to validate lexicons compile
4. **Document** the mapping between generated types and database models

## Troubleshooting

### Codegen fails with union errors
- **Error**: `not implemented: Union`
  - **Fix**: Unions must be wrapped in object properties, not used as top-level defs
- **Error**: `unknown variant 'union'`
  - **Fix**: Union type can only be used within property definitions
- Remember:
  - `query` + `text/event-stream` = Server-Sent Events (SSE)
  - `subscription` + `message` = WebSocket streaming

### Types don't compile
- Ensure `atrium-api` is in dependencies
- Re-export `atrium_api::types` at crate root
- Check for naming conflicts with Rust keywords

### Need to modify generated types
- **Don't!** Edit the lexicon schemas instead, then regenerate
- Use newtype wrappers if you need custom behavior

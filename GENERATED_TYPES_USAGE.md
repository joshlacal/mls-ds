# Using Generated Types from Atrium Codegen

## Quick Reference

All generated types are in `server/src/generated/blue/catbird/mls/`

### Importing Types

```rust
// Shared definitions (ConvoView, MemberView, MessageView, etc.)
use crate::generated::blue::catbird::mls::defs::*;

// Endpoint-specific types
use crate::generated::blue::catbird::mls::create_convo::{Input, Output};
use crate::generated::blue::catbird::mls::send_message;
use crate::generated::blue::catbird::mls::stream_convo_events;
```

## Working with Generated Types

### Basic Endpoint Types

Each endpoint has:
- `Input` or `Parameters` - Request data
- `Output` - Response data
- `Error` - Error enum (if defined in lexicon)
- `NSID` - Constant with the endpoint identifier

```rust
use crate::generated::blue::catbird::mls::send_message;

async fn send_message_handler(
    input: send_message::Input,
) -> Result<send_message::Output, StatusCode> {
    // Access the underlying data with .data
    let data = input.data;

    // Use fields from the generated struct
    let convo_id = data.convo_id;
    let ciphertext = data.ciphertext; // Vec<u8>
    let epoch = data.epoch; // usize

    // ... handler logic

    Ok(send_message::Output::from(send_message::OutputData {
        message_id: msg_id.to_string(),
        sender: sender_did,
        received_at: chrono::Utc::now().into(),
    }))
}
```

### Working with Shared Types

```rust
use crate::generated::blue::catbird::mls::defs::*;

fn build_convo_response(convo: &Conversation) -> ConvoView {
    ConvoView::from(ConvoViewData {
        id: convo.id.clone(),
        group_id: convo.group_id.clone(),
        creator: convo.creator.parse().unwrap(),
        members: vec![],
        epoch: convo.epoch as usize,
        cipher_suite: convo.cipher_suite.clone(),
        created_at: convo.created_at.into(),
        last_message_at: None,
        metadata: None,
    })
}
```

### SSE Event Types (Union Pattern)

The `streamConvoEvents` endpoint demonstrates the union pattern:

```rust
use crate::generated::blue::catbird::mls::stream_convo_events::*;

async fn send_sse_event(
    event_type: &str,
    cursor: String,
) -> EventWrapper {
    let event = match event_type {
        "message" => {
            let msg_event = MessageEvent::from(MessageEventData {
                cursor: cursor.clone(),
                message: /* MessageView */,
            });
            crate::types::Union::Refs(EventWrapperEventRefs::MessageEvent(Box::new(msg_event)))
        }
        "reaction" => {
            let reaction_event = ReactionEvent::from(ReactionEventData {
                cursor: cursor.clone(),
                convo_id: "...".to_string(),
                message_id: "...".to_string(),
                did: "did:plc:xyz".parse().unwrap(),
                reaction: "❤️".to_string(),
                action: "add".to_string(),
            });
            crate::types::Union::Refs(EventWrapperEventRefs::ReactionEvent(Box::new(reaction_event)))
        }
        "typing" => {
            let typing_event = TypingEvent::from(TypingEventData {
                cursor: cursor.clone(),
                convo_id: "...".to_string(),
                did: "did:plc:xyz".parse().unwrap(),
                is_typing: true,
            });
            crate::types::Union::Refs(EventWrapperEventRefs::TypingEvent(Box::new(typing_event)))
        }
        _ => {
            let info_event = InfoEvent::from(InfoEventData {
                cursor: cursor.clone(),
                info: "Heartbeat".to_string(),
            });
            crate::types::Union::Refs(EventWrapperEventRefs::InfoEvent(Box::new(info_event)))
        }
    };

    EventWrapper::from(EventWrapperData { event })
}
```

### Serialization (for SSE)

```rust
use crate::generated::blue::catbird::mls::stream_convo_events::*;

async fn sse_handler() -> impl IntoResponse {
    let event = EventWrapper::from(EventWrapperData {
        event: crate::types::Union::Refs(
            EventWrapperEventRefs::MessageEvent(Box::new(msg_event))
        ),
    });

    // Serialize to JSON for SSE
    let json = serde_json::to_string(&event).unwrap();

    // SSE format
    format!("data: {}\n\n", json)
}
```

The serialized JSON will have the `$type` discriminator:

```json
{
  "event": {
    "$type": "blue.catbird.mls.streamConvoEvents#messageEvent",
    "cursor": "abc123",
    "message": { /* MessageView */ }
  }
}
```

## Type Conversions

### From Database Models to Generated Types

```rust
// Database model
struct DbMember {
    did: String,
    user_did: String,
    device_id: Option<String>,
    joined_at: DateTime<Utc>,
    is_admin: bool,
    // ...
}

// Convert to generated type
fn db_to_member_view(db: &DbMember) -> MemberView {
    MemberView::from(MemberViewData {
        did: db.did.parse().unwrap(), // String → Did
        user_did: db.user_did.parse().unwrap(),
        device_id: db.device_id.clone(),
        device_name: None,
        joined_at: db.joined_at.into(), // DateTime<Utc> → Datetime
        is_admin: db.is_admin,
        leaf_index: None,
        credential: None,
        promoted_at: None,
        promoted_by: None,
    })
}
```

### Atrium Type Wrappers

Generated types use `atrium_api::types` wrappers:

- `types::Object<T>` - Wraps object data with `.data` field
- `types::string::Did` - DID string with validation
- `types::string::Datetime` - RFC3339 datetime string
- `types::Union<T>` - Tagged union for variant types

Access the underlying data:

```rust
let input: CreateConvoInput = /* ... */;
let data: &CreateConvoInputData = &input.data;
let group_id: &String = &data.group_id;
```

## Error Handling

```rust
use crate::generated::blue::catbird::mls::create_convo;

match handler().await {
    Ok(output) => {
        let json = serde_json::to_vec(&output)?;
        Ok(Response::new(json.into()))
    }
    Err(e) => {
        // Use generated error type if defined
        let error = create_convo::Error::ConvoExists;
        Err((StatusCode::CONFLICT, serde_json::to_string(&error)?))
    }
}
```

## Best Practices

1. **Don't modify generated files** - They have `@generated` markers
2. **Use `.data` to access** - Generated types are wrapped in `Object<T>`
3. **Convert early** - Parse database models to generated types at the boundary
4. **Type aliases** - Create type aliases for commonly used generated types:

```rust
pub type MlsConvoView = crate::generated::blue::catbird::mls::defs::ConvoView;
pub type MlsMemberView = crate::generated::blue::catbird::mls::defs::MemberView;
```

5. **Regenerate after lexicon changes**:

```bash
cargo run -p mls-codegen
```

## Common Patterns

### Optional Fields

```rust
// Lexicon: "optional: true"
// Generated: Option<T>
#[serde(skip_serializing_if = "Option::is_none")]
pub metadata: Option<ConvoMetadata>,
```

### Arrays

```rust
// Lexicon: type: "array", items: { type: "ref", ref: "#member" }
// Generated: Vec<T>
pub members: Vec<MemberView>,
```

### Bytes

```rust
// Lexicon: type: "bytes"
// Generated: Vec<u8> with serde_bytes
#[serde(with = "serde_bytes")]
pub ciphertext: Vec<u8>,
```

### Known Values

```rust
// Lexicon: knownValues: ["add", "remove"]
// Generated: String (not enum, for extensibility)
pub action: String, // Client should validate
```

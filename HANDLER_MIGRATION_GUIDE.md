# Handler Migration Guide: Using Generated Types

## Migration Pattern

### Before (Old)
```rust
use crate::models::{ConvoView, CreateConvoInput};

pub async fn create_convo(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<CreateConvoInput>,
) -> Result<Json<ConvoView>, StatusCode> {
    // ...
}
```

### After (Generated Types)
```rust
use crate::generated::blue::catbird::mls::create_convo::{Input, NSID};
use crate::generated::blue::catbird::mls::defs::ConvoView;
use crate::models; // Database models

pub async fn create_convo(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<ConvoView>, StatusCode> {
    let input = input.data; // Unwrap Object<InputData> -> InputData
    // Now use input.group_id, input.cipher_suite, etc.
    // ...
}
```

## Import Mapping

| Old Import | New Import |
|------------|-----------|
| `models::CreateConvoInput` | `generated::blue::catbird::mls::create_convo::Input` |
| `models::ConvoView` | `generated::blue::catbird::mls::defs::ConvoView` |
| `models::MemberView` | `generated::blue::catbird::mls::defs::MemberView` |
| `models::MessageView` | `generated::blue::catbird::mls::defs::MessageView` |
| `models::AddMembersInput` | `generated::blue::catbird::mls::add_members::Input` |
| `models::SendMessageInput` | `generated::blue::catbird::mls::send_message::Input` |

## Handler-by-Handler Checklist

### ✅ `create_convo.rs`
```rust
// OLD imports
use crate::models::{ConvoView, CreateConvoInput};

// NEW imports
use crate::generated::blue::catbird::mls::create_convo::{Input, NSID};
use crate::generated::blue::catbird::mls::defs::{ConvoView, ConvoMetadata, ConvoMetadataData};
use crate::models; // For database models only

// Signature change
Json(input): Json<Input>  // Not CreateConvoInput

// Access data
let input = input.data;  // Unwrap Object wrapper
```

### `add_members.rs`
```rust
// OLD
use crate::models::{AddMembersInput, AddMembersOutput};

// NEW
use crate::generated::blue::catbird::mls::add_members::{Input, Output, OutputData};

// Response
Ok(Json(Output::from(OutputData {
    success: true,
    new_epoch: new_epoch as usize,
})))
```

### `send_message.rs`
```rust
// OLD
use crate::models::{SendMessageInput, SendMessageOutput};

// NEW
use crate::generated::blue::catbird::mls::send_message::{Input, Output, OutputData};
use crate::sqlx_atrium::chrono_to_datetime;

// Response
Ok(Json(Output::from(OutputData {
    message_id: msg_id,
    sender: auth_user.did.parse().unwrap(),
    received_at: chrono_to_datetime(chrono::Utc::now()),
})))
```

### `get_messages.rs`
```rust
// OLD
use crate::models::MessageView;

// NEW
use crate::generated::blue::catbird::mls::get_messages::{Parameters, Output, OutputData};
use crate::generated::blue::catbird::mls::defs::MessageView;

// Convert DB messages to API
let messages: Vec<MessageView> = db_messages
    .iter()
    .map(|m| m.to_message_view())
    .collect();

Ok(Json(Output::from(OutputData {
    messages,
    cursor: None,
})))
```

### `get_convos.rs`
```rust
// OLD
use crate::models::ConvoView;

// NEW
use crate::generated::blue::catbird::mls::get_convos::{Parameters, Output, OutputData};
use crate::generated::blue::catbird::mls::defs::ConvoView;

// Convert with members
let convos: Vec<ConvoView> = db_convos
    .into_iter()
    .map(|c| {
        let members = fetch_members(&pool, &c.id).await?;
        let member_views: Vec<MemberView> = members.iter().map(|m| m.to_member_view()).collect();
        Ok(c.to_convo_view(member_views))
    })
    .collect::<Result<Vec<_>, _>>()?;

Ok(Json(Output::from(OutputData {
    conversations: convos,
    cursor: None,
})))
```

### `publish_key_package.rs`
```rust
// OLD
use crate::models::PublishKeyPackageInput;

// NEW
use crate::generated::blue::catbird::mls::publish_key_package::{Input, Output, OutputData};
use crate::sqlx_atrium::datetime_to_chrono;

// Access input
let input = input.data;
let expires_chrono = datetime_to_chrono(&input.expires);
```

### `get_key_packages.rs`
```rust
// OLD
use crate::models::KeyPackageInfo;

// NEW
use crate::generated::blue::catbird::mls::get_key_packages::{Parameters, Output, OutputData};
use crate::generated::blue::catbird::mls::defs::KeyPackageRef;

// Convert DB to API
let key_packages: Vec<KeyPackageRef> = db_packages
    .iter()
    .map(|kp| kp.to_key_package_ref())
    .collect();

Ok(Json(Output::from(OutputData {
    key_packages,
    missing: Some(missing_dids),
})))
```

### `leave_convo.rs`
```rust
// OLD
use crate::models::{LeaveConvoInput, LeaveConvoOutput};

// NEW
use crate::generated::blue::catbird::mls::leave_convo::{Input, Output, OutputData};
```

### `get_welcome.rs`
```rust
// OLD
use crate::models::GetWelcomeOutput;

// NEW
use crate::generated::blue::catbird::mls::get_welcome::{Parameters, Output, OutputData};
```

## Common Patterns

### 1. Unwrapping Input
```rust
// Generated types use Object<T> wrapper
Json(input): Json<Input>
let input = input.data;  // Get the actual InputData struct
```

### 2. Creating Output
```rust
// Use from() with the Data struct
Ok(Json(Output::from(OutputData {
    field1: value1,
    field2: value2,
})))
```

### 3. DID Conversion
```rust
// String to Did
let did: Did = "did:plc:xyz".parse().unwrap();

// Did to String (for database)
let did_str = did.as_str();
```

### 4. Datetime Conversion
```rust
use crate::sqlx_atrium::{chrono_to_datetime, datetime_to_chrono};

// Chrono to Atrium
let atrium_dt = chrono_to_datetime(chrono::Utc::now());

// Atrium to Chrono
let chrono_dt = datetime_to_chrono(&input.expires);
```

### 5. Database Model to API View
```rust
// Conversation
let convo_view = db_convo.to_convo_view(member_views);

// Member
let member_view = db_member.to_member_view();

// Message
let message_view = db_message.to_message_view();

// KeyPackage
let key_package_ref = db_kp.to_key_package_ref();
```

## Testing After Migration

1. **Compile**: `cargo check --lib`
2. **Test handler**: `cargo test --test integration_test -- create_convo`
3. **Manual test**: `curl -X POST http://localhost:3000/xrpc/blue.catbird.mls.createConvo`

## Validation Checklist

- [ ] All old `models::*Input` imports removed
- [ ] All old `models::*Output` imports removed
- [ ] All handlers use `generated::blue::catbird::mls::*`
- [ ] Input unwrapping: `let input = input.data;`
- [ ] Output wrapping: `Output::from(OutputData { ... })`
- [ ] DID types use `.parse()` or `.as_str()`
- [ ] Datetime conversions use `sqlx_atrium` helpers
- [ ] Database models converted via `.to_*_view()` methods
- [ ] `cargo check` passes
- [ ] Integration tests pass

# Database Quick Reference

## Setup

```bash
# Set environment variable
export DATABASE_URL=postgres://localhost/catbird

# Run migrations
sqlx migrate run

# Or let the server run them automatically
cargo run
```

## Initialize in Code

```rust
use catbird_server::db::*;

// Default config (reads DATABASE_URL env var)
let pool = init_db_default().await?;

// Custom config
let pool = init_db(DbConfig {
    database_url: "postgres://localhost/catbird".to_string(),
    max_connections: 10,
    ..Default::default()
}).await?;
```

## Common Operations

### Conversations

```rust
// Create
let convo = create_conversation(&pool, creator_did, title).await?;

// Get
let convo = get_conversation(&pool, convo_id).await?;

// List user's conversations
let convos = list_conversations(&pool, user_did, 20, 0).await?;

// Update epoch
update_conversation_epoch(&pool, convo_id, new_epoch).await?;
```

### Members

```rust
// Add
add_member(&pool, convo_id, member_did).await?;

// Remove
remove_member(&pool, convo_id, member_did).await?;

// Check
if is_member(&pool, user_did, convo_id).await? { /* ... */ }

// List
let members = list_members(&pool, convo_id).await?;
```

### Messages

```rust
// Create
let msg = create_message(&pool, convo_id, sender_did, "app", epoch, ciphertext).await?;

// List (paginated)
let msgs = list_messages(&pool, convo_id, 50, cursor).await?;

// Count
let count = get_message_count(&pool, convo_id).await?;
```

### Key Packages

```rust
// Store
store_key_package(&pool, did, cipher_suite, key_data, expires_at).await?;

// Get available
let kp = get_key_package(&pool, did, cipher_suite).await?;

// Consume
consume_key_package(&pool, did, cipher_suite, &key_data).await?;

// Count
let count = count_key_packages(&pool, did, cipher_suite).await?;
```

### Blobs

```rust
// Store
let blob = store_blob(&pool, cid, data, uploader_did, Some(convo_id), Some(mime_type)).await?;

// Get
let blob = get_blob(&pool, cid).await?;

// List by conversation
let blobs = list_blobs_by_conversation(&pool, convo_id, 10).await?;
```

## Transactions

```rust
let mut tx = begin_transaction(&pool).await?;

// Do work...
sqlx::query("...").execute(&mut *tx).await?;

// Commit
tx.commit().await?;
```

## Testing

```rust
async fn setup_test_db() -> DbPool {
    let config = DbConfig {
        database_url: "postgres://localhost/catbird_test".to_string(),
        max_connections: 5,
        ..Default::default()
    };
    init_db(config).await.unwrap()
}

#[tokio::test]
async fn test_something() {
    let pool = setup_test_db().await;
    // Test...
}
```

## Error Handling

```rust
use anyhow::{Context, Result};

async fn my_function(pool: &DbPool) -> Result<()> {
    get_conversation(pool, id)
        .await
        .context("Failed to fetch conversation")?;
    Ok(())
}
```

## Common Patterns

### Check membership before action

```rust
if !is_member(&pool, user_did, convo_id).await? {
    return Err(Error::Forbidden);
}
```

### Paginated messages

```rust
let mut cursor = None;
loop {
    let page = list_messages(&pool, convo_id, 50, cursor).await?;
    if page.is_empty() { break; }
    
    // Process page...
    
    cursor = page.last().map(|m| m.sent_at);
}
```

### Create conversation with members atomically

```rust
let convo = create_conversation_with_members(
    &pool,
    creator_did,
    Some(title),
    vec![member1, member2, member3],
).await?;
```

## Indexes

All tables have optimized indexes. Common queries are fast:

- ✅ `is_member()` - O(1) lookup
- ✅ `list_messages()` - O(log n) with pagination
- ✅ `get_key_package()` - O(log n) with partial index
- ✅ `list_conversations()` - O(log n) join

## Environment Variables

```bash
DATABASE_URL=postgres://localhost/catbird          # Production
TEST_DATABASE_URL=postgres://localhost/catbird_test # Testing
```

## Migration Commands

```bash
sqlx migrate run      # Apply pending migrations
sqlx migrate revert   # Revert last migration
sqlx migrate info     # Show status
sqlx migrate add name # Create new migration
```

## Health Check

```rust
if health_check(&pool).await? {
    println!("Database OK");
}
```

## Documentation

- [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) - Complete schema reference
- [DB_USAGE_EXAMPLES.md](DB_USAGE_EXAMPLES.md) - Detailed examples
- [DB_IMPLEMENTATION_SUMMARY.md](DB_IMPLEMENTATION_SUMMARY.md) - Implementation details
- [migrations/README.md](migrations/README.md) - Migration guide

## Tips

1. Reuse the pool - don't create multiple pools
2. Use transactions for multi-step operations
3. Always paginate large result sets
4. Run `delete_expired_key_packages()` periodically
5. Monitor connection pool with logs
6. Use `.context()` for better error messages

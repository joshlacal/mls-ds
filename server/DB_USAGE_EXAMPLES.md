# Database Usage Examples

## Quick Start

```rust
use catbird_server::db::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize with default configuration
    let pool = init_db_default().await?;
    
    // Or with custom configuration
    let config = DbConfig {
        database_url: "postgres://localhost/catbird".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };
    let pool = init_db(config).await?;
    
    Ok(())
}
```

## Conversation Operations

### Create a Conversation

```rust
use catbird_server::db::*;

let conversation = create_conversation(
    &pool,
    "did:plc:creator123",
    Some("My Group Chat".to_string())
).await?;

println!("Created conversation: {}", conversation.id);
```

### Create Conversation with Members (Transaction)

```rust
let conversation = create_conversation_with_members(
    &pool,
    "did:plc:creator",
    Some("Team Chat".to_string()),
    vec![
        "did:plc:alice".to_string(),
        "did:plc:bob".to_string(),
        "did:plc:charlie".to_string(),
    ],
).await?;
```

### Get Conversation

```rust
if let Some(convo) = get_conversation(&pool, "convo_id_here").await? {
    println!("Found: {}", convo.title.unwrap_or_default());
}
```

### List User's Conversations

```rust
let conversations = list_conversations(&pool, "did:plc:user", 20, 0).await?;
for convo in conversations {
    println!("- {} (epoch: {})", convo.id, convo.current_epoch);
}
```

### Update Epoch

```rust
update_conversation_epoch(&pool, "convo_id", 5).await?;
let epoch = get_current_epoch(&pool, "convo_id").await?;
```

## Member Operations

### Add Member

```rust
let membership = add_member(&pool, "convo_id", "did:plc:newuser").await?;
println!("Added at: {}", membership.joined_at);
```

### Remove Member (Soft Delete)

```rust
remove_member(&pool, "convo_id", "did:plc:user").await?;
```

### Check Membership

```rust
if is_member(&pool, "did:plc:user", "convo_id").await? {
    println!("User is a member!");
}
```

### List Members

```rust
let members = list_members(&pool, "convo_id").await?;
for member in members {
    println!("- {} (unread: {})", member.member_did, member.unread_count);
}
```

### Manage Unread Count

```rust
// Increment unread count
update_unread_count(&pool, "convo_id", "did:plc:user", 1).await?;

// Reset to zero
reset_unread_count(&pool, "convo_id", "did:plc:user").await?;
```

## Message Operations

### Create Message

```rust
let ciphertext = vec![1, 2, 3, 4]; // Encrypted data

let message = create_message(
    &pool,
    "convo_id",
    "did:plc:sender",
    "app",  // or "commit"
    0,      // epoch
    ciphertext,
).await?;

println!("Message ID: {}", message.id);
```

### List Messages with Pagination

```rust
// First page
let messages = list_messages(&pool, "convo_id", 50, None).await?;

// Next page using cursor
if let Some(last_msg) = messages.last() {
    let next_page = list_messages(&pool, "convo_id", 50, Some(last_msg.sent_at)).await?;
}
```

### List Messages Since Time

```rust
use chrono::{Utc, Duration};

let since = Utc::now() - Duration::hours(24);
let recent = list_messages_since(&pool, "convo_id", since).await?;
```

### Get Message Count

```rust
let count = get_message_count(&pool, "convo_id").await?;
println!("Total messages: {}", count);
```

## Key Package Operations

### Store Key Package

```rust
use chrono::{Utc, Duration};

let key_data = vec![/* serialized key package */];
let expires_at = Utc::now() + Duration::days(30);

store_key_package(
    &pool,
    "did:plc:user",
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    key_data,
    expires_at,
).await?;
```

### Get Available Key Package

```rust
if let Some(kp) = get_key_package(&pool, "did:plc:user", cipher_suite).await? {
    println!("Found key package, size: {} bytes", kp.key_data.len());
    
    // Use the key package...
    
    // Mark as consumed
    consume_key_package(&pool, &kp.did, &kp.cipher_suite, &kp.key_data).await?;
}
```

### Count Available Key Packages

```rust
let count = count_key_packages(&pool, "did:plc:user", cipher_suite).await?;
println!("Available key packages: {}", count);
```

### Cleanup Expired Key Packages

```rust
let deleted = delete_expired_key_packages(&pool).await?;
println!("Deleted {} expired key packages", deleted);
```

## Blob Operations

### Store Blob

```rust
let blob_data = std::fs::read("image.png")?;
let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

let blob = store_blob(
    &pool,
    cid,
    blob_data,
    "did:plc:uploader",
    Some("convo_id"),
    Some("image/png"),
).await?;

println!("Stored blob: {} ({} bytes)", blob.cid, blob.size);
```

### Get Blob

```rust
if let Some(blob) = get_blob(&pool, cid).await? {
    std::fs::write("downloaded.png", &blob.data)?;
}
```

### List Conversation Blobs

```rust
let blobs = list_blobs_by_conversation(&pool, "convo_id", 10).await?;
for blob in blobs {
    println!("- {} ({} bytes)", blob.cid, blob.size);
}
```

### Get User Storage Size

```rust
let total_bytes = get_user_storage_size(&pool, "did:plc:user").await?;
println!("User storage: {} bytes", total_bytes);
```

## Transaction Example

```rust
use catbird_server::db::*;

async fn complex_operation(pool: &DbPool) -> anyhow::Result<()> {
    let mut tx = begin_transaction(pool).await?;
    
    // Multiple operations in transaction
    sqlx::query("INSERT INTO conversations (...) VALUES (...)")
        .execute(&mut *tx)
        .await?;
    
    sqlx::query("INSERT INTO members (...) VALUES (...)")
        .execute(&mut *tx)
        .await?;
    
    // Commit all changes atomically
    tx.commit().await?;
    
    Ok(())
}
```

## Error Handling

```rust
use anyhow::{Context, Result};

async fn handle_errors(pool: &DbPool) -> Result<()> {
    // All functions return Result with context
    let convo = get_conversation(pool, "invalid_id")
        .await
        .context("Failed to fetch conversation")?;
    
    match convo {
        Some(c) => println!("Found: {}", c.id),
        None => println!("Not found"),
    }
    
    Ok(())
}
```

## Health Check

```rust
// Check database connection
if health_check(&pool).await? {
    println!("Database is healthy");
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    async fn setup_test_db() -> DbPool {
        let config = DbConfig {
            database_url: "postgres://localhost/catbird_test".to_string(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
        };
        
        init_db(config).await.expect("Failed to init test DB")
    }
    
    #[tokio::test]
    async fn test_conversation() {
        let pool = setup_test_db().await;
        
        let convo = create_conversation(&pool, "did:plc:test", None)
            .await
            .expect("Failed to create");
        
        assert_eq!(convo.current_epoch, 0);
    }
}
```

## Environment Variables

```bash
# Production database
export DATABASE_URL=postgres://user:pass@localhost/catbird

# Test database
export TEST_DATABASE_URL=postgres://user:pass@localhost/catbird_test
```

## Connection String Examples

```rust
// Local PostgreSQL
"postgres://localhost/catbird"

// With authentication
"postgres://user:password@localhost/catbird"

// Remote with SSL
"postgres://user:password@db.example.com:5432/catbird?sslmode=require"

// With connection pool settings in URL
"postgres://localhost/catbird?max_connections=10&connect_timeout=30"
```

## Best Practices

1. **Connection Pooling**: Reuse the pool, don't create multiple pools
2. **Transactions**: Use for multi-step operations
3. **Error Handling**: Use `.context()` for better error messages
4. **Indexing**: Rely on provided indexes for optimal performance
5. **Pagination**: Use cursor-based pagination for large result sets
6. **Cleanup**: Regularly run `delete_expired_key_packages()`
7. **Testing**: Use separate test database with cleanup between tests

## Performance Tips

1. Use `list_messages()` with cursor pagination instead of offset
2. Filter on indexed columns: `convo_id`, `member_did`, `sent_at`, etc.
3. Batch operations in transactions when possible
4. Monitor connection pool usage and adjust `max_connections`
5. Use partial indexes for common filter patterns
6. Keep blob sizes reasonable (consider external storage for large files)

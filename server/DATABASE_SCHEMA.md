# Database Schema Documentation

## Overview

The Catbird MLS Server uses PostgreSQL as its primary database for storing conversations, messages, members, key packages, and blob data. This document provides comprehensive documentation of the schema design, indexing strategy, and usage patterns.

## Database Configuration

### Connection Pool Settings

```rust
DbConfig {
    database_url: "postgres://localhost/catbird",
    max_connections: 10,      // Maximum concurrent connections
    min_connections: 2,        // Minimum idle connections
    acquire_timeout: 30s,      // Timeout for acquiring a connection
    idle_timeout: 600s,        // Idle connection timeout
}
```

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string (default: `postgres://localhost/catbird`)
- `TEST_DATABASE_URL`: Test database connection string (default: `postgres://localhost/catbird_test`)

## Schema Design

### 1. Conversations Table

Stores MLS group conversation metadata.

```sql
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,                      -- UUID v4 as string
    creator_did TEXT NOT NULL,                -- DID of conversation creator
    current_epoch INTEGER NOT NULL DEFAULT 0, -- Current MLS epoch
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title TEXT                                -- Optional conversation title
);
```

**Indexes:**
- `idx_conversations_creator_did` on `creator_did` - Efficient lookup of conversations by creator
- `idx_conversations_created_at` on `created_at DESC` - Sorted conversation lists

**Constraints:**
- Primary key on `id`

**Usage Patterns:**
- Create new conversations with `create_conversation()`
- Fetch by ID with `get_conversation()`
- List user's conversations with `list_conversations()`
- Update epoch with `update_conversation_epoch()`
- Delete with `delete_conversation()` (cascades to members and messages)

---

### 2. Members Table

Tracks conversation membership with soft delete support.

```sql
CREATE TABLE members (
    convo_id TEXT NOT NULL,                  -- Reference to conversation
    member_did TEXT NOT NULL,                -- Member's DID
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,                     -- NULL = active member
    unread_count INTEGER NOT NULL DEFAULT 0,
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (convo_id, member_did),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);
```

**Indexes:**
- `idx_members_member_did` on `member_did` - Find all conversations for a user
- `idx_members_left_at` on `left_at WHERE left_at IS NULL` - Filter active members
- `idx_members_active` on `(member_did, convo_id) WHERE left_at IS NULL` - Efficient membership checks
- `idx_members_unread` on `(member_did, unread_count) WHERE unread_count > 0` - Unread message queries

**Constraints:**
- Composite primary key on `(convo_id, member_did)`
- Foreign key to `conversations` with CASCADE delete

**Usage Patterns:**
- Add member with `add_member()` (upserts and resets `left_at` if rejoining)
- Remove member with `remove_member()` (soft delete, sets `left_at`)
- Check membership with `is_member()`
- List members with `list_members()`
- Manage unread counts with `update_unread_count()` and `reset_unread_count()`

**Soft Delete Pattern:**
- Active members: `left_at IS NULL`
- Removed members: `left_at IS NOT NULL`
- Rejoining reactivates membership by setting `left_at = NULL`

---

### 3. Messages Table

Stores encrypted MLS messages and commits.

```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,                     -- UUID v4 as string
    convo_id TEXT NOT NULL,                  -- Reference to conversation
    sender_did TEXT NOT NULL,                -- Sender's DID
    message_type TEXT NOT NULL CHECK (message_type IN ('app', 'commit')),
    epoch INTEGER NOT NULL,                  -- MLS epoch number
    ciphertext BYTEA NOT NULL,               -- Encrypted message data
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE CASCADE
);
```

**Indexes:**
- `idx_messages_convo_sent` on `(convo_id, sent_at DESC)` - Message retrieval by conversation
- `idx_messages_sender` on `sender_did` - User's message history
- `idx_messages_convo_epoch` on `(convo_id, epoch)` - Epoch-based queries
- `idx_messages_pagination` on `(convo_id, sent_at DESC, id)` - Efficient pagination

**Constraints:**
- Primary key on `id`
- Foreign key to `conversations` with CASCADE delete
- Check constraint: `message_type IN ('app', 'commit')`

**Message Types:**
- `app`: Application messages (encrypted chat content)
- `commit`: MLS commit messages (group state changes)

**Usage Patterns:**
- Create message with `create_message()`
- Fetch by ID with `get_message()`
- List with pagination using `list_messages()` (cursor-based)
- Get recent messages with `list_messages_since()`
- Count messages with `get_message_count()`
- Delete with `delete_message()`

**Pagination:**
```rust
// First page
let page1 = list_messages(&pool, convo_id, 50, None).await?;

// Next page (using last message timestamp as cursor)
let cursor = page1.last().map(|m| m.sent_at);
let page2 = list_messages(&pool, convo_id, 50, cursor).await?;
```

---

### 4. Key Packages Table

Stores pre-generated MLS key packages for adding users to groups.

```sql
CREATE TABLE key_packages (
    id SERIAL PRIMARY KEY,                   -- Auto-incrementing ID
    did TEXT NOT NULL,                       -- Owner's DID
    cipher_suite TEXT NOT NULL,              -- MLS cipher suite identifier
    key_data BYTEA NOT NULL,                 -- Serialized key package
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,         -- Expiration timestamp
    consumed BOOLEAN NOT NULL DEFAULT FALSE, -- Whether package has been used
    consumed_at TIMESTAMPTZ
);
```

**Indexes:**
- `idx_key_packages_unique` on `(did, cipher_suite, key_data)` UNIQUE - Prevent duplicates
- `idx_key_packages_did_suite` on `(did, cipher_suite)` - Lookup by user and suite
- `idx_key_packages_available` on `(did, cipher_suite, expires_at) WHERE consumed = FALSE AND expires_at > NOW()` - Find available packages
- `idx_key_packages_expires` on `expires_at` - Cleanup expired packages
- `idx_key_packages_consumed` on `(consumed, consumed_at)` - Track consumption

**Constraints:**
- Primary key on `id`
- Unique constraint on `(did, cipher_suite, key_data)`

**Lifecycle:**
1. Client pre-generates key packages and uploads with `store_key_package()`
2. Server fetches oldest available package with `get_key_package()`
3. Server marks as consumed with `consume_key_package()`
4. Expired packages cleaned up with `delete_expired_key_packages()`

**Usage Patterns:**
- Store with `store_key_package()` (idempotent due to unique constraint)
- Fetch available with `get_key_package()` (FIFO - oldest first)
- Consume with `consume_key_package()`
- Count available with `count_key_packages()`
- Cleanup with `delete_expired_key_packages()`

**Cipher Suites:**
- Example: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Each user should maintain multiple key packages per cipher suite

---

### 5. Blobs Table

Stores binary data (attachments, media) with content addressing.

```sql
CREATE TABLE blobs (
    cid TEXT PRIMARY KEY,                    -- Content identifier (CID)
    data BYTEA NOT NULL,                     -- Binary blob data
    size BIGINT NOT NULL,                    -- Size in bytes
    uploaded_by_did TEXT NOT NULL,           -- Uploader's DID
    convo_id TEXT,                           -- Optional conversation reference
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mime_type TEXT,                          -- Optional MIME type
    FOREIGN KEY (convo_id) REFERENCES conversations(id) ON DELETE SET NULL
);
```

**Indexes:**
- `idx_blobs_uploaded_by` on `uploaded_by_did` - User's uploads
- `idx_blobs_convo` on `convo_id WHERE convo_id IS NOT NULL` - Conversation's blobs
- `idx_blobs_uploaded_at` on `uploaded_at DESC` - Temporal sorting
- `idx_blobs_size` on `size` - Storage analytics

**Constraints:**
- Primary key on `cid`
- Foreign key to `conversations` with SET NULL on delete

**Usage Patterns:**
- Store with `store_blob()`
- Fetch by CID with `get_blob()`
- List by conversation with `list_blobs_by_conversation()`
- Calculate user storage with `get_user_storage_size()`
- Delete with `delete_blob()`

**Content Addressing:**
- CID (Content Identifier) uniquely identifies blob content
- Typically IPFS-style CID (e.g., `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi`)
- Deduplication: same content = same CID

---

## Query Patterns & Performance

### Efficient Membership Checks

```rust
// O(1) with idx_members_active
let is_active = is_member(&pool, "did:plc:user", "convo_123").await?;
```

### Paginated Message Retrieval

```rust
// Uses idx_messages_pagination for efficient cursor-based pagination
let messages = list_messages(&pool, "convo_123", 50, None).await?;
let cursor = messages.last().map(|m| m.sent_at);
let next_page = list_messages(&pool, "convo_123", 50, cursor).await?;
```

### User's Active Conversations

```rust
// Uses idx_members_member_did + join
let conversations = list_conversations(&pool, "did:plc:user", 20, 0).await?;
```

### Available Key Package Lookup

```rust
// Uses idx_key_packages_available (partial index on available packages)
let kp = get_key_package(&pool, "did:plc:user", cipher_suite).await?;
```

---

## Transaction Support

### Atomic Operations

All operations support transactions for ACID guarantees:

```rust
// Begin transaction
let mut tx = begin_transaction(&pool).await?;

// Perform operations
sqlx::query("...").execute(&mut *tx).await?;

// Commit or rollback
tx.commit().await?;
```

### High-Level Transactional Operations

```rust
// Create conversation with members atomically
let convo = create_conversation_with_members(
    &pool,
    "did:plc:creator",
    Some("Team Chat".to_string()),
    vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()],
).await?;
```

---

## Data Integrity

### Foreign Key Constraints

1. **members.convo_id** → conversations.id (CASCADE DELETE)
   - Deleting conversation removes all memberships

2. **messages.convo_id** → conversations.id (CASCADE DELETE)
   - Deleting conversation removes all messages

3. **blobs.convo_id** → conversations.id (SET NULL)
   - Deleting conversation preserves blobs but removes association

### Check Constraints

1. **messages.message_type** ∈ {'app', 'commit'}
   - Ensures only valid message types

### Unique Constraints

1. **members (convo_id, member_did)** - One membership record per user per conversation
2. **key_packages (did, cipher_suite, key_data)** - Prevents duplicate key packages

---

## Indexing Strategy

### Composite Indexes

Used for queries filtering on multiple columns:
- `(convo_id, sent_at DESC)` - Messages by conversation, sorted by time
- `(member_did, convo_id)` - User's active conversations
- `(did, cipher_suite)` - User's key packages by suite

### Partial Indexes

Used for commonly filtered subsets:
- `WHERE left_at IS NULL` - Active members only
- `WHERE consumed = FALSE AND expires_at > NOW()` - Available key packages

### Covering Indexes

Include additional columns to avoid table lookups:
- `(convo_id, sent_at DESC, id)` - Message pagination with ID

---

## Migrations

Migrations are managed with `sqlx migrate` and located in `migrations/`:

```
migrations/
├── 20240101000001_create_conversations.sql
├── 20240101000002_create_members.sql
├── 20240101000003_create_messages.sql
├── 20240101000004_create_key_packages.sql
└── 20240101000005_create_blobs.sql
```

### Running Migrations

```bash
# Run all pending migrations
sqlx migrate run --database-url postgres://localhost/catbird

# Revert last migration
sqlx migrate revert --database-url postgres://localhost/catbird
```

### Creating New Migrations

```bash
sqlx migrate add <migration_name>
```

---

## Connection Pooling

### Pool Configuration

```rust
PgPoolOptions::new()
    .max_connections(10)      // Maximum concurrent connections
    .min_connections(2)        // Minimum idle connections
    .acquire_timeout(30s)      // Connection acquisition timeout
    .idle_timeout(600s)        // Idle connection timeout
    .connect(database_url)
    .await?
```

### Best Practices

1. **Reuse connections**: Pool handles connection lifecycle
2. **Don't hold connections**: Release quickly after operations
3. **Use transactions**: For multi-step operations
4. **Monitor pool**: Track `acquire_timeout` errors

---

## Testing

### Test Database Setup

```rust
async fn setup_test_db() -> PgPool {
    let config = DbConfig {
        database_url: "postgres://localhost/catbird_test".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };
    
    init_db(config).await.expect("Failed to init test DB")
}
```

### Running Tests

```bash
# Set test database URL
export TEST_DATABASE_URL=postgres://localhost/catbird_test

# Run all database tests
cargo test --test db_tests

# Run specific test
cargo test --test db_tests test_conversation_crud
```

### Test Coverage

- CRUD operations for all tables
- Transaction atomicity
- Pagination and cursors
- Concurrent operations
- Constraint validation
- Soft delete behavior
- Cleanup operations

---

## Performance Considerations

### Query Optimization

1. **Use indexes**: All frequent queries have supporting indexes
2. **Limit results**: Always use `LIMIT` for list operations
3. **Cursor pagination**: Use `sent_at` cursors instead of `OFFSET`
4. **Partial indexes**: Filter common predicates at index level

### Scaling Recommendations

1. **Connection pooling**: Tune pool size based on workload
2. **Read replicas**: For read-heavy workloads
3. **Partitioning**: Consider partitioning `messages` by `sent_at` for large datasets
4. **Archive old data**: Move old messages to archive tables
5. **Monitor slow queries**: Use `pg_stat_statements`

### Storage Estimates

- **Conversation**: ~200 bytes
- **Member**: ~150 bytes
- **Message**: ~500 bytes + ciphertext size
- **Key Package**: ~1KB (typical MLS key package)
- **Blob**: Variable (stored inline)

---

## Maintenance

### Cleanup Operations

```rust
// Delete expired key packages
let deleted = delete_expired_key_packages(&pool).await?;

// Archive old conversations (custom implementation)
// Move conversations older than 1 year to archive table
```

### Monitoring Queries

```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'catbird';

-- Table sizes
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables WHERE schemaname = 'public';

-- Index usage
SELECT 
    schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan;
```

---

## API Reference

### Initialization

```rust
// Default configuration
let pool = init_db_default().await?;

// Custom configuration
let config = DbConfig { /* ... */ };
let pool = init_db(config).await?;
```

### Core Operations

See inline documentation in `src/db.rs` for detailed API docs on:
- Conversation operations
- Member operations
- Message operations
- Key package operations
- Blob operations
- Transaction support

---

## Security Considerations

1. **DID Authentication**: All operations require authenticated DID
2. **Membership checks**: Verify membership before message access
3. **Blob access control**: Check conversation membership for blob access
4. **SQL injection**: All queries use parameterized statements
5. **Connection security**: Use SSL/TLS for database connections

---

## Future Enhancements

1. **Message search**: Full-text search on decrypted messages (client-side)
2. **Analytics**: Track message rates, storage usage, active users
3. **Archival**: Move old data to cheaper storage
4. **Replication**: Multi-region read replicas
5. **Sharding**: Partition by conversation ID for horizontal scaling

---

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [sqlx Documentation](https://docs.rs/sqlx/)
- [MLS Protocol RFC](https://datatracker.ietf.org/doc/html/rfc9420)
- [ATProto Specification](https://atproto.com/)

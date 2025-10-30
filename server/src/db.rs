use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

use crate::models::{Conversation, KeyPackage, Membership, Message};

pub type DbPool = PgPool;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/catbird".to_string()),
            max_connections: 10,
            min_connections: 2,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

/// Initialize database connection pool with configuration
pub async fn init_db(config: DbConfig) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .connect(&config.database_url)
        .await
        .context("Failed to connect to database")?;

    // Run migrations
    // Temporarily disabled due to migration checksum issues
    // sqlx::migrate!("./migrations")
    //     .run(&pool)
    //     .await
    //     .context("Failed to run migrations")?;

    Ok(pool)
}

/// Initialize database with default configuration
pub async fn init_db_default() -> Result<DbPool> {
    init_db(DbConfig::default()).await
}

// =============================================================================
// Conversation Operations
// =============================================================================

/// Create a new conversation
pub async fn create_conversation(
    pool: &DbPool,
    creator_did: &str,
    title: Option<String>,
) -> Result<Conversation> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let conversation = sqlx::query_as::<_, Conversation>(
        r#"
        INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name)
        VALUES ($1, $2, 0, $3, $4, $5)
        RETURNING id, creator_did, current_epoch, created_at, name as title
        "#,
    )
    .bind(&id)
    .bind(creator_did)
    .bind(now)
    .bind(now)
    .bind(title)
    .fetch_one(pool)
    .await
    .context("Failed to create conversation")?;

    Ok(conversation)
}

/// Get a conversation by ID
pub async fn get_conversation(pool: &DbPool, convo_id: &str) -> Result<Option<Conversation>> {
    let conversation = sqlx::query_as::<_, Conversation>(
        r#"
        SELECT id, creator_did, current_epoch, created_at, updated_at, name as title
        FROM conversations
        WHERE id = $1
        "#,
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch conversation")?;

    Ok(conversation)
}

/// List conversations for a user (active memberships only)
pub async fn list_conversations(
    pool: &DbPool,
    member_did: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Conversation>> {
    let conversations = sqlx::query_as::<_, Conversation>(
        r#"
        SELECT c.id, c.creator_did, c.current_epoch, c.created_at, c.updated_at, c.name as title
        FROM conversations c
        INNER JOIN members m ON c.id = m.convo_id
        WHERE m.member_did = $1 AND m.left_at IS NULL
        ORDER BY c.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(member_did)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .context("Failed to list conversations")?;

    Ok(conversations)
}

/// Update conversation epoch
pub async fn update_conversation_epoch(
    pool: &DbPool,
    convo_id: &str,
    new_epoch: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE conversations
        SET current_epoch = $1, updated_at = $2
        WHERE id = $3
        "#,
    )
    .bind(new_epoch)
    .bind(Utc::now())
    .bind(convo_id)
    .execute(pool)
    .await
    .context("Failed to update conversation epoch")?;

    Ok(())
}

/// Get current epoch for a conversation
pub async fn get_current_epoch(pool: &DbPool, convo_id: &str) -> Result<i32> {
    let epoch =
        sqlx::query_scalar::<_, i32>("SELECT current_epoch FROM conversations WHERE id = $1")
            .bind(convo_id)
            .fetch_one(pool)
            .await
            .context("Failed to get current epoch")?;

    Ok(epoch)
}

/// Delete a conversation (cascades to members and messages)
pub async fn delete_conversation(pool: &DbPool, convo_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await
        .context("Failed to delete conversation")?;

    Ok(())
}

// =============================================================================
// Member Operations
// =============================================================================

/// Add a member to a conversation
pub async fn add_member(pool: &DbPool, convo_id: &str, member_did: &str) -> Result<Membership> {
    let now = Utc::now();

    let membership = sqlx::query_as::<_, Membership>(
        r#"
        INSERT INTO members (convo_id, member_did, joined_at, unread_count)
        VALUES ($1, $2, $3, 0)
        ON CONFLICT (convo_id, member_did) 
        DO UPDATE SET left_at = NULL, joined_at = $3
        RETURNING convo_id, member_did, joined_at, left_at, unread_count
        "#,
    )
    .bind(convo_id)
    .bind(member_did)
    .bind(now)
    .fetch_one(pool)
    .await
    .context("Failed to add member")?;

    Ok(membership)
}

/// Remove a member from a conversation (soft delete)
pub async fn remove_member(pool: &DbPool, convo_id: &str, member_did: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE members
        SET left_at = $1
        WHERE convo_id = $2 AND member_did = $3
        "#,
    )
    .bind(Utc::now())
    .bind(convo_id)
    .bind(member_did)
    .execute(pool)
    .await
    .context("Failed to remove member")?;

    Ok(())
}

/// Check if a user is an active member of a conversation
pub async fn is_member(pool: &DbPool, did: &str, convo_id: &str) -> Result<bool> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) 
        FROM members 
        WHERE member_did = $1 AND convo_id = $2 AND left_at IS NULL
        "#,
    )
    .bind(did)
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .context("Failed to check membership")?;

    Ok(count > 0)
}

/// List active members of a conversation
pub async fn list_members(pool: &DbPool, convo_id: &str) -> Result<Vec<Membership>> {
    let members = sqlx::query_as::<_, Membership>(
        r#"
        SELECT convo_id, member_did, joined_at, left_at, unread_count
        FROM members
        WHERE convo_id = $1 AND left_at IS NULL
        ORDER BY joined_at ASC
        "#,
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .context("Failed to list members")?;

    Ok(members)
}

/// Get membership information
pub async fn get_membership(
    pool: &DbPool,
    convo_id: &str,
    member_did: &str,
) -> Result<Option<Membership>> {
    let membership = sqlx::query_as::<_, Membership>(
        r#"
        SELECT convo_id, member_did, joined_at, left_at, unread_count
        FROM members
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(convo_id)
    .bind(member_did)
    .fetch_optional(pool)
    .await
    .context("Failed to get membership")?;

    Ok(membership)
}

/// Update unread count for a member
pub async fn update_unread_count(
    pool: &DbPool,
    convo_id: &str,
    member_did: &str,
    increment: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE members
        SET unread_count = GREATEST(0, unread_count + $1)
        WHERE convo_id = $2 AND member_did = $3
        "#,
    )
    .bind(increment)
    .bind(convo_id)
    .bind(member_did)
    .execute(pool)
    .await
    .context("Failed to update unread count")?;

    Ok(())
}

/// Reset unread count for a member
pub async fn reset_unread_count(pool: &DbPool, convo_id: &str, member_did: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE members
        SET unread_count = 0, last_read_at = $1
        WHERE convo_id = $2 AND member_did = $3
        "#,
    )
    .bind(Utc::now())
    .bind(convo_id)
    .bind(member_did)
    .execute(pool)
    .await
    .context("Failed to reset unread count")?;

    Ok(())
}

// =============================================================================
// Message Operations
// =============================================================================

/// Create a new message with direct ciphertext storage (v1 simplified)
pub async fn create_message(
    pool: &DbPool,
    convo_id: &str,
    sender_did: &str,
    ciphertext: Vec<u8>,
    epoch: i64,
    embed_type: Option<&str>,
    embed_uri: Option<&str>,
) -> Result<Message> {
    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);

    // Calculate sequence number within transaction
    let mut tx = pool.begin().await.context("Failed to begin transaction")?;

    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE convo_id = $1"
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .context("Failed to calculate sequence number")?;

    let message = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type, epoch, seq,
            ciphertext, embed_type, embed_uri, created_at, expires_at
        ) VALUES ($1, $2, $3, 'app', $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, convo_id, sender_did, message_type, epoch, seq, ciphertext, embed_type, embed_uri, created_at, expires_at
        "#,
    )
    .bind(&msg_id)
    .bind(convo_id)
    .bind(sender_did)
    .bind(epoch)
    .bind(seq)
    .bind(&ciphertext)
    .bind(embed_type)
    .bind(embed_uri)
    .bind(&now)
    .bind(&expires_at)
    .fetch_one(&mut *tx)
    .await
    .context("Failed to insert message")?;

    tx.commit().await.context("Failed to commit transaction")?;

    Ok(message)
}

/// Get a message by ID
pub async fn get_message(pool: &DbPool, message_id: &str) -> Result<Option<Message>> {
    let message = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, convo_id, sender_did, message_type, epoch, seq, ciphertext, embed_type, embed_uri, created_at, expires_at
        FROM messages
        WHERE id = $1
        "#,
    )
    .bind(message_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch message")?;

    Ok(message)
}

/// List messages for a conversation with pagination
pub async fn list_messages(
    pool: &DbPool,
    convo_id: &str,
    before: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<Vec<Message>> {
    let messages = if let Some(before_time) = before {
        sqlx::query_as::<_, Message>(
            r#"
            SELECT id, convo_id, sender_did, message_type, epoch, seq, ciphertext, embed_type, embed_uri, created_at, expires_at
            FROM messages
            WHERE convo_id = $1 AND created_at < $2 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(convo_id)
        .bind(before_time)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, Message>(
            r#"
            SELECT id, convo_id, sender_did, message_type, epoch, seq, ciphertext, embed_type, embed_uri, created_at, expires_at
            FROM messages
            WHERE convo_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(convo_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
    .context("Failed to list messages")?;

    Ok(messages)
}

/// List messages since a specific time
pub async fn list_messages_since(
    pool: &DbPool,
    convo_id: &str,
    since: DateTime<Utc>,
) -> Result<Vec<Message>> {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, convo_id, sender_did, message_type, epoch, seq, ciphertext, embed_type, embed_uri, created_at, expires_at
        FROM messages
        WHERE convo_id = $1 AND created_at > $2 AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at ASC
        "#,
    )
    .bind(convo_id)
    .bind(since)
    .fetch_all(pool)
    .await
    .context("Failed to list messages since time")?;

    Ok(messages)
}

/// Get message count for a conversation
pub async fn get_message_count(pool: &DbPool, convo_id: &str) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE convo_id = $1")
        .bind(convo_id)
        .fetch_one(pool)
        .await
        .context("Failed to get message count")?;

    Ok(count)
}

/// Delete a message
pub async fn delete_message(pool: &DbPool, message_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM messages WHERE id = $1")
        .bind(message_id)
        .execute(pool)
        .await
        .context("Failed to delete message")?;

    Ok(())
}

// =============================================================================
// Key Package Operations
// =============================================================================

/// Store a new key package
pub async fn store_key_package(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
    key_data: Vec<u8>,
    expires_at: DateTime<Utc>,
) -> Result<KeyPackage> {
    let now = Utc::now();

    let key_package = sqlx::query_as::<_, KeyPackage>(
        r#"
        INSERT INTO key_packages (did, cipher_suite, key_data, created_at, expires_at, consumed)
        VALUES ($1, $2, $3, $4, $5, false)
        ON CONFLICT (did, cipher_suite, key_data) DO NOTHING
        RETURNING did, cipher_suite, key_data, created_at, expires_at, consumed
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(key_data)
    .bind(now)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to store key package")?;

    Ok(key_package)
}

/// Get an available key package for a user
pub async fn get_key_package(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
) -> Result<Option<KeyPackage>> {
    let now = Utc::now();

    let key_package = sqlx::query_as::<_, KeyPackage>(
        r#"
        SELECT did, cipher_suite, key_data, created_at, expires_at, consumed
        FROM key_packages
        WHERE did = $1 
          AND cipher_suite = $2 
          AND consumed = false 
          AND expires_at > $3
        ORDER BY created_at ASC
        LIMIT 1
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(now)
    .fetch_optional(pool)
    .await
    .context("Failed to get key package")?;

    Ok(key_package)
}

/// Mark a key package as consumed
pub async fn consume_key_package(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
    key_data: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE key_packages
        SET consumed = true, consumed_at = $1
        WHERE did = $2 AND cipher_suite = $3 AND key_data = $4
        "#,
    )
    .bind(Utc::now())
    .bind(did)
    .bind(cipher_suite)
    .bind(key_data)
    .execute(pool)
    .await
    .context("Failed to consume key package")?;

    Ok(())
}

/// Delete expired key packages
pub async fn delete_expired_key_packages(pool: &DbPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM key_packages WHERE expires_at < $1")
        .bind(Utc::now())
        .execute(pool)
        .await
        .context("Failed to delete expired key packages")?;

    Ok(result.rows_affected())
}

/// Count available key packages for a user
pub async fn count_key_packages(pool: &DbPool, did: &str, cipher_suite: &str) -> Result<i64> {
    let now = Utc::now();

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) 
        FROM key_packages 
        WHERE did = $1 
          AND cipher_suite = $2 
          AND consumed = false 
          AND expires_at > $3
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(now)
    .fetch_one(pool)
    .await
    .context("Failed to count key packages")?;

    Ok(count)
}

// =============================================================================
// Transaction Support
// =============================================================================

/// Begin a database transaction
pub async fn begin_transaction(pool: &DbPool) -> Result<Transaction<'_, Postgres>> {
    let tx = pool.begin().await.context("Failed to begin transaction")?;
    Ok(tx)
}

/// Create a conversation with initial members in a transaction
pub async fn create_conversation_with_members(
    pool: &DbPool,
    creator_did: &str,
    title: Option<String>,
    member_dids: Vec<String>,
) -> Result<Conversation> {
    let mut tx = begin_transaction(pool).await?;

    // Create conversation
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let conversation = sqlx::query_as::<_, Conversation>(
        r#"
        INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name)
        VALUES ($1, $2, 0, $3, $4, $5)
        RETURNING id, creator_did, current_epoch, created_at, name as title
        "#,
    )
    .bind(&id)
    .bind(creator_did)
    .bind(now)
    .bind(now)
    .bind(&title)
    .fetch_one(&mut *tx)
    .await
    .context("Failed to create conversation")?;

    // Add members
    for member_did in member_dids {
        sqlx::query(
            r#"
            INSERT INTO members (convo_id, member_did, joined_at, unread_count)
            VALUES ($1, $2, $3, 0)
            "#,
        )
        .bind(&id)
        .bind(&member_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("Failed to add member to conversation")?;
    }

    tx.commit().await.context("Failed to commit transaction")?;

    Ok(conversation)
}

// =============================================================================
// Health Check
// =============================================================================

/// Check if database connection is healthy
pub async fn health_check(pool: &DbPool) -> Result<bool> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .context("Database health check failed")?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> DbPool {
        let config = DbConfig {
            database_url: std::env::var("TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string()),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
        };

        init_db(config)
            .await
            .expect("Failed to initialize test database")
    }

    #[tokio::test]
    async fn test_create_and_get_conversation() {
        let pool = setup_test_db().await;

        let conversation =
            create_conversation(&pool, "did:plc:test123", Some("Test Convo".to_string()))
                .await
                .expect("Failed to create conversation");

        assert_eq!(conversation.creator_did, "did:plc:test123");
        assert_eq!(conversation.title, Some("Test Convo".to_string()));

        let fetched = get_conversation(&pool, &conversation.id)
            .await
            .expect("Failed to get conversation")
            .expect("Conversation not found");

        assert_eq!(fetched.id, conversation.id);
    }

    #[tokio::test]
    async fn test_member_operations() {
        let pool = setup_test_db().await;

        let conversation = create_conversation(&pool, "did:plc:creator", None)
            .await
            .expect("Failed to create conversation");

        add_member(&pool, &conversation.id, "did:plc:member1")
            .await
            .expect("Failed to add member");

        let is_member_result = is_member(&pool, "did:plc:member1", &conversation.id)
            .await
            .expect("Failed to check membership");

        assert!(is_member_result);

        let members = list_members(&pool, &conversation.id)
            .await
            .expect("Failed to list members");

        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn test_message_operations() {
        let pool = setup_test_db().await;

        let conversation = create_conversation(&pool, "did:plc:creator", None)
            .await
            .expect("Failed to create conversation");

        let message = create_message(
            &pool,
            &conversation.id,
            "did:plc:sender",
            vec![1, 2, 3, 4],
            0,
            None,
            None,
        )
        .await
        .expect("Failed to create message");

        let fetched = get_message(&pool, &message.id)
            .await
            .expect("Failed to get message")
            .expect("Message not found");

        assert_eq!(fetched.id, message.id);
        assert_eq!(fetched.ciphertext, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_key_package_operations() {
        let pool = setup_test_db().await;

        let expires_at = Utc::now() + chrono::Duration::hours(24);
        let key_data = vec![5, 6, 7, 8];

        store_key_package(
            &pool,
            "did:plc:user",
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            key_data.clone(),
            expires_at,
        )
        .await
        .expect("Failed to store key package");

        let fetched = get_key_package(
            &pool,
            "did:plc:user",
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

        assert_eq!(fetched.key_data, key_data);

        consume_key_package(
            &pool,
            "did:plc:user",
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            &key_data,
        )
        .await
        .expect("Failed to consume key package");

        let consumed = get_key_package(
            &pool,
            "did:plc:user",
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .await
        .expect("Failed to get key package");

        assert!(consumed.is_none());
    }

    #[tokio::test]
    async fn test_transaction() {
        let pool = setup_test_db().await;

        let conversation = create_conversation_with_members(
            &pool,
            "did:plc:creator",
            Some("Group Chat".to_string()),
            vec!["did:plc:member1".to_string(), "did:plc:member2".to_string()],
        )
        .await
        .expect("Failed to create conversation with members");

        let members = list_members(&pool, &conversation.id)
            .await
            .expect("Failed to list members");

        assert_eq!(members.len(), 2);
    }
}

// =============================================================================
// Cursor Operations (Hybrid Messaging)
// =============================================================================

/// Update user's last seen cursor for a conversation
pub async fn update_last_seen_cursor(
    pool: &DbPool,
    user_did: &str,
    convo_id: &str,
    cursor: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO cursors (user_did, convo_id, last_seen_cursor, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_did, convo_id)
        DO UPDATE SET 
            last_seen_cursor = $3,
            updated_at = NOW()
        "#,
        user_did,
        convo_id,
        cursor,
    )
    .execute(pool)
    .await
    .context("Failed to update cursor")?;

    Ok(())
}

/// Get user's last seen cursor for a conversation
pub async fn get_last_seen_cursor(
    pool: &DbPool,
    user_did: &str,
    convo_id: &str,
) -> Result<Option<String>> {
    let result = sqlx::query!(
        r#"
        SELECT last_seen_cursor
        FROM cursors
        WHERE user_did = $1 AND convo_id = $2
        "#,
        user_did,
        convo_id,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to get cursor")?;

    Ok(result.map(|r| r.last_seen_cursor))
}

// =============================================================================
// Envelope Operations (Mailbox Fan-out)
// =============================================================================

/// Create envelope for message delivery (simplified - no provider/zone)
pub async fn create_envelope(
    pool: &DbPool,
    convo_id: &str,
    recipient_did: &str,
    message_id: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();

    sqlx::query!(
        r#"
        INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (recipient_did, message_id) DO NOTHING
        RETURNING id
        "#,
        &id,
        convo_id,
        recipient_did,
        message_id,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to create envelope")?;

    Ok(id)
}

// =============================================================================
// Event Stream Operations (Realtime Events)
// =============================================================================

/// Store event in event stream
pub async fn store_event(
    pool: &DbPool,
    cursor: &str,
    convo_id: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO event_stream (id, convo_id, event_type, payload, emitted_at)
        VALUES ($1, $2, $3, $4, NOW())
        "#,
        cursor,
        convo_id,
        event_type,
        payload,
    )
    .execute(pool)
    .await
    .context("Failed to store event")?;

    Ok(())
}

/// Get events after cursor for backfill
pub async fn get_events_after_cursor(
    pool: &DbPool,
    convo_id: &str,
    event_type: Option<&str>,
    after_cursor: &str,
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, DateTime<Utc>)>> {
    #[derive(sqlx::FromRow)]
    struct EventRow {
        id: String,
        payload: serde_json::Value,
        emitted_at: DateTime<Utc>,
    }

    let events: Vec<EventRow> = if let Some(et) = event_type {
        sqlx::query_as(
            r#"
            SELECT id, payload, emitted_at
            FROM event_stream
            WHERE convo_id = $1 AND event_type = $2 AND id > $3
            ORDER BY id ASC
            LIMIT $4
            "#,
        )
        .bind(convo_id)
        .bind(et)
        .bind(after_cursor)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to get events")?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, payload, emitted_at
            FROM event_stream
            WHERE convo_id = $1 AND id > $2
            ORDER BY id ASC
            LIMIT $3
            "#,
        )
        .bind(convo_id)
        .bind(after_cursor)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to get events")?
    };

    Ok(events
        .into_iter()
        .map(|e| (e.id, e.payload, e.emitted_at))
        .collect())
}

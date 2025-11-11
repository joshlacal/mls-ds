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

/// Create a message with privacy-enhancing fields
///
/// This is the ONLY message creation function. It implements metadata privacy by:
/// - Setting sender_did to NULL (sender derived from decrypted MLS message by clients)
/// - Using client-provided msg_id (ULID) for deduplication
/// - Supporting declared_size/padded_size for traffic analysis resistance
/// - Quantizing timestamps to 2-second buckets
///
/// # Security
/// - Never stores sender identity in plaintext
/// - Idempotent via msg_id and optional idempotency_key
/// - Provides minimal metadata surface for network observers
pub async fn create_message(
    pool: &DbPool,
    convo_id: &str,
    msg_id: &str,
    ciphertext: Vec<u8>,
    epoch: i64,
    padded_size: i64,
    idempotency_key: Option<String>,
) -> Result<Message> {
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);

    // Quantize timestamp to 2-second buckets for traffic analysis resistance
    let received_bucket_ts = (now.timestamp() / 2) * 2;

    // Calculate sequence number within transaction
    let mut tx = pool.begin().await.context("Failed to begin transaction")?;

    // Check for duplicate msg_id (protocol-layer deduplication)
    if let Some(existing) = sqlx::query_as::<_, Message>(
        "SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
         FROM messages WHERE convo_id = $1 AND msg_id = $2"
    )
    .bind(convo_id)
    .bind(msg_id)
    .fetch_optional(&mut *tx)
    .await
    .context("Failed to check msg_id")? {
        // Return existing message without creating a duplicate
        tx.rollback().await.ok();
        return Ok(existing);
    }

    // If idempotency key is provided, check for existing message
    if let Some(ref idem_key) = idempotency_key {
        if let Some(existing) = sqlx::query_as::<_, Message>(
            "SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
             FROM messages WHERE idempotency_key = $1"
        )
        .bind(idem_key)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to check idempotency key")? {
            // Return existing message without creating a duplicate
            tx.rollback().await.ok();
            return Ok(existing);
        }
    }

    let seq: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .context("Failed to calculate sequence number")?;

    // Generate unique row ID (internal database ID)
    let row_id = uuid::Uuid::new_v4().to_string();

    // Try to insert the message
    let insert_result = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type, epoch, seq,
            ciphertext, created_at, expires_at,
            msg_id, padded_size, received_bucket_ts,
            idempotency_key
        ) VALUES ($1, $2, NULL, 'app', $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
        "#,
    )
    .bind(&row_id)
    .bind(convo_id)
    .bind(epoch)
    .bind(seq)
    .bind(&ciphertext)
    .bind(&now)
    .bind(&expires_at)
    .bind(msg_id)
    .bind(padded_size)
    .bind(received_bucket_ts)
    .bind(&idempotency_key)
    .fetch_one(&mut *tx)
    .await;

    match insert_result {
        Ok(message) => {
            // Insert succeeded, commit transaction
            tx.commit().await.context("Failed to commit transaction")?;
            Ok(message)
        }
        Err(e) => {
            // Rollback the transaction immediately (consumes tx)
            tx.rollback().await.ok();

            // Check if this is a unique constraint violation on idempotency_key
            if let Some(db_err) = e.as_database_error() {
                if db_err.code() == Some(std::borrow::Cow::Borrowed("23505")) {
                    // SQLSTATE 23505 = unique_violation
                    // Check if it's the idempotency_key constraint
                    if let Some(constraint) = db_err.constraint() {
                        if constraint == "messages_idempotency_key_unique" {
                            // Query for the existing message with this idempotency key
                            if let Some(ref idem_key) = idempotency_key {
                                if let Some(existing) = sqlx::query_as::<_, Message>(
                                    "SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
                                     FROM messages WHERE idempotency_key = $1"
                                )
                                .bind(idem_key)
                                .fetch_optional(pool)
                                .await
                                .context("Failed to fetch existing message after unique violation")? {
                                    tracing::info!("Idempotency key collision detected, returning existing message: {}", existing.id);
                                    return Ok(existing);
                                }
                            }
                        }
                    }
                }
            }

            // If we get here, it's not a handled unique violation, so propagate the error
            Err(e).context("Failed to insert message")
        }
    }
}

/// Get a message by ID
pub async fn get_message(pool: &DbPool, message_id: &str) -> Result<Option<Message>> {
    let message = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
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
            SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
            FROM messages
            WHERE convo_id = $1 AND created_at < $2 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY epoch ASC, seq ASC
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
            SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
            FROM messages
            WHERE convo_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY epoch ASC, seq ASC
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

/// List messages since a specific sequence number (for seq-based pagination)
pub async fn list_messages_since_seq(
    pool: &DbPool,
    convo_id: &str,
    since_seq: i64,
    limit: i64,
) -> Result<Vec<Message>> {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at
        FROM messages
        WHERE convo_id = $1 AND seq > $2 AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY epoch ASC, seq ASC
        LIMIT $3
        "#,
    )
    .bind(convo_id)
    .bind(since_seq)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("Failed to list messages since sequence number")?;

    Ok(messages)
}

/// Gap detection information
#[derive(Debug, Clone)]
pub struct GapInfo {
    pub has_gaps: bool,
    pub missing_seqs: Vec<i64>,
    pub total_messages: i64,
}

/// Detect gaps in message sequence numbers for a conversation
/// Returns GapInfo with missing sequence numbers within the min-max range
pub async fn detect_message_gaps(
    pool: &DbPool,
    convo_id: &str,
) -> Result<GapInfo> {
    // Get min, max seq and total count
    let stats: Option<(Option<i64>, Option<i64>, i64)> = sqlx::query_as(
        r#"
        SELECT
            MIN(seq) as min_seq,
            MAX(seq) as max_seq,
            COUNT(*) as total
        FROM messages
        WHERE convo_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
        "#,
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .context("Failed to get message sequence stats")?;

    let (min_seq, max_seq, total_messages) = match stats {
        Some((Some(min), Some(max), total)) => (min, max, total),
        _ => {
            // No messages or all expired
            return Ok(GapInfo {
                has_gaps: false,
                missing_seqs: vec![],
                total_messages: 0,
            });
        }
    };

    // Check if there are gaps by comparing expected range with actual count
    let expected_count = (max_seq - min_seq + 1) as i64;
    if expected_count == total_messages {
        // No gaps
        return Ok(GapInfo {
            has_gaps: false,
            missing_seqs: vec![],
            total_messages,
        });
    }

    // Find specific missing sequence numbers
    let missing_seqs: Vec<i64> = sqlx::query_scalar(
        r#"
        WITH RECURSIVE seq_range AS (
            SELECT $2::BIGINT AS seq
            UNION ALL
            SELECT seq + 1
            FROM seq_range
            WHERE seq < $3
        )
        SELECT sr.seq
        FROM seq_range sr
        LEFT JOIN messages m ON sr.seq = m.seq AND m.convo_id = $1 AND (m.expires_at IS NULL OR m.expires_at > NOW())
        WHERE m.seq IS NULL
        ORDER BY sr.seq
        "#,
    )
    .bind(convo_id)
    .bind(min_seq)
    .bind(max_seq)
    .fetch_all(pool)
    .await
    .context("Failed to detect gaps in message sequence")?;

    Ok(GapInfo {
        has_gaps: !missing_seqs.is_empty(),
        missing_seqs,
        total_messages,
    })
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

/// Delete expired messages based on expires_at
pub async fn delete_expired_messages(pool: &DbPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < NOW()")
        .execute(pool)
        .await
        .context("Failed to delete expired messages")?;
    Ok(result.rows_affected())
}

/// Delete old events older than the provided retention window (seconds)
pub async fn delete_old_events(pool: &DbPool, older_than_seconds: i64) -> Result<u64> {
    let result = sqlx::query(
        r#"DELETE FROM event_stream WHERE emitted_at < NOW() - ($1::text || ' seconds')::interval"#,
    )
    .bind(older_than_seconds.to_string())
    .execute(pool)
    .await
    .context("Failed to delete old events")?;
    Ok(result.rows_affected())
}

/// Delete messages older than TTL (in days)
pub async fn compact_messages(pool: &DbPool, ttl_days: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(ttl_days);

    let result = sqlx::query(
        "DELETE FROM messages WHERE created_at < $1"
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .context("Failed to compact messages")?;

    Ok(result.rows_affected())
}

/// Delete event_stream entries older than TTL (in days)
pub async fn compact_event_stream(pool: &DbPool, ttl_days: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(ttl_days);

    let result = sqlx::query(
        "DELETE FROM event_stream WHERE emitted_at < $1"
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .context("Failed to compact event stream")?;

    Ok(result.rows_affected())
}

/// Delete consumed welcome messages older than 7 days
pub async fn compact_welcome_messages(pool: &DbPool) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(7);

    let result = sqlx::query(
        "DELETE FROM welcome_messages
         WHERE consumed = true AND consumed_at < $1"
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .context("Failed to compact welcome messages")?;

    Ok(result.rows_affected())
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
    let id = Uuid::new_v4().to_string();

    // Ensure user exists (upsert)
    sqlx::query(
        r#"
        INSERT INTO users (did, created_at, last_seen_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (did) DO UPDATE SET last_seen_at = $3
        "#,
    )
    .bind(did)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .context("Failed to ensure user exists")?;

    // Compute SHA256 hash of the key package data
    let key_package_hash = crate::crypto::sha256_hex(&key_data);

    let result = sqlx::query_as::<_, KeyPackage>(
        r#"
        INSERT INTO key_packages (id, owner_did, cipher_suite, key_package, key_package_hash, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING owner_did, cipher_suite, key_package as key_data, key_package_hash, created_at, expires_at, consumed_at
        "#,
    )
    .bind(&id)
    .bind(did)
    .bind(cipher_suite)
    .bind(&key_data)
    .bind(&key_package_hash)
    .bind(now)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to store key package")?;

    Ok(result)
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
        SELECT owner_did, cipher_suite, key_package as key_data, key_package_hash, created_at, expires_at, consumed_at
        FROM key_packages
        WHERE owner_did = $1
          AND cipher_suite = $2
          AND consumed_at IS NULL
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

/// Get ALL unconsumed key packages for a user (for multi-device support)
/// Returns all valid key packages, one per device
pub async fn get_all_key_packages(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
) -> Result<Vec<KeyPackage>> {
    let now = Utc::now();

    let key_packages = sqlx::query_as::<_, KeyPackage>(
        r#"
        SELECT owner_did, cipher_suite, key_package as key_data, key_package_hash, created_at, expires_at, consumed_at
        FROM key_packages
        WHERE owner_did = $1
          AND cipher_suite = $2
          AND consumed_at IS NULL
          AND expires_at > $3
        ORDER BY created_at ASC
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(now)
    .fetch_all(pool)
    .await
    .context("Failed to get all key packages")?;

    Ok(key_packages)
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
        SET consumed_at = $1
        WHERE owner_did = $2 AND cipher_suite = $3 AND key_package = $4 AND consumed_at IS NULL
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

/// Mark a key package as consumed by hash (used in group operations)
pub async fn mark_key_package_consumed(
    pool: &DbPool,
    did: &str,
    key_package_hash: &str,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE key_packages
        SET consumed_at = $1
        WHERE owner_did = $2 AND key_package_hash = $3 AND consumed_at IS NULL
        "#,
    )
    .bind(Utc::now())
    .bind(did)
    .bind(key_package_hash)
    .execute(pool)
    .await
    .context("Failed to mark key package as consumed")?;

    Ok(result.rows_affected() > 0)
}

/// Count key packages consumed in last N hours
pub async fn count_consumed_key_packages(
    pool: &DbPool,
    did: &str,
    hours: i64,
) -> Result<i64> {
    let cutoff = Utc::now() - chrono::Duration::hours(hours);

    let result = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM key_packages
        WHERE owner_did = $1 AND consumed_at IS NOT NULL AND consumed_at >= $2
        "#,
    )
    .bind(did)
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .context("Failed to count consumed key packages")?;

    Ok(result)
}

/// Get consumption rate (packages per day) based on last 7 days
pub async fn get_consumption_rate(pool: &DbPool, did: &str) -> Result<f64> {
    let cutoff = Utc::now() - chrono::Duration::days(7);

    let result = sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
        r#"
        SELECT
            COUNT(*) as count,
            EXTRACT(EPOCH FROM (MAX(consumed_at) - MIN(consumed_at)))::bigint as duration_seconds
        FROM key_packages
        WHERE owner_did = $1 AND consumed_at IS NOT NULL AND consumed_at >= $2
        "#,
    )
    .bind(did)
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .context("Failed to calculate consumption rate")?;

    let (count, duration_seconds) = result;

    // If we have less than 2 data points or duration is 0, return 0
    if count.unwrap_or(0) < 2 || duration_seconds.unwrap_or(0) == 0 {
        return Ok(0.0);
    }

    // Calculate packages per day
    let count = count.unwrap() as f64;
    let duration_days = duration_seconds.unwrap() as f64 / 86400.0;

    Ok(count / duration_days)
}

/// Get total count of key packages (all states)
pub async fn count_all_key_packages(
    pool: &DbPool,
    did: &str,
    cipher_suite: Option<&str>,
) -> Result<i64> {
    let result = if let Some(suite) = cipher_suite {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM key_packages
            WHERE owner_did = $1 AND cipher_suite = $2
            "#,
        )
        .bind(did)
        .bind(suite)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM key_packages
            WHERE owner_did = $1
            "#,
        )
        .bind(did)
        .fetch_one(pool)
        .await
    };

    result.context("Failed to count all key packages")
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

/// Delete consumed key packages older than specified hours
pub async fn delete_consumed_key_packages(pool: &DbPool, hours_old: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::hours(hours_old);

    let result = sqlx::query(
        "DELETE FROM key_packages WHERE consumed_at IS NOT NULL AND consumed_at < $1"
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .context("Failed to delete consumed key packages")?;

    Ok(result.rows_affected())
}

/// Enforce maximum key packages per device
pub async fn enforce_key_package_limit(
    pool: &DbPool,
    max_per_device: i64,
) -> Result<u64> {
    // For each DID, keep only the newest max_per_device packages
    let result = sqlx::query(
        r#"
        DELETE FROM key_packages
        WHERE id IN (
            SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY owner_did
                           ORDER BY created_at DESC
                       ) as rn
                FROM key_packages
                WHERE consumed_at IS NULL
            ) ranked
            WHERE rn > $1
        )
        "#
    )
    .bind(max_per_device)
    .execute(pool)
    .await
    .context("Failed to enforce key package limit")?;

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

/// Store minimal event envelope (no full message content)
///
/// Security: Only stores routing metadata. Clients fetch full message
/// via getMessages and decrypt locally. This prevents metadata leakage
/// from event stream storage.
///
/// # Arguments
/// * `cursor` - Event cursor (ULID) for ordering
/// * `convo_id` - Conversation identifier
/// * `event_type` - Type of event (messageEvent, reactionEvent, etc.)
/// * `message_id` - Optional message ID for message events only
pub async fn store_event(
    pool: &DbPool,
    cursor: &str,
    convo_id: &str,
    event_type: &str,
    message_id: Option<&str>,
) -> Result<()> {
    // Store minimal envelope only - no ciphertext or metadata
    let envelope = serde_json::json!({
        "cursor": cursor,
        "convoId": convo_id,
        "messageId": message_id,
    });

    sqlx::query!(
        r#"
        INSERT INTO event_stream (id, convo_id, event_type, payload, emitted_at)
        VALUES ($1, $2, $3, $4, NOW())
        "#,
        cursor,
        convo_id,
        event_type,
        envelope,
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

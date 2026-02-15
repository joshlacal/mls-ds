use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use uuid::Uuid;

use crate::models::{Conversation, KeyPackage, Membership, Message, SequencerReceipt};

pub type DbPool = PgPool;

static KEY_PACKAGE_PARSE_LIMITER: Lazy<Semaphore> = Lazy::new(|| {
    let default_limit = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let configured_limit = std::env::var("KEY_PACKAGE_PARSE_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_limit);
    Semaphore::new(configured_limit)
});

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
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
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

    tracing::warn!(
        "Database pool initialized with max_connections={}, min_connections={}, acquire_timeout={:?}",
        config.max_connections,
        config.min_connections,
        config.acquire_timeout
    );

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("Failed to run migrations")?;

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
///
/// Handles both single-device (legacy) and multi-device modes:
/// - Accepts base user DID or device MLS DID in `member_did` parameter
/// - Matches against either `member_did` OR `user_did` columns
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
        WHERE (m.member_did = $1 OR m.user_did = $1) AND m.left_at IS NULL
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

/// Atomically advance a conversation epoch by one when the expected epoch matches.
///
/// Returns `Ok(Some(new_epoch))` on success, `Ok(None)` when the conversation epoch no
/// longer matches `expected_epoch` (concurrent commit won), or an error for DB failures.
pub async fn try_advance_conversation_epoch_tx(
    tx: &mut Transaction<'_, Postgres>,
    convo_id: &str,
    expected_epoch: i32,
) -> Result<Option<i32>> {
    let advanced_epoch = sqlx::query_scalar::<_, i32>(
        r#"
        UPDATE conversations
        SET current_epoch = current_epoch + 1,
            updated_at = $1
        WHERE id = $2
          AND current_epoch = $3
        RETURNING current_epoch
        "#,
    )
    .bind(Utc::now())
    .bind(convo_id)
    .bind(expected_epoch)
    .fetch_optional(&mut **tx)
    .await
    .context("Failed to advance conversation epoch")?;

    Ok(advanced_epoch)
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
///
/// Handles both single-device (legacy) and multi-device modes:
/// - Accepts base user DID (e.g., `did:plc:abc123`) or device MLS DID (e.g., `did:plc:abc123#device-xyz`)
/// - In multi-device mode, members are stored with device MLS DIDs in `member_did` column
/// - The `user_did` column stores the base DID (without device fragment) for all devices
/// - Returns true if the DID matches either `member_did` OR `user_did`
pub async fn is_member(pool: &DbPool, did: &str, convo_id: &str) -> Result<bool> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM members
        WHERE (member_did = $1 OR user_did = $1) AND convo_id = $2 AND left_at IS NULL
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
        "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
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
pub async fn detect_message_gaps(pool: &DbPool, convo_id: &str) -> Result<GapInfo> {
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
    let result =
        sqlx::query("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < NOW()")
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

    let result = sqlx::query("DELETE FROM messages WHERE created_at < $1")
        .bind(cutoff)
        .execute(pool)
        .await
        .context("Failed to compact messages")?;

    Ok(result.rows_affected())
}

/// Delete event_stream entries older than TTL (in days)
pub async fn compact_event_stream(pool: &DbPool, ttl_days: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(ttl_days);

    let result = sqlx::query("DELETE FROM event_stream WHERE emitted_at < $1")
        .bind(cutoff)
        .execute(pool)
        .await
        .context("Failed to compact event stream")?;

    Ok(result.rows_affected())
}

/// Delete consumed welcome messages older than 24 hours
/// Unconsumed messages are kept indefinitely (until consumed + 24h grace period)
pub async fn compact_welcome_messages(pool: &DbPool) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::hours(24);

    let result = sqlx::query(
        "DELETE FROM welcome_messages
         WHERE consumed = true AND consumed_at < $1",
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
    store_key_package_with_device(pool, did, cipher_suite, key_data, expires_at, None, None).await
}

/// Store a new key package with device information
pub async fn store_key_package_with_device(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
    key_data: Vec<u8>,
    expires_at: DateTime<Utc>,
    device_id: Option<String>,
    _credential_did: Option<String>, // Ignored - extracted from KeyPackage
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

    let parse_timeout_secs = std::env::var("KEY_PACKAGE_PARSE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);

    let did_owned = did.to_string();
    let key_data_for_parse = key_data.clone();
    let _permit = KEY_PACKAGE_PARSE_LIMITER
        .acquire()
        .await
        .context("Key package validation limiter closed")?;

    let mut parse_task = tokio::task::spawn_blocking(move || -> Result<(String, String)> {
        // Compute MLS-compliant hash_ref using OpenMLS
        use openmls::prelude::tls_codec::Deserialize;
        use openmls::prelude::{KeyPackageIn, ProtocolVersion};

        // Create crypto provider (RustCrypto implements OpenMlsCrypto)
        let provider = openmls_rust_crypto::RustCrypto::default();

        // Deserialize and validate the key package
        let kp_in = KeyPackageIn::tls_deserialize(&mut key_data_for_parse.as_slice())
            .context("Failed to deserialize key package")?;
        let kp = kp_in
            .validate(&provider, ProtocolVersion::default())
            .context("Failed to validate key package")?;

        // Extract and validate credential identity
        let credential = kp.leaf_node().credential();
        let credential_identity = match credential.credential_type() {
            openmls::credentials::CredentialType::Basic => {
                // Extract identity bytes from BasicCredential
                let identity_bytes = credential.serialized_content();
                String::from_utf8(identity_bytes.to_vec())
                    .context("Credential identity is not valid UTF-8")?
            }
            _ => {
                bail!("Only BasicCredential is supported");
            }
        };

        // Validate that credential identity is the bare DID (owner_did)
        // This enforces the "bare DID only" policy - no device DIDs allowed in MLS credentials
        if credential_identity != did_owned {
            bail!(
                "KeyPackage credential identity must be the bare user DID ({}), got {} instead. \
                     Device DIDs (with #device-id) are not allowed in MLS credentials.",
                did_owned,
                credential_identity
            );
        }

        // Compute the MLS-defined hash reference
        let hash_ref = kp
            .hash_ref(&provider)
            .context("Failed to compute hash_ref")?;
        let key_package_hash = hex::encode(hash_ref.as_slice());

        Ok((key_package_hash, credential_identity))
    });

    let (key_package_hash, credential_identity) = match tokio::time::timeout(
        Duration::from_secs(parse_timeout_secs),
        &mut parse_task,
    )
    .await
    {
        Ok(join_result) => join_result
            .context("Key package validation task failed")?
            .context("Key package validation error")?,
        Err(_) => {
            parse_task.abort();
            bail!(
                "Key package validation timed out after {}s",
                parse_timeout_secs
            );
        }
    };

    // Store with the verified credential identity (not the client-provided one)
    let result = sqlx::query_as::<_, KeyPackage>(
        r#"
        INSERT INTO key_packages (id, owner_did, cipher_suite, key_package, key_package_hash, created_at, expires_at, device_id, credential_did)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    .bind(device_id)
    .bind(&credential_identity)  // Use verified identity from KeyPackage, not client param
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

/// Get ONE key package PER DEVICE for a user (multi-device support)
/// Returns up to 50 key packages, one per unique device credential.
/// For proper multi-device support, each package must have a unique credential_did.
/// Legacy key packages (without device_id) are returned as a single fallback.
/// Prioritizes active devices over inactive ones.
pub async fn get_all_key_packages(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
) -> Result<Vec<KeyPackage>> {
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);

    // 🔍 DIAGNOSTIC: Log the exact DID and cipher suite being queried
    info!(
        "🔍 [get_all_key_packages] Query params - did: '{}' (len: {}), cipher_suite: '{}'",
        crate::crypto::hash_for_log(did),
        did.len(),
        cipher_suite
    );

    // 🔍 DIAGNOSTIC: First, log all device_ids for this user's key packages
    let device_ids: Vec<(Option<String>, i64)> = sqlx::query_as(
        r#"
        SELECT device_id, COUNT(*) as count
        FROM key_packages
        WHERE owner_did = $1
          AND cipher_suite = $2
          AND consumed_at IS NULL
          AND expires_at > $3
        GROUP BY device_id
        ORDER BY device_id NULLS LAST
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(now)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // 🔍 DIAGNOSTIC: If no packages found, also check if any exist for this DID at all (ignoring cipher suite)
    if device_ids.is_empty() {
        let any_packages: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM key_packages
            WHERE owner_did = $1
            "#,
        )
        .bind(did)
        .fetch_optional(pool)
        .await
        .unwrap_or_default();

        // Also check similar DIDs to detect format mismatches
        let similar_dids: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT owner_did, COUNT(*) as count FROM key_packages
            WHERE owner_did LIKE $1 OR owner_did LIKE $2
            GROUP BY owner_did
            ORDER BY count DESC
            LIMIT 5
            "#,
        )
        .bind(format!("%{}%", &did[..did.len().min(20)]))
        .bind(format!("{}%", &did[..did.len().min(30)]))
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        let redacted_similar: Vec<(String, i64)> = similar_dids
            .into_iter()
            .map(|(d, c)| (crate::crypto::hash_for_log(&d), c))
            .collect();
        warn!(
            "⚠️ [get_all_key_packages] No packages found for DID '{}'. Total packages with this DID (any cipher suite): {:?}. Similar DIDs in DB: {:?}",
            crate::crypto::hash_for_log(did),
            any_packages,
            redacted_similar
        );
    }

    info!(
        "🔍 [get_all_key_packages] Key package device distribution for {}: {:?}",
        crate::crypto::hash_for_log(did),
        device_ids
    );

    // Get ONE key package per unique DEVICE, prioritizing recently active devices
    //
    // CRITICAL FIX: Use device_id (not credential_did) for DISTINCT ON.
    // - credential_did is the bare user DID (same for ALL devices of a user)
    // - device_id is unique per device, ensuring we get one key package per device
    //
    // This enables multi-device support: when inviting a user, we get key packages
    // for ALL their registered devices, so the Welcome message works on any device.
    //
    // For legacy key packages without device_id, we fall back to key_package_hash
    // to still return one package (though these won't work for multi-device).
    let key_packages = sqlx::query_as::<_, KeyPackage>(
        r#"
        SELECT DISTINCT ON (COALESCE(kp.device_id, kp.key_package_hash))
            kp.owner_did, kp.cipher_suite, kp.key_package as key_data, kp.key_package_hash, kp.created_at, kp.expires_at, kp.consumed_at
        FROM key_packages kp
        LEFT JOIN devices d ON kp.device_id = d.device_id
        WHERE kp.owner_did = $1
          AND kp.cipher_suite = $2
          AND kp.consumed_at IS NULL
          AND kp.expires_at > $3
          AND (kp.reserved_at IS NULL OR kp.reserved_at < $4)
        ORDER BY
            COALESCE(kp.device_id, kp.key_package_hash),
            d.last_seen_at DESC NULLS LAST,
            kp.created_at ASC
        LIMIT 50
        "#,
    )
    .bind(did)
    .bind(cipher_suite)
    .bind(now)
    .bind(reservation_timeout)
    .fetch_all(pool)
    .await
    .context("Failed to get all key packages")?;

    info!(
        "🔍 [get_all_key_packages] Returning {} key packages (one per device) for {}",
        key_packages.len(),
        crate::crypto::hash_for_log(did)
    );

    Ok(key_packages)
}

/// Mark a key package as consumed
pub async fn consume_key_package(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
    key_data: &[u8],
) -> Result<()> {
    consume_key_package_with_metadata(pool, did, cipher_suite, key_data, None, None).await
}

/// Mark a key package as consumed with consumption metadata
pub async fn consume_key_package_with_metadata(
    pool: &DbPool,
    did: &str,
    cipher_suite: &str,
    key_data: &[u8],
    consumed_for_convo_id: Option<&str>,
    consumed_by_device_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE key_packages
        SET consumed_at = $1, consumed_for_convo_id = $5, consumed_by_device_id = $6
        WHERE owner_did = $2 AND cipher_suite = $3 AND key_package = $4 AND consumed_at IS NULL
        "#,
    )
    .bind(Utc::now())
    .bind(did)
    .bind(cipher_suite)
    .bind(key_data)
    .bind(consumed_for_convo_id)
    .bind(consumed_by_device_id)
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
    mark_key_package_consumed_with_metadata(pool, did, key_package_hash, None, None).await
}

/// Mark a key package as consumed by hash with consumption metadata
pub async fn mark_key_package_consumed_with_metadata(
    pool: &DbPool,
    did: &str,
    key_package_hash: &str,
    consumed_for_convo_id: Option<&str>,
    consumed_by_device_id: Option<&str>,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE key_packages
        SET consumed_at = $1, consumed_for_convo_id = $4, consumed_by_device_id = $5
        WHERE owner_did = $2 AND key_package_hash = $3 AND consumed_at IS NULL
        "#,
    )
    .bind(Utc::now())
    .bind(did)
    .bind(key_package_hash)
    .bind(consumed_for_convo_id)
    .bind(consumed_by_device_id)
    .execute(pool)
    .await
    .context("Failed to mark key package as consumed")?;

    Ok(result.rows_affected() > 0)
}

/// Count key packages consumed in last N hours
pub async fn count_consumed_key_packages(pool: &DbPool, did: &str, hours: i64) -> Result<i64> {
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

    let result =
        sqlx::query("DELETE FROM key_packages WHERE consumed_at IS NOT NULL AND consumed_at < $1")
            .bind(cutoff)
            .execute(pool)
            .await
            .context("Failed to delete consumed key packages")?;

    Ok(result.rows_affected())
}

/// Delete old unconsumed key packages (prevent accumulation of stale packages)
pub async fn delete_old_unconsumed_key_packages(pool: &DbPool, days_old: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(days_old);

    let result = sqlx::query(
        r#"
        DELETE FROM key_packages
        WHERE consumed_at IS NULL
          AND created_at < $1
        "#,
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .context("Failed to delete old unconsumed key packages")?;

    Ok(result.rows_affected())
}

/// Enforce maximum key packages per device
pub async fn enforce_key_package_limit(pool: &DbPool, max_per_device: i64) -> Result<u64> {
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
        "#,
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

/// Check if a key package with the given hash already exists for the user
pub async fn check_key_package_duplicate(
    pool: &DbPool,
    owner_did: &str,
    key_package_hash: &str,
) -> Result<bool> {
    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM key_packages
            WHERE owner_did = $1 AND key_package_hash = $2
        )
        "#,
    )
    .bind(owner_did)
    .bind(key_package_hash)
    .fetch_one(pool)
    .await
    .context("Failed to check key package duplicate")?;

    Ok(exists)
}

/// Get key package statistics for a user
/// Returns (total_uploaded, available, consumed, reserved)
pub async fn get_key_package_stats(pool: &DbPool, owner_did: &str) -> Result<(i64, i64, i64, i64)> {
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);

    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as "total!",
            COUNT(*) FILTER (
                WHERE consumed_at IS NULL
                  AND (reserved_at IS NULL OR reserved_at < $2)
            ) as "available!",
            COUNT(*) FILTER (WHERE consumed_at IS NOT NULL) as "consumed!",
            COUNT(*) FILTER (
                WHERE consumed_at IS NULL
                  AND reserved_at IS NOT NULL
                  AND reserved_at >= $2
            ) as "reserved!"
        FROM key_packages
        WHERE owner_did = $1
        "#,
        owner_did,
        reservation_timeout
    )
    .fetch_one(pool)
    .await
    .context("Failed to get key package stats")?;

    Ok((row.total, row.available, row.consumed, row.reserved))
}

/// Get paginated list of consumed key packages for a user
#[derive(Debug, sqlx::FromRow)]
pub struct ConsumedKeyPackage {
    pub key_package_hash: String,
    pub consumed_at: Option<DateTime<Utc>>,
    pub consumed_by_convo: Option<String>,
    pub cipher_suite: String,
}

pub async fn get_consumed_key_packages_paginated(
    pool: &DbPool,
    owner_did: &str,
    limit: i64,
    cursor: Option<String>,
) -> Result<(Vec<ConsumedKeyPackage>, Option<String>)> {
    let rows = if let Some(cursor_id) = cursor {
        sqlx::query_as::<_, ConsumedKeyPackage>(
            r#"
            SELECT
                key_package_hash,
                consumed_at,
                COALESCE(consumed_for_convo_id, consumed_by_convo) AS consumed_by_convo,
                cipher_suite
            FROM key_packages
            WHERE owner_did = $1
              AND consumed_at IS NOT NULL
              AND id < $3
            ORDER BY consumed_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(owner_did)
        .bind(limit)
        .bind(cursor_id)
        .fetch_all(pool)
        .await
        .context("Failed to fetch consumed key packages")?
    } else {
        sqlx::query_as::<_, ConsumedKeyPackage>(
            r#"
            SELECT
                key_package_hash,
                consumed_at,
                COALESCE(consumed_for_convo_id, consumed_by_convo) AS consumed_by_convo,
                cipher_suite
            FROM key_packages
            WHERE owner_did = $1
              AND consumed_at IS NOT NULL
            ORDER BY consumed_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(owner_did)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to fetch consumed key packages")?
    };

    // Generate next cursor if we got a full page
    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|r| r.key_package_hash.clone())
    } else {
        None
    };

    Ok((rows, next_cursor))
}

/// Reserve a key package for welcome validation (prevents race conditions)
/// Returns true if reservation successful, false if package not found/already consumed/already reserved
pub async fn reserve_key_package(
    pool: &DbPool,
    owner_did: &str,
    key_package_hash: &str,
    convo_id: &str,
) -> Result<bool> {
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);

    let result = sqlx::query!(
        r#"
        UPDATE key_packages
        SET reserved_at = $4, reserved_by_convo = $5
        WHERE owner_did = $1
          AND key_package_hash = $2
          AND consumed_at IS NULL
          AND (reserved_at IS NULL OR reserved_at < $3)
        "#,
        owner_did,
        key_package_hash,
        reservation_timeout,
        now,
        convo_id
    )
    .execute(pool)
    .await
    .context("Failed to reserve key package")?;

    Ok(result.rows_affected() > 0)
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
        assert_eq!(conversation.name, Some("Test Convo".to_string()));

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
            "msg-test-1",
            vec![1, 2, 3, 4],
            0,
            512,
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

/// Store reaction event with full payload (needed for cursor-based SSE replay)
pub async fn store_reaction_event(
    pool: &DbPool,
    cursor: &str,
    convo_id: &str,
    message_id: &str,
    did: &str,
    reaction: &str,
    action: &str,
) -> Result<()> {
    let envelope = serde_json::json!({
        "cursor": cursor,
        "convoId": convo_id,
        "messageId": message_id,
        "did": did,
        "reaction": reaction,
        "action": action,
    });

    sqlx::query!(
        r#"
        INSERT INTO event_stream (id, convo_id, event_type, payload, emitted_at)
        VALUES ($1, $2, 'reactionEvent', $3, NOW())
        "#,
        cursor,
        convo_id,
        envelope,
    )
    .execute(pool)
    .await
    .context("Failed to store reaction event")?;

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

// =============================================================================
// Key Package Notification Tracking
// =============================================================================

/// Record that a low inventory notification was sent to a user
/// Updates the timestamp if a record already exists
pub async fn record_low_inventory_notification(pool: &DbPool, user_did: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO key_package_notifications (user_did, notified_at, notification_type)
        VALUES ($1, $2, 'low_inventory')
        ON CONFLICT (user_did, notification_type)
        DO UPDATE SET notified_at = $2
        "#,
    )
    .bind(user_did)
    .bind(Utc::now())
    .execute(pool)
    .await
    .context("Failed to record low inventory notification")?;

    Ok(())
}

/// Check if a low inventory notification should be sent to a user
/// Returns true if:
/// - Never sent before, OR
/// - Last sent > 24 hours ago
pub async fn should_send_low_inventory_notification(pool: &DbPool, user_did: &str) -> Result<bool> {
    let last_sent: Option<DateTime<Utc>> = sqlx::query_scalar(
        r#"
        SELECT notified_at FROM key_package_notifications
        WHERE user_did = $1 AND notification_type = 'low_inventory'
        ORDER BY notified_at DESC LIMIT 1
        "#,
    )
    .bind(user_did)
    .fetch_optional(pool)
    .await
    .context("Failed to check last notification time")?;

    match last_sent {
        None => Ok(true), // Never sent before
        Some(sent_at) => {
            let elapsed = Utc::now().signed_duration_since(sent_at);
            Ok(elapsed.num_hours() >= 24) // Only send if 24+ hours have passed
        }
    }
}

/// Count available (unconsumed, non-reserved) key packages for a user
pub async fn count_available_key_packages(pool: &DbPool, user_did: &str) -> Result<i64> {
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM key_packages
        WHERE owner_did = $1
          AND consumed_at IS NULL
          AND expires_at > $2
          AND (reserved_at IS NULL OR reserved_at < $3)
        "#,
    )
    .bind(user_did)
    .bind(now)
    .bind(reservation_timeout)
    .fetch_one(pool)
    .await
    .context("Failed to count available key packages")?;

    Ok(count)
}

// =============================================================================
// Key Package Synchronization (NoMatchingKeyPackage Prevention)
// =============================================================================

/// Get available (unconsumed) key package hashes for a specific device
/// MULTI-DEVICE SUPPORT: Only returns packages belonging to this device
/// This prevents one device from seeing/deleting another device's packages
///
/// This is the PRIMARY function for key package sync - always use this
/// to ensure multi-device safety.
pub async fn get_available_key_package_hashes_for_device(
    pool: &DbPool,
    user_did: &str,
    device_id: &str,
) -> Result<Vec<String>> {
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);

    let hashes = sqlx::query_scalar::<_, String>(
        r#"
        SELECT key_package_hash
        FROM key_packages
        WHERE owner_did = $1
          AND device_id = $2
          AND consumed_at IS NULL
          AND expires_at > $3
          AND (reserved_at IS NULL OR reserved_at < $4)
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(now)
    .bind(reservation_timeout)
    .fetch_all(pool)
    .await
    .context("Failed to get available key package hashes for device")?;

    Ok(hashes)
}

/// Delete specific key packages by hash for a specific device
/// MULTI-DEVICE SUPPORT: Only deletes packages belonging to this device
/// This prevents one device from deleting another device's packages
///
/// This is the PRIMARY function for key package cleanup - always use this
/// to ensure multi-device safety.
pub async fn delete_key_packages_by_hashes_for_device(
    pool: &DbPool,
    user_did: &str,
    device_id: &str,
    hashes: &[String],
) -> Result<u64> {
    if hashes.is_empty() {
        return Ok(0);
    }

    // Use ANY array comparison for efficient batch deletion
    // CRITICAL: Also filter by device_id to prevent cross-device deletion
    let result = sqlx::query(
        r#"
        DELETE FROM key_packages
        WHERE owner_did = $1
          AND device_id = $2
          AND key_package_hash = ANY($3)
          AND consumed_at IS NULL
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(hashes)
    .execute(pool)
    .await
    .context("Failed to delete key packages by hashes for device")?;

    Ok(result.rows_affected())
}

/// Invalidate pending Welcome messages for a recipient when the referenced key packages are deleted.
///
/// `welcome_messages.key_package_hash` is BYTEA, while server key package hashes are stored/returned as hex TEXT.
pub async fn invalidate_welcomes_for_orphaned_key_packages(
    pool: &DbPool,
    user_did: &str,
    key_package_hashes_hex: &[String],
    reason: &str,
) -> Result<u64> {
    if key_package_hashes_hex.is_empty() {
        return Ok(0);
    }

    let result = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed = true,
            consumed_at = NOW(),
            error_reason = $3
        WHERE recipient_did = $1
          AND consumed = false
          AND key_package_hash IS NOT NULL
          AND encode(key_package_hash, 'hex') = ANY($2)
        "#,
    )
    .bind(user_did)
    .bind(key_package_hashes_hex)
    .bind(reason)
    .execute(pool)
    .await
    .context("Failed to invalidate welcomes for orphaned key packages")?;

    Ok(result.rows_affected())
}

// ==================== REACTIONS ====================

/// Check if a message exists in a conversation
pub async fn message_exists(pool: &DbPool, convo_id: &str, message_id: &str) -> Result<bool> {
    let result: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM messages
            WHERE convo_id = $1 AND id = $2
        )
        "#,
    )
    .bind(convo_id)
    .bind(message_id)
    .fetch_one(pool)
    .await
    .context("Failed to check message existence")?;

    Ok(result.0)
}

/// Add a reaction to a message
/// Returns true if inserted, false if already exists
pub async fn add_reaction(
    pool: &DbPool,
    convo_id: &str,
    message_id: &str,
    user_did: &str,
    reaction: &str,
    created_at: DateTime<Utc>,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        INSERT INTO message_reactions (convo_id, message_id, user_did, reaction, created_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (convo_id, message_id, user_did, reaction) DO NOTHING
        "#,
    )
    .bind(convo_id)
    .bind(message_id)
    .bind(user_did)
    .bind(reaction)
    .bind(created_at)
    .execute(pool)
    .await
    .context("Failed to insert reaction")?;

    Ok(result.rows_affected() > 0)
}

/// Remove a reaction from a message
/// Returns true if deleted, false if didn't exist
pub async fn remove_reaction(
    pool: &DbPool,
    convo_id: &str,
    message_id: &str,
    user_did: &str,
    reaction: &str,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM message_reactions
        WHERE convo_id = $1 AND message_id = $2 AND user_did = $3 AND reaction = $4
        "#,
    )
    .bind(convo_id)
    .bind(message_id)
    .bind(user_did)
    .bind(reaction)
    .execute(pool)
    .await
    .context("Failed to delete reaction")?;

    Ok(result.rows_affected() > 0)
}

/// Get all reactions for a message
pub async fn get_message_reactions(
    pool: &DbPool,
    convo_id: &str,
    message_id: &str,
) -> Result<Vec<(String, String, DateTime<Utc>)>> {
    let rows: Vec<(String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT user_did, reaction, created_at
        FROM message_reactions
        WHERE convo_id = $1 AND message_id = $2
        ORDER BY created_at ASC
        "#,
    )
    .bind(convo_id)
    .bind(message_id)
    .fetch_all(pool)
    .await
    .context("Failed to fetch reactions")?;

    Ok(rows)
}

/// Get reactions for multiple messages in a single query
pub async fn get_reactions_for_messages(
    pool: &DbPool,
    convo_id: &str,
    message_ids: &[&str],
) -> Result<std::collections::HashMap<String, Vec<crate::generated_types::ReactionView>>> {
    use crate::generated_types::ReactionView;
    use std::collections::HashMap;

    let rows: Vec<(String, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT message_id, user_did, reaction, created_at
        FROM message_reactions
        WHERE convo_id = $1 AND message_id = ANY($2)
        ORDER BY created_at ASC
        "#,
    )
    .bind(convo_id)
    .bind(message_ids)
    .fetch_all(pool)
    .await
    .context("Failed to fetch reactions for messages")?;

    let mut map: HashMap<String, Vec<ReactionView>> = HashMap::new();
    for (msg_id, user_did, reaction, created_at) in rows {
        map.entry(msg_id).or_default().push(ReactionView {
            user_did,
            reaction,
            created_at,
        });
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Delivery ACKs
// ---------------------------------------------------------------------------

/// Store a delivery acknowledgment received from a remote DS.
pub async fn store_delivery_ack(
    pool: &DbPool,
    ack: &crate::federation::ack::DeliveryAck,
) -> Result<()> {
    let id = ulid::Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO delivery_acks (id, message_id, convo_id, epoch, target_ds_did, acked_at, signature) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (convo_id, message_id, target_ds_did) DO UPDATE SET \
         acked_at = EXCLUDED.acked_at, \
         signature = EXCLUDED.signature",
    )
    .bind(&id)
    .bind(&ack.message_id)
    .bind(&ack.convo_id)
    .bind(ack.epoch)
    .bind(&ack.receiver_ds_did)
    .bind(ack.acked_at)
    .bind(&ack.signature)
    .execute(pool)
    .await
    .context("Failed to store delivery ack")?;
    Ok(())
}

/// Retrieve all delivery acknowledgments for a given message.
pub async fn get_delivery_acks_for_message(
    pool: &DbPool,
    convo_id: &str,
    message_id: &str,
) -> Result<Vec<crate::federation::ack::DeliveryAck>> {
    let rows: Vec<(String, String, i32, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT message_id, convo_id, epoch, target_ds_did, acked_at, signature \
         FROM delivery_acks WHERE convo_id = $1 AND message_id = $2 ORDER BY received_at ASC",
    )
    .bind(convo_id)
    .bind(message_id)
    .fetch_all(pool)
    .await
    .context("Failed to fetch delivery acks")?;

    Ok(rows
        .into_iter()
        .map(
            |(message_id, convo_id, epoch, receiver_ds_did, acked_at, signature)| {
                crate::federation::ack::DeliveryAck {
                    message_id,
                    convo_id,
                    epoch,
                    receiver_ds_did,
                    acked_at,
                    signature,
                }
            },
        )
        .collect())
}

/// Batch-fetch delivery ACKs for multiple messages in a single query.
pub async fn get_delivery_acks_for_messages(
    pool: &DbPool,
    convo_id: &str,
    message_ids: &[&str],
) -> Result<Vec<crate::federation::ack::DeliveryAck>> {
    let ids: Vec<String> = message_ids.iter().map(|s| s.to_string()).collect();
    let rows: Vec<(String, String, i32, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT message_id, convo_id, epoch, target_ds_did, acked_at, signature \
         FROM delivery_acks WHERE convo_id = $1 AND message_id = ANY($2) \
         ORDER BY message_id, received_at ASC LIMIT 500",
    )
    .bind(convo_id)
    .bind(&ids)
    .fetch_all(pool)
    .await
    .context("Failed to batch-fetch delivery acks")?;

    Ok(rows
        .into_iter()
        .map(
            |(message_id, convo_id, epoch, receiver_ds_did, acked_at, signature)| {
                crate::federation::ack::DeliveryAck {
                    message_id,
                    convo_id,
                    epoch,
                    receiver_ds_did,
                    acked_at,
                    signature,
                }
            },
        )
        .collect())
}

// =============================================================================
// Sequencer Receipts
// =============================================================================

/// Store a sequencer receipt (cryptographic proof of epoch assignment).
pub async fn store_sequencer_receipt(pool: &DbPool, receipt: &SequencerReceipt) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sequencer_receipts (convo_id, epoch, commit_hash, sequencer_did, issued_at, signature)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (convo_id, epoch) DO NOTHING
        "#,
    )
    .bind(&receipt.convo_id)
    .bind(receipt.epoch)
    .bind(&receipt.commit_hash)
    .bind(&receipt.sequencer_did)
    .bind(receipt.issued_at)
    .bind(&receipt.signature)
    .execute(pool)
    .await
    .context("Failed to store sequencer receipt")?;
    Ok(())
}

/// Get sequencer receipts for a conversation, optionally filtered by epoch.
pub async fn get_sequencer_receipts(
    pool: &DbPool,
    convo_id: &str,
    since_epoch: Option<i32>,
) -> Result<Vec<SequencerReceipt>> {
    let receipts = if let Some(epoch) = since_epoch {
        sqlx::query_as::<_, SequencerReceipt>(
            r#"
            SELECT convo_id, epoch, commit_hash, sequencer_did, issued_at, signature, created_at
            FROM sequencer_receipts
            WHERE convo_id = $1 AND epoch >= $2
            ORDER BY epoch DESC
            "#,
        )
        .bind(convo_id)
        .bind(epoch)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, SequencerReceipt>(
            r#"
            SELECT convo_id, epoch, commit_hash, sequencer_did, issued_at, signature, created_at
            FROM sequencer_receipts
            WHERE convo_id = $1
            ORDER BY epoch DESC
            "#,
        )
        .bind(convo_id)
        .fetch_all(pool)
        .await
    };
    receipts.context("Failed to fetch sequencer receipts")
}

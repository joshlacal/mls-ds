use anyhow::Result;
use sqlx::{Pool, Postgres, Sqlite};

pub type DbPool = Pool<Sqlite>; // Can switch to Postgres

pub async fn init_db(database_url: &str) -> Result<DbPool> {
    let pool = sqlx::SqlitePool::connect(database_url).await?;
    
    // Run migrations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            creator_did TEXT NOT NULL,
            current_epoch INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            title TEXT
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS memberships (
            convo_id TEXT NOT NULL,
            member_did TEXT NOT NULL,
            joined_at TEXT NOT NULL,
            left_at TEXT,
            unread_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (convo_id, member_did),
            FOREIGN KEY (convo_id) REFERENCES conversations(id)
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            convo_id TEXT NOT NULL,
            sender_did TEXT NOT NULL,
            message_type TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            sent_at TEXT NOT NULL,
            FOREIGN KEY (convo_id) REFERENCES conversations(id)
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS keypackages (
            did TEXT NOT NULL,
            cipher_suite TEXT NOT NULL,
            key_data BLOB NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (did, cipher_suite)
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS blobs (
            cid TEXT PRIMARY KEY,
            data BLOB NOT NULL,
            size INTEGER NOT NULL,
            uploaded_by_did TEXT NOT NULL,
            convo_id TEXT,
            uploaded_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn is_member(pool: &DbPool, did: &str, convo_id: &str) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM memberships WHERE member_did = ? AND convo_id = ? AND left_at IS NULL"
    )
    .bind(did)
    .bind(convo_id)
    .fetch_one(pool)
    .await?;
    
    Ok(result > 0)
}

pub async fn get_current_epoch(pool: &DbPool, convo_id: &str) -> Result<i32> {
    let epoch = sqlx::query_scalar::<_, i32>(
        "SELECT current_epoch FROM conversations WHERE id = ?"
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await?;
    
    Ok(epoch)
}

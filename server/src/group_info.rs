use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, FromRow};

#[derive(FromRow)]
struct GroupInfoRow {
    group_info: Option<Vec<u8>>,
    group_info_epoch: Option<i32>,
    group_info_updated_at: Option<DateTime<Utc>>,
}

/// Store GroupInfo for a conversation
pub async fn store_group_info(
    pool: &PgPool,
    convo_id: &str,
    group_info: &[u8],
    epoch: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE conversations 
         SET group_info = $1, 
             group_info_updated_at = NOW(),
             group_info_epoch = $2
         WHERE id = $3"
    )
    .bind(group_info)
    .bind(epoch)
    .bind(convo_id)
    .execute(pool)
    .await
    .context("Failed to store GroupInfo")?;

    Ok(())
}

/// Get cached GroupInfo for a conversation
pub async fn get_group_info(
    pool: &PgPool,
    convo_id: &str,
) -> Result<Option<(Vec<u8>, i32, DateTime<Utc>)>> {
    let row: Option<GroupInfoRow> = sqlx::query_as(
        "SELECT group_info, group_info_epoch, group_info_updated_at
         FROM conversations
         WHERE id = $1"
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch GroupInfo")?;

    if let Some(r) = row {
        if let (Some(info), Some(epoch), Some(updated_at)) = (r.group_info, r.group_info_epoch, r.group_info_updated_at) {
            return Ok(Some((info, epoch, updated_at)));
        }
    }

    Ok(None)
}

/// Generate and cache GroupInfo from current conversation state
pub async fn generate_and_cache_group_info(
    _pool: &PgPool,
    _convo_id: &str,
) -> Result<Vec<u8>> {
    Err(anyhow::anyhow!("Server-side GroupInfo generation not yet implemented. Clients must upload GroupInfo."))
}

/// Load MLS group state from storage
pub async fn load_mls_group_state(
    _pool: &PgPool,
    _convo_id: &str,
) -> Result<()> {
    Err(anyhow::anyhow!("Loading MLS group state not implemented"))
}

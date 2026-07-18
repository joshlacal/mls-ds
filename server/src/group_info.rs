use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

/// Legacy-row migration helper: older server builds accepted MLS wire bytes
/// wrapped as a JSON string (`CowStr`) and stored the UTF-8 of the base64
/// text into a `bytea` column. New readers expect raw bytes; serve such rows
/// transparently by detecting the ASCII+base64 shape and decoding once.
///
/// A real MLS wire blob starts with `0x00 0x01` (wire-format version 1);
/// if the first two bytes match, we pass through untouched. Otherwise, if
/// the payload is entirely printable ASCII (base64 alphabet + '=' padding)
/// and base64-decodes to bytes whose leading byte is `0x00`, we treat it
/// as a legacy row and emit the decoded form.
///
/// `label` is just a diagnostic string ("GroupInfo", "ciphertext", etc.)
/// for the `warn!` log when a legacy row is detected.
pub fn decode_legacy_if_needed(bytes: Vec<u8>, label: &str) -> Vec<u8> {
    let looks_raw = bytes.len() >= 2 && bytes[0] == 0x00 && bytes[1] == 0x01;
    if looks_raw {
        return bytes;
    }
    if !bytes.iter().all(|&b| b.is_ascii_graphic() || b == b'=') {
        return bytes;
    }
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(&bytes) {
        Ok(decoded) if decoded.len() >= 2 && decoded[0] == 0x00 => {
            tracing::warn!(
                label = %label,
                legacy_len = bytes.len(),
                decoded_len = decoded.len(),
                "Decoded legacy base64-text blob on read"
            );
            decoded
        }
        _ => bytes,
    }
}

/// Minimum valid GroupInfo size in bytes
/// A valid MLS GroupInfo with ratchet tree extension must be at least ~100 bytes
/// for the base structure (protocol version, cipher suite, group ID, epoch, etc.)
pub const MIN_GROUP_INFO_SIZE: usize = 100;

/// Maximum allowed GroupInfo size in bytes (10 MB)
/// GroupInfo grows with group size due to ratchet tree, but 10MB is excessive
pub const MAX_GROUP_INFO_SIZE: usize = 10 * 1024 * 1024;

#[derive(FromRow)]
struct GroupInfoRow {
    group_info: Option<Vec<u8>>,
    group_info_epoch: Option<i32>,
    group_info_updated_at: Option<DateTime<Utc>>,
}

/// Store GroupInfo for a conversation.
///
/// The epoch comparison lives in the UPDATE's WHERE clause (compare-and-set)
/// so a stale writer that lost a read-then-write race (see
/// `update_convo.rs::handle_upload_group_info`, finding F63) cannot roll the
/// cached GroupInfo backward: the write only lands when `epoch` is strictly
/// greater than the stored `group_info_epoch` (or none is stored yet).
///
/// Returns `Ok(true)` when the row was updated, `Ok(false)` when the CAS
/// rejected the write (stale/equal epoch, or unknown convo).
#[deprecated(
    note = "raw legacy write bypasses ADR-011 context CAS; migrate callers to CryptoSessionRepository::apply_transition"
)]
pub async fn store_group_info(
    pool: &PgPool,
    convo_id: &str,
    group_info: &[u8],
    epoch: i32,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE conversations
         SET group_info = $1,
             group_info_updated_at = NOW(),
             group_info_epoch = $2
         WHERE id = $3
           AND (group_info_epoch IS NULL OR group_info_epoch < $2)",
    )
    .bind(group_info)
    .bind(epoch)
    .bind(convo_id)
    .execute(pool)
    .await
    .context("Failed to store GroupInfo")?;

    Ok(result.rows_affected() > 0)
}

/// Get cached GroupInfo for a conversation
pub async fn get_group_info(
    pool: &PgPool,
    convo_id: &str,
) -> Result<Option<(Vec<u8>, i32, DateTime<Utc>)>> {
    let row: Option<GroupInfoRow> = sqlx::query_as(
        "SELECT group_info, group_info_epoch, group_info_updated_at
         FROM conversations
         WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch GroupInfo")?;

    if let Some(r) = row {
        if let (Some(info), Some(epoch), Some(updated_at)) =
            (r.group_info, r.group_info_epoch, r.group_info_updated_at)
        {
            let info = decode_legacy_if_needed(info, &format!("GroupInfo[{convo_id}]"));
            return Ok(Some((info, epoch, updated_at)));
        }
    }

    Ok(None)
}

/// Generate and cache GroupInfo from current conversation state
pub async fn generate_and_cache_group_info(_pool: &PgPool, _convo_id: &str) -> Result<Vec<u8>> {
    Err(anyhow::anyhow!(
        "Server-side GroupInfo generation not yet implemented. Clients must upload GroupInfo."
    ))
}

/// Load MLS group state from storage
pub async fn load_mls_group_state(_pool: &PgPool, _convo_id: &str) -> Result<()> {
    Err(anyhow::anyhow!("Loading MLS group state not implemented"))
}

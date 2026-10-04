//! The verifying head directory and the MLS device views
//! (`MailboxDirectory`, design §1a, §2 "Directory").

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{advisory_lock, PageReq};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::heads::{check_chain_link, verify_epoch_public};
use crate::labyrinth::wire::records::EpochPublic;

fn not_current() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "AttestationNotCurrent",
        "the attesting key is not a current chat device key of this DID",
    )
}

/// The key id of `did`'s *current* chat device key `key`, if any.
pub async fn current_chat_key_id(
    conn: &mut PgConnection,
    did: &str,
    key: &[u8; 32],
) -> LabyrinthResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT k.key_id FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.signing_public_key = $2 \
            AND k.revoked_at IS NULL AND d.status = 'active'",
    )
    .bind(did)
    .bind(key.as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

/// Accept `epoch` into `did`'s head chain (design §1a checks 1–5; check 6,
/// the caller being a device of `did`, holds because `did` is always the
/// authenticated DID). Re-sending an identical head succeeds; a different
/// head under a taken number is `EpochHeadConflict`.
pub async fn record_head(
    conn: &mut PgConnection,
    did: &str,
    epoch: &EpochPublic,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let parts = verify_epoch_public(did, epoch)?;
    let key_id = current_chat_key_id(conn, did, &parts.attestation_key)
        .await?
        .ok_or_else(not_current)?;
    advisory_lock(conn, &format!("labyrinth.epoch_heads:{did}")).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT epoch_public::text FROM labyrinth.epoch_heads \
          WHERE did = $1 AND epoch_number = $2",
    )
    .bind(did)
    .bind(parts.epoch_number as i64)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(text) = existing {
        let stored: EpochPublic = serde_json::from_str(&text).map_err(|error| {
            tracing::error!(?error, "stored epoch head does not parse");
            LabyrinthError::internal()
        })?;
        return if &stored == epoch {
            Ok(())
        } else {
            Err(LabyrinthError::new(
                axum::http::StatusCode::CONFLICT,
                "EpochHeadConflict",
                "a different head is already recorded for this epoch",
            ))
        };
    }
    let latest: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT epoch_number, epoch_head FROM labyrinth.epoch_heads \
          WHERE did = $1 ORDER BY epoch_number DESC LIMIT 1",
    )
    .bind(did)
    .fetch_optional(&mut *conn)
    .await?;
    let latest = latest
        .map(|(n, head)| -> LabyrinthResult<(u64, [u8; 32])> {
            Ok((
                n as u64,
                head.as_slice()
                    .try_into()
                    .map_err(|_| LabyrinthError::internal())?,
            ))
        })
        .transpose()?;
    check_chain_link(&parts, latest)?;
    let text = serde_json::to_string(epoch).map_err(|_| LabyrinthError::internal())?;
    sqlx::query(
        "INSERT INTO labyrinth.epoch_heads \
           (did, epoch_number, epoch_head, previous_epoch_head, epoch_public, \
            epoch_public_bytes, attestation_key_id, received_at) \
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)",
    )
    .bind(did)
    .bind(parts.epoch_number as i64)
    .bind(parts.head.as_slice())
    .bind(parts.previous_head.map(|h| h.to_vec()))
    .bind(&text)
    .bind(text.len() as i32)
    .bind(&key_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `getEpochHead`: the record and when it was received; `None` for latest.
pub async fn get_head(
    conn: &mut PgConnection,
    did: &str,
    n: Option<u64>,
) -> LabyrinthResult<Option<(serde_json::Value, DateTime<Utc>)>> {
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT epoch_public::text, received_at FROM labyrinth.epoch_heads \
          WHERE did = $1 AND ($2::bigint IS NULL OR epoch_number = $2) \
          ORDER BY epoch_number DESC LIMIT 1",
    )
    .bind(did)
    .bind(n.map(|n| n as i64))
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(text, at)| Ok((super::stored_json(&text)?, at)))
        .transpose()
}

/// One `getChatDeviceKeys` item.
pub struct ChatKeyRow {
    pub key_id: String,
    pub signing_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Every chat device key of `did`, revoked ones included (with the time).
/// The cursor is the last keyId.
pub async fn chat_device_keys(
    conn: &mut PgConnection,
    did: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<ChatKeyRow>, Option<String>)> {
    let mut rows: Vec<(String, Vec<u8>, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT k.key_id, k.signing_public_key, k.created_at, \
                COALESCE(k.revoked_at, d.revoked_at) \
           FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.key_id > $2 \
          ORDER BY k.key_id LIMIT $3",
    )
    .bind(did)
    .bind(page.cursor.clone().unwrap_or_default())
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.clone())).flatten();
    let items = rows
        .into_iter()
        .map(
            |(key_id, signing_public_key, created_at, revoked_at)| ChatKeyRow {
                key_id,
                signing_public_key,
                created_at,
                revoked_at,
            },
        )
        .collect();
    Ok((items, cursor))
}

/// Whether `did` ever was a participant of the conversation.
pub async fn ever_participant(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    did: &str,
) -> LabyrinthResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.participants \
                        WHERE conversation_id = $1 AND user_did = $2)",
    )
    .bind(conversation_id)
    .bind(did)
    .fetch_one(&mut *conn)
    .await?)
}

/// One `getMemberDevices` item: a device leaf period of `did`.
pub struct MemberDeviceRow {
    pub key_id: String,
    pub signing_public_key: Vec<u8>,
    pub joined_seq: i64,
    pub removed_seq: Option<i64>,
}

/// `did`'s device leaves in the conversation with the chat seqs that added
/// and removed each. Only a past or present participant may read a
/// conversation's leaf view; anyone else sees `ConversationNotFound`.
pub async fn member_devices(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    did: &str,
    caller_did: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<MemberDeviceRow>, Option<String>)> {
    if !ever_participant(conn, conversation_id, caller_did).await? {
        return Err(LabyrinthError::not_found("ConversationNotFound"));
    }
    let offset = page.seq_cursor()?;
    let mut rows: Vec<(String, Vec<u8>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT leaf_key_id, leaf_signature_key, joined_seq, removed_seq \
           FROM chat.member_devices \
          WHERE conversation_id = $1 AND user_did = $2 \
          ORDER BY joined_seq, leaf_period_id OFFSET $3 LIMIT $4",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(offset)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| (offset + page.limit()).to_string());
    let items = rows
        .into_iter()
        .map(
            |(key_id, signing_public_key, joined_seq, removed_seq)| MemberDeviceRow {
                key_id,
                signing_public_key,
                joined_seq,
                removed_seq,
            },
        )
        .collect();
    Ok((items, cursor))
}

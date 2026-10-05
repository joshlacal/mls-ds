//! The verifying head directory and the MLS device views
//! (`MailboxDirectory`, design §1a, §2 "Directory").

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{advisory_lock, PageReq};
use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::heads::{check_chain_link, verify_epoch_public, verify_prev_sig};
use crate::labyrinth::wire::records::EpochPublic;

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

fn not_caller() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "AttestationNotCaller",
        "the head must be attested by the calling chat device's own key",
    )
}

fn head_conflict() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::CONFLICT,
        "EpochHeadConflict",
        "a different head is already recorded for this epoch",
    )
}

fn parse_stored(text: &str) -> LabyrinthResult<EpochPublic> {
    serde_json::from_str(text).map_err(|error| {
        tracing::error!(?error, "stored epoch head does not parse");
        LabyrinthError::internal()
    })
}

/// Accept `epoch` into the caller DID's head chain (design §1a checks 1-6,
/// tightened by the second security review). The head recomputes, its
/// `selfSig` verifies, it is attested by the **calling** chat device's own
/// key (not merely any current key of the DID), and it extends the stored
/// latest head by one with a `prevSig` by that head's signing key.
/// Re-sending an identical head succeeds; a different head under a taken
/// number is `EpochHeadConflict`. Only `createEpoch` (inside its
/// transaction, after the binding check) and [`republish_head`] call this.
pub async fn record_head(
    conn: &mut PgConnection,
    caller: &Caller,
    epoch: &EpochPublic,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let did = caller.did.as_str();
    let parts = verify_epoch_public(did, epoch)?;
    if parts.attestation_key != caller.signing_key {
        return Err(not_caller());
    }
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
        return if &parse_stored(&text)? == epoch {
            Ok(())
        } else {
            Err(head_conflict())
        };
    }
    let latest: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
        "SELECT epoch_number, epoch_head, epoch_public::text FROM labyrinth.epoch_heads \
          WHERE did = $1 ORDER BY epoch_number DESC LIMIT 1",
    )
    .bind(did)
    .fetch_optional(&mut *conn)
    .await?;
    let latest = latest
        .map(|(n, head, text)| -> LabyrinthResult<_> {
            let head: [u8; 32] = head
                .as_slice()
                .try_into()
                .map_err(|_| LabyrinthError::internal())?;
            let signing = parse_stored(&text)?
                .signing_pubkey
                .array::<32>("signingPubkey")?;
            Ok((n as u64, head, signing))
        })
        .transpose()?;
    check_chain_link(&parts, latest.map(|(n, head, _)| (n, head)))?;
    if let Some((_, _, previous_signing_key)) = latest {
        verify_prev_sig(&parts, &previous_signing_key)?;
    }
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
    .bind(&caller.key_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `publishEpochHead`: re-publish the head of an epoch the caller's mailbox
/// already holds. Heads enter the directory only through `createEpoch`
/// (atomically, behind the Labyrinth device binding); this endpoint can
/// neither introduce an epoch nor squat the next number. The epoch must
/// exist in `labyrinth.epochs` with exactly this `public`, and the caller
/// must be the chat device that attested it.
pub async fn republish_head(
    conn: &mut PgConnection,
    caller: &Caller,
    epoch: &EpochPublic,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT (record->'public')::text FROM labyrinth.epochs \
          WHERE owner_did = $1 AND epoch_number = $2",
    )
    .bind(&caller.did)
    .bind(epoch.epoch_number as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let stored = stored.ok_or_else(|| LabyrinthError::not_found("EpochNotFound"))?;
    if &parse_stored(&stored)? != epoch {
        return Err(head_conflict());
    }
    record_head(conn, caller, epoch, at).await
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

//! The receiving side of the two outbox-delivered `labyrinthRelay` jobs
//! (`crate::labyrinth::repo::outbox`).

use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::labyrinth::auth::decode_b64;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::purge_auth;
use crate::labyrinth::relay::RelayRequest;
use crate::labyrinth::repo::{attachments, retention, thread::parse_thread_id};
use crate::labyrinth::wire::bytes::check_str;
use crate::labyrinth::wire::io::{body, to_bytes};
use crate::storage::DbPool;

fn now_ms() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap_or(now)
}

/// `purgeAuthor` on a sequencer: the account's device signed
/// `deleteAccountData` (accepted for 30 days, under the key current when it
/// signed); redact its items received before then in the conversations
/// where the requesting DS is its home DS. Naturally idempotent.
pub(super) async fn purge_author(
    pool: &DbPool,
    req: &RelayRequest,
    requester: &str,
) -> LabyrinthResult<Vec<u8>> {
    let (Some(device_id), Some(payload), Some(write_body), Some(write_signature), None) = (
        &req.actor_device_id,
        &req.payload,
        &req.write_body,
        &req.write_signature,
        &req.query,
    ) else {
        return Err(LabyrinthError::invalid(
            "purgeAuthor carries actorDeviceId, payload, writeBody and writeSignature",
        ));
    };
    let at = now_ms();
    let bound = purge_auth::verify(
        pool,
        &req.actor_did,
        device_id,
        &decode_b64("writeBody", write_body)?,
        &decode_b64("writeSignature", write_signature)?,
        &payload.0,
        at,
    )
    .await?;
    let mut tx = pool.begin().await?;
    let redacted =
        retention::redact_author(&mut tx, &req.actor_did, Some(requester), bound, at).await?;
    tx.commit().await?;
    to_bytes(&json!({ "redacted": redacted }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvalidateIn {
    thread_id: String,
    message_ids: Vec<String>,
}

/// `invalidateMessages` on a member's home DS: the conversation's own
/// sequencer announces that `actorDid` redacted these messages; drop the
/// references to that author's attachments and refuse new ones.
pub(super) async fn invalidate(
    pool: &DbPool,
    req: &RelayRequest,
    requester: &str,
) -> LabyrinthResult<Vec<u8>> {
    let (Some(payload), None, None, None, None) = (
        &req.payload,
        &req.query,
        &req.write_body,
        &req.read_header,
        &req.actor_device_id,
    ) else {
        return Err(LabyrinthError::invalid(
            "invalidateMessages carries actorDid and payload only",
        ));
    };
    let input: InvalidateIn = body(&payload.0)?;
    if input.message_ids.is_empty() || input.message_ids.len() > 10_000 {
        return Err(LabyrinthError::invalid("messageIds must name 1..=10000 ids"));
    }
    for id in &input.message_ids {
        check_str("messageIds", id, 128)?;
    }
    let conversation: Uuid = parse_thread_id(&input.thread_id)?;
    let sequencer: Option<Option<String>> = sqlx::query_scalar(
        "SELECT CASE WHEN is_remote THEN sequencer_ds END FROM chat.conversations \
          WHERE conversation_id = $1",
    )
    .bind(conversation)
    .fetch_optional(pool)
    .await?;
    match sequencer {
        Some(Some(s)) if crate::identity::dids_equivalent(&s, requester) => {}
        _ => {
            return Err(LabyrinthError::forbidden(
                "NotSequencer",
                "the requesting DS does not sequence this conversation here",
            ))
        }
    }
    let mut tx = pool.begin().await?;
    let removed = attachments::invalidate_messages(
        &mut tx,
        &input.thread_id,
        &req.actor_did,
        &input.message_ids,
        now_ms(),
    )
    .await?;
    tx.commit().await?;
    to_bytes(&json!({ "invalidated": removed }))
}

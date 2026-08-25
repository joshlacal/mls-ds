use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{auth::AuthUser, federation::FederationError, storage::DbPool};

use super::get_convo_digest::authorize_convo_read;

const NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const DEFAULT_LIMIT: i64 = 200;
const MAX_LIMIT: i64 = 1000;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoEventsParams {
    pub convo_id: String,
    pub after_seq: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvoEventEntry {
    pub seq: i64,
    pub epoch: i64,
    pub msg_id: String,
    pub message_type: String,
    #[serde(with = "crate::atproto_bytes")]
    pub ciphertext: Vec<u8>,
    pub padded_size: i64,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub signed_request: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub outer_fingerprint: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoEventsOutput {
    pub convo_id: String,
    pub from_seq_exclusive: i64,
    pub to_seq_inclusive: i64,
    pub events: Vec<ConvoEventEntry>,
}

#[derive(Debug, sqlx::FromRow)]
struct LegacyEventRow {
    seq: i64,
    epoch: i64,
    msg_id: Option<String>,
    message_type: String,
    ciphertext: Vec<u8>,
    padded_size: i64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct CleanEventRow {
    seq: i64,
    epoch: i64,
    entry_id: uuid::Uuid,
    message_id: Option<uuid::Uuid>,
    entry_kind: String,
    accepted_payload_bytes: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
    received_at: DateTime<Utc>,
}
/// GET /xrpc/blue.catbird.mlsDS.getConvoEvents
#[tracing::instrument(skip(pool, auth_user, query))]
pub async fn get_convo_events(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<GetConvoEventsParams>,
) -> Result<Json<GetConvoEventsOutput>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<GetConvoEventsOutput>, FederationError> = async {
        let state = authorize_convo_read(&pool, &query.convo_id, &requester_ds).await?;
        let from_seq = query.after_seq.unwrap_or(0).max(0);
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

        let (events, to_seq_inclusive) = if state.is_clean {
            let convo_uuid = uuid::Uuid::parse_str(&query.convo_id).map_err(|_| {
                FederationError::ConversationNotFound {
                    convo_id: query.convo_id.clone(),
                }
            })?;

            let rows: Vec<CleanEventRow> = sqlx::query_as::<_, CleanEventRow>(
                "SELECT \
                   CAST(seq AS BIGINT) AS seq, \
                   CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                   entry_id, \
                   message_id, \
                   entry_kind, \
                   accepted_payload_bytes, \
                   signed_request_bytes, \
                   outer_entry_fingerprint, \
                   received_at \
                 FROM chat.entries \
                 WHERE conversation_id = $1 AND seq > $2 \
                 ORDER BY seq ASC \
                 LIMIT $3",
            )
            .bind(convo_uuid)
            .bind(from_seq)
            .bind(limit)
            .fetch_all(&pool)
            .await
            .map_err(FederationError::Database)?;

            let events: Vec<ConvoEventEntry> = rows
                .into_iter()
                .map(|row| {
                    let msg_id = row
                        .message_id
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| row.entry_id.to_string());
                    let padded_size = row.accepted_payload_bytes.len() as i64;
                    ConvoEventEntry {
                        seq: row.seq,
                        epoch: row.epoch,
                        msg_id,
                        message_type: row.entry_kind.clone(),
                        ciphertext: row.accepted_payload_bytes,
                        padded_size,
                        created_at: row.received_at,
                        entry_id: Some(row.entry_id.to_string()),
                        entry_kind: Some(row.entry_kind),
                        signed_request: Some(row.signed_request_bytes),
                        outer_fingerprint: Some(row.outer_entry_fingerprint),
                    }
                })
                .collect();
            let to_seq = events.last().map(|e| e.seq).unwrap_or(from_seq);
            (events, to_seq)
        } else {
            let rows: Vec<LegacyEventRow> = sqlx::query_as::<_, LegacyEventRow>(
                "SELECT \
                   CAST(seq AS BIGINT) AS seq, \
                   CAST(epoch AS BIGINT) AS epoch, \
                   COALESCE(msg_id, id) AS msg_id, \
                   message_type, \
                   ciphertext, \
                   CAST(COALESCE(padded_size, 0) AS BIGINT) AS padded_size, \
                   created_at \
                 FROM messages \
                 WHERE convo_id = $1 AND seq > $2 \
                 ORDER BY seq ASC \
                 LIMIT $3",
            )
            .bind(&query.convo_id)
            .bind(from_seq)
            .bind(limit)
            .fetch_all(&pool)
            .await
            .map_err(FederationError::Database)?;

            let events: Vec<ConvoEventEntry> = rows
                .into_iter()
                .map(|row| ConvoEventEntry {
                    seq: row.seq,
                    epoch: row.epoch,
                    msg_id: row.msg_id.unwrap_or_default(),
                    message_type: row.message_type,
                    ciphertext: row.ciphertext,
                    padded_size: row.padded_size,
                    created_at: row.created_at,
                    entry_id: None,
                    entry_kind: None,
                    signed_request: None,
                    outer_fingerprint: None,
                })
                .collect();
            let to_seq = events.last().map(|e| e.seq).unwrap_or(from_seq);
            (events, to_seq)
        };
        Ok(Json(GetConvoEventsOutput {
            convo_id: state.convo_id,
            from_seq_exclusive: from_seq,
            to_seq_inclusive,
            events,
        }))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

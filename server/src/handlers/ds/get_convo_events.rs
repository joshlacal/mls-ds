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

#[derive(Debug, Serialize)]
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
struct EventRow {
    seq: i64,
    epoch: i64,
    msg_id: Option<String>,
    message_type: String,
    ciphertext: Vec<u8>,
    padded_size: i64,
    created_at: DateTime<Utc>,
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

        let rows: Vec<EventRow> = sqlx::query_as::<_, EventRow>(
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
            })
            .collect();
        let to_seq_inclusive = events.last().map(|e| e.seq).unwrap_or(from_seq);

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

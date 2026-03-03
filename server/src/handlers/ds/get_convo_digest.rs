use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use crate::{
    auth::AuthUser, federation::FederationError, identity::canonical_did, storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsDS.getConvoDigest";

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoDigestParams {
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvoDigestOutput {
    pub convo_id: String,
    pub sequencer_ds_did: String,
    pub sequencer_term: i64,
    pub epoch: i64,
    pub last_seq: i64,
    pub event_count: i64,
    pub digest_sha256: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub(super) struct ConvoAuthState {
    pub convo_id: String,
    pub sequencer_ds_did: String,
    pub sequencer_term: i64,
    pub epoch: i64,
}

#[derive(Debug, FromRow)]
struct DigestRow {
    seq: i64,
    epoch: i64,
    msg_id: Option<String>,
    message_type: String,
    ciphertext: Vec<u8>,
    padded_size: i64,
    created_at: DateTime<Utc>,
}

pub(super) async fn authorize_convo_read(
    pool: &DbPool,
    convo_id: &str,
    requester_ds: &str,
) -> Result<ConvoAuthState, FederationError> {
    let self_did = canonical_did(
        &std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string()),
    )
    .to_string();
    let row = sqlx::query_as::<_, (Option<String>, Option<i64>, Option<i64>, bool)>(
        "SELECT \
           c.sequencer_ds, \
           CAST(COALESCE(c.sequencer_term, 0) AS BIGINT), \
           CAST(COALESCE(c.current_epoch, 0) AS BIGINT), \
           EXISTS( \
             SELECT 1 FROM members m \
             WHERE m.convo_id = c.id \
               AND m.left_at IS NULL \
               AND COALESCE(split_part(m.ds_did, '#', 1), $2) = $3 \
           ) AS caller_is_member_ds \
         FROM conversations c \
         WHERE c.id = $1",
    )
    .bind(convo_id)
    .bind(&self_did)
    .bind(requester_ds)
    .fetch_optional(pool)
    .await
    .map_err(FederationError::Database)?;

    let Some((sequencer_ds, sequencer_term, epoch, caller_is_member_ds)) = row else {
        return Err(FederationError::ConversationNotFound {
            convo_id: convo_id.to_string(),
        });
    };

    let sequencer_ds_did = canonical_did(&sequencer_ds.unwrap_or(self_did)).to_string();
    if requester_ds != sequencer_ds_did && !caller_is_member_ds {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "DS {} is not authorized to read reconciliation state for {}",
                requester_ds, convo_id
            ),
        });
    }

    Ok(ConvoAuthState {
        convo_id: convo_id.to_string(),
        sequencer_ds_did,
        sequencer_term: sequencer_term.unwrap_or(0),
        epoch: epoch.unwrap_or(0),
    })
}

/// GET /xrpc/blue.catbird.mlsDS.getConvoDigest
#[tracing::instrument(skip(pool, auth_user, query))]
pub async fn get_convo_digest(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<GetConvoDigestParams>,
) -> Result<Json<GetConvoDigestOutput>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<GetConvoDigestOutput>, FederationError> = async {
        let state = authorize_convo_read(&pool, &query.convo_id, &requester_ds).await?;

        let (last_seq, event_count): (i64, i64) = sqlx::query_as(
            "SELECT CAST(COALESCE(MAX(seq), 0) AS BIGINT), CAST(COUNT(*) AS BIGINT) \
             FROM messages WHERE convo_id = $1",
        )
        .bind(&query.convo_id)
        .fetch_one(&pool)
        .await
        .map_err(FederationError::Database)?;

        let rows: Vec<DigestRow> = sqlx::query_as::<_, DigestRow>(
            "SELECT \
               CAST(seq AS BIGINT) AS seq, \
               CAST(epoch AS BIGINT) AS epoch, \
               COALESCE(msg_id, id) AS msg_id, \
               message_type, \
               ciphertext, \
               CAST(COALESCE(padded_size, 0) AS BIGINT) AS padded_size, \
               created_at \
             FROM messages \
             WHERE convo_id = $1 \
             ORDER BY seq ASC",
        )
        .bind(&query.convo_id)
        .fetch_all(&pool)
        .await
        .map_err(FederationError::Database)?;

        let digest_sha256 = compute_digest(&rows);
        let generated_at = Utc::now();

        Ok(Json(GetConvoDigestOutput {
            convo_id: state.convo_id,
            sequencer_ds_did: state.sequencer_ds_did,
            sequencer_term: state.sequencer_term,
            epoch: state.epoch,
            last_seq,
            event_count,
            digest_sha256,
            generated_at,
        }))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

fn compute_digest(rows: &[DigestRow]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-CONVO-DIGEST-V1:");
    for row in rows {
        hasher.update(row.seq.to_be_bytes());
        hasher.update(row.epoch.to_be_bytes());
        let msg_id = row.msg_id.as_deref().unwrap_or_default();
        hash_len_prefixed(&mut hasher, msg_id.as_bytes());
        hash_len_prefixed(&mut hasher, row.message_type.as_bytes());
        hash_len_prefixed(&mut hasher, &row.ciphertext);
        hasher.update(row.padded_size.to_be_bytes());
        hasher.update(row.created_at.timestamp_millis().to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

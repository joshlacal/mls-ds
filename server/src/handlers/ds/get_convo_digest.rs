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
pub(crate) struct ConvoAuthState {
    pub convo_id: String,
    pub sequencer_ds_did: String,
    pub sequencer_term: i64,
    pub epoch: i64,
    pub is_clean: bool,
}

#[derive(Debug, FromRow)]
pub(crate) struct LegacyDigestRow {
    pub seq: i64,
    pub epoch: i64,
    pub msg_id: Option<String>,
    pub message_type: String,
    pub ciphertext: Vec<u8>,
    pub padded_size: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub(crate) struct CleanDigestRow {
    pub seq: i64,
    pub epoch: i64,
    pub entry_id: uuid::Uuid,
    pub entry_kind: String,
    pub accepted_payload_bytes: Vec<u8>,
    pub signed_request_bytes: Vec<u8>,
    pub outer_entry_fingerprint: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

pub(crate) async fn authorize_convo_read(
    pool: &DbPool,
    convo_id: &str,
    requester_ds: &str,
) -> Result<ConvoAuthState, FederationError> {
    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let self_did = crate::identity::service_did_base();

    // 1. Check clean chat.conversations first if convo_id is a valid UUID
    if let Ok(convo_uuid) = uuid::Uuid::parse_str(convo_id) {
        let clean_row = sqlx::query_as::<_, (bool, Option<String>, i64, i64, bool)>(
            "SELECT \
               c.is_remote, \
               c.sequencer_ds, \
               c.sequencer_term, \
               COALESCE((SELECT MAX(generation) FROM chat.generations g WHERE g.conversation_id = c.conversation_id), 0) AS epoch, \
               EXISTS( \
                 SELECT 1 FROM chat.participants p \
                 WHERE p.conversation_id = c.conversation_id \
                   AND p.current_membership = TRUE \
                   AND COALESCE(p.ds_did, $2) = $3 \
               ) AS caller_is_member_ds \
             FROM chat.conversations c \
             WHERE c.conversation_id = $1",
        )
        .bind(convo_uuid)
        .bind(&self_did)
        .bind(requester_ds)
        .fetch_optional(pool)
        .await
        .map_err(FederationError::Database)?;

        if let Some((is_remote, sequencer_ds, sequencer_term, epoch, caller_is_member_ds)) =
            clean_row
        {
            let sequencer_ds_did = if is_remote {
                canonical_did(&sequencer_ds.unwrap_or_else(|| self_did.clone())).to_string()
            } else {
                canonical_did(&self_did).to_string()
            };

            if requester_ds != sequencer_ds_did && !caller_is_member_ds {
                return Err(FederationError::AuthFailed {
                    reason: format!(
                        "DS {} is not authorized to read reconciliation state for {}",
                        requester_ds, convo_id
                    ),
                });
            }

            return Ok(ConvoAuthState {
                convo_id: convo_id.to_string(),
                sequencer_ds_did,
                sequencer_term,
                epoch,
                is_clean: true,
            });
        }
    }

    // 2. Legacy fallback to conversations (public schema)
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
        is_clean: false,
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

        let (last_seq, event_count, digest_sha256) = if state.is_clean {
            let convo_uuid = uuid::Uuid::parse_str(&query.convo_id).map_err(|_| {
                FederationError::ConversationNotFound {
                    convo_id: query.convo_id.clone(),
                }
            })?;

            let (last_seq, event_count): (i64, i64) = sqlx::query_as(
                "SELECT CAST(COALESCE(MAX(seq), 0) AS BIGINT), CAST(COUNT(*) AS BIGINT) \
                 FROM chat.entries WHERE conversation_id = $1",
            )
            .bind(convo_uuid)
            .fetch_one(&pool)
            .await
            .map_err(FederationError::Database)?;

            let rows: Vec<CleanDigestRow> = sqlx::query_as::<_, CleanDigestRow>(
                "SELECT \
                   CAST(seq AS BIGINT) AS seq, \
                   CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
                   entry_id, \
                   entry_kind, \
                   accepted_payload_bytes, \
                   signed_request_bytes, \
                   outer_entry_fingerprint, \
                   received_at \
                 FROM chat.entries \
                 WHERE conversation_id = $1 \
                 ORDER BY seq ASC",
            )
            .bind(convo_uuid)
            .fetch_all(&pool)
            .await
            .map_err(FederationError::Database)?;

            let digest = compute_clean_convo_digest(&rows);
            (last_seq, event_count, digest)
        } else {
            let (last_seq, event_count): (i64, i64) = sqlx::query_as(
                "SELECT CAST(COALESCE(MAX(seq), 0) AS BIGINT), CAST(COUNT(*) AS BIGINT) \
                 FROM messages WHERE convo_id = $1",
            )
            .bind(&query.convo_id)
            .fetch_one(&pool)
            .await
            .map_err(FederationError::Database)?;

            let rows: Vec<LegacyDigestRow> = sqlx::query_as::<_, LegacyDigestRow>(
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

            let digest = compute_legacy_convo_digest(&rows);
            (last_seq, event_count, digest)
        };

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

pub(crate) fn compute_clean_convo_digest(rows: &[CleanDigestRow]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-CLEAN-CONVO-DIGEST-V1:");
    for row in rows {
        hasher.update(row.seq.to_be_bytes());
        hasher.update(row.epoch.to_be_bytes());
        hasher.update(row.entry_id.as_bytes());
        hash_len_prefixed(&mut hasher, row.entry_kind.as_bytes());
        hash_len_prefixed(&mut hasher, &row.accepted_payload_bytes);
        hash_len_prefixed(&mut hasher, &row.signed_request_bytes);
        hasher.update(&row.outer_entry_fingerprint);
        hasher.update(row.received_at.timestamp_millis().to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn compute_legacy_convo_digest(rows: &[LegacyDigestRow]) -> String {
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

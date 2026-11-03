use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
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
}

#[derive(Clone, Debug, FromRow)]
pub struct CleanDigestRow {
    pub seq: i64,
    pub epoch: i64,
    pub entry_id: uuid::Uuid,
    pub entry_kind: String,
    pub accepted_payload_bytes: Vec<u8>,
    pub accepted_payload_sha256: Vec<u8>,
    pub signed_request_bytes: Vec<u8>,
    pub outer_entry_fingerprint: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

pub(crate) async fn authorize_convo_read(
    pool: &DbPool,
    convo_id: &str,
    requester_ds: &str,
) -> Result<ConvoAuthState, FederationError> {
    let self_did = crate::identity::service_did_base();
    let convo_uuid =
        uuid::Uuid::parse_str(convo_id).map_err(|_| FederationError::ConversationNotFound {
            convo_id: convo_id.to_string(),
        })?;

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

    let Some((is_remote, sequencer_ds, sequencer_term, epoch, caller_is_member_ds)) = clean_row
    else {
        return Err(FederationError::ConversationNotFound {
            convo_id: convo_id.to_string(),
        });
    };

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

    let is_quarantined: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM federation_sync_state
            WHERE convo_id = $1 AND status = 'quarantined'
        )",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .map_err(FederationError::Database)?;

    if is_quarantined {
        return Err(FederationError::DeliveryConflict {
            reason: format!("conversation {} is quarantined", convo_id),
        });
    }

    Ok(ConvoAuthState {
        convo_id: convo_id.to_string(),
        sequencer_ds_did,
        sequencer_term,
        epoch,
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

        let mut stream = sqlx::query_as::<_, CleanDigestRow>(
            "SELECT \
               CAST(seq AS BIGINT) AS seq, \
               CAST(COALESCE(generation, 0) AS BIGINT) AS epoch, \
               entry_id, \
               entry_kind, \
               COALESCE(accepted_payload_bytes, ''::bytea) AS accepted_payload_bytes, \
               accepted_payload_sha256, \
               COALESCE(signed_request_bytes, ''::bytea) AS signed_request_bytes, \
               outer_entry_fingerprint, \
               received_at \
             FROM chat.entries \
             WHERE conversation_id = $1 \
             ORDER BY seq ASC",
        )
        .bind(convo_uuid)
        .fetch(&pool);

        let mut hasher = CleanConvoDigestHasher::new();
        while let Some(row) = stream.try_next().await.map_err(FederationError::Database)? {
            hasher.update_row(&row);
        }
        let digest_sha256 = hasher.finalize();
        let generated_at = crate::sim_hooks::current_utc();

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

#[derive(Default)]
pub struct CleanConvoDigestHasher {
    hasher: Sha256,
}

impl CleanConvoDigestHasher {
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"CATBIRD-CLEAN-CONVO-DIGEST-V1:");
        Self { hasher }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_event(
        &mut self,
        seq: i64,
        epoch: i64,
        entry_id: uuid::Uuid,
        entry_kind: &str,
        accepted_payload_bytes: &[u8],
        signed_request_bytes: &[u8],
        outer_entry_fingerprint: &[u8],
        received_at: DateTime<Utc>,
    ) {
        self.hasher.update(seq.to_be_bytes());
        self.hasher.update(epoch.to_be_bytes());
        self.hasher.update(entry_id.as_bytes());
        hash_len_prefixed(&mut self.hasher, entry_kind.as_bytes());
        hash_len_prefixed(&mut self.hasher, accepted_payload_bytes);
        hash_len_prefixed(&mut self.hasher, signed_request_bytes);
        self.hasher.update(outer_entry_fingerprint);
        self.hasher
            .update(received_at.timestamp_millis().to_be_bytes());
    }
    pub fn update_row(&mut self, row: &CleanDigestRow) {
        self.update_event(
            row.seq,
            row.epoch,
            row.entry_id,
            &row.entry_kind,
            &row.accepted_payload_bytes,
            &row.signed_request_bytes,
            &row.outer_entry_fingerprint,
            row.received_at,
        );
    }

    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

pub fn compute_clean_convo_digest(rows: &[CleanDigestRow]) -> String {
    let mut hasher = CleanConvoDigestHasher::new();
    for row in rows {
        hasher.update_row(row);
    }
    hasher.finalize()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mf09_streaming_digest_hashers_match_batch_digests() {
        assert_eq!(
            CleanConvoDigestHasher::new().finalize(),
            compute_clean_convo_digest(&[])
        );

        let now = Utc::now();
        let clean_rows = vec![
            CleanDigestRow {
                seq: 1,
                epoch: 0,
                entry_id: uuid::Uuid::from_bytes([0x11; 16]),
                entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
                accepted_payload_bytes: vec![1, 2, 3, 4],
                accepted_payload_sha256: vec![0xaa; 32],
                signed_request_bytes: vec![5, 6, 7],
                outer_entry_fingerprint: vec![0xbb; 32],
                received_at: now,
            },
            CleanDigestRow {
                seq: 2,
                epoch: 1,
                entry_id: uuid::Uuid::from_bytes([0x22; 16]),
                entry_kind: "blue.catbird.chat.defs#commitEntry".to_string(),
                accepted_payload_bytes: vec![8, 9],
                accepted_payload_sha256: vec![0xcc; 32],
                signed_request_bytes: vec![10],
                outer_entry_fingerprint: vec![0xdd; 32],
                received_at: now,
            },
        ];
        let mut clean_stream_hasher = CleanConvoDigestHasher::new();
        for row in &clean_rows {
            clean_stream_hasher.update_row(row);
        }
        assert_eq!(
            clean_stream_hasher.finalize(),
            compute_clean_convo_digest(&clean_rows)
        );
    }
}

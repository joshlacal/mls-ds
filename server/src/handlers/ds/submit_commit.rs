use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser,
    crypto::redact_for_log,
    federation::{CommitResult, FederationError, Sequencer},
    identity::canonical_did,
    storage::DbPool,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitCommit<'a> {
    #[serde(borrow)]
    convo_id: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    sender_ds_did: jacquard_common::CowStr<'a>,
    epoch: i64,
    proposed_epoch: i64,
    #[serde(with = "jacquard_common::serde_bytes_helper")]
    commit_data: bytes::Bytes,
}

const NSID: &str = "blue.catbird.mlsDS.submitCommit";

/// POST /xrpc/blue.catbird.mlsDS.submitCommit
///
/// Accept a commit for sequencing (sequencer role). Uses CAS ordering on epoch.
#[tracing::instrument(skip(pool, sequencer, auth_user, body))]
pub async fn submit_commit(
    State(pool): State<DbPool>,
    State(sequencer): State<Arc<Sequencer>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let commit: SubmitCommit<'_> = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid SubmitCommit body",
        )))
    })?;

    let convo_id = commit.convo_id.as_ref();
    let sender_ds = commit.sender_ds_did.as_ref();
    let epoch = commit.epoch as i32;
    let proposed_epoch = commit.proposed_epoch as i32;
    let raw_body: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid SubmitCommit body",
        )))
    })?;
    let sequencer_term = raw_body
        .get("sequencerTerm")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            FederationError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing or invalid sequencerTerm",
            )))
        })?;

    let security = super::deliver_message::enforce_ds_request_security(
        &pool,
        &auth_user,
        NSID,
        Some(sender_ds),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    // Determine our service DID for participant check
    let self_did = canonical_did(
        &std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string()),
    )
    .to_string();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let Some(sequencer_state) =
            super::deliver_message::load_convo_sequencer_state_optional(&pool, convo_id).await?
        else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };
        if canonical_did(&sequencer_state.expected_sequencer) != canonical_did(&self_did) {
            return Err(FederationError::NotSequencer {
                convo_id: convo_id.to_string(),
            });
        }
        if sequencer_term != sequencer_state.current_term {
            return Err(FederationError::TermStale {
                convo_id: convo_id.to_string(),
                provided_term: sequencer_term as i64,
                current_term: sequencer_state.current_term as i64,
            });
        }

        // Verify this DS is still the sequencer for the conversation (runtime check)
        let is_sequencer = sequencer
            .is_sequencer_for(convo_id)
            .await
            .map_err(FederationError::Database)?;

        if !is_sequencer {
            return Err(FederationError::NotSequencer {
                convo_id: convo_id.to_string(),
            });
        }

        // Ensure caller DS participates in the group (prevents arbitrary DS commit submissions).
        let caller_is_participant = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
               SELECT 1 FROM members \
               WHERE convo_id = $1 \
                 AND left_at IS NULL \
                 AND COALESCE(split_part(ds_did, '#', 1), $2) = $3 \
             )",
        )
        .bind(convo_id)
        .bind(&self_did)
        .bind(&requester_ds)
        .fetch_one(&pool)
        .await
        .map_err(FederationError::Database)?;
        if !caller_is_participant {
            return Err(FederationError::AuthFailed {
                reason: format!(
                    "DS {} is not a participant for conversation {}",
                    requester_ds, convo_id
                ),
            });
        }

        // Submit the commit for CAS ordering.
        //
        // TASK #36: the sequencer CAS runs INSIDE this tx. All three CAS
        // predicates (`convo_id`, `current_epoch`, `sequencer_term`) evaluate
        // on the same connection as the `commits` + `messages` inserts below.
        // A crash or rollback between the CAS and `tx.commit()` atomically
        // undoes the epoch advance — no orphan epochs on the federation path.
        // This is the federation-path completion of the task #18 orphan-epoch
        // fixes on the non-federation (mlsChat.commitGroupChange) path.
        //
        // Both `commits` (federation read path) and `messages` (client read
        // path) rows are now tied to the CAS: either all three land together
        // or none do.
        let commit_data_bytes = commit.commit_data.as_ref();
        let mut tx = pool.begin().await.map_err(FederationError::Database)?;
        let result = sequencer
            .submit_commit(
                &mut tx,
                convo_id,
                epoch,
                proposed_epoch,
                sequencer_term,
                commit_data_bytes,
            )
            .await
            .map_err(FederationError::Database)?;

        match result {
            CommitResult::Accepted {
                assigned_epoch,
                receipt,
            } => {
                // Store the commit data (federation read path: `commits` table)
                sqlx::query(
                    "INSERT INTO commits (convo_id, epoch, commit_data, sender_ds_did, created_at) \
                     VALUES ($1, $2, $3, $4, NOW()) \
                     ON CONFLICT (convo_id, epoch) DO NOTHING",
                )
                .bind(convo_id)
                .bind(assigned_epoch)
                .bind(commit.commit_data.as_ref())
                .bind(&requester_ds)
                .execute(&mut *tx)
                .await
                .map_err(FederationError::Database)?;

                // Mirror into `messages` so client `getMessages?type=commit`
                // can walk this commit when catching up from a lower epoch.
                // See handlers/mls_chat/get_messages.rs — the client catchup
                // path reads only the `messages` table.
                let msg_id = uuid::Uuid::new_v4().to_string();
                let seq: i64 = sqlx::query_scalar(
                    "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) \
                       FROM messages WHERE convo_id = $1",
                )
                .bind(convo_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(FederationError::Database)?;

                sqlx::query(
                    "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) \
                     VALUES ($1, $2, $3, 'commit', $4, $5, $6, NOW()) \
                     ON CONFLICT (convo_id, seq) DO NOTHING",
                )
                .bind(&msg_id)
                .bind(convo_id)
                .bind(Option::<&str>::None) // sender_did NULL — PRIV-001
                .bind(assigned_epoch)
                .bind(seq)
                .bind(commit.commit_data.as_ref())
                .execute(&mut *tx)
                .await
                .map_err(FederationError::Database)?;

                tx.commit().await.map_err(FederationError::Database)?;

                debug!(
                    convo = %redact_for_log(convo_id),
                    assigned_epoch,
                    sender_ds = %redact_for_log(sender_ds),
                    "Commit accepted and sequenced"
                );

                Ok(Json(json!({
                    "accepted": true,
                    "assignedEpoch": assigned_epoch,
                    "sequencerTerm": sequencer_term,
                    "receipt": receipt
                })))
            }
            CommitResult::TermStale {
                current_term,
                reason,
            } => {
                warn!(
                    convo = %redact_for_log(convo_id),
                    provided_term = sequencer_term,
                    current_term,
                    %reason,
                    "Commit rejected due to stale sequencer term"
                );
                Err(FederationError::TermStale {
                    convo_id: convo_id.to_string(),
                    provided_term: sequencer_term as i64,
                    current_term: current_term as i64,
                })
            }
            CommitResult::Conflict {
                current_epoch,
                reason,
            } => {
                warn!(
                    convo = %redact_for_log(convo_id),
                    current_epoch,
                    %reason,
                    "Commit conflict"
                );

                Err(FederationError::CommitConflict {
                    convo_id: convo_id.to_string(),
                    current_epoch,
                })
            }
        }
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser,
    federation::{CommitResult, FederationError, Sequencer},
    identity::canonical_did,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mls.ds.submitCommit";

/// POST /xrpc/blue.catbird.mls.ds.submitCommit
///
/// Accept a commit for sequencing (sequencer role). Uses CAS ordering on epoch.
#[tracing::instrument(skip(pool, sequencer, auth_user, body))]
pub async fn submit_commit(
    State(pool): State<DbPool>,
    State(sequencer): State<Arc<Sequencer>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let commit = crate::jacquard_json::from_json_body::<
        crate::generated::blue_catbird::mls::ds::submit_commit::SubmitCommit<'_>,
    >(&body)
    .map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid SubmitCommit body",
        )))
    })?;

    let convo_id = commit.convo_id.as_ref();
    let sender_ds = commit.sender_ds_did.as_ref();
    let epoch = commit.epoch as i32;
    let proposed_epoch = commit.proposed_epoch as i32;

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
        // Verify this DS is the sequencer for the conversation
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

        // Submit the commit for CAS ordering
        let commit_data_bytes = commit.commit_data.as_ref();
        let result = sequencer
            .submit_commit(convo_id, epoch, proposed_epoch, commit_data_bytes)
            .await
            .map_err(FederationError::Database)?;

        match result {
            CommitResult::Accepted {
                assigned_epoch,
                receipt,
            } => {
                // Store the commit data
                sqlx::query(
                    "INSERT INTO commits (convo_id, epoch, commit_data, sender_ds_did, created_at) \
                     VALUES ($1, $2, $3, $4, NOW()) \
                     ON CONFLICT (convo_id, epoch) DO NOTHING",
                )
                .bind(convo_id)
                .bind(assigned_epoch)
                .bind(commit.commit_data.as_ref())
                .bind(&requester_ds)
                .execute(&pool)
                .await
                .map_err(FederationError::Database)?;

                debug!(
                    convo_id,
                    assigned_epoch, sender_ds, "Commit accepted and sequenced"
                );

                Ok(Json(json!({
                    "accepted": true,
                    "assignedEpoch": assigned_epoch,
                    "receipt": receipt
                })))
            }
            CommitResult::Conflict {
                current_epoch,
                reason,
            } => {
                warn!(convo_id, current_epoch, %reason, "Commit conflict");

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

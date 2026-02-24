use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use crate::{
    auth::AuthUser,
    federation::{FederationError, SequencerTransfer},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mls.ds.transferSequencer";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferSequencerInput {
    convo_id: String,
    #[allow(dead_code)]
    current_epoch: Option<i32>,
    new_sequencer_term: u64,
}

/// POST /xrpc/blue.catbird.mls.ds.transferSequencer
///
/// Accept a sequencer role transfer from the current sequencer DS.
#[tracing::instrument(skip(pool, auth_user, body))]
pub async fn transfer_sequencer(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let transfer: TransferSequencerInput = serde_json::from_str(&body).map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid TransferSequencer body",
        )))
    })?;
    let convo_id = transfer.convo_id.as_str();
    let new_sequencer_term = transfer.new_sequencer_term;
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();
    let from_ds = requester_ds.as_str();

    let self_did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());

    let transfer_handler = SequencerTransfer::new(pool.clone(), self_did);

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let _result = transfer_handler
            .accept_transfer(convo_id, from_ds, new_sequencer_term)
            .await
            .map_err(|e| match e {
                crate::federation::TransferError::ConversationNotFound(id) => {
                    FederationError::ConversationNotFound { convo_id: id }
                }
                crate::federation::TransferError::NotCurrentSequencer {
                    convo_id,
                    current_sequencer,
                } => FederationError::NotSequencer {
                    convo_id: format!(
                        "{} (current sequencer: {}, requester: {})",
                        convo_id, current_sequencer, from_ds
                    ),
                },
                crate::federation::TransferError::Database(e) => FederationError::Database(e),
                crate::federation::TransferError::NotAuthorized { convo_id, ds_did } => {
                    FederationError::AuthFailed {
                        reason: format!(
                            "DS {ds_did} is not authorized for conversation {convo_id}"
                        ),
                    }
                }
                crate::federation::TransferError::TermStale {
                    convo_id,
                    current_term,
                    requested_term,
                } => FederationError::TermStale {
                    convo_id,
                    provided_term: requested_term as i64,
                    current_term: current_term as i64,
                },
                crate::federation::TransferError::TermJumpTooLarge {
                    convo_id,
                    current_term,
                    requested_term,
                    ..
                } => FederationError::TermStale {
                    convo_id,
                    provided_term: requested_term as i64,
                    current_term: current_term as i64,
                },
                crate::federation::TransferError::LeaseStillActive {
                    convo_id,
                    observed_age_secs,
                    required_age_secs,
                } => FederationError::TransferFailed {
                    reason: format!(
                        "sequencer lease still active for {convo_id}: {observed_age_secs}s < {required_age_secs}s"
                    ),
                },
            })?;

        debug!(convo_id, from_ds, "Accepted sequencer transfer");

        Ok(Json(json!({
            "accepted": true,
            "newSequencerTerm": new_sequencer_term
        })))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

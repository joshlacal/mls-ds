use axum::{extract::State, Json};
use serde_json::json;
use tracing::debug;

use crate::{
    auth::AuthUser,
    federation::{FederationError, SequencerTransfer},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mls.ds.transferSequencer";

/// POST /xrpc/blue.catbird.mls.ds.transferSequencer
///
/// Accept a sequencer role transfer from the current sequencer DS.
#[tracing::instrument(skip(pool, auth_user, body))]
pub async fn transfer_sequencer(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let transfer = crate::jacquard_json::from_json_body::<
        crate::generated::blue_catbird::mls::ds::transfer_sequencer::TransferSequencer<'_>,
    >(&body)
    .map_err(|_| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid TransferSequencer body",
        )))
    })?;

    let convo_id = transfer.convo_id.as_ref();
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();
    let from_ds = requester_ds.as_str();
    let current_epoch = transfer.current_epoch as i32;

    let self_did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:mls.catbird.blue".to_string());

    let transfer_handler = SequencerTransfer::new(pool.clone(), self_did);

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let _result = transfer_handler
            .accept_transfer(convo_id, from_ds, current_epoch)
            .await
            .map_err(|e| match e {
                crate::federation::TransferError::ConversationNotFound(id) => {
                    FederationError::ConversationNotFound { convo_id: id }
                }
                crate::federation::TransferError::NotCurrentSequencer {
                    convo_id,
                    current_sequencer,
                } => FederationError::AuthFailed {
                    reason: format!(
                        "Transfer rejected: {from_ds} is not the sequencer for {convo_id} (current: {current_sequencer})"
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
            })?;

        debug!(convo_id, from_ds, "Accepted sequencer transfer");

        Ok(Json(json!({ "accepted": true })))
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

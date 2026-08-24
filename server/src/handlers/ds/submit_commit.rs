use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
use jacquard_common::DefaultStr;
use tracing::debug;

use super::deliver_message::{enforce_ds_request_security, record_ds_outcome};
use crate::auth::AuthUser;
use crate::chat_protocol::repository::federation::submit_commit_sequencing;
use crate::federation::envelope::{validate_envelope_header, SUBMIT_COMMIT_NSID};
use crate::federation::{AckSigner, FederationError};
use crate::handlers::chat::ChatRuntime;
use crate::identity::{dids_equivalent, service_did_base};
use crate::storage::DbPool;

/// POST /xrpc/blue.catbird.mlsDS.submitCommit
///
/// Submit a signed commit transition to the sequencer DS for execution through the canonical transition planner and executor.
#[tracing::instrument(skip(pool, ack_signer, runtime, auth_user, body))]
pub async fn submit_commit(
    State(pool): State<DbPool>,
    State(ack_signer): State<Option<Arc<AckSigner>>>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<serde_json::Value>, FederationError> {
    let Some(signer) = ack_signer.as_deref() else {
        return Err(FederationError::SignerUnavailable);
    };

    let msg: SubmitCommit<DefaultStr> = serde_json::from_str(&body).map_err(|e| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid SubmitCommit body: {e}"),
        )))
    })?;

    if msg.extra_data.as_ref().is_some_and(|m| !m.is_empty()) {
        return Err(FederationError::InvalidEnvelope {
            reason: "unknown fields in SubmitCommit request".to_string(),
        });
    }

    let header = validate_envelope_header(&msg.header)?;

    let self_base_did = service_did_base();
    if !dids_equivalent(&header.receiver_ds_did, &self_base_did) {
        return Err(FederationError::InvalidEnvelope {
            reason: format!(
                "receiverDsDid '{}' does not match local service DID '{}'",
                header.receiver_ds_did, self_base_did
            ),
        });
    }

    let security = enforce_ds_request_security(
        &pool,
        &auth_user,
        SUBMIT_COMMIT_NSID,
        Some(&header.sender_ds_did),
    )
    .await?;
    let requester_ds = security.requester_ds.clone();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        let mut tx = pool.begin().await.map_err(FederationError::Database)?;

        let output = submit_commit_sequencing(
            &mut tx,
            signer,
            header,
            msg.signed_request_bytes.to_vec(),
            runtime.relationship_authority().as_ref(),
        )
        .await?;

        tx.commit().await.map_err(FederationError::Database)?;

        debug!(
            delivery_id = %output.receipt.delivery_id,
            convo = %output.receipt.conversation_id,
            "Executed federated submitCommit"
        );

        let value = serde_json::to_value(output).map_err(FederationError::Json)?;
        Ok(Json(value))
    }
    .await;

    record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

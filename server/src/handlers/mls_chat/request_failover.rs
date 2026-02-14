use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    federation::{self, DsResolver, FederatedBackend, FederationConfig, SequencerTransfer},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.requestFailover";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestFailoverInput {
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestFailoverOutput {
    pub new_sequencer_did: String,
    pub convo_id: String,
    pub epoch: i32,
}

/// POST /xrpc/blue.catbird.mlsChat.requestFailover
///
/// Client-facing endpoint to request sequencer failover when the current
/// sequencer DS is unreachable. Only members (preferably admins) may call
/// this. The handler health-checks the current sequencer before allowing
/// the takeover.
#[tracing::instrument(skip(
    pool,
    resolver,
    sequencer_transfer,
    fed_config,
    federated_backend,
    outbound_queue,
    auth_user,
    input
))]
pub async fn request_failover(
    State(pool): State<DbPool>,
    State(resolver): State<Arc<DsResolver>>,
    State(sequencer_transfer): State<Arc<SequencerTransfer>>,
    State(fed_config): State<FederationConfig>,
    State(federated_backend): State<Arc<FederatedBackend>>,
    State(outbound_queue): State<Arc<federation::queue::OutboundQueue>>,
    auth_user: AuthUser,
    Json(input): Json<RequestFailoverInput>,
) -> Result<Json<RequestFailoverOutput>, StatusCode> {
    // Enforce standard client auth
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify caller is a member of the conversation
    crate::auth::verify_is_member(&pool, &input.convo_id, &auth_user.did).await?;

    // Fetch current sequencer and epoch
    let row = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
        "SELECT sequencer_ds, current_epoch FROM conversations WHERE id = $1",
    )
    .bind(&input.convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (sequencer_ds, current_epoch) = match row {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let epoch = current_epoch.unwrap_or(0);
    let self_did = &fed_config.self_did;

    // If this DS is already the sequencer, return early
    let current_seq = sequencer_ds.unwrap_or_default();
    if current_seq.is_empty()
        || crate::identity::canonical_did(&current_seq) == crate::identity::canonical_did(self_did)
    {
        return Ok(Json(RequestFailoverOutput {
            new_sequencer_did: self_did.clone(),
            convo_id: input.convo_id,
            epoch,
        }));
    }

    // Resolve the current sequencer's endpoint for health-checking
    let sequencer_endpoint = match resolver.resolve(&current_seq).await {
        Ok(ep) => ep.endpoint,
        Err(_) => {
            // Can't even resolve → sequencer is unreachable
            warn!(
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                "Cannot resolve sequencer endpoint, assuming unreachable"
            );
            do_assume(
                &sequencer_transfer,
                &input.convo_id,
                self_did,
                epoch,
                &current_seq,
            )
            .await?;
            let new_epoch = increment_epoch(&pool, &input.convo_id).await?;
            broadcast_sequencer_change(
                &federated_backend,
                &outbound_queue,
                &input.convo_id,
                self_did,
                new_epoch,
            );
            return Ok(Json(RequestFailoverOutput {
                new_sequencer_did: self_did.clone(),
                convo_id: input.convo_id,
                epoch: new_epoch,
            }));
        }
    };

    // Health-check the current sequencer (15s timeout)
    let health_url = format!(
        "{}/xrpc/blue.catbird.mls.ds.healthCheck",
        sequencer_endpoint.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Sequencer is healthy — failover not needed
            info!(
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                "Sequencer is healthy, failover denied"
            );
            return Err(StatusCode::CONFLICT);
        }
        Ok(resp) => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                status = %resp.status(),
                "Sequencer returned unhealthy status"
            );
        }
        Err(e) => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                error = %e,
                "Sequencer health check failed"
            );
        }
    }

    // Sequencer is unreachable — assume the role
    do_assume(
        &sequencer_transfer,
        &input.convo_id,
        self_did,
        epoch,
        &current_seq,
    )
    .await?;
    let new_epoch = increment_epoch(&pool, &input.convo_id).await?;

    // Best-effort broadcast to all remote DSes (non-blocking)
    broadcast_sequencer_change(
        &federated_backend,
        &outbound_queue,
        &input.convo_id,
        self_did,
        new_epoch,
    );

    Ok(Json(RequestFailoverOutput {
        new_sequencer_did: self_did.clone(),
        convo_id: input.convo_id,
        epoch: new_epoch,
    }))
}

/// Atomically increment the conversation epoch after a failover to prevent
/// the old and new sequencer from accepting commits at the same epoch.
async fn increment_epoch(pool: &DbPool, convo_id: &str) -> Result<i32, StatusCode> {
    let new_epoch: i32 = sqlx::query_scalar(
        "UPDATE conversations SET current_epoch = current_epoch + 1 WHERE id = $1 RETURNING current_epoch",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(
            convo_id = %crate::crypto::redact_for_log(convo_id),
            error = %e,
            "Failed to increment epoch"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        convo_id = %crate::crypto::redact_for_log(convo_id),
        new_epoch,
        "Epoch incremented after failover"
    );
    Ok(new_epoch)
}

async fn do_assume(
    transfer: &SequencerTransfer,
    convo_id: &str,
    self_did: &str,
    epoch: i32,
    expected_sequencer: &str,
) -> Result<(), StatusCode> {
    transfer
        .assume_sequencer_role(convo_id, expected_sequencer)
        .await
        .map_err(|e| {
            error!("Failed to assume sequencer role: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        convo_id = %crate::crypto::redact_for_log(convo_id),
        new_sequencer = %crate::crypto::redact_for_log(self_did),
        epoch,
        "Failover complete — assumed sequencer role"
    );
    Ok(())
}

/// Spawn a background task to broadcast the sequencer change to all remote DSes.
/// Best-effort via the outbound queue with retries — does not block the response.
fn broadcast_sequencer_change(
    federated_backend: &Arc<FederatedBackend>,
    outbound_queue: &Arc<federation::queue::OutboundQueue>,
    convo_id: &str,
    new_sequencer_did: &str,
    epoch: i32,
) {
    let fb = Arc::clone(federated_backend);
    let oq = Arc::clone(outbound_queue);
    let convo_id = convo_id.to_string();
    let new_seq = new_sequencer_did.to_string();

    tokio::spawn(async move {
        let ds_dids = match fb.get_participant_ds_dids(&convo_id).await {
            Ok(dids) => dids,
            Err(e) => {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    error = %e,
                    "Failed to get participant DS DIDs for failover broadcast"
                );
                return;
            }
        };

        let payload = serde_json::json!({
            "convoId": convo_id,
            "currentEpoch": epoch,
        });
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize failover broadcast payload");
                return;
            }
        };

        for ds_did in ds_dids {
            if crate::identity::dids_equivalent(&ds_did, &new_seq) {
                continue;
            }

            let target_endpoint = ds_did
                .strip_prefix("did:web:")
                .map(|path| format!("https://{}", path.replace(':', "/")))
                .unwrap_or_default();

            if let Err(e) = oq
                .enqueue(
                    &ds_did,
                    &target_endpoint,
                    "blue.catbird.mls.ds.transferSequencer",
                    &payload_bytes,
                    &convo_id,
                    "failover broadcast",
                )
                .await
            {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    target_ds = %crate::crypto::redact_for_log(&ds_did),
                    error = %e,
                    "Failed to enqueue failover broadcast (non-fatal)"
                );
            }
        }

        info!(
            convo_id = %crate::crypto::redact_for_log(&convo_id),
            new_sequencer = %crate::crypto::redact_for_log(&new_seq),
            "Failover broadcast enqueued to remote DSes"
        );
    });
}

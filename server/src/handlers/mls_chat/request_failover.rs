use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    federation::{self, DsResolver, FederatedBackend, FederationConfig, SequencerTransfer},
    generated::blue_catbird::mlsChat::request_failover::{
        RequestFailover, RequestFailoverOutput, RequestFailoverRequest,
    },
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.requestFailover";

/// Build a `RequestFailoverOutput` for the success path.
///
/// Centralized so every construction site funnels through the same
/// type-conversion surface and we don't re-implement `i32 → i64` / `u64 → i64`
/// casts at every call-site.
fn make_output(
    new_sequencer_did: &str,
    convo_id: &str,
    epoch: i32,
    sequencer_term: u64,
) -> RequestFailoverOutput {
    RequestFailoverOutput {
        new_sequencer_did: crate::sqlx_jacquard::string_to_did(new_sequencer_did),
        convo_id: convo_id.into(),
        epoch: epoch as i64,
        sequencer_term: sequencer_term as i64,
        extra_data: Default::default(),
    }
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
    ExtractXrpc(input): ExtractXrpc<RequestFailoverRequest>,
) -> Result<Json<RequestFailoverOutput>, StatusCode> {
    // The `ExtractXrpc` associated type is `RequestFailover` (borrowed);
    // name it explicitly so the rest of the function reads naturally.
    let input: RequestFailover = input;
    let convo_id: String = input.convo_id.as_str().to_string();

    // Enforce standard client auth
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify caller is a member of the conversation
    crate::auth::verify_is_member(&pool, &convo_id, &auth_user.did).await?;

    // Fetch current sequencer (federation) and epoch (via CryptoSession projection)
    let row = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
        "SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1",
    )
    .bind(&convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (sequencer_ds, current_term_raw) = match row {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // TODO(phase 4): read epoch from `crypto_sessions.last_observed_epoch`
    // once `try_advance_conversation_epoch_tx` (db.rs) advances both
    // `conversations.current_epoch` AND `crypto_sessions.last_observed_epoch`
    // in the same tx. Until then `last_observed_epoch` is stale after
    // every accepted commit (see merged_bug_001 from ultrareview;
    // mirrors the send_message.rs:212 revert from PR review #20).
    let epoch: i32 = sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
        .bind(&convo_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch current epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    let sequencer_term = current_term_raw.unwrap_or(0).max(0) as u64;
    let self_did = &fed_config.self_did;

    // If this DS is already the sequencer, return early
    let current_seq = sequencer_ds.unwrap_or_default();
    if current_seq.is_empty()
        || crate::identity::canonical_did(&current_seq) == crate::identity::canonical_did(self_did)
    {
        return Ok(Json(make_output(
            self_did,
            &convo_id,
            epoch,
            sequencer_term,
        )));
    }

    // Resolve the current sequencer's endpoint for health-checking
    let sequencer_endpoint = match resolver.resolve(&current_seq).await {
        Ok(ep) => ep.endpoint,
        Err(_) => {
            // Can't even resolve → sequencer is unreachable
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                "Cannot resolve sequencer endpoint, assuming unreachable"
            );
            let (new_epoch, new_term) =
                do_assume(&sequencer_transfer, &convo_id, self_did, &current_seq).await?;
            broadcast_sequencer_change(
                &federated_backend,
                &outbound_queue,
                &convo_id,
                self_did,
                new_epoch,
                new_term,
            );
            return Ok(Json(make_output(self_did, &convo_id, new_epoch, new_term)));
        }
    };

    // Health-check the current sequencer (15s timeout)
    let health_url = format!(
        "{}/xrpc/blue.catbird.mlsDS.healthCheck",
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
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                "Sequencer is healthy, failover denied"
            );
            return Err(StatusCode::CONFLICT);
        }
        Ok(resp) => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                status = %resp.status(),
                "Sequencer returned unhealthy status"
            );
        }
        Err(e) => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                sequencer = %crate::crypto::redact_for_log(&current_seq),
                error = %e,
                "Sequencer health check failed"
            );
        }
    }

    // Sequencer is unreachable — assume the role
    let (new_epoch, new_term) =
        do_assume(&sequencer_transfer, &convo_id, self_did, &current_seq).await?;

    // Best-effort broadcast to all remote DSes (non-blocking)
    broadcast_sequencer_change(
        &federated_backend,
        &outbound_queue,
        &convo_id,
        self_did,
        new_epoch,
        new_term,
    );

    Ok(Json(make_output(self_did, &convo_id, new_epoch, new_term)))
}

async fn do_assume(
    transfer: &SequencerTransfer,
    convo_id: &str,
    self_did: &str,
    expected_sequencer: &str,
) -> Result<(i32, u64), StatusCode> {
    let result = transfer
        .assume_sequencer_role(convo_id, expected_sequencer)
        .await
        .map_err(|e| {
            error!("Failed to assume sequencer role: {}", e);
            match e {
                crate::federation::TransferError::ConversationNotFound(_) => StatusCode::NOT_FOUND,
                crate::federation::TransferError::NotAuthorized { .. } => StatusCode::FORBIDDEN,
                crate::federation::TransferError::NotCurrentSequencer { .. }
                | crate::federation::TransferError::TermStale { .. }
                | crate::federation::TransferError::TermJumpTooLarge { .. }
                | crate::federation::TransferError::LeaseStillActive { .. } => StatusCode::CONFLICT,
                crate::federation::TransferError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    let (new_epoch, new_sequencer_term) = match result {
        crate::federation::TransferResult::Accepted {
            new_epoch,
            new_sequencer_term,
            ..
        } => (new_epoch, new_sequencer_term),
        crate::federation::TransferResult::Transferred { .. } => {
            error!("Unexpected transfer result while assuming sequencer role");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!(
        convo_id = %crate::crypto::redact_for_log(convo_id),
        new_sequencer = %crate::crypto::redact_for_log(self_did),
        epoch = new_epoch,
        sequencer_term = new_sequencer_term,
        "Failover complete — assumed sequencer role"
    );
    Ok((new_epoch, new_sequencer_term))
}

/// Spawn a background task to broadcast the sequencer change to all remote DSes.
/// Best-effort via the outbound queue with retries — does not block the response.
fn broadcast_sequencer_change(
    federated_backend: &Arc<FederatedBackend>,
    outbound_queue: &Arc<federation::queue::OutboundQueue>,
    convo_id: &str,
    new_sequencer_did: &str,
    epoch: i32,
    new_sequencer_term: u64,
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
            "newSequencerTerm": new_sequencer_term,
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

            if let Err(e) = oq
                .enqueue(
                    &ds_did,
                    "",
                    "blue.catbird.mlsDS.transferSequencer",
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

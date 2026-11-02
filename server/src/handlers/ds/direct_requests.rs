//! DS-to-DS handlers for canonical blue.catbird.chat direct requests.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    chat_protocol::validation::TrustedRequestInstant,
    federation::{
        canonical_relay::{
            self, DeliverAcceptanceEntryInput, DeliverAcceptanceInput, DeliverAcceptanceOutput,
            DeliverDirectRequestInput, DeliverMessageEntryInput, RelaySendMessageInput,
            ReserveRecipientBootstrapInput, ReserveRecipientBootstrapOutput,
        },
        FederationError,
    },
    handlers::chat::ChatRuntime,
    storage::DbPool,
};

use super::deliver_message::enforce_ds_request_security;

const RESERVE_BOOTSTRAP_NSID: &str = "blue.catbird.mlsDS.reserveRecipientBootstrap";
const RELEASE_BOOTSTRAP_NSID: &str = "blue.catbird.mlsDS.releaseRecipientBootstrap";
const PREPARE_NSID: &str = "blue.catbird.mlsDS.prepareDirectRequest";
const PUBLISH_NSID: &str = "blue.catbird.mlsDS.publishDirectRequest";
const DELIVER_REQUEST_NSID: &str = "blue.catbird.mlsDS.deliverDirectRequest";
const DELIVER_ACCEPT_NSID: &str = "blue.catbird.mlsDS.deliverAcceptance";
const DELIVER_ACCEPT_ENTRY_NSID: &str = "blue.catbird.mlsDS.deliverAcceptanceEntry";
const RELAY_SEND_MESSAGE_NSID: &str = "blue.catbird.mlsDS.relaySendMessage";
const DELIVER_MESSAGE_ENTRY_NSID: &str = "blue.catbird.mlsDS.deliverMessageEntry";
const GET_OUTCOME_NSID: &str = "blue.catbird.mlsDS.getDirectRequestOutcome";

/// POST /xrpc/blue.catbird.mlsDS.reserveRecipientBootstrap
pub async fn reserve_recipient_bootstrap(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<ReserveRecipientBootstrapInput>,
) -> Result<Json<ReserveRecipientBootstrapOutput>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, RESERVE_BOOTSTRAP_NSID, None).await?;
    let selected_devices =
        canonical_relay::local_reserve_recipient_bootstrap(&pool, &security.requester_ds, &input)
            .await?;
    Ok(Json(ReserveRecipientBootstrapOutput { selected_devices }))
}
/// POST /xrpc/blue.catbird.mlsDS.releaseRecipientBootstrap
pub async fn release_recipient_bootstrap(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<canonical_relay::ReleaseRecipientBootstrapInput>,
) -> Result<Json<Value>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, RELEASE_BOOTSTRAP_NSID, None).await?;
    canonical_relay::local_release_recipient_bootstrap(
        &pool,
        &security.requester_ds,
        input.request_id,
        &input.recipient_did,
    )
    .await?;
    Ok(Json(json!({ "released": true })))
}

/// POST /xrpc/blue.catbird.mlsDS.prepareDirectRequest
pub async fn prepare_direct_request(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<Value>,
) -> Result<Json<Value>, FederationError> {
    let security = enforce_ds_request_security(&pool, &auth_user, PREPARE_NSID, None).await?;
    let outcome = canonical_relay::coordinator_prepare_direct_request(
        &pool,
        &runtime,
        &security.requester_ds,
        &input,
    )
    .await?;
    Ok(Json(outcome))
}

/// POST /xrpc/blue.catbird.mlsDS.publishDirectRequest
pub async fn publish_direct_request(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<Value>,
) -> Result<Json<Value>, FederationError> {
    let security = enforce_ds_request_security(&pool, &auth_user, PUBLISH_NSID, None).await?;
    let outcome = canonical_relay::coordinator_publish_direct_request(
        &pool,
        &runtime,
        &security.requester_ds,
        &input,
    )
    .await?;
    Ok(Json(outcome))
}

/// POST /xrpc/blue.catbird.mlsDS.deliverDirectRequest
pub async fn deliver_direct_request(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<DeliverDirectRequestInput>,
) -> Result<Json<Value>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, DELIVER_REQUEST_NSID, None).await?;
    canonical_relay::ingest_remote_direct_request_delivery(
        &pool,
        Some(runtime.sse_state()),
        &security.requester_ds,
        input,
    )
    .await?;
    Ok(Json(json!({ "accepted": true, "delivered": true })))
}

/// POST /xrpc/blue.catbird.mlsDS.deliverAcceptance
pub async fn deliver_acceptance(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<DeliverAcceptanceInput>,
) -> Result<Json<DeliverAcceptanceOutput>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, DELIVER_ACCEPT_NSID, None).await?;
    let output = canonical_relay::coordinator_accept_direct_request(
        &pool,
        &runtime,
        &security.requester_ds,
        input.conversation_id,
        &input.direct_request,
    )
    .await?;
    Ok(Json(output))
}

/// POST /xrpc/blue.catbird.mlsDS.deliverAcceptanceEntry
pub async fn deliver_acceptance_entry(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<DeliverAcceptanceEntryInput>,
) -> Result<Json<Value>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, DELIVER_ACCEPT_ENTRY_NSID, None).await?;
    canonical_relay::ingest_remote_acceptance_entry(
        &pool,
        Some(runtime.sse_state()),
        &security.requester_ds,
        input.conversation_id,
        &input.entry,
        &input.acceptance_proof,
    )
    .await?;
    Ok(Json(json!({ "accepted": true, "delivered": true })))
}

/// POST /xrpc/blue.catbird.mlsDS.relaySendMessage
pub async fn relay_send_message(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<RelaySendMessageInput>,
) -> Result<Json<Value>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, RELAY_SEND_MESSAGE_NSID, None).await?;
    let output = canonical_relay::coordinator_handle_message(
        &pool,
        &runtime,
        &security.requester_ds,
        input.conversation_id,
        &input.message,
    )
    .await?;
    Ok(Json(output))
}

/// POST /xrpc/blue.catbird.mlsDS.deliverMessageEntry
pub async fn deliver_message_entry(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Json(input): Json<DeliverMessageEntryInput>,
) -> Result<Json<Value>, FederationError> {
    let security =
        enforce_ds_request_security(&pool, &auth_user, DELIVER_MESSAGE_ENTRY_NSID, None).await?;
    canonical_relay::ingest_remote_message_entry(
        &pool,
        Some(runtime.sse_state()),
        &security.requester_ds,
        input.conversation_id,
        &input.entry,
    )
    .await?;
    runtime.notify_events();

    if let Some(push_client) = runtime.push_gateway_client() {
        let actor_did = input
            .entry
            .pointer("/signedRequest/body/actorDid")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let inbox_rows: Vec<(String, Option<Uuid>, String, Uuid)> = sqlx::query_as(
            "SELECT sender_did, sender_device_id, recipient_did, recipient_device_id \
               FROM chat.direct_request_transport_inbox \
              WHERE conversation_id = $1 AND status = 'accepted'",
        )
        .bind(input.conversation_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        let mut candidates: Vec<(String, Uuid)> = Vec::new();
        for (sender_did, sender_dev_opt, recipient_did, recipient_dev) in inbox_rows {
            if crate::identity::canonical_did(&recipient_did)
                != crate::identity::canonical_did(actor_did)
            {
                candidates.push((recipient_did, recipient_dev));
            }
            if let Some(sender_dev) = sender_dev_opt {
                if crate::identity::canonical_did(&sender_did)
                    != crate::identity::canonical_did(actor_did)
                {
                    candidates.push((sender_did, sender_dev));
                }
            }
        }
        candidates.sort();
        candidates.dedup();

        if !candidates.is_empty() {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let seq = input.entry.get("seq").and_then(Value::as_i64).unwrap_or(0);
            let generation = input
                .entry
                .pointer("/signedRequest/body/prior/generation")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let epoch = input
                .entry
                .pointer("/signedRequest/body/prior/epoch")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let ct = input
                .entry
                .pointer("/signedRequest/body/applicationMessage/bytes")
                .and_then(|v| {
                    v.as_str()
                        .or_else(|| v.get("$bytes").and_then(Value::as_str))
                })
                .and_then(|s| {
                    STANDARD
                        .decode(s)
                        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
                        .ok()
                });
            let _ = push_client
                .dispatch_for_local_recipients(
                    &pool,
                    &candidates,
                    crate::push_gateway::client::PushWakeDispatch {
                        wake_kind: crate::push_gateway::client::PushWakeKind::ApplicationMessage,
                        conversation_id: input.conversation_id,
                        generation,
                        seq,
                        epoch,
                        ciphertext: ct,
                    },
                )
                .await;
        }
    }

    Ok(Json(json!({ "accepted": true, "delivered": true })))
}

/// Query parameters for getDirectRequestOutcome
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOutcomeParams {
    pub request_id: Uuid,
    pub actor_device_id: Uuid,
}

/// GET /xrpc/blue.catbird.mlsDS.getDirectRequestOutcome
pub async fn get_direct_request_outcome(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    Query(query): Query<GetOutcomeParams>,
) -> Result<Json<Value>, FederationError> {
    let security = enforce_ds_request_security(&pool, &auth_user, GET_OUTCOME_NSID, None).await?;
    let outcome = canonical_relay::coordinator_get_outcome(
        &pool,
        &runtime,
        &security.requester_ds,
        query.request_id,
        query.actor_device_id,
    )
    .await?;
    Ok(Json(outcome))
}

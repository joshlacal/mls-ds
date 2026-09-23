//! Thin transport adapters. The repository owns signed admission, ordered locks,
//! attempt claims and commit-before-response behavior; feature activation is off
//! until the dedicated receipt authority has passed its durable startup check.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::direct_request_preparation::{
            self as requests, DirectRequestResult, DirectRequestStoreError,
        },
    },
    storage::DbPool,
};
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

fn failure(endpoint: ChatEndpoint, error: DirectRequestStoreError) -> ChatFailure {
    tracing::warn!(%error, endpoint = endpoint.nsid(), "direct request repository failure");
    let code = match error {
        DirectRequestStoreError::Database(_) => return ChatFailure::storage(endpoint),
        DirectRequestStoreError::ForeignTransaction | DirectRequestStoreError::InvalidReceipt => {
            return ChatFailure::invariant(endpoint)
        }
        DirectRequestStoreError::IdentityConflict => ChatProtocolErrorCode::PreparationConflict,
        DirectRequestStoreError::InvalidSignature => ChatProtocolErrorCode::InvalidSignature,
        DirectRequestStoreError::Expired => ChatProtocolErrorCode::PreparationExpired,
        DirectRequestStoreError::QuotaExceeded => ChatProtocolErrorCode::CapacityUnavailable,
        DirectRequestStoreError::RecipientKeysUnavailable => {
            ChatProtocolErrorCode::RecipientKeysUnavailable
        }
        DirectRequestStoreError::RecipientAuthorityUnsupported => {
            ChatProtocolErrorCode::RecipientAuthorityUnsupported
        }
        DirectRequestStoreError::IncludedAuthorityChanged => {
            ChatProtocolErrorCode::PreparationRevoked
        }
        DirectRequestStoreError::PolicyDenied => ChatProtocolErrorCode::RequestPolicyDenied,
    };
    ChatFailure::protocol(endpoint, code)
}
fn output(result: DirectRequestResult, endpoint: ChatEndpoint) -> Result<Vec<u8>, ChatFailure> {
    let mut payload = match result {
        DirectRequestResult::Keys(bytes) => return Ok(bytes),
        DirectRequestResult::Unknown(id) => {
            serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestUnknownOutcome","requestId":id.to_string()})
        }
        DirectRequestResult::Prepared(bytes) => {
            serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_|ChatFailure::invariant(endpoint))?})
        }
        DirectRequestResult::Terminal(bytes) => {
            let mut value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
            value["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
            value
        }
    };
    // Outcomes and mutation receipts echo retained bare-base64 signed bytes;
    // present them as lexicon `{"$bytes":…}` at response time only.
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut payload,
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;
    let bytes = serde_json::to_vec(&serde_json::json!({"outcome":payload}))
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    if bytes.len() > 8_388_608 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::ArtifactTooLarge,
        ));
    }
    Ok(bytes)
}
async fn mutate(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
    endpoint: ChatEndpoint,
) -> Result<Response, ChatFailure> {
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired))?;
    if !runtime.request_producers_enabled()
        && matches!(
            endpoint,
            ChatEndpoint::PrepareDirectRequest | ChatEndpoint::PublishDirectRequestKeys
        )
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::CutoverRequired,
        ));
    }
    let principal = context::verify_service_principal(pool, endpoint, headers).await?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope<'a> {
        #[serde(rename = "signedRequest", borrow)]
        signed_request: &'a serde_json::value::RawValue,
    }
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let now = crate::chat_protocol::validation::TrustedRequestInstant::capture()
        .map_err(|_| ChatFailure::invariant(endpoint))?
        .datetime();

    if endpoint == ChatEndpoint::PrepareDirectRequest {
        if let Ok(parsed_req) = serde_json::from_str::<serde_json::Value>(envelope.signed_request.get()) {
            if let Some(recipient_did) = parsed_req["body"]["recipientDid"].as_str() {
                let actor_did = principal.did();
                if let Ok(coord) = crate::federation::canonical_relay::resolve_pair_coordinator(pool, actor_did, recipient_did).await {
                    if !coord.is_coordinator {
                        let outcome = crate::federation::canonical_relay::relay_prepare_direct_request(
                            &coord.coordinator_endpoint(),
                            &coord.coordinator_did,
                            &parsed_req,
                        ).await.map_err(|_| failure(endpoint, DirectRequestStoreError::PolicyDenied))?;
                        let bytes = serde_json::to_vec(&outcome)
                            .map_err(|_| ChatFailure::invariant(endpoint))?;
                        return Ok(context::json_ok(bytes));
                    } else if !coord.is_recipient_home {
                        let request_id = uuid::Uuid::parse_str(parsed_req["body"]["requestId"].as_str().unwrap_or_default())
                            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
                        let remote_devices = crate::federation::canonical_relay::reserve_remote_recipient_bootstrap(
                            &coord.recipient_home.endpoint,
                            &coord.recipient_home.did,
                            request_id,
                            actor_did,
                            recipient_did,
                        ).await.map_err(|_| failure(endpoint, DirectRequestStoreError::RecipientKeysUnavailable))?;

                        let mut tx = pool.begin().await.map_err(|_| ChatFailure::storage(endpoint))?;
                        crate::federation::canonical_relay::stage_remote_recipient_devices(&mut tx, &remote_devices, now).await
                            .map_err(|_| failure(endpoint, DirectRequestStoreError::RecipientKeysUnavailable))?;
                        let result = requests::prepare_direct_request(
                            &mut tx,
                            &principal,
                            envelope.signed_request.get().as_bytes(),
                            signer,
                            runtime.relationship_authority().as_ref(),
                            now,
                        ).await.map_err(|e| failure(endpoint, e))?;
                        let bytes = output(result, endpoint)?;
                        tx.commit().await.map_err(|_| ChatFailure::storage(endpoint))?;
                        return Ok(context::json_ok(bytes));
                    }
                }
            }
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let result = match endpoint {
        ChatEndpoint::PublishDirectRequestKeys => {
            requests::publish_direct_request_keys(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                now,
            )
            .await
        }
        ChatEndpoint::PrepareDirectRequest => {
            requests::prepare_direct_request(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                signer,
                runtime.relationship_authority().as_ref(),
                now,
            )
            .await
        }
        ChatEndpoint::CancelDirectRequestPreparation => {
            requests::cancel_direct_request(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                signer,
                now,
            )
            .await
        }
        _ => return Err(ChatFailure::invariant(endpoint)),
    }
    .map_err(|e| failure(endpoint, e))?;
    let bytes = output(result, endpoint)?;
    if bytes.len() > 8_388_608 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::ArtifactTooLarge,
        ));
    }
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(context::json_ok(bytes))
}
macro_rules! handler {
    ($name:ident,$endpoint:ident) => {
        pub(super) async fn $name(
            State(pool): State<DbPool>,
            State(runtime): State<Arc<ChatRuntime>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            match mutate(&pool, &runtime, &headers, &body, ChatEndpoint::$endpoint).await {
                Ok(response) => response,
                Err(error) => error.into_response(),
            }
        }
    };
}
handler!(publish_keys, PublishDirectRequestKeys);
handler!(prepare, PrepareDirectRequest);
handler!(cancel, CancelDirectRequestPreparation);
pub(super) async fn outcome(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    async fn run(
        pool: &DbPool,
        runtime: &ChatRuntime,
        headers: &HeaderMap,
        query: Option<&str>,
    ) -> Result<Response, ChatFailure> {
        let endpoint = ChatEndpoint::GetDirectRequestOutcome;
        let signer = runtime.request_receipt_signer().ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired)
        })?;
        let principal = context::verify_service_principal(pool, endpoint, headers).await?;
        let mut device = None;
        let mut request = None;
        for (k, v) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            let value =
                crate::chat_protocol::validation::CanonicalUuidV4::parse(&v).map_err(|_| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            let id = uuid::Uuid::from_bytes(*value.as_bytes());
            match k.as_ref() {
                "actorDeviceId" if device.is_none() => device = Some(id),
                "requestId" if request.is_none() => request = Some(id),
                _ => {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvalidRequest,
                    ))
                }
            }
        }
        let device = device.ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let request = request.ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let now = crate::chat_protocol::validation::TrustedRequestInstant::capture()
            .map_err(|_| ChatFailure::invariant(endpoint))?
            .datetime();
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| {
                tracing::error!(%error, "get_direct_request_outcome pool.begin failed");
                ChatFailure::storage(endpoint)
            })?;
        let result =
            requests::get_direct_request_outcome(&mut tx, &principal, device, request, signer, now)
                .await
                .map_err(|e| failure(endpoint, e))?;
        if matches!(result, requests::DirectRequestResult::Unknown(_)) {
            let default_ds = std::env::var("DEFAULT_DS_ENDPOINT").ok();
            let self_endpoint = crate::identity::self_endpoint();
            if let Some(ref peer_ds) = default_ds {
                if peer_ds != &self_endpoint {
                    let peer_did = std::env::var("DEFAULT_DS_DID").unwrap_or_else(|_| "did:web:ds1.test".into());
                    if let Ok(relayed) = crate::federation::canonical_relay::relay_get_outcome(
                        peer_ds,
                        &peer_did,
                        request,
                        device,
                    ).await {
                        let bytes = serde_json::to_vec(&relayed).map_err(|_| ChatFailure::invariant(endpoint))?;
                        return Ok(context::json_ok(bytes));
                    }
                }
            }
        }
        let bytes = output(result, endpoint)?;
        tx.commit()
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
        Ok(context::json_ok(bytes))
    }
    match run(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

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
    let payload = match result {
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
            .map_err(|_| ChatFailure::storage(endpoint))?;
        let result =
            requests::get_direct_request_outcome(&mut tx, &principal, device, request, signer, now)
                .await
                .map_err(|e| failure(endpoint, e))?;
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

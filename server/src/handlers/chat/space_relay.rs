//! `blue.catbird.chat.relaySpaceCredential` & `blue.catbird.chat.relaySpaceRead` HTTP handlers (`3A`).
//!
//! CRITICAL PRIVACY INVARIANT (`3A`):
//! Both handlers perform strictly READ-ONLY authorization checks against `chat.devices` and write
//! ZERO rows to any table on the home `mls-ds`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use catbird_atproto::generated::blue_catbird::chat::{
    relay_space_credential::RelaySpaceCredential, relay_space_read::RelaySpaceRead,
};
use serde_json::json;
use uuid::Uuid;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode},
    federation::space_read_relay::{
        relay_space_credential_stateless, relay_space_read_stateless, SpaceRelayError,
    },
    storage::DbPool,
};

const CREDENTIAL_ENDPOINT: ChatEndpoint = ChatEndpoint::RelaySpaceCredential;
const READ_ENDPOINT: ChatEndpoint = ChatEndpoint::RelaySpaceRead;

pub(super) async fn handle_credential(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay_credential(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_read(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay_read(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn verify_active_device_read_only(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    user_did: &str,
    actor_device_id: &str,
) -> Result<(), ChatFailure> {
    let device_uuid = Uuid::parse_str(actor_device_id)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(user_did)
    .bind(device_uuid)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    match status.as_deref() {
        None => Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::DeviceNotRegistered,
        )),
        Some("revoked") => Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::DeviceRevoked,
        )),
        Some("active") => Ok(()),
        Some(_) => Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        )),
    }
}

async fn relay_credential(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, CREDENTIAL_ENDPOINT)?;
    let principal = context::verify_service_principal(pool, CREDENTIAL_ENDPOINT, headers).await?;

    let input: RelaySpaceCredential = serde_json::from_slice(body).map_err(|_| {
        ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
    })?;

    verify_active_device_read_only(
        pool,
        CREDENTIAL_ENDPOINT,
        principal.did(),
        input.actor_device_id.as_ref(),
    )
    .await?;

    let out = relay_space_credential_stateless(
        input.authority_did.as_ref(),
        input.space.as_ref(),
        input.delegation_token.as_ref(),
        input.cnf_key.as_ref().map(|s| s.as_ref()),
    )
    .await
    .map_err(|err| match err {
        SpaceRelayError::InvalidTargetEndpoint(_) => ChatFailure::protocol(
            CREDENTIAL_ENDPOINT,
            ChatProtocolErrorCode::InvalidTargetEndpoint,
        ),
        SpaceRelayError::InvalidDelegationToken(_) => ChatFailure::protocol(
            CREDENTIAL_ENDPOINT,
            ChatProtocolErrorCode::InvalidDelegationToken,
        ),
        SpaceRelayError::InvalidNsid(_) => {
            ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        SpaceRelayError::UpstreamError(_) => {
            ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::UpstreamError)
        }
    })?;

    let response_bytes = serde_json::to_vec(&json!({
        "credential": out.credential,
        "expiresAt": out.expires_at,
    }))
    .map_err(|_| ChatFailure::invariant(CREDENTIAL_ENDPOINT))?;
    context::canonical_json_response(CREDENTIAL_ENDPOINT, 200, response_bytes)
}

async fn relay_read(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, READ_ENDPOINT)?;
    let principal = context::verify_service_principal(pool, READ_ENDPOINT, headers).await?;

    let input: RelaySpaceRead = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

    verify_active_device_read_only(
        pool,
        READ_ENDPOINT,
        principal.did(),
        input.actor_device_id.as_ref(),
    )
    .await?;

    // Check NSID allowlist BEFORE resolving target endpoint!
    if !crate::federation::space_read_relay::is_allowed_space_read_nsid(input.nsid.as_ref()) {
        return Err(ChatFailure::protocol(
            READ_ENDPOINT,
            ChatProtocolErrorCode::InvalidNsid,
        ));
    }

    let relayed = relay_space_read_stateless(
        input.target_did.as_ref(),
        input.nsid.as_ref(),
        input.query.as_ref().map(|s| s.as_ref()),
        input.credential.as_ref(),
        input.space_audience.as_ref(),
        input.want_mac.as_ref().map(|s| s.as_ref()),
        input.signature_input.as_ref(),
        input.signature.as_ref(),
    )
    .await
    .map_err(|err| match err {
        SpaceRelayError::InvalidNsid(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidNsid)
        }
        SpaceRelayError::InvalidTargetEndpoint(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidTargetEndpoint)
        }
        SpaceRelayError::InvalidDelegationToken(_) | SpaceRelayError::UpstreamError(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::UpstreamError)
        }
    })?;

    let status = StatusCode::from_u16(relayed.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_headers = HeaderMap::new();
    if let Ok(ct) = HeaderValue::from_str(&relayed.content_type) {
        resp_headers.insert(CONTENT_TYPE, ct);
    } else {
        resp_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }
    resp_headers.insert(
        HeaderName::from_static("access-control-expose-headers"),
        HeaderValue::from_static("Atproto-Space-Mac"),
    );
    if let Some(mac) = relayed.space_mac {
        if let Ok(val) = HeaderValue::from_str(&mac) {
            resp_headers.insert(HeaderName::from_static("atproto-space-mac"), val);
        }
    }

    Ok((status, resp_headers, relayed.body).into_response())
}

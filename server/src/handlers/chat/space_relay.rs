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
        input.cnf_key.as_ref(),
    )
    .await
    .map_err(credential_relay_failure)?;

    let response_bytes = serde_json::to_vec(&json!({
        "credential": out.credential,
        "expiresAt": out.expires_at,
    }))
    .map_err(|_| ChatFailure::invariant(CREDENTIAL_ENDPOINT))?;
    context::canonical_json_response(CREDENTIAL_ENDPOINT, 200, response_bytes)
}

/// The authority's denial reaches the client with its status: 401 rejects the
/// delegation token, 403 refuses an authenticated caller (e.g. a removed member).
fn credential_relay_failure(err: SpaceRelayError) -> ChatFailure {
    match err {
        SpaceRelayError::InvalidTargetEndpoint(_) => ChatFailure::protocol(
            CREDENTIAL_ENDPOINT,
            ChatProtocolErrorCode::InvalidTargetEndpoint,
        ),
        SpaceRelayError::InvalidDelegationToken(_) => ChatFailure::protocol(
            CREDENTIAL_ENDPOINT,
            ChatProtocolErrorCode::InvalidDelegationToken,
        )
        .with_status(StatusCode::UNAUTHORIZED),
        SpaceRelayError::Forbidden(_) => {
            ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::NotAuthorized)
                .with_status(StatusCode::FORBIDDEN)
        }
        SpaceRelayError::InvalidRequest(_) | SpaceRelayError::InvalidNsid(_) => {
            ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        SpaceRelayError::UpstreamError(_) => {
            ChatFailure::protocol(CREDENTIAL_ENDPOINT, ChatProtocolErrorCode::UpstreamError)
        }
        SpaceRelayError::UpstreamUnavailable(_) => upstream_unavailable(CREDENTIAL_ENDPOINT),
    }
}

/// A read relay failure; the target's own 4xx answer is forwarded, not mapped here.
fn read_relay_failure(err: SpaceRelayError) -> ChatFailure {
    match err {
        SpaceRelayError::InvalidRequest(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        SpaceRelayError::InvalidNsid(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidNsid)
        }
        SpaceRelayError::InvalidTargetEndpoint(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::InvalidTargetEndpoint)
        }
        SpaceRelayError::InvalidDelegationToken(_)
        | SpaceRelayError::Forbidden(_)
        | SpaceRelayError::UpstreamError(_) => {
            ChatFailure::protocol(READ_ENDPOINT, ChatProtocolErrorCode::UpstreamError)
        }
        SpaceRelayError::UpstreamUnavailable(_) => upstream_unavailable(READ_ENDPOINT),
    }
}

/// The target could not answer now: the declared `UpstreamError` as a 503
/// with a retry hint, so the identical relay may be retried.
fn upstream_unavailable(endpoint: ChatEndpoint) -> ChatFailure {
    ChatFailure::protocol_with_retry(endpoint, ChatProtocolErrorCode::UpstreamError, Some(5))
        .with_status(StatusCode::SERVICE_UNAVAILABLE)
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
    .map_err(read_relay_failure)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::space_read_relay::register_test_space_relay_target;
    use axum::{routing::post, Router};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn authority_denials_keep_their_status_through_the_credential_relay() {
        let authority = "did:web:credential-relay-denial.example";
        let space = format!("at://{authority}/space/blue.catbird.labyrinth.mailbox/self");
        let pop = p256::SecretKey::from_slice(&[0x31; 32]).unwrap();
        let kid = atproto_spaces::kem::encode_p256_did_key(&pop.public_key());
        let upstream = Arc::new(Mutex::new((StatusCode::OK, json!({}))));
        let router = Router::new().route(
            "/xrpc/com.atproto.space.getSpaceCredential",
            post({
                let upstream = upstream.clone();
                move || {
                    let (status, body) = upstream.lock().unwrap().clone();
                    async move { (status, axum::Json(body)) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        register_test_space_relay_target(
            authority,
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        for (upstream_status, upstream_error, status, error) in [
            (403, "Forbidden", 403, "NotAuthorized"),
            (401, "CredentialRevoked", 401, "InvalidDelegationToken"),
            (401, "InvalidDelegationToken", 401, "InvalidDelegationToken"),
        ] {
            *upstream.lock().unwrap() = (
                StatusCode::from_u16(upstream_status).unwrap(),
                json!({ "error": upstream_error, "message": "not an active member" }),
            );
            let failure = relay_space_credential_stateless(authority, &space, "dt", &kid)
                .await
                .map_err(credential_relay_failure)
                .expect_err("the authority denied the credential");
            let response = failure.into_response();
            assert_eq!(response.status().as_u16(), status, "{upstream_error}");
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 16)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["error"], error, "{upstream_error}");
        }
        server.abort();
    }

    /// A target, or its authority's DID document, that could not answer now is
    /// the declared `UpstreamError` as a retryable 503 on both relays; a
    /// definitive 4xx keeps its meaning.
    #[tokio::test]
    async fn upstream_outages_are_retryable_503s_and_upstream_refusals_are_preserved() {
        let target = "did:web:space-relay-outage.example";
        let space = format!("at://{target}/space/blue.catbird.labyrinth.mailbox/self");
        let pop = p256::SecretKey::from_slice(&[0x31; 32]).unwrap();
        let kid = atproto_spaces::kem::encode_p256_did_key(&pop.public_key());
        let upstream = Arc::new(Mutex::new(StatusCode::OK));
        let document = Arc::new(Mutex::new(StatusCode::OK));
        let answer = {
            let upstream = upstream.clone();
            move || {
                let status = *upstream.lock().unwrap();
                async move { (status, axum::Json(json!({ "credential": "unverified" }))) }
            }
        };
        let router = Router::new()
            .route(
                "/xrpc/com.atproto.space.getSpaceCredential",
                post(answer.clone()),
            )
            .route(
                "/xrpc/com.atproto.space.getRecord",
                axum::routing::get(answer),
            )
            .route(
                /* did-web-test */ "/.well-known/did.json",
                axum::routing::get({
                    let document = document.clone();
                    move || {
                        let status = *document.lock().unwrap();
                        async move { (status, axum::Json(json!({}))) }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        register_test_space_relay_target(
            target,
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let read = || {
            relay_space_read_stateless(
                target,
                "com.atproto.space.getRecord",
                None,
                "credential",
                "audience",
                None,
                "signature-input",
                "signature",
            )
        };

        for outage in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            *upstream.lock().unwrap() = outage;
            let credential_failure = relay_space_credential_stateless(target, &space, "dt", &kid)
                .await
                .map_err(credential_relay_failure)
                .expect_err("the authority could not answer");
            let read_failure = read()
                .await
                .map_err(read_relay_failure)
                .err()
                .expect("the target could not answer");
            for failure in [credential_failure, read_failure] {
                let response = failure.into_response();
                assert_eq!(
                    response.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{outage}"
                );
                assert_eq!(
                    response.headers()[axum::http::header::RETRY_AFTER],
                    "5",
                    "{outage}"
                );
                let body: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 1 << 16)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(body["error"], "UpstreamError", "{outage}");
            }
        }

        *upstream.lock().unwrap() = StatusCode::NOT_FOUND;
        let refused = relay_space_credential_stateless(target, &space, "dt", &kid)
            .await
            .map_err(credential_relay_failure)
            .expect_err("the authority refused")
            .into_response();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(refused
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
        let Ok(forwarded) = read().await else {
            panic!("the target's 404 is forwarded");
        };
        assert_eq!(forwarded.status, 404);

        // The credential arrives, but the authority's DID document does not.
        *upstream.lock().unwrap() = StatusCode::OK;
        for (document_status, status) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (StatusCode::NOT_FOUND, StatusCode::BAD_REQUEST),
        ] {
            *document.lock().unwrap() = document_status;
            let response = relay_space_credential_stateless(target, &space, "dt", &kid)
                .await
                .map_err(credential_relay_failure)
                .expect_err("the authority key is unavailable")
                .into_response();
            assert_eq!(response.status(), status, "{document_status}");
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .is_some(),
                status == StatusCode::SERVICE_UNAVAILABLE,
                "{document_status}"
            );
        }

        // Nothing listens: the request itself cannot be sent.
        server.abort();
        let _ = server.await;
        let credential_down = relay_space_credential_stateless(target, &space, "dt", &kid)
            .await
            .map_err(credential_relay_failure)
            .expect_err("the authority is down");
        let read_down = read()
            .await
            .map_err(read_relay_failure)
            .err()
            .expect("the target is down");
        for failure in [credential_down, read_down] {
            assert_eq!(
                failure.into_response().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }

    /// `relay_credential` answers `InvalidRequest` for any body this type rejects.
    #[test]
    fn credential_request_requires_the_pop_key_and_an_at_space_uri() {
        let authority = "did:web:credential-relay-input.example";
        let valid = json!({
            "actorDeviceId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
            "authorityDid": authority,
            "space": format!("at://{authority}/space/blue.catbird.labyrinth.mailbox/self"),
            "delegationToken": "delegation.jwt.0123456789",
            "cnfKey": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
        });
        assert!(serde_json::from_value::<RelaySpaceCredential>(valid.clone()).is_ok());
        let mut missing_pop_key = valid.clone();
        missing_pop_key.as_object_mut().unwrap().remove("cnfKey");
        let mut at_space_scheme = valid;
        at_space_scheme["space"] = json!(format!(
            "at-space://{authority}/blue.catbird.labyrinth.mailbox/self"
        ));
        for invalid in [missing_pop_key, at_space_scheme] {
            assert!(serde_json::from_value::<RelaySpaceCredential>(invalid).is_err());
        }
    }
}

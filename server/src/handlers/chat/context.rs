//! Shared standard AppView authentication and admission spine for every
//! clean-chat handler.
//!
//! Handlers never re-implement service-auth/replay crypto. They call one `admit_*`
//! function per auth class, which:
//!   1. evaluates the global cutover gate (OQ-2),
//!   2. captures one trusted instant `T`,
//!   3. verifies exact standard service auth for the requested NSID,
//!   4. extracts the exact `signedRequest` bytes where the endpoint uses one
//!      (preserved
//!      verbatim via `RawValue` so the idempotency wrapper-byte contract holds)
//!      and decodes the canonical mutation, and
//!   5. returns an opaque operation-only admission. Endpoint composition locks
//!      the operation and validates durable post-state before replay bytes can
//!      escape (OQ-3).
//!
//! Every failure is mapped to a [`ChatFailure`] at the exact call site that
//! produced it, so account/session failures remain distinct from malformed
//! request bodies and device-signature failures,
//! while internal storage/invariant failures carry no protocol code.

use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::auth::{self as service_auth, AuthError};
use crate::chat_protocol::{
    dpop::{self, VerifiedReadAdmission},
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::auth::{
        self, AuthRepositoryError, CompletedIdempotentResponse, EnrollmentOperationAdmission,
        SignedOperationAdmission,
    },
    repository::prelude::PreludeError,
    transcript,
    validation::{CanonicalHttpMethod, TrustedRequestInstant},
};
use crate::storage::DbPool;

use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

/// Reject the request unless the global cutover flag is enabled for the
/// clean-chat protocol.
pub(crate) fn require_cutover(
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
) -> Result<(), ChatFailure> {
    if runtime.cutover_enabled() {
        Ok(())
    } else {
        Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::CutoverRequired,
        ))
    }
}

fn capture_instant(endpoint: ChatEndpoint) -> Result<TrustedRequestInstant, ChatFailure> {
    TrustedRequestInstant::capture().map_err(|_| ChatFailure::invariant(endpoint))
}

async fn verify_service_principal(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
) -> Result<crate::auth::VerifiedServicePrincipal, ChatFailure> {
    service_auth::verify_mls_service_principal(headers, pool, endpoint.nsid())
        .await
        .map_err(|error| service_auth_failure(endpoint, error))
}

fn service_auth_failure(endpoint: ChatEndpoint, error: AuthError) -> ChatFailure {
    match error {
        AuthError::TokenExpired => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::AccountSessionExpired)
        }
        AuthError::RateLimitExceeded { retry_after_secs } => {
            ChatFailure::protocol_with_retry(
                endpoint,
                ChatProtocolErrorCode::RateLimited,
                Some(retry_after_secs),
            )
        }
        AuthError::Internal(_) => ChatFailure::storage(endpoint),
        _ => ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized),
    }
}

/// Extract the exact wire bytes of the `signedRequest` field, preserving them
/// verbatim (idempotency wrapper-byte contract). A missing or malformed
/// envelope is a client `InvalidRequest`.
pub(crate) fn signed_request_bytes(
    body: &[u8],
    endpoint: ChatEndpoint,
) -> Result<Vec<u8>, ChatFailure> {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(rename = "signedRequest", borrow)]
        signed_request: &'a RawValue,
    }
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    Ok(envelope.signed_request.get().as_bytes().to_vec())
}

pub(crate) fn actor_device_id_from_query(
    query: Option<&str>,
    endpoint: ChatEndpoint,
) -> Result<String, ChatFailure> {
    let values: Vec<String> = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter_map(|(key, value)| (key == "actorDeviceId").then(|| value.into_owned()))
        .collect();
    match values.as_slice() {
        [value] => Ok(value.clone()),
        _ => Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        )),
    }
}

/// Admit an ordinary unsigned (DPoP) read query and immediately seal the
/// committed authority into an opaque [`VerifiedReadAdmission`].
///
/// Unsigned requests never carry an idempotency record, so the repository
/// outcome is always a first-execution authority. That raw authority is
/// consumed here and never escapes: this is the sole non-test
/// `dpop::seal_read_admission` callsite, and every seal failure becomes a
/// redacted endpoint invariant so no binding detail reaches the wire.
pub(crate) async fn admit_unsigned_read(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    method: CanonicalHttpMethod,
    headers: &HeaderMap,
    actor_device_id: &str,
) -> Result<VerifiedReadAdmission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let principal = match verify_service_principal(pool, endpoint, headers).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("verify_service_principal failed: {:?}", e);
            return Err(e);
        }
    };
    let instant = capture_instant(endpoint)?;
    let pre_replay = match dpop::standard_service_auth_evidence(principal, actor_device_id, method, instant, None) {
        Ok(pr) => pr,
        Err(e) => {
            eprintln!("standard_service_auth_evidence failed: {:?}", e);
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
        }
    };
    let authority = match auth::authorize_unsigned_request(pool, pre_replay).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("authorize_unsigned_request failed: {:?}", e);
            return Err(auth_repository_failure(endpoint, e));
        }
    };
    match dpop::seal_read_admission(authority) {
        Ok(a) => Ok(a),
        Err(e) => {
            eprintln!("seal_read_admission failed: {:?}", e);
            Err(ChatFailure::invariant(endpoint))
        }
    }
}
/// Byte-opaque operation-only admission for an ordinary signed procedure.
/// Global operation arbitration in the caller-owned transaction decides
/// whether first-execution timestamp authority or completed-replay authority
/// may be opened.
pub(crate) async fn admit_signed_operation_only(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<SignedOperationAdmission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let principal = match verify_service_principal(pool, endpoint, headers).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("verify_service_principal failed: {:?}", e);
            return Err(e);
        }
    };
    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let canonical = match transcript::decode_canonical_signed_mutation(&signed_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("decode_canonical_signed_mutation failed: {:?}", e);
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
        }
    };
    let actor_device_id = canonical.actor_device_id().as_str().to_owned();
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(endpoint))?;
    let instant = capture_instant(endpoint)?;
    let pre_replay = match dpop::standard_service_auth_evidence(principal, &actor_device_id, method, instant, None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("standard_service_auth_evidence failed: {:?}", e);
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
        }
    };
    auth::authorize_signed_operation_only(pool, pre_replay, canonical)
        .await
        .map_err(|error| {
            eprintln!("authorize_signed_operation_only failed: {:?}", error);
            auth_repository_failure(endpoint, error)
        })
}
/// Operation-only enrollment admission. This consumes replay evidence but
/// cannot surface completed response bytes; the caller-owned operation prelude
/// must first reserve the global operation and lock the enrollment slot.
pub(crate) async fn admit_enrollment_operation_only(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<EnrollmentOperationAdmission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let principal = verify_service_principal(pool, endpoint, headers).await?;
    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let enrollment_body = transcript::decode_and_verify_enrollment_body(&signed_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let device_id = enrollment_body.device_id().as_str().to_owned();
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(endpoint))?;
    let instant = capture_instant(endpoint)?;
    let pre_replay = dpop::standard_service_auth_evidence(
        principal,
        &device_id,
        method,
        instant,
        Some(enrollment_body),
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    auth::authorize_enrollment_operation_only(pool, pre_replay)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))
}

/// Operation-only replenishment admission. The exact wrapper is decoded once
/// and replay response bytes remain opaque until the prelude re-locks the
/// current actor authority.
pub(crate) async fn admit_replenishment_operation_only(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<SignedOperationAdmission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let principal = verify_service_principal(pool, endpoint, headers).await?;
    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let canonical = transcript::decode_canonical_signed_mutation(&signed_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let actor_device_id = canonical.actor_device_id().as_str().to_owned();
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(endpoint))?;
    let instant = capture_instant(endpoint)?;
    let pre_replay =
        dpop::standard_service_auth_evidence(principal, &actor_device_id, method, instant, None)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    auth::authorize_replenishment_operation_only(pool, pre_replay, canonical)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))
}

/// A fresh `200 OK` JSON response carrying the exact serialized output bytes.
/// The same bytes are the ones recorded for idempotent replay, so a later replay
/// is byte-identical.
pub(crate) fn json_ok(response_bytes: Vec<u8>) -> Response {
    let mut response = Response::new(axum::body::Body::from(response_bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// Render facade-owned canonical JSON bytes at their exact validated status.
/// Endpoint facades use this for deterministic success and terminal-error
/// material; handlers must not deserialize and reserialize those bytes.
pub(crate) fn canonical_json_response(
    endpoint: ChatEndpoint,
    status: i32,
    response_bytes: Vec<u8>,
) -> Result<Response, ChatFailure> {
    let status = u16::try_from(status)
        .ok()
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;
    if response_bytes.is_empty() {
        return Err(ChatFailure::invariant(endpoint));
    }
    let mut response = Response::new(axum::body::Body::from(response_bytes));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}

/// Render a completed idempotency record verbatim (OQ-3): the stored status and
/// exact stored response bytes, with the endpoint content-type.
pub(crate) fn replay_response(completed: &CompletedIdempotentResponse) -> Response {
    let status = u16::try_from(completed.status())
        .ok()
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(StatusCode::OK);
    let mut response = Response::new(axum::body::Body::from(completed.response_bytes().to_vec()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// Map a repository authorization failure to the endpoint's declared wire code
/// at the call site. Codes the endpoint does not declare are downgraded to an
/// internal invariant violation by [`ChatFailure::protocol`] (OQ-11); storage
/// and corrupt-record failures never carry a protocol code.
///
/// Reachable-code note (M-3): this is a SHARED superset used by every admit
/// class, so a given endpoint reaches only the subset its auth flow can produce
/// (e.g. `DeviceAlreadyExists` is reachable only from the enrollment bootstrap;
/// `RequestBindingMismatch`→`InvalidRequest` from a signed idempotency-key reuse
/// with a mutated body). Any pair the caller does not declare is downgraded by
/// `ChatFailure::protocol`, so this superset can never leak an undeclared code.
pub(crate) fn auth_repository_failure(
    endpoint: ChatEndpoint,
    error: AuthRepositoryError,
) -> ChatFailure {
    use AuthRepositoryError as E;
    use ChatProtocolErrorCode as C;
    let code = match error {
        E::Database(_) => return ChatFailure::storage(endpoint),
        E::CorruptIdempotencyRecord | E::InvalidCompletion => {
            return ChatFailure::invariant(endpoint)
        }
        E::ReplayDetected => C::NotAuthorized,
        E::DpopBindingMismatch => C::DeviceBindingMismatch,
        E::DeviceNotRegistered | E::DeviceKeyMissing => C::DeviceNotRegistered,
        E::DeviceAlreadyRegistered => C::DeviceAlreadyExists,
        E::DeviceRevoked | E::DeviceKeyRevoked => C::DeviceRevoked,
        E::AuthenticationGenerationMismatch => C::AuthenticationGenerationConflict,
        E::IdempotencyConflict => C::IdempotencyConflict,
        E::RequestBindingMismatch
        | E::MissingAcceptedRequestBytes
        | E::UnsupportedAuthorizationShape => C::InvalidRequest,
        E::Primitive(_) => C::InvalidSignature,
    };
    ChatFailure::protocol(endpoint, code)
}

/// Map the shared operation-prelude failures without exposing repository
/// integrity detail. Only the exact endpoint-agnostic semantic failures cross
/// the wire; every lock/scope/claim invariant remains internal.
pub(crate) fn operation_prelude_failure(
    endpoint: ChatEndpoint,
    error: PreludeError,
) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use PreludeError as E;

    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
        E::Authorization(error) => auth_repository_failure(endpoint, error),
        E::MissingDevice | E::MissingDeviceKey => {
            ChatFailure::protocol(endpoint, C::DeviceNotRegistered)
        }
        E::OperationIdConflict => ChatFailure::protocol(endpoint, C::IdempotencyConflict),
        E::ForeignTransaction
        | E::UnsupportedAuthority
        | E::NonCanonicalOperation
        | E::CanonicalScope
        | E::ScopeDrift
        | E::MissingPrincipal
        | E::AuthorityBindingMismatch
        | E::ClaimIntegrity => ChatFailure::invariant(endpoint),
    }
}

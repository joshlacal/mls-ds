// The admission helpers below are the shared spine consumed by the H1 endpoint
// handlers (next seal); they are intentionally present in the scaffolding seal
// ahead of their first caller.
#![allow(dead_code)]

//! Shared authentication and admission spine for every clean-chat handler.
//!
//! Handlers never re-implement DPoP/replay crypto. They call one `admit_*`
//! function per auth class, which:
//!   1. evaluates the global cutover gate (OQ-2),
//!   2. captures one trusted instant `T`,
//!   3. dispatches to the correct `dpop::verify_*_request_auth` by NSID,
//!   4. for signed classes, extracts the exact `signedRequest` bytes (preserved
//!      verbatim via `RawValue` so the idempotency wrapper-byte contract holds)
//!      and decodes the canonical mutation, and
//!   5. calls the matching `repository::auth::authorize_*`, returning either a
//!      first-execution authority or a verbatim completed-replay response
//!      (OQ-3).
//!
//! Every failure is mapped to a [`ChatFailure`] at the exact call site that
//! produced it, so DPoP failures surface as `InvalidDPoP`, malformed request
//! bodies as `InvalidRequest`, and signature failures as `InvalidSignature`,
//! while internal storage/invariant failures carry no protocol code.

use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::chat_protocol::{
    dpop::{self, TrustedNestVerifier, VerifiedChatDeviceRequest},
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::auth::{
        self, AuthRepositoryError, AuthorizationOutcome, CompletedIdempotentResponse,
    },
    transcript,
    validation::{CanonicalHttpMethod, TrustedRequestInstant, ValidatedChatNsid},
};
use crate::storage::DbPool;

use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

/// Outcome of admitting a signed or bootstrap request: either a first-execution
/// authority to drive the business mutation, or a ready-to-return verbatim
/// replay of a previously completed identical request.
pub(crate) enum Admission {
    Execute(Box<VerifiedChatDeviceRequest>),
    Replay(Response),
}

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

/// The configured Nest verifier. Absence while cutover is enabled is a
/// misconfiguration (startup rejects it), so at request time it is an internal
/// invariant violation rather than a client-facing error.
fn verifier(
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
) -> Result<&TrustedNestVerifier, ChatFailure> {
    runtime
        .nest_verifier()
        .ok_or_else(|| ChatFailure::invariant(endpoint))
}

struct DpopHeaders {
    authorization: String,
    proof: String,
}

fn read_dpop_headers(
    headers: &HeaderMap,
    endpoint: ChatEndpoint,
) -> Result<DpopHeaders, ChatFailure> {
    let authorization = header_value(headers, "authorization")
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;
    let proof = header_value(headers, "dpop")
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;
    Ok(DpopHeaders {
        authorization,
        proof,
    })
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn validated_nsid(endpoint: ChatEndpoint) -> Result<ValidatedChatNsid, ChatFailure> {
    ValidatedChatNsid::parse(endpoint.nsid()).map_err(|_| ChatFailure::invariant(endpoint))
}

fn capture_instant(endpoint: ChatEndpoint) -> Result<TrustedRequestInstant, ChatFailure> {
    TrustedRequestInstant::capture().map_err(|_| ChatFailure::invariant(endpoint))
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

/// Admit an ordinary unsigned (DPoP) query. Unsigned requests never carry an
/// idempotency record, so the outcome is always a first-execution authority.
pub(crate) async fn admit_unsigned(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    method: CanonicalHttpMethod,
    headers: &HeaderMap,
) -> Result<VerifiedChatDeviceRequest, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let trust = verifier(runtime, endpoint)?;
    let dpop_headers = read_dpop_headers(headers, endpoint)?;
    let nsid = validated_nsid(endpoint)?;
    let instant = capture_instant(endpoint)?;
    let pre_replay = dpop::verify_ordinary_request_auth(
        trust,
        &dpop_headers.authorization,
        &dpop_headers.proof,
        &nsid,
        &method,
        &instant,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;
    match auth::authorize_unsigned_request(pool, pre_replay)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))?
    {
        AuthorizationOutcome::FirstExecution(authority) => Ok(authority),
        // Unsigned endpoints declare no idempotency record; a completed replay
        // is a repository invariant break, not a wire outcome.
        AuthorizationOutcome::CompletedReplay(_) => Err(ChatFailure::invariant(endpoint)),
    }
}

/// Admit an ordinary signed procedure carrying a `{signedRequest}` body.
pub(crate) async fn admit_signed(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Admission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let trust = verifier(runtime, endpoint)?;
    let dpop_headers = read_dpop_headers(headers, endpoint)?;
    let nsid = validated_nsid(endpoint)?;
    let instant = capture_instant(endpoint)?;
    let pre_replay = dpop::verify_ordinary_request_auth(
        trust,
        &dpop_headers.authorization,
        &dpop_headers.proof,
        &nsid,
        &CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(endpoint))?,
        &instant,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;

    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let canonical = transcript::decode_canonical_signed_mutation(&signed_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    let outcome = auth::authorize_signed_request(pool, pre_replay, canonical)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))?;
    Ok(into_admission(outcome))
}

/// Admit an enrollment-bootstrap request (`enrollDevice`).
pub(crate) async fn admit_enrollment(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Admission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let trust = verifier(runtime, endpoint)?;
    let dpop_headers = read_dpop_headers(headers, endpoint)?;
    let instant = capture_instant(endpoint)?;

    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let enrollment_body = transcript::decode_and_verify_enrollment_body(&signed_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let pre_replay = dpop::verify_enrollment_request_auth(
        trust,
        &dpop_headers.authorization,
        &dpop_headers.proof,
        enrollment_body,
        &instant,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;

    let outcome = auth::authorize_enrollment_request(pool, pre_replay)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))?;
    Ok(into_admission(outcome))
}

/// Admit a rebind-bootstrap request (`rebindDeviceAuthentication`).
pub(crate) async fn admit_rebind(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Admission, ChatFailure> {
    require_cutover(runtime, endpoint)?;
    let trust = verifier(runtime, endpoint)?;
    let dpop_headers = read_dpop_headers(headers, endpoint)?;
    let instant = capture_instant(endpoint)?;

    let signed_bytes = signed_request_bytes(body, endpoint)?;
    let bootstrap = transcript::decode_rebind_bootstrap(&signed_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let pre_replay = dpop::verify_rebind_request_auth(
        trust,
        &dpop_headers.authorization,
        &dpop_headers.proof,
        bootstrap,
        &instant,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidDPoP))?;

    let outcome = auth::authorize_rebind_request(pool, pre_replay)
        .await
        .map_err(|error| auth_repository_failure(endpoint, error))?;
    Ok(into_admission(outcome))
}

fn into_admission(outcome: AuthorizationOutcome) -> Admission {
    match outcome {
        AuthorizationOutcome::FirstExecution(authority) => Admission::Execute(Box::new(authority)),
        AuthorizationOutcome::CompletedReplay(response) => {
            Admission::Replay(replay_response(&response))
        }
    }
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
        E::ReplayDetected | E::DpopBindingMismatch => C::InvalidDPoP,
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

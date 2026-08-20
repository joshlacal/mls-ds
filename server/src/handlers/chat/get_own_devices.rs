//! `blue.catbird.chat.getOwnDevices` — ordinary-unsigned own-device snapshot.
//!
//! This handler is deliberately inert. It admits once, transfers the opaque
//! admission once into the repository-owned facade, and moves the resulting
//! committed bytes into `context::json_ok`.
//!
//! It contains no requester extraction, DTO projection, canonical serializer,
//! retry loop, SQL, transaction, isolation statement, durable-session request,
//! direct directory or inventory call, response-item inspection, or discarded
//! admission. The facade in `chat_protocol::repository::inventory` owns the
//! whole fixed three-attempt boundary, the ordered requester locks, the
//! `ownDeviceView` projection and its durable payload bytes, the session TTL,
//! and the commit-before-bytes ordering.
//!
//! The one surface that must stay here is the transport rendering of the
//! three-attempt ceiling: HTTP 503 plus `Retry-After: 1`. `getOwnDevices`
//! declares no retryable protocol code, so no wire vocabulary is emitted — only
//! a transport-generic name matching the 503 status (Inf-1).

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::{header::RETRY_AFTER, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::inventory::{
    create_own_device_snapshot_for_admission, ExistingDeviceReadFacadeError,
};
use crate::chat_protocol::validation::CanonicalHttpMethod;
use crate::storage::DbPool;

use super::context;
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetOwnDevices;
/// `Retry-After` seconds advertised at the facade's fixed three-attempt ceiling.
const RETRY_AFTER_SECONDS: &str = "1";

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_own_devices(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_own_devices(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    let actor_device_id = context::actor_device_id_from_query(query, ENDPOINT)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission =
        context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers, &actor_device_id)
            .await?;

    match create_own_device_snapshot_for_admission(pool, admission).await {
        Ok(snapshot) => Ok(context::json_ok(snapshot.into_response_bytes())),
        // The facade owns the retry loop; the handler only renders its ceiling.
        Err(ExistingDeviceReadFacadeError::RetryCeiling) => Ok(retry_ceiling_response()),
        Err(error) => Err(facade_failure(error)),
    }
}

/// Map the already-sanitized facade vocabulary. Its variants are unit variants
/// carrying no requester, authority, or row detail.
///
/// `RequestTooBroad` belongs to the `getDevices` audience bound and is
/// unreachable here — `getOwnDevices` takes no DID list — so reaching it would
/// be an internal invariant break. `RetryCeiling` is handled by the caller and
/// never reaches this mapper.
fn facade_failure(error: ExistingDeviceReadFacadeError) -> ChatFailure {
    match error {
        ExistingDeviceReadFacadeError::Storage => ChatFailure::storage(ENDPOINT),
        ExistingDeviceReadFacadeError::Invariant
        | ExistingDeviceReadFacadeError::RequestTooBroad
        | ExistingDeviceReadFacadeError::RetryCeiling => ChatFailure::invariant(ENDPOINT),
    }
}

/// The fixed-ceiling surface: HTTP 503 + `Retry-After: 1`, with no invented
/// protocol vocabulary.
fn retry_ceiling_response() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({ "error": "ServiceUnavailable" })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    response
}

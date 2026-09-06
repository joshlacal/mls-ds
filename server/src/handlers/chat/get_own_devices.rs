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

use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
use crate::chat_protocol::repository::inventory::{
    create_own_device_snapshot_for_admission, ExistingDeviceReadFacadeError,
};
use crate::chat_protocol::validation::{CanonicalHttpMethod, CanonicalUuidV4};
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
    context::require_cutover(runtime, ENDPOINT)?;
    let actor_device_id = parse_query(query)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission =
        context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers, &actor_device_id)
            .await?;

    match create_own_device_snapshot_for_admission(pool, admission).await {
        Ok(snapshot) => Ok(context::json_ok(snapshot.into_response_bytes())),
        // The facade owns the retry loop; the handler only renders its ceiling.
        Err(ExistingDeviceReadFacadeError::RetryCeiling) => Ok(retry_ceiling_response()),
        Err(error) => {
            tracing::error!("create_own_device_snapshot error: {:?}", error);
            Err(facade_failure(error))
        }
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
        ExistingDeviceReadFacadeError::RateLimited { retry_after_secs } => {
            ChatFailure::protocol_with_retry(
                ENDPOINT,
                ChatProtocolErrorCode::RateLimited,
                retry_after_secs,
            )
        }
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

fn parse_query(query: Option<&str>) -> Result<String, ChatFailure> {
    let mut actor_device_id = None;
    let mut page_cursor = None;
    let mut limit = None;
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (raw_key, raw_value) = pair.split_once('=').ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let key = percent_decode(raw_key).ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let value = percent_decode(raw_value).ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        match key.as_str() {
            "actorDeviceId" if actor_device_id.is_none() => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                actor_device_id = Some(canonical.as_str().to_string());
            }
            "pageCursor" if page_cursor.is_none() => {
                if value.is_empty() || value.len() > 512 {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
                page_cursor = Some(value);
            }
            "limit" if limit.is_none() => {
                let parsed = value.parse::<u16>().map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                if !(1..=100).contains(&parsed) {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
                limit = Some(parsed);
            }
            _ => {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
        }
    }
    actor_device_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16)?;
                let lo = (bytes[index + 2] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                index += 3;
            }
            byte if byte.is_ascii() => {
                out.push(byte);
                index += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

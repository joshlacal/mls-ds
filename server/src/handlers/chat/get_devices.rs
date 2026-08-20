//! `blue.catbird.chat.getDevices` — ordinary-unsigned addressable-device query.
//!
//! This handler is deliberately inert. It admits once, transfers the opaque
//! admission once into the repository-owned facade with the public `userDids`
//! values, and moves the resulting canonical bytes into `context::json_ok`.
//!
//! It contains no authority inspection, SQL, transaction, isolation statement,
//! retry loop, DTO projection, serializer, row access, direct directory or
//! inventory call, or discarded admission. Every one of those now lives in
//! `chat_protocol::repository::inventory`, which owns the ordered requester
//! locks, the attempt verification, the `addressableDevice` projection, and the
//! canonical response bytes.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
use crate::chat_protocol::repository::inventory::{
    read_addressable_devices_for_admission, ExistingDeviceReadFacadeError,
};
use crate::chat_protocol::validation::{BareDid, CanonicalHttpMethod, CanonicalUuidV4};
use crate::storage::DbPool;
use super::context;
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetDevices;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_devices(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_devices(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let (actor_device_id, dids) = parse_query(query)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission =
        context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers, &actor_device_id)
            .await?;

    let response = read_addressable_devices_for_admission(pool, admission, &dids)
        .await
        .map_err(facade_failure)?;

    Ok(context::json_ok(response.into_response_bytes()))
}

/// Map the already-sanitized facade vocabulary to this endpoint's declared wire
/// surface. The facade's variants are unit variants carrying no requester,
/// authority, or row detail, so nothing here can widen what reaches the client.
///
/// `RetryCeiling` belongs to the `getOwnDevices` three-attempt boundary and is
/// unreachable from the single-attempt `getDevices` facade; reaching it would be
/// an internal invariant break, not a client-visible condition.
fn facade_failure(error: ExistingDeviceReadFacadeError) -> ChatFailure {
    match error {
        ExistingDeviceReadFacadeError::RequestTooBroad => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        ExistingDeviceReadFacadeError::Storage => ChatFailure::storage(ENDPOINT),
        ExistingDeviceReadFacadeError::Invariant | ExistingDeviceReadFacadeError::RetryCeiling => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}

fn parse_query(query: Option<&str>) -> Result<(String, Vec<String>), ChatFailure> {
    let mut actor_device_id = None;
    let mut user_dids: Vec<String> = Vec::new();
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (raw_key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
        let key = percent_decode(raw_key)
            .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
        let value = percent_decode(raw_value)
            .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
        match key.as_str() {
            "actorDeviceId" if actor_device_id.is_none() => {
                let canonical = CanonicalUuidV4::parse(&value)
                    .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
                actor_device_id = Some(canonical.as_str().to_string());
            }
            "userDids" => {
                let did = BareDid::parse(&value)
                    .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
                let did_str = did.as_str().to_string();
                if let Some(prev) = user_dids.last() {
                    if prev.as_bytes() >= did_str.as_bytes() {
                        return Err(ChatFailure::protocol(
                            ENDPOINT,
                            ChatProtocolErrorCode::InvalidRequest,
                        ));
                    }
                }
                user_dids.push(did_str);
            }
            _ => {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
        }
    }
    let actor_device_id = actor_device_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    if user_dids.is_empty() || user_dids.len() > 5 {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    Ok((actor_device_id, user_dids))
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

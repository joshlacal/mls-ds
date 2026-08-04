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
use crate::chat_protocol::validation::CanonicalHttpMethod;
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
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission = context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers).await?;

    let dids = parse_user_dids(query);
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

/// Collect the repeated `userDids` query parameter values in wire order. These
/// are public request values, not authority: bounds enforcement (too many /
/// zero) belongs to the facade's bounded audience read, so this only decodes.
fn parse_user_dids(query: Option<&str>) -> Vec<String> {
    let Some(query) = query else {
        return Vec::new();
    };
    let mut dids = Vec::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        if key != "userDids" {
            continue;
        }
        if let Some(raw) = parts.next() {
            dids.push(percent_decode(raw));
        }
    }
    dids
}

/// Minimal `application/x-www-form-urlencoded` value decode (`+` → space, `%XX`
/// → byte). Invalid escapes are passed through literally.
fn percent_decode(value: &str) -> String {
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
                let hi = (bytes[index + 1] as char).to_digit(16);
                let lo = (bytes[index + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

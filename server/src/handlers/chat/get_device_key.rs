//! Exact historical candidate-key lookup. Authorization remains with the
//! authenticated entry/receipt and signature, never with these public bytes.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::chat_protocol::{
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::inventory::{read_device_key_for_admission, DeviceKeyReadError},
    validation::{BareDid, CanonicalHttpMethod, CanonicalUuidV4, KeyThumbprint},
};
use crate::storage::DbPool;
use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
const ENDPOINT: ChatEndpoint = ChatEndpoint::GetDeviceKey;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match read(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}
async fn read(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let (actor, owner, device, key) = parse_query(query)?;
    for name in ["x-catbird-chat-device-id", "x-catbird-device-id"] {
        let mut values = headers.get_all(name).iter();
        if let Some(value) = values.next() {
            if values.next().is_some() || value.to_str().ok() != Some(actor.as_str()) {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::DeviceBindingMismatch,
                ));
            }
        }
    }
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission =
        context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers, &actor).await?;
    let bytes = read_device_key_for_admission(pool, admission, &owner, device, &key)
        .await
        .map_err(|error| match error {
            DeviceKeyReadError::NotFound => {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceKeyNotFound)
            }
            DeviceKeyReadError::Storage => ChatFailure::storage(ENDPOINT),
            DeviceKeyReadError::Invariant => ChatFailure::invariant(ENDPOINT),
        })?;
    Ok(context::json_ok(bytes))
}
fn invalid() -> ChatFailure {
    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
}
fn parse_query(query: Option<&str>) -> Result<(String, String, uuid::Uuid, String), ChatFailure> {
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if !matches!(
            key.as_ref(),
            "actorDeviceId" | "ownerDid" | "deviceId" | "keyId"
        ) || fields
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(invalid());
        }
    }
    if fields.len() != 4 {
        return Err(invalid());
    }
    let actor = CanonicalUuidV4::parse(&fields["actorDeviceId"]).map_err(|_| invalid())?;
    let device = CanonicalUuidV4::parse(&fields["deviceId"]).map_err(|_| invalid())?;
    let owner = BareDid::parse(&fields["ownerDid"]).map_err(|_| invalid())?;
    let key = KeyThumbprint::parse(&fields["keyId"]).map_err(|_| invalid())?;
    Ok((
        actor.as_str().into(),
        owner.as_str().into(),
        uuid::Uuid::from_bytes(*device.as_bytes()),
        key.as_str().into(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_tuple_requires_canonical_fields_and_no_duplicates() {
        let query = "actorDeviceId=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa&ownerDid=did%3Aplc%3Aaaaaaaaaaaaaaaaaaaaaaaaa&deviceId=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb&keyId=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(parse_query(Some(query)).is_ok());
        for suffix in [
            "&keyId=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "&current=true",
            "&ownerDid=did%3Aplc%3Abbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            assert!(parse_query(Some(&format!("{query}{suffix}"))).is_err());
        }
        assert!(parse_query(Some(
            &query.replace("bbbbbbbb-bbbb-4bbb", "BBBBBBBB-bbbb-4bbb")
        ))
        .is_err());
        assert!(parse_query(Some(
            &query.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short")
        ))
        .is_err());
    }
}

//! `blue.catbird.chat.getEntries` — exact-device visible entry paging.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::chat_protocol::{
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::entry_read::{get_entries_for_admission, EntryReadFacadeError},
    validation::{CanonicalHttpMethod, CanonicalUuidV4, MAX_SAFE_INTEGER},
};
use crate::storage::DbPool;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetEntries;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_entries(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_entries(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let (actor_device_id, conversation_id, after_seq, limit) = parse_query(query)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let (admission, subject) = context::admit_unsigned_read_for_subject(
        pool,
        runtime,
        ENDPOINT,
        method,
        headers,
        &actor_device_id,
    )
    .await?;
    match get_entries_for_admission(pool, admission, conversation_id, after_seq, limit).await {
        Ok(response) => Ok(context::json_ok(response.into_response_bytes())),
        Err(EntryReadFacadeError::NotEntitled) => {
            if let Some(resolver) = runtime.resolver() {
                let device = Uuid::parse_str(&actor_device_id)
                    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                if let Some(bytes) = crate::federation::group_relay::try_relay_recovery_entries(
                    pool,
                    resolver,
                    conversation_id,
                    &subject,
                    device,
                    after_seq,
                    limit,
                )
                .await?
                {
                    return Ok(context::json_ok(bytes));
                }
            }
            Err(facade_failure(EntryReadFacadeError::NotEntitled))
        }
        Err(error) => Err(facade_failure(error)),
    }
}

fn parse_query(query: Option<&str>) -> Result<(String, Uuid, u64, i64), ChatFailure> {
    let mut actor_device_id = None;
    let mut conversation_id = None;
    let mut after_seq = None;
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
            "conversationId" if conversation_id.is_none() => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                let uuid = Uuid::parse_str(canonical.as_str()).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                conversation_id = Some(uuid);
            }
            "afterSeq" if after_seq.is_none() => {
                let parsed = value.parse::<i64>().map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                if !(0..=MAX_SAFE_INTEGER).contains(&parsed) {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
                let seq = u64::try_from(parsed).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                after_seq = Some(seq);
            }
            "limit" if limit.is_none() => {
                let parsed = value.parse::<i64>().map_err(|_| {
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
    let actor_device_id = actor_device_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let conversation_id = conversation_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let after_seq = after_seq
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let limit = limit.unwrap_or(100);
    Ok((actor_device_id, conversation_id, after_seq, limit))
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

pub(crate) fn facade_failure(error: EntryReadFacadeError) -> ChatFailure {
    tracing::error!("get_entries facade_failure: {:?}", error);
    match error {
        EntryReadFacadeError::AccessOutsideMembershipInterval => ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::AccessOutsideMembershipInterval,
        ),
        EntryReadFacadeError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound)
        }
        EntryReadFacadeError::DeviceRevoked => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
        }
        EntryReadFacadeError::InvitationNotPending => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvitationNotPending)
        }
        EntryReadFacadeError::NotEntitled => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled)
        }
        EntryReadFacadeError::InvalidRequest => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        EntryReadFacadeError::Storage | EntryReadFacadeError::Invariant => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_failure_maps_not_entitled_to_declared_protocol_error() {
        let failure = facade_failure(EntryReadFacadeError::NotEntitled);
        assert_eq!(failure.code(), Some(ChatProtocolErrorCode::NotEntitled));
    }

    #[test]
    fn facade_failure_maps_access_outside_membership_interval() {
        let failure = facade_failure(EntryReadFacadeError::AccessOutsideMembershipInterval);
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::AccessOutsideMembershipInterval)
        );
    }

    #[test]
    fn parse_query_validates_mandatory_parameters() {
        let convo = Uuid::new_v4();
        let device = Uuid::new_v4();
        let query = format!(
            "actorDeviceId={}&conversationId={}&afterSeq=0&limit=10",
            device, convo
        );
        let parsed = parse_query(Some(&query)).expect("valid query");
        assert_eq!(parsed.0, device.to_string());
        assert_eq!(parsed.1, convo);
        assert_eq!(parsed.2, 0);
        assert_eq!(parsed.3, 10);
    }

    #[test]
    fn parse_query_rejects_missing_actor_device() {
        let convo = Uuid::new_v4();
        let query = format!("conversationId={}&afterSeq=0", convo);
        assert!(parse_query(Some(&query)).is_err());
    }
}

pub(crate) async fn federated_recovery_read_window(
    pool: &DbPool,
    principal: crate::auth::VerifiedServicePrincipal,
    device: Uuid,
    conversation: Uuid,
    sequencer: &str,
    post_erasure: Option<crate::chat_protocol::repository::entry_read::PageRequest>,
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_federated_read(pool, ENDPOINT, principal, &device.to_string()).await?;
    let window = crate::chat_protocol::repository::entry_read::acknowledged_recovery_read_window(
        pool,
        admission,
        conversation,
        sequencer,
        post_erasure,
    )
    .await
    .map_err(facade_failure)?;
    Ok(axum::Json(window).into_response())
}

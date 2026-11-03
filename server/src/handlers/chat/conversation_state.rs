//! `blue.catbird.chat.getConversationState`.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::conversation::{
            read_conversation_state_for_admission, ConversationStateReadError,
        },
        validation::{CanonicalHttpMethod, CanonicalUuidV4},
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetConversationState;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_conversation_state(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_conversation_state(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let (actor_device_id, conversation_id) = parse_query(query)?;
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
    // A remote group's roster and coordinates belong to its sequencer, and a
    // C33 pair's to its coordinator when this DS homes the pair's sender only.
    if let Ok(device_id) = uuid::Uuid::parse_str(&actor_device_id) {
        use crate::federation::group_relay::{try_relay_group_state, GroupRelayError};
        match try_relay_group_state(pool, &subject, device_id, conversation_id).await {
            Ok(Some(bytes)) => return Ok(context::json_ok(bytes)),
            Ok(None) => {}
            Err(GroupRelayError::Rejected(code)) => {
                return Err(ChatFailure::protocol(ENDPOINT, code));
            }
            Err(GroupRelayError::Internal(_)) => return Err(ChatFailure::storage(ENDPOINT)),
            Err(error @ GroupRelayError::Unavailable(_)) => {
                // Only a group mirror the member is current in has state to
                // fall back on: an index-only member's roster and deletion
                // evidence are the sequencer's, and a C33 sender's home holds
                // no leaf authority for the peer's devices.
                let mut conn = pool
                    .acquire()
                    .await
                    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
                use crate::chat_protocol::repository::entry_read::{
                    remote_group_standing, RemoteGroupStanding,
                };
                let standing = remote_group_standing(&mut conn, conversation_id, &subject)
                    .await
                    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
                let mirrored: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)",
                )
                .bind(conversation_id)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
                if standing == RemoteGroupStanding::IndexOnly || !mirrored {
                    tracing::warn!(
                        ?error,
                        "sequencer state read unavailable without a home mirror"
                    );
                    // The sequencer decided nothing: the identical read retries.
                    return Err(ChatFailure::unavailable(ENDPOINT));
                }
                tracing::warn!(
                    ?error,
                    "sequencer state read unavailable; serving the home mirror"
                );
            }
        }
    }

    let response = read_conversation_state_for_admission(pool, admission, conversation_id)
        .await
        .map_err(facade_failure)?;
    Ok(context::json_ok(response.into_response_bytes()))
}

/// Answer a `getConversationState` read that the account's home DS relayed.
pub(crate) async fn execute_federated_read(
    pool: &DbPool,
    principal: crate::auth::VerifiedServicePrincipal,
    actor_device_id: uuid::Uuid,
    conversation_id: uuid::Uuid,
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_federated_read(pool, ENDPOINT, principal, &actor_device_id.to_string())
            .await?;
    let response = read_conversation_state_for_admission(pool, admission, conversation_id)
        .await
        .map_err(facade_failure)?;
    Ok(context::json_ok(response.into_response_bytes()))
}

fn facade_failure(error: ConversationStateReadError) -> ChatFailure {
    match error {
        ConversationStateReadError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound)
        }
        ConversationStateReadError::NotEntitled => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled)
        }
        ConversationStateReadError::AccessOutsideMembershipInterval => ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::AccessOutsideMembershipInterval,
        ),
        ConversationStateReadError::DeviceRevoked => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
        }
        ConversationStateReadError::Storage | ConversationStateReadError::Invariant => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}

fn parse_query(query: Option<&str>) -> Result<(String, uuid::Uuid), ChatFailure> {
    let mut actor_device_id = None;
    let mut conversation_id = None;
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
            "actorDeviceId" => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                actor_device_id = Some(canonical.as_str().to_string());
            }
            "conversationId" | "convoId" => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                let uuid = uuid::Uuid::parse_str(canonical.as_str()).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                conversation_id = Some(uuid);
            }
            "include" => {}
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
    Ok((actor_device_id, conversation_id))
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

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
    let (conversation_id, after_seq, limit) = parse_query(query)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission = context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers).await?;
    let response = get_entries_for_admission(pool, admission, conversation_id, after_seq, limit)
        .await
        .map_err(facade_failure)?;
    Ok(context::json_ok(response.into_response_bytes()))
}

fn parse_query(query: Option<&str>) -> Result<(Uuid, u64, i64), ChatFailure> {
    let mut conversation_id = None;
    let mut after_seq = None;
    let mut limit = None;
    let mut limit_seen = false;
    for pair in query.unwrap_or_default().split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        match key {
            "conversationId" => conversation_id = Some(value),
            "afterSeq" => after_seq = Some(value),
            "limit" => {
                limit_seen = true;
                limit = value.parse::<i64>().ok();
            }
            _ => {}
        }
    }
    let conversation_id = conversation_id
        .and_then(|value| CanonicalUuidV4::parse(value).ok())
        .and_then(|value| Uuid::from_slice(value.as_bytes()).ok())
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let after_seq = after_seq
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (0..=MAX_SAFE_INTEGER).contains(value))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let limit = match (limit_seen, limit) {
        (true, None) => {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }
        (false, None) => 100,
        (_, Some(value)) if (1..=100).contains(&value) => value,
        (_, Some(_)) => {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }
    };
    Ok((conversation_id, after_seq, limit))
}

fn facade_failure(error: EntryReadFacadeError) -> ChatFailure {
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

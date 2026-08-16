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
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission = context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers).await?;
    let conversation_id = parse_conversation_id(query)
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

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

/// Parse exactly one canonical `conversationId` query parameter. Unknown
/// parameters and duplicate/malformed values are rejected so a client cannot
/// smuggle a second audience into the authenticated request.
fn parse_conversation_id(query: Option<&str>) -> Option<uuid::Uuid> {
    let mut found = None;
    for pair in query?.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key != "conversationId" || found.is_some() {
            return None;
        }
        let value = percent_decode(value)?;
        let canonical = CanonicalUuidV4::parse(&value).ok()?;
        found = uuid::Uuid::parse_str(canonical.as_str()).ok();
    }
    found
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

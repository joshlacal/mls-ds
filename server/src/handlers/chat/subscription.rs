//! `blue.catbird.chat.getSubscriptionTicket` ticket compositor.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::generated::blue_catbird::chat::get_subscription_ticket::{
    GetSubscriptionTicket, GetSubscriptionTicketOutput,
};
use jacquard_common::DefaultStr;
use uuid::Uuid;

use crate::{
    chat_protocol::validation::{CanonicalHttpMethod, CanonicalUuidV4},
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::ticket::{mint_subscription_ticket_for_admission, TicketRepositoryError},
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetSubscriptionTicket;
pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if let Err(failure) = context::require_cutover(&runtime, ENDPOINT) {
        return failure.into_response();
    }
    if let Some(q) = query.as_deref() {
        if !q.is_empty() {
            return ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                .into_response();
        }
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !is_json_content_type(content_type) {
        return ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
            .into_response();
    }
    let input: GetSubscriptionTicket<DefaultStr> = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(_) => {
            return ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                .into_response();
        }
    };
    match issue(&pool, &runtime, &headers, input).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn issue(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    input: GetSubscriptionTicket<DefaultStr>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    CanonicalUuidV4::parse(input.actor_device_id.as_ref())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    parse_canonical_capability(input.inventory_session_id.as_ref())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    parse_canonical_capability(input.event_cursor.as_ref())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission = context::admit_unsigned_read(
        pool,
        runtime,
        ENDPOINT,
        method,
        headers,
        input.actor_device_id.as_ref(),
    )
    .await?;
    let sealer = runtime
        .cursor_sealer()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let (ticket, expires_at) = mint_subscription_ticket_for_admission(
        pool,
        admission,
        input.inventory_session_id.as_ref(),
        input.event_cursor.as_ref(),
        sealer,
    )
    .await
    .map_err(map_ticket_error)?;
    let endpoint = runtime
        .subscription_endpoint()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?
        .to_owned();
    let endpoint = jacquard_common::types::string::UriValue::<DefaultStr>::new_owned(endpoint)
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let output = GetSubscriptionTicketOutput {
        endpoint,
        expires_at: chrono_to_datetime(expires_at),
        ticket: ticket.into(),
        extra_data: None,
    };
    let bytes = serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    Ok(context::json_ok(bytes))
}

fn is_json_content_type(header_value: Option<&str>) -> bool {
    let Some(header) = header_value else {
        return false;
    };
    let mut parts = header.split(';');
    let media_type = parts.next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return false;
    }
    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let Some((key, value)) = param.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return false;
        }
    }
    true
}

fn parse_canonical_capability(value: &str) -> Result<String, ChatProtocolErrorCode> {
    if value.len() != 43 {
        return Err(ChatProtocolErrorCode::InvalidRequest);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ChatProtocolErrorCode::InvalidRequest)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ChatProtocolErrorCode::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn map_ticket_error(error: TicketRepositoryError) -> ChatFailure {
    use TicketRepositoryError as E;
    match error {
        E::CursorMismatch
        | E::InvalidCapability
        | E::CapabilityMismatch
        | E::SessionMissing
        | E::SessionBindingMismatch => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InventorySessionMismatch)
        }
        E::SessionIncomplete => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InventoryIncomplete)
        }
        E::TicketExpired | E::CursorExpired => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InventorySessionExpired)
        }
        E::DeviceBindingMismatch => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
        }
        E::Database(_) => ChatFailure::storage(ENDPOINT),
        E::InvalidTicketHash
        | E::PathMismatch
        | E::TicketNotFound
        | E::TicketAlreadyConsumed
        | E::InvalidReceipt => ChatFailure::invariant(ENDPOINT),
    }
}

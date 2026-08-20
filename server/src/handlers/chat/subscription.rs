//! `blue.catbird.chat.getSubscriptionTicket` ticket compositor.

use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
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
    Json(input): Json<GetSubscriptionTicket<DefaultStr>>,
) -> Response {
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
    let canonical = CanonicalUuidV4::parse(input.inventory_session_id.as_ref())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let inventory_session_id = Uuid::parse_str(canonical.as_str())
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
        inventory_session_id,
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

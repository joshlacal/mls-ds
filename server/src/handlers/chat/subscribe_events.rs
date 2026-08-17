//! `blue.catbird.chat.subscribeEvents` ticket-only WebSocket compositor.

use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::generated::blue_catbird::chat::SubscriptionMessage;
use futures::StreamExt;
use serde::Deserialize;

use crate::realtime::StreamEvent;
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            subscription::{
                ensure_initial_receipt, materialize_envelope, replay_high_water, visible_events,
            },
            ticket::{
                consume_subscription_ticket, ticket_hash, ConsumedTicket, TicketRepositoryError,
                SUBSCRIBE_EVENTS_PATH,
            },
        },
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::SubscribeEvents;
const BATCH_SIZE: i64 = 128;

// The generated subscription parameter module is feature-gated by
// catbird-atproto's client-side `streaming` feature. Keep the server extractor
// exact and minimal while all emitted protocol objects remain generated DTOs.
#[derive(Debug, Deserialize)]
pub(super) struct SubscribeEventsQuery {
    cursor: String,
    ticket: String,
}

pub(super) async fn handle(
    ws: WebSocketUpgrade,
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    Query(query): Query<SubscribeEventsQuery>,
) -> Response {
    match authorize(&pool, &runtime, &query).await {
        Ok((ticket, replay_through)) => ws
            .on_upgrade(move |socket| {
                stream(
                    socket,
                    pool,
                    runtime,
                    ticket,
                    query.cursor.to_string(),
                    replay_through,
                )
            })
            .into_response(),
        Err(failure) => failure.into_response(),
    }
}

async fn authorize(
    pool: &DbPool,
    runtime: &ChatRuntime,
    query: &SubscribeEventsQuery,
) -> Result<(ConsumedTicket, i64), ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    runtime
        .cursor_sealer()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let opaque = URL_SAFE_NO_PAD
        .decode(query.ticket.as_bytes())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidTicket))?;
    if opaque.len() != 32 || URL_SAFE_NO_PAD.encode(&opaque) != query.ticket {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidTicket,
        ));
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let now = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let ticket = consume_subscription_ticket(
        &mut transaction,
        &ticket_hash(&opaque),
        query.cursor.as_ref(),
        SUBSCRIBE_EVENTS_PATH,
        now,
    )
    .await
    .map_err(map_ticket_error)?;
    ensure_initial_receipt(&mut transaction, &ticket)
        .await
        .map_err(map_ticket_error)?;
    let replay_through = replay_high_water(&mut transaction, &ticket)
        .await
        .map_err(map_ticket_error)?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    Ok((ticket, replay_through))
}

async fn stream(
    mut socket: WebSocket,
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    ticket: ConsumedTicket,
    initial_cursor: String,
    replay_through: i64,
) {
    let Some(sealer) = runtime.cursor_sealer() else {
        return;
    };
    let mut scan_position = ticket.event_position;
    let mut previous_cursor = initial_cursor;
    let mut previous_hash = ticket.event_cursor_hash;

    // Replay to the transaction-frozen high-water first. New commits can race
    // this phase safely: they are strictly above `replay_through` and are read
    // by the immediate reconciliation pass below.
    if !send_through(
        &mut socket,
        &pool,
        &ticket,
        sealer,
        &mut scan_position,
        &mut previous_cursor,
        &mut previous_hash,
        replay_through,
    )
    .await
    {
        return;
    }
    let mut typing_receivers = HashMap::new();

    loop {
        // Reconcile the replay/live race before waiting. Subsequent passes use
        // the same monotonic predicate, so durable events are neither missed
        // nor duplicated even though PostgreSQL is the live notification
        // authority rather than the legacy socket store.
        let mut transaction = match pool.begin().await {
            Ok(transaction) => transaction,
            Err(_) => return,
        };
        let through = match replay_high_water(&mut transaction, &ticket).await {
            Ok(value) => value,
            Err(_) => return,
        };
        if transaction.commit().await.is_err()
            || !send_through(
                &mut socket,
                &pool,
                &ticket,
                sealer,
                &mut scan_position,
                &mut previous_cursor,
                &mut previous_hash,
                through,
            )
            .await
        {
            return;
        }

        if refresh_typing_receivers(&pool, &runtime, &ticket, &mut typing_receivers)
            .await
            .is_err()
        {
            return;
        }
        for receiver in typing_receivers.values_mut() {
            loop {
                match receiver.try_recv() {
                    Ok(event @ StreamEvent::CleanTypingEvent { .. }) => {
                        let Some(typing) = event.clean_typing_payload() else {
                            return;
                        };
                        let message = SubscriptionMessage::TypingEvent(Box::new(typing));
                        let Ok(frame) = serde_json::to_string(&message) else {
                            return;
                        };
                        if socket.send(Message::Text(frame.into())).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                }
            }
        }

        tokio::select! {
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(Message::Ping(payload))) => {
                    if socket.send(Message::Pong(payload)).await.is_err() { return; }
                }
                _ => {}
            },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

async fn refresh_typing_receivers(
    pool: &DbPool,
    runtime: &ChatRuntime,
    ticket: &ConsumedTicket,
    receivers: &mut HashMap<String, tokio::sync::broadcast::Receiver<StreamEvent>>,
) -> Result<(), sqlx::Error> {
    let conversations: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT conversation_id
             FROM chat.application_intervals
            WHERE recipient_did=$1 AND recipient_device_id=$2
              AND terminal_seq IS NULL
            ORDER BY conversation_id"#,
    )
    .bind(&ticket.user_did)
    .bind(ticket.device_id)
    .fetch_all(pool)
    .await?;
    let entitled: std::collections::HashSet<String> =
        conversations.into_iter().map(|id| id.to_string()).collect();
    receivers.retain(|conversation_id, _| entitled.contains(conversation_id));
    for conversation_id in entitled {
        if !receivers.contains_key(&conversation_id) {
            receivers.insert(
                conversation_id.clone(),
                runtime.subscribe_typing(&conversation_id).await,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_through(
    socket: &mut WebSocket,
    pool: &DbPool,
    ticket: &ConsumedTicket,
    sealer: &crate::chat_protocol::CursorSealer,
    scan_position: &mut i64,
    previous_cursor: &mut String,
    previous_hash: &mut [u8; 32],
    through_position: i64,
) -> bool {
    while *scan_position < through_position {
        let mut transaction = match pool.begin().await {
            Ok(transaction) => transaction,
            Err(_) => return false,
        };
        let events = match visible_events(
            &mut transaction,
            ticket,
            *scan_position,
            through_position,
            BATCH_SIZE,
        )
        .await
        {
            Ok(events) => events,
            Err(_) => return false,
        };
        if events.is_empty() {
            if transaction.commit().await.is_err() {
                return false;
            }
            *scan_position = through_position;
            break;
        }

        let mut frames = Vec::with_capacity(events.len());
        for event in events {
            *scan_position = event.event_position;
            let (message, cursor, cursor_hash) = match materialize_envelope(
                &mut transaction,
                ticket,
                event,
                previous_cursor,
                *previous_hash,
                sealer,
            )
            .await
            {
                Ok(value) => value,
                Err(_) => return false,
            };
            let frame = match serde_json::to_string(&message) {
                Ok(frame) => frame,
                Err(_) => return false,
            };
            *previous_cursor = cursor;
            *previous_hash = cursor_hash;
            frames.push(frame);
        }
        if transaction.commit().await.is_err() {
            return false;
        }
        // Receipt commit precedes each frame. A lost response is replayed from
        // the sealed receipt; the client never observes an uncommitted cursor.
        for frame in frames {
            if socket.send(Message::Text(frame.into())).await.is_err() {
                return false;
            }
        }
    }
    true
}

fn map_ticket_error(error: TicketRepositoryError) -> ChatFailure {
    use TicketRepositoryError as E;
    match error {
        E::CursorExpired | E::TicketExpired => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::CursorExpired)
        }
        E::DeviceBindingMismatch => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
        }
        E::InvalidCapability
        | E::CapabilityMismatch
        | E::InvalidTicketHash
        | E::CursorMismatch
        | E::PathMismatch
        | E::TicketNotFound
        | E::TicketAlreadyConsumed
        | E::SessionMissing
        | E::SessionBindingMismatch
        | E::SessionIncomplete => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidTicket)
        }
        E::Database(_) => ChatFailure::storage(ENDPOINT),
        E::InvalidReceipt => ChatFailure::invariant(ENDPOINT),
    }
}

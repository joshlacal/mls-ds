//! WebSocket handler for subscribeConvoEvents
//!
//! Implements AT Protocol subscription pattern with DAG-CBOR framing.
//! Features:
//! - Ticket-based authentication
//! - Cursor-based backfill for missed events
//! - Connection limits per user
//! - Bi-directional messaging support

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::Response,
};
use dashmap::DashMap;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::{wrappers::BroadcastStream, StreamMap};
use tracing::{debug, error, info, warn};

use std::collections::HashSet;

use crate::{
    federation::UpstreamManager,
    handlers::subscription_ticket::{verify_ticket, TicketClaims},
    realtime::sse::{SseState, StreamEvent},
    storage::DbPool,
};

// MARK: - Connection Tracking

/// Maximum concurrent WebSocket connections per user DID
const MAX_CONNECTIONS_PER_USER: usize = 5;

/// Server-side heartbeat interval (ping every 30 seconds to detect stale connections)
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Tracks active WebSocket connections per user
pub struct ConnectionTracker {
    /// Map from user DID to number of active connections
    connections: DashMap<String, AtomicUsize>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Try to acquire a connection slot for a user
    /// Returns true if successful, false if limit exceeded
    pub fn try_acquire(&self, user_did: &str) -> bool {
        let entry = self
            .connections
            .entry(user_did.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let current = entry.fetch_add(1, Ordering::SeqCst);

        if current >= MAX_CONNECTIONS_PER_USER {
            // Undo the increment
            entry.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Release a connection slot for a user
    pub fn release(&self, user_did: &str) {
        // Use entry API to acquire write lock immediately, avoiding
        // read-lock -> write-lock deadlock in DashMap
        if let dashmap::mapref::entry::Entry::Occupied(entry) =
            self.connections.entry(user_did.to_string())
        {
            let prev = entry.get().fetch_sub(1, Ordering::SeqCst);
            // Clean up entry if no connections remain
            if prev <= 1 {
                entry.remove();
            }
        }
    }

    /// Get current connection count for a user
    pub fn count(&self, user_did: &str) -> usize {
        self.connections
            .get(user_did)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// Global connection tracker using once_cell (already a dependency)
use once_cell::sync::Lazy;
static CONNECTION_TRACKER: Lazy<ConnectionTracker> = Lazy::new(ConnectionTracker::new);

// MARK: - Types

/// WebSocket query parameters for subscribeConvoEvents
#[derive(Debug, Deserialize)]
pub struct SubscribeQuery {
    /// Authentication ticket from getSubscriptionTicket
    pub ticket: String,
    /// Resume from cursor (ULID string)
    pub cursor: Option<String>,
}

/// AT Protocol WebSocket message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Operation: 1 = message, -1 = error
    pub op: i32,
    /// Type identifier (short form, e.g. "#messageEvent")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// Error payload for WebSocket errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Client-to-server message types for bi-directional messaging
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum ClientMessage {
    /// Client is typing (DEPRECATED: Prefer E2EE ephemeral messages via v2.sendEphemeral.
    /// This creates plaintext typing events visible to the server.)
    #[serde(rename = "blue.catbird.mls.subscribeConvoEvents#typing")]
    Typing {
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "isTyping")]
        is_typing: bool,
    },
    /// Client acknowledges read position
    #[serde(rename = "blue.catbird.mls.subscribeConvoEvents#ack")]
    Ack {
        /// Sequence number being acknowledged
        seq: i64,
    },
    /// Client ping for keep-alive
    #[serde(rename = "blue.catbird.mls.subscribeConvoEvents#ping")]
    Ping,
}

/// Server response to client messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    pub seq: i64,
    pub ok: bool,
}

// MARK: - Handler

/// WebSocket handler for subscribeConvoEvents
/// GET /xrpc/blue.catbird.mls.subscribeConvoEvents (WebSocket upgrade)
pub async fn subscribe_convo_events(
    ws: WebSocketUpgrade,
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(upstream_manager): State<Option<Arc<UpstreamManager>>>,
    Query(query): Query<SubscribeQuery>,
) -> Result<Response, StatusCode> {
    // Verify the ticket
    let claims = match verify_ticket(&query.ticket) {
        Ok(c) => c,
        Err(e) => {
            warn!("Invalid subscription ticket: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_did = claims.sub.clone();
    let convo_id = claims.convo_id.clone();

    // Check connection limit
    if !CONNECTION_TRACKER.try_acquire(&user_did) {
        warn!(
            user = %crate::crypto::redact_for_log(&user_did),
            current_connections = CONNECTION_TRACKER.count(&user_did),
            "Connection limit exceeded for user"
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        convo = convo_id.as_deref().map(|c| crate::crypto::redact_for_log(c)).unwrap_or_default(),
        cursor = ?query.cursor,
        connections = CONNECTION_TRACKER.count(&user_did),
        "WebSocket subscription request validated"
    );

    // If convo_id specified, verify membership (belt and suspenders)
    if let Some(ref cid) = convo_id {
        let is_member = crate::storage::is_member(&pool, &user_did, cid)
            .await
            .map_err(|e| {
                error!(error = ?e, "Membership check failed");
                CONNECTION_TRACKER.release(&user_did);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if !is_member {
            warn!(
                convo = %crate::crypto::redact_for_log(cid),
                user = %crate::crypto::redact_for_log(&user_did),
                "User not a member of conversation"
            );
            CONNECTION_TRACKER.release(&user_did);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let pool_clone = pool.clone();
    let user_did_clone = user_did.clone();
    let upstream_clone = upstream_manager.clone();

    // Upgrade to WebSocket
    Ok(ws.on_upgrade(move |socket| async move {
        handle_socket(
            socket,
            pool_clone,
            sse_state,
            upstream_clone,
            user_did_clone.clone(),
            convo_id,
            query.cursor,
        )
        .await;
        // Release connection slot when done
        CONNECTION_TRACKER.release(&user_did_clone);
    }))
}

// MARK: - Socket Handler

/// Handle the WebSocket connection
async fn handle_socket(
    socket: WebSocket,
    pool: DbPool,
    sse_state: Arc<SseState>,
    upstream_manager: Option<Arc<UpstreamManager>>,
    user_did: String,
    target_convo_id: Option<String>,
    resume_cursor: Option<String>,
) {
    let (sender, mut receiver) = socket.split();
    // Wrap sender in Arc<Mutex> for shared access from heartbeat and send tasks
    let sender = Arc::new(Mutex::new(sender));
    let mut stream_map = StreamMap::new();

    // Sequence counter for this session (starts at 0, increments per event)
    let mut seq: i64 = 0;

    // Track remote (upstream) subscriptions for cleanup on disconnect
    let mut remote_subscriptions: Vec<(String, String)> = Vec::new();

    // 1. Setup Subscriptions
    if let Some(ref cid) = target_convo_id {
        // Single conversation mode — check if remote
        let sequencer_ds = get_sequencer_ds(&pool, cid).await;

        match (&sequencer_ds, &upstream_manager) {
            (Some(seq_did), Some(um)) => {
                // Remote conversation with federation enabled
                match um.subscribe(cid, seq_did, resume_cursor.as_deref()).await {
                    Ok(rx) => {
                        stream_map.insert(cid.clone(), BroadcastStream::new(rx));
                        remote_subscriptions.push((cid.clone(), seq_did.clone()));
                        debug!(
                            convo = %crate::crypto::redact_for_log(cid),
                            "Subscribed to remote conversation via upstream"
                        );
                    }
                    Err(e) => {
                        warn!(
                            convo = %crate::crypto::redact_for_log(cid),
                            error = %e,
                            "Failed upstream subscribe, falling back to local"
                        );
                        let tx = sse_state.get_channel(cid).await;
                        stream_map.insert(cid.clone(), BroadcastStream::new(tx.subscribe()));
                    }
                }
            }
            _ => {
                // Local conversation or federation disabled
                let tx = sse_state.get_channel(cid).await;
                stream_map.insert(cid.clone(), BroadcastStream::new(tx.subscribe()));
            }
        }

        // Backfill only for local conversations (upstream handles its own backfill via cursor)
        if sequencer_ds.is_none() {
            if let Some(ref cursor) = resume_cursor {
                if !cursor.is_empty() {
                    match backfill_events(&pool, cid, cursor).await {
                        Ok(events) => {
                            info!(
                                convo = %crate::crypto::redact_for_log(cid),
                                backfill_count = events.len(),
                                "Sending backfill events"
                            );
                            for (event, _event_cursor) in events {
                                seq += 1;
                                let mut sender_guard = sender.lock().await;
                                if let Err(e) = send_event(&mut *sender_guard, &event, seq).await {
                                    error!("Failed to send backfill event: {}", e);
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to backfill events: {}", e);
                            let mut sender_guard = sender.lock().await;
                            let _ =
                                send_error(&mut *sender_guard, "BackfillFailed", Some(&e)).await;
                        }
                    }
                }
            }
        }
    } else {
        // Global/Multiplexed mode - subscribe to ALL user conversations
        info!(
            "Initializing global subscription for user {}",
            crate::crypto::redact_for_log(&user_did)
        );

        match get_user_convos_with_sequencer(&pool, &user_did).await {
            Ok(convos) => {
                info!("Subscribing to {} conversations", convos.len());
                for (convo_id, sequencer_ds) in convos {
                    match (&sequencer_ds, &upstream_manager) {
                        (Some(seq_did), Some(um)) => {
                            match um
                                .subscribe(&convo_id, seq_did, resume_cursor.as_deref())
                                .await
                            {
                                Ok(rx) => {
                                    stream_map.insert(convo_id.clone(), BroadcastStream::new(rx));
                                    remote_subscriptions.push((convo_id, seq_did.clone()));
                                }
                                Err(e) => {
                                    warn!(
                                        convo = %crate::crypto::redact_for_log(&convo_id),
                                        error = %e,
                                        "Failed upstream subscribe, falling back to local"
                                    );
                                    let tx = sse_state.get_channel(&convo_id).await;
                                    stream_map
                                        .insert(convo_id, BroadcastStream::new(tx.subscribe()));
                                }
                            }
                        }
                        _ => {
                            let tx = sse_state.get_channel(&convo_id).await;
                            stream_map.insert(convo_id, BroadcastStream::new(tx.subscribe()));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to list conversations for global sub: {}", e);
                let mut sender_guard = sender.lock().await;
                let _ = send_error(
                    &mut *sender_guard,
                    "InternalError",
                    Some("Failed to list conversations"),
                )
                .await;
                return;
            }
        }
    }

    // Build set of remote convo IDs for typing indicator filtering
    let remote_convo_ids: HashSet<String> = remote_subscriptions
        .iter()
        .map(|(cid, _)| cid.clone())
        .collect();

    // Channel for client->server message handling
    let (client_msg_tx, mut client_msg_rx) = mpsc::channel::<ClientMessage>(32);
    let sse_state_clone = sse_state.clone();
    let user_did_clone = user_did.clone();

    // Spawn task to handle client messages
    let client_handler = tokio::spawn(async move {
        while let Some(msg) = client_msg_rx.recv().await {
            match msg {
                ClientMessage::Typing {
                    convo_id,
                    is_typing,
                } => {
                    // Do not forward typing indicators for remote conversations
                    if remote_convo_ids.contains(&convo_id) {
                        debug!(
                            convo = %crate::crypto::redact_for_log(&convo_id),
                            "Ignoring typing indicator for remote conversation"
                        );
                        continue;
                    }
                    debug!(
                        user = %crate::crypto::redact_for_log(&user_did_clone),
                        convo = %crate::crypto::redact_for_log(&convo_id),
                        is_typing,
                        "Received typing indicator via WebSocket"
                    );
                    // Broadcast typing event to other subscribers
                    let typing_event = StreamEvent::TypingEvent {
                        cursor: ulid::Ulid::new().to_string(),
                        convo_id: convo_id.clone(),
                        did: user_did_clone.clone(),
                        is_typing,
                    };
                    let tx = sse_state_clone.get_channel(&convo_id).await;
                    let _ = tx.send(typing_event);
                }
                ClientMessage::Ack { seq } => {
                    debug!(seq, "Received ack");
                    // Could be used for flow control in future
                }
                ClientMessage::Ping => {
                    debug!("Received client ping");
                    // Just a keep-alive, no action needed
                }
            }
        }
    });

    // Spawn task to receive from broadcast(s) and send to WebSocket
    let resume_cursor_clone = resume_cursor.clone();
    let sender_clone = sender.clone();
    let mut send_task = tokio::spawn(async move {
        while let Some((convo_id, event_result)) = stream_map.next().await {
            match event_result {
                Ok(event) => {
                    seq += 1;

                    // Extract cursor from event
                    let event_cursor = match &event {
                        StreamEvent::MessageEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::ReactionEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::TypingEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::InfoEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::NewDeviceEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::GroupInfoRefreshRequested { cursor, .. } => cursor.clone(),
                        StreamEvent::ReadditionRequested { cursor, .. } => cursor.clone(),
                        StreamEvent::MembershipChangeEvent { cursor, .. } => cursor.clone(),
                        StreamEvent::ReadEvent { cursor, .. } => cursor.clone(),
                    };

                    // Filter logic (only for single-convo mode generally, but applied here too)
                    if let Some(ref resume_cur) = resume_cursor_clone {
                        if event_cursor <= *resume_cur {
                            continue;
                        }
                    }

                    // Convert StreamEvent to WebSocket message
                    let mut sender_guard = sender_clone.lock().await;
                    if let Err(e) = send_event(&mut *sender_guard, &event, seq).await {
                        error!("Failed to send event for {}: {}", convo_id, e);
                        break;
                    }
                }
                Err(_lagged) => {
                    // BroadcastStream handles Lagged by returning error, we should log and continue
                    warn!("Slow consumer lagged for conversation {}", convo_id);
                }
            }
        }
    });

    // Spawn task to receive from WebSocket
    let client_msg_tx_clone = client_msg_tx.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => {
                    break;
                }
                Message::Ping(_) => {
                    // Pong is handled automatically by axum
                    debug!("Received WebSocket ping");
                }
                Message::Binary(data) => {
                    // Parse DAG-CBOR client message
                    match parse_client_message(&data) {
                        Ok(client_msg) => {
                            if client_msg_tx_clone.send(client_msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse client message: {}", e);
                        }
                    }
                }
                Message::Text(text) => {
                    // Also support JSON for debugging/compatibility
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(client_msg) => {
                            if client_msg_tx_clone.send(client_msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse JSON client message: {}", e);
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // Spawn heartbeat task to detect stale connections
    let sender_heartbeat = sender.clone();
    let mut heartbeat_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            interval.tick().await;
            let mut sender_guard = sender_heartbeat.lock().await;
            if sender_guard
                .send(Message::Ping(vec![].into()))
                .await
                .is_err()
            {
                debug!("Heartbeat ping failed - connection likely closed");
                break;
            }
            debug!("Sent heartbeat ping");
        }
    });

    // Wait for any task to finish (heartbeat failure also terminates connection)
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
            heartbeat_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
            heartbeat_task.abort();
        }
        _ = (&mut heartbeat_task) => {
            send_task.abort();
            recv_task.abort();
        }
    }

    // Cleanup
    client_handler.abort();

    // Unsubscribe from upstream connections for remote conversations
    if let Some(ref um) = upstream_manager {
        for (convo_id, seq_did) in &remote_subscriptions {
            um.unsubscribe(convo_id, seq_did).await;
        }
        if !remote_subscriptions.is_empty() {
            debug!(
                count = remote_subscriptions.len(),
                "Unsubscribed from upstream connections"
            );
        }
    }

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        "WebSocket connection closed"
    );
}

// MARK: - Backfill

/// Backfill events from database starting after the given cursor (ULID)
async fn backfill_events(
    pool: &DbPool,
    convo_id: &str,
    from_cursor: &str,
) -> Result<Vec<(StreamEvent, String)>, String> {
    // Use the existing db function for event backfill
    let events = crate::db::get_events_after_cursor(pool, convo_id, None, from_cursor, 1000)
        .await
        .map_err(|e| format!("Database query failed: {}", e))?;

    let mut result = Vec::with_capacity(events.len());

    for (cursor, payload, _emitted_at) in events {
        // Parse the stored event payload
        match serde_json::from_value::<StreamEvent>(payload) {
            Ok(event) => {
                result.push((event, cursor));
            }
            Err(e) => {
                warn!(cursor = %crate::crypto::redact_for_log(&cursor), error = ?e, "Failed to deserialize stored event");
            }
        }
    }

    Ok(result)
}

// MARK: - Message Parsing

/// Parse a client-to-server DAG-CBOR message
fn parse_client_message(data: &[u8]) -> Result<ClientMessage, String> {
    // Client messages are single DAG-CBOR objects (no header+payload like server messages)
    let value: serde_json::Value = serde_ipld_dagcbor::from_slice(data)
        .map_err(|e| format!("Failed to decode CBOR: {}", e))?;

    serde_json::from_value(value).map_err(|e| format!("Failed to parse client message: {}", e))
}

// MARK: - Event Sending

/// Send an event as a DAG-CBOR framed WebSocket message
async fn send_event(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    event: &StreamEvent,
    seq: i64,
) -> Result<(), String> {
    // Determine message type from event variant
    let msg_type = match event {
        StreamEvent::MessageEvent { .. } => "#messageEvent",
        StreamEvent::ReactionEvent { .. } => "#reactionEvent",
        StreamEvent::TypingEvent { .. } => "#typingEvent",
        StreamEvent::InfoEvent { .. } => "#infoEvent",
        StreamEvent::NewDeviceEvent { .. } => "#newDeviceEvent",
        StreamEvent::GroupInfoRefreshRequested { .. } => "#groupInfoRefreshRequestedEvent",
        StreamEvent::ReadditionRequested { .. } => "#readditionRequestedEvent",
        StreamEvent::MembershipChangeEvent { .. } => "#membershipChangeEvent",
        StreamEvent::ReadEvent { .. } => "#readEvent",
    };

    // Create header
    let header = MessageHeader {
        op: 1,
        t: Some(msg_type.to_string()),
    };

    // Wrap event with seq field and serialize directly to DAG-CBOR.
    // IMPORTANT: We must NOT go through serde_json::Value as an intermediate,
    // because JSON cannot represent CBOR byte strings — Vec<u8> fields
    // (like ciphertext) become JSON arrays of numbers, which then encode as
    // CBOR arrays instead of CBOR byte strings (major type 2).
    #[derive(Serialize)]
    struct WirePayload<'a> {
        #[serde(flatten)]
        event: &'a StreamEvent,
        seq: i64,
    }

    let wire = WirePayload { event, seq };

    // Encode header as DAG-CBOR
    let header_bytes = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| format!("Failed to encode header: {}", e))?;

    // Encode payload directly to DAG-CBOR (preserves byte string types)
    let payload_bytes = serde_ipld_dagcbor::to_vec(&wire)
        .map_err(|e| format!("Failed to encode payload: {}", e))?;

    // Concatenate header and payload
    let mut frame = header_bytes;
    frame.extend_from_slice(&payload_bytes);

    // Send as binary WebSocket message
    sender
        .send(Message::Binary(frame.into()))
        .await
        .map_err(|e| format!("Failed to send WebSocket message: {}", e))?;

    Ok(())
}

/// Send an error frame to the client
async fn send_error(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    error: &str,
    message: Option<&str>,
) -> Result<(), String> {
    let header = MessageHeader { op: -1, t: None };

    let payload = ErrorPayload {
        error: error.to_string(),
        message: message.map(|s| s.to_string()),
    };

    let header_bytes = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| format!("Failed to encode error header: {}", e))?;

    let payload_bytes = serde_ipld_dagcbor::to_vec(&payload)
        .map_err(|e| format!("Failed to encode error payload: {}", e))?;

    let mut frame = header_bytes;
    frame.extend_from_slice(&payload_bytes);

    sender
        .send(Message::Binary(frame.into()))
        .await
        .map_err(|e| format!("Failed to send error: {}", e))?;

    Ok(())
}

// MARK: - Federation Helpers

/// Look up the sequencer_ds for a single conversation.
/// Returns `None` for local conversations or if the row is not found.
async fn get_sequencer_ds(pool: &DbPool, convo_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT sequencer_ds FROM conversations WHERE id = $1")
        .bind(convo_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .flatten()
}

/// Get conversation IDs with their sequencer_ds for all of a user's conversations.
/// Used by the global/multiplexed subscription mode.
async fn get_user_convos_with_sequencer(
    pool: &DbPool,
    user_did: &str,
) -> Result<Vec<(String, Option<String>)>, String> {
    let rows = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT c.id, c.sequencer_ds FROM conversations c \
         INNER JOIN members m ON c.id = m.convo_id \
         WHERE (m.member_did = $1 OR m.user_did = $1) AND m.left_at IS NULL \
         ORDER BY c.created_at DESC \
         LIMIT 1000",
    )
    .bind(user_did)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed to list conversations: {}", e))?;

    Ok(rows)
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_tracker() {
        let tracker = ConnectionTracker::new();
        let user = "did:plc:test123";

        // Should allow first connection
        assert!(tracker.try_acquire(user));
        assert_eq!(tracker.count(user), 1);

        // Should allow up to MAX_CONNECTIONS_PER_USER
        for _ in 1..MAX_CONNECTIONS_PER_USER {
            assert!(tracker.try_acquire(user));
        }
        assert_eq!(tracker.count(user), MAX_CONNECTIONS_PER_USER);

        // Should reject when limit reached
        assert!(!tracker.try_acquire(user));
        assert_eq!(tracker.count(user), MAX_CONNECTIONS_PER_USER);

        // Release one and should allow again
        tracker.release(user);
        assert_eq!(tracker.count(user), MAX_CONNECTIONS_PER_USER - 1);
        assert!(tracker.try_acquire(user));
    }

    #[test]
    fn test_parse_client_message_typing() {
        let msg = ClientMessage::Typing {
            convo_id: "convo123".to_string(),
            is_typing: true,
        };
        let cbor = serde_ipld_dagcbor::to_vec(&serde_json::to_value(&msg).unwrap()).unwrap();
        let parsed = parse_client_message(&cbor).unwrap();

        match parsed {
            ClientMessage::Typing {
                convo_id,
                is_typing,
            } => {
                assert_eq!(convo_id, "convo123");
                assert!(is_typing);
            }
            _ => panic!("Wrong message type"),
        }
    }
}

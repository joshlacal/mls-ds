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
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    handlers::subscription_ticket::{verify_ticket, TicketClaims},
    realtime::sse::{SseState, StreamEvent},
    storage::DbPool,
};

// MARK: - Connection Tracking

/// Maximum concurrent WebSocket connections per user DID
const MAX_CONNECTIONS_PER_USER: usize = 5;

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
        let entry = self.connections.entry(user_did.to_string()).or_insert_with(|| AtomicUsize::new(0));
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
        if let Some(count) = self.connections.get(user_did) {
            let prev = count.fetch_sub(1, Ordering::SeqCst);
            // Clean up entry if no connections remain
            if prev <= 1 {
                self.connections.remove(user_did);
            }
        }
    }

    /// Get current connection count for a user
    pub fn count(&self, user_did: &str) -> usize {
        self.connections.get(user_did)
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
    /// Client is typing
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

    // Upgrade to WebSocket
    Ok(ws.on_upgrade(move |socket| async move {
        handle_socket(socket, pool_clone, sse_state, user_did_clone.clone(), convo_id, query.cursor).await;
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
    user_did: String,
    convo_id: Option<String>,
    resume_cursor: Option<String>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Get convo_id or use empty string for global subscription
    let cid = convo_id.clone().unwrap_or_default();

    // Subscribe to broadcast channel
    let tx = sse_state.get_channel(&cid).await;
    let mut rx = tx.subscribe();

    // Sequence counter for this session (starts at 0, increments per event)
    let mut seq: i64 = 0;

    // Backfill missed events if cursor provided
    if let Some(ref cursor) = resume_cursor {
        if !cursor.is_empty() {
            match backfill_events(&pool, &cid, cursor).await {
                Ok(events) => {
                    info!(
                        convo = %crate::crypto::redact_for_log(&cid),
                        backfill_count = events.len(),
                        from_cursor = %crate::crypto::redact_for_log(cursor),
                        "Sending backfill events"
                    );
                    for (event, event_cursor) in events {
                        seq += 1;
                        if let Err(e) = send_event(&mut sender, &event, seq, Some(&event_cursor)).await {
                            error!("Failed to send backfill event: {}", e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to backfill events: {}", e);
                    let _ = send_error(&mut sender, "BackfillFailed", Some(&e)).await;
                }
            }
        }
    }

    // Channel for client->server message handling
    let (client_msg_tx, mut client_msg_rx) = mpsc::channel::<ClientMessage>(32);
    let sse_state_clone = sse_state.clone();
    let user_did_clone = user_did.clone();
    let cid_clone = cid.clone();

    // Spawn task to handle client messages
    let client_handler = tokio::spawn(async move {
        while let Some(msg) = client_msg_rx.recv().await {
            match msg {
                ClientMessage::Typing { convo_id, is_typing } => {
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

    // Spawn task to receive from broadcast and send to WebSocket
    let resume_cursor_clone = resume_cursor.clone();
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            seq += 1;
            
            // Extract cursor from event for filtering
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
            
            // Skip events before resume cursor
            if let Some(ref resume_cur) = resume_cursor_clone {
                if event_cursor <= *resume_cur {
                    continue;
                }
            }
            
            // Convert StreamEvent to WebSocket message with DAG-CBOR framing
            if let Err(e) = send_event(&mut sender, &event, seq, Some(&event_cursor)).await {
                error!("Failed to send event: {}", e);
                break;
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

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    // Cleanup
    client_handler.abort();

    info!(
        convo = %crate::crypto::redact_for_log(&cid),
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
    
    serde_json::from_value(value)
        .map_err(|e| format!("Failed to parse client message: {}", e))
}

// MARK: - Event Sending

/// Send an event as a DAG-CBOR framed WebSocket message
async fn send_event(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    event: &StreamEvent,
    seq: i64,
    cursor: Option<&str>,
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

    // Serialize event - it already contains cursor field from StreamEvent
    let mut payload = serde_json::to_value(event)
        .map_err(|e| format!("Failed to serialize event: {}", e))?;
    
    // Add seq for WebSocket-specific ordering
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("seq".to_string(), serde_json::json!(seq));
        // If cursor provided externally (for backfill), override the event's cursor
        if let Some(cur) = cursor {
            obj.insert("cursor".to_string(), serde_json::json!(cur));
        }
    }

    // Encode header as DAG-CBOR
    let header_bytes = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| format!("Failed to encode header: {}", e))?;

    // Encode payload as DAG-CBOR
    let payload_bytes = serde_ipld_dagcbor::to_vec(&payload)
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
    let header = MessageHeader {
        op: -1,
        t: None,
    };

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
            ClientMessage::Typing { convo_id, is_typing } => {
                assert_eq!(convo_id, "convo123");
                assert!(is_typing);
            }
            _ => panic!("Wrong message type"),
        }
    }
}

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, db::DbPool, realtime::cursor::CursorGenerator};

use super::sse::{SseState, StreamEvent};

/// WebSocket query parameters for subscribeConvoEvents
#[derive(Debug, Deserialize)]
pub struct SubscribeQuery {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub cursor: Option<i64>,
}

/// WebSocket message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Operation: 1 = message, -1 = error
    pub op: i32,
    /// Type identifier (short form, e.g. "#message")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// Error payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// WebSocket handler for subscribeConvoEvents
pub async fn subscribe_convo_events(
    ws: WebSocketUpgrade,
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Query(query): Query<SubscribeQuery>,
) -> Result<Response, StatusCode> {
    let convo_id = query.convo_id.clone();
    let user_did = auth_user.did.clone();

    info!(
        convo_id = %convo_id,
        user_did = %user_did,
        cursor = ?query.cursor,
        "WebSocket subscription request"
    );

    // Check membership
    let is_member = crate::db::is_member(&pool, &user_did, &convo_id)
        .await
        .map_err(|e| {
            error!(error = ?e, "Membership check failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !is_member {
        warn!(
            convo_id = %convo_id,
            user_did = %user_did,
            "User not a member of conversation"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate cursor if provided
    let resume_cursor = if let Some(cursor) = query.cursor {
        // For now, accept the cursor (backfill not yet implemented)
        Some(cursor)
    } else {
        None
    };

    // Upgrade to WebSocket
    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, sse_state, convo_id, resume_cursor)
    }))
}

async fn handle_socket(
    socket: WebSocket,
    sse_state: Arc<SseState>,
    convo_id: String,
    _resume_cursor: Option<i64>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to broadcast channel
    let tx = sse_state.get_channel(&convo_id).await;
    let mut rx = tx.subscribe();

    // Spawn task to receive from broadcast and send to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            // Convert StreamEvent to WebSocket message
            if let Err(e) = send_event(&mut sender, event).await {
                error!("Failed to send event: {}", e);
                break;
            }
        }
    });

    // Spawn task to receive from WebSocket (we ignore client messages for now)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            // For now, we ignore messages from client
            // In the future, could handle ping/pong, etc.
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    info!(convo_id = %convo_id, "WebSocket connection closed");
}

async fn send_event(sender: &mut futures::stream::SplitSink<WebSocket, Message>, event: StreamEvent) -> Result<(), String> {
    // Determine message type
    let (msg_type, seq, payload) = match &event {
        StreamEvent::MessageEvent { cursor, payload, .. } => {
            ("#message", parse_cursor(cursor), serde_json::to_value(payload).unwrap())
        }
        StreamEvent::ReactionEvent { cursor, payload, .. } => {
            ("#reaction", parse_cursor(cursor), serde_json::to_value(payload).unwrap())
        }
        StreamEvent::TypingEvent { cursor, payload, .. } => {
            ("#typing", parse_cursor(cursor), serde_json::to_value(payload).unwrap())
        }
        StreamEvent::InfoEvent { cursor, reason, detail, .. } => {
            let info_payload = serde_json::json!({
                "reason": reason,
                "detail": detail,
            });
            ("#info", parse_cursor(cursor), info_payload)
        }
    };

    // Create header
    let header = MessageHeader {
        op: 1,
        t: Some(msg_type.to_string()),
    };

    // Add sequence number to payload
    let mut payload_obj = payload.as_object().unwrap().clone();
    payload_obj.insert("seq".to_string(), serde_json::json!(seq));
    
    // Encode header as DAG-CBOR
    let header_bytes = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| format!("Failed to encode header: {}", e))?;

    // Encode payload as DAG-CBOR
    let payload_bytes = serde_ipld_dagcbor::to_vec(&payload_obj)
        .map_err(|e| format!("Failed to encode payload: {}", e))?;

    // Concatenate header and payload
    let mut frame = header_bytes;
    frame.extend_from_slice(&payload_bytes);

    // Send as binary WebSocket message
    sender
        .send(Message::Binary(frame))
        .await
        .map_err(|e| format!("Failed to send WebSocket message: {}", e))?;

    Ok(())
}

async fn send_error(sender: &mut futures::stream::SplitSink<WebSocket, Message>, error: &str, message: Option<&str>) -> Result<(), String> {
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
        .send(Message::Binary(frame))
        .await
        .map_err(|e| format!("Failed to send error: {}", e))?;

    Ok(())
}

fn parse_cursor(cursor: &str) -> i64 {
    // ULID to timestamp conversion (simplified)
    // In production, properly parse ULID
    cursor.parse::<i64>().unwrap_or(0)
}

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Sse,
    },
};
use futures::stream;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, db::DbPool, models::MessageView, realtime::cursor::CursorGenerator};

/// SSE query parameters for subscribeConvoEvents
#[derive(Debug, Deserialize)]
pub struct SubscribeQuery {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub cursor: Option<String>,
}

/// Event types for realtime streaming
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StreamEvent {
    MessageEvent {
        cursor: String,
        message: MessageView,
    },
    ReactionEvent {
        cursor: String,
        convo_id: String,
        emitted_at: String,
        payload: ReactionEventPayload,
    },
    TypingEvent {
        cursor: String,
        convo_id: String,
        emitted_at: String,
        payload: TypingEventPayload,
    },
    InfoEvent {
        cursor: String,
        convo_id: String,
        emitted_at: String,
        reason: String,
        detail: Option<serde_json::Value>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ReactionEventPayload {
    pub message_id: String,
    pub actor_did: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypingEventPayload {
    pub actor_did: String,
    pub is_typing: bool,
}

/// Shared state for SSE connections
pub struct SseState {
    /// Cursor generator for monotonic ULIDs
    pub cursor_gen: CursorGenerator,
    /// Broadcast channels per conversation (convo_id -> sender)
    pub channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    /// Max events buffered per stream before backpressure
    pub buffer_size: usize,
}

impl SseState {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            cursor_gen: CursorGenerator::new(),
            channels: Arc::new(RwLock::new(HashMap::new())),
            buffer_size,
        }
    }

    /// Get or create broadcast channel for a conversation
    pub async fn get_channel(&self, convo_id: &str) -> broadcast::Sender<StreamEvent> {
        let mut channels = self.channels.write().await;
        channels
            .entry(convo_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(self.buffer_size);
                info!(
                    convo = %crate::crypto::redact_for_log(convo_id),
                    "Created new broadcast channel"
                );
                tx
            })
            .clone()
    }

    /// Emit event to all subscribers of a conversation
    pub async fn emit(&self, convo_id: &str, event: StreamEvent) -> Result<(), String> {
        let tx = self.get_channel(convo_id).await;
        tx.send(event)
            .map_err(|e| format!("Failed to emit event: {}", e))?;
        Ok(())
    }
}

/// SSE handler for subscribeConvoEvents
pub async fn subscribe_convo_events(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Query(query): Query<SubscribeQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let convo_id = query.convo_id.clone();
    let user_did = auth_user.did.clone();

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        user = %crate::crypto::redact_for_log(&user_did),
        has_cursor = query.cursor.is_some(),
        "SSE subscription request"
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
            convo = %crate::crypto::redact_for_log(&convo_id),
            user = %crate::crypto::redact_for_log(&user_did),
            "User not a member of conversation"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate cursor if provided
    let resume_cursor = if let Some(cursor_str) = &query.cursor {
        match CursorGenerator::validate(cursor_str) {
            Ok(_) => {
                // Check if cursor is within retention window
                // For now, accept all valid cursors; compaction worker will handle old ones
                Some(cursor_str.clone())
            }
            Err(e) => {
                warn!(
                    cursor = %crate::crypto::redact_for_log(cursor_str),
                    error = %e,
                    "Invalid cursor format"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    } else {
        None
    };

    // Subscribe to broadcast channel
    let tx = sse_state.get_channel(&convo_id).await;
    let rx = tx.subscribe();

    // Create event stream
    let stream = stream::unfold(
        (rx, resume_cursor, convo_id.clone()),
        move |(mut rx, resume_cursor, convo_id)| async move {
            loop {
                tokio::select! {
                    // Wait for broadcast event
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                // Filter based on resume cursor
                                if let Some(ref resume_cur) = resume_cursor {
                                    let event_cursor = match &event {
                                        StreamEvent::MessageEvent { cursor, .. } => cursor,
                                        StreamEvent::ReactionEvent { cursor, .. } => cursor,
                                        StreamEvent::TypingEvent { cursor, .. } => cursor,
                                        StreamEvent::InfoEvent { cursor, .. } => cursor,
                                    };

                                    // Only send events after resume cursor
                                    if !CursorGenerator::is_greater(event_cursor, resume_cur) {
                                        continue;
                                    }
                                }

                                // Serialize event
                                let json = match serde_json::to_string(&event) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        error!(error = ?e, "Failed to serialize event");
                                        continue;
                                    }
                                };

                                let sse_event = Event::default().data(json);
                                return Some((Ok::<Event, Infallible>(sse_event), (rx, None, convo_id.clone())));
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    convo = %crate::crypto::redact_for_log(&convo_id),
                                    skipped = skipped,
                                    "Slow consumer, events skipped"
                                );

                                // Emit infoEvent about slow consumer
                                let info = StreamEvent::InfoEvent {
                                    cursor: ulid::Ulid::new().to_string(),
                                    convo_id: convo_id.clone(),
                                    emitted_at: chrono::Utc::now().to_rfc3339(),
                                    reason: "slow-consumer".to_string(),
                                    detail: Some(serde_json::json!({ "skipped": skipped })),
                                };

                                // SAFETY: StreamEvent is a simple enum with no complex types,
                                // so serialization can only fail if there's a bug in serde_json.
                                let json = serde_json::to_string(&info)
                                    .expect("BUG: Failed to serialize StreamEvent");
                                let sse_event = Event::default().data(json);
                                return Some((Ok::<Event, Infallible>(sse_event), (rx, None, convo_id.clone())));
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!(
                                    convo = %crate::crypto::redact_for_log(&convo_id),
                                    "Broadcast channel closed"
                                );
                                return None;
                            }
                        }
                    }

                    // Heartbeat every 15s
                    _ = tokio::time::sleep(Duration::from_secs(15)) => {
                        // Send comment line as keepalive
                        let sse_event = Event::default().comment("keepalive");
                        return Some((Ok(sse_event), (rx, None, convo_id.clone())));
                    }
                }
            }
        },
    );

    // Return SSE with explicit headers to ensure proper content-type
    // and disable nginx buffering
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Sse::new(stream).keep_alive(KeepAlive::default()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sse_state_creation() {
        let state = SseState::new(1000);
        assert_eq!(state.buffer_size, 1000);
    }

    #[tokio::test]
    async fn test_channel_creation() {
        let state = SseState::new(1000);
        let tx1 = state.get_channel("convo1").await;
        let tx2 = state.get_channel("convo1").await;

        // Same conversation returns same channel
        assert_eq!(tx1.receiver_count(), tx2.receiver_count());
    }

    #[tokio::test]
    async fn test_event_emission() {
        let state = Arc::new(SseState::new(1000));
        let tx = state.get_channel("convo1").await;
        let mut rx = tx.subscribe();

        let event = StreamEvent::InfoEvent {
            cursor: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            convo_id: "convo1".to_string(),
            emitted_at: chrono::Utc::now().to_rfc3339(),
            reason: "test".to_string(),
            detail: None,
        };

        state.emit("convo1", event.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, StreamEvent::InfoEvent { .. }));
    }
}

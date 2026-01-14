use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Sse,
    },
};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
    time::Duration,
};
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
/// Uses AT Protocol format with $type tag for proper client compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum StreamEvent {
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#messageEvent")]
    MessageEvent {
        cursor: String,
        message: MessageView,
    },
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#reactionEvent")]
    ReactionEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
        did: String,
        reaction: String,
        action: String,
    },
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#typingEvent")]
    TypingEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        did: String,
        #[serde(rename = "isTyping")]
        is_typing: bool,
    },
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#infoEvent")]
    InfoEvent { cursor: String, info: String },
    /// Event indicating a user has registered a new device that needs to be added to the conversation
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#newDeviceEvent")]
    NewDeviceEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "userDid")]
        user_did: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "deviceName")]
        device_name: Option<String>,
        #[serde(rename = "deviceCredentialDid")]
        device_credential_did: String,
        #[serde(rename = "pendingAdditionId")]
        pending_addition_id: String,
    },
    /// Event requesting active members to publish fresh GroupInfo for external commit joins
    /// Emitted when a member encounters stale GroupInfo and calls groupInfoRefresh
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#groupInfoRefreshRequestedEvent")]
    GroupInfoRefreshRequested {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        /// DID of the member requesting the refresh (so they don't respond to their own request)
        #[serde(rename = "requestedBy")]
        requested_by: String,
        #[serde(rename = "requestedAt")]
        requested_at: String,
    },
    /// Event indicating a member needs to be re-added to the conversation
    /// Emitted when both Welcome and External Commit have failed
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#readditionRequestedEvent")]
    ReadditionRequested {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        /// DID of the user requesting re-addition
        #[serde(rename = "userDid")]
        user_did: String,
        #[serde(rename = "requestedAt")]
        requested_at: String,
    },
    /// Event indicating a member joined, left, or was removed from the conversation
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#membershipChangeEvent")]
    MembershipChangeEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        /// DID of the affected member
        did: String,
        /// Action: joined, left, removed, or kicked
        action: String,
        /// DID of the actor who performed the action (for removed/kicked)
        actor: Option<String>,
        /// Optional reason for removal
        reason: Option<String>,
        /// New epoch after this change
        epoch: usize,
    },
    /// Event indicating a member has read messages in the conversation
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#readEvent")]
    ReadEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        /// DID of the member who read the messages
        did: String,
        /// Optional specific message ID that was marked as read
        #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        /// ISO 8601 timestamp of when messages were read
        #[serde(rename = "readAt")]
        read_at: String,
    },
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
    /// Returns Ok if event was sent OR if there were no subscribers (non-fatal)
    pub async fn emit(&self, convo_id: &str, event: StreamEvent) -> Result<(), String> {
        let tx = self.get_channel(convo_id).await;
        match tx.send(event) {
            Ok(_) => Ok(()),
            Err(_) => {
                // No active receivers is not an error - it just means no one is listening
                // This is expected when members are offline or haven't connected SSE yet
                Ok(())
            }
        }
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

    // If the client provided a cursor, backfill missed events from the DB first.
    //
    // We intentionally do NOT backfill all message events (app messages) here because clients
    // fetch chat messages via getMessages. However, MLS commit messages are required to maintain
    // local MLS state, so we do backfill commit messageEvent entries to avoid epoch desync when
    // a client reconnects after missing commits.
    let mut replayed_cursors: HashSet<String> = HashSet::new();
    let mut replay_sse_events: Vec<Event> = Vec::new();

    if let Some(ref resume_cur) = resume_cursor {
        let mut replay_items: Vec<(String, String)> = Vec::new();

        // Backfill reaction events (needed for cursor-based SSE replay).
        match crate::db::get_events_after_cursor(&pool, &convo_id, Some("reactionEvent"), resume_cur, 200).await {
            Ok(events) => {
                for (id, payload, _emitted_at) in events {
                    let message_id = payload.get("messageId").and_then(|v| v.as_str());
                    let did = payload.get("did").and_then(|v| v.as_str());
                    let reaction = payload.get("reaction").and_then(|v| v.as_str());
                    let action = payload.get("action").and_then(|v| v.as_str());

                    let (Some(message_id), Some(did), Some(reaction), Some(action)) =
                        (message_id, did, reaction, action)
                    else {
                        // Older reactionEvent rows may have only the minimal envelope.
                        continue;
                    };

                    let event = StreamEvent::ReactionEvent {
                        cursor: id.clone(),
                        convo_id: convo_id.clone(),
                        message_id: message_id.to_string(),
                        did: did.to_string(),
                        reaction: reaction.to_string(),
                        action: action.to_string(),
                    };

                    let json = match serde_json::to_string(&event) {
                        Ok(j) => j,
                        Err(e) => {
                            error!(error = ?e, "Failed to serialize replay reactionEvent");
                            continue;
                        }
                    };

                    replay_items.push((id, json));
                }
            }
            Err(e) => {
                warn!(
                    convo = %crate::crypto::redact_for_log(&convo_id),
                    error = ?e,
                    "Failed to backfill reaction events"
                );
            }
        }

        // Backfill commit message events (required for MLS state correctness).
        //
        // NOTE: This intentionally replays ONLY commit messages, not all app messages.
        // Clients should fetch any missed chat content via getMessages.
        let commit_rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<Vec<u8>>,
                i64,
                i64,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            r#"
            SELECT
                e.id AS cursor,
                m.id AS message_id,
                m.ciphertext,
                m.epoch,
                m.seq,
                m.created_at
            FROM event_stream e
            JOIN messages m
              ON m.id = (e.payload->>'messageId')
            WHERE e.convo_id = $1
              AND e.event_type = 'messageEvent'
              AND e.id > $2
              AND m.message_type = 'commit'
            ORDER BY e.id ASC
            "#,
        )
        .bind(&convo_id)
        .bind(resume_cur)
        .fetch_all(&pool)
        .await;

        match commit_rows {
            Ok(rows) => {
                for (cursor, message_id, ciphertext, epoch, seq, created_at) in rows {
                    let Some(ciphertext) = ciphertext else {
                        // Should never happen for commit messages, but don't emit empty ciphertext.
                        continue;
                    };

                    let message_view =
                        crate::models::MessageView::from(crate::models::MessageViewData {
                            id: message_id,
                            convo_id: convo_id.clone(),
                            ciphertext,
                            epoch: epoch as usize,
                            seq: seq as usize,
                            created_at: crate::sqlx_atrium::chrono_to_datetime(created_at),
                            message_type: None,
                        });

                    let event = StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                    };

                    let json = match serde_json::to_string(&event) {
                        Ok(j) => j,
                        Err(e) => {
                            error!(error = ?e, "Failed to serialize replay commit messageEvent");
                            continue;
                        }
                    };

                    replay_items.push((cursor, json));
                }
            }
            Err(e) => {
                warn!(
                    convo = %crate::crypto::redact_for_log(&convo_id),
                    error = ?e,
                    "Failed to backfill commit messages"
                );
            }
        }

        // Emit replay events in cursor order to preserve server-side ordering semantics.
        replay_items.sort_by(|a, b| a.0.cmp(&b.0));
        for (cursor, json) in replay_items {
            replayed_cursors.insert(cursor);
            replay_sse_events.push(Event::default().data(json));
        }
    }

    let replay_stream = stream::iter(
        replay_sse_events
            .into_iter()
            .map(|evt| Ok::<Event, Infallible>(evt)),
    );

    // Create live event stream
    let live_stream = stream::unfold(
        (rx, resume_cursor, replayed_cursors, convo_id.clone()),
        move |(mut rx, resume_cursor, replayed_cursors, convo_id)| async move {
            let mut replayed_cursors = replayed_cursors;
            loop {
                tokio::select! {
                    // Wait for broadcast event
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                let event_cursor = match &event {
                                    StreamEvent::MessageEvent { cursor, .. } => cursor,
                                    StreamEvent::ReactionEvent { cursor, .. } => cursor,
                                    StreamEvent::TypingEvent { cursor, .. } => cursor,
                                    StreamEvent::InfoEvent { cursor, .. } => cursor,
                                    StreamEvent::NewDeviceEvent { cursor, .. } => cursor,
                                    StreamEvent::GroupInfoRefreshRequested { cursor, .. } => cursor,
                                    StreamEvent::ReadditionRequested { cursor, .. } => cursor,
                                    StreamEvent::MembershipChangeEvent { cursor, .. } => cursor,
                                    StreamEvent::ReadEvent { cursor, .. } => cursor,
                                };

                                // Filter based on resume cursor
                                if let Some(ref resume_cur) = resume_cursor {
                                    // Only send events after resume cursor
                                    if !CursorGenerator::is_greater(event_cursor, resume_cur) {
                                        continue;
                                    }
                                }

                                // Avoid duplicating replayed DB events if they race with live delivery
                                if replayed_cursors.contains(event_cursor) {
                                    continue;
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
                                return Some((Ok::<Event, Infallible>(sse_event), (rx, None, replayed_cursors, convo_id.clone())));
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
                                    info: format!("Slow consumer: {} events skipped", skipped),
                                };

                                // SAFETY: StreamEvent is a simple enum with no complex types,
                                // so serialization can only fail if there's a bug in serde_json.
                                let json = serde_json::to_string(&info)
                                    .expect("BUG: Failed to serialize StreamEvent");
                                let sse_event = Event::default().data(json);
                                return Some((Ok::<Event, Infallible>(sse_event), (rx, None, replayed_cursors, convo_id.clone())));
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
                        return Some((Ok(sse_event), (rx, None, replayed_cursors, convo_id.clone())));
                    }
                }
            }
        },
    );

    let stream = replay_stream.chain(live_stream);

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
            info: "test".to_string(),
        };

        state.emit("convo1", event.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, StreamEvent::InfoEvent { .. }));
    }
}

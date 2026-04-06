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

use crate::{
    auth::AuthUser,
    db::DbPool,
    realtime::{cursor::CursorGenerator, StreamMessageView},
};

/// SSE query parameters for subscribeConvoEvents
#[derive(Debug, Deserialize)]
pub struct SubscribeQuery {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub cursor: Option<String>,
}

/// Event types for realtime streaming
/// Uses AT Protocol format with $type tag for proper client compatibility
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "$type")]
pub enum StreamEvent {
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#messageEvent")]
    MessageEvent {
        cursor: String,
        message: StreamMessageView,
        /// When true, this is an ephemeral signal (typing, read receipt, presence)
        /// that should NOT be shown in chat history. Omitted (defaults to false)
        /// for regular persistent messages.
        #[serde(default, skip_serializing_if = "crate::realtime::sse::is_false")]
        ephemeral: bool,
    },
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#typingEvent")]
    TypingEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        did: String,
        #[serde(rename = "isTyping")]
        is_typing: bool,
    },
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#infoEvent")]
    InfoEvent { cursor: String, info: String },
    /// Event indicating a user has registered a new device that needs to be added to the conversation
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#newDeviceEvent")]
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
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#groupInfoRefreshRequestedEvent")]
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
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#readditionRequestedEvent")]
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
    /// Event indicating the canonical MLS tree state changed.
    /// Clients must compare confirmationTag against their local state and re-join if mismatched.
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#treeChanged")]
    TreeChanged {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "confirmationTag")]
        confirmation_tag: String,
        epoch: i64,
    },
    /// Event indicating a member joined, left, or was removed from the conversation
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#membershipChangeEvent")]
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
    /// Event indicating the MLS group has been reset with a new group_id
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#groupResetEvent")]
    GroupResetEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "newGroupId")]
        new_group_id: String,
        #[serde(rename = "resetGeneration")]
        reset_generation: i32,
        #[serde(rename = "resetBy")]
        reset_by: String,
        #[serde(rename = "cipherSuite")]
        cipher_suite: String,
        reason: Option<String>,
    },
}

/// Helper for `skip_serializing_if` on the `ephemeral` field.
pub fn is_false(v: &bool) -> bool {
    !(*v)
}

/// Manual `Deserialize` for `StreamEvent`.
///
/// The generated `MessageView<'static>` cannot derive `DeserializeOwned` because its
/// `#[serde(borrow)]` attributes constrain `'de: 'static`. We work around this by
/// deserializing via an intermediate `RawMessageView` with owned types, then converting.
impl<'de> serde::Deserialize<'de> for StreamEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Mirror of StreamEvent with a raw message view for the MessageEvent variant.
        #[derive(Deserialize)]
        #[serde(tag = "$type")]
        enum RawStreamEvent {
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#messageEvent")]
            MessageEvent {
                cursor: String,
                message: RawMessageView,
                #[serde(default)]
                ephemeral: bool,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#typingEvent")]
            TypingEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                did: String,
                #[serde(rename = "isTyping")]
                is_typing: bool,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#infoEvent")]
            InfoEvent { cursor: String, info: String },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#newDeviceEvent")]
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
            #[serde(
                rename = "blue.catbird.mlsChat.subscribeEvents#groupInfoRefreshRequestedEvent"
            )]
            GroupInfoRefreshRequested {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "requestedBy")]
                requested_by: String,
                #[serde(rename = "requestedAt")]
                requested_at: String,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#readditionRequestedEvent")]
            ReadditionRequested {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "userDid")]
                user_did: String,
                #[serde(rename = "requestedAt")]
                requested_at: String,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#treeChanged")]
            TreeChanged {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "confirmationTag")]
                confirmation_tag: String,
                epoch: i64,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#membershipChangeEvent")]
            MembershipChangeEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                did: String,
                action: String,
                actor: Option<String>,
                reason: Option<String>,
                epoch: usize,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#groupResetEvent")]
            GroupResetEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "newGroupId")]
                new_group_id: String,
                #[serde(rename = "resetGeneration")]
                reset_generation: i32,
                #[serde(rename = "resetBy")]
                reset_by: String,
                #[serde(rename = "cipherSuite")]
                cipher_suite: String,
                reason: Option<String>,
            },
        }

        /// Owned intermediate for MessageView deserialization.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawMessageView {
            id: String,
            convo_id: String,
            #[serde(with = "jacquard_common::serde_bytes_helper")]
            ciphertext: bytes::Bytes,
            epoch: i64,
            seq: i64,
            created_at: jacquard_common::types::string::Datetime,
            message_type: Option<String>,
        }

        let raw = RawStreamEvent::deserialize(deserializer)?;
        Ok(match raw {
            RawStreamEvent::MessageEvent {
                cursor,
                message,
                ephemeral,
            } => StreamEvent::MessageEvent {
                cursor,
                message: StreamMessageView {
                    id: message.id.into(),
                    convo_id: message.convo_id.into(),
                    ciphertext: message.ciphertext,
                    epoch: message.epoch,
                    seq: message.seq,
                    created_at: message.created_at,
                    message_type: message.message_type.map(Into::into),
                    extra_data: Default::default(),
                },
                ephemeral,
            },
            RawStreamEvent::TypingEvent {
                cursor,
                convo_id,
                did,
                is_typing,
            } => StreamEvent::TypingEvent {
                cursor,
                convo_id,
                did,
                is_typing,
            },
            RawStreamEvent::InfoEvent { cursor, info } => StreamEvent::InfoEvent { cursor, info },
            RawStreamEvent::NewDeviceEvent {
                cursor,
                convo_id,
                user_did,
                device_id,
                device_name,
                device_credential_did,
                pending_addition_id,
            } => StreamEvent::NewDeviceEvent {
                cursor,
                convo_id,
                user_did,
                device_id,
                device_name,
                device_credential_did,
                pending_addition_id,
            },
            RawStreamEvent::GroupInfoRefreshRequested {
                cursor,
                convo_id,
                requested_by,
                requested_at,
            } => StreamEvent::GroupInfoRefreshRequested {
                cursor,
                convo_id,
                requested_by,
                requested_at,
            },
            RawStreamEvent::ReadditionRequested {
                cursor,
                convo_id,
                user_did,
                requested_at,
            } => StreamEvent::ReadditionRequested {
                cursor,
                convo_id,
                user_did,
                requested_at,
            },
            RawStreamEvent::TreeChanged {
                cursor,
                convo_id,
                confirmation_tag,
                epoch,
            } => StreamEvent::TreeChanged {
                cursor,
                convo_id,
                confirmation_tag,
                epoch,
            },
            RawStreamEvent::MembershipChangeEvent {
                cursor,
                convo_id,
                did,
                action,
                actor,
                reason,
                epoch,
            } => StreamEvent::MembershipChangeEvent {
                cursor,
                convo_id,
                did,
                action,
                actor,
                reason,
                epoch,
            },
            RawStreamEvent::GroupResetEvent {
                cursor,
                convo_id,
                new_group_id,
                reset_generation,
                reset_by,
                cipher_suite,
                reason,
            } => StreamEvent::GroupResetEvent {
                cursor,
                convo_id,
                new_group_id,
                reset_generation,
                reset_by,
                cipher_suite,
                reason,
            },
        })
    }
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

                    let message_view: StreamMessageView =
                        crate::generated::blue_catbird::mlsChat::MessageView {
                            id: message_id.into(),
                            convo_id: convo_id.clone().into(),
                            ciphertext: bytes::Bytes::from(ciphertext),
                            epoch,
                            seq,
                            created_at: crate::sqlx_jacquard::chrono_to_datetime(created_at),
                            message_type: Some("commit".into()),
                            extra_data: Default::default(),
                        }
                        .into();

                    let event = StreamEvent::MessageEvent {
                        cursor: cursor.clone(),
                        message: message_view,
                        ephemeral: false,
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
            let replayed_cursors = replayed_cursors;
            loop {
                tokio::select! {
                    // Wait for broadcast event
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                let event_cursor = match &event {
                                    StreamEvent::MessageEvent { cursor, .. } => cursor,
                                    StreamEvent::TypingEvent { cursor, .. } => cursor,
                                    StreamEvent::InfoEvent { cursor, .. } => cursor,
                                    StreamEvent::NewDeviceEvent { cursor, .. } => cursor,
                                    StreamEvent::GroupInfoRefreshRequested { cursor, .. } => cursor,
                                    StreamEvent::ReadditionRequested { cursor, .. } => cursor,
                                    StreamEvent::TreeChanged { cursor, .. } => cursor,
                                    StreamEvent::MembershipChangeEvent { cursor, .. } => cursor,
                                    StreamEvent::GroupResetEvent { cursor, .. } => cursor,
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

    fn test_message_view(id: &str) -> StreamMessageView {
        StreamMessageView {
            id: id.to_string().into(),
            convo_id: "c1".to_string().into(),
            ciphertext: bytes::Bytes::new(),
            epoch: 0,
            seq: 0,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(chrono::Utc::now()),
            message_type: Some("app".into()),
            extra_data: Default::default(),
        }
    }

    #[test]
    fn test_ephemeral_false_skipped_in_serialization() {
        let event = StreamEvent::MessageEvent {
            cursor: "cursor-1".into(),
            message: test_message_view("m1"),
            ephemeral: false,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("\"ephemeral\""),
            "ephemeral:false should be skipped, got: {}",
            json
        );
    }

    #[test]
    fn test_ephemeral_true_included() {
        let event = StreamEvent::MessageEvent {
            cursor: "cursor-2".into(),
            message: test_message_view("m2"),
            ephemeral: true,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"ephemeral\":true"),
            "ephemeral:true should be included, got: {}",
            json
        );
    }
}

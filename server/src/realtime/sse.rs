use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Sse,
    },
};
use dashmap::DashMap;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::{
    auth::AuthUser,
    db::DbPool,
    realtime::cursor::CursorGenerator,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum StreamEvent {
    /// Clean-chat ephemeral typing DTO. Unlike the legacy `TypingEvent`, this
    /// event is uncursored and uses the generated `defs#typingEvent` wire tag.
    /// It intentionally travels through the same per-conversation broadcast
    /// channel as legacy events; the clean subscription compositor is the
    /// only consumer that translates it into `SubscriptionMessage`.
    #[serde(rename = "blue.catbird.chat.defs#typingEvent")]
    CleanTypingEvent {
        #[serde(rename = "actorDeviceId")]
        actor_device_id: catbird_atproto::generated::blue_catbird::chat::DeviceId,
        #[serde(rename = "actorDid")]
        actor_did: catbird_atproto::generated::blue_catbird::chat::BareDid,
        #[serde(rename = "conversationId")]
        conversation_id: catbird_atproto::generated::blue_catbird::chat::OperationId,
        #[serde(rename = "expiresAt")]
        expires_at: catbird_atproto::generated::blue_catbird::chat::CanonicalDatetime,
        #[serde(rename = "isTyping")]
        is_typing: bool,
        #[serde(rename = "typingId")]
        typing_id: catbird_atproto::generated::blue_catbird::chat::OperationId,
    },
}

/// Helper for `skip_serializing_if` on the `ephemeral` field.
pub fn is_false(v: &bool) -> bool {
    !(*v)
}

/// Mutate the `cursor` field of any `StreamEvent` variant in-place. Clean typing is uncursored.
pub fn set_stream_event_cursor(_event: &mut StreamEvent, _new_cursor: String) {}

impl StreamEvent {
    /// Return the generated clean-chat typing DTO carried by this shared-bus
    /// event.
    pub(crate) fn clean_typing_payload(
        &self,
    ) -> Option<catbird_atproto::generated::blue_catbird::chat::TypingEvent> {
        match self {
            Self::CleanTypingEvent {
                actor_device_id,
                actor_did,
                conversation_id,
                expires_at,
                is_typing,
                typing_id,
            } => Some(
                catbird_atproto::generated::blue_catbird::chat::TypingEvent {
                    actor_device_id: actor_device_id.clone(),
                    actor_did: actor_did.clone(),
                    conversation_id: conversation_id.clone(),
                    expires_at: expires_at.clone(),
                    is_typing: *is_typing,
                    typing_id: typing_id.clone(),
                    extra_data: None,
                },
            ),
        }
    }
}

/// Optional DB `event_stream` write to perform **before** the broadcast send,
/// inside the per-convo consumer task. Keeping the store co-located with the
/// emit on the same FIFO queue preserves the "DB insert → broadcast" ordering
/// that clients rely on (otherwise a commit at epoch N+1 can overtake an app
/// message at epoch N, and subscribers drop old-epoch secrets before decoding
/// the older message).
///
/// After task #40, the event itself carries all of cursor, event_type, and
/// message_id — `store_event` derives them internally from the typed
/// `StreamEvent`. Only the DB pool is needed here; the convo_id is captured
/// by the consumer task's closure.
#[derive(Debug)]
pub(crate) struct StoreEventArgs {
    pub pool: DbPool,
}

/// One unit of work on the per-convo FIFO queue.
#[derive(Debug)]
pub(crate) struct EmitJob {
    pub event: StreamEvent,
    pub store: Option<StoreEventArgs>,
}

/// Shared state for SSE connections
pub struct SseState {
    /// Cursor generator for monotonic ULIDs
    pub cursor_gen: CursorGenerator,
    /// Broadcast channels per conversation (convo_id -> sender)
    pub channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    /// Max events buffered per stream before backpressure
    pub buffer_size: usize,
    /// Per-convo FIFO fanout queue. Each conversation has a dedicated consumer
    /// task that drains a single-producer-order-preserving mpsc channel,
    /// performing `store_event` and then the broadcast `send` in that order.
    /// This preserves DB-insert ordering through the emit path even when
    /// multiple handlers produce events concurrently for the same convo.
    ///
    /// IMPORTANT: enqueue at call sites MUST be synchronous (not wrapped in a
    /// `tokio::spawn`) — otherwise two events committed in order A, B can be
    /// enqueued in order B, A and the whole purpose of this queue is lost.
    pub(crate) emit_queue: Arc<DashMap<String, mpsc::UnboundedSender<EmitJob>>>,
}

impl SseState {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            cursor_gen: CursorGenerator::new(),
            channels: Arc::new(RwLock::new(HashMap::new())),
            buffer_size,
            emit_queue: Arc::new(DashMap::new()),
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

    /// Synchronously enqueue a job on the per-convo FIFO queue.
    ///
    /// Lazily spawns the consumer task on first use for a given convo.
    /// This function MUST NOT await and MUST be called synchronously
    /// (no wrapping `tokio::spawn`) at the emission site: the whole point
    /// is that the enqueue order matches the DB commit order.
    fn enqueue_job(&self, convo_id: &str, job: EmitJob) {
        use dashmap::mapref::entry::Entry;

        let sender = match self.emit_queue.entry(convo_id.to_string()) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => {
                let (tx, rx) = mpsc::unbounded_channel::<EmitJob>();
                let channels = self.channels.clone();
                let buffer_size = self.buffer_size;
                let queue_ref = self.emit_queue.clone();
                let convo_id_owned = convo_id.to_string();
                tokio::spawn(consume_emit_queue(
                    channels,
                    buffer_size,
                    queue_ref,
                    convo_id_owned,
                    rx,
                ));
                v.insert(tx).clone()
            }
        };

        if sender.send(job).is_err() {
            // Consumer dropped — extremely rare (only if the task panicked).
            // Drop the entry so the next call respawns.
            warn!(
                convo = %crate::crypto::redact_for_log(convo_id),
                "Per-convo emit queue consumer dropped; resetting slot"
            );
            self.emit_queue.remove(convo_id);
        }
    }

    /// Synchronously enqueue a broadcast event on the per-convo FIFO queue.
    ///
    /// No DB write is performed — use this for ephemeral or non-persisted
    /// events (typing, info, etc.) or when `store_event` has already been
    /// handled elsewhere.
    ///
    /// # Phase 3 — durable outbox interaction
    ///
    /// This is the **best-effort, low-latency** broadcast path. For
    /// events that originated from the chokepoint
    /// (`reset_chokepoint::{request_crypto_session_reset_tx,
    /// activate_crypto_session_tx}`), the chokepoint additionally writes
    /// a `notification_outbox` row in the same Postgres tx as the
    /// `delivery_events` insert. The outbox is the **durable** shadow:
    /// connected subscribers receive the broadcast immediately via this
    /// in-memory path; reconnecting subscribers backfill from
    /// `event_stream` via cursor; if the server SIGKILLs between commit
    /// and broadcast, the outbox worker drains the row on restart.
    ///
    /// Both paths are intentionally redundant — see
    /// `workers/notification_outbox.rs` for the dispatch contract
    /// (`kind='sse'` is a no-op-on-success because the connected
    /// subscriber path already served the intent).
    pub fn enqueue(&self, convo_id: &str, event: StreamEvent) {
        self.enqueue_job(convo_id, EmitJob { event, store: None });
    }

    /// Synchronously enqueue a `store_event` + broadcast pair on the per-convo
    /// FIFO queue. The consumer task performs the DB insert **before** the
    /// broadcast send, co-located on the same task so ordering is preserved
    /// across concurrent emissions for the same convo.
    ///
    /// The event's cursor, event_type, and message_id are derived from the
    /// `StreamEvent` itself (see `crate::db::store_event` and
    /// `crate::db::stream_event_type_str`) — callers only supply the pool.
    pub fn enqueue_with_store(&self, convo_id: &str, pool: DbPool, event: StreamEvent) {
        self.enqueue_job(
            convo_id,
            EmitJob {
                event,
                store: Some(StoreEventArgs { pool }),
            },
        );
    }

    /// Emit event to all subscribers of a conversation.
    ///
    /// Backwards-compatible wrapper around the per-convo FIFO queue: the event
    /// is handed off synchronously to the consumer task for this convo, which
    /// performs the broadcast send in order. The returned future resolves
    /// immediately once the job is enqueued — it does not await broadcast
    /// delivery.
    ///
    /// Returns Ok in all non-panic cases: broadcast channels with no
    /// subscribers are treated as non-fatal (expected when members are
    /// offline).
    pub async fn emit(&self, convo_id: &str, event: StreamEvent) -> Result<(), String> {
        self.enqueue(convo_id, event);
        Ok(())
    }
}

/// Consumer task body for a per-convo FIFO emit queue.
///
/// Drains the mpsc receiver in order, performing the optional DB
/// `store_event` **before** the broadcast `send` to preserve the invariant
/// that subscribers see events in the same order they were committed to the
/// database.
async fn consume_emit_queue(
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    buffer_size: usize,
    queue_ref: Arc<DashMap<String, mpsc::UnboundedSender<EmitJob>>>,
    convo_id: String,
    mut rx: mpsc::UnboundedReceiver<EmitJob>,
) {
    while let Some(job) = rx.recv().await {
        // 1. Persist event_stream row (if requested). This must happen
        //    BEFORE the broadcast send so that late subscribers replaying
        //    from a cursor cannot observe a broadcast whose DB row does
        //    not yet exist.
        if let Some(store) = job.store.as_ref() {
            // Task #40: store_event now takes (pool, convo_id, &StreamEvent)
            // and derives event_type / cursor / message_id from the event.
            let event_type = crate::db::stream_event_type_str(&job.event);
            if let Err(e) = crate::db::store_event(&store.pool, &convo_id, &job.event).await {
                error!(
                    convo = %crate::crypto::redact_for_log(&convo_id),
                    event_type,
                    error = ?e,
                    "per-convo emit queue: store_event failed"
                );
                // Continue to broadcast anyway — cursor is already allocated
                // and dropping the event would look like silent data loss.
            }
        }

        // 2. Broadcast to SSE/WS subscribers. Lazy-create the channel using
        //    the same code path as `get_channel` to share the map.
        let tx = {
            let mut chans = channels.write().await;
            chans
                .entry(convo_id.clone())
                .or_insert_with(|| {
                    let (tx, _rx) = broadcast::channel(buffer_size);
                    info!(
                        convo = %crate::crypto::redact_for_log(&convo_id),
                        "Created new broadcast channel (via emit queue)"
                    );
                    tx
                })
                .clone()
        };

        // Broadcast errors here only indicate "no active subscribers" — which
        // is expected when all members are offline. Not a real failure.
        let _ = tx.send(job.event);
    }

    // Receiver closed — the sender half was dropped (e.g. SseState being
    // torn down). Remove ourselves from the map so a later recreation would
    // spawn a fresh task.
    queue_ref.remove(&convo_id);
    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        "per-convo emit queue consumer exited"
    );
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
    let replay_stream = stream::iter(Vec::<Result<Event, Infallible>>::new());

    // Create live event stream
    let convo_id_str = convo_id.to_string();
    let live_stream = stream::unfold(
        (rx, convo_id_str),
        move |(mut rx, convo_id)| async move {
            loop {
                tokio::select! {
                    // Wait for broadcast event
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                match &event {
                                    StreamEvent::CleanTypingEvent { .. } => continue,
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    convo = %crate::crypto::redact_for_log(&convo_id),
                                    skipped = skipped,
                                    "Slow consumer, events skipped"
                                );
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
                        return Some((Ok(sse_event), (rx, convo_id)));
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

    fn make_test_typing_event(convo_id: &str, typing_id: &str) -> StreamEvent {
        serde_json::from_value(serde_json::json!({
            "$type": "blue.catbird.chat.defs#typingEvent",
            "actorDeviceId": "device-a",
            "actorDid": "did:plc:actor",
            "conversationId": convo_id,
            "expiresAt": "2026-08-16T12:00:08.000Z",
            "isTyping": true,
            "typingId": typing_id
        }))
        .expect("test typing event should deserialize")
    }

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

        let event = make_test_typing_event("convo1", "typing-1");
        state.emit("convo1", event.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert!(matches!(received, StreamEvent::CleanTypingEvent { .. }));
    }

    #[test]
    fn clean_typing_keeps_generated_dto_tag_and_all_fields() {
        let event: StreamEvent = serde_json::from_value(serde_json::json!({
            "$type": "blue.catbird.chat.defs#typingEvent",
            "actorDeviceId": "device-a",
            "actorDid": "did:plc:actor",
            "conversationId": "convo-a",
            "expiresAt": "2026-08-16T12:00:08.000Z",
            "isTyping": true,
            "typingId": "typing-a"
        }))
        .expect("generated clean typing DTO should deserialize on the shared bus");

        let wire = serde_json::to_value(&event).expect("clean typing should serialize");
        assert_eq!(wire["$type"], "blue.catbird.chat.defs#typingEvent");
        assert_eq!(wire["actorDeviceId"], "device-a");
        assert_eq!(wire["actorDid"], "did:plc:actor");
        assert_eq!(wire["conversationId"], "convo-a");
        assert_eq!(wire["expiresAt"], "2026-08-16T12:00:08.000Z");
        assert_eq!(wire["isTyping"], true);
        assert_eq!(wire["typingId"], "typing-a");
    }

    #[tokio::test]
    async fn test_per_convo_fifo_ordering_single_producer() {
        let state = Arc::new(SseState::new(1000));
        let tx = state.get_channel("convo-fifo").await;
        let mut rx = tx.subscribe();

        for i in 0..10 {
            let event = make_test_typing_event("convo-fifo", &format!("typing-{}", i));
            state.enqueue("convo-fifo", event);
        }

        let mut observed = Vec::with_capacity(10);
        for _ in 0..10 {
            let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out waiting for broadcast event")
                .expect("broadcast recv error");
            let StreamEvent::CleanTypingEvent { typing_id, .. } = event;
            assert_eq!(typing_id.as_str(), format!("typing-{}", observed.len()));
            observed.push(typing_id.as_str().to_string());
        }

        let expected: Vec<String> = (0..10).map(|i| format!("typing-{}", i)).collect();
        assert_eq!(observed, expected, "per-convo queue must preserve enqueue order");
    }

    #[tokio::test]
    async fn test_per_convo_queues_are_independent() {
        let state = Arc::new(SseState::new(1000));

        let tx_a = state.get_channel("convo-a").await;
        let tx_b = state.get_channel("convo-b").await;
        let mut rx_a = tx_a.subscribe();
        let mut rx_b = tx_b.subscribe();

        for i in 0..5 {
            state.enqueue("convo-a", make_test_typing_event("convo-a", &format!("a-{}", i)));
            state.enqueue("convo-b", make_test_typing_event("convo-b", &format!("b-{}", i)));
        }

        for i in 0..5 {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
                .await
                .expect("timed out on convo-a")
                .expect("rx_a recv error");
            let StreamEvent::CleanTypingEvent { typing_id, .. } = ev;
            assert_eq!(typing_id.as_str(), format!("a-{}", i));

            let ev = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
                .await
                .expect("timed out on convo-b")
                .expect("rx_b recv error");
            let StreamEvent::CleanTypingEvent { typing_id, .. } = ev;
            assert_eq!(typing_id.as_str(), format!("b-{}", i));
        }

        assert!(state.emit_queue.contains_key("convo-a"));
        assert!(state.emit_queue.contains_key("convo-b"));
    }

    #[tokio::test]
    async fn test_emit_delegates_to_per_convo_queue() {
        let state = Arc::new(SseState::new(1000));
        let tx = state.get_channel("convo-compat").await;
        let mut rx = tx.subscribe();

        for i in 0..3 {
            state
                .emit(
                    "convo-compat",
                    make_test_typing_event("convo-compat", &format!("compat-{}", i)),
                )
                .await
                .unwrap();
        }

        for i in 0..3 {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out")
                .expect("recv err");
            let StreamEvent::CleanTypingEvent { typing_id, .. } = ev;
            assert_eq!(typing_id.as_str(), format!("compat-{}", i));
        }
    }
}

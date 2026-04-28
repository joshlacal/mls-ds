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
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#reactionEvent")]
    ReactionEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        /// DID of the user who reacted
        did: String,
        /// Target message ID
        #[serde(rename = "messageId")]
        message_id: String,
        /// Emoji character (e.g. "👍") or short code
        reaction: String,
        /// "add" or "remove"
        action: String,
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
        #[serde(rename = "requestedBy")]
        requested_by: String,
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
        #[serde(
            rename = "confirmationTag",
            with = "jacquard_common::serde_bytes_helper"
        )]
        confirmation_tag: bytes::Bytes,
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
    /// Event indicating the circuit breaker has tripped — auto-reset is disabled
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#circuitBreakerTrippedEvent")]
    CircuitBreakerTrippedEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "resetCount")]
        reset_count: i32,
        #[serde(rename = "trippedAt")]
        tripped_at: String,
    },
    /// Phase 2.5 §2 — indirect-flow trigger has emitted a
    /// `crypto_session_reset_requested` delivery event. Active members
    /// of the conversation are invited to respond by submitting new
    /// MLS group material via `bootstrap_reset_group` /
    /// `commit_group_change`. First commit wins via the
    /// `UNIQUE (conversation_id, generation)` constraint.
    ///
    /// Stage 1 ships this alongside the legacy `GroupResetEvent` (dual-
    /// emit) so unmodified clients are unaffected.
    #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#resetRequestedEvent")]
    ResetRequestedEvent {
        cursor: String,
        #[serde(rename = "convoId")]
        convo_id: String,
        #[serde(rename = "cryptoSessionId")]
        crypto_session_id: String,
        generation: i32,
        /// Stable string id from `ResetTrigger::as_str()`; mapped to
        /// the lexicon's `knownValues` enumeration.
        trigger: String,
        #[serde(rename = "requestEventId")]
        request_event_id: String,
        #[serde(
            rename = "expectedNewMlsGroupId",
            skip_serializing_if = "Option::is_none"
        )]
        expected_new_mls_group_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(rename = "requestedAt")]
        requested_at: String,
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
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#reactionEvent")]
            ReactionEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                did: String,
                #[serde(rename = "messageId")]
                message_id: String,
                reaction: String,
                action: String,
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
                #[serde(rename = "requestedBy")]
                requested_by: String,
                #[serde(rename = "requestedAt")]
                requested_at: String,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#treeChanged")]
            TreeChanged {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(
                    rename = "confirmationTag",
                    with = "jacquard_common::serde_bytes_helper"
                )]
                confirmation_tag: bytes::Bytes,
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
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#circuitBreakerTrippedEvent")]
            CircuitBreakerTrippedEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "resetCount")]
                reset_count: i32,
                #[serde(rename = "trippedAt")]
                tripped_at: String,
            },
            #[serde(rename = "blue.catbird.mlsChat.subscribeEvents#resetRequestedEvent")]
            ResetRequestedEvent {
                cursor: String,
                #[serde(rename = "convoId")]
                convo_id: String,
                #[serde(rename = "cryptoSessionId")]
                crypto_session_id: String,
                generation: i32,
                trigger: String,
                #[serde(rename = "requestEventId")]
                request_event_id: String,
                #[serde(rename = "expectedNewMlsGroupId", default)]
                expected_new_mls_group_id: Option<String>,
                #[serde(default)]
                reason: Option<String>,
                #[serde(rename = "requestedAt")]
                requested_at: String,
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
            RawStreamEvent::ReactionEvent {
                cursor,
                convo_id,
                did,
                message_id,
                reaction,
                action,
            } => StreamEvent::ReactionEvent {
                cursor,
                convo_id,
                did,
                message_id,
                reaction,
                action,
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
                requested_by,
                requested_at,
            } => StreamEvent::ReadditionRequested {
                cursor,
                convo_id,
                requested_by,
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
            RawStreamEvent::CircuitBreakerTrippedEvent {
                cursor,
                convo_id,
                reset_count,
                tripped_at,
            } => StreamEvent::CircuitBreakerTrippedEvent {
                cursor,
                convo_id,
                reset_count,
                tripped_at,
            },
            RawStreamEvent::ResetRequestedEvent {
                cursor,
                convo_id,
                crypto_session_id,
                generation,
                trigger,
                request_event_id,
                expected_new_mls_group_id,
                reason,
                requested_at,
            } => StreamEvent::ResetRequestedEvent {
                cursor,
                convo_id,
                crypto_session_id,
                generation,
                trigger,
                request_event_id,
                expected_new_mls_group_id,
                reason,
                requested_at,
            },
        })
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

                    // Legacy-row migration (see group_info::decode_legacy_if_needed):
                    // some older commit rows are stored as base64 text of the MLS
                    // wire bytes. Serving those as-is breaks every client because
                    // `MessageView::ciphertext` is raw bytes on the wire.
                    let ciphertext = crate::group_info::decode_legacy_if_needed(
                        ciphertext,
                        &format!("commit-ciphertext[{}]", message_id),
                    );

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
                        };

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

    let replay_stream = stream::iter(replay_sse_events.into_iter().map(Ok::<Event, Infallible>));

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
                                    StreamEvent::ReactionEvent { cursor, .. } => cursor,
                                    StreamEvent::InfoEvent { cursor, .. } => cursor,
                                    StreamEvent::NewDeviceEvent { cursor, .. } => cursor,
                                    StreamEvent::GroupInfoRefreshRequested { cursor, .. } => cursor,
                                    StreamEvent::ReadditionRequested { cursor, .. } => cursor,
                                    StreamEvent::TreeChanged { cursor, .. } => cursor,
                                    StreamEvent::MembershipChangeEvent { cursor, .. } => cursor,
                                    StreamEvent::GroupResetEvent { cursor, .. } => cursor,
                                    StreamEvent::CircuitBreakerTrippedEvent { cursor, .. } => cursor,
                                    StreamEvent::ResetRequestedEvent { cursor, .. } => cursor,
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

    /// Round-trip every `StreamEvent` variant through
    /// `serde_json::to_value` → `from_value`.
    ///
    /// This is the exact path WS/SSE backfill reconstruction takes after
    /// task #40 persisted full event payloads in `event_stream.payload`.
    /// A regression here means a new variant (or a changed field) would
    /// silently drop on replay — clients reconnecting with a cursor would
    /// miss the event. The pure round-trip catches it at `cargo test --lib`.
    #[test]
    fn test_stream_event_roundtrip_all_variants() {
        let variants = vec![
            StreamEvent::MessageEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                message: test_message_view("m-rt"),
                ephemeral: false,
            },
            StreamEvent::TypingEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB1".into(),
                convo_id: "c1".into(),
                did: "did:plc:alice".into(),
                is_typing: true,
            },
            StreamEvent::ReactionEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB2".into(),
                convo_id: "c1".into(),
                did: "did:plc:alice".into(),
                message_id: "m-rt".into(),
                reaction: "👍".into(),
                action: "add".into(),
            },
            StreamEvent::InfoEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB3".into(),
                info: "hi".into(),
            },
            StreamEvent::NewDeviceEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB4".into(),
                convo_id: "c1".into(),
                user_did: "did:plc:alice".into(),
                device_id: "dev-1".into(),
                device_name: Some("phone".into()),
                device_credential_did: "did:key:abc".into(),
                pending_addition_id: "pa-1".into(),
            },
            StreamEvent::GroupInfoRefreshRequested {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB5".into(),
                convo_id: "c1".into(),
                requested_by: "did:plc:alice".into(),
                requested_at: "2026-04-20T00:00:00.000Z".into(),
            },
            StreamEvent::ReadditionRequested {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB6".into(),
                convo_id: "c1".into(),
                requested_by: "did:plc:alice".into(),
                requested_at: "2026-04-20T00:00:00.000Z".into(),
            },
            StreamEvent::TreeChanged {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB7".into(),
                convo_id: "c1".into(),
                confirmation_tag: bytes::Bytes::from(vec![0xDEu8, 0xAD, 0xBE, 0xEF]),
                epoch: 42,
            },
            StreamEvent::MembershipChangeEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB8".into(),
                convo_id: "c1".into(),
                did: "did:plc:alice".into(),
                action: "joined".into(),
                actor: Some("did:plc:bob".into()),
                reason: None,
                epoch: 7,
            },
            StreamEvent::GroupResetEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FB9".into(),
                convo_id: "c1".into(),
                new_group_id: "deadbeef".repeat(4),
                reset_generation: 3,
                reset_by: "did:plc:alice".into(),
                cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
                reason: Some("auto".into()),
            },
            StreamEvent::CircuitBreakerTrippedEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FBA".into(),
                convo_id: "c1".into(),
                reset_count: 4,
                tripped_at: "2026-04-20T00:00:00.000Z".into(),
            },
            StreamEvent::ResetRequestedEvent {
                cursor: "01ARZ3NDEKTSV4RRFFQ69G5FBB".into(),
                convo_id: "c1".into(),
                crypto_session_id: "cs-prior-uuid".into(),
                generation: 17,
                trigger: "quorum_vote".into(),
                request_event_id: "req-evt-uuid".into(),
                expected_new_mls_group_id: None,
                reason: Some("quorum reached".into()),
                requested_at: "2026-04-28T15:32:11.123Z".into(),
            },
        ];

        for original in variants {
            let value = serde_json::to_value(&original)
                .unwrap_or_else(|e| panic!("to_value failed for {:?}: {}", original, e));

            // Every variant must carry a `$type` tag after serialization, so
            // legacy (pre-migration) rows without `$type` are distinguishable
            // and correctly skipped by the WS backfill.
            assert!(
                value.get("$type").is_some(),
                "serialized event missing $type tag: {:?}",
                value
            );

            // `from_value` cannot produce borrowed `&'de str` (it consumes its
            // input), and `jacquard_common::serde_bytes_helper`'s visitor
            // requires `&'de str` map keys. Round-trip via the JSON source
            // string — this is also what the WS backfill path uses.
            let json = serde_json::to_string(&value).expect("to_string on round-trip value failed");
            let round_tripped: StreamEvent = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("from_str failed for {:?}: {}", original, e));

            // Re-serialize both and compare as JSON values to sidestep the
            // fact that `MessageView` doesn't implement `PartialEq` directly.
            let original_again = serde_json::to_value(&original).unwrap();
            let round_again = serde_json::to_value(&round_tripped).unwrap();
            assert_eq!(
                original_again, round_again,
                "round-trip diverged for variant {:?}",
                original
            );
        }
    }

    /// Legacy event_stream rows (pre-task-40) stored only
    /// `{cursor, convoId, messageId}` with no `$type` tag. Confirm they fail
    /// deserialization so the WS backfill can skip them cleanly.
    #[test]
    fn test_legacy_payload_fails_deserialization() {
        let legacy = serde_json::json!({
            "cursor": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "convoId": "c1",
            "messageId": "m1",
        });

        let json = serde_json::to_string(&legacy).unwrap();
        let result: Result<StreamEvent, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "legacy envelope without $type should fail deserialization, got: {:?}",
            result
        );
    }
    /// Task #39: the per-convo emit queue must preserve synchronous enqueue
    /// order through the broadcast channel, even if multiple producers race
    /// to call `enqueue` concurrently.
    ///
    /// This test simulates the DB-tx-serialized producer pattern: a single
    /// caller enqueues a known order of events; we then verify the subscriber
    /// sees them in that exact order.
    #[tokio::test]
    async fn test_per_convo_fifo_ordering_single_producer() {
        let state = Arc::new(SseState::new(1000));
        // Subscribe BEFORE enqueuing so the broadcast receiver captures all
        // events. We create the broadcast channel up-front so the consumer
        // task, when lazily spawned on first enqueue, reuses the same sender.
        let tx = state.get_channel("convo-fifo").await;
        let mut rx = tx.subscribe();

        // Enqueue 100 events in strict order.
        for i in 0..100 {
            let event = StreamEvent::InfoEvent {
                cursor: ulid::Ulid::new().to_string(),
                info: format!("evt-{:03}", i),
            };
            state.enqueue("convo-fifo", event);
        }

        // Drain the receiver. The consumer task needs a moment to spawn and
        // process; use a timeout per recv.
        let mut observed = Vec::with_capacity(100);
        for _ in 0..100 {
            let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out waiting for broadcast event")
                .expect("broadcast recv error");
            if let StreamEvent::InfoEvent { info, .. } = event {
                observed.push(info);
            } else {
                panic!("unexpected event variant");
            }
        }

        let expected: Vec<String> = (0..100).map(|i| format!("evt-{:03}", i)).collect();
        assert_eq!(
            observed, expected,
            "per-convo queue must preserve enqueue order"
        );
    }

    /// Task #39: different convos must fan out independently. One slow convo's
    /// consumer task must NOT block another convo's consumer.
    #[tokio::test]
    async fn test_per_convo_queues_are_independent() {
        let state = Arc::new(SseState::new(1000));

        let tx_a = state.get_channel("convo-a").await;
        let tx_b = state.get_channel("convo-b").await;
        let mut rx_a = tx_a.subscribe();
        let mut rx_b = tx_b.subscribe();

        // Interleave enqueues across two convos.
        for i in 0..10 {
            state.enqueue(
                "convo-a",
                StreamEvent::InfoEvent {
                    cursor: ulid::Ulid::new().to_string(),
                    info: format!("a-{:02}", i),
                },
            );
            state.enqueue(
                "convo-b",
                StreamEvent::InfoEvent {
                    cursor: ulid::Ulid::new().to_string(),
                    info: format!("b-{:02}", i),
                },
            );
        }

        // Each convo must see its own events in order, with no cross-contamination.
        for i in 0..10 {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
                .await
                .expect("timed out on convo-a")
                .expect("rx_a recv error");
            if let StreamEvent::InfoEvent { info, .. } = ev {
                assert_eq!(info, format!("a-{:02}", i));
            } else {
                panic!("unexpected variant on convo-a");
            }

            let ev = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
                .await
                .expect("timed out on convo-b")
                .expect("rx_b recv error");
            if let StreamEvent::InfoEvent { info, .. } = ev {
                assert_eq!(info, format!("b-{:02}", i));
            } else {
                panic!("unexpected variant on convo-b");
            }
        }

        // Queues for the two convos must be distinct DashMap entries.
        assert!(state.emit_queue.contains_key("convo-a"));
        assert!(state.emit_queue.contains_key("convo-b"));
    }

    /// Sanity: the backwards-compatible async `emit` delegates to the queue.
    #[tokio::test]
    async fn test_emit_delegates_to_per_convo_queue() {
        let state = Arc::new(SseState::new(1000));
        let tx = state.get_channel("convo-compat").await;
        let mut rx = tx.subscribe();

        for i in 0..5 {
            state
                .emit(
                    "convo-compat",
                    StreamEvent::InfoEvent {
                        cursor: ulid::Ulid::new().to_string(),
                        info: format!("compat-{i}"),
                    },
                )
                .await
                .unwrap();
        }

        for i in 0..5 {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out")
                .expect("recv err");
            if let StreamEvent::InfoEvent { info, .. } = ev {
                assert_eq!(info, format!("compat-{i}"));
            } else {
                panic!("unexpected variant");
            }
        }
    }
}

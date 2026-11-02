use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::realtime::cursor::CursorGenerator;

/// Event types for realtime streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum StreamEvent {
    /// Clean-chat ephemeral typing DTO.
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

pub fn is_false(v: &bool) -> bool {
    !(*v)
}

pub fn set_stream_event_cursor(_event: &mut StreamEvent, _new_cursor: String) {}

impl StreamEvent {
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

#[derive(Debug)]
pub(crate) struct EmitJob {
    pub event: StreamEvent,
}

/// Shared state for per-conversation realtime broadcasts.
pub struct SseState {
    pub cursor_gen: CursorGenerator,
    pub channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    pub buffer_size: usize,
    pub(crate) emit_queue: Arc<DashMap<String, mpsc::UnboundedSender<EmitJob>>>,
    spawner: std::sync::RwLock<Arc<dyn crate::sim_hooks::TaskSpawner>>,
}

impl SseState {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            cursor_gen: CursorGenerator::new(),
            channels: Arc::new(RwLock::new(HashMap::new())),
            buffer_size,
            emit_queue: Arc::new(DashMap::new()),
            spawner: std::sync::RwLock::new(Arc::new(crate::sim_hooks::TokioTaskSpawner)),
        }
    }

    pub fn set_spawner(&self, spawner: Arc<dyn crate::sim_hooks::TaskSpawner>) {
        let mut guard = self.spawner.write().unwrap_or_else(|e| e.into_inner());
        *guard = spawner;
    }

    pub fn spawner(&self) -> Arc<dyn crate::sim_hooks::TaskSpawner> {
        Arc::clone(&self.spawner.read().unwrap_or_else(|e| e.into_inner()))
    }

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
                let spawner = self.spawner();
                let fut: crate::sim_hooks::BoxedTaskFuture = if spawner.is_queued() {
                    Box::pin(flush_emit_queue_batch(
                        channels,
                        buffer_size,
                        queue_ref,
                        convo_id_owned,
                        rx,
                    ))
                } else {
                    Box::pin(consume_emit_queue(
                        channels,
                        buffer_size,
                        queue_ref,
                        convo_id_owned,
                        rx,
                    ))
                };
                spawner.spawn_box("sse.consume_emit_queue", fut);
                v.insert(tx).clone()
            }
        };

        if sender.send(job).is_err() {
            warn!(
                convo = %crate::crypto::redact_for_log(convo_id),
                "Per-convo emit queue consumer dropped; resetting slot"
            );
            self.emit_queue.remove(convo_id);
        }
    }

    pub fn enqueue(&self, convo_id: &str, event: StreamEvent) {
        self.enqueue_job(convo_id, EmitJob { event });
    }

    pub async fn emit(&self, convo_id: &str, event: StreamEvent) -> Result<(), String> {
        self.enqueue(convo_id, event);
        Ok(())
    }

    pub fn broadcast(&self, event_type: &str, payload: &str) {
        debug!(event_type, payload, "Broadcasting realtime event");
    }

    /// Prune conversation broadcast channels that currently have zero active
    /// receivers and no in-flight emit-queue consumer (`M-F05`).
    pub async fn prune_idle_channels(&self) -> usize {
        let mut channels = self.channels.write().await;
        let before = channels.len();
        channels.retain(|convo_id, sender| {
            sender.receiver_count() > 0 || self.emit_queue.contains_key(convo_id)
        });
        before.saturating_sub(channels.len())
    }
}

async fn consume_emit_queue(
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    buffer_size: usize,
    queue_ref: Arc<DashMap<String, mpsc::UnboundedSender<EmitJob>>>,
    convo_id: String,
    mut rx: mpsc::UnboundedReceiver<EmitJob>,
) {
    while let Some(job) = rx.recv().await {
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

        let _ = tx.send(job.event);
    }

    queue_ref.remove(&convo_id);
    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        "per-convo emit queue consumer exited"
    );
}

async fn flush_emit_queue_batch(
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<StreamEvent>>>>,
    buffer_size: usize,
    queue_ref: Arc<DashMap<String, mpsc::UnboundedSender<EmitJob>>>,
    convo_id: String,
    mut rx: mpsc::UnboundedReceiver<EmitJob>,
) {
    queue_ref.remove(&convo_id);
    while let Some(job) = rx.recv().await {
        let tx = {
            let mut chans = channels.write().await;
            chans
                .entry(convo_id.clone())
                .or_insert_with(|| broadcast::channel(buffer_size).0)
                .clone()
        };
        let _ = tx.send(job.event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
        assert_eq!(
            observed, expected,
            "per-convo queue must preserve enqueue order"
        );
    }

    #[tokio::test]
    async fn test_per_convo_queues_are_independent() {
        let state = Arc::new(SseState::new(1000));

        let tx_a = state.get_channel("convo-a").await;
        let tx_b = state.get_channel("convo-b").await;
        let mut rx_a = tx_a.subscribe();
        let mut rx_b = tx_b.subscribe();

        for i in 0..5 {
            state.enqueue(
                "convo-a",
                make_test_typing_event("convo-a", &format!("a-{}", i)),
            );
            state.enqueue(
                "convo-b",
                make_test_typing_event("convo-b", &format!("b-{}", i)),
            );
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

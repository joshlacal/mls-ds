//! Manages multiplexed WebSocket connections to remote sequencer DSes.
//!
//! When a client subscribes to a conversation whose sequencer is on another DS,
//! the UpstreamManager lazily creates a single upstream WS connection per
//! (sequencer_did, convo_id) and fans out events to all local subscribers via a
//! `broadcast` channel — identical to the local SSE path. The sequencer only
//! sees "one connection from this home DS," never individual client devices.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{broadcast, RwLock};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::federation::errors::FederationError;
use crate::federation::resolver::DsResolver;
use crate::federation::service_auth::ServiceAuthClient;
use crate::realtime::sse::StreamEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TICKET_METHOD: &str = "blue.catbird.mls.getSubscriptionTicket";
const SUBSCRIBE_METHOD: &str = "blue.catbird.mls.subscribeConvoEvents";
const RECONNECT_BASE: Duration = Duration::from_secs(1);
const RECONNECT_CAP: Duration = Duration::from_secs(60);
const GRACE_PERIOD: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Wire types for parsing upstream DAG-CBOR frames
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WireHeader {
    #[allow(dead_code)]
    op: i32,
    #[allow(dead_code)]
    t: String,
}

/// Ticket response from the sequencer DS.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TicketResponse {
    ticket: String,
    #[allow(dead_code)]
    endpoint: Option<String>,
}

// ---------------------------------------------------------------------------
// UpstreamKey / UpstreamConnection
// ---------------------------------------------------------------------------

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct UpstreamKey {
    sequencer_did: String,
    convo_id: String,
}

struct UpstreamConnection {
    tx: broadcast::Sender<StreamEvent>,
    refcount: Arc<AtomicUsize>,
    cancel: CancellationToken,
    #[allow(dead_code)]
    last_cursor: Arc<RwLock<Option<String>>>,
}

// ---------------------------------------------------------------------------
// UpstreamManager
// ---------------------------------------------------------------------------

pub struct UpstreamManager {
    resolver: Arc<DsResolver>,
    auth: Arc<ServiceAuthClient>,
    http: reqwest::Client,
    self_did: String,
    #[allow(dead_code)]
    self_endpoint: String,
    connections: Arc<RwLock<HashMap<UpstreamKey, UpstreamConnection>>>,
    shutdown: CancellationToken,
    buffer_size: usize,
}

impl UpstreamManager {
    pub fn new(
        resolver: Arc<DsResolver>,
        auth: Arc<ServiceAuthClient>,
        self_did: String,
        self_endpoint: String,
        shutdown: CancellationToken,
        buffer_size: usize,
    ) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            resolver,
            auth,
            http,
            self_did,
            self_endpoint,
            connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown,
            buffer_size,
        }
    }

    /// Subscribe to events for a remote conversation.
    ///
    /// Lazily creates an upstream WS connection to the sequencer if none exists.
    /// Returns a `broadcast::Receiver<StreamEvent>` identical to what `SseState`
    /// provides for local conversations.
    pub async fn subscribe(
        &self,
        convo_id: &str,
        sequencer_did: &str,
        cursor: Option<&str>,
    ) -> Result<broadcast::Receiver<StreamEvent>, FederationError> {
        let key = UpstreamKey {
            sequencer_did: sequencer_did.to_string(),
            convo_id: convo_id.to_string(),
        };

        // Fast path: connection already exists
        {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(&key) {
                conn.refcount.fetch_add(1, Ordering::Relaxed);
                debug!(
                    convo_id,
                    sequencer_did, "Reusing existing upstream connection"
                );
                return Ok(conn.tx.subscribe());
            }
        }

        // Slow path: create new upstream connection
        let endpoint = self.resolver.resolve(sequencer_did).await?;
        let (tx, _) = broadcast::channel(self.buffer_size);
        let cancel = self.shutdown.child_token();
        let refcount = Arc::new(AtomicUsize::new(1));
        let last_cursor = Arc::new(RwLock::new(cursor.map(String::from)));

        let conn = UpstreamConnection {
            tx: tx.clone(),
            refcount: refcount.clone(),
            cancel: cancel.clone(),
            last_cursor: last_cursor.clone(),
        };

        let rx = tx.subscribe();

        {
            let mut conns = self.connections.write().await;
            // Double-check: another task may have created it while we awaited
            if let Some(existing) = conns.get(&key) {
                existing.refcount.fetch_add(1, Ordering::Relaxed);
                return Ok(existing.tx.subscribe());
            }
            conns.insert(key.clone(), conn);
        }

        // Spawn background reader task
        let task_ctx = ReaderTaskContext {
            key: key.clone(),
            endpoint_url: endpoint.endpoint,
            sequencer_did: sequencer_did.to_string(),
            convo_id: convo_id.to_string(),
            auth: self.auth.clone(),
            http: self.http.clone(),
            self_did: self.self_did.clone(),
            tx,
            cancel,
            last_cursor,
        };

        tokio::spawn(upstream_reader_task(task_ctx));

        info!(
            convo_id,
            sequencer_did, "Created new upstream WS connection"
        );

        Ok(rx)
    }

    /// Decrement refcount. If zero, close upstream after grace period.
    pub async fn unsubscribe(&self, convo_id: &str, sequencer_did: &str) {
        let key = UpstreamKey {
            sequencer_did: sequencer_did.to_string(),
            convo_id: convo_id.to_string(),
        };

        let (refcount, cancel) = {
            let conns = self.connections.read().await;
            match conns.get(&key) {
                Some(conn) => {
                    let prev = conn.refcount.fetch_sub(1, Ordering::Relaxed);
                    if prev <= 1 {
                        (0usize, Some(conn.cancel.clone()))
                    } else {
                        return; // Still has subscribers
                    }
                }
                None => return,
            }
        };

        if refcount == 0 {
            // Spawn delayed cleanup
            let connections = self.connections.clone();
            let cancel = cancel.expect("cancel token present when refcount was 0");
            let key_clone = key;
            tokio::spawn(async move {
                sleep(GRACE_PERIOD).await;
                let mut conns = connections.write().await;
                if let Some(conn) = conns.get(&key_clone) {
                    if conn.refcount.load(Ordering::Relaxed) == 0 {
                        conn.cancel.cancel();
                        conns.remove(&key_clone);
                        debug!(
                            convo_id = key_clone.convo_id,
                            sequencer_did = key_clone.sequencer_did,
                            "Upstream connection closed after grace period"
                        );
                    }
                }
                drop(cancel); // ensure cancel lives until here
            });
        }
    }

    /// Check if there's an active upstream for this convo.
    pub async fn has_upstream(&self, convo_id: &str) -> bool {
        let conns = self.connections.read().await;
        conns.keys().any(|k| k.convo_id == convo_id)
    }

    /// Graceful shutdown — cancel all upstream connections.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let mut conns = self.connections.write().await;
        conns.clear();
        info!("All upstream connections shut down");
    }
}

// ---------------------------------------------------------------------------
// Background reader task
// ---------------------------------------------------------------------------

struct ReaderTaskContext {
    #[allow(dead_code)]
    key: UpstreamKey,
    endpoint_url: String,
    sequencer_did: String,
    convo_id: String,
    auth: Arc<ServiceAuthClient>,
    http: reqwest::Client,
    self_did: String,
    tx: broadcast::Sender<StreamEvent>,
    cancel: CancellationToken,
    last_cursor: Arc<RwLock<Option<String>>>,
}

async fn upstream_reader_task(ctx: ReaderTaskContext) {
    let mut backoff = RECONNECT_BASE;

    loop {
        if ctx.cancel.is_cancelled() {
            debug!(
                convo_id = ctx.convo_id,
                sequencer_did = ctx.sequencer_did,
                "Upstream reader cancelled"
            );
            return;
        }

        match connect_and_stream(&ctx).await {
            Ok(()) => {
                // Clean disconnect — reconnect from last cursor
                backoff = RECONNECT_BASE;
                info!(
                    convo_id = ctx.convo_id,
                    sequencer_did = ctx.sequencer_did,
                    "Upstream WS cleanly closed, reconnecting"
                );
            }
            Err(e) => {
                warn!(
                  convo_id = ctx.convo_id,
                  sequencer_did = ctx.sequencer_did,
                  error = %e,
                  backoff_secs = backoff.as_secs(),
                  "Upstream WS error, reconnecting after backoff"
                );
            }
        }

        tokio::select! {
          _ = sleep(backoff) => {}
          _ = ctx.cancel.cancelled() => return,
        }

        // Exponential backoff, capped
        backoff = (backoff * 2).min(RECONNECT_CAP);
    }
}

/// Acquire ticket, connect WS, and stream events until disconnect.
async fn connect_and_stream(ctx: &ReaderTaskContext) -> Result<(), FederationError> {
    // 1. Acquire subscription ticket from sequencer DS
    let ticket = acquire_ticket(ctx).await?;

    // 2. Build WS URL
    let cursor_param = {
        let cursor = ctx.last_cursor.read().await;
        cursor
            .as_ref()
            .map(|c| format!("&cursor={}", urlencoding::encode(c)))
            .unwrap_or_default()
    };

    let ws_url = format!(
        "{}/xrpc/{}?ticket={}{}",
        ctx.endpoint_url
            .replace("https://", "wss://")
            .replace("http://", "ws://"),
        SUBSCRIBE_METHOD,
        urlencoding::encode(&ticket),
        cursor_param,
    );

    debug!(
        convo_id = ctx.convo_id,
        sequencer_did = ctx.sequencer_did,
        "Connecting upstream WS"
    );

    // 3. Connect with timeout
    let connect_fut = tokio_tungstenite::connect_async(&ws_url);
    let (ws_stream, _response) = tokio::select! {
      result = connect_fut => result.map_err(|e| FederationError::DsUnreachable {
        endpoint: ctx.endpoint_url.clone(),
        reason: format!("WS connect failed: {e}"),
      })?,
      _ = sleep(CONNECT_TIMEOUT) => {
        return Err(FederationError::DsUnreachable {
          endpoint: ctx.endpoint_url.clone(),
          reason: "WS connect timeout".into(),
        });
      }
      _ = ctx.cancel.cancelled() => return Ok(()),
    };

    info!(
        convo_id = ctx.convo_id,
        sequencer_did = ctx.sequencer_did,
        "Upstream WS connected"
    );

    let (mut write, mut read) = ws_stream.split();

    // 4. Read loop
    loop {
        tokio::select! {
          msg = read.next() => {
            match msg {
              Some(Ok(WsMessage::Binary(data))) => {
                if let Some(event) = parse_dagcbor_frame(&data, &ctx.convo_id) {
                  // Update last cursor
                  if let Some(cursor) = extract_cursor(&event) {
                    let mut lc = ctx.last_cursor.write().await;
                    *lc = Some(cursor);
                  }
                  // Broadcast to local subscribers — ignore send error (no receivers)
                  let _ = ctx.tx.send(event);
                }
              }
              Some(Ok(WsMessage::Ping(payload))) => {
                if write.send(WsMessage::Pong(payload)).await.is_err() {
                  break;
                }
              }
              Some(Ok(WsMessage::Close(_))) => {
                debug!(convo_id = ctx.convo_id, "Upstream sent close frame");
                break;
              }
              Some(Ok(_)) => {} // Text frames, pong — ignore
              Some(Err(e)) => {
                return Err(FederationError::DsUnreachable {
                  endpoint: ctx.endpoint_url.clone(),
                  reason: format!("WS read error: {e}"),
                });
              }
              None => break, // Stream ended
            }
          }
          _ = ctx.cancel.cancelled() => {
            let _ = write.send(WsMessage::Close(None)).await;
            return Ok(());
          }
        }
    }

    Ok(())
}

/// Acquire a subscription ticket from the sequencer DS using service auth.
async fn acquire_ticket(ctx: &ReaderTaskContext) -> Result<String, FederationError> {
    let token = ctx
        .auth
        .sign_request(&ctx.sequencer_did, TICKET_METHOD)
        .map_err(|e| FederationError::AuthFailed {
            reason: format!("Failed to sign ticket request: {e}"),
        })?;

    let url = format!("{}/xrpc/{}", ctx.endpoint_url, TICKET_METHOD);

    let body = serde_json::json!({
      "convoId": ctx.convo_id,
    });

    let resp = ctx
        .http
        .post(&url)
        .bearer_auth(&token)
        .header("atproto-proxy", &ctx.self_did)
        .json(&body)
        .send()
        .await
        .map_err(|e| FederationError::DsUnreachable {
            endpoint: ctx.endpoint_url.clone(),
            reason: format!("Ticket request failed: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(FederationError::RemoteError {
            status,
            body: body_text,
        });
    }

    let ticket_resp: TicketResponse =
        resp.json()
            .await
            .map_err(|e| FederationError::RemoteError {
                status: 200,
                body: format!("Failed to parse ticket response: {e}"),
            })?;

    Ok(ticket_resp.ticket)
}

// ---------------------------------------------------------------------------
// DAG-CBOR frame parsing
// ---------------------------------------------------------------------------

/// Parse a DAG-CBOR binary frame into a StreamEvent.
///
/// Frame format: [header_cbor][payload_cbor] concatenated.
/// CBOR is self-delimiting so we can deserialize sequentially.
fn parse_dagcbor_frame(data: &[u8], convo_id: &str) -> Option<StreamEvent> {
    let mut cursor = Cursor::new(data);

    // Parse header (we don't use it for routing, but must consume it)
    let _header: WireHeader = match serde_ipld_dagcbor::from_reader(&mut cursor) {
        Ok(h) => h,
        Err(e) => {
            warn!(convo_id, error = %e, "Failed to parse upstream CBOR header");
            return None;
        }
    };

    // Parse payload — the remaining bytes are the StreamEvent
    let remaining = &data[cursor.position() as usize..];
    match serde_ipld_dagcbor::from_slice::<StreamEvent>(remaining) {
        Ok(event) => Some(event),
        Err(e) => {
            warn!(convo_id, error = %e, "Failed to parse upstream CBOR payload");
            None
        }
    }
}

/// Extract the cursor string from a StreamEvent.
fn extract_cursor(event: &StreamEvent) -> Option<String> {
    match event {
        StreamEvent::MessageEvent { cursor, .. }
        | StreamEvent::ReactionEvent { cursor, .. }
        | StreamEvent::TypingEvent { cursor, .. }
        | StreamEvent::NewDeviceEvent { cursor, .. }
        | StreamEvent::GroupInfoRefreshRequested { cursor, .. }
        | StreamEvent::ReadditionRequested { cursor, .. }
        | StreamEvent::MembershipChangeEvent { cursor, .. }
        | StreamEvent::ReadEvent { cursor, .. }
        | StreamEvent::InfoEvent { cursor, .. } => Some(cursor.clone()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_key_eq() {
        let a = UpstreamKey {
            sequencer_did: "did:web:alice.example".into(),
            convo_id: "convo-123".into(),
        };
        let b = UpstreamKey {
            sequencer_did: "did:web:alice.example".into(),
            convo_id: "convo-123".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_upstream_key_ne() {
        let a = UpstreamKey {
            sequencer_did: "did:web:alice.example".into(),
            convo_id: "convo-123".into(),
        };
        let b = UpstreamKey {
            sequencer_did: "did:web:bob.example".into(),
            convo_id: "convo-123".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_extract_cursor_message() {
        let event = StreamEvent::MessageEvent {
            cursor: "01ABC".into(),
            message: crate::generated_types::MessageView {
                id: "m1".into(),
                convo_id: "c1".into(),
                ciphertext: vec![],
                epoch: 0,
                seq: 0,
                created_at: chrono::Utc::now(),
                message_type: "app".into(),
                reactions: None,
            },
            ephemeral: false,
        };
        assert_eq!(extract_cursor(&event), Some("01ABC".into()));
    }

    #[test]
    fn test_parse_invalid_cbor_returns_none() {
        let bad_data = vec![0xFF, 0xFF, 0xFF];
        assert!(parse_dagcbor_frame(&bad_data, "test-convo").is_none());
    }

    #[test]
    fn test_parse_dagcbor_frame_valid() {
        // Mirror the WireHeader struct for serialization (production one is Deserialize-only)
        #[derive(serde::Serialize)]
        struct TestHeader {
            op: i32,
            t: String,
        }

        let header = TestHeader {
            op: 1,
            t: "#infoEvent".into(),
        };
        let header_bytes = serde_ipld_dagcbor::to_vec(&header).unwrap();

        let event = StreamEvent::InfoEvent {
            cursor: "cursor-xyz".into(),
            info: "test-info".into(),
        };
        let payload_bytes = serde_ipld_dagcbor::to_vec(&event).unwrap();

        let mut frame = Vec::new();
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&payload_bytes);

        let parsed = parse_dagcbor_frame(&frame, "test-convo");
        assert!(parsed.is_some(), "Expected valid frame to parse");

        match parsed.unwrap() {
            StreamEvent::InfoEvent { cursor, info } => {
                assert_eq!(cursor, "cursor-xyz");
                assert_eq!(info, "test-info");
            }
            other => panic!("Expected InfoEvent, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_cursor_all_variants() {
        let now = chrono::Utc::now();
        let msg_view = crate::generated_types::MessageView {
            id: "m1".into(),
            convo_id: "c1".into(),
            ciphertext: vec![],
            epoch: 0,
            seq: 0,
            created_at: now,
            message_type: "app".into(),
            reactions: None,
        };

        let variants: Vec<(&str, StreamEvent)> = vec![
            (
                "MessageEvent",
                StreamEvent::MessageEvent {
                    cursor: "c-msg".into(),
                    message: msg_view,
                    ephemeral: false,
                },
            ),
            (
                "ReactionEvent",
                StreamEvent::ReactionEvent {
                    cursor: "c-react".into(),
                    convo_id: "c1".into(),
                    message_id: "m1".into(),
                    did: "did:x".into(),
                    reaction: "👍".into(),
                    action: "add".into(),
                },
            ),
            (
                "TypingEvent",
                StreamEvent::TypingEvent {
                    cursor: "c-type".into(),
                    convo_id: "c1".into(),
                    did: "did:x".into(),
                    is_typing: true,
                },
            ),
            (
                "InfoEvent",
                StreamEvent::InfoEvent {
                    cursor: "c-info".into(),
                    info: "hello".into(),
                },
            ),
            (
                "NewDeviceEvent",
                StreamEvent::NewDeviceEvent {
                    cursor: "c-dev".into(),
                    convo_id: "c1".into(),
                    user_did: "did:x".into(),
                    device_id: "d1".into(),
                    device_name: None,
                    device_credential_did: "did:key:z".into(),
                    pending_addition_id: "pa1".into(),
                },
            ),
            (
                "GroupInfoRefreshRequested",
                StreamEvent::GroupInfoRefreshRequested {
                    cursor: "c-gir".into(),
                    convo_id: "c1".into(),
                    requested_by: "did:x".into(),
                    requested_at: now.to_rfc3339(),
                },
            ),
            (
                "ReadditionRequested",
                StreamEvent::ReadditionRequested {
                    cursor: "c-readd".into(),
                    convo_id: "c1".into(),
                    user_did: "did:x".into(),
                    requested_at: now.to_rfc3339(),
                },
            ),
            (
                "MembershipChangeEvent",
                StreamEvent::MembershipChangeEvent {
                    cursor: "c-member".into(),
                    convo_id: "c1".into(),
                    did: "did:x".into(),
                    action: "joined".into(),
                    actor: None,
                    reason: None,
                    epoch: 1,
                },
            ),
            (
                "ReadEvent",
                StreamEvent::ReadEvent {
                    cursor: "c-read".into(),
                    convo_id: "c1".into(),
                    did: "did:x".into(),
                    message_id: None,
                    read_at: now.to_rfc3339(),
                },
            ),
        ];

        for (name, event) in &variants {
            let cursor = extract_cursor(event);
            assert!(
                cursor.is_some(),
                "extract_cursor returned None for {}",
                name
            );
            assert!(
                cursor.as_ref().unwrap().starts_with("c-"),
                "Unexpected cursor for {}: {:?}",
                name,
                cursor
            );
        }
    }

    #[tokio::test]
    async fn test_refcount_tracking() {
        let key = UpstreamKey {
            sequencer_did: "did:web:seq.example".into(),
            convo_id: "convo-abc".into(),
        };

        let (tx, _) = broadcast::channel::<StreamEvent>(16);
        let refcount = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let last_cursor = Arc::new(RwLock::new(None));

        let conn = UpstreamConnection {
            tx,
            refcount: refcount.clone(),
            cancel,
            last_cursor,
        };

        let connections: Arc<RwLock<HashMap<UpstreamKey, UpstreamConnection>>> =
            Arc::new(RwLock::new(HashMap::new()));
        connections.write().await.insert(key.clone(), conn);

        // Simulate two subscribes
        {
            let conns = connections.read().await;
            conns
                .get(&key)
                .unwrap()
                .refcount
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(refcount.load(Ordering::Relaxed), 1);

        {
            let conns = connections.read().await;
            conns
                .get(&key)
                .unwrap()
                .refcount
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(refcount.load(Ordering::Relaxed), 2);

        // Simulate unsubscribe — decrement
        {
            let conns = connections.read().await;
            let prev = conns
                .get(&key)
                .unwrap()
                .refcount
                .fetch_sub(1, Ordering::Relaxed);
            assert_eq!(prev, 2);
        }
        assert_eq!(refcount.load(Ordering::Relaxed), 1);

        // Last unsubscribe — hits zero
        {
            let conns = connections.read().await;
            let prev = conns
                .get(&key)
                .unwrap()
                .refcount
                .fetch_sub(1, Ordering::Relaxed);
            assert_eq!(prev, 1);
        }
        assert_eq!(refcount.load(Ordering::Relaxed), 0);

        // At zero, the real unsubscribe would schedule cleanup via grace period
        let conns = connections.read().await;
        assert!(
            conns.contains_key(&key),
            "Entry still present before grace period"
        );
    }
}

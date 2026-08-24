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
use sqlx::PgPool;
use tokio::sync::{broadcast, RwLock};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::federation::errors::FederationError;
use crate::federation::resolver::DsResolver;
use crate::federation::service_auth::ServiceAuthClient;
use crate::identity::canonical_did;
use crate::realtime::sse::StreamEvent;
use crate::util::outbound_body::{
    decode_json_bounded, summarize_error_body, ResponseBodyBudget, ORDINARY_DS_CONTROL_MAX_BYTES,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TICKET_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TICKET_METHOD: &str = "blue.catbird.chat.getSubscriptionTicket";
const SUBSCRIBE_METHOD: &str = "blue.catbird.chat.subscribeEvents";
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
    pool: PgPool,
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
        pool: PgPool,
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
            pool,
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
        let canonical_sequencer = canonical_did(sequencer_did);
        super::peer_policy::enforce_outbound_peer_policy(&self.pool, canonical_sequencer).await?;

        let key = UpstreamKey {
            sequencer_did: canonical_sequencer.to_string(),
            convo_id: convo_id.to_string(),
        };

        // Fast path: connection already exists
        {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(&key) {
                conn.refcount.fetch_add(1, Ordering::Relaxed);
                debug!(
                    convo_id,
                    sequencer_did = canonical_sequencer, "Reusing existing upstream connection"
                );
                return Ok(conn.tx.subscribe());
            }
        }

        // Slow path: create new upstream connection
        let endpoint = self.resolver.resolve_ds_did(canonical_sequencer).await?;
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
            sequencer_did: canonical_sequencer.to_string(),
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
    acquire_ticket_with_timeout(ctx, TICKET_REQUEST_TIMEOUT).await
}

async fn acquire_ticket_with_timeout(
    ctx: &ReaderTaskContext,
    timeout: Duration,
) -> Result<String, FederationError> {
    let started_at = tokio::time::Instant::now();
    let deadline =
        started_at
            .checked_add(timeout)
            .ok_or_else(|| FederationError::DsUnreachable {
                endpoint: "remote DS".into(),
                reason: "Ticket request deadline could not be computed".into(),
            })?;

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

    let send = ctx
        .http
        .post(&url)
        .bearer_auth(&token)
        .header("atproto-proxy", &ctx.self_did)
        .json(&body)
        .send();
    let resp = tokio::time::timeout_at(deadline, send)
        .await
        .map_err(|_| FederationError::DsUnreachable {
            endpoint: "remote DS".into(),
            reason: "Ticket request deadline exceeded".into(),
        })?
        .map_err(|_| FederationError::DsUnreachable {
            endpoint: "remote DS".into(),
            reason: "Ticket request failed".into(),
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let summary = summarize_error_body(resp, deadline)
            .await
            .map(|summary| summary.to_string())
            .unwrap_or_else(|error| format!("error response metadata unavailable: {error}"));
        return Err(FederationError::RemoteError {
            status,
            body: summary,
        });
    }

    let ticket_resp: TicketResponse = decode_json_bounded(
        resp,
        ResponseBodyBudget::new(ORDINARY_DS_CONTROL_MAX_BYTES, deadline),
    )
    .await
    .map_err(|error| FederationError::RemoteError {
        status: 200,
        body: format!("Failed to parse ticket response: {error}"),
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
        StreamEvent::CleanTypingEvent { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Response, StatusCode},
        routing::post,
        Json, Router,
    };
    use bytes::Bytes;
    use futures::stream;
    use serde_json::json;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    async fn spawn_ticket_server(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
    }

    fn ticket_context(endpoint_url: String) -> ReaderTaskContext {
        let (tx, _) = broadcast::channel(1);
        ReaderTaskContext {
            key: UpstreamKey {
                sequencer_did: "did:web:sequencer.test".into(),
                convo_id: "convo-test".into(),
            },
            endpoint_url,
            sequencer_did: "did:web:sequencer.test".into(),
            convo_id: "convo-test".into(),
            auth: Arc::new(ServiceAuthClient::from_shared_secret(
                "did:web:local.test".into(),
                b"test-only-secret",
            )),
            http: reqwest::Client::new(),
            self_did: "did:web:local.test".into(),
            tx,
            cancel: CancellationToken::new(),
            last_cursor: Arc::new(RwLock::new(None)),
        }
    }

    #[tokio::test]
    async fn bounded_ticket_response_succeeds() {
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async { Json(json!({ "ticket": "bounded-ticket" })) }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let ticket = acquire_ticket_with_timeout(&context, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(ticket, "bounded-ticket");
    }

    #[tokio::test]
    async fn declared_ticket_body_over_one_mib_is_rejected() {
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(vec![b' '; ORDINARY_DS_CONTROL_MAX_BYTES + 1]))
                    .unwrap()
            }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let error = acquire_ticket_with_timeout(&context, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            FederationError::RemoteError { status: 200, ref body }
                if body.contains("exceeding limit 1048576")
        ));
    }

    #[tokio::test]
    async fn chunked_ticket_body_over_one_mib_is_rejected() {
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async {
                let chunks = vec![
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 700 * 1024])),
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 400 * 1024])),
                ];
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(stream::iter(chunks)))
                    .unwrap()
            }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let error = acquire_ticket_with_timeout(&context, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            FederationError::RemoteError { status: 200, ref body }
                if body.contains("exceeding limit 1048576")
        ));
    }

    #[tokio::test]
    async fn ticket_headers_and_body_share_one_deadline() {
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async {
                tokio::time::sleep(Duration::from_millis(45)).await;
                let chunks = stream::once(async {
                    tokio::time::sleep(Duration::from_millis(45)).await;
                    Ok::<_, Infallible>(Bytes::from_static(br#"{"ticket":"too-late"}"#))
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let error = acquire_ticket_with_timeout(&context, Duration::from_millis(70))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            FederationError::RemoteError { status: 200, ref body }
                if body.contains("deadline exceeded")
        ));
    }

    #[tokio::test]
    async fn non_success_preserves_status_without_body_content() {
        const CANARY: &str = "ticket=canary-secret bearer=canary-token cookie=canary-cookie";
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async {
                Response::builder()
                    .status(StatusCode::IM_A_TEAPOT)
                    .body(Body::from(CANARY))
                    .unwrap()
            }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let error = acquire_ticket_with_timeout(&context, Duration::from_secs(1))
            .await
            .unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(matches!(
            error,
            FederationError::RemoteError { status: 418, .. }
        ));
        assert!(!display.contains(CANARY));
        assert!(!debug.contains(CANARY));
        assert!(!display.contains("canary"));
        assert!(!debug.contains("canary"));
    }

    #[tokio::test]
    async fn malformed_bounded_ticket_keeps_remote_error_shape() {
        const CANARY: &str = "malformed-canary-ticket";
        let router = Router::new().route(
            &format!("/xrpc/{TICKET_METHOD}"),
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(CANARY))
                    .unwrap()
            }),
        );
        let context = ticket_context(spawn_ticket_server(router).await);

        let error = acquire_ticket_with_timeout(&context, Duration::from_secs(1))
            .await
            .unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(matches!(
            error,
            FederationError::RemoteError { status: 200, ref body }
                if body.starts_with("Failed to parse ticket response:")
        ));
        assert!(!display.contains(CANARY));
        assert!(!debug.contains(CANARY));
    }

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
    fn test_extract_cursor_clean_typing() {
        let event: StreamEvent = serde_json::from_value(serde_json::json!({
            "$type": "blue.catbird.chat.defs#typingEvent",
            "actorDeviceId": "device-a",
            "actorDid": "did:plc:actor",
            "conversationId": "convo-a",
            "expiresAt": "2026-08-16T12:00:08.000Z",
            "isTyping": true,
            "typingId": "typing-a"
        }))
        .unwrap();
        assert_eq!(extract_cursor(&event), None);
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

    #[tokio::test]
    async fn test_upstream_subscribe_denies_untrusted_peer_before_resolution() {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => {
                eprintln!("Skipping upstream peer policy test: TEST_DATABASE_URL not set");
                return;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db must succeed when TEST_DATABASE_URL is set");
        let http_client = reqwest::Client::new();
        let resolver = Arc::new(DsResolver::new(
            pool.clone(),
            http_client,
            "did:web:local.test".to_string(),
            "https://local.test".to_string(),
            None,
            300,
        ));
        let auth = Arc::new(ServiceAuthClient::from_shared_secret(
            "did:web:local.test".into(),
            b"test-secret",
        ));
        let manager = UpstreamManager::new(
            pool,
            resolver,
            auth,
            "did:web:local.test".to_string(),
            "https://local.test".to_string(),
            CancellationToken::new(),
            100,
        );

        // Subscribing to an unallowlisted peer must fail with AuthFailed before resolution or network
        let result = manager
            .subscribe("convo-1", "did:web:unknown-peer.example.com", None)
            .await;
        assert!(result.is_err(), "subscribe must fail for unallowlisted peer");
        match result.unwrap_err() {
            FederationError::AuthFailed { reason } => {
                assert!(
                    reason.contains("not allowlisted") || reason.contains("Peer DS"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }
}

//! Production-router contract tests for the clean-chat conversation reads.
//!
//! These are deliberately database-free: a cutover-open request with no DPoP
//! headers must reach the real admission dispatcher, while a cutover-closed
//! request must stop before the pool or verifier is touched.

use std::sync::{Arc, Mutex, Once};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use catbird_server::{
    blob_store::BlobStore,
    handlers::chat::{chat_router, ChatRuntime},
    realtime::SseState,
    storage::DbPool,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use tower_util::ServiceExt;

#[derive(Clone)]
struct TestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    blob_store: BlobStore,
}

impl FromRef<TestState> for DbPool {
    fn from_ref(state: &TestState) -> Self {
        state.pool.clone()
    }
}

impl FromRef<TestState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<TestState> for BlobStore {
    fn from_ref(state: &TestState) -> Self {
        state.blob_store.clone()
    }
}

fn runtime(cutover_enabled: bool) -> Arc<ChatRuntime> {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "conversation-reads");
        std::env::set_var(
            "CHAT_NEST_VERIFYING_KEY",
            STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        );
        std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
        std::env::set_var("CHAT_CURSOR_KEY_ID", URL_SAFE_NO_PAD.encode([0x11_u8; 32]));
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0x22_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
    let _guard = LOCK.lock().expect("runtime env lock");
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).expect("clean-chat runtime"))
}

fn router(cutover_enabled: bool) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/conversation_reads_must_not_connect")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: runtime(cutover_enabled),
        blob_store: BlobStore::for_route_tests(),
    })
}

async fn send(router: Router, uri: &str) -> (StatusCode, Value) {
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn conversation_read_routes_are_cutover_gated() {
    for endpoint in ["getConversations", "getConversationState"] {
        let (status, body) = send(
            router(false),
            &format!("/xrpc/blue.catbird.chat.{endpoint}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{endpoint}");
        assert_eq!(body["error"], "CutoverRequired", "{endpoint}");
    }
}

#[tokio::test]
async fn conversation_read_routes_dispatch_real_dpop_admission() {
    let (status, body) = send(
        router(true),
        "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId=018f3f6a-7b2c-4d91-8a5e-0f123456789b&conversationId=018f3f6a-7b2c-4d91-8a5e-0f123456789a",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

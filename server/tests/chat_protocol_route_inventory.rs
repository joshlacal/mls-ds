//! Database-free route inventory for the frozen `blue.catbird.chat.*` surface.
//!
//! This target is intentionally an integration test: the library is compiled
//! without `cfg(test)`, so the routes that are already backed by production
//! compositors exercise those handlers rather than the unit-test-only stub
//! branch in `handlers/chat/mod.rs`.

use std::sync::{Arc, Mutex, Once};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_server::{
    chat_protocol::error::ChatEndpoint,
    handlers::chat::{chat_router, ChatRuntime},
    storage::DbPool,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use tower_util::ServiceExt;

#[derive(Clone)]
struct TestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
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

fn runtime() -> Arc<ChatRuntime> {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "route-inventory");
        std::env::set_var(
            "CHAT_NEST_VERIFYING_KEY",
            STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        );
        std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
    });
    let _guard = LOCK.lock().expect("runtime env lock");
    std::env::remove_var("CHAT_CUTOVER_ENABLED");
    Arc::new(ChatRuntime::from_env().expect("clean-chat runtime"))
}

fn router() -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/clean_chat_route_inventory")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: runtime(),
    })
}

fn live_router() -> Router {
    let _ = runtime();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/clean_chat_route_inventory")
        .expect("lazy pool");
    std::env::set_var("CHAT_CUTOVER_ENABLED", "true");
    let runtime = Arc::new(ChatRuntime::from_env().expect("live clean-chat runtime"));
    std::env::remove_var("CHAT_CUTOVER_ENABLED");
    chat_router::<TestState>().with_state(TestState { pool, runtime })
}

fn is_get(endpoint: ChatEndpoint) -> bool {
    matches!(
        endpoint,
        ChatEndpoint::GetBlob
            | ChatEndpoint::GetBlobUsage
            | ChatEndpoint::GetConversationState
            | ChatEndpoint::GetConversations
            | ChatEndpoint::GetDevices
            | ChatEndpoint::GetEntries
            | ChatEndpoint::GetLeafRecoveryInbox
            | ChatEndpoint::GetOwnDevices
            | ChatEndpoint::GetPendingWelcomes
            | ChatEndpoint::SubscribeEvents
    )
}

#[tokio::test]
async fn every_clean_endpoint_is_registered_and_cutover_gated() {
    for endpoint in ChatEndpoint::ALL {
        let method = if is_get(*endpoint) { "GET" } else { "POST" };
        let request = Request::builder()
            .method(method)
            .uri(format!("/xrpc/{}", endpoint.nsid()))
            .body(Body::empty())
            .expect("request");
        let response = router().oneshot(request).await.expect("route response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{} must be reachable with its declared method",
            endpoint.nsid()
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body: Value = serde_json::from_slice(&bytes).expect("XRPC error body");
        assert_eq!(body["error"], "CutoverRequired", "{}", endpoint.nsid());
    }
}

#[tokio::test]
async fn clean_endpoint_method_mismatch_is_not_silently_accepted() {
    for endpoint in ChatEndpoint::ALL {
        let method = if is_get(*endpoint) { "POST" } else { "GET" };
        let request = Request::builder()
            .method(method)
            .uri(format!("/xrpc/{}", endpoint.nsid()))
            .body(Body::empty())
            .expect("request");
        let response = router().oneshot(request).await.expect("route response");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{} must reject the opposite HTTP method",
            endpoint.nsid()
        );
    }
}

#[tokio::test]
async fn leave_routes_reach_production_authentication_before_database_work() {
    let request = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.chat.requestLeave")
        .body(Body::empty())
        .expect("request");
    let response = live_router()
        .oneshot(request)
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&bytes).expect("XRPC error body");
    assert_eq!(body["error"], "InvalidDPoP");
}

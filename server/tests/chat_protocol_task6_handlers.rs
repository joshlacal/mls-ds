//! Stateless production-router proofs for the Task 6 clean-chat compositors.
//!
//! These tests intentionally use a lazy pool and never touch PostgreSQL. They
//! exercise the production library configuration, avoiding the repository
//! modules that are deliberately absent from the library's `cfg(test)` graph.

use std::sync::{Arc, Mutex, Once};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_server::{
    handlers::chat::{chat_router, ChatRuntime},
    storage::DbPool,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use tower_util::ServiceExt;

const TASK6_ENDPOINTS: &[&str] = &[
    "requestReset",
    "activateReset",
    "revokeDevice",
    "acknowledgeWelcome",
    "rejectWelcome",
    "requestLeafRecovery",
    "cancelLeafRecovery",
    "submitTransition",
];

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

fn runtime(cutover_enabled: bool) -> Arc<ChatRuntime> {
    static ENV: Once = Once::new();
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    ENV.call_once(|| {
        let signing_key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "nest-key-1");
        std::env::set_var("CHAT_NEST_VERIFYING_KEY", STANDARD.encode(point.as_bytes()));
        std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
    });
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    Arc::new(ChatRuntime::from_env().expect("build clean-chat runtime"))
}

fn router(cutover_enabled: bool) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/task6_router_must_not_connect")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: runtime(cutover_enabled),
    })
}

fn post(path: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap()
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn task6_routes_are_post_only_and_fail_closed_before_cutover() {
    for endpoint in TASK6_ENDPOINTS {
        let clean_path = format!("/xrpc/blue.catbird.chat.{endpoint}");
        let (status, body) = send(router(false), post(&clean_path)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{clean_path}");
        assert_eq!(body["error"], "CutoverRequired", "{clean_path}");

        let legacy_path = format!("/xrpc/blue.catbird.mlsChat.{endpoint}");
        let (status, _) = send(router(false), post(&legacy_path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{legacy_path}");

        let request = Request::builder()
            .method("GET")
            .uri(&clean_path)
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(router(false), request).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{clean_path}");
    }
}

#[tokio::test]
async fn implemented_task6_routes_reach_admission_when_cutover_is_open() {
    for endpoint in TASK6_ENDPOINTS {
        let path = format!("/xrpc/blue.catbird.chat.{endpoint}");
        let (status, body) = send(router(true), post(&path)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} is still stubbed");
        assert_eq!(body["error"], "InvalidDPoP", "{path} is still stubbed");
    }
}

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
    blob_store: catbird_server::blob_store::BlobStore,
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

impl FromRef<TestState> for catbird_server::blob_store::BlobStore {
    fn from_ref(state: &TestState) -> Self {
        state.blob_store.clone()
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
        std::env::set_var(
            "CHAT_CURSOR_KEY_ID",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11_u8; 32]),
        );
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    if cutover_enabled {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("build clean-chat runtime"),
    )
}

/// A pool that is never connected. Any real database access through it fails,
/// which is what makes "the gated worker never touched the pool" observable.
fn lazy_pool() -> DbPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/task6_router_must_not_connect")
        .expect("lazy pool")
}

fn router(cutover_enabled: bool) -> Router {
    chat_router::<TestState>().with_state(TestState {
        pool: lazy_pool(),
        runtime: runtime(cutover_enabled),
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
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

// ===========================================================================
// Clean-chat expiry sweeper — cutover gate.
//
// The whole `blue.catbird.chat.*` surface must stay inert while
// `CHAT_CUTOVER_ENABLED` is off; that property is the entire basis for shipping
// this code dark, and a background worker is the one thing in the tree that
// could touch `chat.*` with no request to gate it. `main.rs` refuses to spawn
// the sweeper at all when the flag is off, and the worker re-checks the flag
// before building its timer or borrowing the pool. These tests pin the second
// gate directly, using the same never-connectable lazy pool the router tests
// use: if the gated worker touched the pool at all it would have to connect.
// ===========================================================================
mod expiry_sweeper_cutover_gate {
    use super::{lazy_pool, runtime};
    use catbird_server::handlers::chat::{run_chat_expiry_sweeper, ChatExpirySweepConfig};
    use std::time::Duration;

    /// Cutover OFF: the sweeper returns immediately instead of entering its
    /// loop, so no timer is created and the (never-connectable) pool is never
    /// used.
    #[tokio::test]
    async fn sweeper_returns_immediately_when_cutover_is_off() {
        let finished = tokio::time::timeout(
            Duration::from_secs(5),
            run_chat_expiry_sweeper(lazy_pool(), runtime(false)),
        )
        .await;
        assert!(
            finished.is_ok(),
            "a cutover-off sweeper must return without entering its loop"
        );
    }

    /// Cutover ON: the same call does NOT return — it enters the sweep loop.
    /// This is the paired negative that proves the previous test is measuring
    /// the gate and not merely a worker that always exits.
    #[tokio::test]
    async fn sweeper_enters_its_loop_when_cutover_is_on() {
        let finished = tokio::time::timeout(
            Duration::from_millis(750),
            run_chat_expiry_sweeper(lazy_pool(), runtime(true)),
        )
        .await;
        assert!(
            finished.is_err(),
            "a cutover-on sweeper must keep sweeping rather than return"
        );
    }

    /// The cadence is read from the environment with documented defaults; a
    /// missing, unparseable, or non-positive value can never produce a zero
    /// interval (which `tokio::time::interval` would panic on) or an empty
    /// batch.
    #[test]
    fn sweep_config_defaults_are_positive_and_env_overridable() {
        let defaults = ChatExpirySweepConfig::default();
        assert_eq!(defaults.interval_secs, 60);
        assert_eq!(defaults.batch, 128);

        for (interval, batch) in [("0", "0"), ("not-a-number", "-4"), ("", " ")] {
            std::env::set_var("CHAT_EXPIRY_SWEEP_INTERVAL_SECS", interval);
            std::env::set_var("CHAT_EXPIRY_SWEEP_BATCH", batch);
            assert_eq!(
                ChatExpirySweepConfig::from_env(),
                defaults,
                "a rejected value ({interval:?}, {batch:?}) falls back to the default"
            );
        }

        std::env::set_var("CHAT_EXPIRY_SWEEP_INTERVAL_SECS", "15");
        std::env::set_var("CHAT_EXPIRY_SWEEP_BATCH", "7");
        assert_eq!(
            ChatExpirySweepConfig::from_env(),
            ChatExpirySweepConfig {
                interval_secs: 15,
                batch: 7
            }
        );
        std::env::remove_var("CHAT_EXPIRY_SWEEP_INTERVAL_SECS");
        std::env::remove_var("CHAT_EXPIRY_SWEEP_BATCH");
    }
}

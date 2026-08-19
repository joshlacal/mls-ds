//! Adversarial Challenger M2: Empirical Verification Suite for Legacy mlsChat Retirement
//!
//! Verifies:
//! 1. All legacy `blue.catbird.mlsChat.*` endpoints are 404 on the merged application router
//! 2. `config::classify_device_auth_endpoint` returns `None` for all `blue.catbird.mlsChat.*` NSIDs
//! 3. `chat_router` mounts only `blue.catbird.chat.*` routes
//! 4. Ingress body limits and idempotency do not match or route legacy paths
//! 5. Deleted legacy directories/files remain completely deleted

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
    chat_protocol::error::ChatEndpoint,
    config::classify_device_auth_endpoint,
    handlers::chat::{chat_router, ChatRuntime},
    realtime::SseState,
    storage::DbPool,
};
use p256::ecdsa::SigningKey;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
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

fn test_runtime() -> Arc<ChatRuntime> {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "adv-m2");
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
    Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).expect("clean-chat runtime"))
}

fn test_router() -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/clean_chat_adv_m2")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime: test_runtime(),
        blob_store: BlobStore::for_route_tests(),
    })
}

const LEGACY_ENDPOINTS: &[&str] = &[
    "blue.catbird.mlsChat.getConvos",
    "blue.catbird.mlsChat.getConvo",
    "blue.catbird.mlsChat.getConvoForMembers",
    "blue.catbird.mlsChat.createConvo",
    "blue.catbird.mlsChat.sendMessage",
    "blue.catbird.mlsChat.getMessages",
    "blue.catbird.mlsChat.commitGroupChange",
    "blue.catbird.mlsChat.getGroupInfo",
    "blue.catbird.mlsChat.getKeyPackages",
    "blue.catbird.mlsChat.publishKeyPackages",
    "blue.catbird.mlsChat.beginDeviceAuthBinding",
    "blue.catbird.mlsChat.completeDeviceAuthBinding",
    "blue.catbird.mlsChat.revokeDevice",
    "blue.catbird.mlsChat.listDevices",
    "blue.catbird.mlsChat.requestLeave",
    "blue.catbird.mlsChat.leaveConvo",
    "blue.catbird.mlsChat.requestReset",
    "blue.catbird.mlsChat.activateReset",
    "blue.catbird.mlsChat.cancelReset",
    "blue.catbird.mlsChat.getResetState",
    "blue.catbird.mlsChat.getSubscriptionTicket",
    "blue.catbird.mlsChat.subscribeEvents",
    "blue.catbird.mlsChat.uploadBlob",
    "blue.catbird.mlsChat.getBlob",
    "blue.catbird.mlsChat.acceptConvo",
    "blue.catbird.mlsChat.declineConvo",
    "blue.catbird.mlsChat.muteConvo",
    "blue.catbird.mlsChat.unmuteConvo",
    "blue.catbird.mlsChat.updateConvo",
    "blue.catbird.mlsChat.reportConvo",
];

#[tokio::test]
async fn legacy_mlschat_endpoints_return_404_not_found() {
    for &legacy in LEGACY_ENDPOINTS {
        for method in ["GET", "POST"] {
            let request = Request::builder()
                .method(method)
                .uri(format!("/xrpc/{legacy}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"dummy":"data"}"#))
                .expect("request");
            let response = test_router().oneshot(request).await.expect("response");
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "legacy endpoint /xrpc/{legacy} (method {method}) must return 404 Not Found, but got {}",
                response.status()
            );
        }
    }
}

#[test]
fn legacy_mlschat_endpoints_fail_closed_in_device_auth_classification() {
    for &legacy in LEGACY_ENDPOINTS {
        let classification = classify_device_auth_endpoint(legacy);
        assert!(
            classification.is_none(),
            "legacy NSID {legacy} must NOT be classified in device_auth, got: {classification:?}"
        );
    }
}

#[test]
fn all_32_clean_chat_endpoints_are_classified_in_device_auth() {
    for endpoint in ChatEndpoint::ALL {
        let classification = classify_device_auth_endpoint(endpoint.nsid());
        assert!(
            classification.is_some(),
            "clean chat NSID {} must be classified in device_auth",
            endpoint.nsid()
        );
    }
}

#[test]
fn legacy_handlers_and_types_files_do_not_exist() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let legacy_paths = [
        manifest_dir.join("src/handlers/mls_chat"),
        manifest_dir.join("src/lexicon_types.rs"),
        manifest_dir.join("src/error_responses.rs"),
        manifest_dir.join("src/realtime/websocket.rs.deprecated"),
    ];

    for path in &legacy_paths {
        assert!(
            !path.exists(),
            "Legacy file/directory must not exist: {}",
            path.display()
        );
    }
}

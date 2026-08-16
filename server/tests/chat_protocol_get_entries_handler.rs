//! Production-library reachability checks for the clean `getEntries` handler.

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

fn router() -> Router {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().expect("runtime env lock");
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "get-entries-handler");
        std::env::set_var(
            "CHAT_NEST_VERIFYING_KEY",
            STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        );
        std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
    });
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let runtime = Arc::new(ChatRuntime::from_env().expect("clean-chat runtime"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/clean_chat_get_entries")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState { pool, runtime })
}

#[tokio::test]
async fn get_entries_uses_real_auth_admission() {
    let request = Request::builder()
        .uri("/xrpc/blue.catbird.chat.getEntries?conversationId=018f3f6a-7b2c-4d91-8a5e-0f123456789a&afterSeq=0&limit=10")
        .body(Body::empty())
        .expect("request");
    let response = router().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&bytes).expect("XRPC error body");
    assert_eq!(body["error"], "InvalidDPoP");
}

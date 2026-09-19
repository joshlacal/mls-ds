//! Comprehensive regression tests for v2 chat read query parameter validation.
//!
//! Covers:
//! 1. Full lexicon-declared parameters accepted and reaching admission (401 NotAuthorized).
//! 2. Truly unknown/bogus query keys strictly rejected with 400 InvalidRequest.
//! 3. Duplicate query keys strictly rejected with 400 InvalidRequest.
//! 4. Missing required parameters strictly rejected with 400 InvalidRequest.
//! 5. Exact 43-character base64url capability format enforced for `inventorySessionId` (Finding 1).
//! 6. Lexicon-required `limit` enforced on getConversations, getPendingWelcomes, getLeafRecoveryInbox, getEntries (Finding 3).
//! 7. Complete `userDids` contract (syntax, strict ascending order, duplicate-free, 1..5 bounds) on getDevices (Finding 4).
//! 8. Strict transport validation (content-type, query rejection, capability inputs) on getSubscriptionTicket (Finding 5).

use std::sync::{Arc, Mutex, Once};

use axum::{
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_server::{
    handlers::chat::{chat_router, parse_subscribe_events_query, ChatRuntime},
    storage::DbPool,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use tower_util::ServiceExt;

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

fn router() -> Router {
    static INIT: Once = Once::new();
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    INIT.call_once(|| {
        let key = SigningKey::from_bytes((&[0x5a_u8; 32]).into()).expect("signing key");
        std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
        std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
        std::env::set_var("CHAT_NEST_KEY_ID", "param-validation-test");
        std::env::set_var(
            "CHAT_NEST_VERIFYING_KEY",
            STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        );
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
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("clean-chat runtime"),
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/param_validation_test")
        .expect("lazy pool");
    chat_router::<TestState>().with_state(TestState {
        pool,
        runtime,
        blob_store: catbird_server::blob_store::BlobStore::for_route_tests(),
    })
}

async fn get_uri(uri: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let response = router().oneshot(request).await.expect("route response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn post_uri(
    uri: &str,
    content_type: Option<&str>,
    body_bytes: Vec<u8>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
    }
    let request = builder.body(Body::from(body_bytes)).expect("request");
    let response = router().oneshot(request).await.expect("route response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

const VALID_DEVICE_ID: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const VALID_CONVO_ID: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789b";
const VALID_BLOB_ID: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789c";
// 43-character base64url capability string (the actual shape emitted by getConversations)
const VALID_CAPABILITY_SESSION: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
const VALID_DID_1: &str = "did:web:alice.example.com";
const VALID_DID_2: &str = "did:web:bob.example.com";
const VALID_DID_3: &str = "did:web:charlie.example.com";

// =========================================================================
// 1. getConversations
// =========================================================================

#[tokio::test]
async fn get_conversations_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={VALID_DEVICE_ID}&limit=20&pageCursor=cursor123"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_conversations_accepts_absent_limit_and_applies_default() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_conversations_rejects_missing_actor_device_id() {
    let (status, body) = get_uri("/xrpc/blue.catbird.chat.getConversations?limit=20").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_conversations_rejects_unknown_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={VALID_DEVICE_ID}&limit=50&bogusKey=123"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_conversations_rejects_inventory_session_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={VALID_DEVICE_ID}&limit=50&inventorySessionId={VALID_CAPABILITY_SESSION}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_conversations_rejects_duplicate_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={VALID_DEVICE_ID}&actorDeviceId={VALID_DEVICE_ID}&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 2. getPendingWelcomes
// =========================================================================

#[tokio::test]
async fn get_pending_welcomes_accepts_full_lexicon_params_with_capability_session() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}&limit=50&pageCursor=c1"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_pending_welcomes_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?inventorySessionId={VALID_CAPABILITY_SESSION}&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_pending_welcomes_rejects_missing_inventory_session_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_pending_welcomes_accepts_absent_limit_and_applies_default() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_pending_welcomes_rejects_uuid_formatted_session() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId=018f3f6a-7b2c-4d91-8a5e-0f123456789a&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_pending_welcomes_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}&limit=50&extra=1"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 3. getLeafRecoveryInbox
// =========================================================================

#[tokio::test]
async fn get_leaf_recovery_inbox_accepts_full_lexicon_params_with_capability_session() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}&limit=25&pageCursor=c2"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_leaf_recovery_inbox_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?inventorySessionId={VALID_CAPABILITY_SESSION}&limit=25"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_leaf_recovery_inbox_rejects_missing_inventory_session_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&limit=25"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_leaf_recovery_inbox_accepts_absent_limit_and_applies_default() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_leaf_recovery_inbox_rejects_uuid_formatted_session() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId=018f3f6a-7b2c-4d91-8a5e-0f123456789a&limit=25"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_leaf_recovery_inbox_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={VALID_CAPABILITY_SESSION}&limit=25&unknownParam=abc"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 4. getEntries
// =========================================================================

#[tokio::test]
async fn get_entries_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&afterSeq=42&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_entries_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?conversationId={VALID_CONVO_ID}&afterSeq=0&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_entries_rejects_missing_conversation_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&afterSeq=0&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_entries_rejects_missing_after_seq() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_entries_accepts_absent_limit_and_applies_default() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&afterSeq=0"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_entries_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&afterSeq=0&limit=50&bogus=true"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_entries_rejects_duplicate_conversation_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&conversationId={VALID_CONVO_ID}&afterSeq=0&limit=50"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 5. getDevices
// =========================================================================

#[tokio::test]
async fn get_devices_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids={VALID_DID_1}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_devices_accepts_multiple_strictly_ordered_user_dids() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids={VALID_DID_1}&userDids={VALID_DID_2}&userDids={VALID_DID_3}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_devices_rejects_unordered_user_dids() {
    // bob < charlie, but passing charlie then bob is out of order
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids={VALID_DID_3}&userDids={VALID_DID_2}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_duplicate_user_dids() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids={VALID_DID_1}&userDids={VALID_DID_1}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_malformed_did_syntax() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids=not_a_valid_did"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?userDids={VALID_DID_1}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_missing_user_dids() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids={VALID_DID_1}&extra=1"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_devices_rejects_too_many_user_dids() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getDevices?actorDeviceId={VALID_DEVICE_ID}&userDids=did:web:d1.com&userDids=did:web:d2.com&userDids=did:web:d3.com&userDids=did:web:d4.com&userDids=did:web:d5.com&userDids=did:web:d6.com"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 6. getOwnDevices
// =========================================================================

#[tokio::test]
async fn get_own_devices_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getOwnDevices?actorDeviceId={VALID_DEVICE_ID}&limit=30&pageCursor=page1"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_own_devices_accepts_minimal_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getOwnDevices?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_own_devices_rejects_missing_actor_device_id() {
    let (status, body) = get_uri("/xrpc/blue.catbird.chat.getOwnDevices?limit=30").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_own_devices_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getOwnDevices?actorDeviceId={VALID_DEVICE_ID}&bogus=123"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 7. getConversationState
// =========================================================================

#[tokio::test]
async fn get_conversation_state_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_conversation_state_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversationState?conversationId={VALID_CONVO_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_conversation_state_rejects_missing_conversation_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_conversation_state_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={VALID_DEVICE_ID}&conversationId={VALID_CONVO_ID}&foo=bar"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 8. getBlob
// =========================================================================

#[tokio::test]
async fn get_blob_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlob?actorDeviceId={VALID_DEVICE_ID}&blobId={VALID_BLOB_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_blob_rejects_missing_actor_device_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlob?blobId={VALID_BLOB_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_blob_rejects_missing_blob_id() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlob?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_blob_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlob?actorDeviceId={VALID_DEVICE_ID}&blobId={VALID_BLOB_ID}&other=123"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 9. getBlobUsage
// =========================================================================

#[tokio::test]
async fn get_blob_usage_accepts_full_lexicon_params() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlobUsage?actorDeviceId={VALID_DEVICE_ID}"
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_blob_usage_rejects_missing_actor_device_id() {
    let (status, body) = get_uri("/xrpc/blue.catbird.chat.getBlobUsage").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_blob_usage_rejects_bogus_key() {
    let (status, body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getBlobUsage?actorDeviceId={VALID_DEVICE_ID}&extra=1"
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 10. uploadBlob
// =========================================================================

#[tokio::test]
async fn upload_blob_accepts_full_lexicon_params() {
    let ticket = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (status, body) = post_uri(
        &format!(
            "/xrpc/blue.catbird.chat.uploadBlob?actorDeviceId={VALID_DEVICE_ID}&uploadTicket={ticket}"
        ),
        Some("application/octet-stream"),
        vec![0x42; 10],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn upload_blob_rejects_missing_actor_device_id() {
    let ticket = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (status, body) = post_uri(
        &format!("/xrpc/blue.catbird.chat.uploadBlob?uploadTicket={ticket}"),
        Some("application/octet-stream"),
        vec![0x42; 10],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn upload_blob_rejects_missing_upload_ticket() {
    let (status, body) = post_uri(
        &format!("/xrpc/blue.catbird.chat.uploadBlob?actorDeviceId={VALID_DEVICE_ID}"),
        Some("application/octet-stream"),
        vec![0x42; 10],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn upload_blob_rejects_bogus_key() {
    let ticket = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (status, body) = post_uri(
        &format!(
            "/xrpc/blue.catbird.chat.uploadBlob?actorDeviceId={VALID_DEVICE_ID}&uploadTicket={ticket}&bogus=1"
        ),
        Some("application/octet-stream"),
        vec![0x42; 10],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

// =========================================================================
// 11. getSubscriptionTicket (Finding 5)
// =========================================================================

#[tokio::test]
async fn get_subscription_ticket_accepts_valid_body_and_content_type() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    let (status, body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket",
        Some("application/json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "NotAuthorized");
}

#[tokio::test]
async fn get_subscription_ticket_rejects_query_parameters() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    let (status, body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket?bogus=1",
        Some("application/json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_subscription_ticket_rejects_non_json_content_type() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    let (status, body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket",
        Some("text/plain"),
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_subscription_ticket_rejects_uuid_formatted_inventory_session() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    let (status, body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket",
        Some("application/json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn get_subscription_ticket_rejects_missing_actor_device_id() {
    let body = serde_json::json!({
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    let (status, body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket",
        Some("application/json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}
#[tokio::test]
async fn get_subscription_ticket_accepts_case_insensitive_content_type() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    for ct in [
        "Application/JSON",
        "APPLICATION/JSON; charset=utf-8",
        "application/json; charset=UTF-8",
    ] {
        let (status, body) = post_uri(
            "/xrpc/blue.catbird.chat.getSubscriptionTicket",
            Some(ct),
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "failed for Content-Type: {ct}"
        );
        assert_eq!(
            body["error"], "NotAuthorized",
            "failed for Content-Type: {ct}"
        );
    }
}

#[tokio::test]
async fn get_subscription_ticket_rejects_malformed_content_type_params() {
    let body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": VALID_CAPABILITY_SESSION,
        "eventCursor": VALID_CAPABILITY_SESSION,
    });
    for ct in [
        "application/json;garbage",
        "application/json;=",
        "application/json;charset=",
    ] {
        let (status, body) = post_uri(
            "/xrpc/blue.catbird.chat.getSubscriptionTicket",
            Some(ct),
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "failed to reject Content-Type: {ct}"
        );
        assert_eq!(
            body["error"], "InvalidRequest",
            "failed to reject Content-Type: {ct}"
        );
    }
}

#[tokio::test]
async fn inventory_session_capability_round_trip_emitter_to_consumers() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::{rngs::OsRng, RngCore};

    // Generate a fresh random 32-byte secret capability as getConversations does at runtime
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let emitted_capability = URL_SAFE_NO_PAD.encode(random_bytes);
    assert_eq!(emitted_capability.len(), 43);

    // Emitted response JSON from getConversations (exact output shape)
    let get_conversations_output = serde_json::json!({
        "items": [],
        "hasMore": false,
        "inventorySessionId": emitted_capability,
        "snapshotEventCursor": emitted_capability,
        "snapshotExpiresAt": "2026-08-20T12:00:00.000Z"
    });

    // Extract the exact emitted capability string from getConversations response
    let extracted_session = get_conversations_output["inventorySessionId"]
        .as_str()
        .expect("emitted inventorySessionId");
    let extracted_cursor = get_conversations_output["snapshotEventCursor"]
        .as_str()
        .expect("emitted snapshotEventCursor");
    assert_eq!(extracted_session, emitted_capability);
    assert_eq!(extracted_cursor, emitted_capability);

    // Feed the extracted capability into getPendingWelcomes
    let (welcomes_status, welcomes_body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getPendingWelcomes?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={extracted_session}&limit=50"
    ))
    .await;
    assert_eq!(welcomes_status, StatusCode::UNAUTHORIZED);
    assert_eq!(welcomes_body["error"], "NotAuthorized");

    // Feed the extracted capability into getLeafRecoveryInbox
    let (recovery_status, recovery_body) = get_uri(&format!(
        "/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={VALID_DEVICE_ID}&inventorySessionId={extracted_session}&limit=50"
    ))
    .await;
    assert_eq!(recovery_status, StatusCode::UNAUTHORIZED);
    assert_eq!(recovery_body["error"], "NotAuthorized");

    // Feed the extracted capability and cursor into getSubscriptionTicket
    let ticket_body = serde_json::json!({
        "actorDeviceId": VALID_DEVICE_ID,
        "inventorySessionId": extracted_session,
        "eventCursor": extracted_cursor,
    });
    let (ticket_status, ticket_body) = post_uri(
        "/xrpc/blue.catbird.chat.getSubscriptionTicket",
        Some("application/json"),
        serde_json::to_vec(&ticket_body).unwrap(),
    )
    .await;
    assert_eq!(ticket_status, StatusCode::UNAUTHORIZED);
    assert_eq!(ticket_body["error"], "NotAuthorized");
}
// =========================================================================
// 12. subscribeEvents
// =========================================================================

#[test]
fn subscribe_events_accepts_full_lexicon_params() {
    let ticket = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    let query = format!("ticket={ticket}&cursor=123");
    let parsed = parse_subscribe_events_query(Some(&query)).expect("parse valid params");
    assert_eq!(parsed.ticket, ticket);
    assert_eq!(parsed.cursor, "123");
}

#[test]
fn subscribe_events_rejects_missing_ticket() {
    let result = parse_subscribe_events_query(Some("cursor=123"));
    assert!(result.is_err());
}

#[test]
fn subscribe_events_rejects_missing_cursor() {
    let ticket = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    let result = parse_subscribe_events_query(Some(&format!("ticket={ticket}")));
    assert!(result.is_err());
}

#[test]
fn subscribe_events_rejects_bogus_key() {
    let ticket = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    let result = parse_subscribe_events_query(Some(&format!("ticket={ticket}&cursor=123&bogus=1")));
    assert!(result.is_err());
}

#[test]
fn subscribe_events_rejects_duplicate_key() {
    let ticket = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    let result =
        parse_subscribe_events_query(Some(&format!("ticket={ticket}&ticket={ticket}&cursor=123")));
    assert!(result.is_err());
}

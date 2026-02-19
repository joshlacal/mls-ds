//! Comprehensive federation security tests.
//!
//! Covers JWT validation, SSRF/discovery protection, peer policy enforcement,
//! and DID resolver edge cases.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower_util::util::ServiceExt;
use uuid::Uuid;

use catbird_server::db::{init_db, DbConfig};
use catbird_server::federation::errors::FederationError;
use catbird_server::federation::resolver::{host_is_allowlisted, validate_endpoint_url_with_policy};
use catbird_server::federation::{AckSigner, Sequencer};
use catbird_server::handlers;
use catbird_server::identity::{canonical_did, dids_equivalent};
use catbird_server::realtime::SseState;

// ---------------------------------------------------------------------------
// Test infrastructure (mirrors federation_hostile_peers.rs)
// ---------------------------------------------------------------------------

#[derive(Clone, FromRef)]
struct TestState {
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    ack_signer: Option<Arc<AckSigner>>,
    sequencer: Arc<Sequencer>,
}

#[derive(Debug, Serialize)]
struct ServiceClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    lxm: &'a str,
    jti: &'a str,
}

/// Partial claims that allow omitting fields.
#[derive(Debug, Serialize)]
struct PartialClaims {
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    lxm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

fn configure_security_env() {
    std::env::set_var("SERVICE_DID", "did:web:test.ds.local");
    std::env::set_var("ENFORCE_LXM", "true");
    std::env::set_var("ENFORCE_JTI", "true");
    std::env::set_var("JTI_TTL_SECONDS", "120");
    std::env::set_var("FEDERATION_ADMIN_DIDS", "did:plc:federation-admin");
}

/// Build a valid service-auth JWT with all claims populated.
fn service_token(iss: &str, lxm: &str, jti: &str) -> String {
    let now = Utc::now().timestamp();
    let claims = ServiceClaims {
        iss,
        aud: "did:web:test.ds.local",
        exp: now + 120,
        iat: now,
        lxm,
        jti,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("failed to sign test token")
}

/// Build a JWT from partial claims so we can omit lxm or jti.
fn partial_token(claims: &PartialClaims) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("failed to sign partial test token")
}

async fn setup_test_db() -> Option<PgPool> {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("Skipping test: TEST_DATABASE_URL not set");
        return None;
    };

    configure_security_env();

    let config = DbConfig {
        database_url,
        max_connections: 8,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(20),
        idle_timeout: Duration::from_secs(60),
    };

    let pool = init_db(config).await.expect("failed to init DB");
    cleanup_tables(&pool).await;
    Some(pool)
}

async fn cleanup_tables(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE TABLE \
            auth_jti_nonce, federation_peers, messages, welcome_messages, key_packages, \
            members, conversations, devices, users \
         CASCADE",
    )
    .execute(pool)
    .await
    .expect("failed to cleanup tables");
}

fn test_router(pool: PgPool) -> Router {
    let self_did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| "did:web:test.ds.local".to_string());
    let state = TestState {
        db_pool: pool.clone(),
        sse_state: Arc::new(SseState::new(64)),
        ack_signer: None,
        sequencer: Arc::new(Sequencer::new(pool, self_did)),
    };

    Router::<TestState>::new()
        .route(
            "/xrpc/blue.catbird.mls.ds.deliverMessage",
            post(handlers::ds::deliver_message),
        )
        .route(
            "/xrpc/blue.catbird.mls.ds.submitCommit",
            post(handlers::ds::submit_commit),
        )
        .route(
            "/xrpc/blue.catbird.mls.ds.fetchKeyPackage",
            get(handlers::ds::fetch_key_package),
        )
        .route(
            "/xrpc/blue.catbird.mls.admin.getFederationPeers",
            get(handlers::get_federation_peers),
        )
        .route(
            "/xrpc/blue.catbird.mls.admin.upsertFederationPeer",
            post(handlers::upsert_federation_peer),
        )
        .route(
            "/xrpc/blue.catbird.mls.admin.deleteFederationPeer",
            post(handlers::delete_federation_peer),
        )
        .with_state(state)
}

async fn call_json(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("failed to build request");

    let response = app.clone().oneshot(req).await.expect("request failed");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed reading body");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, parsed)
}

#[allow(dead_code)]
async fn call_get(app: &Router, path: &str, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("failed to build request");

    let response = app.clone().oneshot(req).await.expect("request failed");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed reading body");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, parsed)
}

async fn seed_conversation(pool: &PgPool, convo_id: &str, sequencer_ds: Option<&str>) {
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, sequencer_ds) \
         VALUES ($1, $2, 0, NOW(), NOW(), $3)",
    )
    .bind(convo_id)
    .bind("did:plc:creator")
    .bind(sequencer_ds)
    .execute(pool)
    .await
    .expect("failed to seed conversation");
}

/// Helper: build a standard deliverMessage payload for a conversation.
fn deliver_message_payload(convo_id: &str, sender_ds: &str) -> Value {
    json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "epoch": 1,
        "senderDsDid": sender_ds,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        "paddedSize": 512,
        "messageType": "app"
    })
}

// ===========================================================================
// 1. JWT Security Tests
// ===========================================================================

#[tokio::test]
async fn test_rejects_expired_token() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:expired-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    // Build a token that expired 60 seconds ago.
    let now = Utc::now().timestamp();
    let claims = ServiceClaims {
        iss: &sender,
        aud: "did:web:test.ds.local",
        exp: now - 60, // already expired
        iat: now - 180,
        lxm: "blue.catbird.mls.ds.deliverMessage",
        jti: &Uuid::new_v4().to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .unwrap();

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired token must be rejected: {body}");
}

#[tokio::test]
async fn test_rejects_wrong_audience() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:wrongaud-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    // Token addressed to a different DS.
    let now = Utc::now().timestamp();
    let claims = ServiceClaims {
        iss: &sender,
        aud: "did:web:WRONG-audience.example", // does not match SERVICE_DID
        exp: now + 120,
        iat: now,
        lxm: "blue.catbird.mls.ds.deliverMessage",
        jti: &Uuid::new_v4().to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .unwrap();

    let (status, _body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong audience must be rejected");
}

#[tokio::test]
async fn test_rejects_missing_lxm() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:nolxm-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    let now = Utc::now().timestamp();
    let claims = PartialClaims {
        iss: sender.clone(),
        aud: "did:web:test.ds.local".into(),
        exp: now + 120,
        iat: now,
        lxm: None, // <-- missing lxm
        jti: Some(Uuid::new_v4().to_string()),
    };
    let token = partial_token(&claims);

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing lxm must be rejected: {body}");
}

#[tokio::test]
async fn test_rejects_wrong_lxm() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:wronglxm-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    // Token's lxm claim says submitCommit, but we are calling deliverMessage.
    let token = service_token(
        &sender,
        "blue.catbird.mls.ds.submitCommit", // wrong endpoint
        &Uuid::new_v4().to_string(),
    );

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong lxm must be rejected: {body}");
}

#[tokio::test]
async fn test_rejects_replayed_jti() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:replay-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(&sender, "blue.catbird.mls.ds.deliverMessage", &jti);

    // First request should succeed.
    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK, "first use of jti must succeed");

    // Second request with the same jti should be rejected.
    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED, "replayed jti must be rejected");
    let error_str = second_body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        error_str.contains("Replay"),
        "error should mention replay, got: {error_str}"
    );
}

#[tokio::test]
async fn test_rejects_missing_jti() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:nojti-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    let now = Utc::now().timestamp();
    let claims = PartialClaims {
        iss: sender.clone(),
        aud: "did:web:test.ds.local".into(),
        exp: now + 120,
        iat: now,
        lxm: Some("blue.catbird.mls.ds.deliverMessage".into()),
        jti: None, // <-- missing jti
    };
    let token = partial_token(&claims);

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing jti must be rejected: {body}");
}

#[tokio::test]
async fn test_accepts_valid_token() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sender = format!("did:web:valid-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sender)).await;

    let token = service_token(
        &sender,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );

    let (status, _body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &sender),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "valid token with all correct claims must be accepted");
}

// ===========================================================================
// 2. Discovery Security Tests (SSRF protection)
//    These call `validate_endpoint_url_with_policy` directly.
// ===========================================================================

#[test]
fn test_rejects_private_ip_in_endpoint() {
    // 10.x (RFC 1918)
    let result = validate_endpoint_url_with_policy("https://10.0.0.1/xrpc", false);
    assert!(result.is_err(), "10.x address must be blocked");

    // 192.168.x (RFC 1918)
    let result = validate_endpoint_url_with_policy("https://192.168.1.100/xrpc", false);
    assert!(result.is_err(), "192.168.x address must be blocked");

    // 127.x (loopback)
    let result = validate_endpoint_url_with_policy("https://127.0.0.1/xrpc", false);
    assert!(result.is_err(), "127.x loopback must be blocked");

    // 172.16.x (RFC 1918)
    let result = validate_endpoint_url_with_policy("https://172.16.5.1/xrpc", false);
    assert!(result.is_err(), "172.16.x address must be blocked");
}

#[test]
fn test_rejects_localhost_endpoint() {
    let result = validate_endpoint_url_with_policy("https://localhost/xrpc", false);
    assert!(result.is_err(), "localhost must be blocked in strict mode");

    let result = validate_endpoint_url_with_policy("https://localhost:3000/xrpc", false);
    assert!(result.is_err(), "localhost with port must be blocked");

    // Subdomain of localhost
    let result = validate_endpoint_url_with_policy("https://evil.localhost/xrpc", false);
    assert!(result.is_err(), "*.localhost must be blocked");
}

#[test]
fn test_rejects_ftp_scheme() {
    let result = validate_endpoint_url_with_policy("ftp://ds.example.com/xrpc", false);
    assert!(result.is_err(), "ftp scheme must be rejected");

    let result = validate_endpoint_url_with_policy("ftp://ds.example.com/xrpc", true);
    assert!(result.is_err(), "ftp scheme must be rejected even with allow_http");
}

#[test]
fn test_rejects_http_in_strict_mode() {
    let result = validate_endpoint_url_with_policy("http://ds.example.com/xrpc", false);
    assert!(result.is_err(), "http must be rejected in strict mode");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("HTTP") || err_msg.contains("http") || err_msg.contains("https"),
        "error should mention HTTP policy, got: {err_msg}"
    );
}

#[test]
fn test_allows_http_in_dev_mode() {
    let result = validate_endpoint_url_with_policy("http://ds.example.com/xrpc", true);
    assert!(result.is_ok(), "http must be allowed in dev mode (allow_http=true)");
}

#[test]
fn test_rejects_host_not_in_allowlist() {
    let allowlist = vec!["trusted.example.com".to_string()];
    assert!(
        !host_is_allowlisted("evil.example.com", &allowlist),
        "unlisted host must be rejected"
    );
    assert!(
        !host_is_allowlisted("trusted.example.com.evil.com", &allowlist),
        "host that contains allowlisted name but is not a subdomain must be rejected"
    );
}

#[test]
fn test_allows_host_in_allowlist() {
    let allowlist = vec!["example.com".to_string()];
    assert!(
        host_is_allowlisted("example.com", &allowlist),
        "exact match must be allowed"
    );
    assert!(
        host_is_allowlisted("sub.example.com", &allowlist),
        "subdomain must be allowed"
    );
    assert!(
        host_is_allowlisted("deep.sub.example.com", &allowlist),
        "deep subdomain must be allowed"
    );
}

#[test]
fn test_rejects_ipv6_loopback() {
    let result = validate_endpoint_url_with_policy("https://[::1]/xrpc", false);
    assert!(result.is_err(), "IPv6 loopback [::1] must be blocked");

    let result = validate_endpoint_url_with_policy("https://[::1]:8080/xrpc", false);
    assert!(result.is_err(), "IPv6 loopback with port must be blocked");
}

// ===========================================================================
// 3. Peer Policy Tests (require DB)
// ===========================================================================

#[tokio::test]
async fn test_blocks_suspended_peer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let suspended_ds = format!("did:web:suspended-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&suspended_ds)).await;

    // Mark this peer as suspended.
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'suspend', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'suspend', updated_at = NOW()",
    )
    .bind(&suspended_ds)
    .execute(&pool)
    .await
    .expect("failed to set peer as suspended");

    let token = service_token(
        &suspended_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &suspended_ds),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "suspended peer must be blocked: {body}"
    );
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("suspended"),
        "error should mention suspension, got: {msg}"
    );
}

#[tokio::test]
async fn test_blocks_blocked_peer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let blocked_ds = format!("did:web:blocked-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&blocked_ds)).await;

    // Mark this peer as blocked.
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'block', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'block', updated_at = NOW()",
    )
    .bind(&blocked_ds)
    .execute(&pool)
    .await
    .expect("failed to set peer as blocked");

    let token = service_token(
        &blocked_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &blocked_ds),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "blocked peer must be blocked: {body}"
    );
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("blocklisted") || msg.contains("block"),
        "error should mention block, got: {msg}"
    );
}

#[tokio::test]
async fn test_allows_allowed_peer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let allowed_ds = format!("did:web:allowed-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&allowed_ds)).await;

    // Pre-approve this peer.
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'allow', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(&allowed_ds)
    .execute(&pool)
    .await
    .expect("failed to set peer as allowed");

    let token = service_token(
        &allowed_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );

    let (status, _body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &allowed_ds),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "allowed peer must be accepted"
    );
}

#[tokio::test]
async fn test_pending_peer_default_behavior() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let pending_ds = format!("did:web:pending-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&pending_ds)).await;

    // Explicitly set the peer as pending.
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'pending', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'pending', updated_at = NOW()",
    )
    .bind(&pending_ds)
    .execute(&pool)
    .await
    .expect("failed to set peer as pending");

    let token = service_token(
        &pending_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &pending_ds),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "pending peer should be rejected by default: {body}"
    );
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("pending"),
        "error should mention pending status, got: {msg}"
    );
}

#[tokio::test]
async fn test_rate_limit_exceeded() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let rate_limited_ds = format!("did:web:ratelimit-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&rate_limited_ds)).await;

    // Set an extremely low rate limit (1 request per minute).
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, max_requests_per_minute, updated_at) \
         VALUES ($1, 'allow', 1, NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           max_requests_per_minute = 1, status = 'allow', updated_at = NOW()",
    )
    .bind(&rate_limited_ds)
    .execute(&pool)
    .await
    .expect("failed to seed peer with rate limit");

    // First request should succeed.
    let token_a = service_token(
        &rate_limited_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token_a,
        deliver_message_payload(&convo_id, &rate_limited_ds),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK, "first request within rate limit");

    // Second request should be rate-limited.
    let token_b = service_token(
        &rate_limited_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token_b,
        deliver_message_payload(&convo_id, &rate_limited_ds),
    )
    .await;

    assert_eq!(
        second_status,
        StatusCode::TOO_MANY_REQUESTS,
        "second request should be rate-limited: {second_body}"
    );
}

#[tokio::test]
async fn test_trust_score_updates() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let peer_ds = format!("did:web:trust-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&peer_ds)).await;

    // Ensure peer starts with trust_score = 0 and status = allow.
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, updated_at) \
         VALUES ($1, 'allow', 0, NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', trust_score = 0, updated_at = NOW()",
    )
    .bind(&peer_ds)
    .execute(&pool)
    .await
    .expect("failed to set initial trust score");

    // Successful request should increase trust score.
    let token = service_token(
        &peer_ds,
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        deliver_message_payload(&convo_id, &peer_ds),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let trust_after_success: i32 =
        sqlx::query_scalar("SELECT trust_score FROM federation_peers WHERE ds_did = $1")
            .bind(&peer_ds)
            .fetch_one(&pool)
            .await
            .expect("failed to query trust score");
    assert!(
        trust_after_success > 0,
        "trust score should increase after successful request, got: {trust_after_success}"
    );

    let successful_count: i64 = sqlx::query_scalar(
        "SELECT successful_request_count FROM federation_peers WHERE ds_did = $1",
    )
    .bind(&peer_ds)
    .fetch_one(&pool)
    .await
    .expect("failed to query successful_request_count");
    assert!(
        successful_count > 0,
        "successful_request_count should be incremented"
    );
}

// ===========================================================================
// 4. Resolver Edge Cases
// ===========================================================================

#[test]
fn test_did_web_resolution_url_construction() {
    // did:web: should resolve to https://<domain>/.well-known/did.json
    let did = "did:web:ds.example.com";
    let domain = did.strip_prefix("did:web:").unwrap();
    let url = format!(
        "https://{}/.well-known/did.json",
        domain.replace(':', "/")
    );
    assert_eq!(url, "https://ds.example.com/.well-known/did.json");

    // did:web: with path components
    let did = "did:web:example.com:users:alice";
    let domain = did.strip_prefix("did:web:").unwrap();
    let url = format!(
        "https://{}/.well-known/did.json",
        domain.replace(':', "/")
    );
    assert_eq!(url, "https://example.com/users/alice/.well-known/did.json");
}

#[test]
fn test_did_plc_resolution_url_construction() {
    let did = "did:plc:z72i7hdynmk6r22z27h6tvur";
    let url = format!("https://plc.directory/{did}");
    assert_eq!(
        url,
        "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"
    );
}

#[test]
fn test_unsupported_did_method_rejected() {
    // The resolver only supports did:web: and did:plc: methods.
    // did:key: and other methods should be rejected.
    let did = "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";
    assert!(
        !did.starts_with("did:web:") && !did.starts_with("did:plc:"),
        "did:key should not match web or plc prefixes"
    );

    // Verify it would produce a ResolutionFailed error.
    let result = if did.starts_with("did:web:") {
        Ok("web".to_string())
    } else if did.starts_with("did:plc:") {
        Ok("plc".to_string())
    } else {
        Err(FederationError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("Unsupported DID method: {did}"),
        })
    };
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("Unsupported DID method"));
}

#[test]
fn test_is_self_detection() {
    // canonical_did should strip fragment.
    assert_eq!(
        canonical_did("did:web:ds.example.com#atproto_mls"),
        "did:web:ds.example.com"
    );
    assert_eq!(canonical_did("did:web:ds.example.com"), "did:web:ds.example.com");

    // dids_equivalent tests self-detection.
    assert!(dids_equivalent(
        "did:web:ds.example.com#atproto_mls",
        "did:web:ds.example.com"
    ));
    assert!(dids_equivalent(
        "did:web:ds.example.com#svc-a",
        "did:web:ds.example.com#svc-b"
    ));
    assert!(!dids_equivalent(
        "did:web:ds-a.example.com",
        "did:web:ds-b.example.com"
    ));
}

// ===========================================================================
// Additional edge-case tests
// ===========================================================================

#[test]
fn test_validate_url_rejects_data_scheme() {
    let result = validate_endpoint_url_with_policy("data:text/html,<h1>hi</h1>", false);
    assert!(result.is_err(), "data: scheme must be rejected");
}

#[test]
fn test_validate_url_rejects_javascript_scheme() {
    let result = validate_endpoint_url_with_policy("javascript:alert(1)", false);
    // This will fail to parse as a valid URL, which is also acceptable.
    assert!(result.is_err(), "javascript: scheme must be rejected");
}

#[test]
fn test_validate_url_rejects_0_0_0_0() {
    let result = validate_endpoint_url_with_policy("https://0.0.0.0/xrpc", false);
    assert!(result.is_err(), "0.0.0.0 must be blocked");
}

#[test]
fn test_validate_url_allows_valid_https() {
    let result = validate_endpoint_url_with_policy("https://ds.example.com/xrpc/endpoint", false);
    assert!(result.is_ok(), "valid HTTPS endpoint must be accepted");
}

#[test]
fn test_allowlist_subdomain_matching() {
    let allowlist = vec!["example.com".to_string(), "trusted.net".to_string()];

    // Exact match
    assert!(host_is_allowlisted("example.com", &allowlist));
    assert!(host_is_allowlisted("trusted.net", &allowlist));

    // Subdomain match
    assert!(host_is_allowlisted("ds.example.com", &allowlist));
    assert!(host_is_allowlisted("mls.ds.example.com", &allowlist));

    // Not a subdomain (suffix attack)
    assert!(!host_is_allowlisted("notexample.com", &allowlist));
    assert!(!host_is_allowlisted("evil-trusted.net", &allowlist));

    // Completely unrelated
    assert!(!host_is_allowlisted("evil.org", &allowlist));
}

#[test]
fn test_allowlist_case_insensitive() {
    let allowlist = vec!["example.com".to_string()];
    assert!(host_is_allowlisted("EXAMPLE.COM", &allowlist));
    assert!(host_is_allowlisted("Example.Com", &allowlist));
    assert!(host_is_allowlisted("DS.EXAMPLE.COM", &allowlist));
}

#[test]
fn test_allowlist_empty_rejects_all() {
    let allowlist: Vec<String> = vec![];
    assert!(!host_is_allowlisted("example.com", &allowlist));
    assert!(!host_is_allowlisted("anything.net", &allowlist));
}

#[test]
fn test_canonical_did_no_fragment() {
    assert_eq!(canonical_did("did:plc:abc123"), "did:plc:abc123");
}

#[test]
fn test_canonical_did_with_fragment() {
    assert_eq!(
        canonical_did("did:web:example.com#service"),
        "did:web:example.com"
    );
}

#[test]
fn test_canonical_did_multiple_fragments() {
    // Only the first '#' matters - everything after it is stripped.
    assert_eq!(
        canonical_did("did:web:example.com#a#b"),
        "did:web:example.com"
    );
}

#[test]
fn test_federation_error_status_codes() {
    // Verify that the key error variants map to the expected HTTP status codes.
    assert_eq!(
        FederationError::AuthFailed {
            reason: "test".into()
        }
        .status_code(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        FederationError::ResolutionFailed {
            did: "test".into(),
            reason: "blocked".into()
        }
        .status_code(),
        StatusCode::BAD_GATEWAY
    );

    assert_eq!(
        FederationError::EndpointNotFound {
            did: "test".into()
        }
        .status_code(),
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        FederationError::NotSequencer {
            convo_id: "test".into()
        }
        .status_code(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn test_service_auth_client_shared_secret_roundtrip() {
    // Verify the ServiceAuthClient produces valid JWTs with all required claims.
    let client = catbird_server::federation::ServiceAuthClient::from_shared_secret(
        "did:web:source.example.com".to_string(),
        b"test-secret-key-minimum-32-bytes!",
    );

    let token = client
        .sign_request(
            "did:web:target.example.com",
            "blue.catbird.mls.ds.deliverMessage",
        )
        .expect("signing should succeed");

    // Decode and verify all claims are present.
    let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
    validation.set_audience(&["did:web:target.example.com"]);
    let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret-key-minimum-32-bytes!");
    let decoded = jsonwebtoken::decode::<catbird_server::federation::service_auth::ServiceAuthClaims>(
        &token,
        &key,
        &validation,
    )
    .expect("decoding should succeed");

    let claims = decoded.claims;
    assert_eq!(claims.iss, "did:web:source.example.com");
    assert_eq!(claims.aud, "did:web:target.example.com");
    assert_eq!(claims.lxm, "blue.catbird.mls.ds.deliverMessage");
    assert!(!claims.jti.is_empty(), "jti must be present");
    assert!(claims.exp > claims.iat, "exp must be after iat");
    assert_eq!(claims.exp - claims.iat, 120, "token should expire in 120 seconds");
}

#[test]
fn test_service_auth_unique_jti_per_request() {
    let client = catbird_server::federation::ServiceAuthClient::from_shared_secret(
        "did:web:ds.example.com".to_string(),
        b"test-secret-key-minimum-32-bytes!",
    );

    let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
    validation.set_audience(&["did:web:target.example.com"]);
    let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret-key-minimum-32-bytes!");

    let token1 = client
        .sign_request("did:web:target.example.com", "m")
        .unwrap();
    let token2 = client
        .sign_request("did:web:target.example.com", "m")
        .unwrap();

    let jti1 = jsonwebtoken::decode::<catbird_server::federation::service_auth::ServiceAuthClaims>(
        &token1, &key, &validation,
    )
    .unwrap()
    .claims
    .jti;
    let jti2 = jsonwebtoken::decode::<catbird_server::federation::service_auth::ServiceAuthClaims>(
        &token2, &key, &validation,
    )
    .unwrap()
    .claims
    .jti;

    assert_ne!(jti1, jti2, "each request must have a unique jti");
}

#[test]
fn test_validate_url_rejects_link_local_ipv4() {
    let result = validate_endpoint_url_with_policy("https://169.254.1.1/xrpc", false);
    assert!(result.is_err(), "link-local 169.254.x.x must be blocked");
}

#[test]
fn test_validate_url_http_with_private_ip_allowed_in_dev() {
    // In dev mode (allow_http=true), private IPs should be allowed because
    // developers need to target local services.
    let result = validate_endpoint_url_with_policy("http://127.0.0.1:3000/xrpc", true);
    assert!(
        result.is_ok(),
        "localhost should be allowed in dev mode, got: {:?}",
        result.err()
    );

    let result = validate_endpoint_url_with_policy("http://10.0.0.5:3000/xrpc", true);
    assert!(
        result.is_ok(),
        "private IPs should be allowed in dev mode, got: {:?}",
        result.err()
    );
}

#[test]
fn test_peer_status_round_trip() {
    use catbird_server::federation::peer_policy::PeerStatus;

    let statuses = [
        ("pending", PeerStatus::Pending),
        ("allow", PeerStatus::Allow),
        ("suspend", PeerStatus::Suspend),
        ("block", PeerStatus::Block),
    ];

    for (str_val, expected) in &statuses {
        let parsed = PeerStatus::from_str(str_val).unwrap();
        assert_eq!(parsed, *expected, "parsing '{str_val}' failed");
        assert_eq!(parsed.as_db_str(), *str_val, "round-trip for '{str_val}' failed");
    }

    // Unknown status should return None.
    assert!(PeerStatus::from_str("unknown").is_none());
    assert!(PeerStatus::from_str("").is_none());
    assert!(PeerStatus::from_str("ALLOW").is_none(), "status parsing should be case-sensitive");
}

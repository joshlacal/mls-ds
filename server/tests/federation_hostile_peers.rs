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
use catbird_server::federation::{AckSigner, Sequencer};
use catbird_server::handlers;
use catbird_server::realtime::SseState;

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

fn configure_security_env() {
    std::env::set_var("SERVICE_DID", "did:web:test.ds.local");
    std::env::set_var("ENFORCE_LXM", "true");
    std::env::set_var("ENFORCE_JTI", "true");
    std::env::set_var("JTI_TTL_SECONDS", "120");
    std::env::set_var("FEDERATION_ADMIN_DIDS", "did:plc:federation-admin");
}

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

#[tokio::test]
async fn deliver_message_accepts_fragmented_issuer_for_bound_sequencer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;

    let token = service_token(
        &format!("{sequencer_base}#atproto_mls"),
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let canonical_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM federation_peers WHERE ds_did = $1)")
            .bind(&sequencer_base)
            .fetch_one(&pool)
            .await
            .expect("failed query canonical peer row");
    assert!(canonical_exists);

    let fragment_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM federation_peers WHERE ds_did = $1)")
            .bind(format!("{sequencer_base}#atproto_mls"))
            .fetch_one(&pool)
            .await
            .expect("failed query fragment peer row");
    assert!(!fragment_exists);
}

#[tokio::test]
async fn replayed_service_token_is_rejected() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(&sequencer_base, "blue.catbird.mls.ds.deliverMessage", &jti);

    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        "paddedSize": 512,
        "messageType": "app"
    });

    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
    assert!(second_body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("Replay detected"));
}

#[tokio::test]
async fn replayed_service_token_is_rejected_across_app_instances() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app_a = test_router(pool.clone());
    let app_b = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(&sequencer_base, "blue.catbird.mls.ds.deliverMessage", &jti);

    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
        "paddedSize": 512,
        "messageType": "app"
    });

    let (first_status, _) = call_json(
        &app_a,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, second_body) = call_json(
        &app_b,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
    assert!(second_body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("Replay detected"));
}

#[tokio::test]
async fn ds_rate_limit_applies_across_service_fragments() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let base_ds = format!("did:web:rate-limit-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&base_ds)).await;

    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, max_requests_per_minute, updated_at) \
         VALUES ($1, 'allow', 1, NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET max_requests_per_minute = 1, status = 'allow', updated_at = NOW()",
    )
    .bind(&base_ds)
    .execute(&pool)
    .await
    .expect("failed to seed peer override");

    let payload = |msg_id: String, sender: String| {
        json!({
            "convoId": convo_id,
            "msgId": msg_id,
            "epoch": 1,
            "senderDsDid": sender,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"hello"),
            "paddedSize": 512,
            "messageType": "app"
        })
    };

    let token_a = service_token(
        &format!("{base_ds}#svc-a"),
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token_a,
        payload(format!("msg-{}", Uuid::new_v4()), base_ds.clone()),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let token_b = service_token(
        &format!("{base_ds}#svc-b"),
        "blue.catbird.mls.ds.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.deliverMessage",
        &token_b,
        payload(format!("msg-{}", Uuid::new_v4()), base_ds.clone()),
    )
    .await;
    assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
    assert!(second_body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("rate limit"));
}

#[tokio::test]
async fn submit_commit_rejects_non_participant_peer_ds() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, None).await;

    let attacker_ds = format!("did:web:attacker-{}.example", Uuid::new_v4());
    let token = service_token(
        &attacker_ds,
        "blue.catbird.mls.ds.submitCommit",
        &Uuid::new_v4().to_string(),
    );

    let payload = json!({
        "convoId": convo_id,
        "senderDsDid": attacker_ds,
        "epoch": 0,
        "proposedEpoch": 1,
        "commitData": base64::engine::general_purpose::STANDARD.encode(b"commit"),
    });

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.ds.submitCommit",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("not a participant"));
}

#[tokio::test]
async fn fetch_key_package_requires_convo_id_and_membership_authorization() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let requester_ds = format!("did:web:member-ds-{}.example", Uuid::new_v4());
    let unauthorized_ds = format!("did:web:unauth-ds-{}.example", Uuid::new_v4());
    let recipient_did = format!("did:plc:recipient-{}", Uuid::new_v4());

    seed_conversation(&pool, &convo_id, Some(&requester_ds)).await;

    sqlx::query("INSERT INTO users (did, created_at) VALUES ($1, NOW())")
        .bind(&recipient_did)
        .execute(&pool)
        .await
        .expect("failed to insert recipient user");
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, ds_did, is_admin) \
         VALUES ($1, $2, $2, NOW(), NULL, false)",
    )
    .bind(&convo_id)
    .bind(&recipient_did)
    .execute(&pool)
    .await
    .expect("failed to seed recipient member");
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, ds_did, is_admin) \
         VALUES ($1, $2, $2, NOW(), $3, false)",
    )
    .bind(&convo_id)
    .bind("did:plc:remote-member")
    .bind(&requester_ds)
    .execute(&pool)
    .await
    .expect("failed to seed requester member");

    sqlx::query(
        "INSERT INTO key_packages \
         (id, owner_did, cipher_suite, key_package, key_package_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&recipient_did)
    .bind("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
    .bind(b"kp-bytes".as_ref())
    .bind(format!("hash-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("failed to seed key package");

    let missing_convo_token = service_token(
        &requester_ds,
        "blue.catbird.mls.ds.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (missing_status, _) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mls.ds.fetchKeyPackage?recipientDid={}",
            urlencoding::encode(&recipient_did)
        ),
        &missing_convo_token,
    )
    .await;
    assert_eq!(missing_status, StatusCode::BAD_REQUEST);

    let unauthorized_token = service_token(
        &unauthorized_ds,
        "blue.catbird.mls.ds.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (unauth_status, _) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mls.ds.fetchKeyPackage?recipientDid={}&convoId={}",
            urlencoding::encode(&recipient_did),
            urlencoding::encode(&convo_id)
        ),
        &unauthorized_token,
    )
    .await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);

    let authorized_token = service_token(
        &format!("{requester_ds}#svc"),
        "blue.catbird.mls.ds.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (ok_status, ok_body) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mls.ds.fetchKeyPackage?recipientDid={}&convoId={}",
            urlencoding::encode(&recipient_did),
            urlencoding::encode(&convo_id)
        ),
        &authorized_token,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK);
    assert!(ok_body.get("keyPackage").is_some());
    assert!(ok_body.get("keyPackageHash").is_some());
}

#[tokio::test]
async fn federation_peer_admin_lifecycle_endpoints_work() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool);

    let admin_token = service_token(
        "did:plc:federation-admin",
        "blue.catbird.mls.admin.upsertFederationPeer",
        &Uuid::new_v4().to_string(),
    );
    let target_ds = format!("did:web:managed-peer-{}.example", Uuid::new_v4());

    let (upsert_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.admin.upsertFederationPeer",
        &admin_token,
        json!({
            "dsDid": format!("{target_ds}#service"),
            "status": "block",
            "maxRequestsPerMinute": 42,
            "note": "hostile behavior"
        }),
    )
    .await;
    assert_eq!(upsert_status, StatusCode::OK);

    let list_token = service_token(
        "did:plc:federation-admin",
        "blue.catbird.mls.admin.getFederationPeers",
        &Uuid::new_v4().to_string(),
    );
    let (list_status, list_body) = call_get(
        &app,
        "/xrpc/blue.catbird.mls.admin.getFederationPeers?status=block",
        &list_token,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    let peers = list_body
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(peers.iter().any(|peer| {
        peer.get("dsDid")
            .and_then(|v| v.as_str())
            .map(|did| did == target_ds)
            .unwrap_or(false)
    }));

    let delete_token = service_token(
        "did:plc:federation-admin",
        "blue.catbird.mls.admin.deleteFederationPeer",
        &Uuid::new_v4().to_string(),
    );
    let (delete_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mls.admin.deleteFederationPeer",
        &delete_token,
        json!({ "dsDid": target_ds }),
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
}

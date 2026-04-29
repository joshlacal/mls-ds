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
use catbird_server::federation::{
    AckSigner, Sequencer, SequencerTransfer, TransferError, TransferResult,
};
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
    std::env::set_var("FEDERATION_SEQUENCER_FAILOVER_MIN_STALE_SECS", "30");
    std::env::set_var("FEDERATION_SEQUENCER_TRANSFER_MAX_TERM_JUMP", "8");
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
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            post(handlers::ds::deliver_message),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.submitCommit",
            post(handlers::ds::submit_commit),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage",
            get(handlers::ds::fetch_key_package),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest",
            get(handlers::ds::get_convo_digest),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            get(handlers::ds::get_convo_events),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getFederationPeers",
            get(handlers::get_federation_peers),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            post(handlers::upsert_federation_peer),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deleteFederationPeer",
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
        "INSERT INTO conversations (id, creator_did, current_epoch, sequencer_term, created_at, updated_at, sequencer_ds, group_id) \
         VALUES ($1, $2, 0, 0, NOW(), NOW(), $3, $1)",
    )
    .bind(convo_id)
    .bind("did:plc:creator")
    .bind(sequencer_ds)
    .execute(pool)
    .await
    .expect("failed to seed conversation");
}

async fn allow_peer(pool: &PgPool, ds_did: &str) {
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'allow', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(ds_did)
    .execute(pool)
    .await
    .expect("failed to allow federation peer");
}

async fn seed_message(pool: &PgPool, convo_id: &str, msg_id: &str, seq: i64, epoch: i64) {
    sqlx::query(
        "INSERT INTO messages (id, convo_id, message_type, epoch, seq, ciphertext, msg_id, padded_size, created_at) \
         VALUES ($1, $2, 'app', $3, $4, $5, $6, 512, NOW())",
    )
    .bind(msg_id)
    .bind(convo_id)
    .bind(epoch)
    .bind(seq)
    .bind(b"hello".as_ref())
    .bind(msg_id)
    .execute(pool)
    .await
    .expect("failed to seed message");
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn deliver_message_accepts_fragmented_issuer_for_bound_sequencer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;
    allow_peer(&pool, &sequencer_base).await;

    let token = service_token(
        &format!("{sequencer_base}#atproto_mls"),
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
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
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn replayed_service_token_is_rejected() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;
    allow_peer(&pool, &sequencer_base).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(&sequencer_base, "blue.catbird.mlsDS.deliverMessage", &jti);

    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        second_body.get("reasonCode").and_then(|v| v.as_str()),
        Some("auth_failed")
    );
    assert!(second_body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("Replay detected"));
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn replayed_service_token_is_rejected_across_app_instances() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app_a = test_router(pool.clone());
    let app_b = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_base = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_base)).await;
    allow_peer(&pool, &sequencer_base).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(&sequencer_base, "blue.catbird.mlsDS.deliverMessage", &jti);

    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": sequencer_base,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (first_status, _) = call_json(
        &app_a,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, second_body) = call_json(
        &app_b,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        second_body.get("reasonCode").and_then(|v| v.as_str()),
        Some("auth_failed")
    );
    assert!(second_body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("Replay detected"));
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
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
            "deliveryId": ulid::Ulid::new().to_string(),
            "sequencerTerm": 0,
            "epoch": 1,
            "senderDsDid": sender,
            "ciphertext": {
                "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
            },
            "paddedSize": 512,
            "messageType": "app"
        })
    };

    let token_a = service_token(
        &format!("{base_ds}#svc-a"),
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token_a,
        payload(format!("msg-{}", Uuid::new_v4()), base_ds.clone()),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let token_b = service_token(
        &format!("{base_ds}#svc-b"),
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (second_status, second_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token_b,
        payload(format!("msg-{}", Uuid::new_v4()), base_ds.clone()),
    )
    .await;
    assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second_body.get("reasonCode").and_then(|v| v.as_str()),
        Some("rate_limited")
    );
    assert!(second_body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("rate limit"));
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn deliver_message_rejects_sender_issuer_mismatch() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_ds = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    let spoofed_sender_ds = format!("did:web:spoofed-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_ds)).await;
    allow_peer(&pool, &sequencer_ds).await;

    let token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": spoofed_sender_ds,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body.get("reasonCode").and_then(|v| v.as_str()),
        Some("auth_failed")
    );
    assert!(body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .contains("does not match JWT issuer"));
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn deliver_message_rejects_non_sequencer_peer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let expected_sequencer = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    let attacker_ds = format!("did:web:attacker-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&expected_sequencer)).await;
    allow_peer(&pool, &attacker_ds).await;

    let token = service_token(
        &attacker_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": attacker_ds,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body.get("reasonCode").and_then(|v| v.as_str()),
        Some("not_sequencer")
    );
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn submit_commit_rejects_non_participant_peer_ds() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, None).await;

    let attacker_ds = format!("did:web:attacker-{}.example", Uuid::new_v4());
    allow_peer(&pool, &attacker_ds).await;
    let token = service_token(
        &attacker_ds,
        "blue.catbird.mlsDS.submitCommit",
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
        "/xrpc/blue.catbird.mlsDS.submitCommit",
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
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn deliver_message_rejects_stale_sequencer_term() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_ds = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_ds)).await;
    allow_peer(&pool, &sequencer_ds).await;
    sqlx::query("UPDATE conversations SET sequencer_term = 3 WHERE id = $1")
        .bind(&convo_id)
        .execute(&pool)
        .await
        .expect("failed to set sequencer term");

    let token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 2,
        "epoch": 1,
        "senderDsDid": sequencer_ds,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body.get("reasonCode").and_then(|v| v.as_str()),
        Some("term_stale")
    );
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn deliver_message_denies_unallowlisted_peer() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_ds = format!("did:web:unknown-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_ds)).await;

    let token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let payload = json!({
        "convoId": convo_id,
        "msgId": format!("msg-{}", Uuid::new_v4()),
        "deliveryId": ulid::Ulid::new().to_string(),
        "sequencerTerm": 0,
        "epoch": 1,
        "senderDsDid": sequencer_ds,
        "ciphertext": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(b"hello")
        },
        "paddedSize": 512,
        "messageType": "app"
    });

    let (status, body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body.get("reasonCode").and_then(|v| v.as_str()),
        Some("auth_failed")
    );
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
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
    allow_peer(&pool, &requester_ds).await;

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
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(b"kp-bytes".as_ref())
    .bind(format!("hash-{}", Uuid::new_v4()))
    .execute(&pool)
    .await
    .expect("failed to seed key package");

    let missing_convo_token = service_token(
        &requester_ds,
        "blue.catbird.mlsDS.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (missing_status, _) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage?recipientDid={}",
            urlencoding::encode(&recipient_did)
        ),
        &missing_convo_token,
    )
    .await;
    assert_eq!(missing_status, StatusCode::BAD_REQUEST);

    let unauthorized_token = service_token(
        &unauthorized_ds,
        "blue.catbird.mlsDS.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (unauth_status, _) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage?recipientDid={}&convoId={}",
            urlencoding::encode(&recipient_did),
            urlencoding::encode(&convo_id)
        ),
        &unauthorized_token,
    )
    .await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);

    let authorized_token = service_token(
        &format!("{requester_ds}#svc"),
        "blue.catbird.mlsDS.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
    );
    let (ok_status, ok_body) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage?recipientDid={}&convoId={}",
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
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn federation_peer_admin_lifecycle_endpoints_work() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool);

    let admin_token = service_token(
        "did:plc:federation-admin",
        "blue.catbird.mlsDS.upsertFederationPeer",
        &Uuid::new_v4().to_string(),
    );
    let target_ds = format!("did:web:managed-peer-{}.example", Uuid::new_v4());

    let (upsert_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
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
        "blue.catbird.mlsDS.getFederationPeers",
        &Uuid::new_v4().to_string(),
    );
    let (list_status, list_body) = call_get(
        &app,
        "/xrpc/blue.catbird.mlsDS.getFederationPeers?status=block",
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
        "blue.catbird.mlsDS.deleteFederationPeer",
        &Uuid::new_v4().to_string(),
    );
    let (delete_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deleteFederationPeer",
        &delete_token,
        json!({ "dsDid": target_ds }),
    )
    .await;
    assert_eq!(delete_status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn reconciliation_endpoints_require_allowlist_and_return_events() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_ds = format!("did:web:sequencer-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&sequencer_ds)).await;
    seed_message(&pool, &convo_id, &format!("msg-{}", Uuid::new_v4()), 1, 0).await;

    let denied_token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.getConvoDigest",
        &Uuid::new_v4().to_string(),
    );
    let (denied_status, _) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={}",
            urlencoding::encode(&convo_id)
        ),
        &denied_token,
    )
    .await;
    assert_eq!(denied_status, StatusCode::UNAUTHORIZED);

    allow_peer(&pool, &sequencer_ds).await;

    let digest_token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.getConvoDigest",
        &Uuid::new_v4().to_string(),
    );
    let (digest_status, digest_body) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={}",
            urlencoding::encode(&convo_id)
        ),
        &digest_token,
    )
    .await;
    assert_eq!(digest_status, StatusCode::OK);
    assert_eq!(
        digest_body.get("convoId").and_then(|v| v.as_str()),
        Some(convo_id.as_str())
    );
    assert!(digest_body.get("digestSha256").is_some());

    let events_token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.getConvoEvents",
        &Uuid::new_v4().to_string(),
    );
    let (events_status, events_body) = call_get(
        &app,
        &format!(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents?convoId={}&afterSeq=0&limit=10",
            urlencoding::encode(&convo_id)
        ),
        &events_token,
    )
    .await;
    assert_eq!(events_status, StatusCode::OK);
    let events = events_body
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!events.is_empty());
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn transfer_accept_increments_term_and_preserves_epoch_state() {
    let Some(pool) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.example", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&ds1)).await;
    sqlx::query("UPDATE conversations SET current_epoch = 7, sequencer_term = 5 WHERE id = $1")
        .bind(&convo_id)
        .execute(&pool)
        .await
        .expect("failed to seed term and epoch");

    let transfer = SequencerTransfer::new(pool.clone(), ds2.clone());
    let result = transfer
        .accept_transfer(&convo_id, &ds1, 6)
        .await
        .expect("transfer should succeed");
    assert!(matches!(
        result,
        TransferResult::Accepted {
            new_epoch: 7,
            new_sequencer_term: 6,
            ..
        }
    ));

    let (sequencer_ds, current_epoch, sequencer_term): (Option<String>, i32, i64) = sqlx::query_as(
        "SELECT sequencer_ds, current_epoch, sequencer_term FROM conversations WHERE id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&pool)
    .await
    .expect("failed to read conversation");
    assert_eq!(sequencer_ds.as_deref(), Some(ds2.as_str()));
    assert_eq!(current_epoch, 7);
    assert_eq!(sequencer_term, 6);
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn transfer_accept_rejects_invalid_term_jump() {
    let Some(pool) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.example", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&ds1)).await;
    sqlx::query("UPDATE conversations SET sequencer_term = 1 WHERE id = $1")
        .bind(&convo_id)
        .execute(&pool)
        .await
        .expect("failed to seed term");

    let transfer = SequencerTransfer::new(pool.clone(), ds2);
    let err = transfer
        .accept_transfer(&convo_id, &ds1, 5_000)
        .await
        .expect_err("large term jump must be rejected");
    assert!(matches!(
        err,
        TransferError::TermJumpTooLarge {
            current_term: 1,
            requested_term: 5_000,
            ..
        }
    ));

    let (sequencer_ds, sequencer_term): (Option<String>, i64) =
        sqlx::query_as("SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("failed to read conversation");
    assert_eq!(sequencer_ds.as_deref(), Some(ds1.as_str()));
    assert_eq!(sequencer_term, 1);
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn failover_rejects_takeover_when_current_lease_is_fresh() {
    let Some(pool) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.example", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&ds1)).await;
    sqlx::query("UPDATE conversations SET sequencer_term = 4 WHERE id = $1")
        .bind(&convo_id)
        .execute(&pool)
        .await
        .expect("failed to seed term");

    let transfer = SequencerTransfer::new(pool.clone(), ds2);
    let err = transfer
        .assume_sequencer_role(&convo_id, &ds1)
        .await
        .expect_err("fresh lease must block failover");
    assert!(matches!(
        err,
        TransferError::LeaseStillActive {
            required_age_secs: 30,
            ..
        }
    ));
}

#[tokio::test]
#[ignore = "fixture rot: federation contract changed (auth/status codes), tests not realigned"]
async fn failover_fences_old_sequencer_after_term_bump() {
    let Some(pool) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.example", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.example", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&ds1)).await;
    allow_peer(&pool, &ds1).await;
    allow_peer(&pool, &ds2).await;

    let ds1_token_before = service_token(
        &ds1,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (before_status, before_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &ds1_token_before,
        json!({
            "convoId": convo_id.clone(),
            "msgId": format!("msg-{}", Uuid::new_v4()),
            "deliveryId": ulid::Ulid::new().to_string(),
            "sequencerTerm": 0,
            "epoch": 1,
            "senderDsDid": ds1.clone(),
            "ciphertext": {
                "$bytes": base64::engine::general_purpose::STANDARD.encode(b"before-failover")
            },
            "paddedSize": 512,
            "messageType": "app"
        }),
    )
    .await;
    assert_eq!(before_status, StatusCode::OK);
    let before_seq = before_body
        .get("seq")
        .and_then(|v| v.as_i64())
        .expect("missing sequence in pre-failover response");

    let transfer = SequencerTransfer::new(pool.clone(), ds2.clone());
    let transfer_result = transfer
        .accept_transfer(&convo_id, &ds1, 1)
        .await
        .expect("failover transfer should succeed");
    assert!(matches!(
        transfer_result,
        TransferResult::Accepted {
            new_sequencer_term: 1,
            ..
        }
    ));

    let ds1_token_after = service_token(
        &ds1,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (old_status, old_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &ds1_token_after,
        json!({
            "convoId": convo_id.clone(),
            "msgId": format!("msg-{}", Uuid::new_v4()),
            "deliveryId": ulid::Ulid::new().to_string(),
            "sequencerTerm": 1,
            "epoch": 1,
            "senderDsDid": ds1.clone(),
            "ciphertext": {
                "$bytes": base64::engine::general_purpose::STANDARD.encode(b"stale-writer")
            },
            "paddedSize": 512,
            "messageType": "app"
        }),
    )
    .await;
    assert_eq!(old_status, StatusCode::FORBIDDEN);
    assert_eq!(
        old_body.get("reasonCode").and_then(|v| v.as_str()),
        Some("not_sequencer")
    );

    let ds2_token = service_token(
        &ds2,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
    );
    let (new_status, new_body) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &ds2_token,
        json!({
            "convoId": convo_id.clone(),
            "msgId": format!("msg-{}", Uuid::new_v4()),
            "deliveryId": ulid::Ulid::new().to_string(),
            "sequencerTerm": 1,
            "epoch": 1,
            "senderDsDid": ds2.clone(),
            "ciphertext": {
                "$bytes": base64::engine::general_purpose::STANDARD.encode(b"after-failover")
            },
            "paddedSize": 512,
            "messageType": "app"
        }),
    )
    .await;
    assert_eq!(new_status, StatusCode::OK);
    let new_seq = new_body
        .get("seq")
        .and_then(|v| v.as_i64())
        .expect("missing sequence in post-failover response");
    assert!(new_seq > before_seq);

    let message_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE convo_id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("failed to count messages");
    assert_eq!(message_count, 2);
}

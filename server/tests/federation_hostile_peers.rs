mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage;
use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
use chrono::{SecondsFormat, Utc};
use jacquard_common::DefaultStr;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower_util::util::ServiceExt;
use uuid::Uuid;

use catbird_server::auth::{
    cache_test_did_document, DidDocument, PublicKeyJwk, VerificationMethod,
};
use catbird_server::db::{init_db, DbConfig};
use catbird_server::federation::envelope::{
    compute_commit_envelope_digest, compute_message_envelope_digest, validate_entry_locator,
    validate_envelope_header,
};
use catbird_server::federation::{
    AckSigner, DsResolver, FederationMode, Sequencer, SequencerTransfer, TransferError,
    TransferResult,
};
use catbird_server::handlers::{self, chat::ChatRuntime};
use catbird_server::realtime::SseState;

#[derive(Clone, FromRef)]
struct TestState {
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    ack_signer: Option<Arc<AckSigner>>,
    sequencer: Arc<Sequencer>,
    resolver: Arc<DsResolver>,
    runtime: Arc<ChatRuntime>,
}

const DESTINATION_DID: &str = "did:web:destination.catbird.blue";
const ADMIN_DID: &str = "did:plc:federation-admin";
/// The one local recipient every delivery fixture addresses.
const RECIPIENT_DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

fn configure_security_env() {
    std::env::set_var("SERVICE_DID", DESTINATION_DID);
    std::env::set_var("ENFORCE_LXM", "true");
    std::env::set_var("ENFORCE_JTI", "true");
    std::env::set_var("JTI_TTL_SECONDS", "120");
    std::env::set_var("FEDERATION_ADMIN_DIDS", ADMIN_DID);
    std::env::set_var("FEDERATION_SEQUENCER_FAILOVER_MIN_STALE_SECS", "30");
    std::env::set_var("FEDERATION_SEQUENCER_TRANSFER_MAX_TERM_JUMP", "8");
    std::env::set_var("FEDERATION_MODE", "allowlist");
    FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
}

fn random_p256() -> P256SigningKey {
    P256SigningKey::random(&mut rand::thread_rng())
}

/// Publishes a fresh P-256 verification method for `did` and returns its signer.
async fn cache_did_key(did: &str) -> P256SigningKey {
    let key = random_p256();
    let canonical = catbird_server::identity::canonical_did(did);
    let point = key.verifying_key().to_encoded_point(false);
    let jwk_val = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let jwk: PublicKeyJwk = serde_json::from_value(jwk_val).unwrap();
    let doc = DidDocument {
        id: canonical.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{canonical}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: canonical.to_string(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }],
        service: None,
    };
    cache_test_did_document(doc).await;
    key
}

fn sign_jwt(header: Value, claims: Value, key: &P256SigningKey) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

fn service_token(iss: &str, lxm: &str, jti: &str, key: &P256SigningKey) -> String {
    let now = Utc::now().timestamp();
    let kid = format!("{}#atproto", catbird_server::identity::canonical_did(iss));
    sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":kid}),
        json!({
            "iss": iss,
            "sub": iss,
            "aud": DESTINATION_DID,
            "exp": now + 120,
            "iat": now,
            "lxm": lxm,
            "jti": jti,
        }),
        key,
    )
}

/// Reserved per-run database prefix owned by this target.
const FEDERATION_DB_PREFIX: &str = "mlsds_fedpeers_";

static FEDERATION_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup_test_db() -> Option<(PgPool, common::fresh_db::DisposableDatabase)> {
    if std::env::var("TEST_DATABASE_URL").is_err() {
        eprintln!("Skipping test: TEST_DATABASE_URL not set");
        return None;
    }

    configure_security_env();

    let database = common::fresh_db::fresh_fully_migrated_db(FEDERATION_DB_PREFIX).await;
    let config = DbConfig {
        database_url: database.url().to_owned(),
        max_connections: 8,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(20),
        idle_timeout: Duration::from_secs(60),
    };

    let pool = init_db(config).await.expect("failed to init DB");
    Some((pool, database))
}

fn test_router(pool: PgPool) -> Router {
    let self_did = std::env::var("SERVICE_DID").unwrap_or_else(|_| DESTINATION_DID.to_string());
    let sse_state = Arc::new(SseState::new(64));
    let resolver = Arc::new(DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        self_did.clone(),
        "https://destination.catbird.blue".to_string(),
        None,
        300,
    ));
    let runtime = Arc::new(
        ChatRuntime::from_env(sse_state.clone())
            .expect("build chat runtime")
            .with_resolver(resolver.clone()),
    );
    let ack_key = random_p256();
    let ack_signer = Some(Arc::new(AckSigner::new(ack_key, self_did.clone())));
    let state = TestState {
        db_pool: pool.clone(),
        sse_state,
        ack_signer,
        sequencer: Arc::new(Sequencer::new(pool, self_did)),
        resolver,
        runtime,
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
    let _ = sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, sequencer_term, created_at, updated_at, sequencer_ds, group_id) \
         VALUES ($1, $2, 0, 0, NOW(), NOW(), $3, $1) ON CONFLICT (id) DO NOTHING",
    )
    .bind(convo_id)
    .bind("did:plc:creator")
    .bind(sequencer_ds)
    .execute(pool)
    .await;
}

async fn allow_peer(pool: &PgPool, ds_did: &str) {
    let canonical = catbird_server::identity::canonical_did(ds_did);
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) \
         VALUES ($1, 'allow', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(canonical)
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

fn make_deliver_message_body(
    convo_id: &str,
    sender_ds_did: &str,
    sequencer_ds_did: &str,
    sequencer_term: i64,
) -> Value {
    let entry_bytes = b"entry_payload";
    let signed_request_bytes = b"signed_request";
    let mut body = json!({
        "header": {
            "protocolVersion": "1",
            "deliveryId": Uuid::new_v4().to_string(),
            "conversationId": convo_id,
            "senderDsDid": sender_ds_did,
            "receiverDsDid": DESTINATION_DID,
            "sequencerDid": sequencer_ds_did,
            "sequencerTerm": sequencer_term,
            "receivedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "payloadSha256": { "$bytes": STANDARD.encode([0; 32]) }
        },
        "entryLocator": {
            "entryId": Uuid::new_v4().to_string(),
            "seq": 1,
            "acceptedPayloadSha256": { "$bytes": STANDARD.encode([0x22; 32]) },
            "outerEntryFingerprint": { "$bytes": STANDARD.encode([0x33; 32]) }
        },
        "recipientDid": RECIPIENT_DID,
        "entryBytes": { "$bytes": STANDARD.encode(entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(signed_request_bytes) }
    });
    let message: DeliverMessage<DefaultStr> =
        serde_json::from_value(body.clone()).expect("current DeliverMessage contract");
    let mut header = validate_envelope_header(&message.header).expect("valid envelope header");
    let locator = validate_entry_locator(&message.entry_locator).expect("valid entry locator");
    header.payload_sha256 = compute_message_envelope_digest(
        &header,
        RECIPIENT_DID,
        &locator,
        entry_bytes,
        signed_request_bytes,
    )
    .expect("valid envelope digest inputs");
    body["header"]["payloadSha256"] = json!({ "$bytes": STANDARD.encode(header.payload_sha256) });
    body
}

#[tokio::test]
async fn deliver_message_accepts_fragmented_issuer_for_bound_sequencer() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let sequencer_base = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_base).await;
    allow_peer(&pool, &sequencer_base).await;

    let token = service_token(
        &format!("{sequencer_base}#atproto_mls"),
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let payload = make_deliver_message_body(&convo_id, &sequencer_base, &sequencer_base, 0);

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    // Request passes service authentication (not rejected for auth)
    assert_ne!(status, StatusCode::UNAUTHORIZED);

    let canonical_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM federation_peers WHERE ds_did = $1)")
            .bind(&sequencer_base)
            .fetch_one(&pool)
            .await
            .expect("failed query canonical peer row");
    assert!(canonical_exists);
}

#[tokio::test]
async fn replayed_service_token_is_rejected() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let sequencer_base = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_base).await;
    allow_peer(&pool, &sequencer_base).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(
        &sequencer_base,
        "blue.catbird.mlsDS.deliverMessage",
        &jti,
        &key,
    );
    let payload = make_deliver_message_body(&convo_id, &sequencer_base, &sequencer_base, 0);

    let (first_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    // First request passes authentication
    assert_ne!(first_status, StatusCode::UNAUTHORIZED);

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
        second_body.get("error").and_then(|v| v.as_str()),
        Some("ReplayDetected")
    );
}

#[tokio::test]
async fn replayed_service_token_is_rejected_across_app_instances() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app_a = test_router(pool.clone());
    let app_b = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let sequencer_base = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_base).await;
    allow_peer(&pool, &sequencer_base).await;

    let jti = Uuid::new_v4().to_string();
    let token = service_token(
        &sequencer_base,
        "blue.catbird.mlsDS.deliverMessage",
        &jti,
        &key,
    );
    let payload = make_deliver_message_body(&convo_id, &sequencer_base, &sequencer_base, 0);

    let (first_status, _) = call_json(
        &app_a,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload.clone(),
    )
    .await;
    assert_ne!(first_status, StatusCode::UNAUTHORIZED);

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
        second_body.get("error").and_then(|v| v.as_str()),
        Some("ReplayDetected")
    );
}

#[tokio::test]
async fn federation_admin_allowlist_applies_across_service_fragments() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let key = cache_did_key(ADMIN_DID).await;

    // Administrative authorization compares the canonical base DID.
    let token = service_token(
        &format!("{ADMIN_DID}#svc-a"),
        "blue.catbird.mlsDS.getFederationPeers",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let (status, _) = call_get(&app, "/xrpc/blue.catbird.mlsDS.getFederationPeers", &token).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn deliver_message_rejects_sender_issuer_mismatch() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let sequencer_ds = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let spoofed_sender_ds = format!("did:web:spoofed-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_ds).await;
    allow_peer(&pool, &sequencer_ds).await;

    let token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let payload = make_deliver_message_body(
        &convo_id,
        &spoofed_sender_ds, // mismatch with JWT issuer
        &sequencer_ds,
        0,
    );

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "issuer mismatch must be rejected: status={status}"
    );
}

#[tokio::test]
async fn deliver_message_rejects_non_sequencer_peer() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let attacker_ds = format!("did:web:attacker-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&attacker_ds).await;
    allow_peer(&pool, &attacker_ds).await;

    let token = service_token(
        &attacker_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let payload = make_deliver_message_body(&convo_id, &attacker_ds, &attacker_ds, 0);

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "non-sequencer delivery must fail: status={status}"
    );
}

#[tokio::test]
async fn submit_commit_rejects_non_participant_peer_ds() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let attacker_ds = format!("did:web:attacker-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&attacker_ds).await;
    allow_peer(&pool, &attacker_ds).await;

    let token = service_token(
        &attacker_ds,
        "blue.catbird.mlsDS.submitCommit",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let signed_request_bytes = b"signed_request";
    let mut payload = json!({
        "header": {
            "protocolVersion": "1",
            "deliveryId": Uuid::new_v4().to_string(),
            "conversationId": convo_id,
            "senderDsDid": attacker_ds,
            "receiverDsDid": DESTINATION_DID,
            "sequencerDid": DESTINATION_DID,
            "sequencerTerm": 0,
            "receivedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "payloadSha256": { "$bytes": STANDARD.encode([0; 32]) }
        },
        "signedRequestBytes": { "$bytes": STANDARD.encode(signed_request_bytes) }
    });
    let message: SubmitCommit<DefaultStr> =
        serde_json::from_value(payload.clone()).expect("current SubmitCommit contract");
    let mut header = validate_envelope_header(&message.header).expect("valid envelope header");
    header.payload_sha256 =
        compute_commit_envelope_digest(&header, signed_request_bytes).expect("valid envelope");
    payload["header"]["payloadSha256"] =
        json!({ "$bytes": STANDARD.encode(header.payload_sha256) });

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        &token,
        payload,
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::UNAUTHORIZED,
        "non-participant submitCommit must fail: status={status}"
    );
}

#[tokio::test]
async fn deliver_message_rejects_stale_sequencer_term() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let sequencer_ds = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_ds).await;
    allow_peer(&pool, &sequencer_ds).await;

    let token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let payload = make_deliver_message_body(
        &convo_id,
        &sequencer_ds,
        &sequencer_ds,
        0, // stale term
    );

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert!(
        status == StatusCode::CONFLICT
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::NOT_FOUND,
        "stale term must be rejected: status={status}"
    );
}

#[tokio::test]
async fn deliver_message_denies_unallowlisted_peer() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let unallowlisted_ds = format!("did:web:unknown-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&unallowlisted_ds).await;

    let token = service_token(
        &unallowlisted_ds,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let payload = make_deliver_message_body(&convo_id, &unallowlisted_ds, &unallowlisted_ds, 0);

    let (status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &token,
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fetch_key_package_requires_convo_id_and_membership_authorization() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let unauthorized_ds = format!("did:web:unauth-ds-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&unauthorized_ds).await;

    let token = service_token(
        &unauthorized_ds,
        "blue.catbird.mlsDS.fetchKeyPackage",
        &Uuid::new_v4().to_string(),
        &key,
    );
    let (status, _) = call_get(
        &app,
        "/xrpc/blue.catbird.mlsDS.fetchKeyPackage?convoId=test&recipientDid=did:plc:test",
        &token,
    )
    .await;
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn federation_peer_admin_lifecycle_endpoints_work() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool);

    let admin_key = cache_did_key(ADMIN_DID).await;

    let admin_token = service_token(
        ADMIN_DID,
        "blue.catbird.mlsDS.upsertFederationPeer",
        &Uuid::new_v4().to_string(),
        &admin_key,
    );
    let target_ds = format!("did:web:managed-peer-{}.catbird.blue", Uuid::new_v4());

    let (upsert_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
        &admin_token,
        json!({
            "dsDid": target_ds.clone(),
            "status": "block",
            "maxRequestsPerMinute": 42,
            "note": "hostile behavior"
        }),
    )
    .await;
    assert_eq!(upsert_status, StatusCode::OK);

    let list_token = service_token(
        ADMIN_DID,
        "blue.catbird.mlsDS.getFederationPeers",
        &Uuid::new_v4().to_string(),
        &admin_key,
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
        ADMIN_DID,
        "blue.catbird.mlsDS.deleteFederationPeer",
        &Uuid::new_v4().to_string(),
        &admin_key,
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
async fn reconciliation_endpoints_require_allowlist_and_return_events() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let sequencer_ds = format!("did:web:sequencer-{}.catbird.blue", Uuid::new_v4());
    let key = cache_did_key(&sequencer_ds).await;

    seed_conversation(&pool, &convo_id, Some(&sequencer_ds)).await;
    seed_message(&pool, &convo_id, &format!("msg-{}", Uuid::new_v4()), 1, 0).await;

    let denied_token = service_token(
        &sequencer_ds,
        "blue.catbird.mlsDS.getConvoDigest",
        &Uuid::new_v4().to_string(),
        &key,
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
        &key,
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
        &key,
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
async fn transfer_accept_increments_term_and_preserves_epoch_state() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.catbird.blue", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.catbird.blue", Uuid::new_v4());
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
async fn transfer_accept_rejects_invalid_term_jump() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.catbird.blue", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.catbird.blue", Uuid::new_v4());
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
async fn failover_rejects_takeover_when_current_lease_is_fresh() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };

    let convo_id = format!("convo-{}", Uuid::new_v4());
    let ds1 = format!("did:web:sequencer-a-{}.catbird.blue", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.catbird.blue", Uuid::new_v4());
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
async fn failover_fences_old_sequencer_after_term_bump() {
    let _fixture_guard = FEDERATION_FIXTURE_LOCK.lock().await;
    let Some((pool, _database)) = setup_test_db().await else {
        return;
    };
    let app = test_router(pool.clone());

    let convo_id = Uuid::new_v4().to_string();
    let ds1 = format!("did:web:sequencer-a-{}.catbird.blue", Uuid::new_v4());
    let ds2 = format!("did:web:sequencer-b-{}.catbird.blue", Uuid::new_v4());
    seed_conversation(&pool, &convo_id, Some(&ds1)).await;
    allow_peer(&pool, &ds1).await;
    allow_peer(&pool, &ds2).await;
    let key1 = cache_did_key(&ds1).await;
    cache_did_key(&ds2).await;

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

    // Old sequencer with stale term 0 is rejected
    let ds1_token_after = service_token(
        &ds1,
        "blue.catbird.mlsDS.deliverMessage",
        &Uuid::new_v4().to_string(),
        &key1,
    );
    let (old_status, _) = call_json(
        &app,
        "POST",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        &ds1_token_after,
        make_deliver_message_body(&convo_id, &ds1, &ds1, 0),
    )
    .await;
    assert!(
        old_status == StatusCode::FORBIDDEN
            || old_status == StatusCode::CONFLICT
            || old_status == StatusCode::NOT_FOUND,
        "old sequencer must be fenced after failover: old_status={old_status}"
    );
}

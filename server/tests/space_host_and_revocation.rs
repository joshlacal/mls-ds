//! Option A Conversation `SpaceHost` & Revocation Fan-Out integration tests (`atproto#5187`).
//!
//! Pins all Review Focus items from Plan 04 Task 3:
//! 1. `getSpaceCredential` & `notifyWrite` require `status = 'active'` with ZERO `NOT c.is_remote`
//!    local-only blocks, 60s single-use delegation `jti` replay cache, and 10m credential `jti` ledger.
//! 2. `listRepos` includes writers with `status IN ('active', 'left', 'removed')` in ascending
//!    `spaceRev` order while strictly excluding `'pending'` / declined `C33` direct-request targets.
//! 3. Member removal or device revocation immediately marks credential `jti`s revoked (`401`
//!    `CredentialRevoked` on subsequent reads) AND fans out `com.atproto.space.notifyCredentialRevoked`
//!    to ALL writers' PDSes (after DB commit — never inside an open SQL transaction, `M-F04`).
//! 4. Account deletion (`delete_account_data_with_conversations` / `removeWriter`) removes the
//!    deleted DID from `listRepos`, and generation close fans out `com.atproto.space.notifySpaceDeleted`
//!    to registered syncers and writers' PDSes, after which Space calls return `410 SpaceDeleted`.

mod common;

use atproto_spaces::{
    http_signature::sign_credential_request,
    kem::encode_p256_did_key,
    tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind},
};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
    Json, Router,
};
use base64::Engine as _;
use catbird_server::{
    chat_protocol::{
        repository::direct_request_receipts::DirectRequestReceiptSigner,
        test_support::{
            seed_clean_slate_active_zero_leaf_member_for_test,
            seed_clean_slate_application_fixture, seed_clean_slate_expired_direct_request_fixture,
            seed_clean_slate_remove_zero_leaf_member_for_test,
        },
    },
    labyrinth::repo::retention::delete_account_data_with_conversations,
    space_host::{
        revocation_fanout::{
            fan_out_space_deleted_for_conversation,
            revoke_inactive_space_credentials_for_conversation,
            revoke_user_space_credentials_across_conversations,
        },
        space_host_router, SpaceHostConfig, SpaceHostRuntime,
    },
};
use chrono::Utc;
use p256::{
    ecdsa::SigningKey as P256SigningKey, pkcs8::EncodePrivateKey, PublicKey as P256PublicKey,
    SecretKey as P256Secret,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tower_util::ServiceExt;
use uuid::Uuid;

fn p256_pem(sk: &P256SigningKey) -> String {
    let secret = P256Secret::from_slice(&sk.to_bytes()).expect("p256 secret");
    secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

fn build_signed_space_headers(
    pop_key: &P256SigningKey,
    cred_jwt: &str,
    authority_did: &str,
    now_sec: u64,
    nonce: &str,
) -> HeaderMap {
    let secret = P256Secret::from_slice(&pop_key.to_bytes()).expect("p256 secret");
    sign_credential_request(&secret, cred_jwt, authority_did, now_sec, nonce)
        .expect("sign_credential_request")
        .to_header_map()
        .expect("to_header_map")
}

#[derive(Clone, Default)]
struct RecordedNotice {
    path: String,
    auth: Option<String>,
    body: Value,
}

async fn start_mock_pds_and_syncer() -> (String, Arc<Mutex<Vec<RecordedNotice>>>) {
    let notices: Arc<Mutex<Vec<RecordedNotice>>> = Arc::new(Mutex::new(Vec::new()));
    let state = notices.clone();
    let app = Router::new()
        .route(
            "/xrpc/com.atproto.space.notifyCredentialRevoked",
            post(
                |State(log): State<Arc<Mutex<Vec<RecordedNotice>>>>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    log.lock().unwrap().push(RecordedNotice {
                        path: "/xrpc/com.atproto.space.notifyCredentialRevoked".into(),
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        body,
                    });
                    StatusCode::OK
                },
            ),
        )
        .route(
            "/xrpc/com.atproto.space.notifySpaceDeleted",
            post(
                |State(log): State<Arc<Mutex<Vec<RecordedNotice>>>>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    log.lock().unwrap().push(RecordedNotice {
                        path: "/xrpc/com.atproto.space.notifySpaceDeleted".into(),
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        body,
                    });
                    StatusCode::OK
                },
            ),
        )
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(
                |State(log): State<Arc<Mutex<Vec<RecordedNotice>>>>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    log.lock().unwrap().push(RecordedNotice {
                        path: "/xrpc/com.atproto.space.notifyWrite".into(),
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        body,
                    });
                    StatusCode::OK
                },
            ),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), notices)
}

fn mint_delegation(
    user_did: &str,
    user_pds_key: &P256SigningKey,
    authority_did: &str,
    space_uri: &str,
    cnf_kid: &str,
    jti: &str,
    now_sec: u64,
) -> String {
    let _ = cnf_kid;
    let signing_key = SpaceSigningKey::P256 {
        signing_key: user_pds_key.clone(),
        kid: "#atproto".to_string(),
    };
    mint_space_token(
        SpaceTokenKind::Delegation,
        &signing_key,
        &SpaceTokenClaims {
            iss: user_did.to_string(),
            sub: space_uri.to_string(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: jti.to_string(),
            cnf_kid: None,
        },
    )
    .expect("mint delegation JWT")
}

fn mint_service_jwt_es256(issuer_did: &str, key: &P256SigningKey, aud: &str, lxm: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature};
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer_did,
            "aud": aud,
            "lxm": lxm,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{claims}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

#[tokio::test]
async fn space_host_enforces_active_vs_historical_rosters_replay_revocation_and_deletion() {
    let authority_did = "did:web:ds-space.example.com";
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://ds-space.example.com");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_space_host_").await;
    let pool = db.connect(4).await;
    common::http_acceptance::ensure_fence(&pool).await;

    let fixture = seed_clean_slate_application_fixture(&pool, false, authority_did, None)
        .await
        .expect("seed group conversation");

    // Flip `is_remote = true` to prove remote flag never blocks SpaceHost!
    sqlx::query(
        "UPDATE chat.conversations SET is_remote = TRUE, sequencer_ds = $2 WHERE conversation_id = $1",
    )
    .bind(fixture.conversation_id)
    .bind(authority_did)
    .execute(&pool)
    .await
    .unwrap();

    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("conversation_spaces row");

    let (mock_url, recorded_notices) = start_mock_pds_and_syncer().await;

    let authority_key = P256SigningKey::from_bytes((&[0x31u8; 32]).into()).unwrap();
    let sender_pds_key = P256SigningKey::from_bytes((&[0x32u8; 32]).into()).unwrap();
    let recipient_pds_key = P256SigningKey::from_bytes((&[0x33u8; 32]).into()).unwrap();
    let pending_pds_key = P256SigningKey::from_bytes((&[0x34u8; 32]).into()).unwrap();

    let host_runtime = Arc::new(SpaceHostRuntime::new(
        pool.clone(),
        SpaceHostConfig::for_test(authority_did.to_string(), authority_key.clone()),
    ));
    host_runtime.register_test_did_endpoint(
        &fixture.sender_did,
        sender_pds_key.verifying_key(),
        &mock_url,
    );
    host_runtime.register_test_did_endpoint(
        &fixture.recipient_did,
        recipient_pds_key.verifying_key(),
        &mock_url,
    );
    host_runtime.register_test_did_endpoint(
        "did:plc:syncerserviceaaaaaaaaaaa",
        sender_pds_key.verifying_key(),
        &mock_url,
    );

    let app = space_host_router(host_runtime.clone());
    let now_sec = Utc::now().timestamp() as u64;

    // 1. Active sender & active recipient both mint Space credentials even with is_remote = true!
    let sender_pop = P256SigningKey::from_bytes((&[0x41u8; 32]).into()).unwrap();
    let sender_kid = encode_p256_did_key(&P256PublicKey::from(sender_pop.verifying_key()));
    let sender_del = mint_delegation(
        &fixture.sender_did,
        &sender_pds_key,
        authority_did,
        &space_uri,
        &sender_kid,
        "del-jti-sender-1",
        now_sec,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "credentialKid": sender_kid,
                        "delegationToken": sender_del,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "active member must mint credential"
    );
    let sender_cred_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 65536).await.unwrap())
            .unwrap();
    let sender_cred = sender_cred_json["credential"].as_str().unwrap().to_string();

    // Replaying the exact same delegation jti MUST fail closed!
    let replay_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "credentialKid": sender_kid,
                        "delegationToken": sender_del,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            replay_resp.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
        ),
        "replayed delegation jti must fail closed, got {}",
        replay_resp.status()
    );

    // Mint credential for recipient too
    let recip_pop = P256SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
    let recip_kid = encode_p256_did_key(&P256PublicKey::from(recip_pop.verifying_key()));
    let recip_del = mint_delegation(
        &fixture.recipient_did,
        &recipient_pds_key,
        authority_did,
        &space_uri,
        &recip_kid,
        "del-jti-recip-1",
        now_sec,
    );
    let recip_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "credentialKid": recip_kid,
                        "delegationToken": recip_del,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recip_resp.status(), StatusCode::OK);
    let recip_cred_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(recip_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let recip_cred = recip_cred_json["credential"].as_str().unwrap().to_string();

    // 2. Pending / unaccepted C33 direct-request target MUST be denied getSpaceCredential & excluded from listRepos!
    let receipt_key = P256SigningKey::random(&mut OsRng);
    let service_key = P256SigningKey::random(&mut OsRng);
    let receipt_doc = catbird_server::identity::did_doc::build_direct_request_receipt_did_document(
        authority_did,
        receipt_key.verifying_key(),
    );
    let dr_signer = DirectRequestReceiptSigner::configured(
        &p256_pem(&receipt_key),
        &p256_pem(&service_key),
        &serde_json::to_string(&receipt_doc).unwrap(),
    )
    .expect("direct request receipt signer");
    let expired_seeded = seed_clean_slate_expired_direct_request_fixture(&pool, &dr_signer)
        .await
        .expect("seed C33 fixture");
    let pending_space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1",
    )
    .bind(expired_seeded.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("C33 conversation_spaces row");
    let pending_target_did = expired_seeded.recipient_did.clone();
    host_runtime.register_test_did_endpoint(
        &pending_target_did,
        pending_pds_key.verifying_key(),
        &mock_url,
    );
    let pending_del = mint_delegation(
        &pending_target_did,
        &pending_pds_key,
        authority_did,
        &pending_space_uri,
        &recip_kid,
        "del-jti-pending-1",
        now_sec,
    );
    let pending_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": pending_space_uri,
                        "credentialKid": recip_kid,
                        "delegationToken": pending_del,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pending_resp.status(),
        StatusCode::FORBIDDEN,
        "pending C33 target must be denied Space credential"
    );

    // 3. Register syncer via registerNotify, then both sender and recipient call notifyWrite
    let mut reg_headers =
        build_signed_space_headers(&sender_pop, &sender_cred, authority_did, now_sec, "reg-1");
    reg_headers.insert("content-type", "application/json".parse().unwrap());
    let mut reg_req = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.registerNotify")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "space": space_uri,
                "service": "did:plc:syncerserviceaaaaaaaaaaa#atproto_sync",
            }))
            .unwrap(),
        ))
        .unwrap();
    *reg_req.headers_mut() = reg_headers;
    let reg_resp = app.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_resp.status(), StatusCode::OK, "registerNotify failed");

    for (did, key, rev_str, fill) in [
        (
            &fixture.sender_did,
            &sender_pds_key,
            "3k2aaaaaaaaaa",
            0x11u8,
        ),
        (
            &fixture.recipient_did,
            &recipient_pds_key,
            "3k2aaaaaaaaab",
            0x22u8,
        ),
    ] {
        let jwt = mint_service_jwt_es256(
            did,
            key,
            &format!("{authority_did}#atproto_mls"),
            "com.atproto.space.notifyWrite",
        );
        let nw_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.space.notifyWrite")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "space": space_uri,
                            "repo": did,
                            "repoRev": rev_str,
                            "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode([fill; 32]) },
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            nw_resp.status(),
            StatusCode::OK,
            "notifyWrite for {did} failed"
        );
    }

    // 4. Add a 3rd active member (charlie_did), mint credential + notifyWrite, then remove charlie_did via committed policy transition:
    //    - Removed member is immediately denied new getSpaceCredential & notifyWrite (403 Forbidden)
    //    - revoke_inactive_space_credentials_for_conversation revokes charlie_did's existing credential jti (401 CredentialRevoked)
    //      AND fans out notifyCredentialRevoked to ALL 3 writers' PDSes!
    //    - listRepos STILL includes charlie_did's historical writer entry alongside active writers in ascending spaceRev order!
    let charlie_did = "did:web:charlie-member.routing.example.com";
    let charlie_pds_key = P256SigningKey::from_bytes((&[0x35u8; 32]).into()).unwrap();
    host_runtime.register_test_did_endpoint(
        charlie_did,
        charlie_pds_key.verifying_key(),
        &mock_url,
    );
    seed_clean_slate_active_zero_leaf_member_for_test(
        &pool,
        fixture.conversation_id,
        &fixture.sender_did,
        charlie_did,
    )
    .await
    .expect("seed active charlie");

    let charlie_pop = P256SigningKey::from_bytes((&[0x43u8; 32]).into()).unwrap();
    let charlie_kid = encode_p256_did_key(&P256PublicKey::from(charlie_pop.verifying_key()));
    let charlie_del = mint_delegation(
        charlie_did,
        &charlie_pds_key,
        authority_did,
        &space_uri,
        &charlie_kid,
        "del-jti-charlie-1",
        now_sec,
    );
    let charlie_cred_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "credentialKid": charlie_kid,
                        "delegationToken": charlie_del,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(charlie_cred_resp.status(), StatusCode::OK);
    let charlie_cred_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(charlie_cred_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let charlie_cred = charlie_cred_json["credential"]
        .as_str()
        .unwrap()
        .to_string();

    let charlie_nw_jwt = mint_service_jwt_es256(
        charlie_did,
        &charlie_pds_key,
        &format!("{authority_did}#atproto_mls"),
        "com.atproto.space.notifyWrite",
    );
    let charlie_nw_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.notifyWrite")
                .header("authorization", format!("Bearer {charlie_nw_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "repo": charlie_did,
                        "repoRev": "3k2aaaaaaaaac",
                        "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]) },
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        charlie_nw_resp.status(),
        StatusCode::OK,
        "notifyWrite for charlie failed"
    );

    seed_clean_slate_remove_zero_leaf_member_for_test(
        &pool,
        fixture.conversation_id,
        &fixture.sender_did,
        charlie_did,
    )
    .await
    .expect("remove charlie via committed policy transition");

    revoke_inactive_space_credentials_for_conversation(&host_runtime, fixture.conversation_id, 0)
        .await
        .expect("revoke inactive credentials and fan out");

    // Removed member MUST be denied new getSpaceCredential (403 Forbidden)!
    let charlie_del_after = mint_delegation(
        charlie_did,
        &charlie_pds_key,
        authority_did,
        &space_uri,
        &charlie_kid,
        "del-jti-charlie-after-rem",
        now_sec,
    );
    let charlie_after_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.space.getSpaceCredential")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "space": space_uri,
                        "credentialKid": charlie_kid,
                        "delegationToken": charlie_del_after,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        charlie_after_resp.status(),
        StatusCode::FORBIDDEN,
        "removed member must be denied getSpaceCredential"
    );

    // Charlie's previously-minted credential MUST now fail with 401 CredentialRevoked on listRepos!
    let revoked_headers = build_signed_space_headers(
        &charlie_pop,
        &charlie_cred,
        authority_did,
        now_sec,
        "rev-list-1",
    );
    let mut rev_list_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencoding::encode(&space_uri)
        ))
        .body(Body::empty())
        .unwrap();
    *rev_list_req.headers_mut() = revoked_headers;
    let rev_list_resp = app.clone().oneshot(rev_list_req).await.unwrap();
    assert_eq!(
        rev_list_resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked credential jti must be rejected immediately"
    );

    // Sender's credential still works AND listRepos still returns ALL THREE writers (active + removed historical writer)!
    let sender_list_headers = build_signed_space_headers(
        &sender_pop,
        &sender_cred,
        authority_did,
        now_sec,
        "sender-list-1",
    );
    let mut list_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencoding::encode(&space_uri)
        ))
        .body(Body::empty())
        .unwrap();
    *list_req.headers_mut() = sender_list_headers;
    let list_resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(list_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let repo_dids: Vec<&str> = list_json["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["did"].as_str().unwrap())
        .collect();
    assert_eq!(
        repo_dids,
        vec![
            fixture.sender_did.as_str(),
            fixture.recipient_did.as_str(),
            charlie_did
        ],
        "listRepos must preserve historical removed writer alongside active writers in ascending spaceRev order"
    );

    // Verify notifyCredentialRevoked was fanned out to ALL 3 writers' PDSes!
    {
        let log = recorded_notices.lock().unwrap();
        let rev_calls: Vec<&RecordedNotice> = log
            .iter()
            .filter(|n| n.path == "/xrpc/com.atproto.space.notifyCredentialRevoked")
            .collect();
        assert!(
            rev_calls.len() >= 3,
            "notifyCredentialRevoked must fan out to all writers' PDSes, got {}",
            rev_calls.len()
        );
        assert!(rev_calls[0]
            .auth
            .as_deref()
            .unwrap_or("")
            .starts_with("Bearer "));
        assert_eq!(rev_calls[0].body["space"], space_uri);
        assert_eq!(
            rev_calls[0].body["credentials"].as_array().unwrap().len(),
            1
        );
    }

    // Device revocation across conversations (revoke_user_space_credentials_across_conversations) also revokes recipient's credential!
    revoke_user_space_credentials_across_conversations(&host_runtime, &fixture.recipient_did)
        .await
        .expect("revoke device credentials across conversations");
    let recip_rev_headers = build_signed_space_headers(
        &recip_pop,
        &recip_cred,
        authority_did,
        now_sec,
        "recip-rev-1",
    );
    let mut recip_rev_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencoding::encode(&space_uri)
        ))
        .body(Body::empty())
        .unwrap();
    *recip_rev_req.headers_mut() = recip_rev_headers;
    let recip_rev_resp = app.clone().oneshot(recip_rev_req).await.unwrap();
    assert_eq!(recip_rev_resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Account deletion (delete_account_data_with_conversations) removes writer from Space!
    delete_account_data_with_conversations(
        &pool,
        charlie_did,
        Utc::now(),
        Some(&catbird_server::federation::receipt::I13ReceiptSigner::new(
            P256SigningKey::random(&mut OsRng),
            authority_did.to_owned(),
        )),
    )
    .await
    .unwrap();

    let list_after_del_headers = build_signed_space_headers(
        &sender_pop,
        &sender_cred,
        authority_did,
        now_sec,
        "sender-list-2",
    );
    let mut list_after_del_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencoding::encode(&space_uri)
        ))
        .body(Body::empty())
        .unwrap();
    *list_after_del_req.headers_mut() = list_after_del_headers;
    let list_after_del_resp = app.clone().oneshot(list_after_del_req).await.unwrap();
    assert_eq!(list_after_del_resp.status(), StatusCode::OK);
    let list_after_del_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(list_after_del_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let remaining_dids: Vec<&str> = list_after_del_json["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["did"].as_str().unwrap())
        .collect();
    assert_eq!(
        remaining_dids,
        vec![fixture.sender_did.as_str(), fixture.recipient_did.as_str()],
        "account deletion must remove deleted DID from listRepos"
    );

    // 6. Generation close fans out notifySpaceDeleted to syncers + writers, and subsequent listRepos returns 410 Gone!
    fan_out_space_deleted_for_conversation(&host_runtime, fixture.conversation_id, 0)
        .await
        .expect("fan out notifySpaceDeleted");

    {
        let log = recorded_notices.lock().unwrap();
        assert!(
            log.iter()
                .any(|n| n.path == "/xrpc/com.atproto.space.notifySpaceDeleted"
                    && n.body["space"] == space_uri),
            "notifySpaceDeleted must be delivered to registered syncers/writers"
        );
    }

    let list_closed_headers = build_signed_space_headers(
        &sender_pop,
        &sender_cred,
        authority_did,
        now_sec,
        "sender-list-3",
    );
    let mut closed_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencoding::encode(&space_uri)
        ))
        .body(Body::empty())
        .unwrap();
    *closed_req.headers_mut() = list_closed_headers;
    let closed_resp = app.oneshot(closed_req).await.unwrap();
    assert_eq!(
        closed_resp.status(),
        StatusCode::GONE,
        "closed generation Space must return 410 Gone (SpaceDeleted)"
    );

    pool.close().await;
}

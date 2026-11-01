//! `D1` Federated Cross-Server Group Relay & `3A` Stateless Space Relays integration tests.
//!
//! Pins:
//! 1. `D1`: Remote group member talks ONLY to their own home `mls-ds`, which relays group
//!    mutations (`relayGroupMutation`) to the sequencing `mls-ds` and ingests `deliverGroupEntry`
//!    fan-out (with `I13` sequencer receipt!) on remote member home `mls-ds` instances.
//! 2. `3A` `blue.catbird.chat.relaySpaceCredential`: Stateless home-`mls-ds` relay exchanging a
//!    PDS delegation token with a remote Space authority, returning `{credential, expiresAt}` and
//!    writing ZERO operational DB rows on the home `mls-ds`.
//! 3. `3A` `blue.catbird.chat.relaySpaceRead`:
//!    - Enforces strict read-only `com.atproto.space.*` NSID allowlist (`400 InvalidNsid` on writes),
//!    - Enforces DNS-pinned SSRF guard (`400 InvalidTargetEndpoint` on `169.254.169.254` / `10.0.0.1`),
//!    - Forwards `Authorization: Atproto-Space-Credential ...`, `Atproto-Space-Audience`,
//!      `Atproto-Space-Want-Mac`, `Signature-Input`, and `Signature` untouched,
//!    - Preserves upstream `Atproto-Space-Mac` and exposes `Access-Control-Expose-Headers: Atproto-Space-Mac`,
//!    - Writes ZERO rows on the home `mls-ds`!

mod common;

use atproto_spaces::{
    http_signature::sign_credential_request,
    kem::encode_p256_did_key,
    tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind},
};
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use catbird_server::{
    chat_protocol::test_support::seed_clean_slate_application_fixture,
    federation::{
        group_relay::{
            deliver_group_entry_to_remote_home, group_relay_router,
            relay_group_mutation_to_sequencer, DeliverGroupEntryRequest, GroupRelayState,
            RelayGroupMutationRequest,
        },
        receipt::I13ReceiptSigner,
        space_read_relay::register_test_space_relay_target,
    },
    space_host::{space_host_router, SpaceHostConfig, SpaceHostRuntime},
};
use chrono::Utc;
use common::http_acceptance as http;
use p256::{
    ecdsa::SigningKey as P256SigningKey, PublicKey as P256PublicKey, SecretKey as P256Secret,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone, Default)]
struct CapturedUpstreamRead {
    auth: Option<String>,
    audience: Option<String>,
    want_mac: Option<String>,
    sig_input: Option<String>,
    sig: Option<String>,
    query: Option<String>,
}

async fn count_mutable_chat_rows(pool: &sqlx::PgPool) -> i64 {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'chat' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut total = 0_i64;
    for table in tables {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM chat.\"{table}\""))
            .fetch_one(pool)
            .await
            .unwrap();
        total += count;
    }
    total
}

static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn d1_cross_server_group_relay_sequences_on_authority_and_fans_out_with_i13_receipt() {
    let _env_guard = ENV_LOCK.lock().await;
    let seq_did = "did:web:ds-seq.example.com";
    let home_a_did = "did:web:ds-home-a.example.com";
    let home_b_did = "did:web:ds-home-b.example.com";
    std::env::set_var("SERVICE_DID", seq_did);
    std::env::set_var("SELF_ENDPOINT", "https://ds-seq.example.com");

    let db_seq = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_seq = db_seq.connect(4).await;
    http::ensure_fence(&pool_seq).await;

    let db_home_b = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_home_b = db_home_b.connect(4).await;
    http::ensure_fence(&pool_home_b).await;

    let i13_key = P256SigningKey::from_bytes((&[0x61u8; 32]).into()).unwrap();
    let i13_signer = Arc::new(I13ReceiptSigner::from_signing_key_for_test(
        seq_did.to_string(),
        i13_key.clone(),
    ));

    let fixture =
        seed_clean_slate_application_fixture(&pool_seq, false, home_b_did, Some([0xAB; 32]))
            .await
            .expect("seed sequencer group conversation");

    // Spawn sequencer S2S group_relay_router + home-B S2S group_relay_router
    let s2s_secret = b"shared-federation-s2s-test-key!!";
    let seq_state = GroupRelayState::for_test(
        pool_seq.clone(),
        seq_did.to_string(),
        s2s_secret,
        Some(i13_signer.clone()),
    );
    let seq_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seq_addr = seq_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(seq_listener, group_relay_router(seq_state))
            .await
            .unwrap();
    });

    let home_b_state = GroupRelayState::for_test(
        pool_home_b.clone(),
        home_b_did.to_string(),
        s2s_secret,
        None,
    );
    let home_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let home_b_addr = home_b_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(home_b_listener, group_relay_router(home_b_state))
            .await
            .unwrap();
    });

    // Sender on remote home_a relays real OpenMLS PrivateMessage sendMessage via home_a -> sequencer!
    let relay_out = relay_group_mutation_to_sequencer(
        &format!("http://{seq_addr}"),
        home_a_did,
        seq_did,
        s2s_secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.sendMessage".to_string(),
            actor_did: fixture.sender_did.clone(),
            actor_device_id: fixture.sender_device_id,
            signed_request: fixture.signed_request.clone(),
        },
    )
    .await
    .expect("relay group sendMessage to sequencer");

    assert_eq!(relay_out.entry["seq"].as_u64(), Some(4));
    assert_eq!(
        relay_out.entry["sequencerReceipt"]["sequencerDid"], seq_did,
        "sequenced cross-server group entry must carry I13 receipt"
    );

    // Sequencer fans out sequenced entry to Bob's home DS (`deliverGroupEntry`)!
    deliver_group_entry_to_remote_home(
        &format!("http://{home_b_addr}"),
        seq_did,
        home_b_did,
        s2s_secret,
        &DeliverGroupEntryRequest {
            conversation_id: fixture.conversation_id,
            generation: 0,
            space_uri: format!(
                "at://{seq_did}/space/blue.catbird.labyrinth.conversation/{}-0",
                fixture.conversation_id
            ),
            recipient_dids: vec![fixture.recipient_did.clone()],
            recipient_devices: vec![(fixture.recipient_did.clone(), fixture.recipient_device_id)],
            entry: relay_out.entry.clone(),
        },
    )
    .await
    .expect("deliverGroupEntry to remote home DS");

    let replicated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool_home_b)
    .await
    .unwrap();
    assert_eq!(
        replicated_count, 1,
        "remote home DS must replicate delivered group entry"
    );

    pool_seq.close().await;
    pool_home_b.close().await;
}

#[tokio::test]
async fn stateless_3a_space_credential_and_read_relays_preserve_headers_reject_ssrf_and_write_zero_rows(
) {
    let _env_guard = ENV_LOCK.lock().await;
    let authority_did = "did:web:remote-space.example.com";
    let home_did = "did:web:chat.catbird.blue";
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://remote-space.example.com");

    let db_remote = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_remote = db_remote.connect(2).await;
    http::ensure_fence(&pool_remote).await;
    let remote_fixture =
        seed_clean_slate_application_fixture(&pool_remote, false, authority_did, None)
            .await
            .unwrap();
    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(remote_fixture.conversation_id)
    .fetch_one(&pool_remote)
    .await
    .unwrap();

    std::env::set_var("SERVICE_DID", home_did);
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    // Start remote SpaceHost + mock writer PDS returning Atproto-Space-Mac!
    let authority_key = P256SigningKey::from_bytes((&[0x71u8; 32]).into()).unwrap();
    let user_pds_key = P256SigningKey::from_bytes((&[0x72u8; 32]).into()).unwrap();
    let remote_host = Arc::new(SpaceHostRuntime::new(
        pool_remote.clone(),
        SpaceHostConfig::for_test(authority_did.to_string(), authority_key),
    ));
    remote_host.register_test_did_endpoint(
        &remote_fixture.sender_did,
        user_pds_key.verifying_key(),
        "http://127.0.0.1:9",
    );

    let captured_read: Arc<Mutex<Option<CapturedUpstreamRead>>> = Arc::new(Mutex::new(None));
    let cap_clone = captured_read.clone();
    let remote_router = space_host_router(remote_host).route(
        "/xrpc/com.atproto.space.getBlob",
        get(
            move |headers: HeaderMap, Query(q): Query<BTreeMap<String, String>>| {
                let cap = cap_clone.clone();
                async move {
                    *cap.lock().unwrap() = Some(CapturedUpstreamRead {
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        audience: headers
                            .get("atproto-space-audience")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        want_mac: headers
                            .get("atproto-space-want-mac")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        sig_input: headers
                            .get("signature-input")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        sig: headers
                            .get("signature")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        query: Some(
                            q.iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join("&"),
                        ),
                    });
                    (
                        StatusCode::OK,
                        [
                            ("content-type", "application/octet-stream"),
                            ("atproto-space-mac", "enc=:AAECAw==:,mac=:BAUGBw==:"),
                        ],
                        b"ciphertext-space-blob-bytes".as_slice(),
                    )
                        .into_response()
                }
            },
        ),
    );
    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(remote_listener, remote_router).await.unwrap();
    });

    register_test_space_relay_target(authority_did, &format!("http://{remote_addr}"));

    // Home mls-ds for sender_did
    let db_home = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_home = db_home.connect(4).await;
    http::ensure_fence(&pool_home).await;
    let home_fixture = seed_clean_slate_application_fixture(&pool_home, false, home_did, None)
        .await
        .unwrap();
    // Align sender DID on home_db to remote_fixture.sender_did by enrolling a device for remote_fixture.sender_did
    let user_did = remote_fixture.sender_did.clone();
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING")
        .bind(&user_did)
        .execute(&pool_home)
        .await
        .unwrap();
    let dev_p256 = http::random_p256();
    let dev_jwk = http::public_jwk(&dev_p256);
    let dev_jkt = http::jwk_thumbprint(&dev_jwk);
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Mac', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp())",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&dev_jkt)
    .execute(&pool_home)
    .await
    .unwrap();
    let user_dev = http::Device {
        did: user_did.clone(),
        device_id,
        jkt: dev_jkt,
        signing: dev_p256,
        jwk: dev_jwk,
    };
    http::cache_device_did(&user_dev).await;
    let _ = home_fixture;

    let home_router = http::router_for_authenticated_acceptance(pool_home.clone()).await;

    let rows_before = count_mutable_chat_rows(&pool_home).await;

    // 1. relaySpaceCredential exchanges delegation token via home mls-ds with ZERO DB writes!
    let now_sec = Utc::now().timestamp() as u64;
    let pop_key = P256SigningKey::from_bytes((&[0x73u8; 32]).into()).unwrap();
    let cnf_kid = encode_p256_did_key(&P256PublicKey::from(pop_key.verifying_key()));
    let del_token = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: user_pds_key,
            kid: "#atproto".to_string(),
        },
        &SpaceTokenClaims {
            iss: user_did.clone(),
            sub: space_uri.clone(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: "relay-del-1".into(),
            cnf_kid: None,
        },
    )
    .unwrap();

    let (cred_status, cred_resp) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": del_token,
                "cnfKey": cnf_kid,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        cred_status,
        StatusCode::OK,
        "relaySpaceCredential failed: {cred_resp}"
    );
    let cred_jwt = cred_resp["credential"].as_str().unwrap().to_string();
    assert!(cred_resp["expiresAt"].as_str().is_some());

    // 2. relaySpaceRead rejects disallowed write NSID (`com.atproto.space.putRecord`) with 400 InvalidNsid!
    let pop_secret = P256Secret::from_slice(&pop_key.to_bytes()).unwrap();
    let signed_hdrs = sign_credential_request(
        &pop_secret,
        &cred_jwt,
        authority_did,
        now_sec,
        "relay-read-1",
    )
    .unwrap();
    let sig_input = signed_hdrs.signature_input.clone();
    let sig_val = signed_hdrs.signature.clone();

    let (bad_nsid_status, bad_nsid_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceRead",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "targetDid": authority_did,
                "nsid": "com.atproto.space.putRecord",
                "credential": cred_jwt,
                "spaceAudience": authority_did,
                "signatureInput": sig_input,
                "signature": sig_val,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(bad_nsid_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_nsid_body["error"], "InvalidNsid");

    // 3. relaySpaceRead rejects SSRF target DID (`did:web:169.254.169.254`) with 400 InvalidTargetEndpoint!
    let (ssrf_status, ssrf_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceRead",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "targetDid": "did:web:169.254.169.254",
                "nsid": "com.atproto.space.getBlob",
                "credential": cred_jwt,
                "spaceAudience": authority_did,
                "signatureInput": sig_input,
                "signature": sig_val,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(ssrf_status, StatusCode::BAD_REQUEST);
    assert_eq!(ssrf_body["error"], "InvalidTargetEndpoint");

    // 4. Valid relaySpaceRead forwards exact headers, returns raw bytes, preserves Atproto-Space-Mac,
    //    sets Access-Control-Expose-Headers: Atproto-Space-Mac, and writes ZERO DB rows!
    let want_mac = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
    let read_req = http::unsigned_json_request(
        &user_dev,
        "blue.catbird.chat.relaySpaceRead",
        serde_json::to_vec(&json!({
            "actorDeviceId": device_id,
            "targetDid": authority_did,
            "nsid": "com.atproto.space.getBlob",
            "query": format!("space={}&cid=bafkreiaaaa", urlencoding::encode(&space_uri)),
            "credential": cred_jwt,
            "spaceAudience": authority_did,
            "wantMac": want_mac,
            "signatureInput": sig_input,
            "signature": sig_val,
        }))
        .unwrap(),
    );
    let read_resp = tower_util::ServiceExt::oneshot(home_router, read_req)
        .await
        .unwrap();
    assert_eq!(read_resp.status(), StatusCode::OK);
    assert_eq!(
        read_resp
            .headers()
            .get("atproto-space-mac")
            .and_then(|v| v.to_str().ok()),
        Some("enc=:AAECAw==:,mac=:BAUGBw==:")
    );
    let expose = read_resp
        .headers()
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        expose.to_ascii_lowercase().contains("atproto-space-mac"),
        "Access-Control-Expose-Headers must expose Atproto-Space-Mac, got {expose:?}"
    );
    let raw_bytes = axum::body::to_bytes(read_resp.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(&raw_bytes[..], b"ciphertext-space-blob-bytes");

    let upstream = captured_read.lock().unwrap().clone().expect("upstream hit");
    assert_eq!(
        upstream.auth.as_deref(),
        Some(format!("Atproto-Space-Credential {cred_jwt}").as_str())
    );
    assert_eq!(upstream.audience.as_deref(), Some(authority_did));
    assert_eq!(upstream.want_mac.as_deref(), Some(want_mac));
    assert_eq!(upstream.sig_input.as_deref(), Some(sig_input.as_str()));
    assert_eq!(upstream.sig.as_deref(), Some(sig_val.as_str()));
    assert!(upstream
        .query
        .as_deref()
        .unwrap_or("")
        .contains("cid=bafkreiaaaa"));

    let rows_after = count_mutable_chat_rows(&pool_home).await;
    assert_eq!(
        rows_after, rows_before,
        "3A Space credential & read relays MUST write zero rows in home mls-ds DB"
    );

    pool_home.close().await;
    pool_remote.close().await;
}

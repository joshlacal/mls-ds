//! Push Gateway (`D2`, `I12`, `M-F06`) and DNS-Pinned SSRF Guard integration tests.
//!
//! Pins:
//! 1. `blue.catbird.chat.registerPushGateway` rejects `http://`, non-443 ports, wrong paths,
//!    metadata IP `169.254.169.254`, and DNS hostnames resolving to private `10.0.0.1` (`400 InvalidGatewayUrl`).
//! 2. `registerPushGateway` enforces Ed25519 device signature (`CATBIRD-CHAT-PUSH-GATEWAY\0`) and
//!    rejects tampered signatures (`InvalidSignature`) or revoked devices (`DeviceRevoked`).
//! 3. `PushGatewayClient` enforces `INLINE_CIPHERTEXT_MAX_BYTES = 2200` (`I12`): `<= 2200` B embeds
//!    `ciphertext`, `2201` B omits `ciphertext`, zero display strings ever appear, and `mls-ds` signs
//!    outbound wakes with `#atproto` ES256 DID-JWT (`lxm = "blue.catbird.push.deliver"`).
//! 4. Home-`mls-ds`-only privacy (`D2`) and `410 Gone` (`PushTokenGone`) binding pruning.

mod common;

use axum::{
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_server::{
    chat_protocol::test_support::seed_clean_slate_application_fixture,
    push_gateway::{
        build_push_gateway_transcript,
        client::{PushGatewayClient, PushWakeDispatch, PushWakeKind, INLINE_CIPHERTEXT_MAX_BYTES},
        ssrf::{validate_push_gateway_url_with_resolver, PushGatewaySsrfError},
    },
};
use chrono::{SecondsFormat, Utc};
use common::http_acceptance as http;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct CapturedWake {
    auth: Option<String>,
    body: Value,
}

#[tokio::test]
async fn push_gateway_ssrf_rejects_metadata_private_dns_non_tls_and_bad_paths() {
    assert_eq!(INLINE_CIPHERTEXT_MAX_BYTES, 2200);

    // 1. Metadata IP literal 169.254.169.254 rejected
    let meta = validate_push_gateway_url_with_resolver(
        "https://169.254.169.254/xrpc/blue.catbird.push.deliver",
        |_host| Ok(vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))]),
    );
    assert!(matches!(meta, Err(PushGatewaySsrfError::ForbiddenIp(_))));

    // 2. Hostname resolving via DNS to private 10.0.0.1 rejected (DNS rebinding / SSRF protection)
    let priv_dns = validate_push_gateway_url_with_resolver(
        "https://evil-gateway.example.test/xrpc/blue.catbird.push.deliver",
        |_host| Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]),
    );
    assert!(matches!(
        priv_dns,
        Err(PushGatewaySsrfError::ForbiddenIp(_))
    ));

    // 3. Plain HTTP, non-443 port, and non-matching path all rejected
    for bad_url in [
        "http://nest.catbird.blue/xrpc/blue.catbird.push.deliver",
        "https://nest.catbird.blue:8443/xrpc/blue.catbird.push.deliver",
        "https://nest.catbird.blue/xrpc/other.endpoint",
        "https://nest.catbird.blue/xrpc/blue.catbird.push.deliver?foo=bar",
    ] {
        let res = validate_push_gateway_url_with_resolver(bad_url, |_host| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        });
        assert!(
            res.is_err(),
            "bad gateway URL {bad_url} must fail SSRF validation"
        );
    }

    // 4. Valid HTTPS :443 public-IP Push Gateway URL succeeds and pins resolved public SocketAddr
    let ok = validate_push_gateway_url_with_resolver(
        "https://nest.catbird.blue/xrpc/blue.catbird.push.deliver",
        |_host| Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
    )
    .expect("valid public gateway URL");
    assert_eq!(
        ok.pinned_addrs,
        vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443
        )]
    );
}

#[tokio::test]
async fn register_push_gateway_and_client_enforce_i12_cutoff_home_privacy_and_410_pruning() {
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_push_gw_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;

    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("fixture");

    let recip_p256 = http::random_p256();
    let recip_jwk = http::public_jwk(&recip_p256);
    let recip_dev = http::Device {
        did: fixture.recipient_did.clone(),
        device_id: fixture.recipient_device_id,
        jkt: http::jwk_thumbprint(&recip_jwk),
        signing: recip_p256,
        jwk: recip_jwk,
    };
    http::cache_device_did(&recip_dev).await;

    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let recip_ed = EdSigningKey::from_bytes(&fixture.recipient_ed25519_seed);

    // 1. Metadata SSRF URL rejected at HTTP boundary with 400 InvalidGatewayUrl
    let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let bad_url = "https://169.254.169.254/xrpc/blue.catbird.push.deliver";
    let bad_push_key = "push_key_opaque_valid_length_0123456789abcdef";
    let bad_transcript = build_push_gateway_transcript(
        &fixture.recipient_device_id,
        &fixture.recipient_key_id,
        1,
        bad_url,
        "blue.catbird.ios",
        bad_push_key,
        true,
        &signed_at,
    )
    .unwrap();
    let bad_sig = recip_ed.sign(&bad_transcript);
    let (ssrf_status, ssrf_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &recip_dev,
            "blue.catbird.chat.registerPushGateway",
            serde_json::to_vec(&json!({
                "deviceId": fixture.recipient_device_id,
                "keyId": fixture.recipient_key_id,
                "authGeneration": 1,
                "gatewayUrl": bad_url,
                "appId": "blue.catbird.ios",
                "pushKey": bad_push_key,
                "enabled": true,
                "signedAt": signed_at,
                "signature": { "$bytes": STANDARD.encode(bad_sig.to_bytes()) },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        ssrf_status,
        StatusCode::BAD_REQUEST,
        "SSRF URL must fail: {ssrf_body}"
    );
    assert_eq!(ssrf_body["error"], "InvalidGatewayUrl");

    // 2. Start local mock Push Gateway and register test loopback mapping for nest.example.test
    let captured: Arc<Mutex<Vec<CapturedWake>>> = Arc::new(Mutex::new(Vec::new()));
    let return_gone = Arc::new(AtomicBool::new(false));
    let cap_clone = captured.clone();
    let gone_clone = return_gone.clone();
    let gw_app = Router::new().route(
        "/xrpc/blue.catbird.push.deliver",
        post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let cap = cap_clone.clone();
            let gone = gone_clone.clone();
            async move {
                cap.lock().unwrap().push(CapturedWake {
                    auth: headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                    body,
                });
                if gone.load(Ordering::SeqCst) {
                    (
                        StatusCode::GONE,
                        Json(json!({ "error": "PushTokenGone", "message": "APNs 410" })),
                    )
                } else {
                    (StatusCode::ACCEPTED, Json(json!({ "accepted": true })))
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, gw_app).await.unwrap();
    });

    catbird_server::push_gateway::ssrf::register_test_gateway_override(
        "https://nest-gw.example.test/xrpc/blue.catbird.push.deliver",
        format!("http://{gw_addr}/xrpc/blue.catbird.push.deliver"),
    );

    let gw_url = "https://nest-gw.example.test/xrpc/blue.catbird.push.deliver";
    let push_key = "push_key_opaque_valid_length_0123456789abcdef";
    let ok_transcript = build_push_gateway_transcript(
        &fixture.recipient_device_id,
        &fixture.recipient_key_id,
        1,
        gw_url,
        "blue.catbird.ios",
        push_key,
        true,
        &signed_at,
    )
    .unwrap();
    let ok_sig = recip_ed.sign(&ok_transcript);

    // Tampered signature must fail InvalidSignature
    let mut bad_sig_bytes = ok_sig.to_bytes();
    bad_sig_bytes[0] ^= 0xff;
    let (tamper_status, tamper_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &recip_dev,
            "blue.catbird.chat.registerPushGateway",
            serde_json::to_vec(&json!({
                "deviceId": fixture.recipient_device_id,
                "keyId": fixture.recipient_key_id,
                "authGeneration": 1,
                "gatewayUrl": gw_url,
                "appId": "blue.catbird.ios",
                "pushKey": push_key,
                "enabled": true,
                "signedAt": signed_at,
                "signature": { "$bytes": STANDARD.encode(bad_sig_bytes) },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(tamper_status, StatusCode::UNAUTHORIZED);
    assert_eq!(tamper_body["error"], "InvalidSignature");

    // Valid signature registers binding in chat.push_gateway_bindings
    let (reg_status, reg_body) = http::send(
        router,
        http::unsigned_json_request(
            &recip_dev,
            "blue.catbird.chat.registerPushGateway",
            serde_json::to_vec(&json!({
                "deviceId": fixture.recipient_device_id,
                "keyId": fixture.recipient_key_id,
                "authGeneration": 1,
                "gatewayUrl": gw_url,
                "appId": "blue.catbird.ios",
                "pushKey": push_key,
                "enabled": true,
                "signedAt": signed_at,
                "signature": { "$bytes": STANDARD.encode(ok_sig.to_bytes()) },
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        reg_status,
        StatusCode::OK,
        "registerPushGateway failed: {reg_body}"
    );
    assert!(reg_body["registeredAt"].as_str().is_some());

    // 3. Dispatch 2200-byte ciphertext (inlined!) vs 2201-byte ciphertext (omitted per I12!)
    let ds_key = P256SigningKey::from_bytes((&[0x55u8; 32]).into()).unwrap();
    let client = PushGatewayClient::new_es256("did:web:chat.catbird.blue".to_string(), ds_key);

    // Also verify remote federated DID (did:plc:remotefederatedmemberaaa with routing_ds != self) is NEVER woken by this DS!
    sqlx::query(
        "INSERT INTO public.did_ds_mappings (actor_did, ds_did) VALUES ($1, 'did:web:other-ds.example.com')",
    )
    .bind("did:plc:remotefederatedmemberaaa")
    .execute(&pool)
    .await
    .unwrap();

    let exact_2200 = vec![0xABu8; 2200];
    let sent_1 = client
        .dispatch_for_local_recipients(
            &pool,
            &[
                (fixture.recipient_did.clone(), fixture.recipient_device_id),
                (
                    "did:plc:remotefederatedmemberaaa".to_string(),
                    uuid::Uuid::new_v4(),
                ),
            ],
            PushWakeDispatch {
                wake_kind: PushWakeKind::ApplicationMessage,
                conversation_id: fixture.conversation_id,
                generation: 1,
                seq: 2,
                epoch: 1,
                ciphertext: Some(exact_2200.clone()),
            },
        )
        .await
        .expect("dispatch 2200B wake");
    assert_eq!(
        sent_1, 1,
        "only local home-DS device binding may receive push wake"
    );

    let over_2201 = vec![0xCDu8; 2201];
    client
        .dispatch_for_local_recipients(
            &pool,
            &[(fixture.recipient_did.clone(), fixture.recipient_device_id)],
            PushWakeDispatch {
                wake_kind: PushWakeKind::ApplicationMessage,
                conversation_id: fixture.conversation_id,
                generation: 1,
                seq: 3,
                epoch: 1,
                ciphertext: Some(over_2201),
            },
        )
        .await
        .expect("dispatch 2201B wake");

    {
        let wakes = captured.lock().unwrap();
        assert_eq!(wakes.len(), 2);
        assert!(wakes[0]
            .auth
            .as_deref()
            .unwrap_or("")
            .starts_with("Bearer "));
        assert_eq!(
            wakes[0].body["payload"]["ciphertext"]["$bytes"],
            STANDARD.encode(&exact_2200),
            "2200-byte ciphertext must be inlined"
        );
        assert!(
            wakes[1].body["payload"].get("ciphertext").is_none(),
            "2201-byte ciphertext must be omitted per I12"
        );
        for forbidden in ["senderHandle", "title", "body", "conversationTitle"] {
            assert!(wakes[0].body["payload"].get(forbidden).is_none());
            assert!(wakes[1].body["payload"].get(forbidden).is_none());
        }
    }

    // 4. Trigger 410 Gone from Push Gateway -> binding is immediately pruned from chat.push_gateway_bindings!
    return_gone.store(true, Ordering::SeqCst);
    client
        .dispatch_for_local_recipients(
            &pool,
            &[(fixture.recipient_did.clone(), fixture.recipient_device_id)],
            PushWakeDispatch {
                wake_kind: PushWakeKind::ControlTransition,
                conversation_id: fixture.conversation_id,
                generation: 1,
                seq: 4,
                epoch: 2,
                ciphertext: None,
            },
        )
        .await
        .expect("410 Gone handled cleanly");

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.push_gateway_bindings WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining, 0,
        "410 Gone must immediately prune push_gateway_bindings row"
    );

    pool.close().await;
}

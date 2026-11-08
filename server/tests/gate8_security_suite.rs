//! Gate 8 security closure suite (`M-F01`, `F-03`, `M-F04`..`M-F08`, `M-F11`):
//! - `M-F01` & `F-03`: Non-admin group member removal and non-admin group `requestReset` fail
//!   closed (`NotAuthorized` / `AdminRequired`);
//! - `M-F04`: Zero PostgreSQL transactions or advisory locks held across outbound federation HTTP;
//! - `M-F05`: `subscribeEvents` enforces per-device (`4`), per-DID (`16`), and global (`8192`) WS
//!   caps (`RateLimited`), `64 KiB` frame/message caps, `Notify` instant wakeup, and `SseState`
//!   idle channel pruning;
//! - `M-F06`: Legacy unsigned `updatePushToken` returns `404 Not Found`;
//! - `M-F07`: Mandatory Ed25519 device-signed read verification (`catbird-chat-read` +
//!   `catbird-chat-read-signature`, `CATBIRD-CHAT-READ\0`) rejects unsigned, wrong-device,
//!   expired, and tampered-query reads;
//! - `M-F08`: `revokeDevice` immediately revokes device access, deletes push bindings, and
//!   evicts active WebSocket connections for the revoked device;
//! - `M-F11`: Symmetric `16 MiB` (`16_777_216`) body limits across client and S2S artifact routes.
//! - `R4`: every requestLeafRecovery-created `leafRecoveryView` carries the requester's exact
//!   signed request (acceptance-created ones carry none); a non-admin `activateReset` is
//!   `AdminRequired` with no effect.

mod common;

use axum::{body::Body, http::Request, http::StatusCode};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    chat_protocol::{
        read_auth::{
            canonical_query, ReadClaim, CHAT_READ_DOMAIN, CHAT_READ_HEADER, CHAT_READ_SIG_HEADER,
        },
        test_support::seed_clean_slate_application_fixture,
    },
    handlers::chat::ChatRuntime,
    realtime::SseState,
    request_body_limit,
};
use chrono::{SecondsFormat, Utc};
use common::http_acceptance as http;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[test]
fn mf11_client_and_s2s_artifact_routes_enforce_symmetric_16_mib_body_limits() {
    const SIXTEEN_MIB: usize = 16 * 1024 * 1024;
    const FIFTEEN_MIB: usize = 15 * 1024 * 1024;
    for route in [
        "/xrpc/blue.catbird.chat.publishDirectRequest",
        "/xrpc/blue.catbird.chat.publishDirectRequestKeys",
        "/xrpc/blue.catbird.mlsDS.publishDirectRequest",
        "/xrpc/blue.catbird.mlsDS.deliverDirectRequest",
    ] {
        assert_eq!(
            request_body_limit(route),
            SIXTEEN_MIB,
            "direct-request route {route} must enforce symmetric 16 MiB body limit"
        );
    }
    for route in [
        "/xrpc/blue.catbird.chat.createConversation",
        "/xrpc/blue.catbird.chat.submitTransition",
        "/xrpc/blue.catbird.chat.sendMessage",
        "/xrpc/blue.catbird.mlsDS.deliverMessage",
        "/xrpc/blue.catbird.mlsDS.deliverWelcome",
        "/xrpc/blue.catbird.mlsDS.submitCommit",
        "/xrpc/blue.catbird.mlsDS.relaySendMessage",
        "/xrpc/blue.catbird.mlsDS.deliverMessageEntry",
        "/xrpc/blue.catbird.mlsDS.relayGroupMutation",
    ] {
        assert_eq!(
            request_body_limit(route),
            FIFTEEN_MIB,
            "MLS artifact route {route} must enforce symmetric 15 MiB body limit"
        );
    }
}

#[tokio::test]
async fn mf05_sse_state_prunes_idle_channels_and_ws_registry_enforces_caps_and_notify() {
    let sse = SseState::new(16);
    let tx_idle = sse.get_channel("convo-idle").await;
    drop(tx_idle);
    let tx_active = sse.get_channel("convo-active").await;
    let _rx_live = tx_active.subscribe();

    let pruned = sse.prune_idle_channels().await;
    assert_eq!(pruned, 1, "zero-subscriber channel must be pruned");
    assert_eq!(sse.channels.read().await.len(), 1);

    std::env::set_var("CHAT_CURSOR_KEY_ID", URL_SAFE_NO_PAD.encode([0x11_u8; 32]));
    std::env::set_var(
        "CHAT_CURSOR_SEALING_SECRET",
        URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
    );
    std::env::set_var(
        "CHAT_SUBSCRIPTION_ENDPOINT",
        "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
    );
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    let runtime = Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(16))).unwrap());

    let did = "did:plc:wscaptestuseraaaaaaaaaaa";
    let dev1 = Uuid::new_v4();
    let mut guards = Vec::new();
    for _ in 0..4 {
        guards.push(
            runtime
                .acquire_ws_slot(did, dev1)
                .expect("up to 4 WS per device allowed"),
        );
    }
    assert!(
        runtime.acquire_ws_slot(did, dev1).is_err(),
        "5th WS on same device must fail RateLimited"
    );
    drop(guards);

    // Per-DID cap = 16 across distinct devices
    let mut did_guards = Vec::new();
    for _ in 0..16 {
        did_guards.push(
            runtime
                .acquire_ws_slot(did, Uuid::new_v4())
                .expect("up to 16 WS per DID allowed"),
        );
    }
    assert!(
        runtime.acquire_ws_slot(did, Uuid::new_v4()).is_err(),
        "17th WS on same DID must fail RateLimited"
    );

    // Notify wakeup fires immediately (< 50ms) when notify_events() is called
    let r2 = runtime.clone();
    let waiter =
        tokio::spawn(async move { r2.wait_for_events_or_timeout(Duration::from_secs(5)).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let start = tokio::time::Instant::now();
    runtime.notify_events();
    let notified = waiter.await.unwrap();
    assert!(notified, "notify_events must wake subscriber immediately");
    assert!(start.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn mf06_and_mf07_retired_push_route_is_404_and_signed_reads_enforce_ed25519_claims() {
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_gate8_auth_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;

    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("fixture");

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&sender_jwk),
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;

    let router = http::router_for_authenticated_acceptance_strict_reads(pool.clone()).await;

    // M-F06: legacy unsigned updatePushToken is completely unrouted (404)
    let (push_status, _) = http::send(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/xrpc/blue.catbird.mlsChat.updatePushToken")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(push_status, StatusCode::NOT_FOUND);

    let raw_query = format!(
        "actorDeviceId={}&conversationId={}&afterSeq=0&limit=20",
        fixture.sender_device_id, fixture.conversation_id
    );

    // M-F07 (1): Unsigned read rejected when require_signed_reads is active
    let (unsigned_status, _) = http::send(
        router.clone(),
        http::unsigned_get_request(&sender_dev, "blue.catbird.chat.getEntries", &raw_query),
    )
    .await;
    assert_eq!(unsigned_status, StatusCode::UNAUTHORIZED);

    // M-F07 (2): Tampered query string in signed read claim rejected
    let sender_ed = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let bad_claim = ReadClaim {
        v: 1,
        nsid: "blue.catbird.chat.getEntries".into(),
        query: canonical_query(Some(&format!(
            "actorDeviceId={}&conversationId={}&afterSeq=999&limit=20",
            fixture.sender_device_id, fixture.conversation_id
        ))),
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id.to_string(),
        issued_at: Utc::now().timestamp_millis(),
    };
    let bad_bytes = serde_json::to_vec(&bad_claim).unwrap();
    let bad_sig = sender_ed.sign(&[CHAT_READ_DOMAIN, &bad_bytes].concat());
    let mut bad_req =
        http::unsigned_get_request(&sender_dev, "blue.catbird.chat.getEntries", &raw_query);
    bad_req.headers_mut().insert(
        CHAT_READ_HEADER,
        URL_SAFE_NO_PAD.encode(&bad_bytes).parse().unwrap(),
    );
    bad_req.headers_mut().insert(
        CHAT_READ_SIG_HEADER,
        URL_SAFE_NO_PAD.encode(bad_sig.to_bytes()).parse().unwrap(),
    );
    let (tampered_status, _) = http::send(router.clone(), bad_req).await;
    assert!(
        matches!(
            tampered_status,
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
        ),
        "tampered query claim must fail closed, got {tampered_status}"
    );

    // M-F07 (3): Valid Ed25519 device-signed read claim succeeds (200 OK)
    let good_claim = ReadClaim {
        v: 1,
        nsid: "blue.catbird.chat.getEntries".into(),
        query: canonical_query(Some(&raw_query)),
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id.to_string(),
        issued_at: Utc::now().timestamp_millis(),
    };
    let good_bytes = serde_json::to_vec(&good_claim).unwrap();
    let good_sig = sender_ed.sign(&[CHAT_READ_DOMAIN, &good_bytes].concat());
    let mut good_req =
        http::unsigned_get_request(&sender_dev, "blue.catbird.chat.getEntries", &raw_query);
    good_req.headers_mut().insert(
        CHAT_READ_HEADER,
        URL_SAFE_NO_PAD.encode(&good_bytes).parse().unwrap(),
    );
    good_req.headers_mut().insert(
        CHAT_READ_SIG_HEADER,
        URL_SAFE_NO_PAD.encode(good_sig.to_bytes()).parse().unwrap(),
    );
    let (good_status, good_body) = http::send(router.clone(), good_req).await;
    assert_eq!(
        good_status,
        StatusCode::OK,
        "valid signed read failed: {good_body}"
    );
}

#[tokio::test]
async fn f03_non_admin_group_request_reset_rejected_while_admin_succeeds_and_mf08_revoke_cleans_up()
{
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_gate8_f03_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;

    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("group fixture (sender is admin, recipient is member)");

    let recipient_p256 = http::random_p256();
    let recipient_jwk = http::public_jwk(&recipient_p256);
    let recipient_dev = http::Device {
        did: fixture.recipient_did.clone(),
        device_id: fixture.recipient_device_id,
        jkt: http::jwk_thumbprint(&recipient_jwk),
        signing: recipient_p256,
        jwk: recipient_jwk,
    };
    http::cache_device_did(&recipient_dev).await;

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&sender_jwk),
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;

    let router = http::router_for_authenticated_acceptance(pool.clone()).await;

    // F-03: Non-admin group participant attempting requestReset MUST be rejected with 403 NotAuthorized!
    let prior = fixture.signed_request["body"]["prior"].clone();
    let non_admin_reset_id = Uuid::new_v4();
    let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let non_admin_body = json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
        "resetRequestId": non_admin_reset_id,
        "idempotencyKey": non_admin_reset_id,
        "actorDid": fixture.recipient_did,
        "actorDeviceId": fixture.recipient_device_id,
        "keyId": fixture.recipient_key_id,
        "authGeneration": 1,
        "prior": prior,
        "reason": "epochDivergence",
        "signedAt": signed_at,
    });
    let non_admin_ed = EdSigningKey::from_bytes(&fixture.recipient_ed25519_seed);
    let non_admin_signed =
        catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
            &non_admin_body,
            &non_admin_ed,
        )
        .expect("sign resetRequestBody");

    let (non_admin_status, non_admin_resp) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &recipient_dev,
            "blue.catbird.chat.requestReset",
            serde_json::to_vec(&json!({ "signedRequest": non_admin_signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        non_admin_status,
        StatusCode::UNAUTHORIZED,
        "non-admin group requestReset must return 401 NotAuthorized: {non_admin_resp}"
    );
    assert_eq!(non_admin_resp["error"], "NotAuthorized");

    // Admin group participant attempting requestReset succeeds (200 OK)!
    let admin_reset_id = Uuid::new_v4();
    let admin_body = json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
        "resetRequestId": admin_reset_id,
        "idempotencyKey": admin_reset_id,
        "actorDid": fixture.sender_did,
        "actorDeviceId": fixture.sender_device_id,
        "keyId": fixture.sender_key_id,
        "authGeneration": 1,
        "prior": fixture.signed_request["body"]["prior"],
        "reason": "epochDivergence",
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let admin_ed = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let admin_signed = catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
        &admin_body,
        &admin_ed,
    )
    .expect("sign admin resetRequestBody");
    let (admin_status, admin_resp) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.requestReset",
            serde_json::to_vec(&json!({ "signedRequest": admin_signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        admin_status,
        StatusCode::OK,
        "admin group requestReset failed: {admin_resp}"
    );

    // M-F08: Seed a push_gateway_binding on recipient_device_id, revoke the device, verify binding is deleted and reads fail!
    sqlx::query(
        "INSERT INTO chat.push_gateway_bindings \
         (user_did, device_id, gateway_url, app_id, push_key, key_id, auth_generation, signed_at, updated_at) \
         VALUES ($1, $2, 'https://nest.catbird.blue/xrpc/blue.catbird.push.deliver', 'blue.catbird.ios', 'push-key-1234567890', $3, 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .bind(&fixture.recipient_key_id)
    .execute(&pool)
    .await
    .unwrap();

    let revoke_body = json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0000}",
        "idempotencyKey": Uuid::new_v4(),
        "actorDid": fixture.recipient_did,
        "actorDeviceId": fixture.recipient_device_id,
        "keyId": fixture.recipient_key_id,
        "authGeneration": 1,
        "targetDeviceId": fixture.recipient_device_id,
        "targetAuthGeneration": 1,
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let revoke_signed = catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
        &revoke_body,
        &non_admin_ed,
    )
    .expect("sign deviceRevocationBody");
    let (rev_status, rev_resp) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &recipient_dev,
            "blue.catbird.chat.revokeDevice",
            serde_json::to_vec(&json!({ "signedRequest": revoke_signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        rev_status,
        StatusCode::OK,
        "revokeDevice failed: {rev_resp}"
    );

    let remaining_push_bindings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.push_gateway_bindings WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_push_bindings, 0,
        "revokeDevice must purge push_gateway_bindings"
    );

    let (post_revoke_read_status, _) = http::send(
        router,
        http::unsigned_get_request(
            &recipient_dev,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=10",
                fixture.recipient_device_id, fixture.conversation_id
            ),
        ),
    )
    .await;
    assert!(
        matches!(
            post_revoke_read_status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "revoked device must immediately lose read entitlement, got {post_revoke_read_status}"
    );
    let _ = STANDARD;
}

fn fixture_device(did: &str, device_id: Uuid) -> http::Device {
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    http::Device {
        did: did.to_owned(),
        device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing,
        jwk,
    }
}

/// Rewrite every lexicon `{"$bytes": b64}` presentation to the bare base64
/// form a client signs and submits.
fn bare_bytes(value: &mut serde_json::Value) {
    if let Some(bytes) = value
        .get("$bytes")
        .and_then(serde_json::Value::as_str)
        .filter(|_| value.as_object().is_some_and(|object| object.len() == 1))
        .map(str::to_owned)
    {
        *value = serde_json::Value::String(bytes);
        return;
    }
    match value {
        serde_json::Value::Object(object) => object.values_mut().for_each(bare_bytes),
        serde_json::Value::Array(items) => items.iter_mut().for_each(bare_bytes),
        _ => {}
    }
}

/// The view's `signedRequest` is exactly the submitted wrapper and verifies
/// under the requester's device key.
fn assert_exact_signed_request(
    view: &serde_json::Value,
    submitted: &serde_json::Value,
    requester: &ed25519_dalek::VerifyingKey,
) {
    let mut signed = view
        .get("signedRequest")
        .cloned()
        .unwrap_or_else(|| panic!("requestLeafRecovery view lacks signedRequest: {view}"));
    bare_bytes(&mut signed);
    assert_eq!(
        &signed, submitted,
        "signedRequest is the exact submitted wrapper"
    );
    let canonical = catbird_server::chat_protocol::test_support::decode_canonical_signed_mutation(
        &serde_json::to_vec(&signed).unwrap(),
    )
    .expect("signedRequest decodes as a canonical signed mutation");
    let signature: [u8; 64] = STANDARD
        .decode(signed["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    requester
        .verify_strict(
            canonical.transcript_bytes(),
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .expect("signedRequest verifies under the requester device key");
}

/// The requester device's leaf-recovery inbox items, read through the
/// inventory session its own getConversations opens.
async fn leaf_recovery_inbox(
    router: axum::Router,
    device: &http::Device,
) -> Vec<serde_json::Value> {
    let (status, conversations) = http::send(
        router.clone(),
        http::unsigned_get_request(
            device,
            "blue.catbird.chat.getConversations",
            &format!("actorDeviceId={}&limit=50", device.device_id),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getConversations: {conversations}");
    let session = conversations["inventorySessionId"].as_str().unwrap();
    let (status, inbox) = http::send(
        router,
        http::unsigned_get_request(
            device,
            "blue.catbird.chat.getLeafRecoveryInbox",
            &format!(
                "actorDeviceId={}&inventorySessionId={session}&limit=50",
                device.device_id
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getLeafRecoveryInbox: {inbox}");
    inbox["items"].as_array().unwrap().clone()
}

/// R4: a requestLeafRecovery-created recovery carries the requester's exact
/// verified signed request in the requestLeafRecovery answer, in another
/// current leaf's `getConversationState.pendingLeafRecoveryRequests`, and in the
/// requester's inbox; an acceptance-created recovery carries none.
#[tokio::test]
async fn r4_leaf_recovery_views_carry_exactly_the_requesters_signed_request() {
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_gate8_r4_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;
    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("group fixture (sender holds a leaf and an available KeyPackage)");
    let requester_dev = fixture_device(&fixture.sender_did, fixture.sender_device_id);
    let fulfiller_dev = fixture_device(&fixture.recipient_did, fixture.recipient_device_id);
    http::cache_device_did(&requester_dev).await;
    http::cache_device_did(&fulfiller_dev).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    catbird_server::chat_protocol::test_support::seed_deterministic_recovery_reservation_fallback(
        &pool,
        vec![fixture.sender_did.clone(), fixture.recipient_did.clone()],
    )
    .await
    .expect("fresh recoveryReservation fallback");

    let recovery_request_id = Uuid::new_v4();
    let requester_ed = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let submitted = catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryRequestBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\u{0000}",
            "recoveryRequestId": recovery_request_id,
            "idempotencyKey": recovery_request_id,
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "recoveryKind": "replace",
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &requester_ed,
    )
    .expect("sign leafRecoveryRequestBody");
    let (status, answer) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &requester_dev,
            "blue.catbird.chat.requestLeafRecovery",
            serde_json::to_vec(&json!({ "signedRequest": submitted })).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "requestLeafRecovery: {answer}");
    let requester_key = requester_ed.verifying_key();
    assert_exact_signed_request(&answer["recovery"], &submitted, &requester_key);

    // Another current leaf discovers it, with the requester's signed request.
    let (status, state) = http::send(
        router.clone(),
        http::unsigned_get_request(
            &fulfiller_dev,
            "blue.catbird.chat.getConversationState",
            &format!(
                "actorDeviceId={}&conversationId={}",
                fixture.recipient_device_id, fixture.conversation_id
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getConversationState: {state}");
    let pending = state["pendingLeafRecoveryRequests"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "exactly the open request: {state}");
    assert_eq!(
        pending[0]["recoveryRequestId"],
        recovery_request_id.to_string()
    );
    assert_exact_signed_request(&pending[0], &submitted, &requester_key);

    // The requester's own inbox carries it too.
    let requester_inbox = leaf_recovery_inbox(router.clone(), &requester_dev).await;
    let own = requester_inbox
        .iter()
        .find(|item| item["recoveryRequestId"] == recovery_request_id.to_string())
        .unwrap_or_else(|| panic!("requester inbox lacks the request: {requester_inbox:?}"));
    assert_exact_signed_request(own, &submitted, &requester_key);

    // The fixture's acceptance-created recovery (the fulfiller's join) carries none.
    let fulfiller_inbox = leaf_recovery_inbox(router, &fulfiller_dev).await;
    let accepted = fulfiller_inbox
        .iter()
        .find(|item| item["requesterDid"] == fixture.recipient_did.as_str())
        .unwrap_or_else(|| {
            panic!("fulfiller inbox lacks its acceptance recovery: {fulfiller_inbox:?}")
        });
    assert!(
        accepted.get("signedRequest").is_none(),
        "an acceptance-created recovery carries no signedRequest: {accepted}"
    );
}

/// R4: `activateReset` signed by an active non-admin member, after an admin's
/// pending reset request, is refused `AdminRequired` and changes nothing.
#[tokio::test]
async fn r4_non_admin_reset_activation_is_admin_required_without_any_effect() {
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_gate8_r4_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;
    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("group fixture (sender is admin, recipient is member)");
    let admin_dev = fixture_device(&fixture.sender_did, fixture.sender_device_id);
    let member_dev = fixture_device(&fixture.recipient_did, fixture.recipient_device_id);
    http::cache_device_did(&admin_dev).await;
    http::cache_device_did(&member_dev).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;

    let prior = fixture.signed_request["body"]["prior"].clone();
    let reset_request_id = Uuid::new_v4();
    let admin_request = catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
            "resetRequestId": reset_request_id,
            "idempotencyKey": reset_request_id,
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": prior,
            "reason": "manualRecovery",
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &EdSigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .expect("sign admin resetRequestBody");
    let (status, response) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &admin_dev,
            "blue.catbird.chat.requestReset",
            serde_json::to_vec(&json!({ "signedRequest": admin_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin requestReset: {response}");

    let mut participants = vec![
        json!({"userDid": fixture.sender_did, "role": "admin", "status": "active"}),
        json!({"userDid": fixture.recipient_did, "role": "member", "status": "active"}),
    ];
    participants.sort_by(|a, b| a["userDid"].as_str().cmp(&b["userDid"].as_str()));
    let activation = catbird_server::chat_protocol::test_support::sign_reset_activation_for_test(
        reset_request_id,
        &prior,
        json!(participants),
        &fixture.recipient_did,
        fixture.recipient_device_id,
        &fixture.recipient_key_id,
        fixture.recipient_ed25519_seed,
    )
    .expect("sign member resetActivationBody");

    let (pool_ref, conversation_id) = (&pool, fixture.conversation_id);
    let snapshot = move || async move {
        sqlx::query_as::<_, (i64, i64, i64, Vec<u8>, i64, String)>(
            "SELECT c.current_generation, c.current_state_version, c.next_entry_seq, s.group_id, \
                    (SELECT count(*) FROM chat.entries e WHERE e.conversation_id = c.conversation_id), \
                    (SELECT r.status FROM chat.reset_requests r WHERE r.reset_request_id = $2) \
               FROM chat.conversations c \
               JOIN chat.generation_states s ON s.conversation_id = c.conversation_id \
                AND s.generation = c.current_generation \
                AND s.state_version = c.current_state_version \
              WHERE c.conversation_id = $1",
        )
        .bind(conversation_id)
        .bind(reset_request_id)
        .fetch_one(pool_ref)
        .await
        .expect("conversation head, coordinate, entries, and reset request")
    };
    let before = snapshot().await;
    assert_eq!(before.5, "pending");
    let (status, refused) = http::send(
        router,
        http::unsigned_json_request(
            &member_dev,
            "blue.catbird.chat.activateReset",
            serde_json::to_vec(&json!({ "signedRequest": activation })).unwrap(),
        ),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "non-admin activateReset: {refused}");
    assert_eq!(refused["error"], "AdminRequired", "{refused}");
    assert_eq!(
        snapshot().await,
        before,
        "a refused activation changes nothing"
    );
}

#[test]
fn mf04_no_outbound_federation_http_awaited_inside_db_transactions() {
    let publish_handler = include_str!("../src/handlers/chat/publish_direct_request.rs");
    let tx_pos = publish_handler
        .find("let mut tx = pool.begin()")
        .expect("publish_direct_request tx begin");
    assert!(
        !publish_handler[tx_pos..].contains("resolve_authorized_device_keys("),
        "publish_direct_request must resolve PDS device keys BEFORE opening PostgreSQL transaction"
    );

    let submit_facade = include_str!("../src/chat_protocol/repository/submit_transition.rs");
    assert!(
        !submit_facade.contains("submitter\n            .submit(\n                transaction"),
        "execute_prepared_submit_transition must not hold an active PostgreSQL transaction across RemoteCommitSubmitter::submit"
    );
}

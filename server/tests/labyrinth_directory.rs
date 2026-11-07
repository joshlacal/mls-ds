//! Clean-slate Labyrinth backend: admission, verifying `EpochPublic` head directory,
//! and chat device-key / member-device views (`G6`, `I14`, `2A`, `L-F01`, `L-F10`).
//!
//! Requires `TEST_DATABASE_URL` naming the local clean-chat gate database
//! (only its cluster is used: every test mints a private database) and
//! `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED`, like the other fresh-DB suites.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

#[path = "common/labyrinth_chain.rs"]
mod chain;

use axum::{body::Body, http::Request, http::StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use harness::*;
use serde_json::{json, Value};

use catbird_server::labyrinth::heads::{attestation_message, compute_epoch_head};

fn publish(epoch: &Value) -> Value {
    json!({ "epoch": epoch })
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admission_requires_cutover_service_auth_and_a_current_device() {
    let env = Env::new().await;
    let alice = env.account().await;

    // No token.
    let request = Request::get(format!(
        "/xrpc/{PREFIX}getChatDeviceKeys?actorDeviceId={}&did={}",
        alice.device_id, alice.did
    ))
    .body(Body::empty())
    .unwrap();
    send(&env.router, request).await.fails(401, "NotAuthorized");

    // A token minted for another NSID (lxm mismatch).
    let request = Request::get(format!(
        "/xrpc/{PREFIX}getChatDeviceKeys?actorDeviceId={}&did={}",
        alice.device_id, alice.did
    ))
    .header(
        "authorization",
        format!("Bearer {}", alice.token(&format!("{PREFIX}getEpochHead"))),
    )
    .body(Body::empty())
    .unwrap();
    send(&env.router, request).await.fails(401, "NotAuthorized");

    // Missing actorDeviceId is a malformed request.
    let nsid = format!("{PREFIX}getChatDeviceKeys");
    let request = Request::get(format!("/xrpc/{nsid}?did={}", alice.did))
        .header("authorization", format!("Bearer {}", alice.token(&nsid)))
        .body(Body::empty())
        .unwrap();
    send(&env.router, request)
        .await
        .fails(400, "InvalidRequest");

    // A device that is not registered for this DID.
    let mut stranger = alice.clone();
    stranger.device_id = uuid::Uuid::new_v4();
    stranger
        .query("getChatDeviceKeys", &[("did", alice.did.clone())])
        .await
        .fails(401, "NotAuthorized");

    // The real device works, then stops working once revoked.
    alice
        .query("getChatDeviceKeys", &[("did", alice.did.clone())])
        .await
        .ok();
    env.revoke(&alice).await;
    alice
        .query("getChatDeviceKeys", &[("did", alice.did.clone())])
        .await
        .fails(401, "DeviceRevoked");
    alice
        .call("purgeMailbox", &json!({}))
        .await
        .fails(401, "DeviceRevoked");

    // Without the chat cutover gate nothing is served.
    let gated = Env::with(false).await;
    let bob = gated.account().await;
    bob.query("getChatDeviceKeys", &[("did", bob.did.clone())])
        .await
        .fails(400, "CutoverRequired");
}

/// A `GET` of `name` by `device` with explicit read headers.
fn get_with(
    device: &Device,
    name: &str,
    query: &str,
    headers: Option<(String, String)>,
) -> Request<Body> {
    let nsid = format!("{PREFIX}{name}");
    let mut request = Request::get(format!("/xrpc/{nsid}?{query}"))
        .header("authorization", format!("Bearer {}", device.token(&nsid)));
    if let Some((read, sig)) = headers {
        request = request
            .header("catbird-labyrinth-read", read)
            .header("catbird-labyrinth-read-signature", sig);
    }
    request.body(Body::empty()).unwrap()
}

/// Finding 3: a query names its device only through a claim that device
/// signed, bound to the account, endpoint, exact query and a fresh instant.
#[tokio::test]
async fn reads_require_a_device_signed_claim_over_the_exact_query() {
    let env = Env::new().await;
    let alice = env.account().await;
    let alice2 = env.device_for(&alice.did, random_seed()).await;
    let nsid = format!("{PREFIX}getChatDeviceKeys");
    let q = format!("actorDeviceId={}&did={}", alice.device_id, alice.did);
    let ok = |device: &Device, query: &str| Some(device.read_headers(&nsid, query));

    send(&env.router, get_with(&alice, "getChatDeviceKeys", &q, None))
        .await
        .fails(400, "InvalidRequest");
    // Signed by another key (an impostor holding the account JWT).
    let mut impostor = alice.clone();
    impostor.chat_key = SigningKey::from_bytes(&random_seed());
    send(
        &env.router,
        get_with(&alice, "getChatDeviceKeys", &q, ok(&impostor, &q)),
    )
    .await
    .fails(401, "InvalidSignature");
    // Another current device of the same account cannot be named: its claim
    // carries its own deviceId, not actorDeviceId.
    send(
        &env.router,
        get_with(&alice, "getChatDeviceKeys", &q, ok(&alice2, &q)),
    )
    .await
    .fails(400, "InvalidRequest");
    // Claim over another query, another endpoint, or a stale instant.
    let tampered = format!("{q}&limit=1");
    send(
        &env.router,
        get_with(&alice, "getChatDeviceKeys", &tampered, ok(&alice, &q)),
    )
    .await
    .fails(400, "InvalidRequest");
    let other_nsid = Some(alice.read_headers(&format!("{PREFIX}getEpochHead"), &q));
    send(
        &env.router,
        get_with(&alice, "getChatDeviceKeys", &q, other_nsid),
    )
    .await
    .fails(400, "InvalidRequest");
    let stale = chrono::Utc::now().timestamp_millis() - 301_000;
    let old = Some(alice.read_headers_at(&nsid, &q, stale));
    send(&env.router, get_with(&alice, "getChatDeviceKeys", &q, old))
        .await
        .fails(400, "InvalidRequest");
    // Parameter order and encoding do not matter; the canonical form does.
    let reordered = format!("limit=5&{q}");
    let canonical_twin = format!("{q}&limit=5");
    send(
        &env.router,
        get_with(
            &alice,
            "getChatDeviceKeys",
            &reordered,
            ok(&alice, &canonical_twin),
        ),
    )
    .await
    .ok();
    send(
        &env.router,
        get_with(&alice, "getChatDeviceKeys", &q, ok(&alice, &q)),
    )
    .await
    .ok();
}

#[tokio::test]
async fn retired_mailbox_virtual_device_and_orf_endpoints_return_404() {
    let env = Env::new().await;
    let alice = env.account().await;
    for query_name in [
        "listDevices",
        "listEpochs",
        "getVirtualDevice",
        "listVirtualDevices",
    ] {
        let reply = alice.query(query_name, &[]).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{query_name} must be unmounted (404)"
        );
    }
    for proc_name in [
        "createDevice",
        "createEpoch",
        "createVirtualDevice",
        "touchVirtualDevice",
        "deleteVirtualDevice",
        "registerOrfState",
        "deleteOrfState",
    ] {
        let reply = alice.call(proc_name, &json!({})).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{proc_name} must be unmounted (404)"
        );
    }
}

#[tokio::test]
async fn writes_require_a_valid_signed_write_body() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, _) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    let nsid = format!("{PREFIX}publishEpochHead");
    let input = serde_json::to_vec(&publish(&genesis)).unwrap();
    let op = *uuid::Uuid::new_v4().as_bytes();

    let post = |write: String, sig: String, body: Vec<u8>| {
        Request::post(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", alice.token(&nsid)))
            .header("catbird-labyrinth-write", write)
            .header("catbird-labyrinth-write-signature", sig)
            .body(Body::from(body))
            .unwrap()
    };

    // Signature by a key that is not the device's chat key.
    let mut impostor = alice.clone();
    impostor.chat_key = SigningKey::from_bytes(&random_seed());
    let (write, sig) = impostor.write_headers(&nsid, &input, op);
    send(&env.router, post(write, sig, input.clone()))
        .await
        .fails(401, "InvalidSignature");

    // Body digest does not match the signed payloadSha256.
    let (write, sig) = alice.write_headers(&nsid, &input, op);
    let mut tampered = input.clone();
    tampered.push(b' ');
    send(&env.router, post(write, sig, tampered))
        .await
        .fails(400, "InvalidRequest");

    // Write body bound to another endpoint.
    let (write, sig) = alice.write_headers(&format!("{PREFIX}purgeMailbox"), &input, op);
    send(&env.router, post(write, sig, input.clone()))
        .await
        .fails(400, "InvalidRequest");

    // Missing headers.
    let request = Request::post(format!("/xrpc/{nsid}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", alice.token(&nsid)))
        .body(Body::from(input.clone()))
        .unwrap();
    send(&env.router, request)
        .await
        .fails(400, "InvalidRequest");

    // The genuine request succeeds.
    let (write, sig) = alice.write_headers(&nsid, &input, op);
    send(&env.router, post(write, sig, input)).await.ok();
}

// ---------------------------------------------------------------------------
// Head chain acceptance
// ---------------------------------------------------------------------------

/// The vector DID's two chat devices (epochs 0-1 are attested by d0, epoch 2 by d1).
async fn vector_devices(env: &Env, v: &Vectors) -> (Device, Device) {
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    (d0, d1)
}

#[tokio::test]
async fn head_chain_accepts_crate_vectors_in_order_and_serves_them() {
    let env = Env::new().await;
    let v = vectors();
    let (d0, d1) = vector_devices(&env, &v).await;
    let reader = env.account().await;

    reader
        .query("getEpochHead", &[("did", v.did.clone())])
        .await
        .fails(404, "EpochNotFound");
    for epoch in &v.chain[..2] {
        d0.call("publishEpochHead", &publish(epoch)).await.ok();
    }
    d1.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .ok();
    // Re-publishing an existing epoch's head is accepted (identical bytes).
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .ok();

    let latest = reader
        .query("getEpochHead", &[("did", v.did.clone())])
        .await;
    assert_eq!(latest.ok()["epoch"], v.chain[2]);
    assert!(latest.json["receivedAt"].as_str().unwrap().ends_with('Z'));
    let first = reader
        .query(
            "getEpochHead",
            &[("did", v.did.clone()), ("epochNumber", "0".into())],
        )
        .await;
    assert_eq!(first.ok()["epoch"], v.chain[0]);
    reader
        .query(
            "getEpochHead",
            &[("did", v.did.clone()), ("epochNumber", "7".into())],
        )
        .await
        .fails(404, "EpochNotFound");
}

#[tokio::test]
async fn head_chain_rejects_gaps_non_genesis_starts_and_forks() {
    let env = Env::new().await;
    let v = vectors();
    let (d0, d1) = vector_devices(&env, &v).await;

    // Not genesis on an empty chain.
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .ok();
    // Skips epoch 1.
    d1.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .ok();
    // A different epoch 1 (same predecessor) is a fork -> 409 EpochHeadConflict.
    d0.call("publishEpochHead", &publish(&v.fork))
        .await
        .fails(409, "EpochHeadConflict");
}

/// Re-attest `epoch` after replacing its predecessor link, recomputing the
/// head as the server does. Its `selfSig` no longer verifies.
fn relinked(did: &str, epoch: &Value, previous: [u8; 32], seed: [u8; 32]) -> Value {
    let mut e = epoch.clone();
    let n = e["epochNumber"].as_u64().unwrap();
    let auth: [u8; 32] = unb(&e["authPubkey"]).try_into().unwrap();
    let signing: [u8; 32] = unb(&e["signingPubkey"]).try_into().unwrap();
    let members_hash: [u8; 32] = unb(&e["membersHash"]).try_into().unwrap();
    let head = compute_epoch_head(
        n,
        &auth,
        &unb(&e["encryptionPubkey"]),
        &signing,
        &members_hash,
        Some(&previous),
        did,
    );
    let key = SigningKey::from_bytes(&seed);
    e["previousEpochHead"] = b(&previous);
    e["epochHead"] = b(&head);
    e["attestation"]["sig"] = b(&key.sign(&attestation_message(did, &head)).to_bytes());
    e
}

#[tokio::test]
async fn head_chain_requires_a_recomputable_self_signed_attested_head() {
    let env = Env::new().await;
    let v = vectors();
    let (d0, _d1) = vector_devices(&env, &v).await;
    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .ok();

    // Re-headed onto another predecessor: selfSig no longer verifies.
    let wrong_link = relinked(&v.did, &v.chain[1], [0xAB; 32], v.seeds[0]);
    d0.call("publishEpochHead", &publish(&wrong_link))
        .await
        .fails(400, "InvalidRequest");
    // A head that does not recompute from its keys.
    let mut tampered = v.chain[1].clone();
    tampered["authPubkey"] = b(&[0x5A; 32]);
    d0.call("publishEpochHead", &publish(&tampered))
        .await
        .fails(400, "InvalidRequest");
    // A forged attestation or self signature.
    let mut forged = v.chain[1].clone();
    forged["attestation"]["sig"] = b(&[0x11; 64]);
    d0.call("publishEpochHead", &publish(&forged))
        .await
        .fails(400, "InvalidRequest");
    let mut forged = v.chain[1].clone();
    forged["selfSig"] = v.chain[0]["selfSig"].clone();
    d0.call("publishEpochHead", &publish(&forged))
        .await
        .fails(400, "InvalidRequest");
    // A head for another DID (the caller's own DID is always the subject).
    let other = env.account().await;
    other
        .call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .fails(400, "InvalidRequest");
}

#[tokio::test]
async fn prev_sig_must_be_signed_by_the_previous_epochs_key() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, g) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&genesis))
        .await
        .ok();
    // Correct head, self signature and attestation, but prevSig by a key
    // that is not epoch 0's.
    let (bad, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), Some([9; 32]));
    alice
        .call("publishEpochHead", &publish(&bad))
        .await
        .fails(400, "InvalidRequest");
    let (good, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), None);
    alice.call("publishEpochHead", &publish(&good)).await.ok();
}

#[tokio::test]
async fn head_attestation_must_be_the_callers_own_chat_key() {
    let env = Env::new().await;
    let v = vectors();
    let (d0, d1) = vector_devices(&env, &v).await;
    for epoch in &v.chain[..2] {
        d0.call("publishEpochHead", &publish(epoch)).await.ok();
    }
    // Epoch 2 is attested by d1's key: d0 cannot publish it.
    d0.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .fails(400, "AttestationNotCaller");
    // d1 cannot re-publish d0's epoch either.
    d1.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .fails(400, "AttestationNotCaller");
    // Once d1 is revoked it cannot act at all.
    env.revoke(&d1).await;
    d1.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .fails(401, "DeviceRevoked");
}

#[tokio::test]
async fn a_space_hosted_account_publishes_heads_and_rejects_cross_device_forgeries() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, g) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    let (one, l1) = chain::epoch_public(&alice, 1, [2; 32], Some(g), None);

    // Genesis first, then each number once, chained.
    alice
        .call("publishEpochHead", &publish(&one))
        .await
        .fails(400, "InvalidEpochChain");
    alice
        .call("publishEpochHead", &publish(&genesis))
        .await
        .ok();
    let (bad, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), Some([9; 32]));
    alice
        .call("publishEpochHead", &publish(&bad))
        .await
        .fails(400, "InvalidRequest");
    alice.call("publishEpochHead", &publish(&one)).await.ok();
    // Re-publishing identical bytes is fine; another head for 1 is a fork.
    alice.call("publishEpochHead", &publish(&one)).await.ok();
    let (fork, _) = chain::epoch_public(&alice, 1, [3; 32], Some(g), None);
    alice
        .call("publishEpochHead", &publish(&fork))
        .await
        .fails(409, "EpochHeadConflict");

    // Another chat device of the DID cannot publish a head attested by
    // alice's key, nor publish without epoch 1's signing key (`prevSig`).
    let other = env.device_for(&alice.did, random_seed()).await;
    let (two, _) = chain::epoch_public(&alice, 2, [4; 32], Some(l1), None);
    other
        .call("publishEpochHead", &publish(&two))
        .await
        .fails(400, "AttestationNotCaller");
    let (rogue_two, _) = chain::epoch_public(&other, 2, [5; 32], Some(l1), Some([8; 32]));
    other
        .call("publishEpochHead", &publish(&rogue_two))
        .await
        .fails(400, "InvalidRequest");

    alice.call("publishEpochHead", &publish(&two)).await.ok();
    let latest = other
        .query("getEpochHead", &[("did", alice.did.clone())])
        .await;
    assert_eq!(latest.ok()["epoch"], two);
}

#[tokio::test]
async fn a_space_hosted_account_deletes_its_data_and_advances_floor() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, _) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&genesis))
        .await
        .ok();

    let other = env.device_for(&alice.did, random_seed()).await;
    other.call("deleteAccountData", &json!({})).await.ok();
    other
        .query("getEpochHead", &[("did", alice.did.clone())])
        .await
        .fails(404, "EpochNotFound");
    // Epoch 0 cannot be reused after purge; restarting at floor + 1 succeeds.
    alice
        .call("publishEpochHead", &publish(&genesis))
        .await
        .fails(400, "InvalidEpochChain");
    let (restarted, _) = chain::epoch_public(&alice, 1, [9; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&restarted))
        .await
        .ok();
}

// ---------------------------------------------------------------------------
// Device views
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chat_device_keys_include_revoked_keys_with_their_time() {
    let env = Env::new().await;
    let alice = env.account().await;
    let second = env.device_for(&alice.did, random_seed()).await;
    env.revoke(&second).await;
    let reader = env.account().await;

    let reply = reader
        .query("getChatDeviceKeys", &[("did", alice.did.clone())])
        .await;
    let items = reply.ok()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2);
    let find = |key: [u8; 32]| {
        items
            .iter()
            .find(|i| unb(&i["signingPublicKey"]) == key)
            .unwrap()
            .clone()
    };
    assert!(find(alice.chat_pub()).get("revokedAt").is_none());
    assert!(find(second.chat_pub())["revokedAt"].as_str().is_some());

    // Paging.
    let page = reader
        .query(
            "getChatDeviceKeys",
            &[("did", alice.did.clone()), ("limit", "1".into())],
        )
        .await;
    assert_eq!(page.ok()["items"].as_array().unwrap().len(), 1);
    let cursor = page.json["cursor"].as_str().unwrap().to_owned();
    let rest = reader
        .query(
            "getChatDeviceKeys",
            &[("did", alice.did.clone()), ("cursor", cursor)],
        )
        .await;
    assert_eq!(rest.ok()["items"].as_array().unwrap().len(), 1);
    assert!(rest.json.get("cursor").is_none());
}

#[tokio::test]
async fn member_devices_serve_join_and_removal_seqs_to_participants_only() {
    let env = Env::new().await;
    let alice = env.account().await;
    let alice_old = env.device_for(&alice.did, random_seed()).await;
    let bob = env.account().await;
    let stranger = env.account().await;
    let conversation = seed_conversation(
        &env,
        &[
            Leaf {
                device: &alice_old,
                joined_seq: 1,
                removed_seq: Some(5),
            },
            Leaf {
                device: &alice,
                joined_seq: 4,
                removed_seq: None,
            },
            Leaf {
                device: &bob,
                joined_seq: 1,
                removed_seq: None,
            },
        ],
        9,
    )
    .await;
    let reply = bob
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", alice.did.clone()),
            ],
        )
        .await;
    let items = reply.ok()["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["joinedSeq"], 1);
    assert_eq!(items[0]["removedSeq"], 5);
    assert_eq!(unb(&items[0]["signingPublicKey"]), alice_old.chat_pub());
    assert_eq!(items[1]["joinedSeq"], 4);
    assert!(items[1].get("removedSeq").is_none());

    stranger
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", alice.did.clone()),
            ],
        )
        .await
        .fails(404, "ConversationNotFound");
}

static MEMBER_DEVICE_FEDERATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(feature = "sim")]
#[tokio::test]
async fn member_devices_use_the_pinned_two_home_sequencer_without_mirror_fallback() {
    use axum::{extract::Json, routing::post, Router};
    use p256::pkcs8::EncodePrivateKey as _;
    use std::sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    };

    struct RestoreFederation(Option<std::ffi::OsString>);
    impl Drop for RestoreFederation {
        fn drop(&mut self) {
            catbird_server::federation::open_federation_for_test();
            match self.0.take() {
                Some(value) => std::env::set_var("SIGNING_KEY_PEM", value),
                None => std::env::remove_var("SIGNING_KEY_PEM"),
            }
        }
    }

    let _guard = MEMBER_DEVICE_FEDERATION.lock().await;
    catbird_server::federation::open_federation_for_test();
    let restore = RestoreFederation(std::env::var_os("SIGNING_KEY_PEM"));
    let sequencer_did = "did:web:other.catbird.blue";
    let sequencer_key = jwt_key_for(sequencer_did);
    let sequencer_hooks = Arc::new(catbird_server::sim_hooks::SimDsHooks {
        service_did: sequencer_did.to_owned(),
        self_endpoint: "https://other.catbird.blue".to_owned(),
        signing_key_pem: Some(
            sequencer_key
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        ),
        group_relay_hmac_secret: None,
        http_transport: Arc::new(|_| {
            Box::pin(async { Err("unexpected sequencer outbound request".to_owned()) })
        }),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
        retain_application_ciphertext: false,
    });
    let sequencer = Env::federated(Federation {
        self_did: sequencer_did.to_owned(),
        key: sequencer_key,
        peer: None,
        sim_hooks: Some(sequencer_hooks),
    })
    .await;
    let sequencer_addr = sequencer.serve().await;
    let home_did = catbird_server::identity::service_did_base();
    let home_key = jwt_key_for(&home_did);
    std::env::set_var(
        "SIGNING_KEY_PEM",
        home_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .as_str(),
    );
    cache_did_key(&home_did, &home_key).await;
    let home = Env::federated(Federation {
        self_did: home_did.clone(),
        key: home_key.clone(),
        peer: Some(sequencer_addr),
        sim_hooks: None,
    })
    .await;
    allow_peer(&sequencer, &home_did).await;
    allow_peer(&home, sequencer_did).await;

    let alice = sequencer.account().await;
    let bob = sequencer.account().await;
    let conversation = seed_conversation(
        &sequencer,
        &[
            Leaf {
                device: &alice,
                joined_seq: 1,
                removed_seq: None,
            },
            Leaf {
                device: &bob,
                joined_seq: 1,
                removed_seq: None,
            },
        ],
        2,
    )
    .await;
    set_home_ds(&sequencer, conversation, &alice, &home_did).await;

    // Local authority remains a direct read.
    let local = bob
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await;
    assert_eq!(local.ok()["items"].as_array().unwrap().len(), 1);

    let home_alice = home.replicate(&alice).await;
    let home_bob = home.replicate(&bob).await;
    seed_conversation_with_id(
        &home,
        conversation,
        &[
            Leaf {
                device: &home_alice,
                joined_seq: 99,
                removed_seq: None,
            },
            Leaf {
                device: &home_bob,
                joined_seq: 99,
                removed_seq: None,
            },
        ],
        100,
    )
    .await;
    make_remote_to(&home, conversation, sequencer_did).await;

    // A closed gate returns 503 before even reaching the sequencer.
    let before = sequencer.request_count.load(Ordering::Relaxed);
    catbird_server::federation::FederationMode::set_runtime_override(Some(
        catbird_server::federation::FederationMode::Off,
    ));
    home_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await
        .fails(503, "RelayUnavailable");
    assert_eq!(
        sequencer.request_count.load(Ordering::Relaxed),
        before,
        "closed federation must send no S2S request"
    );
    catbird_server::federation::open_federation_for_test();

    // The mirror's complete-looking Bob leaf says 99; only the sequencer says 1.
    let remote = home_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await;
    let remote_item = &remote.ok()["items"][0];
    assert_eq!(remote_item["joinedSeq"], 1);
    assert_eq!(unb(&remote_item["signingPublicKey"]), bob.chat_pub());

    // A fresh restore intersects home device keys with sequencer leaf history.
    let directory = home_alice
        .query("getChatDeviceKeys", &[("did", bob.did.clone())])
        .await;
    let directory_key = &directory.ok()["items"][0];
    assert_eq!(directory_key["keyId"], remote_item["keyId"]);
    assert_eq!(
        unb(&directory_key["signingPublicKey"]),
        unb(&remote_item["signingPublicKey"])
    );

    // The sequencer response must bind the pinned term, not just the DS DID.
    set_sequencer_term(&home, conversation, 1).await;
    home_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await
        .fails(403, "NotAuthorized");
    set_sequencer_term(&home, conversation, 0).await;

    // The sequencer's semantic absence stays a 404.
    let missing = uuid::Uuid::new_v4();
    seed_conversation_with_id(
        &home,
        missing,
        &[Leaf {
            device: &home_alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        2,
    )
    .await;
    make_remote_to(&home, missing, sequencer_did).await;
    home_alice
        .query(
            "getMemberDevices",
            &[("threadId", missing.to_string()), ("did", bob.did.clone())],
        )
        .await
        .fails(404, "ConversationNotFound");

    // An old sequencer with a moved route refuses the stale request.
    make_remote_to(&sequencer, conversation, "did:web:replacement.catbird.blue").await;
    home_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await
        .fails(403, "NotAuthorized");

    // A second home points at a controlled peer for transient and tamper cases.
    let peer_mode = Arc::new(AtomicU8::new(0));
    let peer_calls = Arc::new(AtomicUsize::new(0));
    let fake_router = Router::new().route(
        "/xrpc/blue.catbird.mlsDS.getLabyrinthDirectory",
        post({
            let peer_mode = Arc::clone(&peer_mode);
            let peer_calls = Arc::clone(&peer_calls);
            move |Json(request): Json<Value>| {
                let peer_mode = Arc::clone(&peer_mode);
                let peer_calls = Arc::clone(&peer_calls);
                async move {
                    peer_calls.fetch_add(1, Ordering::Relaxed);
                    if peer_mode.load(Ordering::Relaxed) == 1 {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"error": "ServiceUnavailable"})),
                        );
                    }
                    let query = request["query"].as_str().unwrap();
                    let thread = url::form_urlencoded::parse(query.as_bytes())
                        .find_map(|(key, value)| (key == "threadId").then(|| value.into_owned()))
                        .unwrap();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "endpoint": request["endpoint"],
                            "query": query,
                            "sequencerDid": sequencer_did,
                            "sequencerTerm": 0,
                            "actorDid": request["actorDid"],
                            "actorDeviceId": request["actorDeviceId"],
                            "conversationId": thread,
                            "subjectDid": "did:web:tampered.example.com",
                            "page": {"items": []},
                        })),
                    )
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, fake_router).await;
    });
    let fake_home = Env::federated(Federation {
        self_did: home_did.clone(),
        key: home_key,
        peer: Some(fake_addr),
        sim_hooks: None,
    })
    .await;
    allow_peer(&fake_home, sequencer_did).await;
    let fake_alice = fake_home.replicate(&alice).await;
    let fake_conversation = seed_conversation(
        &fake_home,
        &[Leaf {
            device: &fake_alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        2,
    )
    .await;
    make_remote_to(&fake_home, fake_conversation, sequencer_did).await;

    peer_mode.store(1, Ordering::Relaxed);
    fake_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", fake_conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await
        .fails(503, "RelayUnavailable");
    peer_mode.store(0, Ordering::Relaxed);
    fake_alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", fake_conversation.to_string()),
                ("did", bob.did.clone()),
            ],
        )
        .await
        .fails(403, "NotAuthorized");
    assert_eq!(peer_calls.load(Ordering::Relaxed), 2);

    drop(restore);
}

#[tokio::test]
async fn lf01_purge_preserves_epoch_head_high_water_floor() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (e0, link0) = chain::epoch_public(&alice, 0, [0x11; 32], None, None);
    let (e1, _) = chain::epoch_public(&alice, 1, [0x22; 32], Some(link0), None);
    alice.call("publishEpochHead", &publish(&e0)).await.ok();
    alice.call("publishEpochHead", &publish(&e1)).await.ok();

    alice.call("purgeMailbox", &json!({})).await.ok();
    alice
        .query("getEpochHead", &[("did", alice.did.clone())])
        .await
        .fails(404, "EpochNotFound");

    // Re-anchoring at or below prior_max (1), or skipping past prior_max + 1, must fail.
    let (re0, _) = chain::epoch_public(&alice, 0, [0x33; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&re0))
        .await
        .fails(400, "InvalidEpochChain");
    let (re1, _) = chain::epoch_public(&alice, 1, [0x44; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&re1))
        .await
        .fails(400, "InvalidEpochChain");
    let (skip3, _) = chain::epoch_public(&alice, 3, [0x55; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&skip3))
        .await
        .fails(400, "InvalidEpochChain");

    // Post-purge restart at prior_max + 1 (2) succeeds and extends normally to 3.
    let (re2, link2) = chain::epoch_public(&alice, 2, [0x66; 32], None, None);
    alice.call("publishEpochHead", &publish(&re2)).await.ok();
    let (e3, _) = chain::epoch_public(&alice, 3, [0x77; 32], Some(link2), None);
    alice.call("publishEpochHead", &publish(&e3)).await.ok();
}

#[tokio::test]
async fn lf10_member_devices_cursor_near_i64_max_does_not_overflow() {
    let env = Env::new().await;
    let alice = env.account().await;
    let conversation = seed_conversation(
        &env,
        &[Leaf {
            device: &alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        2,
    )
    .await;
    let reply = alice
        .query(
            "getMemberDevices",
            &[
                ("threadId", conversation.to_string()),
                ("did", alice.did.clone()),
                ("cursor", i64::MAX.to_string()),
            ],
        )
        .await;
    assert_eq!(reply.ok()["items"], json!([]));
}

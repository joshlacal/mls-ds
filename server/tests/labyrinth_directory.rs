//! Labyrinth backend: admission and the verifying head directory
//! (labyrinth `docs/MLSDS_BACKEND.md` §1a, §2 "Directory", §3).
//!
//! Requires `TEST_DATABASE_URL` naming the local clean-chat gate database
//! (only its cluster is used: every test mints a private database) and
//! `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED`, like the other fresh-DB suites.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

#[path = "common/labyrinth_chain.rs"]
mod chain;

use axum::{body::Body, http::Request};
use ed25519_dalek::{Signer as _, SigningKey};
use harness::*;
use serde_json::{json, Value};

use catbird_server::labyrinth::heads::{attestation_message, compute_epoch_head};

fn publish(epoch: &Value) -> Value {
    json!({ "epoch": epoch })
}

// ---------------------------------------------------------------------------
// Admission (design §3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admission_requires_cutover_service_auth_and_a_current_device() {
    let env = Env::new().await;
    let alice = env.account().await;

    // No token.
    let request = Request::get(format!(
        "/xrpc/{PREFIX}listDevices?actorDeviceId={}",
        alice.device_id
    ))
    .body(Body::empty())
    .unwrap();
    send(&env.router, request).await.fails(401, "NotAuthorized");

    // A token minted for another NSID (lxm mismatch).
    let request = Request::get(format!(
        "/xrpc/{PREFIX}listDevices?actorDeviceId={}",
        alice.device_id
    ))
    .header(
        "authorization",
        format!("Bearer {}", alice.token(&format!("{PREFIX}listEpochs"))),
    )
    .body(Body::empty())
    .unwrap();
    send(&env.router, request).await.fails(401, "NotAuthorized");

    // Missing actorDeviceId is a malformed request.
    let nsid = format!("{PREFIX}listDevices");
    let request = Request::get(format!("/xrpc/{nsid}"))
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
        .query("listDevices", &[])
        .await
        .fails(401, "NotAuthorized");

    // The real device works, then stops working once revoked.
    alice.query("listDevices", &[]).await.ok();
    env.revoke(&alice).await;
    alice
        .query("listDevices", &[])
        .await
        .fails(401, "DeviceRevoked");
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([1; 32]) }),
        )
        .await
        .fails(401, "DeviceRevoked");

    // Without the chat cutover gate nothing is served.
    let gated = Env::with(false, None).await;
    let bob = gated.account().await;
    bob.query("listDevices", &[])
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
    let nsid = format!("{PREFIX}listDevices");
    let q = format!("actorDeviceId={}", alice.device_id);
    let ok = |device: &Device, query: &str| Some(device.read_headers(&nsid, query));

    send(&env.router, get_with(&alice, "listDevices", &q, None))
        .await
        .fails(400, "InvalidRequest");
    // Signed by another key (an impostor holding the account JWT).
    let mut impostor = alice.clone();
    impostor.chat_key = SigningKey::from_bytes(&random_seed());
    send(
        &env.router,
        get_with(&alice, "listDevices", &q, ok(&impostor, &q)),
    )
    .await
    .fails(401, "InvalidSignature");
    // Another current device of the same account cannot be named: its claim
    // carries its own deviceId, not actorDeviceId.
    send(
        &env.router,
        get_with(&alice, "listDevices", &q, ok(&alice2, &q)),
    )
    .await
    .fails(400, "InvalidRequest");
    // Claim over another query, another endpoint, or a stale instant.
    let tampered = format!("{q}&limit=1");
    send(
        &env.router,
        get_with(&alice, "listDevices", &tampered, ok(&alice, &q)),
    )
    .await
    .fails(400, "InvalidRequest");
    let other_nsid = Some(alice.read_headers(&format!("{PREFIX}listEpochs"), &q));
    send(&env.router, get_with(&alice, "listDevices", &q, other_nsid))
        .await
        .fails(400, "InvalidRequest");
    let stale = chrono::Utc::now().timestamp_millis() - 301_000;
    let old = Some(alice.read_headers_at(&nsid, &q, stale));
    send(&env.router, get_with(&alice, "listDevices", &q, old))
        .await
        .fails(400, "InvalidRequest");
    // Parameter order and encoding do not matter; the canonical form does.
    let reordered = format!("limit=5&{q}");
    let canonical_twin = format!("{q}&limit=5");
    send(
        &env.router,
        get_with(
            &alice,
            "listDevices",
            &reordered,
            ok(&alice, &canonical_twin),
        ),
    )
    .await
    .ok();
    send(
        &env.router,
        get_with(&alice, "listDevices", &q, ok(&alice, &q)),
    )
    .await
    .ok();
}

/// getVirtualDevice stamps `lastUsedAt` only on a valid device-signed read.
#[tokio::test]
async fn bundle_use_is_recorded_only_for_device_signed_reads() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice
        .call(
            "createVirtualDevice",
            &json!({ "record": vdevice_record([0x51; 16], [0x52; 32]) }),
        )
        .await
        .ok();
    let last_used = || async {
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT last_used_at FROM labyrinth.virtual_devices WHERE owner_did = $1",
        )
        .bind(&alice.did)
        .fetch_one(&env.pool)
        .await
        .unwrap()
    };
    let nsid = format!("{PREFIX}getVirtualDevice");
    let q = format!(
        "actorDeviceId={}&vdeviceId={}",
        alice.device_id,
        hex::encode([0x51; 16])
    );
    let mut impostor = alice.clone();
    impostor.chat_key = SigningKey::from_bytes(&random_seed());
    let forged = Some(impostor.read_headers(&nsid, &q));
    send(
        &env.router,
        get_with(&alice, "getVirtualDevice", &q, forged),
    )
    .await
    .fails(401, "InvalidSignature");
    send(&env.router, get_with(&alice, "getVirtualDevice", &q, None))
        .await
        .fails(400, "InvalidRequest");
    assert!(last_used().await.is_none(), "refused reads record no use");
    let genuine = Some(alice.read_headers(&nsid, &q));
    send(
        &env.router,
        get_with(&alice, "getVirtualDevice", &q, genuine),
    )
    .await
    .ok();
    assert!(last_used().await.is_some());
}

#[tokio::test]
async fn writes_require_a_valid_signed_write_body() {
    let env = Env::new().await;
    let alice = env.account().await;
    let nsid = format!("{PREFIX}createDevice");
    let input = serde_json::to_vec(&json!({ "record": alice.device_record([1; 32]) })).unwrap();
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
    let (write, sig) = alice.write_headers(&format!("{PREFIX}createEpoch"), &input, op);
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
// Head chain acceptance (design §1a; second security review finding 1)
// ---------------------------------------------------------------------------

/// `createEpoch` input opening `public` with Labyrinth device `opened_by`.
fn open_epoch(public: &Value, opened_by: [u8; 32]) -> Value {
    json!({ "epoch": epoch_record(public, opened_by), "members": [] })
}

/// The vector DID's two chat devices, each holding a bound Labyrinth device
/// (d0: 0xD0, d1: 0xD1). Epochs 0-1 are attested by d0, epoch 2 by d1.
async fn vector_devices(env: &Env, v: &Vectors) -> (Device, Device) {
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    d0.enroll([0xD0; 32]).await;
    d1.enroll([0xD1; 32]).await;
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
        d0.call("createEpoch", &open_epoch(epoch, [0xD0; 32]))
            .await
            .ok();
    }
    d1.call("createEpoch", &open_epoch(&v.chain[2], [0xD1; 32]))
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
    d0.call("createEpoch", &open_epoch(&v.chain[1], [0xD0; 32]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("createEpoch", &open_epoch(&v.chain[0], [0xD0; 32]))
        .await
        .ok();
    // Skips epoch 1.
    d1.call("createEpoch", &open_epoch(&v.chain[2], [0xD1; 32]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("createEpoch", &open_epoch(&v.chain[1], [0xD0; 32]))
        .await
        .ok();
    // A different epoch 1 (same predecessor) is a fork: the [CB-9] race
    // guard on createEpoch, a conflict on publishEpochHead.
    d0.call("createEpoch", &open_epoch(&v.fork, [0xD0; 32]))
        .await
        .fails(409, "RecordAlreadyExists");
    d0.call("publishEpochHead", &publish(&v.fork))
        .await
        .fails(409, "EpochHeadConflict");
}

/// Re-attest `epoch` after replacing its predecessor link, recomputing the
/// head as the server does. Its `selfSig` no longer verifies (the vector's
/// signing key is the crate's), which is exactly what the server checks.
fn relinked(did: &str, epoch: &Value, previous: [u8; 32], seed: [u8; 32]) -> Value {
    let mut e = epoch.clone();
    let n = e["epochNumber"].as_u64().unwrap();
    let head = compute_epoch_head(
        n,
        &unb(&e["authPubkey"]),
        &unb(&e["encryptionPubkey"]),
        &unb(&e["signingPubkey"]),
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
    d0.call("createEpoch", &open_epoch(&v.chain[0], [0xD0; 32]))
        .await
        .ok();
    let create = |e: &Value| open_epoch(e, [0xD0; 32]);

    // Re-headed onto another predecessor: selfSig no longer verifies.
    let wrong_link = relinked(&v.did, &v.chain[1], [0xAB; 32], v.seeds[0]);
    d0.call("createEpoch", &create(&wrong_link))
        .await
        .fails(400, "InvalidRequest");
    // A head that does not recompute from its keys.
    let mut tampered = v.chain[1].clone();
    tampered["authPubkey"] = b(&[0x5A; 32]);
    d0.call("createEpoch", &create(&tampered))
        .await
        .fails(400, "InvalidRequest");
    // A forged attestation or self signature.
    let mut forged = v.chain[1].clone();
    forged["attestation"]["sig"] = b(&[0x11; 64]);
    d0.call("createEpoch", &create(&forged))
        .await
        .fails(400, "InvalidRequest");
    let mut forged = v.chain[1].clone();
    forged["selfSig"] = v.chain[0]["selfSig"].clone();
    d0.call("createEpoch", &create(&forged))
        .await
        .fails(400, "InvalidRequest");
    // A head for another DID (the caller's own DID is always the subject).
    let other = env.account().await;
    other.enroll([0x0B; 32]).await;
    other
        .call("createEpoch", &open_epoch(&v.chain[0], [0x0B; 32]))
        .await
        .fails(400, "InvalidRequest");
}

#[tokio::test]
async fn prev_sig_must_be_signed_by_the_previous_epochs_key() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice.enroll([0xA0; 32]).await;
    let (genesis, g) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    alice
        .call("createEpoch", &open_epoch(&genesis, [0xA0; 32]))
        .await
        .ok();
    // Correct head, self signature and attestation, but prevSig by a key
    // that is not epoch 0's.
    let (bad, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), Some([9; 32]));
    alice
        .call("createEpoch", &open_epoch(&bad, [0xA0; 32]))
        .await
        .fails(400, "InvalidRequest");
    let (good, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), None);
    alice
        .call("createEpoch", &open_epoch(&good, [0xA0; 32]))
        .await
        .ok();
}

#[tokio::test]
async fn head_attestation_must_be_the_callers_own_chat_key() {
    let env = Env::new().await;
    let v = vectors();
    let (d0, d1) = vector_devices(&env, &v).await;
    for epoch in &v.chain[..2] {
        d0.call("createEpoch", &open_epoch(epoch, [0xD0; 32]))
            .await
            .ok();
    }
    // Epoch 2 is attested by d1's key: d0 can neither open nor publish it,
    // although d1's key is a current chat key of the DID.
    d0.call("createEpoch", &open_epoch(&v.chain[2], [0xD0; 32]))
        .await
        .fails(400, "AttestationNotCaller");
    // d1 cannot re-publish d0's epoch either.
    d1.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .fails(400, "AttestationNotCaller");
    // Once d1 is revoked it cannot act at all.
    env.revoke(&d1).await;
    d1.call("createEpoch", &open_epoch(&v.chain[2], [0xD1; 32]))
        .await
        .fails(401, "DeviceRevoked");
}

/// Finding 1 repro: before the fix an unbound chat device of the DID could
/// publish a self-attested head n+1 through publishEpochHead and squat the
/// number, wedging every later rotation.
#[tokio::test]
async fn unbound_device_cannot_squat_the_next_head_and_rotation_proceeds() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice.enroll([0xA0; 32]).await;
    let (genesis, g) = chain::epoch_public(&alice, 0, [1; 32], None, None);
    alice
        .call("createEpoch", &open_epoch(&genesis, [0xA0; 32]))
        .await
        .ok();

    // A second chat device of the same DID with no Labyrinth device builds
    // a fully valid epoch 1 (it cannot sign prevSig without epoch 0's key,
    // so give it that key too: the attack must fail on authority alone).
    let rogue = env.device_for(&alice.did, random_seed()).await;
    let (squat, _) = chain::epoch_public(&rogue, 1, [6; 32], Some(g), None);
    rogue
        .call("publishEpochHead", &publish(&squat))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // Bound, but the epoch is not in its mailbox: publishEpochHead never
    // introduces a head.
    rogue.enroll([0x7E; 32]).await;
    rogue
        .call("publishEpochHead", &publish(&squat))
        .await
        .fails(404, "EpochNotFound");
    // The rogue's own bound device may open its own epoch only with its own
    // attestation; alice's attestation is refused for it.
    let (alices_next, _) = chain::epoch_public(&alice, 1, [2; 32], Some(g), None);
    rogue
        .call("createEpoch", &open_epoch(&alices_next, [0x7E; 32]))
        .await
        .fails(400, "AttestationNotCaller");
    let heads: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.epoch_heads WHERE did = $1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(heads, 1, "nothing was squatted");

    // The real rotation succeeds, and its head can be re-published.
    alice
        .call("createEpoch", &open_epoch(&alices_next, [0xA0; 32]))
        .await
        .ok();
    alice
        .call("publishEpochHead", &publish(&alices_next))
        .await
        .ok();
    let latest = alice
        .query("getEpochHead", &[("did", alice.did.clone())])
        .await;
    assert_eq!(latest.ok()["epoch"], alices_next);
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

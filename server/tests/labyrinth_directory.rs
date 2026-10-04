//! Labyrinth backend: admission and the verifying head directory
//! (labyrinth `docs/MLSDS_BACKEND.md` §1a, §2 "Directory", §3).
//!
//! Requires `TEST_DATABASE_URL` naming the local clean-chat gate database
//! (only its cluster is used: every test mints a private database) and
//! `CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED`, like the other fresh-DB suites.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

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
        .call("createDevice", &json!({ "record": device_record([1; 32]) }))
        .await
        .fails(401, "DeviceRevoked");

    // Without the chat cutover gate nothing is served.
    let gated = Env::with(false, None).await;
    let bob = gated.account().await;
    bob.query("listDevices", &[])
        .await
        .fails(400, "CutoverRequired");
}

#[tokio::test]
async fn writes_require_a_valid_signed_write_body() {
    let env = Env::new().await;
    let alice = env.account().await;
    let nsid = format!("{PREFIX}createDevice");
    let input = serde_json::to_vec(&json!({ "record": device_record([1; 32]) })).unwrap();
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
// Head chain acceptance (design §1a)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn head_chain_accepts_crate_vectors_in_order_and_serves_them() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let _d1 = env.device_for(&v.did, v.seeds[1]).await;
    let reader = env.account().await;

    reader
        .query("getEpochHead", &[("did", v.did.clone())])
        .await
        .fails(404, "EpochNotFound");
    for epoch in &v.chain {
        d0.call("publishEpochHead", &publish(epoch)).await.ok();
    }
    // Re-sending identical bytes is accepted.
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
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    env.device_for(&v.did, v.seeds[1]).await;

    // Not genesis on an empty chain.
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .ok();
    // Skips epoch 1.
    d0.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .fails(400, "InvalidEpochChain");
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .ok();
    // A different epoch 1 (same predecessor) is a fork.
    d0.call("publishEpochHead", &publish(&v.fork))
        .await
        .fails(409, "EpochHeadConflict");
}

/// Re-attest `epoch` after replacing its predecessor link, recomputing the
/// head as the server does (selfSig/prevSig are client-verified only).
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
async fn head_chain_requires_the_previous_head_link_and_a_recomputable_head() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .ok();

    // Well-formed and attested, but linked to a head that is not epoch 0's.
    let wrong_link = relinked(&v.did, &v.chain[1], [0xAB; 32], v.seeds[0]);
    d0.call("publishEpochHead", &publish(&wrong_link))
        .await
        .fails(400, "InvalidEpochChain");

    // A head that does not recompute from its keys.
    let mut tampered = v.chain[1].clone();
    tampered["authPubkey"] = b(&[0x5A; 32]);
    d0.call("publishEpochHead", &publish(&tampered))
        .await
        .fails(400, "InvalidRequest");

    // A forged attestation signature.
    let mut forged = v.chain[1].clone();
    forged["attestation"]["sig"] = b(&[0x11; 64]);
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
async fn head_attestation_must_be_a_current_chat_key_of_the_did() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    for epoch in &v.chain[..2] {
        d1.call("publishEpochHead", &publish(epoch)).await.ok();
    }
    // Epoch 2 is attested by d1's key; revoke d1 and publish from d0.
    env.revoke(&d1).await;
    d0.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .fails(400, "AttestationNotCurrent");
    // d0's own epochs stay publishable (identical resend).
    d0.call("publishEpochHead", &publish(&v.chain[1]))
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

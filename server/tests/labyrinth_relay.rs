//! Labyrinth backend: the `labyrinthRelay` federation procedure (design §3
//! "Federation", Y3). Two DSes in one process, each with its own database:
//! the sequencer is served on loopback, the home DS reaches it through the
//! real pinned outbound client (destination hook), real DS service auth and
//! the peer policy.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use catbird_server::federation::FederationMode;
use chrono::Utc;
use curve25519_dalek::ristretto::RistrettoPoint;
use ed25519_dalek::Signer as _;
use harness::*;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256Key};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use uuid::Uuid;

const RELAY: &str = "blue.catbird.labyrinth.labyrinthRelay";
const HOME_DS: &str = "did:web:home-ds.labyrinth-relay.dev";
/// The sequencer's DID is this process's SERVICE_DID (the audience every
/// inbound token is checked against); `.test` is not a bare DID host.
const SEQUENCER_DS: &str = "did:web:sequencer.labyrinth-relay.dev";
const MEK_A: [u8; 12] = [0xA; 12];
const MEK_B: [u8; 12] = [0xB; 12];

fn sequencer_did() -> String {
    SEQUENCER_DS.to_owned()
}

fn configure() {
    std::env::set_var("SERVICE_DID", SEQUENCER_DS);
    std::env::set_var("ENFORCE_LXM", "true");
    std::env::set_var("FEDERATION_MODE", "allowlist");
    FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
}

fn ds_key(label: &str) -> P256Key {
    jwt_key_for(&format!("labyrinth-relay-ds:{label}"))
}

/// The sequencer DS, the home DS, alice (homed on the home DS, replicated on
/// the sequencer), bob (homed on the sequencer) and their conversation.
struct World {
    seq: Env,
    home: Env,
    alice: Device,
    alice_on_seq: Device,
    bob: Device,
    thread: Uuid,
}

async fn world(object: Option<&TestObject>) -> World {
    configure();
    let seq = Env::federated(
        Federation {
            self_did: sequencer_did(),
            key: ds_key("seq"),
            peer: None,
        },
        None,
    )
    .await;
    let addr = seq.serve().await;
    let home_key = ds_key("home");
    cache_did_key(HOME_DS, &home_key).await;
    let home = Env::federated(
        Federation {
            self_did: HOME_DS.to_owned(),
            key: home_key,
            peer: Some(addr),
        },
        object,
    )
    .await;
    allow_peer(&seq, HOME_DS).await;
    allow_peer(&home, &sequencer_did()).await;

    let alice = home.account().await;
    let alice_on_seq = seq.replicate(&alice).await;
    let bob = seq.account().await;
    let leaf = |device| Leaf {
        device,
        joined_seq: 1,
        removed_seq: None,
    };
    let thread = seed_conversation(&seq, &[leaf(&alice_on_seq), leaf(&bob)], 10).await;
    set_home_ds(&seq, thread, &alice_on_seq, HOME_DS).await;
    seed_conversation_with_id(&home, thread, &[leaf(&alice)], 10).await;
    make_remote_to(&home, thread, &sequencer_did()).await;
    World {
        seq,
        home,
        alice,
        alice_on_seq,
        bob,
        thread,
    }
}

fn batch(thread: Uuid, sender: &Device, mek: [u8; 12], messages: &[&str]) -> Value {
    let items: Vec<Value> = messages
        .iter()
        .map(|m| {
            json!({ "messageId": m, "timestamp": 1000, "mekId": b(&mek),
                    "senderTransportPubkey": b(&sender.chat_pub()),
                    "signedEncMessage": b(&[0x61; 96]) })
        })
        .collect();
    json!({ "record": { "$type": "blue.catbird.labyrinth.batch", "threadId": thread.to_string(),
                        "items": items, "createdAt": "2026-10-04T12:00:00.000Z" } })
}

async fn rows(env: &Env, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM labyrinth.{table}"))
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn thread_operations_of_a_remote_conversation_run_on_its_sequencer() {
    let w = world(None).await;
    let mek = |sender: &Device, id| json!({ "record": transport_mek(w.thread, id, sender.chat_pub(), &[&w.alice.did, &w.bob.did]) });
    let created = w.alice.call("createMek", &mek(&w.alice, MEK_A)).await;
    assert_eq!(created.ok()["order"]["seq"], 1, "{}", created.json);
    w.bob.call("createMek", &mek(&w.bob, MEK_B)).await.ok();

    // The home DS forwards; the sequencer stamps and stores.
    let op = [0x51; 16];
    let first = w
        .alice
        .call_op(
            "appendBatch",
            &batch(w.thread, &w.alice, MEK_A, &["a1"]),
            op,
        )
        .await;
    assert_eq!(first.ok()["order"]["seq"], 3);
    assert_eq!(first.json["order"]["chatSeq"], 9);
    let replay = w
        .alice
        .call_op(
            "appendBatch",
            &batch(w.thread, &w.alice, MEK_A, &["a1"]),
            op,
        )
        .await;
    assert_eq!(
        replay.bytes, first.bytes,
        "the sequencer replays the operation"
    );
    assert_eq!(
        (
            rows(&w.seq, "batches").await,
            rows(&w.home, "batches").await
        ),
        (1, 0)
    );
    assert_eq!(
        (rows(&w.seq, "meks").await, rows(&w.home, "meks").await),
        (2, 0)
    );

    // Typed errors pass through.
    let mixed = json!({ "record": { "$type": "blue.catbird.labyrinth.batch",
        "threadId": w.thread.to_string(), "createdAt": "2026-10-04T12:00:00.000Z",
        "items": [
            { "messageId": "x", "timestamp": 1, "mekId": b(&MEK_A),
              "senderTransportPubkey": b(&w.alice.chat_pub()), "signedEncMessage": b(&[1; 96]) },
            { "messageId": "y", "timestamp": 1, "mekId": b(&MEK_B),
              "senderTransportPubkey": b(&w.alice.chat_pub()), "signedEncMessage": b(&[1; 96]) }
        ] } });
    w.alice
        .call("appendBatch", &mixed)
        .await
        .fails(400, "MixedMekBatch");

    // Reads through the relay see exactly what a sequencer-homed member sees.
    w.bob
        .call("appendBatch", &batch(w.thread, &w.bob, MEK_B, &["b1"]))
        .await
        .ok();
    let thread = ("threadId", w.thread.to_string());
    let via_relay = w.alice.query("listBatches", &[thread.clone()]).await;
    let direct = w.alice_on_seq.query("listBatches", &[thread.clone()]).await;
    assert_eq!(via_relay.ok()["items"].as_array().unwrap().len(), 2);
    assert_eq!(via_relay.json, direct.json);
    let meks = w
        .alice
        .query("findMeks", &[thread.clone(), ("mekId", hex::encode(MEK_B))])
        .await;
    assert_eq!(meks.ok()["items"][0]["author"], w.bob.did);

    // Unsend through the relay.
    let signed = format!(
        "catbird.labyrinth.redaction:did={};message_id=a1;thread_id={}",
        w.alice.did,
        hex::encode(w.thread.to_string().as_bytes())
    );
    let redacted = w
        .alice
        .call(
            "redactMessage",
            &json!({ "threadId": w.thread.to_string(), "messageId": "a1",
                     "redaction": { "transportPubkey": b(&w.alice.chat_pub()),
                                    "sig": b(&w.alice.chat_key.sign(signed.as_bytes()).to_bytes()) } }),
        )
        .await;
    assert_eq!(redacted.ok()["redacted"], 1);
}

/// A hand-built relay request from DS `iss` signed with `key`.
async fn relay_as(w: &World, iss: &str, key: &P256Key, input: &Value) -> Reply {
    let now = Utc::now().timestamp();
    let header = json!({ "alg": "ES256", "typ": "JWT" });
    let claims = json!({ "iss": iss, "sub": iss, "aud": sequencer_did(), "lxm": RELAY,
                         "iat": now, "exp": now + 60, "jti": Uuid::new_v4().to_string() });
    let input_b64 = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig: P256Signature = key.sign(input_b64.as_bytes());
    let token = format!("{input_b64}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    let request = Request::post(format!("/xrpc/{RELAY}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(input).unwrap()))
        .unwrap();
    send(&w.seq.router, request).await
}

/// A relayed write of `name` for `device`, its write body signed by
/// `signer`'s chat key over `signed_payload`, carrying `payload`.
fn relayed_write(
    device: &Device,
    signer: &Device,
    name: &str,
    signed_payload: &Value,
    payload: &Value,
) -> Value {
    let nsid = format!("{PREFIX}{name}");
    let (write, sig) =
        signer.write_headers(&nsid, &serde_json::to_vec(signed_payload).unwrap(), [7; 16]);
    json!({ "op": name, "actorDid": device.did, "actorDeviceId": device.device_id.to_string(),
            "payload": b(&serde_json::to_vec(payload).unwrap()),
            "writeBody": write, "writeSignature": sig })
}

#[tokio::test]
async fn the_sequencer_verifies_peer_home_device_and_signature() {
    let w = world(None).await;
    let home_key = ds_key("home");
    let mek =
        json!({ "record": transport_mek(w.thread, MEK_A, w.alice.chat_pub(), &[&w.alice.did]) });

    // A DS outside the peer allowlist.
    let stranger = "did:web:stranger.labyrinth-relay.dev";
    let stranger_key = ds_key("stranger");
    cache_did_key(stranger, &stranger_key).await;
    relay_as(
        &w,
        stranger,
        &stranger_key,
        &relayed_write(&w.alice, &w.alice, "createMek", &mek, &mek),
    )
    .await
    .fails(401, "NotAuthorized");

    // The home DS cannot write without the device's own signature: a write
    // body signed by another key, or over another payload, fails.
    let mut impostor = w.alice.clone();
    impostor.chat_key = ed25519_dalek::SigningKey::from_bytes(&random_seed());
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &relayed_write(&w.alice, &impostor, "createMek", &mek, &mek),
    )
    .await
    .fails(401, "InvalidSignature");
    let other =
        json!({ "record": transport_mek(w.thread, MEK_B, w.alice.chat_pub(), &[&w.alice.did]) });
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &relayed_write(&w.alice, &w.alice, "createMek", &other, &mek),
    )
    .await
    .fails(400, "InvalidRequest");

    // A DS that is not the actor's home DS in the conversation (bob is
    // homed on the sequencer itself).
    let bob_mek =
        json!({ "record": transport_mek(w.thread, MEK_B, w.bob.chat_pub(), &[&w.bob.did]) });
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &relayed_write(&w.bob, &w.bob, "createMek", &bob_mek, &bob_mek),
    )
    .await
    .fails(403, "NotHomeDs");
    let signed_read = |device: &Device, signer: &Device, signed_query: &str, query: &str| {
        let (header, sig) = signer.read_headers(&format!("{PREFIX}listBatches"), signed_query);
        json!({ "op": "listBatches", "actorDid": device.did,
                "actorDeviceId": device.device_id.to_string(),
                "query": query, "readHeader": header, "readSignature": sig })
    };
    let read = |device: &Device, thread: Uuid| {
        let q = format!("threadId={thread}");
        signed_read(device, device, &q, &q)
    };
    relay_as(&w, HOME_DS, &home_key, &read(&w.bob, w.thread))
        .await
        .fails(403, "NotHomeDs");

    // A conversation this DS does not sequence.
    let elsewhere = seed_conversation(
        &w.seq,
        &[Leaf {
            device: &w.alice_on_seq,
            joined_seq: 1,
            removed_seq: None,
        }],
        2,
    )
    .await;
    make_remote_to(&w.seq, elsewhere, "did:web:third.labyrinth-relay.dev").await;
    relay_as(&w, HOME_DS, &home_key, &read(&w.alice, elsewhere))
        .await
        .fails(400, "NotSequencer");

    // Relayed reads carry the device's own signed read claim (finding 3):
    // missing, signed by another key, or over another query, they fail.
    let q = format!("threadId={}", w.thread);
    let mut unsigned = read(&w.alice, w.thread);
    unsigned.as_object_mut().unwrap().remove("readHeader");
    relay_as(&w, HOME_DS, &home_key, &unsigned)
        .await
        .fails(400, "InvalidRequest");
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &signed_read(&w.alice, &impostor, &q, &q),
    )
    .await
    .fails(401, "InvalidSignature");
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &signed_read(&w.alice, &w.alice, &format!("{q}&limit=1"), &q),
    )
    .await
    .fails(400, "InvalidRequest");
    // A claim by bob cannot be relayed as alice's read.
    let mut swapped = signed_read(&w.bob, &w.bob, &q, &q);
    swapped["actorDid"] = json!(w.alice.did);
    swapped["actorDeviceId"] = json!(w.alice.device_id.to_string());
    relay_as(&w, HOME_DS, &home_key, &swapped)
        .await
        .fails(400, "InvalidRequest");
    relay_as(&w, HOME_DS, &home_key, &read(&w.alice, w.thread))
        .await
        .ok();

    // The real thing works, until the device is revoked on the sequencer.
    relay_as(
        &w,
        HOME_DS,
        &home_key,
        &relayed_write(&w.alice, &w.alice, "createMek", &mek, &mek),
    )
    .await
    .ok();
    w.seq.revoke(&w.alice_on_seq).await;
    relay_as(&w, HOME_DS, &home_key, &read(&w.alice, w.thread))
        .await
        .fails(401, "DeviceRevoked");
}

fn point(label: &[u8]) -> [u8; 32] {
    let h: [u8; 64] = Sha512::digest(label).into();
    RistrettoPoint::from_uniform_bytes(&h).compress().to_bytes()
}

#[tokio::test]
async fn attachment_existence_and_account_deletion_reach_the_sequencer() {
    let object = TestObject {
        key: "bafy-relay-object".to_owned(),
        data: vec![0x21; 40],
    };
    let w = world(Some(&object)).await;
    grant_interval(&w.home, w.thread, &w.alice, 1, None).await;
    let (blob, message) = seed_bound_attachment(&w.home, &w.alice, w.thread, &object, 5).await;
    let message = message.to_string();
    let key = [0xC4; 32];
    w.alice
        .call("registerOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
    w.alice
        .call(
            "putAttachmentRef",
            &json!({ "deviceKeyPubkey": b(&key), "blindedIndex": b(&point(b"i")),
                     "blindedTokenSalt": b(&point(b"t")), "blobId": blob.to_string(),
                     "threadId": w.thread.to_string(), "messageId": message }),
        )
        .await
        .ok();
    let fetch = || async {
        w.alice
            .query(
                "getAttachmentBlob",
                &[
                    ("deviceKeyPubkey", hex::encode(key)),
                    ("blindedIndex", hex::encode(point(b"i"))),
                    ("blindedTokenSalt", hex::encode(point(b"t"))),
                    ("threadId", w.thread.to_string()),
                    ("messageId", message.clone()),
                ],
            )
            .await
    };
    // Not yet stored on the sequencer.
    fetch().await.fails(404, "NotFound");
    // Bob's copy on the sequencer, addressed to alice, makes it exist.
    w.bob
        .call("createMek", &json!({ "record": transport_mek(w.thread, MEK_B, w.bob.chat_pub(), &[&w.alice.did, &w.bob.did]) }))
        .await
        .ok();
    w.bob
        .call("appendBatch", &batch(w.thread, &w.bob, MEK_B, &[&message]))
        .await
        .ok();
    let got = fetch().await;
    assert_eq!(got.status.as_u16(), 200, "{}", got.json);
    assert_eq!(got.bytes, object.data);

    // deleteAccountData: the sequencer redacts alice's items, unsigned.
    w.alice
        .call("createMek", &json!({ "record": transport_mek(w.thread, MEK_A, w.alice.chat_pub(), &[&w.alice.did, &w.bob.did]) }))
        .await
        .ok();
    w.alice
        .call(
            "appendBatch",
            &batch(w.thread, &w.alice, MEK_A, &["a1", "a2"]),
        )
        .await
        .ok();
    w.alice.enroll([0xA0; 32]).await;
    w.alice.call("deleteAccountData", &json!({})).await.ok();
    let page = w
        .bob
        .query("listBatches", &[("threadId", w.thread.to_string())])
        .await;
    for b in page.ok()["items"].as_array().unwrap() {
        for item in b["record"]["items"].as_array().unwrap() {
            let redacted = item.get("redaction").is_some();
            assert_eq!(redacted, b["author"] == w.alice.did.as_str(), "{item}");
        }
    }
    assert_eq!(rows(&w.home, "orf_states").await, 0, "home mailbox purged");
}

#[tokio::test]
async fn lookups_of_remote_conversations_reach_the_sequencer() {
    let w = world(None).await;
    let to = [w.alice.did.as_str(), w.bob.did.as_str()];
    let mek = |sender: &Device, id| json!({ "record": transport_mek(w.thread, id, sender.chat_pub(), &to) });
    w.alice.call("createMek", &mek(&w.alice, MEK_A)).await.ok();
    w.alice
        .call(
            "appendBatch",
            &batch(w.thread, &w.alice, MEK_A, &["a1", "a2"]),
        )
        .await
        .ok();
    w.bob
        .call("appendBatch", &batch(w.thread, &w.bob, MEK_A, &["b1"]))
        .await
        .ok();

    // getMessages: relayed, identical to a direct read on the sequencer.
    let params = [
        ("threadId", w.thread.to_string()),
        ("messageIds", "a2".to_owned()),
        ("messageIds", "b1".to_owned()),
    ];
    let via_relay = w.alice.query("getMessages", &params).await;
    let direct = w.alice_on_seq.query("getMessages", &params).await;
    assert_eq!(via_relay.ok()["items"].as_array().unwrap().len(), 2);
    assert_eq!(via_relay.json, direct.json);
    // Newest-first listBatches through the relay.
    let newest = w
        .alice
        .query(
            "listBatches",
            &[
                ("threadId", w.thread.to_string()),
                ("reverse", "true".into()),
            ],
        )
        .await;
    let seqs: Vec<i64> = newest.ok()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["order"]["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![3, 2]);

    // listThreads merges the home DS's own conversations with the
    // sequencer's. A sequencer conversation in which the home DS is not
    // alice's home DS is not listed through the relay.
    let carol = w.home.account().await;
    let leaf = |device| Leaf {
        device,
        joined_seq: 1,
        removed_seq: None,
    };
    let local = seed_conversation(&w.home, &[leaf(&w.alice), leaf(&carol)], 2).await;
    w.alice
        .call(
            "createMek",
            &json!({ "record": transport_mek(local, MEK_B, w.alice.chat_pub(), &[&carol.did]) }),
        )
        .await
        .ok();
    let elsewhere = seed_conversation(&w.seq, &[leaf(&w.alice_on_seq), leaf(&w.bob)], 2).await;
    w.bob
        .call("createMek", &json!({ "record": transport_mek(elsewhere, MEK_B, w.bob.chat_pub(), &[&w.alice.did]) }))
        .await
        .ok();
    let ids = |reply: &Reply| -> Vec<String> {
        reply.ok()["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["threadId"].as_str().unwrap().to_owned())
            .collect()
    };
    let mut expected = [w.thread, local];
    expected.sort();
    let expected: Vec<String> = expected.iter().map(Uuid::to_string).collect();
    assert_eq!(ids(&w.alice.query("listThreads", &[]).await), expected);
    let first = w.alice.query("listThreads", &[("limit", "1".into())]).await;
    assert_eq!(ids(&first), expected[..1]);
    let cursor = first.json["cursor"].as_str().unwrap().to_owned();
    let rest = w.alice.query("listThreads", &[("cursor", cursor)]).await;
    assert_eq!(ids(&rest), expected[1..]);
    assert!(rest.json.get("cursor").is_none());
    // Bob, homed on the sequencer, lists both of his there directly.
    let mut bobs = [w.thread, elsewhere];
    bobs.sort();
    let bobs: Vec<String> = bobs.iter().map(Uuid::to_string).collect();
    assert_eq!(ids(&w.bob.query("listThreads", &[]).await), bobs);
}

//! Labyrinth backend: ORF states and attachment references (SPEC §8,
//! whitepaper v1.1 p.41-43; gap audit G-P0-1, decision J4; migration
//! `20261004100005`).

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use harness::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use uuid::Uuid;

const MEK: [u8; 12] = [9; 12];

/// `client_map(c, domain, x)` without the client's HMAC scoping: the server
/// only sees `H(x) * c`.
fn blind(c: Scalar, x: &[u8]) -> [u8; 32] {
    let h: [u8; 64] = Sha512::digest(x).into();
    (RistrettoPoint::from_uniform_bytes(&h) * c)
        .compress()
        .to_bytes()
}

fn object() -> TestObject {
    TestObject {
        key: "bafy-labyrinth-test-object".to_owned(),
        data: vec![0x5A; 64],
    }
}

/// The same bytes under another object-store key (keys are unique).
fn keyed(object: &TestObject, suffix: &str) -> TestObject {
    TestObject {
        key: format!("{}-{suffix}", object.key),
        data: object.data.clone(),
    }
}

/// One member's view of a reference: device key, client scalar, labels.
#[derive(Clone, Copy)]
struct Client {
    device_key: [u8; 32],
    c: Scalar,
}

impl Client {
    fn put(&self, label: &str, blob: Uuid, thread: Uuid, message: &str) -> Value {
        json!({
            "deviceKeyPubkey": b(&self.device_key),
            "blindedIndex": b(&blind(self.c, format!("idx-{label}").as_bytes())),
            "blindedTokenSalt": b(&blind(self.c, format!("tok-{label}").as_bytes())),
            "blobId": blob.to_string(),
            "threadId": thread.to_string(),
            "messageId": message,
        })
    }

    fn get(&self, label: &str, thread: Uuid, message: &str) -> Vec<(&'static str, String)> {
        vec![
            ("deviceKeyPubkey", hex::encode(self.device_key)),
            (
                "blindedIndex",
                hex::encode(blind(self.c, format!("idx-{label}").as_bytes())),
            ),
            (
                "blindedTokenSalt",
                hex::encode(blind(self.c, format!("tok-{label}").as_bytes())),
            ),
            ("threadId", thread.to_string()),
            ("messageId", message.to_owned()),
        ]
    }
}

fn leaves<'a>(devices: &[&'a Device]) -> Vec<Leaf<'a>> {
    devices
        .iter()
        .map(|device| Leaf {
            device,
            joined_seq: 1,
            removed_seq: None,
        })
        .collect()
}

async fn register(device: &Device, key: [u8; 32]) {
    device
        .call("registerOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
}

/// Store one sender message `message_id` from `author` in `thread`, under a
/// transport MEK addressed to `recipients`.
async fn send_message(author: &Device, thread: Uuid, message_id: &str, recipients: &[&str]) {
    author
        .call(
            "createMek",
            &json!({ "record": transport_mek(thread, MEK, author.chat_pub(), recipients) }),
        )
        .await;
    let batch = json!({
        "$type": "blue.catbird.labyrinth.batch",
        "threadId": thread.to_string(),
        "items": [{
            "messageId": message_id,
            "timestamp": 1000,
            "mekId": b(&MEK),
            "senderTransportPubkey": b(&author.chat_pub()),
            "signedEncMessage": b(&[0x61; 96]),
        }],
        "createdAt": "2026-10-04T12:00:00.000Z",
    });
    author
        .call("appendBatch", &json!({ "record": batch }))
        .await
        .ok();
}

#[tokio::test]
async fn orf_states_register_evolve_and_delete() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (parent, child) = ([0xA1; 32], [0xA2; 32]);
    register(&alice, parent).await;
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&parent) }),
        )
        .await
        .fails(409, "RecordAlreadyExists");
    let evolve = |from: [u8; 32], token: [u8; 32]| {
        json!({ "deviceKeyPubkey": b(&child),
                "parent": { "deviceKeyPubkey": b(&from), "evolveToken": b(&token) } })
    };
    alice
        .call(
            "registerOrfState",
            &evolve([0xEE; 32], Scalar::from(3u64).to_bytes()),
        )
        .await
        .fails(404, "OrfStateNotFound");
    alice
        .call("registerOrfState", &evolve(parent, [0; 32]))
        .await
        .fails(400, "InvalidRequest");
    alice
        .call(
            "registerOrfState",
            &evolve(parent, Scalar::from(3u64).to_bytes()),
        )
        .await
        .ok();
    // Once the account keeps its mailbox here (another chat device of it
    // enrolled), deleting a state needs a bound device.
    env.device_for(&alice.did, [0xE2; 32])
        .await
        .enroll([0xE3; 32])
        .await;
    alice
        .call("deleteOrfState", &json!({ "deviceKeyPubkey": b(&child) }))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice.enroll([0xE1; 32]).await;
    alice
        .call("deleteOrfState", &json!({ "deviceKeyPubkey": b(&child) }))
        .await
        .ok();
    alice
        .call("deleteOrfState", &json!({ "deviceKeyPubkey": b(&child) }))
        .await
        .ok();

    // markDeviceRevoked deletes the revoked device's state too.
    alice.enroll([0xB0; 32]).await;
    alice.enroll(parent).await;
    alice
        .call(
            "markDeviceRevoked",
            &json!({ "deviceKeyPubkey": b(&parent), "revokedAt": "2026-10-04T13:00:00.000Z" }),
        )
        .await
        .ok();
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.orf_states WHERE owner_did = $1 AND device_key = $2",
    )
    .bind(&alice.did)
    .bind(parent.as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}

/// G-P0-1: a reference can only be stored for a blob that is a bound
/// attachment of exactly that message of that conversation, by a device that
/// may read it.
#[tokio::test]
async fn put_requires_a_bound_blob_of_that_message_the_device_may_read() {
    let object = object();
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    let bob = env.account().await;
    let a = seed_conversation(&env, &leaves(&[&alice, &bob]), 10).await;
    let other = seed_conversation(&env, &leaves(&[&bob]), 10).await;
    let client = Client {
        device_key: [0xA1; 32],
        c: Scalar::from(77u64),
    };
    register(&alice, client.device_key).await;

    let (blob, message) = seed_bound_attachment(&env, &bob, a, &object, 5).await;
    let message = message.to_string();
    let (foreign_blob, foreign_message) =
        seed_bound_attachment(&env, &bob, other, &keyed(&object, "foreign"), 5).await;
    let unbound = seed_attachment_blob(&env, &bob, &keyed(&object, "unbound")).await;

    // No application interval yet: alice's device may not read the entry.
    alice
        .call("putAttachmentRef", &client.put("1", blob, a, &message))
        .await
        .fails(403, "AttachmentNotEntitled");
    // An interval that ended before the entry does not cover it.
    grant_interval(&env, a, &alice, 1, Some(4)).await;
    alice
        .call("putAttachmentRef", &client.put("1", blob, a, &message))
        .await
        .fails(403, "AttachmentNotEntitled");
    grant_interval(&env, a, &alice, 5, None).await;

    for (label, blob_id, thread, msg) in [
        // An unbound upload.
        ("u", unbound, a, Uuid::new_v4().to_string()),
        // Another conversation's attachment, named under this conversation.
        ("x", foreign_blob, a, foreign_message.to_string()),
        // This attachment under another message id, or a non-chat id.
        ("m", blob, a, Uuid::new_v4().to_string()),
        ("n", blob, a, "not-a-chat-message".to_owned()),
        // The right message, named under another conversation.
        ("c", blob, other, message.clone()),
    ] {
        alice
            .call(
                "putAttachmentRef",
                &client.put(label, blob_id, thread, &msg),
            )
            .await
            .fails(403, "AttachmentNotEntitled");
    }
    // Bob's foreign conversation attachment is his, not alice's.
    alice
        .call(
            "putAttachmentRef",
            &client.put("y", foreign_blob, other, &foreign_message.to_string()),
        )
        .await
        .fails(403, "AttachmentNotEntitled");

    alice
        .call("putAttachmentRef", &client.put("1", blob, a, &message))
        .await
        .ok();
    alice
        .call("putAttachmentRef", &client.put("1", blob, a, &message))
        .await
        .fails(409, "RecordAlreadyExists");

    // A deleted/expired or reclaimed blob is refused.
    let (expired, expired_message) =
        seed_bound_attachment(&env, &bob, a, &keyed(&object, "expired"), 6).await;
    force_blob_state(&env, expired, "expired").await;
    alice
        .call(
            "putAttachmentRef",
            &client.put("e", expired, a, &expired_message.to_string()),
        )
        .await
        .fails(403, "AttachmentNotEntitled");

    // No clear linkage is stored: the row holds no DID, conversation or
    // message id (decision J4).
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT to_jsonb(r)::text FROM labyrinth.attachment_refs r")
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    for needle in [alice.did.as_str(), &a.to_string(), &message] {
        assert!(!rows[0].contains(needle), "attachment_refs leaks {needle}");
    }
}

/// Access needs the token over the exact (thread, message), a still-bound
/// blob, and a message that still exists for the caller (p.42).
#[tokio::test]
async fn get_checks_token_blob_state_and_that_the_message_exists() {
    let object = object();
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    let bob = env.account().await;
    let thread = seed_conversation(
        &env,
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
        10,
    )
    .await;
    grant_interval(&env, thread, &alice, 1, None).await;
    let (blob, message) = seed_bound_attachment(&env, &bob, thread, &object, 5).await;
    let message = message.to_string();
    let parent = Client {
        device_key: [0xA1; 32],
        c: Scalar::from(1234567u64),
    };
    register(&alice, parent.device_key).await;
    alice
        .call("putAttachmentRef", &parent.put("1", blob, thread, &message))
        .await
        .ok();

    // A restored device: its state is evolved, its client scalar c * r.
    let r = Scalar::from(987654u64);
    let child = Client {
        device_key: [0xA2; 32],
        c: parent.c * r,
    };
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&child.device_key),
                     "parent": { "deviceKeyPubkey": b(&parent.device_key), "evolveToken": b(&r.to_bytes()) } }),
        )
        .await
        .ok();
    let found = alice
        .query("getAttachmentRef", &child.get("1", thread, &message)[..2])
        .await;
    assert!(found.ok()["createdAt"].as_str().unwrap().ends_with('Z'));

    // The message is not stored anywhere yet.
    let fetch = |params: Vec<(&'static str, String)>| {
        let alice = alice.clone();
        async move { alice.query("getAttachmentBlob", &params).await }
    };
    fetch(child.get("1", thread, &message))
        .await
        .fails(404, "NotFound");
    // Bob's sender copy, addressed to alice, makes it exist.
    send_message(&bob, thread, &message, &[&alice.did, &bob.did]).await;
    let bytes = fetch(child.get("1", thread, &message)).await;
    assert_eq!(bytes.status.as_u16(), 200, "{}", bytes.json);
    assert_eq!(bytes.bytes, object.data);

    // A token over another message, or the wrong salt, reads as NotFound.
    fetch(child.get("1", thread, &Uuid::new_v4().to_string()))
        .await
        .fails(404, "NotFound");
    let mut wrong_salt = child.get("1", thread, &message);
    wrong_salt[2].1 = hex::encode(blind(child.c, b"tok-other"));
    fetch(wrong_salt).await.fails(404, "NotFound");

    // Another account using the same device key and blinding finds nothing:
    // references are scoped to their owner.
    let carol = env.account().await;
    register(&carol, parent.device_key).await;
    carol
        .query("getAttachmentBlob", &parent.get("1", thread, &message))
        .await
        .fails(404, "NotFound");

    // A blob that left the bound state is no longer served.
    force_blob_state(&env, blob, "expired").await;
    fetch(child.get("1", thread, &message))
        .await
        .fails(404, "NotFound");
}

#[tokio::test]
async fn own_archive_copies_count_and_deletion_revokes() {
    let object = object();
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    // Owner-archive and bundle writes need a bound Labyrinth device.
    alice.enroll([0xE0; 32]).await;
    let thread = seed_conversation(
        &env,
        &[Leaf {
            device: &alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        10,
    )
    .await;
    grant_interval(&env, thread, &alice, 1, None).await;
    let (blob, message) = seed_bound_attachment(&env, &alice, thread, &object, 5).await;
    let message = message.to_string();
    let client = Client {
        device_key: [0xA1; 32],
        c: Scalar::from(5u64),
    };
    register(&alice, client.device_key).await;
    alice
        .call("putAttachmentRef", &client.put("1", blob, thread, &message))
        .await
        .ok();
    alice
        .query("getAttachmentBlob", &client.get("1", thread, &message))
        .await
        .fails(404, "NotFound");

    // An owner-archive copy of the message (re-archived history).
    let mut archive = owner_batch_record(&thread.to_string(), &[1000]);
    archive["items"][0]["messageId"] = json!(message);
    alice
        .call("appendOwnerBatch", &json!({ "record": archive }))
        .await
        .ok();
    let got = alice
        .query("getAttachmentBlob", &client.get("1", thread, &message))
        .await;
    assert_eq!(got.status.as_u16(), 200, "{}", got.json);

    // deleteAttachmentRef is idempotent and revokes access.
    let index = json!({ "deviceKeyPubkey": b(&client.device_key),
                        "blindedIndex": b(&blind(client.c, b"idx-1")) });
    alice.call("deleteAttachmentRef", &index).await.ok();
    alice.call("deleteAttachmentRef", &index).await.ok();
    alice
        .query("getAttachmentBlob", &client.get("1", thread, &message))
        .await
        .fails(404, "NotFound");

    // Deleting the ORF state revokes every read through it.
    alice.enroll([0xE1; 32]).await;
    alice
        .call("putAttachmentRef", &client.put("2", blob, thread, &message))
        .await
        .ok();
    alice
        .call(
            "deleteOrfState",
            &json!({ "deviceKeyPubkey": b(&client.device_key) }),
        )
        .await
        .ok();
    alice
        .query("getAttachmentBlob", &client.get("2", thread, &message))
        .await
        .fails(404, "OrfStateNotFound");

    // Finding 5: the retention pass releases references (and their blob
    // pins) created through a deleted ORF state.
    assert_eq!(table_rows(&env, "attachment_refs").await, 1);
    let gc = catbird_server::labyrinth::repo::retention::run_gc(&env.pool, chrono::Utc::now(), 100)
        .await
        .unwrap();
    assert_eq!(gc.released_refs, 1);
    assert_eq!(table_rows(&env, "attachment_refs").await, 0);
    assert_eq!(table_rows(&env, "orf_state_tombstones").await, 0);
}

async fn table_rows(env: &Env, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM labyrinth.{table}"))
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

/// Findings 5 and 9: a reader's own archive copy never vouches for another
/// author's message; unsend revokes the reader's reference and refuses new
/// ones.
#[tokio::test]
async fn another_authors_message_lives_only_through_its_sender_copy() {
    let object = object();
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    let bob = env.account().await;
    // Owner-archive and bundle writes need a bound Labyrinth device.
    bob.enroll([0xE1; 32]).await;
    let thread = seed_conversation(&env, &leaves(&[&alice, &bob]), 10).await;
    grant_interval(&env, thread, &bob, 1, None).await;
    let (blob, message) = seed_bound_attachment(&env, &alice, thread, &object, 5).await;
    let message = message.to_string();
    let client = Client {
        device_key: [0xB1; 32],
        c: Scalar::from(7u64),
    };
    register(&bob, client.device_key).await;
    bob.call("putAttachmentRef", &client.put("1", blob, thread, &message))
        .await
        .ok();
    let fetch = || async {
        bob.query("getAttachmentBlob", &client.get("1", thread, &message))
            .await
    };
    // Bob archived the message himself; that is not alice's sender copy.
    let mut archive = owner_batch_record(&thread.to_string(), &[1000]);
    archive["items"][0]["messageId"] = json!(message);
    bob.call("appendOwnerBatch", &json!({ "record": archive }))
        .await
        .ok();
    fetch().await.fails(404, "NotFound");
    // Alice's sender copy addressed to bob makes it live.
    send_message(&alice, thread, &message, &[&alice.did, &bob.did]).await;
    let got = fetch().await;
    assert_eq!(got.status.as_u16(), 200, "{}", got.json);
    // Alice unsends: bob's reference goes, and no new one can be put.
    let signed = format!(
        "catbird.labyrinth.redaction:did={};message_id={message};thread_id={}",
        alice.did,
        hex::encode(thread.to_string().as_bytes())
    );
    use ed25519_dalek::Signer as _;
    alice
        .call(
            "redactMessage",
            &json!({ "threadId": thread.to_string(), "messageId": message, "redaction": {
                "transportPubkey": b(&alice.chat_pub()),
                "sig": b(&alice.chat_key.sign(signed.as_bytes()).to_bytes()) } }),
        )
        .await
        .ok();
    assert_eq!(table_rows(&env, "attachment_refs").await, 0);
    fetch().await.fails(404, "NotFound");
    bob.call("putAttachmentRef", &client.put("2", blob, thread, &message))
        .await
        .fails(410, "MessageRedacted");
}

/// L-F07: `labyrinth.sender_message_state` must require `ever_participant` and
/// leaf-interval coverage (`d.joined_seq <= b.chat_seq < d.removed_seq`), so an
/// outsider addressed in `mek_recipients` or a removed member for a post-removal
/// batch never sees `live = true`.
#[tokio::test]
async fn lf07_sender_message_state_requires_participant_and_leaf_coverage() {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let outsider = env.account().await;

    let thread = seed_conversation(&env, &leaves(&[&alice, &bob]), 3).await;
    // Alice removes Bob at MLS transition seq = 3 (`removed_seq = 3`, `next_entry_seq = 4`),
    // then appends a batch (which receives `chat_seq = 3`, i.e., post-removal).
    remove_member(&env, thread, &bob, 3).await;
    set_next_entry_seq(&env, thread, 4).await;

    // Seed a MEK row + post-removal batch directly via SQL only if handler blocks
    // non-participants, or check what happens when Alice addresses herself, then inspect
    // `sender_message_state` when `mek_recipients` contains `bob` and `outsider` (simulating
    // a pre-hardening MEK or pre-removal MEK reused after Bob's removal!).
    // Specifically: Bob WAS an accepted participant before seq 3, so Alice could address
    // MEK to `[alice, bob]` BEFORE removing Bob! Let's test that exact real attack!
    let thread2 = seed_conversation(&env, &leaves(&[&alice, &bob]), 3).await;
    alice
        .call(
            "createMek",
            &json!({ "record": transport_mek(thread2, MEK, alice.chat_pub(), &[&alice.did, &bob.did]) }),
        )
        .await
        .ok();
    // Now Bob is removed at seq = 3 (`removed_seq = 3`, `next_entry_seq = 4`), and Alice sends
    // a post-removal message (`chat_seq = 3`) reusing that pre-removal MEK!
    remove_member(&env, thread2, &bob, 3).await;
    set_next_entry_seq(&env, thread2, 4).await;
    let post_removal_msg = "msg-post-removal";
    let batch = json!({
        "$type": "blue.catbird.labyrinth.batch",
        "threadId": thread2.to_string(),
        "items": [{
            "messageId": post_removal_msg,
            "timestamp": 2000,
            "mekId": b(&MEK),
            "senderTransportPubkey": b(&alice.chat_pub()),
            "signedEncMessage": b(&[0x61; 96]),
        }],
        "createdAt": "2026-10-04T12:00:00.000Z",
    });
    alice
        .call("appendBatch", &json!({ "record": batch }))
        .await
        .ok();

    let mut conn = env.pool.acquire().await.unwrap();
    let (bob_live, _) = catbird_server::labyrinth::repo::liveness::sender_state(
        &mut conn,
        &bob.did,
        thread2,
        post_removal_msg,
        &alice.did,
    )
    .await
    .unwrap();
    assert!(
        !bob_live,
        "removed member must not see post-removal batch (chat_seq == removed_seq) as live"
    );

    // Also insert a synthetic `mek_recipients` row for `outsider` (as from a pre-L-F03 row)
    // and verify SQL `sender_message_state` itself enforces `ever_participant` + `leaf_covered`.
    sqlx::query(
        "INSERT INTO labyrinth.mek_recipients (conversation_id, mek_id, author_did, recipient_did) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(thread2)
    .bind(MEK.as_slice())
    .bind(&alice.did)
    .bind(&outsider.did)
    .execute(&mut *conn)
    .await
    .unwrap();

    let (outsider_live, _) = catbird_server::labyrinth::repo::liveness::sender_state(
        &mut conn,
        &outsider.did,
        thread2,
        post_removal_msg,
        &alice.did,
    )
    .await
    .unwrap();
    assert!(
        !outsider_live,
        "non-participant in mek_recipients must not see message as live"
    );
}

/// L-F09: hosted accounts enforce `require_bound_if_hosted` on `putAttachmentRef`,
/// `deleteAttachmentRef`, `getAttachmentRef`, and `getAttachmentBlob`, and an active
/// physical device cannot overwrite or delete another active physical sibling's ORF state.
#[tokio::test]
async fn lf09_hosted_attachment_and_orf_endpoints_enforce_device_and_sibling_binding() {
    let object = object();
    let env = Env::with(true, Some(&object)).await;
    let alice_d1 = env.account().await;
    let alice_d2 = env.device_for(&alice_d1.did, [0xD2; 32]).await;
    let alice_unbound = env.device_for(&alice_d1.did, [0xD3; 32]).await;
    let bob = env.account().await;

    let d1_key = [0xA1; 32];
    let d2_key = [0xA2; 32];
    alice_d1.enroll(d1_key).await;
    alice_d2.enroll(d2_key).await;

    // Physical device d1 registers its own ORF state; active sibling d2 cannot
    // overwrite/evolve or delete d1's active physical ORF state!
    register(&alice_d1, d1_key).await;
    alice_d2
        .call(
            "registerOrfState",
            &json!({
                "deviceKeyPubkey": b(&[0xA9; 32]),
                "parent": {
                    "deviceKeyPubkey": b(&d1_key),
                    "evolveToken": b(&Scalar::from(5u64).to_bytes()),
                }
            }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice_d2
        .call("deleteOrfState", &json!({ "deviceKeyPubkey": b(&d1_key) }))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // Nor can d2 register an ORF state AT d2_key? Wait: d2 CAN register d2_key,
    // whereas d1 CANNOT register d2_key before d2 does!
    alice_d1
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&d2_key) }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");

    // Seed an attachment on a conversation containing alice_d1, alice_unbound, and bob.
    let thread = seed_conversation(&env, &leaves(&[&alice_d1, &alice_unbound, &bob]), 10).await;
    grant_interval(&env, thread, &alice_d1, 1, None).await;
    grant_interval(&env, thread, &alice_unbound, 1, None).await;
    let (blob, message) = seed_bound_attachment(&env, &bob, thread, &object, 5).await;
    let message = message.to_string();
    send_message(&bob, thread, &message, &[&alice_d1.did, &bob.did]).await;

    let client = Client {
        device_key: d1_key,
        c: Scalar::from(19u64),
    };

    // Unbound chat device on a hosted account is rejected on all 4 attachment endpoints.
    alice_unbound
        .call("putAttachmentRef", &client.put("1", blob, thread, &message))
        .await
        .fails(403, "LabyrinthDeviceNotBound");

    // Bound device d1 stores the ref cleanly.
    alice_d1
        .call("putAttachmentRef", &client.put("1", blob, thread, &message))
        .await
        .ok();

    alice_unbound
        .query("getAttachmentRef", &client.get("1", thread, &message)[..2])
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice_unbound
        .query("getAttachmentBlob", &client.get("1", thread, &message))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice_unbound
        .call(
            "deleteAttachmentRef",
            &json!({
                "deviceKeyPubkey": b(&client.device_key),
                "blindedIndex": b(&blind(client.c, b"idx-1")),
            }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
}

//! Labyrinth backend: retention (decisions J1, J2; migration
//! `20261004100006`): unsend by author redaction, mailbox and account
//! purge, recovery-bundle lifecycle, idempotency GC, and the retention scope
//! that keeps every row immutable to ordinary SQL.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use catbird_server::labyrinth::repo::retention::run_gc;
use chrono::Duration;
use ed25519_dalek::Signer as _;
use harness::*;
use serde_json::{json, Value};
use uuid::Uuid;

const MEK: [u8; 12] = [4; 12];

fn leaf(device: &Device) -> Leaf<'_> {
    Leaf {
        device,
        joined_seq: 1,
        removed_seq: None,
    }
}

fn batch(thread: Uuid, sender: &Device, messages: &[&str]) -> Value {
    let items: Vec<Value> = messages
        .iter()
        .map(|m| {
            json!({
                "messageId": m,
                "timestamp": 1000,
                "mekId": b(&MEK),
                "senderTransportPubkey": b(&sender.chat_pub()),
                "signedEncMessage": b(&[0x61; 96]),
            })
        })
        .collect();
    json!({ "record": {
        "$type": "blue.catbird.labyrinth.batch",
        "threadId": thread.to_string(),
        "items": items,
        "createdAt": "2026-10-04T12:00:00.000Z",
    }})
}

fn redaction(device: &Device, thread: Uuid, message: &str) -> Value {
    let signed = format!(
        "catbird.labyrinth.redaction:did={};message_id={message};thread_id={}",
        device.did,
        hex::encode(thread.to_string().as_bytes())
    );
    json!({
        "transportPubkey": b(&device.chat_pub()),
        "sig": b(&device.chat_key.sign(signed.as_bytes()).to_bytes()),
    })
}

fn redact(device: &Device, thread: Uuid, message: &str) -> Value {
    json!({ "threadId": thread.to_string(), "messageId": message,
            "redaction": redaction(device, thread, message) })
}

/// Every item of a `listBatches` page, flattened.
async fn items(reader: &Device, thread: Uuid) -> Vec<(String, Value)> {
    let page = reader
        .query("listBatches", &[("threadId", thread.to_string())])
        .await;
    page.ok()["items"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|b| {
            let author = b["author"].as_str().unwrap().to_owned();
            b["record"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |i| (author.clone(), i.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn usage(env: &Env, did: &str) -> i64 {
    sqlx::query_scalar("SELECT bytes_used FROM labyrinth.author_usage WHERE author_did = $1")
        .bind(did)
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

/// Two members exchange messages under alice's MEK; bob reuses message id
/// `m1` for his own message ([CB-31]).
async fn chat(env: &Env) -> (Device, Device, Uuid) {
    let alice = env.account().await;
    let bob = env.account().await;
    let thread = seed_conversation(env, &[leaf(&alice), leaf(&bob)], 10).await;
    alice
        .call(
            "createMek",
            &json!({ "record": transport_mek(thread, MEK, alice.chat_pub(), &[&alice.did, &bob.did]) }),
        )
        .await
        .ok();
    alice
        .call("appendBatch", &batch(thread, &alice, &["m1", "m2"]))
        .await
        .ok();
    bob.call("appendBatch", &batch(thread, &bob, &["m1"]))
        .await
        .ok();
    (alice, bob, thread)
}

#[tokio::test]
async fn unsend_redacts_only_the_authors_items_and_keeps_their_order() {
    let env = Env::new().await;
    let (alice, bob, thread) = chat(&env).await;
    let before = items(&bob, thread).await;
    let usage_before = usage(&env, &alice.did).await;

    // A bad or foreign signature is refused.
    let mut forged = redact(&alice, thread, "m1");
    forged["redaction"] = redaction(&alice, thread, "m2");
    alice
        .call("redactMessage", &forged)
        .await
        .fails(400, "InvalidRedaction");
    let mut foreign = redact(&alice, thread, "m1");
    foreign["redaction"]["transportPubkey"] = b(&bob.chat_pub());
    alice
        .call("redactMessage", &foreign)
        .await
        .fails(400, "InvalidRedaction");

    // Bob's unsend of "m1" touches only his own copy.
    let bobs = bob.call("redactMessage", &redact(&bob, thread, "m1")).await;
    assert_eq!(bobs.ok()["redacted"], 1);
    let alices = alice
        .call("redactMessage", &redact(&alice, thread, "m1"))
        .await;
    assert_eq!(alices.ok()["redacted"], 1);
    // Idempotent: nothing left to redact.
    let again = alice
        .call("redactMessage", &redact(&alice, thread, "m1"))
        .await;
    assert_eq!(again.ok()["redacted"], 0);

    let after = items(&bob, thread).await;
    assert_eq!(after.len(), before.len(), "rows and items stay");
    for ((author, item), (_, old)) in after.iter().zip(&before) {
        assert_eq!(item["messageId"], old["messageId"]);
        assert_eq!(item["timestamp"], old["timestamp"]);
        if item["messageId"] == "m1" {
            assert_eq!(item["signedEncMessage"], json!({ "$bytes": "" }));
            let r = &item["redaction"];
            assert!(r["redactedAt"].as_str().unwrap().ends_with('Z'));
            let signer = if author == &alice.did { &alice } else { &bob };
            assert_eq!(r["transportPubkey"], b(&signer.chat_pub()));
            assert_eq!(unb(&r["sig"]).len(), 64);
        } else {
            assert_eq!(item, old, "{author}'s m2 is untouched");
        }
    }
    // Usage follows the stored bytes exactly.
    let stored: i64 = sqlx::query_scalar(
        "SELECT (SELECT coalesce(sum(record_bytes), 0) FROM labyrinth.batches WHERE author_did = $1) \
              + (SELECT coalesce(sum(record_bytes), 0) FROM labyrinth.meks WHERE author_did = $1)",
    )
    .bind(&alice.did)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(usage(&env, &alice.did).await, stored);
    assert_ne!(usage(&env, &alice.did).await, usage_before);

    // Ordinary SQL still cannot delete or rewrite thread rows.
    assert!(sqlx::query("DELETE FROM labyrinth.batches")
        .execute(&env.pool)
        .await
        .is_err());
    assert!(sqlx::query(
        "UPDATE labyrinth.batches SET record = record || '{}'::jsonb, record_bytes = 1"
    )
    .execute(&env.pool)
    .await
    .is_err());
}

#[tokio::test]
async fn unsend_invalidates_attachment_references_to_the_message() {
    let object = TestObject {
        key: "bafy-retention-object".to_owned(),
        data: vec![0x33; 48],
    };
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    let bob = env.account().await;
    let thread = seed_conversation(&env, &[leaf(&alice), leaf(&bob)], 10).await;
    grant_interval(&env, thread, &bob, 1, None).await;
    let (blob, message) = seed_bound_attachment(&env, &alice, thread, &object, 5).await;
    let message = message.to_string();
    alice
        .call(
            "createMek",
            &json!({ "record": transport_mek(thread, MEK, alice.chat_pub(), &[&alice.did, &bob.did]) }),
        )
        .await
        .ok();
    alice
        .call("appendBatch", &batch(thread, &alice, &[&message]))
        .await
        .ok();

    let key = [0xB1; 32];
    bob.call("registerOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
    let point = |label: &[u8]| {
        use sha2::Digest;
        let h: [u8; 64] = sha2::Sha512::digest(label).into();
        curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&h)
            .compress()
            .to_bytes()
    };
    bob.call(
        "putAttachmentRef",
        &json!({ "deviceKeyPubkey": b(&key), "blindedIndex": b(&point(b"i")),
                 "blindedTokenSalt": b(&point(b"t")), "blobId": blob.to_string(),
                 "threadId": thread.to_string(), "messageId": message }),
    )
    .await
    .ok();
    let get = || {
        let bob = bob.clone();
        let message = message.clone();
        async move {
            bob.query(
                "getAttachmentBlob",
                &[
                    ("deviceKeyPubkey", hex::encode(key)),
                    ("blindedIndex", hex::encode(point(b"i"))),
                    ("blindedTokenSalt", hex::encode(point(b"t"))),
                    ("threadId", thread.to_string()),
                    ("messageId", message),
                ],
            )
            .await
        }
    };
    assert_eq!(get().await.status.as_u16(), 200);

    alice
        .call("redactMessage", &redact(&alice, thread, &message))
        .await
        .ok();
    get().await.fails(404, "NotFound");
    let refs: i64 = sqlx::query_scalar("SELECT count(*) FROM labyrinth.attachment_refs")
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(refs, 0, "the reference row itself is gone");
}

async fn count(env: &Env, table: &str, column: &str, did: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM labyrinth.{table} WHERE {column} = $1"
    ))
    .bind(did)
    .fetch_one(&env.pool)
    .await
    .unwrap()
}

const MAILBOX_TABLES: &[(&str, &str)] = &[
    ("mailboxes", "owner_did"),
    ("devices", "owner_did"),
    ("epochs", "owner_did"),
    ("epoch_members", "owner_did"),
    ("virtual_devices", "owner_did"),
    ("owner_batches", "owner_did"),
    ("owner_batch_items", "owner_did"),
    ("orf_states", "owner_did"),
    ("epoch_heads", "did"),
];

/// A full mailbox for the vector DID: device, epoch 0 with a member, a
/// recovery bundle, an owner batch and an ORF state.
async fn fill_mailbox(d0: &Device, v: &Vectors) {
    d0.enroll([0xD0; 32]).await;
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.chain[0], [0xD0; 32]),
                 "members": [member_record(0, [0xD0; 32])] }),
    )
    .await
    .ok();
    d0.call(
        "createVirtualDevice",
        &json!({ "record": vdevice_record([0xAA; 16], [0xBB; 32]) }),
    )
    .await
    .ok();
    d0.call(
        "appendOwnerBatch",
        &json!({ "record": owner_batch_record("t", &[1]) }),
    )
    .await
    .ok();
    d0.call(
        "registerOrfState",
        &json!({ "deviceKeyPubkey": b(&[0xD0; 32]) }),
    )
    .await
    .ok();
}

#[tokio::test]
async fn purge_mailbox_resets_the_account_and_nothing_else() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    fill_mailbox(&d0, &v).await;
    let bob = env.account().await;
    bob.enroll([0xB0; 32]).await;

    d0.call("purgeMailbox", &json!({})).await.ok();
    for (table, column) in MAILBOX_TABLES {
        assert_eq!(
            count(&env, table, column, &v.did).await,
            0,
            "{table} purged"
        );
    }
    assert_eq!(count(&env, "devices", "owner_did", &bob.did).await, 1);
    d0.query("getEpochHead", &[("did", v.did.clone())])
        .await
        .fails(404, "EpochNotFound");
    // The account enrolls again from epoch 0.
    d0.enroll([0xD0; 32]).await;
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.chain[0], [0xD0; 32]), "members": [] }),
    )
    .await
    .ok();
    // Only a bound device purges a mailbox kept here (finding 6).
    let other = env.device_for(&v.did, random_seed()).await;
    other
        .call("purgeMailbox", &json!({}))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // A retry of the same operation replays; once no mailbox is kept here,
    // a fresh purge has nothing to guard and is a no-op.
    d0.call_op("purgeMailbox", &json!({}), [0x77; 16])
        .await
        .ok();
    d0.call_op("purgeMailbox", &json!({}), [0x77; 16])
        .await
        .ok();
    d0.call("purgeMailbox", &json!({})).await.ok();
}

#[tokio::test]
async fn delete_account_data_purges_signs_redactions_and_keeps_operations() {
    let env = Env::new().await;
    let (alice, bob, thread) = chat(&env).await;
    alice.enroll([0xA0; 32]).await;
    let owner_batch = json!({ "record": owner_batch_record("t", &[1]) });
    let before = alice.call_op("appendOwnerBatch", &owner_batch, [0x0B; 16]).await;
    before.ok();

    alice.call("deleteAccountData", &json!({})).await.ok();
    for (table, column) in MAILBOX_TABLES {
        assert_eq!(
            count(&env, table, column, &alice.did).await,
            0,
            "{table} purged"
        );
    }
    // Finding 10: idempotency records survive the deletion, so a replayed
    // pre-deletion write answers from its record and writes nothing.
    let ops = count(&env, "operations", "owner_did", &alice.did).await;
    assert!(ops >= 5, "operations kept: {ops}");
    let replay = alice.call_op("appendOwnerBatch", &owner_batch, [0x0B; 16]).await;
    assert_eq!(replay.bytes, before.bytes);
    assert_eq!(count(&env, "owner_batches", "owner_did", &alice.did).await, 0);
    // The MEK stays: bob's batch is sealed under it.
    assert_eq!(count(&env, "meks", "author_did", &alice.did).await, 1);
    // Finding 7: each account-deletion redaction names this DS and the
    // reason, and is signed by the DS redaction key over the agreed message.
    let by = catbird_server::identity::service_did();
    let ds_key = ed25519_dalek::SigningKey::from_bytes(&REDACTION_SEED).verifying_key();
    let mut seen = 0;
    for (author, item) in items(&bob, thread).await {
        if author == alice.did {
            assert_eq!(item["signedEncMessage"], json!({ "$bytes": "" }));
            let r = &item["redaction"];
            assert!(r.get("transportPubkey").is_none());
            assert_eq!(r["by"], json!(by));
            assert_eq!(r["reason"], "accountDeleted");
            let message = catbird_server::labyrinth::ds_sign::message(
                &by,
                &alice.did,
                item["messageId"].as_str().unwrap(),
                r["redactedAt"].as_str().unwrap(),
                &thread.to_string(),
            );
            let sig: [u8; 64] = unb(&r["sig"]).try_into().unwrap();
            ds_key
                .verify_strict(message.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig))
                .expect("DS redaction signature verifies");
            seen += 1;
        } else {
            assert_eq!(unb(&item["signedEncMessage"]).len(), 96, "bob's items stay");
            assert!(item.get("redaction").is_none());
        }
    }
    assert_eq!(seen, 2);

    // Finding 4: a conversation sequenced elsewhere does not block the
    // deletion; its purge is queued durably for that sequencer.
    let carol = env.account().await;
    let remote = seed_conversation(&env, &[leaf(&carol)], 2).await;
    make_remote(&env, remote).await;
    carol.enroll([0xC0; 32]).await;
    let unbound = env.device_for(&carol.did, random_seed()).await;
    unbound
        .call("deleteAccountData", &json!({}))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    carol.call("deleteAccountData", &json!({})).await.ok();
    assert_eq!(count(&env, "devices", "owner_did", &carol.did).await, 0);
    let queued: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT op, status, request->>'actorDid' FROM labyrinth.relay_outbox",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0],
        ("purgeAuthor".to_owned(), "pending".to_owned(), carol.did.clone())
    );
}

fn vdevice(id: u8, mechanism: &str) -> Value {
    let mut record = vdevice_record([id; 16], [id; 32]);
    record["mechanism"] = json!(mechanism);
    json!({ "record": record })
}

#[tokio::test]
async fn recovery_bundles_record_use_expire_when_idle_and_can_be_deleted() {
    let env = Env::new().await;
    let alice = env.account().await;
    for (id, mechanism) in [
        (1, "keychain"),
        (2, "passkey"),
        (3, "code"),
        (4, "keychain"),
    ] {
        alice
            .call("createVirtualDevice", &vdevice(id, mechanism))
            .await
            .ok();
    }
    // A client may not write lastUsedAt.
    let mut forged = vdevice(5, "code");
    forged["record"]["lastUsedAt"] = json!("2026-10-04T12:00:00.000Z");
    alice
        .call("createVirtualDevice", &forged)
        .await
        .fails(400, "InvalidRequest");

    let got = alice
        .query("getVirtualDevice", &[("vdeviceId", hex::encode([1u8; 16]))])
        .await;
    assert!(got.ok()["record"]["lastUsedAt"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    alice
        .call("touchVirtualDevice", &json!({ "vdeviceId": b(&[4; 16]) }))
        .await
        .ok();
    alice
        .call("touchVirtualDevice", &json!({ "vdeviceId": b(&[9; 16]) }))
        .await
        .fails(404, "VirtualDeviceNotFound");

    // Delete one bundle: its row, its ORF state and its counters go.
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xAA; 32]) }),
        )
        .await
        .ok();
    alice
        .call("registerOrfState", &json!({ "deviceKeyPubkey": b(&[4; 32]),
            "parent": { "deviceKeyPubkey": b(&[0xAA; 32]), "evolveToken": b(&{ let mut t = [0u8; 32]; t[0] = 7; t }) } }))
        .await
        .ok();
    let vdevices: i64 =
        sqlx::query_scalar("SELECT vdevice_count FROM labyrinth.mailboxes WHERE owner_did = $1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    // Deleting a bundle needs a bound Labyrinth device (review 2, finding 6).
    alice
        .call("deleteVirtualDevice", &json!({ "vdeviceId": b(&[4; 16]) }))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice.enroll([0xA7; 32]).await;
    alice
        .call("deleteVirtualDevice", &json!({ "vdeviceId": b(&[4; 16]) }))
        .await
        .ok();
    alice
        .call("deleteVirtualDevice", &json!({ "vdeviceId": b(&[4; 16]) }))
        .await
        .fails(404, "VirtualDeviceNotFound");
    let after: i64 =
        sqlx::query_scalar("SELECT vdevice_count FROM labyrinth.mailboxes WHERE owner_did = $1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(after, vdevices - 1);
    let orf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.orf_states WHERE owner_did = $1 AND device_key = $2",
    )
    .bind(&alice.did)
    .bind([4u8; 32].as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(orf, 0);

    // GC: idempotency records go after 7 days; idle keychain/passkey bundles
    // after 180; code bundles never.
    let now = env.now().await;
    let first = run_gc(&env.pool, now + Duration::days(8), 500)
        .await
        .unwrap();
    assert!(first.operations >= 6, "{first:?}");
    assert_eq!(first.virtual_devices, 0);
    assert_eq!(count(&env, "operations", "owner_did", &alice.did).await, 0);
    let later = run_gc(&env.pool, now + Duration::days(181), 500)
        .await
        .unwrap();
    assert_eq!(later.virtual_devices, 2, "{later:?}");
    let left: Vec<String> = sqlx::query_scalar(
        "SELECT record->>'mechanism' FROM labyrinth.virtual_devices WHERE owner_did = $1",
    )
    .bind(&alice.did)
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert_eq!(left, vec!["code".to_owned()]);
}

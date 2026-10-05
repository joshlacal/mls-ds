//! Labyrinth backend: direct lookups (whitepaper "Database Abstraction":
//! by inbox, by thread, by message id, by time range). `getMessages`,
//! `listThreads`, `listOwnerThreads`, and newest-first paging plus server
//! `receivedAt` windows on `listBatches` / `listOwnerBatches`. The relayed
//! forms are in `labyrinth_relay`.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use ed25519_dalek::Signer as _;
use harness::*;
use serde_json::{json, Value};
use uuid::Uuid;

const MEK1: [u8; 12] = [1; 12];
const MEK2: [u8; 12] = [2; 12];

fn leaf(device: &Device, joined_seq: i64) -> Leaf<'_> {
    Leaf {
        device,
        joined_seq,
        removed_seq: None,
    }
}

fn items(reply: &Reply) -> Vec<Value> {
    reply.ok()["items"].as_array().unwrap().clone()
}

fn seqs(reply: &Reply) -> Vec<i64> {
    items(reply)
        .iter()
        .map(|i| i["order"]["seq"].as_i64().unwrap())
        .collect()
}

fn thread_ids(reply: &Reply) -> Vec<String> {
    items(reply)
        .iter()
        .map(|i| i["threadId"].as_str().unwrap().to_owned())
        .collect()
}

fn cursor(reply: &Reply) -> Option<String> {
    reply.json["cursor"].as_str().map(str::to_owned)
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

async fn mek(author: &Device, thread: Uuid, id: [u8; 12], to: &[&str]) {
    author
        .call(
            "createMek",
            &json!({ "record": transport_mek(thread, id, author.chat_pub(), to) }),
        )
        .await
        .ok();
}

/// Append and return the batch's server order.
async fn append(author: &Device, thread: Uuid, id: [u8; 12], messages: &[&str]) -> Value {
    let reply = author
        .call("appendBatch", &batch(thread, author, id, messages))
        .await;
    reply.ok()["order"].clone()
}

async fn get_messages(
    reader: &Device,
    thread: Uuid,
    ids: &[&str],
    extra: &[(&str, String)],
) -> Reply {
    let mut params = vec![("threadId", thread.to_string())];
    params.extend(ids.iter().map(|id| ("messageIds", (*id).to_owned())));
    params.extend(extra.iter().cloned());
    reader.query("getMessages", &params).await
}

fn redact(device: &Device, thread: Uuid, message: &str) -> Value {
    let signed = format!(
        "catbird.labyrinth.redaction:did={};message_id={message};thread_id={}",
        device.did,
        hex::encode(thread.to_string().as_bytes())
    );
    json!({ "threadId": thread.to_string(), "messageId": message, "redaction": {
        "transportPubkey": b(&device.chat_pub()),
        "sig": b(&device.chat_key.sign(signed.as_bytes()).to_bytes()),
    }})
}

/// Alice and bob talk under MEK1; bob leaves; carol joins and alice talks
/// to her under MEK2. Seqs: MEK1=1, a1=2, b1=3, MEK2=4, a2=5.
struct Eras {
    env: Env,
    alice: Device,
    bob: Device,
    carol: Device,
    stranger: Device,
    thread: Uuid,
}

async fn eras() -> Eras {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let carol = env.account().await;
    let stranger = env.account().await;
    let thread = seed_conversation(&env, &[leaf(&alice, 1), leaf(&bob, 1)], 3).await;
    mek(&alice, thread, MEK1, &[&alice.did, &bob.did]).await;
    append(&alice, thread, MEK1, &["a1"]).await;
    append(&bob, thread, MEK1, &["b1", "shared"]).await;
    remove_member(&env, thread, &bob, 5).await;
    add_member(&env, thread, &[leaf(&carol, 6)]).await;
    mek(&alice, thread, MEK2, &[&alice.did, &carol.did]).await;
    append(&alice, thread, MEK2, &["a2", "shared"]).await;
    Eras {
        env,
        alice,
        bob,
        carol,
        stranger,
        thread,
    }
}

#[tokio::test]
async fn get_messages_is_authorized_per_mek() {
    let w = eras().await;
    let all = ["a1", "b1", "a2", "shared", "missing"];
    let got = |who: &Device| {
        let who = who.clone();
        async move { seqs(&get_messages(&who, w.thread, &all, &[]).await) }
    };
    assert_eq!(got(&w.alice).await, vec![2, 3, 5]);
    assert_eq!(
        got(&w.bob).await,
        vec![2, 3],
        "leaver keeps addressed history"
    );
    assert_eq!(got(&w.carol).await, vec![5], "joiner sees nothing earlier");
    assert!(
        got(&w.stranger).await.is_empty(),
        "non-recipient sees nothing"
    );

    // One id, reused by two authors under different MEKs ([CB-31]).
    let shared = get_messages(&w.alice, w.thread, &["shared"], &[]).await;
    let authors: Vec<_> = items(&shared)
        .iter()
        .map(|i| i["author"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(authors, vec![w.bob.did.clone(), w.alice.did.clone()]);
    // A batch is returned once however many of its ids match.
    let once = get_messages(&w.alice, w.thread, &["b1", "shared"], &[]).await;
    assert_eq!(seqs(&once), vec![3, 5]);

    // Paging.
    let page = get_messages(&w.alice, w.thread, &all, &[("limit", "2".into())]).await;
    assert_eq!(seqs(&page), vec![2, 3]);
    let rest = get_messages(
        &w.alice,
        w.thread,
        &all,
        &[("cursor", cursor(&page).unwrap())],
    )
    .await;
    assert_eq!((seqs(&rest), cursor(&rest)), (vec![5], None));

    // Validation: 1..=100 ids, each 1..=128 bytes.
    w.alice
        .query("getMessages", &[("threadId", w.thread.to_string())])
        .await
        .fails(400, "InvalidRequest");
    let many: Vec<String> = (0..101).map(|i| format!("m{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    get_messages(&w.alice, w.thread, &many, &[])
        .await
        .fails(400, "InvalidRequest");
    let long = "x".repeat(129);
    get_messages(&w.alice, w.thread, &[long.as_str()], &[])
        .await
        .fails(400, "InvalidRequest");
    // Other parameters stay single-valued.
    w.alice
        .query(
            "getMessages",
            &[
                ("threadId", w.thread.to_string()),
                ("threadId", w.thread.to_string()),
                ("messageIds", "a1".into()),
            ],
        )
        .await
        .fails(400, "InvalidRequest");

    // Remote conversations are relayed (unconfigured here).
    make_remote(&w.env, w.thread).await;
    get_messages(&w.alice, w.thread, &["a1"], &[])
        .await
        .fails(503, "RelayUnavailable");
}

#[tokio::test]
async fn get_messages_returns_redacted_items_as_stored() {
    let w = eras().await;
    w.alice
        .call("redactMessage", &redact(&w.alice, w.thread, "a1"))
        .await
        .ok();
    for reader in [&w.alice, &w.bob] {
        let got = get_messages(reader, w.thread, &["a1"], &[]).await;
        let got = items(&got);
        assert_eq!(got.len(), 1);
        let item = &got[0]["record"]["items"][0];
        assert_eq!(item["messageId"], "a1");
        assert_eq!(item["signedEncMessage"], json!({ "$bytes": "" }));
        assert!(item["redaction"]["redactedAt"].as_str().is_some());
    }
    assert!(items(&get_messages(&w.carol, w.thread, &["a1"], &[]).await).is_empty());
}

#[tokio::test]
async fn list_threads_lists_authored_and_addressed_conversations() {
    let w = eras().await;
    // A second conversation: carol writes a MEK addressed to herself only;
    // alice is a member but never addressed.
    let other = seed_conversation(&w.env, &[leaf(&w.alice, 1), leaf(&w.carol, 1)], 2).await;
    mek(&w.carol, other, MEK1, &[&w.carol.did]).await;
    // A third: alice addressed by bob.
    let third = seed_conversation(&w.env, &[leaf(&w.alice, 1), leaf(&w.bob, 1)], 2).await;
    mek(&w.bob, third, MEK1, &[&w.alice.did]).await;

    let list = |who: &Device, params: Vec<(&'static str, String)>| {
        let who = who.clone();
        async move { who.query("listThreads", &params).await }
    };
    let sorted = |mut v: Vec<Uuid>| {
        v.sort();
        v.into_iter().map(|u| u.to_string()).collect::<Vec<_>>()
    };
    assert_eq!(
        thread_ids(&list(&w.alice, vec![]).await),
        sorted(vec![w.thread, third])
    );
    assert_eq!(
        thread_ids(&list(&w.bob, vec![]).await),
        sorted(vec![w.thread, third]),
        "a leaver keeps the conversation it was addressed in; an author lists its own"
    );
    assert_eq!(
        thread_ids(&list(&w.carol, vec![]).await),
        sorted(vec![w.thread, other])
    );
    assert!(thread_ids(&list(&w.stranger, vec![]).await).is_empty());

    // Paging by conversation id.
    let page = list(&w.alice, vec![("limit", "1".into())]).await;
    let first = thread_ids(&page);
    assert_eq!(first.len(), 1);
    let rest = list(&w.alice, vec![("cursor", cursor(&page).unwrap())]).await;
    let mut both = first.clone();
    both.extend(thread_ids(&rest));
    assert_eq!(both, sorted(vec![w.thread, third]));
    assert_eq!(cursor(&rest), None);
    list(&w.alice, vec![("cursor", "not-a-uuid".into())])
        .await
        .fails(400, "InvalidRequest");
}

#[tokio::test]
async fn list_owner_threads_pages_the_callers_archive_only() {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    for thread in ["thread-b", "thread-a", "thread-b", "thread-c"] {
        alice
            .call(
                "appendOwnerBatch",
                &json!({ "record": owner_batch_record(thread, &[1]) }),
            )
            .await
            .ok();
    }
    bob.call(
        "appendOwnerBatch",
        &json!({ "record": owner_batch_record("thread-z", &[1]) }),
    )
    .await
    .ok();
    let all = alice.query("listOwnerThreads", &[]).await;
    assert_eq!(thread_ids(&all), vec!["thread-b", "thread-a", "thread-c"]);
    let page = alice
        .query("listOwnerThreads", &[("limit", "2".into())])
        .await;
    assert_eq!(thread_ids(&page), vec!["thread-b", "thread-a"]);
    let rest = alice
        .query("listOwnerThreads", &[("cursor", cursor(&page).unwrap())])
        .await;
    assert_eq!(
        (thread_ids(&rest), cursor(&rest)),
        (vec!["thread-c".to_owned()], None)
    );
    assert_eq!(
        thread_ids(&bob.query("listOwnerThreads", &[]).await),
        vec!["thread-z"]
    );
}

/// Distinct server receive instants (ms precision).
async fn tick() {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

#[tokio::test]
async fn list_batches_pages_newest_first_and_by_receive_window() {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let carol = env.account().await;
    let thread = seed_conversation(&env, &[leaf(&alice, 1), leaf(&bob, 1)], 2).await;
    mek(&alice, thread, MEK1, &[&alice.did, &bob.did]).await;
    let mut received = Vec::new();
    for m in ["m1", "m2", "m3", "m4"] {
        tick().await;
        received.push(append(&alice, thread, MEK1, &[m]).await["receivedAt"].clone());
    }
    // A late joiner's era is invisible to bob in either direction.
    add_member(&env, thread, &[leaf(&carol, 5)]).await;
    mek(&alice, thread, MEK2, &[&alice.did, &carol.did]).await;
    tick().await;
    append(&alice, thread, MEK2, &["m5"]).await;
    let q = |who: &Device, extra: Vec<(&'static str, String)>| {
        let who = who.clone();
        async move {
            let mut p = vec![("threadId", thread.to_string())];
            p.extend(extra);
            who.query("listBatches", &p).await
        }
    };
    let rev = || ("reverse", "true".to_owned());

    assert_eq!(seqs(&q(&alice, vec![rev()]).await), vec![7, 5, 4, 3, 2]);
    assert_eq!(seqs(&q(&bob, vec![rev()]).await), vec![5, 4, 3, 2]);
    assert_eq!(seqs(&q(&carol, vec![rev()]).await), vec![7]);

    // Newest-first paging continues toward older records.
    let p1 = q(&bob, vec![rev(), ("limit", "3".into())]).await;
    assert_eq!(seqs(&p1), vec![5, 4, 3]);
    let p2 = q(
        &bob,
        vec![
            rev(),
            ("limit", "3".into()),
            ("cursor", cursor(&p1).unwrap()),
        ],
    )
    .await;
    assert_eq!((seqs(&p2), cursor(&p2)), (vec![2], None));
    // Oldest-first, for contrast.
    let f1 = q(&bob, vec![("limit", "3".into())]).await;
    assert_eq!(seqs(&f1), vec![2, 3, 4]);
    let f2 = q(&bob, vec![("cursor", cursor(&f1).unwrap())]).await;
    assert_eq!(seqs(&f2), vec![5]);

    // Server receive windows: since inclusive, until exclusive.
    let at = |i: usize| received[i].as_str().unwrap().to_owned();
    let window = q(&bob, vec![("since", at(1)), ("until", at(3))]).await;
    assert_eq!(seqs(&window), vec![3, 4]);
    let newer = q(&bob, vec![("since", at(2)), rev()]).await;
    assert_eq!(seqs(&newer), vec![5, 4]);
    // Combined with the sender-timestamp window (all items at 1000 here).
    let none = q(&bob, vec![("since", at(0)), ("fromMs", "1001".into())]).await;
    assert!(seqs(&none).is_empty());
    q(&bob, vec![("since", "yesterday".into())])
        .await
        .fails(400, "InvalidRequest");
    q(&bob, vec![("reverse", "maybe".into())])
        .await
        .fails(400, "InvalidRequest");
}

#[tokio::test]
async fn list_owner_batches_pages_newest_first_and_by_receive_window() {
    let env = Env::new().await;
    let alice = env.account().await;
    let mut received = Vec::new();
    for ts in [10u64, 20, 30, 40] {
        tick().await;
        let reply = alice
            .call(
                "appendOwnerBatch",
                &json!({ "record": owner_batch_record("t", &[ts]) }),
            )
            .await;
        received.push(
            reply.ok()["order"]["receivedAt"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    alice
        .call(
            "appendOwnerBatch",
            &json!({ "record": owner_batch_record("other", &[50]) }),
        )
        .await
        .ok();
    let q = |extra: Vec<(&'static str, String)>| {
        let alice = alice.clone();
        async move {
            let mut p = vec![("threadId", "t".to_owned())];
            p.extend(extra);
            alice.query("listOwnerBatches", &p).await
        }
    };
    let rev = || ("reverse", "true".to_owned());
    assert_eq!(seqs(&q(vec![rev()]).await), vec![4, 3, 2, 1]);
    let p1 = q(vec![rev(), ("limit", "3".into())]).await;
    assert_eq!(seqs(&p1), vec![4, 3, 2]);
    let p2 = q(vec![rev(), ("cursor", cursor(&p1).unwrap())]).await;
    assert_eq!((seqs(&p2), cursor(&p2)), (vec![1], None));
    let window = q(vec![
        ("since", received[1].clone()),
        ("until", received[3].clone()),
    ])
    .await;
    assert_eq!(seqs(&window), vec![2, 3]);
    let older = q(vec![("until", received[2].clone()), rev()]).await;
    assert_eq!(seqs(&older), vec![2, 1]);
    // Both windows at once.
    let both = q(vec![
        ("since", received[0].clone()),
        ("untilMs", "30".into()),
    ])
    .await;
    assert_eq!(seqs(&both), vec![1, 2]);
}

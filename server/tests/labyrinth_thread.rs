//! Labyrinth backend: per-conversation sender records, server order and
//! per-MEK read authorization (labyrinth `docs/MLSDS_BACKEND.md` §1b, §2
//! "Thread", §3). ORF and attachments: `labyrinth_attachments`.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use harness::*;
use serde_json::{json, Value};
use uuid::Uuid;

const MEK1: [u8; 12] = [1; 12];
const MEK2: [u8; 12] = [2; 12];

fn record(r: Value) -> Value {
    json!({ "record": r })
}

fn items(reply: &Reply) -> Vec<Value> {
    reply.ok()["items"].as_array().unwrap().clone()
}

fn batch_seqs(reply: &Reply) -> Vec<i64> {
    items(reply)
        .iter()
        .map(|i| i["order"]["seq"].as_i64().unwrap())
        .collect()
}

#[tokio::test]
async fn mek_writes_check_leaf_sender_and_recipients() {
    let env = Env::new().await;
    let v = vectors();
    let alice = env.account().await;
    let bob = env.account().await;
    let carol = env.account().await;
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
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
            Leaf {
                device: &d0,
                joined_seq: 1,
                removed_seq: None,
            },
        ],
        7,
    )
    .await;
    let to = [alice.did.as_str(), bob.did.as_str()];

    let created = alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &to)),
        )
        .await;
    assert_eq!(created.ok()["rkey"], hex::encode(MEK1));
    assert_eq!(created.json["order"]["seq"], 1);
    assert_eq!(created.json["order"]["chatSeq"], 6);
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &to)),
        )
        .await
        .fails(409, "RecordAlreadyExists");
    // Another author may not claim the same mekId in the conversation
    // (review 2, finding 8): one id names one MEK.
    bob.call(
        "createMek",
        &record(transport_mek(thread, MEK1, bob.chat_pub(), &to)),
    )
    .await
    .fails(409, "RecordAlreadyExists");

    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK2, bob.chat_pub(), &to)),
        )
        .await
        .fails(400, "SenderMismatch");
    alice
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                MEK2,
                alice.chat_pub(),
                &[carol.did.as_str()],
            )),
        )
        .await
        .fails(400, "RecipientNotParticipant");
    carol
        .call(
            "createMek",
            &record(transport_mek(thread, MEK2, carol.chat_pub(), &to)),
        )
        .await
        .fails(403, "NotParticipant");
    alice
        .call(
            "createMek",
            &record(transport_mek(Uuid::new_v4(), MEK2, alice.chat_pub(), &to)),
        )
        .await
        .fails(403, "NotParticipant");

    // Labyrinth senders: the DID is the caller's and the embedded epoch is
    // attested by a current chat key of it.
    alice
        .call(
            "createMek",
            &record(labyrinth_mek(thread, MEK2, &v.did, &v.chain[0], &to)),
        )
        .await
        .fails(400, "SenderMismatch");
    d0.call(
        "createMek",
        &record(labyrinth_mek(thread, MEK2, &v.did, &v.chain[0], &to)),
    )
    .await
    .ok();
    env.revoke(&d1).await;
    d0.call(
        "createMek",
        &record(labyrinth_mek(thread, [3; 12], &v.did, &v.chain[2], &to)),
    )
    .await
    .fails(400, "AttestationNotCurrent");
    let mut bad_head = labyrinth_mek(thread, [4; 12], &v.did, &v.chain[0], &to);
    bad_head["sender"]["senderEpochHead"] = b(&[0; 32]);
    d0.call("createMek", &record(bad_head))
        .await
        .fails(400, "InvalidRequest");

    // Remote conversations are relayed to their sequencer; this DS has no
    // federation service auth configured, so the relay is unavailable
    // (labyrinth_relay covers the configured path).
    make_remote(&env, thread).await;
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, [5; 12], alice.chat_pub(), &to)),
        )
        .await
        .fails(503, "RelayUnavailable");
}

#[tokio::test]
async fn batches_are_single_mek_from_the_writer_key_under_a_usable_mek() {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let dave = env.account().await;
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
            Leaf {
                device: &dave,
                joined_seq: 1,
                removed_seq: None,
            },
        ],
        3,
    )
    .await;
    let to = [alice.did.as_str(), bob.did.as_str()];
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &to)),
        )
        .await
        .ok();
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK2, alice.chat_pub(), &to)),
        )
        .await
        .ok();

    alice
        .call(
            "appendBatch",
            &record(batch_record(
                thread,
                alice.chat_pub(),
                &[(MEK1, 1), (MEK2, 2)],
            )),
        )
        .await
        .fails(400, "MixedMekBatch");
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, bob.chat_pub(), &[(MEK1, 1)])),
        )
        .await
        .fails(400, "SenderKeyMismatch");
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[([9; 12], 1)])),
        )
        .await
        .fails(400, "UnknownMek");
    dave.call(
        "appendBatch",
        &record(batch_record(thread, dave.chat_pub(), &[(MEK1, 1)])),
    )
    .await
    .fails(403, "NotRecipient");
    alice
        .call(
            "appendBatch",
            &record(batch_record(
                thread,
                alice.chat_pub(),
                &[(MEK1, 1), (MEK1, 2)],
            )),
        )
        .await
        .ok();
    // A recipient may reuse a MEK it opened (SPEC §7.3).
    bob.call(
        "appendBatch",
        &record(batch_record(thread, bob.chat_pub(), &[(MEK1, 3)])),
    )
    .await
    .ok();
}

#[tokio::test]
async fn records_are_stamped_with_server_order_linearized_with_chat() {
    let env = Env::new().await;
    let alice = env.account().await;
    let thread = seed_conversation(
        &env,
        &[Leaf {
            device: &alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        4,
    )
    .await;
    let me = [alice.did.as_str()];
    let mek = alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &me)),
        )
        .await;
    assert_eq!(
        (
            mek.ok()["order"]["seq"].as_i64(),
            mek.json["order"]["chatSeq"].as_i64()
        ),
        (Some(1), Some(3))
    );
    let first = alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 50)])),
        )
        .await;
    assert_eq!(first.ok()["order"]["seq"], 2);
    // MLS entries advance the conversation; the next stamp follows them.
    set_next_entry_seq(&env, thread, 10).await;
    let second = alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 10)])),
        )
        .await;
    assert_eq!(second.ok()["order"]["seq"], 3);
    assert_eq!(second.json["order"]["chatSeq"], 9);
    assert!(
        second.json["order"]["receivedAt"].as_str() >= first.json["order"]["receivedAt"].as_str()
    );
    assert!(
        second.json["rkey"].as_str() > first.json["rkey"].as_str(),
        "TIDs increase"
    );

    // Listed in server order, not by sender timestamp.
    let list = alice
        .query("listBatches", &[("threadId", thread.to_string())])
        .await;
    assert_eq!(batch_seqs(&list), vec![2, 3]);
    let found = alice
        .query(
            "findMeks",
            &[
                ("threadId", thread.to_string()),
                ("mekId", hex::encode(MEK1)),
            ],
        )
        .await;
    let found = items(&found);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["author"], alice.did);
    assert_eq!(found[0]["order"]["chatSeq"], 3);
}

#[tokio::test]
async fn reads_are_authorized_per_mek_leavers_keep_history_joiners_see_nothing_earlier() {
    let env = Env::new().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let carol = env.account().await;
    let stranger = env.account().await;
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
        3,
    )
    .await;
    // Era 1: alice and bob.
    alice
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                MEK1,
                alice.chat_pub(),
                &[&alice.did, &bob.did],
            )),
        )
        .await
        .ok();
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 1)])),
        )
        .await
        .ok();
    bob.call(
        "appendBatch",
        &record(batch_record(thread, bob.chat_pub(), &[(MEK1, 2)])),
    )
    .await
    .ok();

    // Bob leaves; carol joins later.
    remove_member(&env, thread, &bob, 5).await;
    let thread_leaves = [Leaf {
        device: &carol,
        joined_seq: 6,
        removed_seq: None,
    }];
    add_member(&env, thread, &thread_leaves).await;

    // Era 2: alice and carol.
    alice
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                MEK2,
                alice.chat_pub(),
                &[&alice.did, &carol.did],
            )),
        )
        .await
        .ok();
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK2, 3)])),
        )
        .await
        .ok();
    // bob can no longer write, nor address MEKs to himself.
    bob.call(
        "appendBatch",
        &record(batch_record(thread, bob.chat_pub(), &[(MEK1, 4)])),
    )
    .await
    .fails(403, "NotParticipant");
    alice
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                [7; 12],
                alice.chat_pub(),
                &[&bob.did],
            )),
        )
        .await
        .fails(400, "RecipientNotParticipant");

    let list = |who: &Device| {
        let who = who.clone();
        async move {
            who.query("listBatches", &[("threadId", thread.to_string())])
                .await
        }
    };
    // mek seqs: MEK1=1, batches 2,3; MEK2=4, batch 5.
    assert_eq!(batch_seqs(&list(&alice).await), vec![2, 3, 5]);
    assert_eq!(
        batch_seqs(&list(&bob).await),
        vec![2, 3],
        "leaver keeps addressed history"
    );
    assert_eq!(
        batch_seqs(&list(&carol).await),
        vec![5],
        "joiner sees nothing earlier"
    );
    assert!(batch_seqs(&list(&stranger).await).is_empty());

    let find = |who: &Device, mek: [u8; 12]| {
        let who = who.clone();
        async move {
            items(
                &who.query(
                    "findMeks",
                    &[
                        ("threadId", thread.to_string()),
                        ("mekId", hex::encode(mek)),
                    ],
                )
                .await,
            )
            .len()
        }
    };
    assert_eq!(find(&bob, MEK1).await, 1);
    assert_eq!(find(&bob, MEK2).await, 0);
    assert_eq!(find(&carol, MEK1).await, 0);
    assert_eq!(find(&carol, MEK2).await, 1);

    // Sender filter and paging.
    let only_bob = alice
        .query(
            "listBatches",
            &[
                ("threadId", thread.to_string()),
                ("sender", bob.did.clone()),
            ],
        )
        .await;
    assert_eq!(batch_seqs(&only_bob), vec![3]);
    let page = alice
        .query(
            "listBatches",
            &[("threadId", thread.to_string()), ("limit", "2".into())],
        )
        .await;
    assert_eq!(batch_seqs(&page), vec![2, 3]);
    let cursor = page.json["cursor"].as_str().unwrap().to_owned();
    let rest = alice
        .query(
            "listBatches",
            &[("threadId", thread.to_string()), ("cursor", cursor)],
        )
        .await;
    assert_eq!(batch_seqs(&rest), vec![5]);
}

#[tokio::test]
async fn thread_records_count_against_the_author_quota() {
    let env = Env::new().await;
    let alice = env.account().await;
    let thread = seed_conversation(
        &env,
        &[Leaf {
            device: &alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        2,
    )
    .await;
    let me = [alice.did.as_str()];
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &me)),
        )
        .await
        .ok();
    sqlx::query(
        "UPDATE labyrinth.author_usage SET bytes_used = 1073741824 - 10 WHERE author_did = $1",
    )
    .bind(&alice.did)
    .execute(&env.pool)
    .await
    .unwrap();
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 1)])),
        )
        .await
        .fails(400, "QuotaExceeded");
}

#[tokio::test]
async fn lf03_legacy_mek_and_batch_enforce_active_lifecycle_accepted_recipients_and_current_gen_bounds(
) {
    let env = Env::new().await;
    let alice = env.account().await;
    let pending = env.account().await;
    let thread = seed_conversation(
        &env,
        &[
            Leaf {
                device: &alice,
                joined_seq: 5,
                removed_seq: None,
            },
            Leaf {
                device: &pending,
                joined_seq: 5,
                removed_seq: None,
            },
        ],
        10,
    )
    .await;

    // Mark `pending` as an unaccepted direct-request participant (`status = 'pending'`).
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chat.participants \
            SET status = 'pending', \
                invitation_transition_id = $3, \
                invitation_entry_id = $4, \
                invited_at = now(), \
                acceptance_transition_id = NULL, \
                acceptance_entry_id = NULL, \
                accepted_at = NULL \
          WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(thread)
    .bind(&pending.did)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Pending participant cannot write MEKs or be addressed in MEKs.
    pending
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                MEK1,
                pending.chat_pub(),
                &[&alice.did],
            )),
        )
        .await
        .fails(403, "NotParticipant");
    alice
        .call(
            "createMek",
            &record(transport_mek(
                thread,
                MEK1,
                alice.chat_pub(),
                &[&alice.did, &pending.did],
            )),
        )
        .await
        .fails(400, "RecipientNotParticipant");

    // Valid MEK for alice alone succeeds while active.
    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK1, alice.chat_pub(), &[&alice.did])),
        )
        .await
        .ok();

    // Pre-join MEK (`chat_seq = 2 < alice.joined_seq = 5`) must be rejected by appendBatch.
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE labyrinth.meks SET chat_seq = 2 WHERE conversation_id = $1 AND mek_id = $2",
    )
    .bind(thread)
    .bind(MEK1.as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 100)])),
        )
        .await
        .fails(400, "UnknownMek");

    // Restore chat_seq = 6, then mark MEK as stale generation 0 (`current_generation = 1`).
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE labyrinth.meks SET chat_seq = 6, chat_generation = 0 WHERE conversation_id = $1 AND mek_id = $2")
        .bind(thread)
        .bind(MEK1.as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 101)])),
        )
        .await
        .fails(400, "UnknownMek");

    // Restore current generation, then close the conversation: both createMek and appendBatch fail.
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE labyrinth.meks SET chat_generation = 1 WHERE conversation_id = $1 AND mek_id = $2",
    )
    .bind(thread)
    .bind(MEK1.as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.conversations \
            SET lifecycle = 'superseded', \
                close_transition_id = $2, \
                close_generation = 1, \
                close_state_version = 1, \
                close_seq = 9, \
                closed_at = now() \
          WHERE conversation_id = $1",
    )
    .bind(thread)
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    alice
        .call(
            "createMek",
            &record(transport_mek(thread, MEK2, alice.chat_pub(), &[&alice.did])),
        )
        .await
        .fails(403, "NotParticipant");
    alice
        .call(
            "appendBatch",
            &record(batch_record(thread, alice.chat_pub(), &[(MEK1, 102)])),
        )
        .await
        .fails(403, "NotParticipant");
}

#[tokio::test]
async fn lf08_mek_validates_transport_sig_unique_recipients_and_roster_hash() {
    let env = Env::new().await;
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
        5,
    )
    .await;

    // 1. Forged transportSender.sig is rejected.
    let mut bad_sig = transport_mek(thread, MEK1, alice.chat_pub(), &[&alice.did, &bob.did]);
    bad_sig["sender"]["sig"] = b(&[0x99; 64]);
    alice
        .call("createMek", &record(bad_sig))
        .await
        .fails(400, "InvalidRequest");

    // 2. Duplicate recipient DID is rejected.
    let dup = transport_mek(thread, MEK1, alice.chat_pub(), &[&alice.did, &alice.did]);
    alice
        .call("createMek", &record(dup))
        .await
        .fails(400, "InvalidRequest");

    // 3. Tampered rosterHash is rejected.
    let mut bad_roster = transport_mek(thread, MEK1, alice.chat_pub(), &[&alice.did, &bob.did]);
    bad_roster["rosterHash"] = b(&[0xAA; 32]);
    alice
        .call("createMek", &record(bad_roster))
        .await
        .fails(400, "InvalidRequest");
}

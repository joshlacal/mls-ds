//! `deliverTransportControlEntry` regressions on real PostgreSQL. A C33
//! coordinator's signed deletion of the account it homes reaches the peer's
//! transport-only home through the production queue and route, behind the
//! pair's earlier delivery there. The home verifies it before any effect,
//! returns it verbatim from `getEntries` and prunes the deleted account's held
//! ciphertext.

use super::super::super::entry_ack_relay::transport_control_entry::{
    accept_transport_control_entry, DeliverTransportControlEntry,
};
use super::*;
use crate::{
    chat_protocol::{repository::delivery, test_support::CleanSlateApplicationFixture},
    common::fresh_db::DisposableDatabase,
    federation::{
        canonical_relay::{coordinator_handle_message, DeliverMessageEntryInput},
        queue::{claim_due_heads, mark_item_delivered},
        receipt::AccountDeletion,
    },
    labyrinth::repo::retention::purge_account,
};

const CONTROL_PREFIX: &str = "transport-control-";

impl Network {
    /// Publish `did`'s dedicated `#mls-receipt-1` key, as a sequencer's DID
    /// document does.
    fn publish_receipt_key(&self, did: &str, key: &SigningKey) {
        self.documents
            .lock()
            .unwrap()
            .get_mut(host(did))
            .expect("a published DS DID document")["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": format!("{did}#mls-receipt-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase":
                    crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
            }));
    }
}

/// A direct pair C33_SEQ coordinates: the deleted account D is the sender homed
/// there, its peer P the recipient homed at C33_HOME, which holds the pair's
/// transport inbox and every entry before D's application. D's application is
/// sequenced and queued for P's home.
struct Pair {
    _dbs: [DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    fixture: CleanSlateApplicationFixture,
    cid: Uuid,
    /// A second conversation of the same pair this home holds.
    twin: Uuid,
    network: Network,
    clock: Arc<ManualDsClock>,
    seq_hooks: Arc<SimDsHooks>,
    home_hooks: Arc<SimDsHooks>,
    seq_key: SigningKey,
    receipt: I13ReceiptSigner,
    other_receipt: I13ReceiptSigner,
    home: GroupRelayState,
    /// D's application: its seq and the entry `deliverMessageEntry` carries.
    seq: i64,
    message: Value,
    /// P's device key id, which also binds its DPoP key here.
    peer_key_id: String,
}

impl Pair {
    async fn new() -> Self {
        crate::federation::open_federation_for_test();
        let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let seq_pool = seq_db.connect(4).await;
        let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let home_pool = home_db.connect(4).await;
        for (pool, peers) in [
            (&seq_pool, [C33_HOME, C33_OTHER]),
            (&home_pool, [C33_SEQ, C33_OTHER]),
        ] {
            ensure_fence(pool).await;
            for peer in peers {
                sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
                    .bind(peer)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
        let fixture = seed_clean_slate_application_fixture_with_sender_home(
            &seq_pool,
            true,
            C33_HOME,
            Some([0x5e; 32]),
            None,
        )
        .await
        .unwrap();
        let cid = fixture.conversation_id;
        let (seq_key, home_key, other_key) = (key(0x51), key(0x52), key(0x53));
        let network = Network::new(&[
            (C33_SEQ, &seq_key),
            (C33_HOME, &home_key),
            (C33_OTHER, &other_key),
        ]);
        for ds in [C33_SEQ, C33_HOME, C33_OTHER] {
            network.declare_delivery_service(ds);
        }
        network.declare_user(&fixture.sender_did, C33_SEQ);
        network.declare_user(&fixture.recipient_did, C33_HOME);
        network.publish_receipt_key(C33_SEQ, &key(0x54));
        network.publish_receipt_key(C33_OTHER, &key(0x55));
        let receipt = I13ReceiptSigner::new(key(0x54), C33_SEQ.to_owned());
        let other_receipt = I13ReceiptSigner::new(key(0x55), C33_OTHER.to_owned());
        let clock = manual_clock();
        let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
        let home_hooks = hooks(C33_HOME, Some(&home_key), false, &network);
        let runtime = Arc::new(
            crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(
                8,
            )))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(receipt.clone()),
        );

        // D's message, relayed by nobody: D is homed at its coordinator.
        let sequenced = scope_ds_clock(
            clock.clone(),
            scope_sim_ds(
                Arc::clone(&seq_hooks),
                coordinator_handle_message(
                    &seq_pool,
                    &runtime,
                    C33_SEQ,
                    cid,
                    &fixture.signed_request,
                ),
            ),
        )
        .await
        .expect("coordinate D's application");
        let seq = sequenced["entry"]["seq"].as_i64().unwrap();
        let queued = queue_rows(&seq_pool, cid).await;
        assert_eq!(
            queued
                .iter()
                .map(|row| (row.0.as_str(), row.1.as_str(), row.2.as_str()))
                .collect::<Vec<_>>(),
            [(
                format!("msg-delivery-{cid}-{seq}").as_str(),
                C33_HOME,
                "pending"
            )]
        );
        let message = serde_json::from_slice::<DeliverMessageEntryInput>(&queued[0].5)
            .unwrap()
            .entry;

        let home = GroupRelayState::for_test(
            home_pool.clone(),
            C33_HOME.to_owned(),
            HMAC.as_bytes(),
            None,
        )
        .with_sim_hooks(Arc::clone(&home_hooks))
        .with_clock(clock.clone());
        let peer_public = ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
            .verifying_key()
            .to_bytes();
        let peer_key_id = seed_actor_at(
            &home_pool,
            &fixture.recipient_did,
            fixture.recipient_device_id,
            &peer_public,
            clock_now(&home_pool).await,
        )
        .await;
        let twin = Uuid::new_v4();
        let pair = Self {
            _dbs: [seq_db, home_db],
            seq_pool,
            home_pool,
            fixture,
            cid,
            twin,
            network,
            clock,
            seq_hooks,
            home_hooks,
            seq_key,
            receipt,
            other_receipt,
            home,
            seq,
            message,
            peer_key_id,
        };
        for conversation_id in [cid, twin] {
            c33_inbox(
                &pair.home_pool,
                conversation_id,
                C33_SEQ,
                (pair.deleted(), pair.fixture.sender_device_id),
                (pair.peer(), pair.fixture.recipient_device_id),
            )
            .await;
            // The pair's opening and acceptance: the entry only needs their seq.
            for earlier in 1..seq {
                pair.store(
                    conversation_id,
                    &json!({
                        "conversationId": conversation_id,
                        "entryId": Uuid::new_v4(),
                        "seq": earlier,
                    }),
                )
                .await;
            }
        }
        pair
    }

    fn deleted(&self) -> &str {
        &self.fixture.sender_did
    }

    fn peer(&self) -> &str {
        &self.fixture.recipient_did
    }

    /// Store `entry` at this home exactly as its single transport writer does.
    async fn store(&self, conversation_id: Uuid, entry: &Value) {
        let mut tx = self.home_pool.begin().await.unwrap();
        let stored = delivery::insert_transport_entry(
            &mut tx,
            conversation_id,
            entry["seq"].as_i64().unwrap(),
            entry["entryId"].as_str().unwrap().parse().unwrap(),
            &serde_json::to_vec(entry).unwrap(),
            current_utc(),
        )
        .await
        .unwrap();
        assert_eq!(stored, delivery::TransportEntryInsert::Inserted);
        tx.commit().await.unwrap();
    }

    /// `signer`'s signed `accountDeletedEntry`.
    fn entry(
        signer: &I13ReceiptSigner,
        conversation_id: Uuid,
        deleted_did: &str,
        seq: i64,
        entry_id: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Value {
        let deletion = AccountDeletion {
            sequencer_did: signer.sequencer_did().to_owned(),
            conversation_id,
            deleted_did: deleted_did.to_owned(),
            seq,
            entry_id,
            deleted_at,
        };
        deletion.entry(&signer.sign_account_deletion(&deletion).unwrap())
    }

    async fn accept(&self, caller: &str, entry: &Value) -> Result<Value, Response> {
        let body = serde_json::to_vec(&DeliverTransportControlEntry {
            entry: entry.clone(),
        })
        .unwrap();
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            accept_transport_control_entry(&self.home, caller, &body),
        )
        .await
    }

    async fn assert_refused(
        &self,
        caller: &str,
        entry: &Value,
        (status, code): (StatusCode, &str),
    ) {
        let before = home_state(&self.home_pool).await;
        let response = self.accept(caller, entry).await.expect_err("refused");
        let actual = response.status();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (actual, body["error"].as_str()),
            (status, Some(code)),
            "{caller}: {entry}: {body}"
        );
        assert_eq!(
            home_state(&self.home_pool).await,
            before,
            "{caller}: {entry}"
        );
    }

    /// P's `getEntries` page after `after_seq`, read through its real admission.
    async fn peer_entries(&self, after_seq: i64) -> Vec<Value> {
        let trusted = clock_now(&self.home_pool)
            .await
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let authority = crate::chat_protocol::repository::auth::authorize_unsigned_request(
            &self.home_pool,
            crate::chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
                Uuid::new_v4(),
                proof_jti,
                "blue.catbird.chat.getEntries",
                &trusted,
                self.peer(),
                self.fixture.recipient_device_id,
                &self.peer_key_id,
            ),
        )
        .await
        .expect("P's device reads here");
        let admission = crate::chat_protocol::dpop::seal_read_admission(authority).unwrap();
        let page = crate::chat_protocol::repository::entry_read::get_entries_for_admission(
            &self.home_pool,
            admission,
            self.cid,
            after_seq as u64,
            100,
        )
        .await
        .expect("P's getEntries");
        let page: Value = serde_json::from_slice(&page.into_response_bytes()).unwrap();
        page["entries"].as_array().unwrap().clone()
    }
}

/// `(conversation, seq, original digest, pruned)` of every entry this home holds.
async fn home_state(pool: &DbPool) -> Vec<(String, i64, Vec<u8>, bool)> {
    sqlx::query_as(
        "SELECT conversation_id::text, seq, original_entry_sha256, payload_pruned_at IS NOT NULL \
           FROM chat.direct_request_transport_entries ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn edited(entry: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut entry = entry.clone();
    edit(&mut entry);
    entry
}

/// The queued control entries of `conversation_id`.
async fn control_rows(pool: &DbPool, conversation_id: Uuid) -> Vec<QueueRow> {
    queue_rows(pool, conversation_id)
        .await
        .into_iter()
        .filter(|row| row.0.starts_with(CONTROL_PREFIX))
        .collect()
}

#[tokio::test]
async fn a_transport_only_home_verifies_a_control_entry_before_any_effect() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    let deleted = p.deleted().to_owned();
    let peer = p.peer().to_owned();
    scope_ds_clock(p.clock.clone(), async {
        let at = current_utc();
        let entry_id = Uuid::new_v4();
        let genuine = Pair::entry(&p.receipt, cid, &deleted, seq + 1, entry_id, at);
        let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
        let unsigned = (StatusCode::FORBIDDEN, "InvalidSignature");
        let impostor = I13ReceiptSigner::new(key(0x56), C33_SEQ.to_owned());
        // An authority naming a receipt method the coordinator never published.
        let unpublished = I13ReceiptSigner::new_with_key_id(
            key(0x57),
            C33_SEQ.to_owned(),
            format!("{C33_SEQ}#mls-receipt-2"),
        )
        .unwrap();
        let cases = [
            // Not the pair's coordinator, with the coordinator's entry or its own.
            (C33_OTHER, genuine.clone(), forbidden),
            (
                C33_OTHER,
                Pair::entry(&p.other_receipt, cid, &deleted, seq + 1, entry_id, at),
                forbidden,
            ),
            // The coordinator forwarding an entry another DS sequenced.
            (
                C33_SEQ,
                Pair::entry(&p.other_receipt, cid, &deleted, seq + 1, entry_id, at),
                forbidden,
            ),
            // A conversation this home holds no pair for.
            (
                C33_SEQ,
                Pair::entry(&p.receipt, Uuid::new_v4(), &deleted, seq + 1, entry_id, at),
                (StatusCode::NOT_FOUND, "ConversationNotFound"),
            ),
            // Only the pair's counterparty, never a stranger or this home's own party.
            (
                C33_SEQ,
                Pair::entry(
                    &p.receipt,
                    cid,
                    "did:web:stranger.example.com",
                    seq + 1,
                    entry_id,
                    at,
                ),
                forbidden,
            ),
            (
                C33_SEQ,
                Pair::entry(&p.receipt, cid, &peer, seq + 1, entry_id, at),
                forbidden,
            ),
            // The coordinator's name over another key.
            (
                C33_SEQ,
                Pair::entry(&impostor, cid, &deleted, seq + 1, entry_id, at),
                unsigned,
            ),
            (
                C33_SEQ,
                Pair::entry(&unpublished, cid, &deleted, seq + 1, entry_id, at),
                unsigned,
            ),
            // Every signed field, altered after signing.
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["sequencerDid"] = json!(C33_OTHER);
                    e["sequencerAuthority"]["sequencerDid"] = json!(C33_OTHER);
                }),
                forbidden,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["conversationId"] = json!(p.twin)),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["deletedDid"] = json!(peer)),
                forbidden,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["seq"] = json!(seq + 2)),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["entryId"] = json!(Uuid::new_v4())),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["receivedAt"] = json!((at + chrono::TimeDelta::milliseconds(1))
                        .to_rfc3339_opts(SecondsFormat::Millis, true))
                }),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["sequencerAuthority"]["keyId"] = json!(format!("{C33_SEQ}#atproto"))
                }),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    let mut signature = STANDARD
                        .decode(
                            e["sequencerAuthority"]["signature"]["$bytes"]
                                .as_str()
                                .unwrap(),
                        )
                        .unwrap();
                    signature[31] ^= 1;
                    e["sequencerAuthority"]["signature"]["$bytes"] =
                        json!(STANDARD.encode(signature));
                }),
                unsigned,
            ),
            // Not the canonical entry.
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["signature"] = json!(STANDARD.encode([0; 64]))
                }),
                (StatusCode::BAD_REQUEST, "InvalidRequest"),
            ),
        ];
        for (caller, entry, refusal) in cases {
            p.assert_refused(caller, &entry, refusal).await;
        }

        // D's application, the entry's predecessor, has not reached this home:
        // a retryable predecessor refusal that changes nothing.
        let before = home_state(&p.home_pool).await;
        let gap = p.accept(C33_SEQ, &genuine).await.expect_err("a gap");
        assert_eq!(gap.status(), StatusCode::CONFLICT);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(gap.into_body(), 1 << 16)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body["error"],
            crate::federation::errors::PREDECESSOR_MISSING_ERROR
        );
        assert_eq!(home_state(&p.home_pool).await, before);

        // After the earlier delivery the same entry applies, pruning D's held
        // ciphertext; its redelivery changes nothing, and another entry at its
        // seq is a definitive conflict.
        p.store(cid, &p.message).await;
        assert_eq!(
            p.accept(C33_SEQ, &genuine).await.unwrap(),
            json!({ "accepted": true, "applied": true, "prunedCount": 1 })
        );
        let settled = home_state(&p.home_pool).await;
        assert_eq!(
            p.accept(C33_SEQ, &genuine).await.unwrap(),
            json!({ "accepted": true, "applied": false, "prunedCount": 0 })
        );
        assert_eq!(home_state(&p.home_pool).await, settled);
        p.assert_refused(
            C33_SEQ,
            &Pair::entry(&p.receipt, cid, &deleted, seq + 1, Uuid::new_v4(), at),
            (StatusCode::CONFLICT, "EntryConflict"),
        )
        .await;
    })
    .await;
}

/// D, homed at its pair's coordinator, deletes its account. The coordinator
/// sequences the signed entry and queues it for P's transport-only home in the
/// same transaction, behind D's earlier delivery there and ahead of any later
/// one, and retries it through a partition and an undeclared 404. P's home
/// applies it: P's `getEntries` returns it verbatim at its seq, and D's held
/// ciphertext there is pruned.
#[tokio::test]
async fn a_c33_coordinator_delivers_its_own_partys_deletion_to_the_peers_home() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    let deleted = p.deleted().to_owned();
    // A C33 delivery resolves its home's declared endpoint from that home's DID
    // document, so its queue resolves through the sim network, not a DID pin.
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );
    scope_ds_clock(p.clock.clone(), async {
        let at = current_utc();
        let chain_before = chain(&p.seq_pool, cid).await;
        let head: (i64, i64) = sqlx::query_as(
            "SELECT current_generation, current_state_version FROM chat.conversations \
              WHERE conversation_id = $1",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        // Without the dedicated receipt signer, or with a pair whose peer home
        // was not resolved before the transaction, the deletion commits nothing.
        let unsigned = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            delete_account_data_with_conversations(&p.seq_pool, &deleted, at, None),
        )
        .await
        .expect_err("no receipt signer");
        assert_eq!(
            (unsigned.status(), unsigned.name()),
            (StatusCode::SERVICE_UNAVAILABLE, "SignerUnavailable")
        );
        let mut conn = p.seq_pool.acquire().await.unwrap();
        let unresolved = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            purge_account(
                &mut conn,
                &deleted,
                at,
                Some(&p.receipt),
                &C33PeerHomes::default(),
            ),
        )
        .await
        .expect_err("an unresolved peer home");
        assert_eq!(
            (unresolved.status(), unresolved.name()),
            (StatusCode::SERVICE_UNAVAILABLE, "PeerHomeUnavailable")
        );
        drop(conn);
        assert_eq!(chain(&p.seq_pool, cid).await, chain_before);
        assert!(control_rows(&p.seq_pool, cid).await.is_empty());

        assert_eq!(
            scope_sim_ds(
                Arc::clone(&p.seq_hooks),
                delete_account_data_with_conversations(&p.seq_pool, &deleted, at, Some(&p.receipt)),
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            deletions(&p.seq_pool, cid).await,
            [(seq + 1, deleted.clone())]
        );
        // Sequencing it moves no coordinates: only the coordinator's seq head
        // advances, so its pair's next message is sequenced right after it.
        assert_eq!(
            chain(&p.seq_pool, cid).await,
            (chain_before.0 + 1, Some(seq + 1), seq + 2)
        );
        let head_after: (i64, i64) = sqlx::query_as(
            "SELECT current_generation, current_state_version FROM chat.conversations \
              WHERE conversation_id = $1",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(head_after, head);
        let rows = control_rows(&p.seq_pool, cid).await;
        assert_eq!(rows.len(), 1, "one control entry for P's home");
        let (id, target, status, _, _, payload) = &rows[0];
        assert_eq!(
            (id.as_str(), target.as_str(), status.as_str()),
            (
                format!("{CONTROL_PREFIX}{cid}-{}", seq + 1).as_str(),
                C33_HOME,
                "pending"
            )
        );
        let entry = serde_json::from_slice::<DeliverTransportControlEntry>(payload)
            .unwrap()
            .entry;
        let (deletion, authority) = AccountDeletion::from_entry(&entry).unwrap();
        let entry_id: Uuid = sqlx::query_scalar(
            "SELECT entry_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
        )
        .bind(cid)
        .bind(seq + 1)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(
            deletion,
            AccountDeletion {
                sequencer_did: C33_SEQ.to_owned(),
                conversation_id: cid,
                deleted_did: deleted.clone(),
                seq: seq + 1,
                entry_id,
                deleted_at: at,
            }
        );
        authority
            .verify(&p.receipt.verifying_key(), &deletion)
            .expect("signed by the coordinator's #mls-receipt-1 key");

        // Only the stream's head, D's earlier delivery, is ever due first.
        p.clock.set_utc(latest_due(&p.seq_pool).await);
        let due = claim_due_heads(&p.seq_pool, 10, None).await.unwrap();
        assert_eq!(
            due.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
            [format!("msg-delivery-{cid}-{seq}").as_str()]
        );
        // That delivery lands, as P's home stores it.
        p.store(cid, &p.message).await;
        assert!(
            mark_item_delivered(&p.seq_pool, &due[0].id, due[0].claim_token)
                .await
                .unwrap()
        );
        // A later send of D's other device, queued to that home before the
        // entry leaves, never overtakes it: the stream orders by seq. (Its body
        // is never sent here; only its queue position is under test.)
        let mut tx = p.seq_pool.begin().await.unwrap();
        crate::federation::queue::enqueue_c33_in_tx(
            &p.seq_pool,
            &mut tx,
            &format!("msg-delivery-{cid}-{}", seq + 2),
            C33_HOME,
            &format!("https://{}", host(C33_HOME)),
            "blue.catbird.mlsDS.deliverMessageEntry",
            &serde_json::to_vec(&json!({ "conversationId": cid, "entry": { "seq": seq + 2 } }))
                .unwrap(),
            &cid.to_string(),
            "",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Unreachable, the home is retried past the queue's retry limit.
        p.network.partition(true);
        for attempt in 1..=6 {
            p.clock
                .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
            assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
            let rows = control_rows(&p.seq_pool, cid).await;
            let last_error: Option<String> =
                sqlx::query_scalar("SELECT last_error FROM outbound_queue WHERE id = $1")
                    .bind(&rows[0].0)
                    .fetch_one(&p.seq_pool)
                    .await
                    .unwrap();
            assert_eq!(
                (rows[0].2.as_str(), rows[0].3),
                ("pending", attempt),
                "attempt {attempt}: {last_error:?}"
            );
        }
        // A home answering an undeclared 404 may still hold the pair: retried.
        p.network.partition(false);
        p.network.serve(C33_HOME, Router::new());
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
        let rows = control_rows(&p.seq_pool, cid).await;
        assert_eq!((rows[0].2.as_str(), rows[0].3), ("pending", 7));
        p.network
            .serve(C33_HOME, group_relay_router(p.home.clone()));
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
        assert_eq!(control_rows(&p.seq_pool, cid).await[0].2, "delivered");

        // P reads the coordinator's exact entry at its seq, after D's pruned message.
        let stored: (Vec<u8>, bool) = sqlx::query_as(
            "SELECT entry_bytes, payload_pruned_at IS NOT NULL \
               FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = $2",
        )
        .bind(cid)
        .bind(seq)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert!(stored.1, "D's held ciphertext is pruned");
        assert!(serde_json::from_slice::<Value>(&stored.0).unwrap()["payloadPruned"] == true);
        let entries = p.peer_entries(seq - 1).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            (
                entries[0]["seq"].as_i64(),
                entries[0]["payloadPruned"].as_bool()
            ),
            (Some(seq), Some(true))
        );
        assert_eq!(entries[1], entry);

        // Redelivered, it changes nothing.
        let settled = home_state(&p.home_pool).await;
        assert_eq!(
            p.accept(C33_SEQ, &entry).await.unwrap(),
            json!({ "accepted": true, "applied": false, "prunedCount": 0 })
        );
        assert_eq!(home_state(&p.home_pool).await, settled);
    })
    .await;
}

impl Pair {
    /// P's own signed application at `seq`, its body edited by `edit` before
    /// P's device signs it.
    fn peer_message(&self, seq: i64, edit: impl FnOnce(&mut Value)) -> Value {
        let message_id = Uuid::new_v4();
        let mut body = self.fixture.signed_request["body"].clone();
        body["messageId"] = json!(message_id);
        body["actorDid"] = json!(self.peer());
        body["actorDeviceId"] = json!(self.fixture.recipient_device_id);
        body["keyId"] = json!(self.fixture.recipient_key_id);
        body["aad"]["messageId"] = json!(STANDARD.encode(message_id.as_bytes()));
        edit(&mut body);
        let signed = crate::chat_protocol::test_support::sign_mutation_json_for_test(
            &body,
            &ed25519_dalek::SigningKey::from_bytes(&self.fixture.recipient_ed25519_seed),
        )
        .unwrap();
        json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "entryId": Uuid::new_v4(),
            "conversationId": self.cid,
            "seq": seq,
            "receivedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
            "signedRequest": signed,
        })
    }

    /// This home ingesting `entry` from the pair's coordinator.
    async fn ingest(&self, entry: &Value) -> Result<(), crate::federation::FederationError> {
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            crate::federation::canonical_relay::ingest_remote_message_entry(
                &self.home_pool,
                None,
                C33_SEQ,
                self.cid,
                entry,
            ),
        )
        .await
    }
}

/// A control entry carries no coordinates: the next message of a deleted
/// account's peer is compared with the nearest entry that does, so the pair's
/// stream continues past the deletion entry. A wrong prior is still refused,
/// and a missing predecessor is still the retryable gap.
#[tokio::test]
async fn a_transport_home_keeps_its_pairs_stream_after_a_deletion_entry() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    p.network.authorize_device(
        p.peer(),
        &ed25519_dalek::SigningKey::from_bytes(&p.fixture.recipient_ed25519_seed)
            .verifying_key()
            .to_bytes(),
    );
    scope_ds_clock(p.clock.clone(), async {
        p.store(cid, &p.message).await;
        let deletion = Pair::entry(
            &p.receipt,
            cid,
            p.deleted(),
            seq + 1,
            Uuid::new_v4(),
            current_utc(),
        );
        p.accept(C33_SEQ, &deletion)
            .await
            .expect("the deletion applies");
        let refusal = |result: Result<(), crate::federation::FederationError>| match result {
            Err(crate::federation::FederationError::InvalidRequest(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        };

        let before = home_state(&p.home_pool).await;
        let wrong = p.peer_message(seq + 2, |body| {
            let epoch = body["prior"]["epoch"].as_i64().unwrap() + 1;
            body["prior"]["epoch"] = json!(epoch);
            body["aad"]["prior"]["epoch"] = json!(epoch);
        });
        assert_eq!(
            refusal(p.ingest(&wrong).await),
            "message coordinates differ from retained predecessor"
        );
        assert_eq!(home_state(&p.home_pool).await, before);

        p.ingest(&p.peer_message(seq + 2, |_| {}))
            .await
            .expect("the pair's next message follows the deletion entry");
        let later = p.peer_message(seq + 4, |_| {});
        // The gap is the typed, retried predecessor conflict, not a refusal.
        let gap = p.ingest(&later).await.expect_err("a gap");
        assert!(
            matches!(
                &gap,
                crate::federation::FederationError::PredecessorMissing { .. }
            ),
            "{gap:?}"
        );
        assert_eq!(
            gap.reason_code(),
            crate::federation::errors::PREDECESSOR_MISSING_REASON
        );
        p.ingest(&p.peer_message(seq + 3, |_| {}))
            .await
            .expect("the gap's predecessor arrives");
        p.ingest(&later).await.expect("the gap closes");
        let held: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM chat.direct_request_transport_entries \
              WHERE conversation_id = $1 ORDER BY seq",
        )
        .bind(cid)
        .fetch_all(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(held, (1..=seq + 4).collect::<Vec<_>>());
    })
    .await;
}

#[path = "c33_deleted_peer_tests.rs"]
mod deleted_peer;

#[path = "c33_deleted_acceptance_tests.rs"]
mod deleted_acceptance;

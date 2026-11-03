//! `relayAccountDeletion` regressions on real PostgreSQL. A deleted account's
//! home never writes a mirror's seq chain: it relays the deletion, signed, to
//! each remote sequencer, which sequences `accountDeletedEntry` once, fans it
//! out in order and prunes the account's held ciphertext with signed notices.

use super::super::entry_ack_relay::account_deletion_relay::{
    accept_account_deletion_relay, AccountDeletionRelay,
};
use super::*;
use crate::labyrinth::repo::retention::delete_account_data_with_conversations;

const ACCOUNT_DELETED: &str = "blue.catbird.chat.defs#accountDeletedEntry";

fn canonical(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn deletion_relay(
    key: &SigningKey,
    home_did: &str,
    sequencer_did: &str,
    conversation_id: Uuid,
    deleted_did: &str,
    deleted_at: &str,
) -> AccountDeletionRelay {
    let mut relay = AccountDeletionRelay {
        home_did: home_did.to_owned(),
        sequencer_did: sequencer_did.to_owned(),
        conversation_id,
        deleted_did: deleted_did.to_owned(),
        deleted_at: deleted_at.to_owned(),
        signature: String::new(),
    };
    let signature: Signature = key.sign(&relay.signing_bytes());
    relay.signature = STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes());
    relay
}

/// A C33 inbox of `conversation_id`, coordinated by `coordinator`.
async fn c33_inbox(
    pool: &DbPool,
    conversation_id: Uuid,
    coordinator: &str,
    (sender_did, sender_device_id): (&str, Uuid),
    (recipient_did, recipient_device_id): (&str, Uuid),
) {
    let opening = b"c33-account-deletion-fixture";
    sqlx::query(
        "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id, \
             coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry, \
             signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt, \
             import_until,status) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10,$9,$9,$11,'accepted')",
    )
    .bind(Uuid::new_v4())
    .bind(conversation_id)
    .bind(Uuid::new_v4())
    .bind(coordinator)
    .bind(sender_did)
    .bind(sender_device_id)
    .bind(recipient_did)
    .bind(recipient_device_id)
    .bind(opening.as_slice())
    .bind(Sha256::digest(opening).as_slice())
    .bind(Utc::now() + chrono::Duration::days(1))
    .execute(pool)
    .await
    .unwrap();
}

/// `(entries, highest seq, next seq)` of a conversation's local seq chain.
async fn chain(pool: &DbPool, conversation_id: Uuid) -> (i64, Option<i64>, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM chat.entries WHERE conversation_id = $1), \
                (SELECT max(seq) FROM chat.entries WHERE conversation_id = $1), \
                (SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1)",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `(seq, actor)` of each `accountDeletedEntry` of a conversation.
async fn deletions(pool: &DbPool, conversation_id: Uuid) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT seq, actor_did FROM chat.entries \
          WHERE conversation_id = $1 AND entry_kind = $2 ORDER BY seq",
    )
    .bind(conversation_id)
    .bind(ACCOUNT_DELETED)
    .fetch_all(pool)
    .await
    .unwrap()
}

type SequencerState = (Vec<i64>, Vec<(i64, String)>, Vec<(String, String, i32)>);

/// Every effect a relay may have at the sequencer: ACK and payload state,
/// deletion entries, and queued deliveries and notices.
async fn sequencer_state(pool: &DbPool, conversation_id: Uuid) -> SequencerState {
    (
        ack_state(pool, conversation_id).await,
        deletions(pool, conversation_id).await,
        queue_rows(pool, conversation_id)
            .await
            .into_iter()
            .map(|(id, _, status, retries, _, _)| (id, status, retries))
            .collect(),
    )
}

async fn assert_refused(
    state: &GroupRelayState,
    caller: &str,
    relay: &AccountDeletionRelay,
    conversation_id: Uuid,
    (status, code): (StatusCode, &str),
) {
    let before = sequencer_state(&state.pool, conversation_id).await;
    let response =
        accept_account_deletion_relay(state, caller, &serde_json::to_vec(relay).unwrap())
            .await
            .expect_err("the relay must be refused");
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
        "{caller}: {body}"
    );
    assert_eq!(
        sequencer_state(&state.pool, conversation_id).await,
        before,
        "{caller}: {body}"
    );
}

async fn push_bound(pool: &DbPool, did: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.push_gateway_bindings WHERE user_did = $1)",
    )
    .bind(did)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_deleted_accounts_home_relays_each_remote_conversation_and_never_writes_its_mirror() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    // The deleted account is homed here: a member of SEQ's group, mirrored
    // here, and a party to a C33 pair SEQ coordinates.
    let mirror = seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, None)
        .await
        .unwrap();
    let deleted = mirror.recipient_did.clone();
    let c33 = Uuid::new_v4();
    c33_inbox(
        &pool,
        c33,
        SEQ,
        (&mirror.sender_did, mirror.sender_device_id),
        (&deleted, mirror.recipient_device_id),
    )
    .await;
    // A third remote group knows the account only through this home's
    // verified membership index: it is owed exactly one relay too.
    let indexed = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.remote_group_memberships \
             (conversation_id, user_did, sequencer_did, status, evidence_seq, \
              evidence_entry_id, updated_at) \
         VALUES ($1, $2, $3, 'active', 3, $4, now())",
    )
    .bind(indexed)
    .bind(&deleted)
    .bind(SEQ)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    let index_rows = |pool: DbPool, deleted: String| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM chat.remote_group_memberships WHERE user_did = $1",
        )
        .bind(deleted)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    sqlx::query(
        "INSERT INTO chat.push_gateway_bindings (user_did, device_id, gateway_url, app_id, \
             push_key, key_id, auth_generation, signed_at, updated_at) \
         VALUES ($1, $2, 'https://push.example.com/xrpc/blue.catbird.push.deliver', \
                 'blue.catbird.test', 'deleted-account-push-key', $3, 1, now(), now())",
    )
    .bind(&deleted)
    .bind(mirror.recipient_device_id)
    .bind(&mirror.recipient_key_id)
    .execute(&pool)
    .await
    .unwrap();
    let mirrored = chain(&pool, mirror.conversation_id).await;
    let home_key = key(0x32);
    let network = Network::default();

    scope_ds_clock(manual_clock(), async {
        let at = current_utc();
        // Without its S2S signer the home refuses the whole deletion.
        let refused = scope_sim_ds(
            hooks(HOME, None, false, &network),
            delete_account_data_with_conversations(&pool, &deleted, at, None),
        )
        .await
        .expect_err("the owed relays cannot be signed");
        assert_eq!(
            (refused.status(), refused.name()),
            (StatusCode::SERVICE_UNAVAILABLE, "SignerUnavailable")
        );
        assert!(push_bound(&pool, &deleted).await, "nothing commits");
        for conversation_id in [mirror.conversation_id, c33, indexed] {
            assert!(queue_rows(&pool, conversation_id).await.is_empty());
        }
        assert_eq!(chain(&pool, mirror.conversation_id).await, mirrored);
        assert_eq!(
            index_rows(pool.clone(), deleted.clone()).await,
            1,
            "nothing commits"
        );

        // With it, the mirror's seq chain stays SEQ's alone and each remote
        // conversation's sequencer is owed one bound relay; replaying the
        // same deletion queues nothing more.
        let deleted_at = canonical(at);
        for _ in 0..2 {
            // It sequences none of them, so it needs no receipt signer.
            let sequenced = scope_sim_ds(
                hooks(HOME, Some(&home_key), false, &network),
                delete_account_data_with_conversations(&pool, &deleted, at, None),
            )
            .await
            .unwrap();
            assert_eq!(sequenced, 0, "this home sequences none of them");
            assert_eq!(chain(&pool, mirror.conversation_id).await, mirrored);
            assert!(!push_bound(&pool, &deleted).await);
            assert_eq!(
                index_rows(pool.clone(), deleted.clone()).await,
                0,
                "the deleted account's index rows end with it"
            );
            for conversation_id in [mirror.conversation_id, c33, indexed] {
                let rows = queue_rows(&pool, conversation_id).await;
                assert_eq!(rows.len(), 1, "one relay per remote conversation");
                let (id, target, status, retries, due, payload) = &rows[0];
                assert_eq!(
                    id,
                    &format!("account-deletion-{conversation_id}-{deleted}-{deleted_at}")
                );
                assert_eq!(
                    (target.as_str(), status.as_str(), *retries),
                    (SEQ, "pending", 0)
                );
                assert!(*due <= current_utc(), "the relay is due immediately");
                let relay: AccountDeletionRelay = serde_json::from_slice(payload).unwrap();
                let signature =
                    Signature::from_slice(&STANDARD.decode(&relay.signature).unwrap()).unwrap();
                home_key
                    .verifying_key()
                    .verify(&relay.signing_bytes(), &signature)
                    .expect("signed by the home's #atproto key");
                assert_eq!(
                    AccountDeletionRelay {
                        signature: String::new(),
                        ..relay
                    },
                    AccountDeletionRelay {
                        home_did: HOME.to_owned(),
                        sequencer_did: SEQ.to_owned(),
                        conversation_id,
                        deleted_did: deleted.clone(),
                        deleted_at: deleted_at.clone(),
                        signature: String::new(),
                    }
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn a_sequencer_applies_its_homes_account_deletion_relay_exactly_once() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let (seq_key, home_key, other_key) = (key(0x31), key(0x32), key(0x33));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key), (OTHER, &other_key)]);
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    // The deleted account, homed at HOME, sent an application SEQ still holds.
    let (fixture, state, seq) =
        relayed_application(&pool, Arc::clone(&seq_hooks), clock.clone(), &seq_key).await;
    let cid = fixture.conversation_id;
    let deleted = fixture.sender_did.as_str();
    assert_eq!(ack_state(&pool, cid).await, [0, 0, 1, 1, 1]);

    scope_ds_clock(
        clock,
        scope_sim_ds(seq_hooks, async {
            let deleted_at = canonical(current_utc());
            let later = canonical(current_utc() + chrono::TimeDelta::milliseconds(1));
            let genuine = deletion_relay(&home_key, HOME, SEQ, cid, deleted, &deleted_at);
            let edited = |edit: &dyn Fn(&mut AccountDeletionRelay)| {
                let mut relay = genuine.clone();
                edit(&mut relay);
                relay
            };
            let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
            let tampered = (StatusCode::FORBIDDEN, "InvalidSignature");
            let cases = [
                // Wrong home: a genuine signature from a DS the account is not homed at.
                (
                    OTHER,
                    deletion_relay(&other_key, OTHER, SEQ, cid, deleted, &deleted_at),
                    forbidden,
                ),
                (OTHER, genuine.clone(), forbidden),
                // Bound to another sequencer.
                (
                    HOME,
                    deletion_relay(&home_key, HOME, OTHER, cid, deleted, &deleted_at),
                    forbidden,
                ),
                // HOME speaks neither for SEQ's local member nor for a stranger.
                (
                    HOME,
                    deletion_relay(
                        &home_key,
                        HOME,
                        SEQ,
                        cid,
                        &fixture.recipient_did,
                        &deleted_at,
                    ),
                    forbidden,
                ),
                (
                    HOME,
                    deletion_relay(
                        &home_key,
                        HOME,
                        SEQ,
                        cid,
                        "did:web:never-joined.example.com",
                        &deleted_at,
                    ),
                    forbidden,
                ),
                // A conversation SEQ does not hold.
                (
                    HOME,
                    deletion_relay(&home_key, HOME, SEQ, Uuid::new_v4(), deleted, &deleted_at),
                    (StatusCode::NOT_FOUND, "ConversationNotFound"),
                ),
                // A deletion instant outside its canonical form.
                (
                    HOME,
                    deletion_relay(&home_key, HOME, SEQ, cid, deleted, "2026-11-03T12:00:00Z"),
                    (StatusCode::BAD_REQUEST, "InvalidRequest"),
                ),
                // Every signed field, altered after signing.
                (HOME, edited(&|r| r.home_did = OTHER.to_owned()), forbidden),
                (
                    HOME,
                    edited(&|r| r.sequencer_did = OTHER.to_owned()),
                    forbidden,
                ),
                (
                    HOME,
                    edited(&|r| r.conversation_id = Uuid::new_v4()),
                    tampered,
                ),
                (
                    HOME,
                    edited(&|r| r.deleted_did = fixture.recipient_did.clone()),
                    tampered,
                ),
                (HOME, edited(&|r| r.deleted_at = later.clone()), tampered),
                (
                    HOME,
                    edited(&|r| {
                        let mut signature = STANDARD.decode(&r.signature).unwrap();
                        signature[63] ^= 1;
                        r.signature = STANDARD.encode(signature);
                    }),
                    tampered,
                ),
            ];
            for (caller, relay, refusal) in cases {
                assert_refused(&state, caller, &relay, cid, refusal).await;
            }

            // A sequencer without its #mls-receipt-1 signer cannot sequence the
            // signed entry: it answers 503 so the home retries, and changes nothing.
            let unsigned =
                GroupRelayState::for_test(pool.clone(), SEQ.to_owned(), HMAC.as_bytes(), None);
            assert_refused(
                &unsigned,
                HOME,
                &genuine,
                cid,
                (StatusCode::SERVICE_UNAVAILABLE, "SignerUnavailable"),
            )
            .await;

            // The genuine relay applies as a local deletion: the entry is
            // sequenced and queued for HOME in seq order, and the account's
            // message keeps only its seq, digests and I13 receipt, with HOME's
            // signed notice queued.
            let body = serde_json::to_vec(&genuine).unwrap();
            let applied = accept_account_deletion_relay(&state, HOME, &body)
                .await
                .expect("the genuine relay applies");
            assert_eq!(
                applied,
                json!({ "accepted": true, "sequenced": true, "prunedCount": 1 })
            );
            assert_eq!(deletions(&pool, cid).await, [(seq + 1, deleted.to_owned())]);
            assert_eq!(ack_state(&pool, cid).await, [0, 0, 0, 0, 1]);
            let notices = notice_rows(&pool, cid).await;
            assert_eq!(notices.len(), 1, "one notice for HOME");
            assert_eq!(
                notices[0].0,
                format!("entries-pruned-{cid}-{seq:020}-{HOME}")
            );
            let notice: EntriesPrunedNotice = serde_json::from_slice(&notices[0].5).unwrap();
            assert_eq!(notice, signed_notice(&seq_key, SEQ, HOME, cid, vec![seq]));
            let fanned_out = queue_rows(&pool, cid)
                .await
                .into_iter()
                .find(|row| row.0 == format!("group-entry-{cid}-{}-{HOME}", seq + 1))
                .expect("the entry is queued for HOME");
            let request: DeliverGroupEntryRequest = serde_json::from_slice(&fanned_out.5).unwrap();
            assert_eq!(
                request.recipient_devices,
                [(deleted.to_owned(), fixture.sender_device_id)]
            );
            let entry_id: Uuid = sqlx::query_scalar(
                "SELECT entry_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
            )
            .bind(cid)
            .bind(seq + 1)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                (
                    request.entry["$type"].as_str(),
                    request.entry["entryId"].as_str(),
                    request.entry["deletedDid"].as_str(),
                    request.entry["seq"].as_i64(),
                ),
                (
                    Some(ACCOUNT_DELETED),
                    Some(entry_id.to_string().as_str()),
                    Some(deleted),
                    Some(seq + 1)
                )
            );
            // HOME is fanned out the exact entry SEQ signed with its receipt key,
            // stamped with SEQ's own instant, as SEQ's getEntries presents it.
            let (deletion, authority) =
                crate::federation::receipt::AccountDeletion::from_entry(&request.entry)
                    .expect("the exact canonical entry");
            authority
                .verify(seq_key.verifying_key(), &deletion)
                .expect("signed by SEQ#mls-receipt-1");
            assert_eq!(
                (deletion.sequencer_did.as_str(), deletion.deleted_at),
                (SEQ, current_utc())
            );
            let (server_fields, received_at): (Vec<u8>, DateTime<Utc>) = sqlx::query_as(
                "SELECT server_fields_bytes, received_at FROM chat.entries \
                  WHERE conversation_id = $1 AND seq = $2",
            )
            .bind(cid)
            .bind(seq + 1)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                serde_ipld_dagcbor::from_slice::<
                    crate::chat_protocol::repository::entry_read::AccountDeletedServerFields,
                >(&server_fields)
                .unwrap()
                .entry(cid, seq + 1, entry_id, received_at),
                request.entry,
                "the stored row rebuilds exactly the fanned-out entry"
            );

            // A duplicate relay sequences, prunes and queues nothing more.
            let settled = sequencer_state(&pool, cid).await;
            let again = accept_account_deletion_relay(&state, HOME, &body)
                .await
                .expect("a duplicate relay is accepted");
            assert_eq!(
                again,
                json!({ "accepted": true, "sequenced": false, "prunedCount": 0 })
            );
            assert_eq!(sequencer_state(&pool, cid).await, settled);
        }),
    )
    .await;
}

/// One production queue-worker pass at `did`.
async fn drain(
    queue: &OutboundQueue,
    hooks: &Arc<SimDsHooks>,
    did: &str,
    key: &SigningKey,
) -> usize {
    crate::federation::open_federation_for_test();
    let auth = ServiceAuthClient::from_es256_pem(
        did.to_owned(),
        pem(key).as_bytes(),
        Some("#atproto".to_owned()),
    )
    .unwrap();
    let sign = move |target: &str, method: &str| {
        auth.sign_request(target, method)
            .map_err(|error| error.to_string())
    };
    scope_sim_ds(
        Arc::clone(hooks),
        queue.process_pending_batch(&OutboundClient::new(5, 5), &sign),
    )
    .await
    .unwrap()
}

/// `(status, retries)` of a conversation's one queued relay.
async fn relay_status(pool: &DbPool, conversation_id: Uuid) -> (String, i32) {
    let rows = queue_rows(pool, conversation_id).await;
    assert_eq!(rows.len(), 1);
    let (_, _, status, retries, _, _) = rows.into_iter().next().unwrap();
    (status, retries)
}

async fn latest_due(pool: &DbPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT max(next_retry_at) FROM outbound_queue WHERE status = 'pending'")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The C33 coordinator records no home for the remote party: it learns it
/// from the account's PDS declaration. The transport-only home's relay reaches
/// it through the production queue and route, and is retried until it lands.
#[tokio::test]
async fn a_c33_coordinator_applies_the_deletion_its_transport_only_home_relays() {
    crate::federation::open_federation_for_test();
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    for (pool, peer) in [(&seq_pool, C33_HOME), (&home_pool, C33_SEQ)] {
        ensure_fence(pool).await;
        sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
            .bind(peer)
            .execute(pool)
            .await
            .unwrap();
    }
    // A direct pair SEQ coordinates: the deleted sender is remote, the recipient local.
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        true,
        C33_SEQ,
        Some([0x5d; 32]),
        None,
    )
    .await
    .unwrap();
    let cid = fixture.conversation_id;
    let deleted = fixture.sender_did.as_str();
    let (seq_key, home_key) = (key(0x41), key(0x42));
    let network = Network::new(&[(C33_SEQ, &seq_key), (C33_HOME, &home_key)]);
    for ds in [C33_SEQ, C33_HOME] {
        network.declare_delivery_service(ds);
    }
    network.declare_user(deleted, C33_HOME);
    network.declare_user(&fixture.recipient_did, C33_SEQ);
    let clock = manual_clock();
    let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
    let home_hooks = hooks(C33_HOME, Some(&home_key), false, &network);
    let seq_state = GroupRelayState::for_test(
        seq_pool.clone(),
        C33_SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(I13ReceiptSigner::new(
            seq_key.clone(),
            C33_SEQ.to_owned(),
        ))),
    )
    .with_sim_hooks(Arc::clone(&seq_hooks))
    .with_clock(clock.clone());
    let runtime = Arc::new(
        crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(I13ReceiptSigner::new(seq_key.clone(), C33_SEQ.to_owned())),
    );
    // The home holds the pair's inbox, and one for a pair SEQ no longer holds.
    let gone = Uuid::new_v4();
    for conversation_id in [cid, gone] {
        c33_inbox(
            &home_pool,
            conversation_id,
            C33_SEQ,
            (deleted, fixture.sender_device_id),
            (&fixture.recipient_did, fixture.recipient_device_id),
        )
        .await;
    }
    let queue = OutboundQueue::new(
        home_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(resolver(&home_pool, C33_HOME)),
    );

    scope_ds_clock(clock.clone(), async {
        // The deleted account's message, relayed by its declared home.
        let sequenced = scope_sim_ds(
            Arc::clone(&seq_hooks),
            crate::federation::canonical_relay::coordinator_handle_message(
                &seq_pool,
                &runtime,
                C33_HOME,
                cid,
                &fixture.signed_request,
            ),
        )
        .await
        .expect("coordinate the deleted account's application");
        let seq = sequenced["entry"]["seq"].as_i64().unwrap();
        assert_eq!(ack_state(&seq_pool, cid).await, [0, 0, 1, 1, 1]);

        // The deleted account's own home holds its message, exactly as the home
        // that relayed it stores the coordinator's entry.
        let message = &sequenced["entry"];
        let mut tx = home_pool.begin().await.unwrap();
        crate::chat_protocol::repository::delivery::insert_transport_entry(
            &mut tx,
            cid,
            seq,
            message["entryId"].as_str().unwrap().parse().unwrap(),
            &serde_json::to_vec(message).unwrap(),
            current_utc(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        /// `(entry bytes, original digest, request digest, signed metadata, pruned)`.
        type Held = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, bool);
        async fn held(pool: &DbPool, conversation_id: Uuid, seq: i64) -> Held {
            sqlx::query_as(
                "SELECT entry_bytes, original_entry_sha256, application_request_sha256, \
                        application_metadata_bytes, payload_pruned_at IS NOT NULL \
                   FROM chat.direct_request_transport_entries \
                  WHERE conversation_id = $1 AND seq = $2",
            )
            .bind(conversation_id)
            .bind(seq)
            .fetch_one(pool)
            .await
            .unwrap()
        }
        let ciphertext = fixture.signed_request["body"]["applicationMessage"]["bytes"]
            .as_str()
            .unwrap()
            .to_owned();
        let carries_ciphertext = |bytes: &[u8]| {
            bytes
                .windows(ciphertext.len())
                .any(|w| w == ciphertext.as_bytes())
        };
        let stored = held(&home_pool, cid, seq).await;
        assert!(!stored.4 && carries_ciphertext(&stored.0));

        // Deleting it leaves no ciphertext of the account's in any column there:
        // the entry keeps its seq, digests, signed metadata and I13 receipt, and
        // a repeated deletion prunes nothing more.
        let at = current_utc();
        let mut after = Vec::new();
        for _ in 0..2 {
            let local = scope_sim_ds(
                Arc::clone(&home_hooks),
                delete_account_data_with_conversations(&home_pool, deleted, at, None),
            )
            .await
            .unwrap();
            assert_eq!(local, 0);
            after.push(held(&home_pool, cid, seq).await);
        }
        let pruned = &after[0];
        assert_eq!(after[1], *pruned, "a repeat prunes nothing more");
        assert!(pruned.4, "the deleted account's own copy is pruned");
        assert!(!carries_ciphertext(&pruned.0));
        let metadata = pruned.3.as_deref().expect("signed metadata stays");
        assert!(!carries_ciphertext(metadata));
        assert_eq!((&pruned.1, &pruned.2), (&stored.1, &stored.2));
        let projection: Value = serde_json::from_slice(&pruned.0).unwrap();
        assert_eq!(projection["payloadPruned"], true);
        assert_eq!(projection["sequencerReceipt"], message["sequencerReceipt"]);

        // An unreachable coordinator is retried past the queue's retry limit,
        // and an undeclared 404 is retried too: a deletion is never dropped.
        network.partition(true);
        for attempt in 1..=6 {
            clock.set_utc(latest_due(&home_pool).await);
            assert_eq!(drain(&queue, &home_hooks, C33_HOME, &home_key).await, 2);
            for conversation_id in [cid, gone] {
                assert_eq!(
                    relay_status(&home_pool, conversation_id).await,
                    ("pending".to_owned(), attempt)
                );
            }
        }
        network.partition(false);
        network.serve(C33_SEQ, Router::new());
        clock.set_utc(latest_due(&home_pool).await);
        assert_eq!(drain(&queue, &home_hooks, C33_HOME, &home_key).await, 2);
        for conversation_id in [cid, gone] {
            assert_eq!(
                relay_status(&home_pool, conversation_id).await,
                ("pending".to_owned(), 7)
            );
        }
        assert!(deletions(&seq_pool, cid).await.is_empty());

        // The coordinator applies the relay; its declared absence for the
        // pair it no longer holds is final.
        network.serve(C33_SEQ, group_relay_router(seq_state.clone()));
        clock.set_utc(latest_due(&home_pool).await);
        assert_eq!(drain(&queue, &home_hooks, C33_HOME, &home_key).await, 2);
        assert_eq!(relay_status(&home_pool, cid).await.0, "delivered");
        assert_eq!(relay_status(&home_pool, gone).await.0, "failed");
        assert_eq!(
            deletions(&seq_pool, cid).await,
            [(seq + 1, deleted.to_owned())]
        );
        assert_eq!(ack_state(&seq_pool, cid).await, [0, 0, 0, 0, 1]);
        // D's own home is owed nothing; the peer, local here, reads the
        // coordinator's signed entry at its seq.
        assert!(queue_rows(&seq_pool, cid)
            .await
            .iter()
            .all(|row| !row.0.starts_with("transport-control-")));
        let (server_fields, entry_id, received_at): (Vec<u8>, Uuid, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT server_fields_bytes, entry_id, received_at FROM chat.entries \
                  WHERE conversation_id = $1 AND seq = $2",
            )
            .bind(cid)
            .bind(seq + 1)
            .fetch_one(&seq_pool)
            .await
            .unwrap();
        let entry = serde_ipld_dagcbor::from_slice::<
            crate::chat_protocol::repository::entry_read::AccountDeletedServerFields,
        >(&server_fields)
        .unwrap()
        .entry(cid, seq + 1, entry_id, received_at);
        let (deletion, authority) =
            crate::federation::receipt::AccountDeletion::from_entry(&entry).unwrap();
        assert_eq!(
            (
                deletion.deleted_did.as_str(),
                deletion.sequencer_did.as_str()
            ),
            (deleted, C33_SEQ)
        );
        authority
            .verify(
                &I13ReceiptSigner::new(seq_key.clone(), C33_SEQ.to_owned()).verifying_key(),
                &deletion,
            )
            .unwrap();

        // Redelivered, the relay changes nothing.
        let payload = queue_rows(&home_pool, cid).await.remove(0).5;
        let settled = sequencer_state(&seq_pool, cid).await;
        let again = scope_sim_ds(
            Arc::clone(&seq_hooks),
            accept_account_deletion_relay(&seq_state, C33_HOME, &payload),
        )
        .await
        .expect("a duplicate relay is accepted");
        assert_eq!(again["sequenced"], false);
        assert_eq!(sequencer_state(&seq_pool, cid).await, settled);
    })
    .await;
}

/// The coordinator cannot resolve a C33 peer's home before the deletion's
/// transaction. The peer's PDS unreachable decided nothing: 503
/// `PeerHomeUnavailable` with `Retry-After`, as is a pair resolved before it
/// existed. This DS's own peer-policy store failing while resolving it decided
/// nothing either: 500, no retry hint. None commits anything; the identical
/// deletion then sequences its entry and queues it for the peer's home.
#[tokio::test]
async fn a_c33_peer_home_that_cannot_be_resolved_now_holds_the_deletion_back() {
    use axum::{http::header::RETRY_AFTER, response::IntoResponse as _};
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    ensure_fence(&pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(C33_HOME)
        .execute(&pool)
        .await
        .unwrap();
    // A direct pair C33_SEQ coordinates: the deleted account D is the sender
    // homed there, its peer P the recipient homed at C33_HOME.
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        true,
        C33_HOME,
        Some([0x5f; 32]),
        None,
    )
    .await
    .unwrap();
    let (cid, deleted) = (fixture.conversation_id, fixture.sender_did.as_str());
    let seq_key = key(0x45);
    let network = Network::new(&[(C33_SEQ, &seq_key), (C33_HOME, &key(0x46))]);
    for ds in [C33_SEQ, C33_HOME] {
        network.declare_delivery_service(ds);
    }
    network.declare_user(deleted, C33_SEQ);
    network.declare_user(&fixture.recipient_did, C33_HOME);
    let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
    let signer = I13ReceiptSigner::new(key(0x47), C33_SEQ.to_owned());
    let at = current_utc();
    let delete = || {
        scope_sim_ds(
            Arc::clone(&seq_hooks),
            delete_account_data_with_conversations(&pool, deleted, at, Some(&signer)),
        )
    };
    let before = (chain(&pool, cid).await, queue_rows(&pool, cid).await.len());

    network.partition(true);
    let unreachable = delete()
        .await
        .expect_err("an unreachable peer home holds it back");
    network.partition(false);
    assert_eq!(
        (unreachable.status(), unreachable.name()),
        (StatusCode::SERVICE_UNAVAILABLE, "PeerHomeUnavailable")
    );
    assert_eq!(
        unreachable
            .into_response()
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        (chain(&pool, cid).await, queue_rows(&pool, cid).await.len()),
        before
    );

    sqlx::query("ALTER TABLE federation_peers RENAME TO federation_peers_offline")
        .execute(&pool)
        .await
        .unwrap();
    let stored = delete()
        .await
        .expect_err("this DS's own store failing holds it back");
    sqlx::query("ALTER TABLE federation_peers_offline RENAME TO federation_peers")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        (stored.status(), stored.name()),
        (StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError")
    );
    assert!(stored.into_response().headers().get(RETRY_AFTER).is_none());
    assert_eq!(
        (chain(&pool, cid).await, queue_rows(&pool, cid).await.len()),
        before
    );

    // A pair the peer homes were resolved before (one created since) is held
    // back the same way, its entry rolled back.
    let mut conn = pool.acquire().await.unwrap();
    let unresolved = scope_sim_ds(
        Arc::clone(&seq_hooks),
        crate::labyrinth::repo::retention::purge_account(
            &mut conn,
            deleted,
            at,
            Some(&signer),
            &crate::federation::group_relay::C33PeerHomes::default(),
        ),
    )
    .await
    .expect_err("a pair whose peer home was not resolved holds it back");
    drop(conn);
    assert_eq!(
        (unresolved.status(), unresolved.name()),
        (StatusCode::SERVICE_UNAVAILABLE, "PeerHomeUnavailable")
    );
    assert_eq!(
        unresolved
            .into_response()
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        (chain(&pool, cid).await, queue_rows(&pool, cid).await.len()),
        before
    );

    assert_eq!(delete().await.unwrap(), 1);
    assert_eq!(
        deletions(&pool, cid).await,
        [(before.0 .2, deleted.to_owned())]
    );
    let queued = queue_rows(&pool, cid).await;
    assert!(
        queued
            .iter()
            .any(|row| row.0.starts_with("transport-control-") && row.1 == C33_HOME),
        "{queued:?}"
    );
}

#[path = "transport_control_entry_tests.rs"]
mod transport_control;

#[path = "deletion_evidence_tests.rs"]
mod deletion_evidence;

#[path = "c33_close_relay_tests.rs"]
mod c33_close;

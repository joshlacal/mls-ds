//! A C33 coordinator delivers none of a pair's later entries to the home of a
//! party with an `accountDeletedEntry` sequenced in that conversation, and
//! decides so before resolving that home. D, the fixture's sender, is homed at
//! the pair's transport-only home, which relays D's deletion; P, homed at the
//! coordinator, sends through the coordinator's real `sendMessage` route. With
//! D homed at the coordinator instead, P's transport-only home relays to the
//! coordinator its inbox recorded, and a pruned send replays as its accepted,
//! pruned entry through both delivery services' real routes. D's own state
//! read at its transport-only home is the coordinator's answer, relayed with
//! P's deletion evidence.

use super::*;
use crate::{
    chat_protocol::relationship_policy::{PublicResponse, SimSourceFault, TransportError},
    common::http_acceptance as http,
    handlers::chat::ChatRuntime,
};

const SEND_MESSAGE: &str = "blue.catbird.chat.sendMessage";
const DELIVER_MESSAGE_ENTRY: &str = "/xrpc/blue.catbird.mlsDS.deliverMessageEntry";

/// A direct pair C33_SEQ coordinates. D is homed at C33_HOME, which holds the
/// pair's transport inbox and D's sequenced message, and stores what the
/// coordinator delivers through its real `deliverMessageEntry` ingest. P is
/// homed at C33_SEQ.
struct RelayedPair {
    _dbs: [DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    fixture: CleanSlateApplicationFixture,
    cid: Uuid,
    network: Network,
    clock: Arc<ManualDsClock>,
    seq_hooks: Arc<SimDsHooks>,
    home_hooks: Arc<SimDsHooks>,
    home_key: SigningKey,
    runtime: Arc<ChatRuntime>,
    router: Router,
    device: http::Device,
    /// D's message's seq.
    seq: i64,
}

impl RelayedPair {
    async fn new() -> Self {
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
        let fixture = seed_clean_slate_application_fixture_with_sender_home(
            &seq_pool,
            true,
            C33_SEQ,
            Some([0x5f; 32]),
            None,
        )
        .await
        .unwrap();
        let cid = fixture.conversation_id;
        let (seq_key, home_key) = (key(0x61), key(0x62));
        let network = Network::new(&[(C33_SEQ, &seq_key), (C33_HOME, &home_key)]);
        for ds in [C33_SEQ, C33_HOME] {
            network.declare_delivery_service(ds);
        }
        network.declare_user(&fixture.sender_did, C33_HOME);
        network.declare_user(&fixture.recipient_did, C33_SEQ);
        network.authorize_device(
            &fixture.recipient_did,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
                .verifying_key()
                .to_bytes(),
        );
        let clock = manual_clock();
        let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
        let home_hooks = hooks(C33_HOME, Some(&home_key), false, &network);
        let signer = I13ReceiptSigner::new(seq_key.clone(), C33_SEQ.to_owned());
        network.serve(
            C33_SEQ,
            group_relay_router(
                GroupRelayState::for_test(
                    seq_pool.clone(),
                    C33_SEQ.to_owned(),
                    HMAC.as_bytes(),
                    Some(Arc::new(signer.clone())),
                )
                .with_sim_hooks(Arc::clone(&seq_hooks))
                .with_clock(clock.clone()),
            ),
        );
        // D's home ingests a delivery exactly as its `deliverMessageEntry`
        // route does once it has authenticated the pair's coordinator.
        let (pool, ingest_hooks) = (home_pool.clone(), Arc::clone(&home_hooks));
        network.serve(
            C33_HOME,
            Router::new().route(
                DELIVER_MESSAGE_ENTRY,
                axum::routing::post(move |Json(input): Json<DeliverMessageEntryInput>| {
                    let (pool, hooks) = (pool.clone(), Arc::clone(&ingest_hooks));
                    async move {
                        scope_sim_ds(
                            hooks,
                            crate::federation::canonical_relay::ingest_remote_message_entry(
                                &pool,
                                None,
                                C33_SEQ,
                                input.conversation_id,
                                &input.entry,
                            ),
                        )
                        .await
                        .map(|()| Json(json!({ "accepted": true })))
                    }
                }),
            ),
        );
        let runtime = Arc::new(
            ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
                .unwrap()
                .with_sim_allow_all_relationships()
                .unwrap()
                .with_i13_receipt_signer(signer.clone()),
        );
        let router = http::router_for_authenticated_acceptance_with(seq_pool.clone(), |runtime| {
            runtime
                .with_sim_allow_all_relationships()
                .unwrap()
                .with_i13_receipt_signer(signer)
                .with_clock(clock.clone())
                .with_sim_hooks(Arc::clone(&seq_hooks))
        })
        .await;
        // P's DID document also carries the key its service-auth JWTs verify with.
        let signing = http::random_p256();
        let jwk = http::public_jwk(&signing);
        network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(&fixture.recipient_did))
            .expect("P's DID document")["verificationMethod"] = json!([{
            "id": format!("{}#atproto", fixture.recipient_did),
            "type": "JsonWebKey2020",
            "controller": fixture.recipient_did,
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: fixture.recipient_did.clone(),
            device_id: fixture.recipient_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            signing,
            jwk,
        };
        c33_inbox(
            &home_pool,
            cid,
            C33_SEQ,
            (&fixture.sender_did, fixture.sender_device_id),
            (&fixture.recipient_did, fixture.recipient_device_id),
        )
        .await;

        // D's message, relayed by its home, which stores the coordinator's entry.
        let seq = scope_ds_clock(clock.clone(), async {
            let sequenced = scope_sim_ds(
                Arc::clone(&seq_hooks),
                coordinator_handle_message(
                    &seq_pool,
                    &runtime,
                    C33_HOME,
                    cid,
                    &fixture.signed_request,
                ),
            )
            .await
            .expect("coordinate D's application");
            let entry = &sequenced["entry"];
            let seq = entry["seq"].as_i64().unwrap();
            let mut tx = home_pool.begin().await.unwrap();
            delivery::insert_transport_entry(
                &mut tx,
                cid,
                seq,
                entry["entryId"].as_str().unwrap().parse().unwrap(),
                &serde_json::to_vec(entry).unwrap(),
                current_utc(),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            seq
        })
        .await;
        Self {
            _dbs: [seq_db, home_db],
            seq_pool,
            home_pool,
            fixture,
            cid,
            network,
            clock,
            seq_hooks,
            home_hooks,
            home_key,
            runtime,
            router,
            device,
            seq,
        }
    }

    /// P's own signed application, signed now.
    fn peer_send(&self) -> Value {
        self.fixture.next_recipient_signed_request()
    }

    /// D's own signed application, signed now.
    fn sender_send(&self) -> Value {
        self.fixture.next_sender_signed_request()
    }

    /// P sending `signed` through the coordinator's real `sendMessage` route.
    async fn send(&self, signed: &Value) -> (StatusCode, Value) {
        let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
        scope_sim_ds(Arc::clone(&self.seq_hooks), async {
            http::send(
                self.router.clone(),
                http::unsigned_json_request(&self.device, SEND_MESSAGE, body),
            )
            .await
        })
        .await
    }

    async fn submit(&self, nsid: &str, signed: &Value) -> (StatusCode, Value) {
        let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
        scope_sim_ds(Arc::clone(&self.seq_hooks), async {
            http::send(
                self.router.clone(),
                http::unsigned_json_request(&self.device, nsid, body),
            )
            .await
        })
        .await
    }

    /// P's `signed` application sequenced through the coordinator's relayed-send path.
    async fn relay(&self, signed: &Value) -> Result<Value, crate::federation::FederationError> {
        scope_sim_ds(
            Arc::clone(&self.seq_hooks),
            coordinator_handle_message(&self.seq_pool, &self.runtime, C33_SEQ, self.cid, signed),
        )
        .await
    }

    /// D's home deletes D and relays the deletion through its production queue;
    /// the coordinator sequences it. Returns its seq.
    async fn relay_deletion(&self) -> i64 {
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            delete_account_data_with_conversations(
                &self.home_pool,
                &self.fixture.sender_did,
                current_utc(),
                None,
            ),
        )
        .await
        .unwrap();
        let queue = OutboundQueue::new(
            self.home_pool.clone(),
            AuthMiddleware::new(),
            Arc::new(resolver(&self.home_pool, C33_HOME)),
        );
        assert_eq!(
            drain(&queue, &self.home_hooks, C33_HOME, &self.home_key).await,
            1
        );
        assert_eq!(relay_status(&self.home_pool, self.cid).await.0, "delivered");
        let deleted = deletions(&self.seq_pool, self.cid).await;
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].1, self.fixture.sender_did);
        deleted[0].0
    }

    /// The seq of every `deliverMessageEntry` that reached D's home.
    fn delivered(&self) -> Vec<i64> {
        self.network
            .delivered
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path == DELIVER_MESSAGE_ENTRY)
            .map(|(_, body)| {
                serde_json::from_slice::<DeliverMessageEntryInput>(body)
                    .unwrap()
                    .entry["seq"]
                    .as_i64()
                    .unwrap()
            })
            .collect()
    }

    /// The coordinator's queued `deliverMessageEntry` rows of the pair.
    async fn queued(&self) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT id FROM outbound_queue \
              WHERE convo_id = $1 AND method = 'blue.catbird.mlsDS.deliverMessageEntry' \
              ORDER BY id",
        )
        .bind(self.cid.to_string())
        .fetch_all(&self.seq_pool)
        .await
        .unwrap()
    }

    /// The seqs D's home holds.
    async fn held(&self) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT seq FROM chat.direct_request_transport_entries \
              WHERE conversation_id = $1 ORDER BY seq",
        )
        .bind(self.cid)
        .fetch_all(&self.home_pool)
        .await
        .unwrap()
    }
}

/// Before D's deletion, P's relayed C33 send reaches D's home, which stores it
/// next. Once D's relayed deletion is sequenced at N, P's local send and its
/// replay, and P's relayed send and its redrive, are sequenced from N+1 while
/// nothing more is sent or queued to D's home, whose stream would otherwise
/// stall at N forever.
#[tokio::test]
async fn a_c33_coordinator_delivers_nothing_to_a_relay_deleted_partys_home() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let sent = p
            .relay(&p.peer_send())
            .await
            .expect("P's relayed C33 send is sequenced");
        let first = p.seq + 1;
        assert_eq!(sent["entry"]["seq"], first);
        assert_eq!(p.delivered(), [first]);
        assert_eq!(p.held().await, [p.seq, first]);
        let jobs_before = p.queued().await;
        assert_eq!(jobs_before.len(), 1, "the delivered C33 job is retained");

        let n = p.relay_deletion().await;
        assert_eq!(n, first + 1);

        let signed = p.peer_send();
        let (status, sent) = p.send(&signed).await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        assert_eq!(sent["entry"]["seq"], n + 1);
        let (status, replay) = p.send(&signed).await;
        assert_eq!((status, &replay), (StatusCode::OK, &sent));
        let relayed = p.peer_send();
        let out = p
            .relay(&relayed)
            .await
            .expect("P's relayed send is sequenced");
        assert_eq!(out["entry"]["seq"], n + 2);
        let again = p.relay(&relayed).await.expect("its redrive sends nothing");
        assert_eq!(again["entry"]["seq"], n + 2);
        assert_eq!(p.delivered(), [first], "nothing more reaches D's home");
        assert_eq!(
            p.queued().await,
            jobs_before,
            "nothing more is queued for it"
        );
        assert_eq!(p.held().await, [p.seq, first]);
    })
    .await;
}

/// After D's relayed deletion its chat declaration is gone; P's send is still
/// sequenced, because the coordinator never resolves the home of a party it
/// delivers nothing to.
#[tokio::test]
async fn a_c33_send_needs_no_declaration_from_a_relay_deleted_peer() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let n = p.relay_deletion().await;
        assert_eq!(n, p.seq + 1);
        p.network.serve(
            &format!("pds-{}", host(&p.fixture.sender_did)),
            Router::new(),
        );

        let (status, sent) = p.send(&p.peer_send()).await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        assert_eq!(sent["entry"]["seq"], n + 1);
        assert!(p.delivered().is_empty());
        assert!(p.queued().await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn survivor_controls_ignore_a_relay_deleted_peers_home_and_declaration() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let deleted_seq = p.relay_deletion().await;
        assert_eq!(deleted_seq, p.seq + 1);
        p.network.serve(
            &format!("pds-{}", host(&p.fixture.sender_did)),
            Router::new(),
        );
        let peer_key = ed25519_dalek::SigningKey::from_bytes(&p.fixture.recipient_ed25519_seed);
        let reset_id = Uuid::new_v4();
        let reset = crate::chat_protocol::test_support::sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#resetRequestBody",
                "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
                "resetRequestId": reset_id,
                "idempotencyKey": reset_id,
                "actorDid": p.fixture.recipient_did,
                "actorDeviceId": p.fixture.recipient_device_id,
                "keyId": p.fixture.recipient_key_id,
                "authGeneration": 1,
                "prior": p.fixture.peer_self_update_signed_request["body"]["prior"],
                "reason": "manualRecovery",
                "signedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
            &peer_key,
        )
        .unwrap();
        let (status, reset_response) = p.submit("blue.catbird.chat.requestReset", &reset).await;
        assert_eq!(status, StatusCode::OK, "{reset_response}");
        assert!(reset_response["entry"]["sequencerReceipt"].is_object());
        let next_after_reset: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let (status, reset_replay) = p.submit("blue.catbird.chat.requestReset", &reset).await;
        assert_eq!((status, reset_replay), (StatusCode::OK, reset_response));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(p.cid)
            .fetch_one(&p.seq_pool)
            .await
            .unwrap(),
            next_after_reset
        );

        let update = p.fixture.peer_self_update_signed_request.clone();
        let (status, update_response) = p
            .submit("blue.catbird.chat.submitTransition", &update)
            .await;
        assert_eq!(status, StatusCode::OK, "{update_response}");
        assert!(update_response["entry"]["sequencerReceipt"].is_object());
        let next_after_update: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let (status, update_replay) = p
            .submit("blue.catbird.chat.submitTransition", &update)
            .await;
        assert_eq!((status, update_replay), (StatusCode::OK, update_response));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(p.cid)
            .fetch_one(&p.seq_pool)
            .await
            .unwrap(),
            next_after_update
        );
        let controls: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM outbound_queue WHERE convo_id=$1 \
               AND target_ds_did=$2 AND id LIKE 'transport-control-%'",
        )
        .bind(p.cid.to_string())
        .bind(C33_HOME)
        .fetch_all(&p.seq_pool)
        .await
        .unwrap();
        assert!(
            controls.is_empty(),
            "deleted peer home received later controls: {controls:?}"
        );
    })
    .await;

    let retained = RelayedPair::new().await;
    scope_ds_clock(retained.clock.clone(), async {
        retained.relay_deletion().await;
        let reset_id = Uuid::new_v4();
        let reset = crate::chat_protocol::test_support::sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#resetRequestBody",
                "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
                "resetRequestId": reset_id,
                "idempotencyKey": reset_id,
                "actorDid": retained.fixture.recipient_did,
                "actorDeviceId": retained.fixture.recipient_device_id,
                "keyId": retained.fixture.recipient_key_id,
                "authGeneration": 1,
                "prior": retained.fixture.peer_self_update_signed_request["body"]["prior"],
                "reason": "manualRecovery",
                "signedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
            &ed25519_dalek::SigningKey::from_bytes(&retained.fixture.recipient_ed25519_seed),
        )
        .unwrap();
        let (status, response) = retained
            .submit("blue.catbird.chat.requestReset", &reset)
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let controls: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM outbound_queue WHERE convo_id=$1 \
               AND target_ds_did=$2 AND id LIKE 'transport-control-%'",
        )
        .bind(retained.cid.to_string())
        .bind(C33_HOME)
        .fetch_all(&retained.seq_pool)
        .await
        .unwrap();
        assert!(
            controls.is_empty(),
            "retained deleted declaration still routed a control: {controls:?}"
        );
    })
    .await;
}

/// Once D's relayed deletion is sequenced, D's home is owed none of the pair's
/// later entries, control entries included, although D's declaration still
/// names it: P's own deletion queues nothing there (that home never stores D's
/// deletion, so it would refuse any later entry as a predecessor gap, retried
/// forever), and P's close addresses no home for D.
#[tokio::test]
async fn a_relay_deleted_partys_home_is_owed_no_later_deletion_or_close() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let peer_home = || {
            scope_sim_ds(
                Arc::clone(&p.seq_hooks),
                C33PeerHomes::peer_home(&p.seq_pool, p.cid, &p.fixture.sender_did),
            )
        };
        assert_eq!(peer_home().await.unwrap().as_deref(), Some(C33_HOME));
        let n = p.relay_deletion().await;
        assert_eq!(
            peer_home().await.unwrap(),
            None,
            "P's close owes D's home nothing"
        );

        let sequenced = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            delete_account_data_with_conversations(
                &p.seq_pool,
                &p.fixture.recipient_did,
                current_utc(),
                p.runtime.i13_receipt_signer(),
            ),
        )
        .await
        .expect("P's deletion");
        assert_eq!(sequenced, 1);
        assert_eq!(
            deletions(&p.seq_pool, p.cid).await,
            [
                (n, p.fixture.sender_did.clone()),
                (n + 1, p.fixture.recipient_did.clone())
            ]
        );
        let owed: Vec<(String, String)> = queue_rows(&p.seq_pool, p.cid)
            .await
            .into_iter()
            .filter(|row| row.1 == C33_HOME)
            .map(|row| (row.0, row.2))
            .collect();
        assert!(owed.is_empty(), "nothing is queued for D's home: {owed:?}");
        assert!(p.delivered().is_empty());
        assert_eq!(p.held().await, [p.seq]);
    })
    .await;
}

/// The coordinator's sends recorded for `cid`.
async fn sends(pool: &DbPool, cid: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1")
        .bind(cid)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Every coordinator-side effect a refused C33 send could otherwise leave.
async fn send_effects(pool: &DbPool, cid: Uuid) -> (Vec<i64>, i64, i64, i64) {
    sqlx::query_as(
        "SELECT \
           ARRAY(SELECT seq FROM chat.entries WHERE conversation_id=$1 ORDER BY seq), \
           (SELECT count(*) FROM chat.message_sends WHERE conversation_id=$1), \
           (SELECT count(*) FROM chat.relationship_projection_snapshots), \
           (SELECT count(*) FROM outbound_queue)",
    )
    .bind(cid)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// D's home relays D's send while the coordinator's relationship source cannot
/// answer. That decided nothing: the retryable 503 `RelationshipPolicyUnavailable`,
/// never the `InvalidProof` 400 D's home takes as final, and nothing is
/// sequenced. The identical relay is sequenced once the source answers.
#[tokio::test]
async fn a_relayed_send_whose_relationship_source_cannot_answer_is_retryable() {
    let p = RelayedPair::new().await;
    let fault = SimSourceFault::default();
    let runtime = Arc::new(
        ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
            .unwrap()
            .with_sim_faulty_relationships(Arc::clone(&fault))
            .unwrap()
            .with_i13_receipt_signer(I13ReceiptSigner::new(key(0x61), C33_SEQ.to_owned())),
    );
    scope_ds_clock(p.clock.clone(), async {
        let signed = p.sender_send();
        let before = sends(&p.seq_pool, p.cid).await;
        *fault.lock().unwrap() = Some(Err(TransportError::Network));
        let refused = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_handle_message(&p.seq_pool, &runtime, C33_HOME, p.cid, &signed),
        )
        .await;
        *fault.lock().unwrap() = None;
        let error = refused.expect_err("the source could not answer");
        assert!(
            matches!(
                error,
                crate::federation::FederationError::RelationshipPolicyUnavailable { .. }
            ),
            "{error:?}"
        );
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            sends(&p.seq_pool, p.cid).await,
            before,
            "nothing was sequenced"
        );

        let sequenced = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_handle_message(&p.seq_pool, &runtime, C33_HOME, p.cid, &signed),
        )
        .await
        .expect("the identical relay is sequenced");
        assert_eq!(sequenced["entry"]["seq"], p.seq + 1);
    })
    .await;
}

/// P's relayed send is committed with its delivery to D's home queued. A
/// replay whose redrive D's home refuses still answers the accepted send: the
/// queued delivery, not the replay, owes that home its entry.
#[tokio::test]
async fn a_replayed_send_answers_its_accepted_entry_whatever_its_redrive_meets() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let signed = p.peer_send();
        let sent = p
            .relay(&signed)
            .await
            .expect("P's relayed send is sequenced");
        assert_eq!(sent["entry"]["seq"], p.seq + 1);
        p.network.serve(
            C33_HOME,
            Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        let replay = p
            .relay(&signed)
            .await
            .expect("the replay answers the accepted send");
        assert_eq!(replay["entry"]["seq"], p.seq + 1);
    })
    .await;
}

/// P's relayed send owes D's home a queued delivery. With the coordinator's
/// queue to that home full the send decided nothing: the retryable 503 of an
/// S2S answer that could not be given now, and nothing is sequenced. The
/// identical relay is sequenced once the queue drains.
#[tokio::test]
async fn a_relayed_send_whose_delivery_queue_is_full_is_retryable() {
    let p = RelayedPair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        sqlx::query(
            "INSERT INTO outbound_queue \
                 (id, target_ds_did, target_endpoint, method, payload, convo_id) \
             SELECT 'queue-full-' || g, $1, $2, 'blue.catbird.mlsDS.deliverMessageEntry', \
                    '\\x00'::bytea, $3 \
               FROM generate_series(1, 500) g",
        )
        .bind(C33_HOME)
        .bind(format!("https://{}", host(C33_HOME)))
        .bind(p.cid.to_string())
        .execute(&p.seq_pool)
        .await
        .unwrap();
        let signed = p.peer_send();
        let before = sends(&p.seq_pool, p.cid).await;
        let error = p.relay(&signed).await.expect_err("the queue is full");
        assert_eq!(
            error.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{error:?}"
        );
        assert!(error.is_retryable());
        assert_eq!(
            sends(&p.seq_pool, p.cid).await,
            before,
            "nothing was sequenced"
        );

        sqlx::query("DELETE FROM outbound_queue WHERE id LIKE 'queue-full-%'")
            .execute(&p.seq_pool)
            .await
            .unwrap();
        let sent = p
            .relay(&signed)
            .await
            .expect("the identical relay is sequenced");
        assert_eq!(sent["entry"]["seq"], p.seq + 1);
    })
    .await;
}

/// D's own home holds the pair only as its transport-only home, with no leaf
/// authority for P's devices, so it cannot project the pair's state. D's
/// `getConversationState` there is the coordinator's answer for D's device,
/// P's deletion evidence included, relayed as a late-joined group member's is.
/// With the coordinator unreachable D gets the retryable 503 with a retry
/// hint, never the `ConversationNotFound` a closed pair answers.
#[tokio::test]
async fn a_c33_senders_transport_only_home_relays_its_state_read_to_the_coordinator() {
    const STATE: &str = "blue.catbird.chat.getConversationState";
    let p = RelayedPair::new().await;
    let (cid, f) = (p.cid, &p.fixture);
    // D's device at its home, the route that home recorded relaying D's
    // request to the coordinator, and the service-auth key D's DID publishes.
    let public = ed25519_dalek::SigningKey::from_bytes(&f.sender_ed25519_seed)
        .verifying_key()
        .to_bytes();
    let at = clock_now(&p.home_pool).await;
    seed_actor_at(&p.home_pool, &f.sender_did, f.sender_device_id, &public, at).await;
    sqlx::query(
        "INSERT INTO chat.direct_request_outbound_routes \
             (request_id, actor_did, actor_device_id, recipient_did, coordinator_did, created_at, answered_at) \
         SELECT request_id, sender_did, sender_device_id, recipient_did, coordinator_did, created_at, created_at \
           FROM chat.direct_request_transport_inbox WHERE conversation_id = $1",
    )
    .bind(cid)
    .execute(&p.home_pool)
    .await
    .unwrap();
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    p.network
        .documents
        .lock()
        .unwrap()
        .get_mut(host(&f.sender_did))
        .expect("D's DID document")["verificationMethod"] = json!([{
        "id": format!("{}#atproto", f.sender_did),
        "type": "JsonWebKey2020",
        "controller": f.sender_did,
        "publicKeyJwk": jwk,
    }]);
    let device = http::Device {
        did: f.sender_did.clone(),
        device_id: f.sender_device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing,
        jwk,
    };
    let (clock, hooks) = (p.clock.clone(), Arc::clone(&p.home_hooks));
    let home = http::router_for_authenticated_acceptance_with(p.home_pool.clone(), |runtime| {
        runtime.with_clock(clock).with_sim_hooks(hooks)
    })
    .await;
    let query = format!("actorDeviceId={}&conversationId={cid}", f.sender_device_id);
    let read = || {
        // The DS clock moves up to the wall clock the harness mints tokens on,
        // and each token names, as its audience, the DS the request reaches.
        let wall = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        p.clock.set_utc(wall.max(current_utc()));
        let (home, device, query) = (home.clone(), &device, &query);
        scope_sim_ds(Arc::clone(&p.home_hooks), async move {
            let response = tower_util::ServiceExt::oneshot(
                home,
                http::unsigned_get_request(device, STATE, query),
            )
            .await
            .unwrap();
            let retry_after = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .map(|value| value.to_str().unwrap().to_owned());
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, retry_after, body)
        })
    };
    scope_ds_clock(p.clock.clone(), async {
        let sequenced = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            delete_account_data_with_conversations(
                &p.seq_pool,
                &f.recipient_did,
                current_utc(),
                p.runtime.i13_receipt_signer(),
            ),
        )
        .await
        .expect("P's deletion");
        assert_eq!(sequenced, 1);

        let (status, _, relayed) = read().await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&relayed)
        );
        let own = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            crate::handlers::chat::execute_federated_conversation_state_read(
                &p.seq_pool,
                VerifiedServicePrincipal::for_federated_s2s(&f.sender_did, STATE),
                f.sender_device_id,
                cid,
            ),
        )
        .await
        .unwrap_or_else(axum::response::IntoResponse::into_response);
        assert_eq!(own.status(), StatusCode::OK);
        let own = axum::body::to_bytes(own.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            relayed, own,
            "D's home relays the coordinator's answer verbatim"
        );
        let state: Value = serde_json::from_slice(&relayed).unwrap();
        assert_eq!(state["state"]["sequencerDid"], C33_SEQ, "{state}");
        assert_eq!(
            state["accountDeletions"][0]["deletedDid"],
            f.recipient_did.as_str(),
            "{state}"
        );

        p.network.partition(true);
        let (status, retry_after, failed) = read().await;
        assert_eq!(
            (
                status,
                retry_after.as_deref(),
                serde_json::from_slice::<Value>(&failed).unwrap()
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
                json!({ "error": "RateLimited", "message": "RateLimited" })
            )
        );
    })
    .await;
}

/// [`Pair`] (D homed at the coordinator, P at the pair's transport-only home)
/// with both delivery services' production chat routers: P sends through its
/// home's `sendMessage`, which relays over the sim network to the coordinator,
/// and reads the coordinator's `getEntries`.
struct Routed {
    p: Pair,
    home_router: Router,
    seq_router: Router,
    /// The coordinator's runtime for a relayed send called directly.
    runtime: Arc<ChatRuntime>,
    /// What the coordinator's relationship source answers.
    relationships: SimSourceFault,
    /// P's device, whose service-auth key P's DID document publishes.
    device: http::Device,
}

impl Routed {
    async fn new() -> Self {
        let p = Pair::new().await;
        let relationships = SimSourceFault::default();
        let (clock, hooks, receipt, seq_relationships) = (
            p.clock.clone(),
            Arc::clone(&p.seq_hooks),
            p.receipt.clone(),
            Arc::clone(&relationships),
        );
        let seq_router =
            http::router_for_authenticated_acceptance_with(p.seq_pool.clone(), |runtime| {
                runtime
                    .with_sim_faulty_relationships(seq_relationships)
                    .unwrap()
                    .with_i13_receipt_signer(receipt)
                    .with_clock(clock)
                    .with_sim_hooks(hooks)
            })
            .await;
        let (clock, hooks) = (p.clock.clone(), Arc::clone(&p.home_hooks));
        let home_router =
            http::router_for_authenticated_acceptance_with(p.home_pool.clone(), |runtime| {
                runtime
                    .with_sim_allow_all_relationships()
                    .unwrap()
                    .with_clock(clock)
                    .with_sim_hooks(hooks)
            })
            .await;
        let runtime = Arc::new(
            ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
                .unwrap()
                .with_sim_faulty_relationships(Arc::clone(&relationships))
                .unwrap()
                .with_i13_receipt_signer(p.receipt.clone()),
        );
        // The coordinator executes a relayed send exactly as its
        // `relaySendMessage` route does once it has authenticated P's home.
        let (pool, hooks, relay_runtime) = (
            p.seq_pool.clone(),
            Arc::clone(&p.seq_hooks),
            Arc::clone(&runtime),
        );
        p.network.serve(
            C33_SEQ,
            Router::new().route(
                "/xrpc/blue.catbird.mlsDS.relaySendMessage",
                axum::routing::post(
                    move |Json(input): Json<
                        crate::federation::canonical_relay::RelaySendMessageInput,
                    >| {
                        let (pool, hooks, runtime) =
                            (pool.clone(), Arc::clone(&hooks), Arc::clone(&relay_runtime));
                        async move {
                            scope_sim_ds(
                                hooks,
                                coordinator_handle_message(
                                    &pool,
                                    &runtime,
                                    C33_HOME,
                                    input.conversation_id,
                                    &input.message,
                                ),
                            )
                            .await
                            .map(Json)
                        }
                    },
                ),
            ),
        );
        let signing = http::random_p256();
        let jwk = http::public_jwk(&signing);
        p.network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(p.peer()))
            .expect("P's DID document")["verificationMethod"] = json!([{
            "id": format!("{}#atproto", p.peer()),
            "type": "JsonWebKey2020",
            "controller": p.peer(),
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: p.peer().to_owned(),
            device_id: p.fixture.recipient_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            signing,
            jwk,
        };
        Self {
            p,
            home_router,
            seq_router,
            runtime,
            relationships,
            device,
        }
    }

    /// The DS clock moved up to the wall clock the harness mints tokens on.
    fn sync_clock(&self) {
        let wall = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        self.p.clock.set_utc(wall.max(current_utc()));
    }

    /// P's own signed application, signed now.
    fn peer_send(&self) -> Value {
        self.sync_clock();
        self.p.fixture.next_recipient_signed_request()
    }

    /// P sending `signed` through its home's real `sendMessage` route.
    async fn send(&self, signed: &Value) -> (StatusCode, Value) {
        self.sync_clock();
        let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
        scope_sim_ds(Arc::clone(&self.p.home_hooks), async {
            http::send(
                self.home_router.clone(),
                http::unsigned_json_request(&self.device, SEND_MESSAGE, body),
            )
            .await
        })
        .await
    }

    /// P's `signed` application relayed by its home to the coordinator, called
    /// directly, so the home never sees the coordinator's answer.
    async fn relay(&self, signed: &Value) -> Result<Value, crate::federation::FederationError> {
        let p = &self.p;
        scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_handle_message(&p.seq_pool, &self.runtime, C33_HOME, p.cid, signed),
        )
        .await
    }

    /// `seq` exactly as the coordinator's `getEntries` serves it to P's device.
    async fn served(&self, seq: i64) -> Value {
        self.sync_clock();
        let query = format!(
            "actorDeviceId={}&conversationId={}&afterSeq={}&limit=1",
            self.p.fixture.recipient_device_id,
            self.p.cid,
            seq - 1
        );
        let (status, page) = scope_sim_ds(Arc::clone(&self.p.seq_hooks), async {
            http::send(
                self.seq_router.clone(),
                http::unsigned_get_request(&self.device, "blue.catbird.chat.getEntries", &query),
            )
            .await
        })
        .await;
        assert_eq!(status, StatusCode::OK, "getEntries: {page}");
        assert_eq!(page["entries"][0]["seq"], seq, "{page}");
        page["entries"][0].clone()
    }

    /// The seqs P's home holds.
    async fn held(&self) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT seq FROM chat.direct_request_transport_entries \
              WHERE conversation_id = $1 ORDER BY seq",
        )
        .bind(self.p.cid)
        .fetch_all(&self.p.home_pool)
        .await
        .unwrap()
    }
}

/// P sends through its transport-only home while either party blocks the
/// other. The coordinator's declared `BlockedRelationship` reaches P unchanged
/// (never `NotAuthorized`), and neither delivery service writes anything.
#[tokio::test]
async fn a_transport_home_preserves_a_coordinators_blocked_send_refusal() {
    let r = Routed::new().await;
    let p = &r.p;
    scope_ds_clock(p.clock.clone(), async {
        let signed = r.peer_send();
        let before = (send_effects(&p.seq_pool, p.cid).await, r.held().await);
        let mut pair = [p.peer(), p.deleted()];
        pair.sort();
        *r.relationships.lock().unwrap() = Some(Ok(PublicResponse::json(
            200,
            json!({
                "actor": pair[0],
                "relationships": [{
                    "$type": "app.bsky.graph.defs#relationship",
                    "did": pair[1],
                    "blocking": format!("at://{}/app.bsky.graph.block/relay", pair[0]),
                }],
            }),
        )));

        let (status, body) = r.send(&signed).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("BlockedRelationship")),
            "{body}"
        );
        assert_eq!(
            (send_effects(&p.seq_pool, p.cid).await, r.held().await),
            before,
            "a blocked send writes nothing at either delivery service"
        );
    })
    .await;
}

/// D, homed at the coordinator, is deleted and its declaration is gone. P's
/// transport-only home still relays P's send, to the coordinator its inbox
/// recorded, and the coordinator sequences it without D's declaration. A later
/// send whose relayed answer never reached P's home, then pruned at the
/// coordinator, replays as its accepted outcome: the coordinator answers with
/// the pruned entry its `getEntries` serves, and P's home returns it to P
/// storing nothing, no ciphertext resent and no delivery redriven.
#[tokio::test]
async fn a_transport_home_relays_to_its_recorded_coordinator_and_replays_pruned_sends() {
    let r = Routed::new().await;
    let (p, cid, seq) = (&r.p, r.p.cid, r.p.seq);
    scope_ds_clock(p.clock.clone(), async {
        p.store(cid, &p.message).await;
        scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            delete_account_data_with_conversations(
                &p.seq_pool,
                p.deleted(),
                current_utc(),
                Some(&p.receipt),
            ),
        )
        .await
        .expect("D's deletion");
        let rows = control_rows(&p.seq_pool, cid).await;
        let deletion = serde_json::from_slice::<DeliverTransportControlEntry>(&rows[0].5)
            .unwrap()
            .entry;
        p.accept(C33_SEQ, &deletion)
            .await
            .expect("P's home applies D's deletion");
        p.network
            .serve(&format!("pds-{}", host(p.deleted())), Router::new());

        let (status, sent) = r.send(&r.peer_send()).await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        assert_eq!(sent["entry"]["seq"], seq + 2);
        assert_eq!(r.held().await, (1..=seq + 2).collect::<Vec<_>>());

        let lost = r.peer_send();
        let sequenced = r.relay(&lost).await.expect("P's next send is sequenced");
        assert_eq!(sequenced["entry"]["seq"], seq + 3);
        let mut tx = p.seq_pool.begin().await.unwrap();
        assert!(
            delivery::prune_application_entry_payload(&mut tx, cid, seq + 3, current_utc())
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        let served = r.served(seq + 3).await;
        assert_eq!(served["payloadPruned"], true, "{served}");
        assert!(served.get("signedRequest").is_none(), "{served}");
        let mut first = sequenced["entry"].clone();
        crate::chat_protocol::direct_request_transcript::present_read_presentation(
            "applicationEntry",
            &mut first,
        )
        .unwrap();
        for field in [
            "entryId",
            "conversationId",
            "seq",
            "receivedAt",
            "sequencerReceipt",
        ] {
            assert_eq!(served[field], first[field], "{field}");
        }

        let replayed = r.relay(&lost).await.expect("the pruned replay is accepted");
        assert_eq!(
            replayed,
            json!({ "entry": served, "sequencerReceipt": served["sequencerReceipt"] })
        );
        let (status, reply) = r.send(&lost).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        let mut entry = served.clone();
        entry.as_object_mut().unwrap().remove("$type");
        assert_eq!(
            reply,
            json!({ "entry": entry, "sequencerReceipt": served["sequencerReceipt"] })
        );
        assert_eq!(r.held().await, (1..=seq + 2).collect::<Vec<_>>());
    })
    .await;
}

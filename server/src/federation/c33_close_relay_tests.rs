//! A C33 coordinator's `closeConversation` reaches the pair's transport-only
//! home on real PostgreSQL. After its own wipe the coordinator queues the exact
//! signed close for the peer's declared home as `deliverGroupEntry`, retried
//! until delivered; only a declared `ConversationNotFound` is final. The home
//! verifies it before any effect, then holds no transport row and no opening or
//! application ciphertext of the pair, only that entry, which the close's
//! frozen audience still reads through `getEntries`.

use super::*;
use crate::{
    chat_protocol::{
        repository::{
            delivery, direct_request_opening::DIRECT_REQUEST_ENTRY_KIND,
            direct_request_opening_tests::residue,
        },
        test_support::sign_mutation_json_for_test,
    },
    common::{fresh_db::DisposableDatabase, http_acceptance as http},
    federation::resolver::build_resolver_http_client,
    sim_hooks::QueuedTaskSpawner,
};

// Delivery services of their own, so their DID documents' keys are this file's.
const SEQ_DS: &str = "did:web:c33-close-coordinator.example.com";
const HOME_DS: &str = "did:web:c33-close-home.example.com";
const OTHER_DS: &str = "did:web:c33-close-other.example.com";
const DELIVER: &str = "blue.catbird.mlsDS.deliverGroupEntry";
const OPENING: &[u8] = b"the pair's opening ciphertext held at the peer's home";

/// One party of the pair, with its device's signing seed.
struct Party {
    did: String,
    device: Uuid,
    key_id: String,
    seed: [u8; 32],
}

impl Party {
    fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.seed)
    }

    /// This party's signed close of `prior`, as its client signs it: its
    /// idempotency key is its transition id.
    fn close(&self, prior: &Value) -> Value {
        let transition = Uuid::new_v4();
        self.signed_close(prior, transition, transition)
    }

    /// This party's signed close of `prior` with the given ids.
    fn signed_close(&self, prior: &Value, transition: Uuid, idempotency_key: Uuid) -> Value {
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
        retired["lifecycle"] = json!("superseded");
        sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#conversationCloseBody",
                "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0}",
                "transitionId": transition,
                "idempotencyKey": idempotency_key,
                "actorDid": self.did,
                "actorDeviceId": self.device,
                "keyId": self.key_id,
                "authGeneration": 1,
                "conversationKind": "direct",
                "prior": prior,
                "retired": retired,
                "signedAt": canonical(current_utc()),
            }),
            &self.signing_key(),
        )
        .unwrap()
    }
}

/// Publish `user`'s one `blue.catbird.chat.device` record on its PDS.
fn publish_device(network: &Network, user: &str, public_key: &[u8]) {
    let pds = format!("pds-{}", host(user));
    let records = json!({ "records": [{
        "uri": format!("at://{user}/blue.catbird.chat.device/self"),
        "value": {
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(public_key) },
            "algorithm": "ed25519",
            "createdAt": "2026-07-16T00:00:00Z",
        },
    }]});
    let mut routers = network.routers.lock().unwrap();
    let pds_router = routers.remove(&pds).expect("a declared user's PDS").route(
        "/xrpc/com.atproto.repo.listRecords",
        axum::routing::get(move || {
            let records = records.clone();
            async move { Json(records) }
        }),
    );
    routers.insert(pds, pds_router);
}

async fn databases() -> ([DisposableDatabase; 2], DbPool, DbPool) {
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    for (pool, peers) in [
        (&seq_pool, [HOME_DS, OTHER_DS]),
        (&home_pool, [SEQ_DS, OTHER_DS]),
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
    ([seq_db, home_db], seq_pool, home_pool)
}

/// A direct pair `SEQ_DS` coordinates: `actor` is homed there, its `peer` at
/// `HOME_DS`, the pair's transport-only home. Requests reach the coordinator
/// through its production chat router; its post-commit work waits in `spawner`.
struct Closing {
    _dbs: [DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    network: Network,
    clock: Arc<ManualDsClock>,
    seq_hooks: Arc<SimDsHooks>,
    home_hooks: Arc<SimDsHooks>,
    seq_key: SigningKey,
    home: GroupRelayState,
    router: Router,
    spawner: Arc<QueuedTaskSpawner>,
    queue: OutboundQueue,
    cid: Uuid,
    actor: Party,
    peer: Party,
    prior: Value,
}

impl Closing {
    async fn new(
        dbs: [DisposableDatabase; 2],
        seq_pool: DbPool,
        home_pool: DbPool,
        cid: Uuid,
        actor: Party,
        peer: Party,
        prior: Value,
    ) -> Self {
        crate::federation::open_federation_for_test();
        let (seq_key, home_key, other_key) = (key(0x71), key(0x72), key(0x73));
        let network = Network::new(&[
            (SEQ_DS, &seq_key),
            (HOME_DS, &home_key),
            (OTHER_DS, &other_key),
        ]);
        for ds in [SEQ_DS, HOME_DS, OTHER_DS] {
            network.declare_delivery_service(ds);
        }
        network.declare_user(&actor.did, SEQ_DS);
        network.declare_user(&peer.did, HOME_DS);
        publish_device(
            &network,
            &actor.did,
            &actor.signing_key().verifying_key().to_bytes(),
        );
        let clock = manual_clock();
        let seq_hooks = hooks(SEQ_DS, Some(&seq_key), false, &network);
        // The home also admits this file's HMAC-authenticated direct deliveries.
        let home_hooks = hooks(HOME_DS, Some(&home_key), true, &network);
        let state = |did: &str, pool: &DbPool, hooks: &Arc<SimDsHooks>| {
            GroupRelayState::for_test(pool.clone(), did.to_owned(), HMAC.as_bytes(), None)
                .with_sim_hooks(Arc::clone(hooks))
                .with_clock(clock.clone())
        };
        let home = state(HOME_DS, &home_pool, &home_hooks);
        network.serve(
            SEQ_DS,
            group_relay_router(state(SEQ_DS, &seq_pool, &seq_hooks)),
        );
        network.serve(HOME_DS, group_relay_router(home.clone()));
        // The peer's device is registered at its own home.
        seed_actor_at(
            &home_pool,
            &peer.did,
            peer.device,
            &peer.signing_key().verifying_key().to_bytes(),
            clock_now(&home_pool).await,
        )
        .await;
        let spawner = Arc::new(QueuedTaskSpawner::new());
        let router = {
            let (spawner, hooks, clock) = (
                Arc::clone(&spawner),
                Arc::clone(&seq_hooks),
                Arc::clone(&clock),
            );
            http::router_for_authenticated_acceptance_with(seq_pool.clone(), move |runtime| {
                runtime
                    .with_spawner(spawner)
                    .with_sim_hooks(hooks)
                    .with_clock(clock)
            })
            .await
        };
        let queue = OutboundQueue::new(
            seq_pool.clone(),
            AuthMiddleware::new(),
            Arc::new(DsResolver::new(
                seq_pool.clone(),
                build_resolver_http_client(),
                SEQ_DS.to_owned(),
                format!("https://{}", host(SEQ_DS)),
                None,
                300,
            )),
        );
        Self {
            _dbs: dbs,
            seq_pool,
            home_pool,
            network,
            clock,
            seq_hooks,
            home_hooks,
            seq_key,
            home,
            router,
            spawner,
            queue,
            cid,
            actor,
            peer,
            prior,
        }
    }

    /// `party`'s `signed` close, through the coordinator's router.
    async fn close_as(&self, party: &Party, signed: Value) -> (StatusCode, Value) {
        let (status, _, body) = self.close_answer(party, signed).await;
        (status, body)
    }

    /// `party`'s `signed` close, through the coordinator's router: its status,
    /// `Retry-After` hint and body.
    async fn close_answer(
        &self,
        party: &Party,
        signed: Value,
    ) -> (StatusCode, Option<String>, Value) {
        use tower_util::ServiceExt as _;
        // The harness mints the client's service-auth token on the wall clock.
        let wall = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        self.clock.set_utc(wall.max(current_utc()));
        // One service-auth key per party, however often it closes.
        let signing = p256::ecdsa::SigningKey::from_slice(&Sha256::digest(party.seed)).unwrap();
        let jwk = http::public_jwk(&signing);
        // The party's DID document, which also names its PDS for the home's
        // resolver, carries the key its service-auth JWT verifies with.
        self.network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(&party.did))
            .expect("a declared party's DID document")["verificationMethod"] = json!([{
            "id": format!("{}#atproto", party.did),
            "type": "JsonWebKey2020",
            "controller": party.did,
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: party.did.clone(),
            device_id: party.device,
            jkt: http::jwk_thumbprint(&jwk),
            jwk,
            signing,
        };
        let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
        scope_sim_ds(Arc::clone(&self.seq_hooks), async {
            let request =
                http::unsigned_json_request(&device, "blue.catbird.chat.closeConversation", body);
            let response = self.router.clone().oneshot(request).await.unwrap();
            let retry_after = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .map(|value| value.to_str().unwrap().to_owned());
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                retry_after,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        })
        .await
    }

    /// The coordinator's one queued delivery of `cid`'s close, to the peer's home.
    async fn queued_close(&self, cid: Uuid) -> DeliverGroupEntryRequest {
        let rows = queue_rows(&self.seq_pool, cid).await;
        let queued: Vec<_> = rows
            .iter()
            .map(|row| (row.0.as_str(), row.1.as_str(), row.2.as_str(), row.3))
            .collect();
        assert!(
            matches!(queued.as_slice(), [(id, HOME_DS, "pending", 0)]
                if id.starts_with(&format!("group-entry-{cid}-"))),
            "one queued close for the peer's home: {queued:?}"
        );
        let request: DeliverGroupEntryRequest = serde_json::from_slice(&rows[0].5).unwrap();
        assert_eq!(request.conversation_id, cid);
        assert_eq!(
            request.entry["signedRequest"]["body"]["conversationKind"],
            "direct"
        );
        request
    }

    /// The home's handling of `request` from `caller`.
    async fn deliver(
        &self,
        caller: &str,
        request: &DeliverGroupEntryRequest,
    ) -> (StatusCode, Value) {
        let body = serde_json::to_vec(request).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(S2S_CALLER_DID_HEADER, caller.parse().unwrap());
        headers.insert(S2S_TARGET_DID_HEADER, HOME_DS.parse().unwrap());
        headers.insert(
            S2S_MAC_HEADER,
            compute_s2s_mac(HMAC.as_bytes(), caller, HOME_DS, DELIVER, &body)
                .parse()
                .unwrap(),
        );
        // Boxed here and below, like the production close futures: inline, each
        // would size the test body's frame past the 2 MiB debug test stack.
        let response = scope_sim_ds(
            Arc::clone(&self.home_hooks),
            Box::pin(handle_deliver_group_entry(
                State(self.home.clone()),
                headers,
                Bytes::from(body),
            )),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    /// Every effect a close delivery may have at the home.
    async fn effects(&self) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT ARRAY[ \
                (SELECT count(*) FROM chat.events), \
                (SELECT count(*) FROM chat.event_recipients), \
                (SELECT count(*) FROM chat.conversation_close_terminal_entries), \
                (SELECT count(*) FROM chat.direct_request_transport_inbox WHERE conversation_id = $1), \
                (SELECT count(*) FROM chat.direct_request_transport_entries WHERE conversation_id = $1), \
                (SELECT count(*) FROM outbound_queue) \
             ]::bigint[]",
        )
        .bind(self.cid)
        .fetch_one(&self.home_pool)
        .await
        .unwrap()
    }

    async fn assert_refused(
        &self,
        caller: &str,
        request: &DeliverGroupEntryRequest,
        (status, code): (StatusCode, &str),
    ) {
        let before = self.effects().await;
        let (actual, body) = self.deliver(caller, request).await;
        assert_eq!(
            (actual, body["error"].as_str()),
            (status, Some(code)),
            "{caller}: {body}"
        );
        assert_eq!(self.effects().await, before, "{caller}");
    }

    /// The peer's `getEntries` page, read through its real admission at its home.
    async fn peer_entries(&self) -> Vec<Value> {
        let trusted = clock_now(&self.home_pool)
            .await
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let authority = Box::pin(
            crate::chat_protocol::repository::auth::authorize_unsigned_request(
                &self.home_pool,
                crate::chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
                    Uuid::new_v4(),
                    proof_jti,
                    "blue.catbird.chat.getEntries",
                    &trusted,
                    &self.peer.did,
                    self.peer.device,
                    &self.peer.key_id,
                ),
            ),
        )
        .await
        .expect("the peer's device reads at its home");
        let admission = crate::chat_protocol::dpop::seal_read_admission(authority).unwrap();
        let page = Box::pin(
            crate::chat_protocol::repository::entry_read::get_entries_for_admission(
                &self.home_pool,
                admission,
                self.cid,
                0,
                100,
            ),
        )
        .await
        .expect("the peer's getEntries");
        let page: Value = serde_json::from_slice(&page.into_response_bytes()).unwrap();
        page["entries"].as_array().unwrap().clone()
    }

    /// Store `entry` at the home exactly as its single transport writer does.
    async fn store(&self, entry: &Value) {
        let mut tx = self.home_pool.begin().await.unwrap();
        let stored = delivery::insert_transport_entry(
            &mut tx,
            self.cid,
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

    /// The home's copies of the pair's opening: the inbox row, in `status`, and
    /// the opening's transport entry.
    async fn hold_opening(&self, sender: &Party, recipient: &Party, status: &str) {
        let request = Uuid::new_v4();
        let entry = json!({
            "$type": DIRECT_REQUEST_ENTRY_KIND,
            "entryId": Uuid::new_v4(),
            "conversationId": self.cid,
            "seq": 1,
            "receivedAt": canonical(current_utc()),
            "signedRequest": {
                "body": {
                    "$type": "blue.catbird.chat.defs#directRequestPublicationBody",
                    "signatureDomain": "CATBIRD-DIRECT-REQUEST-PUBLISH\u{0}",
                    "requestId": request,
                    "conversationId": self.cid,
                    "artifacts": {
                        "initialCiphertext": STANDARD.encode(OPENING),
                        "welcome": {"opaqueWelcome": STANDARD.encode(b"welcome")}
                    }
                },
                "signature": STANDARD.encode([7_u8; 64])
            },
            "sequencerReceipt": {"seq": 1, "signature": STANDARD.encode([8_u8; 64])},
            "publicationReceipt": {
                "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
                "body": {"receipt": {"requestId": request}},
                "signature": STANDARD.encode([9_u8; 64])
            }
        });
        self.hold(request, &entry, sender, recipient, status).await;
    }

    /// The home's inbox row for `request`, in `status`, and its opening `entry`,
    /// exactly as its transport writer stores them.
    async fn hold(
        &self,
        request: Uuid,
        entry: &Value,
        sender: &Party,
        recipient: &Party,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id, \
                 coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry, \
                 signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt, \
                 import_until,status) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$10,$10,$13,$14)",
        )
        .bind(request)
        .bind(self.cid)
        .bind(entry["entryId"].as_str().unwrap().parse::<Uuid>().unwrap())
        .bind(SEQ_DS)
        .bind(&sender.did)
        .bind(sender.device)
        .bind(&recipient.did)
        .bind(recipient.device)
        .bind(serde_json::to_vec(entry).unwrap())
        .bind(serde_json::to_vec(&entry["signedRequest"]).unwrap())
        .bind(b"welcome".as_slice())
        .bind(Sha256::digest(b"welcome").as_slice())
        .bind(current_utc() + chrono::Duration::days(7))
        .bind(status)
        .execute(&self.home_pool)
        .await
        .unwrap();
        self.store(entry).await;
    }

    /// One production queue-worker pass at the coordinator once its next retry is due.
    async fn drain_queue(&self) {
        self.clock
            .set_utc(latest_due(&self.seq_pool).await.max(current_utc()));
        Box::pin(drain(&self.queue, &self.seq_hooks, SEQ_DS, &self.seq_key)).await;
    }

    /// D's `signed` application, relayed by D's home and sequenced here.
    async fn relay_application(&self, signed: &Value) -> Value {
        let runtime = Arc::new(
            crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(
                8,
            )))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(
                crate::federation::receipt::I13ReceiptSigner::new(
                    self.seq_key.clone(),
                    SEQ_DS.to_owned(),
                ),
            ),
        );
        scope_sim_ds(
            Arc::clone(&self.seq_hooks),
            Box::pin(
                crate::federation::canonical_relay::coordinator_handle_message(
                    &self.seq_pool,
                    &runtime,
                    HOME_DS,
                    self.cid,
                    signed,
                ),
            ),
        )
        .await
        .expect("coordinate D's application")
    }

    /// Neither home holds a transport row of the pair or any of `needles`, and
    /// the peer's device reads exactly the retained signed `close`.
    async fn assert_closed(&self, close: &Value, needles: &[&[u8]]) {
        let held: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM chat.direct_request_transport_inbox WHERE conversation_id = $1), \
                    (SELECT count(*) FROM chat.direct_request_transport_entries WHERE conversation_id = $1)",
        )
        .bind(self.cid)
        .fetch_one(&self.home_pool)
        .await
        .unwrap();
        assert_eq!(held, (0, 0), "the home's transport rows are wiped");
        for needle in needles {
            for pool in [&self.seq_pool, &self.home_pool] {
                assert_eq!(residue(pool, needle).await, Vec::<String>::new());
            }
        }
        let mut expected = close.clone();
        if expected.get("$type").is_none() {
            expected["$type"] = json!("blue.catbird.chat.defs#conversationCloseEntry");
        }
        assert_eq!(self.peer_entries().await, [expected]);
    }

    /// The actor's close of `prior`, then everything the peer's transport-only
    /// home must and must not do with it. The close is queued for that home
    /// after the coordinator's own wipe and retried through a partition and an
    /// undeclared 404 until it lands. The home refuses another caller's or a
    /// re-signed copy before any effect, then holds none of `needles`, only the
    /// signed close the peer's device reads; its replay changes nothing and a
    /// different close is refused.
    async fn close_and_relay(&self, needles: &[&[u8]]) {
        let (status, body) = self
            .close_as(&self.actor, self.actor.close(&self.prior))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let request = self.queued_close(self.cid).await;
        assert_eq!(
            request.recipient_devices,
            [(self.peer.did.clone(), self.peer.device)]
        );

        // Only the pair's coordinator, carrying the actor's exact signature.
        self.assert_refused(OTHER_DS, &request, (StatusCode::FORBIDDEN, "NotAuthorized"))
            .await;
        // The retained entry carries its signature as a lexicon `$bytes` object.
        let mut forged = request.clone();
        let signature = &mut forged.entry["signedRequest"]["signature"]["$bytes"];
        let mut bytes = STANDARD.decode(signature.as_str().unwrap()).unwrap();
        bytes[0] ^= 1;
        *signature = json!(STANDARD.encode(bytes));
        self.assert_refused(
            SEQ_DS,
            &forged,
            (StatusCode::UNAUTHORIZED, "InvalidSignature"),
        )
        .await;

        // The post-commit send meets a partition, the worker an undeclared 404:
        // both are retried, and the close lands once the home answers.
        self.network.partition(true);
        self.spawner.drain_all().await;
        assert_eq!(
            relay_status(&self.seq_pool, self.cid).await,
            ("pending".to_owned(), 1)
        );
        self.network.partition(false);
        self.network.serve(HOME_DS, Router::new());
        self.drain_queue().await;
        assert_eq!(
            relay_status(&self.seq_pool, self.cid).await,
            ("pending".to_owned(), 2)
        );
        self.network
            .serve(HOME_DS, group_relay_router(self.home.clone()));
        self.drain_queue().await;
        assert!(
            queue_rows(&self.seq_pool, self.cid).await.is_empty(),
            "delivered"
        );
        self.assert_closed(&request.entry, needles).await;

        // A redelivery changes nothing; another close is not the retained one.
        let settled = self.effects().await;
        assert_eq!(
            self.deliver(SEQ_DS, &request).await,
            (StatusCode::OK, json!({ "accepted": true }))
        );
        assert_eq!(self.effects().await, settled);
        let mut other = request.clone();
        other.entry["entryId"] = json!(Uuid::new_v4());
        other.entry["signedRequest"] = self.actor.close(&self.prior);
        self.assert_refused(SEQ_DS, &other, (StatusCode::FORBIDDEN, "NotAuthorized"))
            .await;
    }
}

/// P, homed at the coordinator, closes the accepted pair. Its close is queued
/// for D's home after the coordinator's own wipe and retried through a
/// partition and an undeclared 404 until it lands. D's home refuses another
/// caller's or a re-signed copy before any effect, then holds only the signed
/// close D's device reads; its replay changes nothing.
#[tokio::test]
async fn a_c33_close_wipes_the_accepted_pairs_transport_only_home() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("catbird_server=warn")
        .try_init();
    let (dbs, seq_pool, home_pool) = databases().await;
    // The coordinator records no home for the remote sender D.
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        true,
        SEQ_DS,
        Some([0x6d; 32]),
        None,
    )
    .await
    .unwrap();
    let actor = Party {
        did: fixture.recipient_did.clone(),
        device: fixture.recipient_device_id,
        key_id: fixture.recipient_key_id.clone(),
        seed: fixture.recipient_ed25519_seed,
    };
    let peer = Party {
        did: fixture.sender_did.clone(),
        device: fixture.sender_device_id,
        key_id: fixture.sender_key_id.clone(),
        seed: fixture.sender_ed25519_seed,
    };
    let prior = fixture.signed_request["body"]["prior"].clone();
    let c = Closing::new(
        dbs,
        seq_pool,
        home_pool,
        fixture.conversation_id,
        actor,
        peer,
        prior,
    )
    .await;
    let application = STANDARD
        .decode(
            fixture.signed_request["body"]["applicationMessage"]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    scope_ds_clock(
        c.clock.clone(),
        Box::pin(async {
            // D's home holds the pair's opening and, as D's relay, the entry the
            // coordinator sequences for D's signed application.
            c.hold_opening(&c.peer, &c.actor, "accepted").await;
            let sequenced = c.relay_application(&fixture.signed_request).await;
            c.store(&sequenced["entry"]).await;
            assert!(!residue(&c.home_pool, OPENING).await.is_empty());
            for pool in [&c.seq_pool, &c.home_pool] {
                assert!(!residue(pool, &application).await.is_empty());
            }
            c.close_and_relay(&[OPENING, &application]).await;
        }),
    )
    .await;
}

/// S, homed at the coordinator, closes its genuinely published request before
/// R, homed at the pair's transport-only home, decides. That home held the
/// pending opening exactly as published; the close leaves its ciphertext on
/// neither home, as for an accepted pair.
#[tokio::test]
async fn a_c33_close_wipes_the_pending_requests_transport_only_home() {
    let (dbs, seq_pool, home_pool) = databases().await;
    let did = |role: &str| {
        format!(
            "did:web:c33-pending-{role}-{}.example.com",
            Uuid::new_v4().simple()
        )
    };
    let request = crate::chat_protocol::test_support::seed_genuine_pending_direct_request_for_pair(
        &seq_pool,
        &did("sender"),
        &did("recipient"),
    )
    .await
    .unwrap();
    let party = |(did, device, key_id, seed): (String, Uuid, String, [u8; 32])| Party {
        did,
        device,
        key_id,
        seed,
    };
    let (entry, opening): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT request_entry, initial_ciphertext FROM chat.direct_request_publications \
          WHERE request_id = $1",
    )
    .bind(request.request_id)
    .fetch_one(&seq_pool)
    .await
    .unwrap();
    let entry: Value = serde_json::from_slice(&entry).unwrap();
    let c = Closing::new(
        dbs,
        seq_pool,
        home_pool,
        request.conversation_id,
        party(request.sender_identity()),
        party(request.recipient_identity()),
        request.coordinate().clone(),
    )
    .await;
    scope_ds_clock(
        c.clock.clone(),
        Box::pin(async {
            c.hold(request.request_id, &entry, &c.actor, &c.peer, "pending")
                .await;
            for pool in [&c.seq_pool, &c.home_pool] {
                assert!(!residue(pool, &opening).await.is_empty());
            }
            // A close whose idempotency key is not its transition id is refused
            // before any effect; the conforming close below still lands.
            let mismatched = c
                .actor
                .signed_close(&c.prior, Uuid::new_v4(), Uuid::new_v4());
            let (status, body) = c.close_as(&c.actor, mismatched).await;
            assert_eq!(
                (status, body["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("InvalidRequest")),
                "{body}"
            );
            let lifecycle: String = sqlx::query_scalar(
                "SELECT lifecycle FROM chat.conversations WHERE conversation_id = $1",
            )
            .bind(c.cid)
            .fetch_one(&c.seq_pool)
            .await
            .unwrap();
            assert_eq!(lifecycle, "active");
            c.close_and_relay(&[&opening]).await;
        }),
    )
    .await;
}

/// What a close changes at the coordinator: the pair's lifecycle, its entries
/// and its queued deliveries.
async fn coordinator_state(pool: &DbPool, cid: Uuid) -> (String, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT lifecycle FROM chat.conversations WHERE conversation_id = $1), \
                (SELECT count(*) FROM chat.entries WHERE conversation_id = $1), \
                (SELECT count(*) FROM outbound_queue WHERE convo_id = $2)",
    )
    .bind(cid)
    .bind(cid.to_string())
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The coordinator cannot resolve the C33 peer's home before the close's
/// transaction. The peer's PDS unreachable decided nothing: 503
/// `CapacityUnavailable` with `Retry-After`. This DS's own peer-policy store
/// failing while resolving it decided nothing either: 500, no retry hint.
/// Neither commits anything, and the identical signed close then lands, queued
/// for the peer's home.
#[tokio::test]
async fn a_close_whose_peer_home_cannot_be_resolved_now_commits_nothing() {
    let (dbs, seq_pool, home_pool) = databases().await;
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        true,
        SEQ_DS,
        Some([0x6e; 32]),
        None,
    )
    .await
    .unwrap();
    let actor = Party {
        did: fixture.recipient_did.clone(),
        device: fixture.recipient_device_id,
        key_id: fixture.recipient_key_id.clone(),
        seed: fixture.recipient_ed25519_seed,
    };
    let peer = Party {
        did: fixture.sender_did.clone(),
        device: fixture.sender_device_id,
        key_id: fixture.sender_key_id.clone(),
        seed: fixture.sender_ed25519_seed,
    };
    let prior = fixture.signed_request["body"]["prior"].clone();
    let c = Closing::new(
        dbs,
        seq_pool,
        home_pool,
        fixture.conversation_id,
        actor,
        peer,
        prior,
    )
    .await;
    scope_ds_clock(
        c.clock.clone(),
        Box::pin(async {
            let close = c.actor.close(&c.prior);
            let before = coordinator_state(&c.seq_pool, c.cid).await;
            assert_eq!(before.0, "active");

            c.network.partition(true);
            let (status, retry_after, body) = c.close_answer(&c.actor, close.clone()).await;
            c.network.partition(false);
            assert_eq!(
                (status, retry_after.as_deref(), body["error"].as_str()),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some("5"),
                    Some("CapacityUnavailable")
                ),
                "{body}"
            );
            assert_eq!(coordinator_state(&c.seq_pool, c.cid).await, before);

            let rename = |from: &str, to: &str| {
                format!("ALTER TABLE federation_peers{from} RENAME TO federation_peers{to}")
            };
            sqlx::query(&rename("", "_offline"))
                .execute(&c.seq_pool)
                .await
                .unwrap();
            let (status, retry_after, body) = c.close_answer(&c.actor, close.clone()).await;
            sqlx::query(&rename("_offline", ""))
                .execute(&c.seq_pool)
                .await
                .unwrap();
            assert_eq!(
                (status, retry_after.as_deref(), body["error"].as_str()),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    Some("InternalServerError")
                ),
                "{body}"
            );
            assert_eq!(coordinator_state(&c.seq_pool, c.cid).await, before);

            let (status, body) = c.close_as(&c.actor, close).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            c.queued_close(c.cid).await;
        }),
    )
    .await;
}

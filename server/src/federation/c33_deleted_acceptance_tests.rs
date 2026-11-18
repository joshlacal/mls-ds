//! A pending C33 request ends once either party's `accountDeletedEntry` is in
//! its conversation. P's genuinely signed v2 acceptance is refused
//! `InvitationNotPending` (final for the client) at the coordinator, through
//! its real `acceptConversation` route and the relayed path, and at P's
//! transport-only home once that home holds the coordinator's deletion entry.
//! Without the refusal the acceptance landed after the deletion, and the
//! coordinator delivered the deletion to the deleted party's home as the
//! "acceptance" it read at seq 2. An acceptance that completed before a later
//! deletion stays a duplicate: its exact replay returns the stored outcome.

use super::*;
use crate::{
    chat_protocol::{
        direct_request_transcript::{direct_request_signing_bytes, DirectRequestKind},
        relationship_policy::{PublicResponse, SimSourceFault, TransportError},
        repository::direct_request_receipts::DirectRequestReceiptSigner,
        test_support::{
            seed_clean_slate_pending_direct_request_fixture, CleanSlatePendingDirectRequestFixture,
        },
    },
    common::http_acceptance as http,
    federation::canonical_relay::{
        coordinator_accept_direct_request, ingest_remote_acceptance_entry,
        DeliverAcceptanceEntryInput, DeliverAcceptanceInput,
    },
    handlers::chat::ChatRuntime,
};
use ed25519_dalek::Signer as _;
use sha2::Digest as _;

const ACCEPT_CONVERSATION: &str = "blue.catbird.chat.acceptConversation";

/// A request receipt authority's keys, as its runtime and the fixture take them.
struct ReceiptKeys {
    receipt: String,
    service: String,
    document: String,
}

impl ReceiptKeys {
    fn new(authority: &str, seed: u8) -> Self {
        let receipt = key(seed);
        let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
            authority,
            receipt.verifying_key(),
        );
        Self {
            receipt: pem(&receipt),
            service: pem(&key(seed + 1)),
            document: serde_json::to_string(&document).unwrap(),
        }
    }

    fn signer(&self) -> DirectRequestReceiptSigner {
        DirectRequestReceiptSigner::configured(&self.receipt, &self.service, &self.document)
            .unwrap()
    }
}

/// `pool`'s chat runtime, built with cutover enabled and `customize`d, its
/// request receipt authority validated as at startup, and the router serving it.
async fn validated_router(
    pool: &DbPool,
    keys: &ReceiptKeys,
    customize: impl FnOnce(ChatRuntime) -> ChatRuntime,
) -> (Arc<ChatRuntime>, Router) {
    // The harness scopes the cutover environment to runtime construction.
    let mut built = None;
    let _ = http::router_for_authenticated_acceptance_with(pool.clone(), |runtime| {
        built = Some(ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8))).unwrap());
        runtime
    })
    .await;
    let runtime = customize(built.unwrap())
        .with_request_receipt_keys(&keys.receipt, &keys.service, &keys.document)
        .unwrap();
    runtime.validate_protocol_fence(pool).await.unwrap();
    let runtime = Arc::new(runtime);
    let router =
        crate::handlers::chat::chat_router::<http::TestState>().with_state(http::TestState {
            pool: pool.clone(),
            runtime: Arc::clone(&runtime),
        });
    (runtime, router)
}

/// How the coordinator's `deliverAcceptance` route answers a relayed acceptance.
#[derive(Clone, Copy, PartialEq)]
enum CoordinatorAnswers {
    /// As its real route does.
    Accepts,
    /// 503: its federation gate is closed, before it reads the acceptance.
    GateClosed,
    /// As its real route does, after which its DID document (and with it the
    /// receipt key the home verifies the outcome with) cannot be fetched.
    ThenUnresolvable,
}

/// D's pending request to P, coordinated by C33_SEQ. `requester_home` homes D
/// and the other DS homes P; C33_HOME holds the pair's transport inbox. Both
/// DSes serve their real group relay routes through the sim network.
struct PendingPair {
    _dbs: [DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    fixture: CleanSlatePendingDirectRequestFixture,
    network: Network,
    clock: Arc<ManualDsClock>,
    seq_hooks: Arc<SimDsHooks>,
    home_hooks: Arc<SimDsHooks>,
    seq_key: SigningKey,
    home_key: SigningKey,
    /// The coordinator's `#mls-receipt-1` signer.
    receipt: I13ReceiptSigner,
    seq_runtime: Arc<ChatRuntime>,
    /// What the coordinator's relationship sources answer while a test sets it.
    relationships: SimSourceFault,
    coordinator_answers: Arc<Mutex<CoordinatorAnswers>>,
    seq_router: Router,
    home_router: Router,
    /// P's service-auth key.
    device: http::Device,
}

impl PendingPair {
    async fn new(requester_home: &str) -> Self {
        Self::new_with_i13(requester_home, true).await
    }

    async fn new_with_i13(requester_home: &str, issue_i13: bool) -> Self {
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
        let run = Uuid::new_v4().simple();
        let requester = format!("did:web:requester-{run}.example.com");
        let recipient = format!("did:web:recipient-{run}.example.com");
        let recipient_home = if requester_home == C33_SEQ {
            C33_HOME
        } else {
            C33_SEQ
        };
        let (seq_key, home_key) = (key(0x71), key(0x72));
        let network = Network::new(&[(C33_SEQ, &seq_key), (C33_HOME, &home_key)]);
        for ds in [C33_SEQ, C33_HOME] {
            network.declare_delivery_service(ds);
        }
        network.declare_user(&requester, requester_home);
        network.declare_user(&recipient, recipient_home);
        network.publish_receipt_key(C33_SEQ, &key(0x73));
        let receipt = I13ReceiptSigner::new(key(0x73), C33_SEQ.to_owned());
        let clock = manual_clock();
        let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
        let home_hooks = hooks(C33_HOME, Some(&home_key), false, &network);
        let seq_keys = ReceiptKeys::new(C33_SEQ, 0x74);
        let fixture = seed_clean_slate_pending_direct_request_fixture(
            &seq_pool,
            &seq_keys.signer(),
            &requester,
            &recipient,
        )
        .await
        .unwrap();
        let relationships = SimSourceFault::default();
        let runtime_receipt = receipt.clone();
        let (seq_runtime, seq_router) = validated_router(&seq_pool, &seq_keys, |runtime| {
            let runtime = runtime
                .with_sim_faulty_relationships(relationships.clone())
                .unwrap()
                .with_clock(clock.clone())
                .with_sim_hooks(Arc::clone(&seq_hooks));
            if issue_i13 {
                runtime.with_i13_receipt_signer(runtime_receipt)
            } else {
                runtime
            }
        })
        .await;
        let (_, home_router) =
            validated_router(&home_pool, &ReceiptKeys::new(C33_HOME, 0x76), |runtime| {
                runtime
                    .with_clock(clock.clone())
                    .with_sim_hooks(Arc::clone(&home_hooks))
            })
            .await;
        // A home verifies the coordinator's acceptance proof with its published
        // request receipt key.
        let receipt_document: Value = serde_json::from_str(&seq_keys.document).unwrap();
        network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(C33_SEQ))
            .expect("the coordinator's DID document")["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .extend(
                receipt_document["verificationMethod"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned(),
            );
        // Each DS serves its real group relay routes, and the C33 acceptance
        // legs exactly as their routes run them once the caller is authenticated.
        let coordinator_answers = Arc::new(Mutex::new(CoordinatorAnswers::Accepts));
        let (accept_pool, accept_runtime, accept_hooks, accept_answers, accept_network) = (
            seq_pool.clone(),
            Arc::clone(&seq_runtime),
            Arc::clone(&seq_hooks),
            Arc::clone(&coordinator_answers),
            network.clone(),
        );
        network.serve(
            C33_SEQ,
            group_relay_router(
                GroupRelayState::for_test(
                    seq_pool.clone(),
                    C33_SEQ.to_owned(),
                    HMAC.as_bytes(),
                    Some(Arc::new(receipt.clone())),
                )
                .with_sim_hooks(Arc::clone(&seq_hooks))
                .with_clock(clock.clone()),
            )
            .route(
                "/xrpc/blue.catbird.mlsDS.deliverAcceptance",
                axum::routing::post(move |Json(input): Json<DeliverAcceptanceInput>| {
                    let (pool, runtime, hooks, answers, network) = (
                        accept_pool.clone(),
                        Arc::clone(&accept_runtime),
                        Arc::clone(&accept_hooks),
                        *accept_answers.lock().unwrap(),
                        accept_network.clone(),
                    );
                    async move {
                        if answers == CoordinatorAnswers::GateClosed {
                            return Err(crate::federation::FederationError::FederationDisabled {
                                reason: "the coordinator's gate is closed".into(),
                            });
                        }
                        let output = scope_sim_ds(hooks, async {
                            coordinator_accept_direct_request(
                                &pool,
                                &runtime,
                                C33_HOME,
                                input.conversation_id,
                                &input.direct_request,
                            )
                            .await
                        })
                        .await?;
                        if answers == CoordinatorAnswers::ThenUnresolvable {
                            network.documents.lock().unwrap().remove(host(C33_SEQ));
                        }
                        Ok(Json(output))
                    }
                }),
            ),
        );
        let (ingest_pool, ingest_hooks) = (home_pool.clone(), Arc::clone(&home_hooks));
        network.serve(
            C33_HOME,
            group_relay_router(
                GroupRelayState::for_test(
                    home_pool.clone(),
                    C33_HOME.to_owned(),
                    HMAC.as_bytes(),
                    None,
                )
                .with_sim_hooks(Arc::clone(&home_hooks))
                .with_clock(clock.clone()),
            )
            .route(
                "/xrpc/blue.catbird.mlsDS.deliverAcceptanceEntry",
                axum::routing::post(move |Json(input): Json<DeliverAcceptanceEntryInput>| {
                    let (pool, hooks) = (ingest_pool.clone(), Arc::clone(&ingest_hooks));
                    async move {
                        scope_sim_ds(hooks, async {
                            ingest_remote_acceptance_entry(
                                &pool,
                                None,
                                C33_SEQ,
                                input.conversation_id,
                                &input.entry,
                                &input.acceptance_proof,
                            )
                            .await
                        })
                        .await
                        .map(|()| Json(json!({ "accepted": true })))
                    }
                }),
            ),
        );
        // P's DID document carries the key its service-auth JWTs verify with.
        let signing = http::random_p256();
        let jwk = http::public_jwk(&signing);
        network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(&recipient))
            .expect("P's DID document")["verificationMethod"] = json!([{
            "id": format!("{recipient}#atproto"),
            "type": "JsonWebKey2020",
            "controller": recipient,
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: recipient.clone(),
            device_id: fixture.recipient_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            signing,
            jwk,
        };
        // P's device is registered at the transport-only home and listed on P's
        // PDS, as each acceptance leg checks it.
        let public = ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
            .verifying_key()
            .to_bytes();
        seed_actor_at(
            &home_pool,
            &fixture.recipient_did,
            fixture.recipient_device_id,
            &public,
            clock_now(&home_pool).await,
        )
        .await;
        network.authorize_device(&recipient, &public);
        // The home's inbox for the pending request, holding the opening whose
        // signed `next` coordinate an acceptance's `prior` must equal, and the
        // opening entry it holds at seq 1.
        let cid = fixture.conversation_id;
        let opening = serde_json::to_vec(&json!({
            "conversationId": cid,
            "seq": 1,
            "signedRequest": { "body": { "next": fixture.prior } },
        }))
        .unwrap();
        sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id, \
                 coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry, \
                 signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt, \
                 import_until,status) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10,$9,$9,$11,'pending')",
        )
        .bind(fixture.request_id)
        .bind(cid)
        .bind(Uuid::new_v4())
        .bind(C33_SEQ)
        .bind(&fixture.actor_did)
        .bind(fixture.actor_device_id)
        .bind(&fixture.recipient_did)
        .bind(fixture.recipient_device_id)
        .bind(&opening)
        .bind(Sha256::digest(&opening).as_slice())
        .bind(Utc::now() + chrono::Duration::days(1))
        .execute(&home_pool)
        .await
        .unwrap();
        let mut tx = home_pool.begin().await.unwrap();
        let opening_entry = json!({ "conversationId": cid, "entryId": Uuid::new_v4(), "seq": 1 });
        delivery::insert_transport_entry(
            &mut tx,
            cid,
            1,
            opening_entry["entryId"].as_str().unwrap().parse().unwrap(),
            &serde_json::to_vec(&opening_entry).unwrap(),
            current_utc(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self {
            _dbs: [seq_db, home_db],
            seq_pool,
            home_pool,
            fixture,
            network,
            clock,
            seq_hooks,
            home_hooks,
            seq_key,
            home_key,
            receipt,
            seq_runtime,
            relationships,
            coordinator_answers,
            seq_router,
            home_router,
            device,
        }
    }

    /// P's genuinely signed v2 acceptance at the request's published coordinate.
    fn acceptance(&self) -> Value {
        let f = &self.fixture;
        let transition = Uuid::new_v4();
        let mut next = f.prior.clone();
        next["stateVersion"] = json!(f.prior["stateVersion"].as_i64().unwrap() + 1);
        let body = json!({
            "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
            "protocolVersion": "2",
            "actorDid": f.recipient_did,
            "actorDeviceId": f.recipient_device_id,
            "keyId": f.recipient_key_id,
            "authGeneration": 1,
            "requestId": f.request_id,
            "transitionId": transition,
            "prior": f.prior,
            "next": next,
            "invitationProvenance": {
                "invitationTransitionId": f.request_id,
                "invitedByDid": f.actor_did,
                "invitedByDeviceId": f.actor_device_id,
            },
            "idempotencyKey": transition,
            "signedAt": canonical(current_utc()),
        });
        let bytes = direct_request_signing_bytes(
            DirectRequestKind::Accept,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let signature =
            ed25519_dalek::SigningKey::from_bytes(&f.recipient_ed25519_seed).sign(&bytes);
        json!({ "body": body, "signature": STANDARD.encode(signature.to_bytes()) })
    }

    /// P's `acceptConversation` through `router`, the real route, at `hooks`' DS.
    async fn accept_at(
        &self,
        router: &Router,
        hooks: &Arc<SimDsHooks>,
        acceptance: &Value,
    ) -> (StatusCode, Value) {
        let (status, _, body) = self.answer_at(router, hooks, acceptance).await;
        (status, body)
    }

    /// [`Self::accept_at`]'s status, `Retry-After` and body.
    async fn answer_at(
        &self,
        router: &Router,
        hooks: &Arc<SimDsHooks>,
        acceptance: &Value,
    ) -> (StatusCode, Option<String>, Value) {
        let (status, retry_after, body) = self.raw_answer_at(router, hooks, acceptance).await;
        (
            status,
            retry_after,
            serde_json::from_slice(&body).unwrap_or(Value::Null),
        )
    }

    async fn raw_answer_at(
        &self,
        router: &Router,
        hooks: &Arc<SimDsHooks>,
        acceptance: &Value,
    ) -> (StatusCode, Option<String>, Vec<u8>) {
        let body = serde_json::to_vec(&json!({ "directRequest": acceptance })).unwrap();
        let response = scope_sim_ds(Arc::clone(hooks), async {
            tower_util::ServiceExt::oneshot(
                router.clone(),
                http::unsigned_json_request(&self.device, ACCEPT_CONVERSATION, body),
            )
            .await
            .unwrap()
        })
        .await;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, retry_after, body.into())
    }

    async fn entries_at(&self, pool: &DbPool, did: &str, device_id: Uuid) -> Vec<Value> {
        let dpop_jkt: String = sqlx::query_scalar(
            "SELECT dpop_jkt FROM chat.devices WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let trusted = canonical(current_utc());
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let authority = crate::chat_protocol::repository::auth::authorize_unsigned_request(
            pool,
            crate::chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
                Uuid::new_v4(),
                proof_jti,
                "blue.catbird.chat.getEntries",
                &trusted,
                did,
                device_id,
                &dpop_jkt,
            ),
        )
        .await
        .unwrap();
        let admission = crate::chat_protocol::dpop::seal_read_admission(authority).unwrap();
        let page = crate::chat_protocol::repository::entry_read::get_entries_for_admission(
            pool,
            admission,
            self.fixture.conversation_id,
            1,
            100,
        )
        .await
        .unwrap();
        let page: Value = serde_json::from_slice(&page.into_response_bytes()).unwrap();
        page["entries"].as_array().unwrap().clone()
    }

    fn assert_i13_receipt(&self, acceptance: &Value, entry: &Value) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let body = &acceptance["body"];
        let receipt = &entry["sequencerReceipt"];
        let decode = |field: &str| {
            STANDARD
                .decode(
                    receipt[field]
                        .as_str()
                        .or_else(|| receipt[field]["$bytes"].as_str())
                        .unwrap(),
                )
                .unwrap()
        };
        let transcript = direct_request_signing_bytes(
            DirectRequestKind::Accept,
            &serde_json::to_vec(body).unwrap(),
        )
        .unwrap();
        let request_digest: [u8; 32] = sha2::Sha256::digest(transcript).into();
        let archive_commitment: [u8; 32] = decode("archiveCommitment").try_into().unwrap();
        let group_id = decode("groupId");
        let signature: [u8; 64] = decode("signature").try_into().unwrap();
        let issued_at_ms =
            chrono::DateTime::parse_from_rfc3339(entry["receivedAt"].as_str().unwrap())
                .unwrap()
                .timestamp_millis();

        assert_eq!(receipt["sequencerDid"], C33_SEQ);
        assert_eq!(receipt["conversationId"], entry["conversationId"]);
        assert_eq!(receipt["entryId"], entry["entryId"]);
        assert_eq!(receipt["seq"], entry["seq"]);
        assert_eq!(receipt["issuedAtMs"], issued_at_ms);
        assert_eq!(receipt["senderDid"], body["actorDid"]);
        assert_eq!(receipt["senderDeviceId"], body["actorDeviceId"]);
        assert_eq!(archive_commitment, request_digest);
        assert_eq!(receipt["generation"], body["next"]["generation"]);
        assert_eq!(receipt["epoch"], body["next"]["epoch"]);
        assert_eq!(
            group_id,
            STANDARD
                .decode(body["next"]["groupId"].as_str().unwrap())
                .unwrap()
        );

        labyrinth_protocol::receipt::verify_sequencer_receipt(
            &self.receipt.verifying_key(),
            C33_SEQ,
            &labyrinth_protocol::receipt::SignedSequencerReceipt {
                payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
                    sequencer_did: C33_SEQ.to_owned(),
                    conversation_id: entry["conversationId"].as_str().unwrap().to_owned(),
                    group_id,
                    epoch: receipt["epoch"].as_u64().unwrap(),
                    sender_device_did_url: format!(
                        "{}#{}",
                        body["actorDid"].as_str().unwrap(),
                        body["actorDeviceId"].as_str().unwrap()
                    ),
                    entry_id: entry["entryId"].as_str().unwrap().to_owned(),
                    archive_commitment,
                    seq: entry["seq"].as_u64().unwrap(),
                    issued_at_ms,
                },
                key_id: receipt["kid"].as_str().unwrap().to_owned(),
                signature,
            },
        )
        .unwrap();
    }
    /// The pair's graph source answering that the greater of D and P blocks
    /// the lesser: the one edge a two-party block-only graph asks about.
    fn blocking_graph(&self) -> Option<Result<PublicResponse, TransportError>> {
        let mut pair = [&self.fixture.actor_did, &self.fixture.recipient_did];
        pair.sort();
        Some(Ok(PublicResponse::json(
            200,
            json!({ "relationships": [{
                "$type": "app.bsky.graph.defs#relationship",
                "did": pair[0],
                "blocking": format!("at://{}/app.bsky.graph.block/acceptance", pair[1]),
            }]}),
        )))
    }

    /// P's acceptances tampered after signing: one changed timestamp, and one
    /// naming a conversation nobody holds.
    fn tampered(&self) -> [Value; 2] {
        let mut late = self.acceptance();
        late["body"]["signedAt"] = json!(canonical(current_utc() - chrono::Duration::seconds(1)));
        let mut elsewhere = self.acceptance();
        elsewhere["body"]["prior"]["conversationId"] = json!(Uuid::new_v4());
        [late, elsewhere]
    }

    /// D's declaration is gone, as a deleted account's typically is.
    fn withdraw_requester_declaration(&self) {
        self.network.serve(
            &format!("pds-{}", host(&self.fixture.actor_did)),
            Router::new(),
        );
    }

    /// The coordinator's `(entry seqs, P's participant status, acceptance
    /// records, queued outbound ids)` of the pair.
    async fn coordinator_state(&self) -> (Vec<i64>, String, i64, Vec<String>) {
        let cid = self.fixture.conversation_id;
        let (seqs, status, accepted): (Vec<i64>, String, i64) = sqlx::query_as(
            "SELECT ARRAY(SELECT seq FROM chat.entries WHERE conversation_id = $1 ORDER BY seq), \
                    (SELECT status FROM chat.participants \
                      WHERE conversation_id = $1 AND user_did = $2 AND current_membership), \
                    (SELECT count(*) FROM chat.direct_request_lifecycle WHERE request_id = $3) \
                  + (SELECT count(*) FROM chat.direct_request_acceptance_claims WHERE request_id = $3)",
        )
        .bind(cid)
        .bind(&self.fixture.recipient_did)
        .bind(self.fixture.request_id)
        .fetch_one(&self.seq_pool)
        .await
        .unwrap();
        let queued = queue_rows(&self.seq_pool, cid)
            .await
            .into_iter()
            .map(|row| row.0)
            .collect();
        (seqs, status, accepted, queued)
    }

    /// D's home deletes D and relays the deletion through its production
    /// queue; the coordinator sequences it.
    async fn relay_requester_deletion(&self) {
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            crate::labyrinth::repo::retention::delete_account_data_with_fixture_authority(
                &self.home_pool,
                &self.fixture.actor_did,
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
    }

    /// D deletes its account at its coordinator, which sequences the deletion
    /// and queues it for P's home.
    async fn delete_requester_at_coordinator(&self) {
        assert_eq!(
            scope_sim_ds(
                Arc::clone(&self.seq_hooks),
                crate::labyrinth::repo::retention::delete_account_data_with_fixture_authority(
                    &self.seq_pool,
                    &self.fixture.actor_did,
                    current_utc(),
                    Some(&self.receipt),
                ),
            )
            .await
            .unwrap(),
            1
        );
    }

    /// The coordinator's production queue delivers its deletion entry to P's
    /// home through that home's real route.
    async fn deliver_deletion_to_home(&self) {
        let queue = OutboundQueue::new(
            self.seq_pool.clone(),
            AuthMiddleware::new(),
            Arc::new(DsResolver::new(
                self.seq_pool.clone(),
                crate::federation::resolver::build_resolver_http_client(),
                C33_SEQ.to_owned(),
                format!("https://{}", host(C33_SEQ)),
                None,
                300,
            )),
        );
        assert_eq!(
            drain(&queue, &self.seq_hooks, C33_SEQ, &self.seq_key).await,
            1
        );
        let rows = control_rows(&self.seq_pool, self.fixture.conversation_id).await;
        let (status, last_error) = (
            &rows[0].2,
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT last_error FROM outbound_queue WHERE id = $1",
            )
            .bind(&rows[0].0)
            .fetch_one(&self.seq_pool)
            .await
            .unwrap(),
        );
        assert_eq!(status, "delivered", "{last_error:?}");
    }
}

/// The coordinator binds the relay's outer conversation id both to the signed
/// acceptance prior and to the publication selected by its request id. Neither
/// mismatch reaches signature admission or mutates the pending pair.
#[tokio::test]
async fn a_relayed_acceptance_rejects_each_outer_conversation_id_mismatch() {
    let p = PendingPair::new(C33_SEQ).await;
    let accepted = p.acceptance();
    let wrong = Uuid::new_v4();
    scope_ds_clock(p.clock.clone(), async {
        let before = p.coordinator_state().await;
        let signed_mismatch = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_accept_direct_request(
                &p.seq_pool,
                &p.seq_runtime,
                C33_HOME,
                wrong,
                &accepted,
            ),
        )
        .await
        .expect_err("outer id must match the signed acceptance");
        assert!(matches!(
            &signed_mismatch,
            crate::federation::FederationError::InvalidRequest(reason)
                if reason == "outer conversationId does not match signed acceptance"
        ));
        assert_eq!(p.coordinator_state().await, before);

        let mut publication_mismatch = accepted;
        publication_mismatch["body"]["prior"]["conversationId"] = json!(wrong);
        let stored_mismatch = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_accept_direct_request(
                &p.seq_pool,
                &p.seq_runtime,
                C33_HOME,
                wrong,
                &publication_mismatch,
            ),
        )
        .await
        .expect_err("outer id must match the stored publication");
        assert!(matches!(
            &stored_mismatch,
            crate::federation::FederationError::InvalidRequest(reason)
                if reason == "outer conversationId does not match stored direct request"
        ));
        assert_eq!(p.coordinator_state().await, before);
    })
    .await;
}

/// D's home relays D's deletion; the coordinator sequences it at seq 2. P,
/// homed at the coordinator, accepts through its real route, first while D's
/// declaration still resolves and then once it is gone: each is refused
/// `InvitationNotPending`, nothing is sequenced or queued, and nothing reaches
/// D's home.
#[tokio::test]
async fn a_c33_coordinator_refuses_acceptance_after_the_requesters_relayed_deletion() {
    let p = PendingPair::new(C33_HOME).await;
    let (cid, requester) = (p.fixture.conversation_id, p.fixture.actor_did.clone());
    scope_ds_clock(p.clock.clone(), async {
        p.relay_requester_deletion().await;
        assert_eq!(deletions(&p.seq_pool, cid).await, [(2, requester.clone())]);
        let settled = p.coordinator_state().await;
        for declared in [true, false] {
            if !declared {
                p.network
                    .serve(&format!("pds-{}", host(&requester)), Router::new());
            }
            let (status, body) = p
                .accept_at(&p.seq_router, &p.seq_hooks, &p.acceptance())
                .await;
            assert_eq!(
                (status, body["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("InvitationNotPending")),
                "declaration resolves: {declared}: {body}"
            );
            assert_eq!(
                p.coordinator_state().await,
                settled,
                "declaration resolves: {declared}"
            );
        }
        assert!(
            !p.network
                .delivered
                .lock()
                .unwrap()
                .iter()
                .any(|(path, _)| path.ends_with("deliverAcceptanceEntry")),
            "nothing reaches D's home"
        );
    })
    .await;
}

/// D, homed at the coordinator, deletes its account there. P's acceptance
/// relayed from P's home is refused under the conversation lock. Once P's home
/// holds the coordinator's deletion entry, delivered through the production
/// queue and route, P's home refuses the acceptance itself.
#[tokio::test]
async fn a_requesters_deletion_at_its_coordinator_ends_relayed_and_home_acceptance() {
    let p = PendingPair::new(C33_SEQ).await;
    let (cid, requester) = (p.fixture.conversation_id, p.fixture.actor_did.clone());
    scope_ds_clock(p.clock.clone(), async {
        p.delete_requester_at_coordinator().await;
        assert_eq!(deletions(&p.seq_pool, cid).await, [(2, requester.clone())]);

        let settled = p.coordinator_state().await;
        let refused = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_accept_direct_request(
                &p.seq_pool,
                &p.seq_runtime,
                C33_HOME,
                cid,
                &p.acceptance(),
            ),
        )
        .await
        .expect_err("a relayed acceptance after the deletion");
        assert!(
            matches!(
                &refused,
                crate::federation::FederationError::RemoteError { status: 400, body }
                    if body.ends_with("NotPending")
            ),
            "{refused:?}"
        );
        assert_eq!(p.coordinator_state().await, settled);

        p.deliver_deletion_to_home().await;
        let held = home_state(&p.home_pool).await;
        let (status, body) = p
            .accept_at(&p.home_router, &p.home_hooks, &p.acceptance())
            .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("InvitationNotPending")),
            "{body}"
        );
        assert_eq!(home_state(&p.home_pool).await, held);
        assert_eq!(p.coordinator_state().await.0, [1, 2]);
    })
    .await;
}

/// P accepts D's pending request at the coordinator (delivered to D's home),
/// and only then is D's deletion relayed and sequenced after it. P's exact
/// replay returns the stored outcome, as any duplicate does.
#[tokio::test]
async fn a_coordinator_replays_an_acceptance_completed_before_a_later_relayed_deletion() {
    let p = PendingPair::new(C33_HOME).await;
    let (cid, requester) = (p.fixture.conversation_id, p.fixture.actor_did.clone());
    scope_ds_clock(p.clock.clone(), async {
        let acceptance = p.acceptance();
        let (status, _, accepted_bytes) = p
            .raw_answer_at(&p.seq_router, &p.seq_hooks, &acceptance)
            .await;
        let accepted: Value = serde_json::from_slice(&accepted_bytes).unwrap();
        assert_eq!(status, StatusCode::OK, "{accepted}");
        let entry = &accepted["acceptanceProof"]["entry"];
        p.assert_i13_receipt(&acceptance, entry);
        let stored_receipt: Vec<u8> = sqlx::query_scalar(
            "SELECT sequencer_receipt_bytes FROM chat.entries \
             WHERE conversation_id = $1 AND seq = 2",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let mut stored_receipt: Value = serde_json::from_slice(&stored_receipt).unwrap();
        crate::chat_protocol::direct_request_transcript::present_read_presentation(
            "sequencerReceipt",
            &mut stored_receipt,
        )
        .unwrap();
        assert_eq!(stored_receipt, entry["sequencerReceipt"]);
        let home_entries = p
            .entries_at(
                &p.home_pool,
                &p.fixture.recipient_did,
                p.fixture.recipient_device_id,
            )
            .await;
        let synced = home_entries.iter().find(|row| row["seq"] == 2).unwrap();
        assert_eq!(synced["sequencerReceipt"], entry["sequencerReceipt"]);

        p.relay_requester_deletion().await;
        assert_eq!(deletions(&p.seq_pool, cid).await, [(3, requester.clone())]);
        let (status, _, replayed_bytes) = p
            .raw_answer_at(&p.seq_router, &p.seq_hooks, &acceptance)
            .await;
        assert_eq!((status, replayed_bytes), (StatusCode::OK, accepted_bytes));
        let entries: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
                .bind(cid)
                .fetch_one(&p.seq_pool)
                .await
                .unwrap();
        assert_eq!(entries, 3);
    })
    .await;
}

/// P accepts at its transport-only home, which relays to D's coordinator;
/// the coordinator's receipt is mirrored byte-for-byte and is readable there.
#[tokio::test]
async fn a_transport_home_replays_an_acceptance_completed_before_a_later_deletion() {
    let p = PendingPair::new(C33_SEQ).await;
    let (cid, requester) = (p.fixture.conversation_id, p.fixture.actor_did.clone());
    scope_ds_clock(p.clock.clone(), async {
        let acceptance = p.acceptance();
        let (status, _, accepted_bytes) = p
            .raw_answer_at(&p.home_router, &p.home_hooks, &acceptance)
            .await;
        let accepted: Value = serde_json::from_slice(&accepted_bytes).unwrap();
        assert_eq!(status, StatusCode::OK, "{accepted}");
        let entry = &accepted["acceptanceProof"]["entry"];
        p.assert_i13_receipt(&acceptance, entry);
        assert_eq!(entry["sequencerReceipt"]["sequencerDid"], C33_SEQ);

        let coordinator_receipt: Vec<u8> = sqlx::query_scalar(
            "SELECT sequencer_receipt_bytes FROM chat.entries \
             WHERE conversation_id = $1 AND seq = 2",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let coordinator_receipt: Value = serde_json::from_slice(&coordinator_receipt).unwrap();
        let mut presented_receipt = coordinator_receipt.clone();
        crate::chat_protocol::direct_request_transcript::present_read_presentation(
            "sequencerReceipt",
            &mut presented_receipt,
        )
        .unwrap();
        assert_eq!(presented_receipt, entry["sequencerReceipt"]);

        let mirror_bytes: Vec<u8> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
             WHERE conversation_id = $1 AND seq = 2",
        )
        .bind(cid)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        let mirror: Value = serde_json::from_slice(&mirror_bytes).unwrap();
        assert_eq!(mirror["sequencerReceipt"], coordinator_receipt);
        let home_entries = p
            .entries_at(
                &p.home_pool,
                &p.fixture.recipient_did,
                p.fixture.recipient_device_id,
            )
            .await;
        let synced = home_entries.iter().find(|entry| entry["seq"] == 2).unwrap();
        assert_eq!(synced["sequencerReceipt"], presented_receipt);

        p.delete_requester_at_coordinator().await;
        assert_eq!(deletions(&p.seq_pool, cid).await, [(3, requester.clone())]);
        p.deliver_deletion_to_home().await;
        let (status, _, replayed_bytes) = p
            .raw_answer_at(&p.home_router, &p.home_hooks, &acceptance)
            .await;
        assert_eq!((status, replayed_bytes), (StatusCode::OK, accepted_bytes));
    })
    .await;
}

#[tokio::test]
async fn a_signerless_coordinator_keeps_acceptance_compatible_and_idempotent() {
    let p = PendingPair::new_with_i13(C33_HOME, false).await;
    let cid = p.fixture.conversation_id;
    scope_ds_clock(p.clock.clone(), async {
        let acceptance = p.acceptance();
        let (status, _, accepted_bytes) = p
            .raw_answer_at(&p.seq_router, &p.seq_hooks, &acceptance)
            .await;
        let accepted: Value = serde_json::from_slice(&accepted_bytes).unwrap();
        assert_eq!(status, StatusCode::OK, "{accepted}");
        assert!(
            accepted["acceptanceProof"]["entry"]
                .get("sequencerReceipt")
                .is_none(),
            "{accepted}"
        );
        let stored_receipt: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT sequencer_receipt_bytes FROM chat.entries \
             WHERE conversation_id = $1 AND seq = 2",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        assert!(stored_receipt.is_none());
        let (status, _, replayed_bytes) = p
            .raw_answer_at(&p.seq_router, &p.seq_hooks, &acceptance)
            .await;
        assert_eq!((status, replayed_bytes), (StatusCode::OK, accepted_bytes));
        let entries: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
                .bind(cid)
                .fetch_one(&p.seq_pool)
                .await
                .unwrap();
        assert_eq!(entries, 2);
    })
    .await;
}

/// After D's relayed deletion, with D's declaration gone, a tampered
/// acceptance at the coordinator is refused `InvalidSignature` before it can
/// learn the request is deleted, pending or unknown; nothing changes.
#[tokio::test]
async fn a_coordinator_authenticates_an_acceptance_before_any_state_it_names() {
    let p = PendingPair::new(C33_HOME).await;
    scope_ds_clock(p.clock.clone(), async {
        p.relay_requester_deletion().await;
        p.withdraw_requester_declaration();
        let settled = p.coordinator_state().await;
        for acceptance in p.tampered() {
            let (status, body) = p.accept_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
            assert_eq!(
                (status, body["error"].as_str()),
                (StatusCode::UNAUTHORIZED, Some("InvalidSignature")),
                "{}: {body}",
                acceptance["body"]
            );
            assert_eq!(p.coordinator_state().await, settled);
        }
    })
    .await;
}

/// Once P's home holds D's deletion and D's declaration is gone, a tampered
/// acceptance there is refused `InvalidSignature` before anything it names is
/// read or relayed; neither home changes.
#[tokio::test]
async fn a_transport_home_authenticates_an_acceptance_before_any_state_it_names() {
    let p = PendingPair::new(C33_SEQ).await;
    scope_ds_clock(p.clock.clone(), async {
        p.delete_requester_at_coordinator().await;
        p.deliver_deletion_to_home().await;
        p.withdraw_requester_declaration();
        let (held, settled) = (home_state(&p.home_pool).await, p.coordinator_state().await);
        for acceptance in p.tampered() {
            let (status, body) = p
                .accept_at(&p.home_router, &p.home_hooks, &acceptance)
                .await;
            assert_eq!(
                (status, body["error"].as_str()),
                (StatusCode::UNAUTHORIZED, Some("InvalidSignature")),
                "{}: {body}",
                acceptance["body"]
            );
            assert_eq!(home_state(&p.home_pool).await, held);
            assert_eq!(p.coordinator_state().await, settled);
        }
    })
    .await;
}

/// Every insert into `table` fails, as this store failing mid-transaction
/// would; [`heal_inserts`] undoes it.
async fn break_inserts(pool: &DbPool, table: &str) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.injected_store_failure() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected store failure'; END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER injected_store_failure BEFORE INSERT ON {table} \
         FOR EACH ROW EXECUTE FUNCTION public.injected_store_failure()"
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn heal_inserts(pool: &DbPool, table: &str) {
    sqlx::query(&format!("DROP TRIGGER injected_store_failure ON {table}"))
        .execute(pool)
        .await
        .unwrap();
}

/// `(status, Retry-After, error)` of an answer.
fn answered(
    answer: &(StatusCode, Option<String>, Value),
) -> (StatusCode, Option<&str>, Option<&str>) {
    (answer.0, answer.1.as_deref(), answer.2["error"].as_str())
}

/// P accepts at its coordinator while the pair is blocked: the declared
/// `BlockedRelationship` refusal, not an unavailable policy; nothing is
/// sequenced or queued.
#[tokio::test]
async fn a_coordinator_refuses_an_acceptance_across_a_block() {
    let p = PendingPair::new(C33_HOME).await;
    scope_ds_clock(p.clock.clone(), async {
        let settled = p.coordinator_state().await;
        *p.relationships.lock().unwrap() = p.blocking_graph();
        let answer = p
            .answer_at(&p.seq_router, &p.seq_hooks, &p.acceptance())
            .await;
        assert_eq!(
            answered(&answer),
            (StatusCode::BAD_REQUEST, None, Some("BlockedRelationship")),
            "{}",
            answer.2
        );
        assert_eq!(p.coordinator_state().await, settled);
    })
    .await;
}

/// P accepts through its transport-only home while the pair is blocked. The
/// coordinator's declared refusal reaches P unchanged, and neither delivery
/// service writes anything.
#[tokio::test]
async fn a_transport_home_preserves_a_coordinators_blocked_acceptance_refusal() {
    let p = PendingPair::new(C33_SEQ).await;
    scope_ds_clock(p.clock.clone(), async {
        let settled = (home_state(&p.home_pool).await, p.coordinator_state().await);
        *p.relationships.lock().unwrap() = p.blocking_graph();
        let answer = p
            .answer_at(&p.home_router, &p.home_hooks, &p.acceptance())
            .await;
        assert_eq!(
            answered(&answer),
            (StatusCode::BAD_REQUEST, None, Some("BlockedRelationship")),
            "{}",
            answer.2
        );
        assert_eq!(
            (home_state(&p.home_pool).await, p.coordinator_state().await),
            settled,
            "a blocked acceptance writes nothing at either delivery service"
        );
    })
    .await;
}

/// P accepts at its coordinator while the pair's relationship source cannot
/// answer, then while the coordinator's own store fails. Neither decided
/// anything: the declared retryable `RelationshipPolicyUnavailable`
/// (`Retry-After: 5`), then a storage failure, and nothing is sequenced. Once
/// both answer, the identical acceptance is accepted.
#[tokio::test]
async fn a_coordinator_decides_no_acceptance_while_its_relationship_source_or_store_fails() {
    let p = PendingPair::new(C33_HOME).await;
    scope_ds_clock(p.clock.clone(), async {
        let (acceptance, settled) = (p.acceptance(), p.coordinator_state().await);
        *p.relationships.lock().unwrap() = Some(Err(TransportError::Network));
        let answer = p.answer_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
        assert_eq!(
            answered(&answer),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
                Some("RelationshipPolicyUnavailable")
            ),
            "relationship source unreachable: {}",
            answer.2
        );
        assert_eq!(p.coordinator_state().await, settled);

        *p.relationships.lock().unwrap() = None;
        break_inserts(&p.seq_pool, "chat.relationship_projection_snapshots").await;
        let answer = p.answer_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
        heal_inserts(&p.seq_pool, "chat.relationship_projection_snapshots").await;
        assert_eq!(
            answered(&answer),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                Some("InternalServerError")
            ),
            "store failing: {}",
            answer.2
        );
        assert_eq!(p.coordinator_state().await, settled);

        let (status, accepted) = p.accept_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
    })
    .await;
}

/// P's acceptance commits at its coordinator while D's home cannot take the
/// acceptance entry. The committed acceptance stands, and so does its exact
/// replay: the entry waits in the coordinator's queue for D's home.
#[tokio::test]
async fn an_acceptance_committed_at_its_coordinator_stands_while_the_senders_home_cannot_take_it() {
    let p = PendingPair::new(C33_HOME).await;
    let cid = p.fixture.conversation_id;
    scope_ds_clock(p.clock.clone(), async {
        // D's home answers nothing it is sent.
        p.network.serve(C33_HOME, Router::new());
        let acceptance = p.acceptance();
        let (status, accepted) = p.accept_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        let queued: Vec<_> = queue_rows(&p.seq_pool, cid)
            .await
            .into_iter()
            .filter(|row| row.0 == format!("acceptance-delivery-{cid}"))
            .map(|row| (row.1, row.2))
            .collect();
        assert_eq!(queued, [(C33_HOME.to_owned(), "pending".to_owned())]);
        let (status, replayed) = p.accept_at(&p.seq_router, &p.seq_hooks, &acceptance).await;
        assert_eq!((status, &replayed), (StatusCode::OK, &accepted));
    })
    .await;
}

/// P accepts at its transport-only home while the pair's coordinator cannot
/// answer: its declarations unreachable, its gate closed, or its receipt key
/// unresolvable once it answered. Each decided nothing at the home (the
/// declared retryable `RelationshipPolicyUnavailable`, `Retry-After: 5`) and
/// the home holds nothing new. Once the coordinator answers, the identical
/// acceptance completes with the coordinator's outcome.
#[tokio::test]
async fn a_transport_home_answers_retryably_while_the_pairs_coordinator_cannot_answer() {
    let p = PendingPair::new(C33_SEQ).await;
    scope_ds_clock(p.clock.clone(), async {
        let acceptance = p.acceptance();
        let held = home_state(&p.home_pool).await;
        let retryable = |answer: (StatusCode, Option<String>, Value), attempt: &str| {
            assert_eq!(
                answered(&answer),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some("5"),
                    Some("RelationshipPolicyUnavailable")
                ),
                "{attempt}: {}",
                answer.2
            );
        };

        let settled = p.coordinator_state().await;
        p.network.partition(true);
        let answer = p
            .answer_at(&p.home_router, &p.home_hooks, &acceptance)
            .await;
        p.network.partition(false);
        retryable(answer, "declarations unreachable");
        *p.coordinator_answers.lock().unwrap() = CoordinatorAnswers::GateClosed;
        retryable(
            p.answer_at(&p.home_router, &p.home_hooks, &acceptance)
                .await,
            "coordinator's gate closed",
        );
        assert_eq!(home_state(&p.home_pool).await, held);
        assert_eq!(p.coordinator_state().await, settled);

        let document = p.network.documents.lock().unwrap()[host(C33_SEQ)].clone();
        *p.coordinator_answers.lock().unwrap() = CoordinatorAnswers::ThenUnresolvable;
        retryable(
            p.answer_at(&p.home_router, &p.home_hooks, &acceptance)
                .await,
            "coordinator's receipt key unresolvable",
        );
        assert_eq!(home_state(&p.home_pool).await, held);
        p.network
            .documents
            .lock()
            .unwrap()
            .insert(host(C33_SEQ).to_owned(), document);
        *p.coordinator_answers.lock().unwrap() = CoordinatorAnswers::Accepts;
        let (status, accepted) = p
            .accept_at(&p.home_router, &p.home_hooks, &acceptance)
            .await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        assert_ne!(home_state(&p.home_pool).await, held);
    })
    .await;
}

/// D's coordinator, relayed P's acceptance from P's home, while the pair's
/// relationship source cannot answer and then while its own store fails:
/// it decided nothing, so it answers 5xx (`RelationshipPolicyUnavailable`
/// 503, then 500) for the home to retry, and sequences nothing. The
/// identical relay is then accepted.
#[tokio::test]
async fn a_coordinator_answers_a_relayed_acceptance_it_could_not_decide_with_5xx() {
    let p = PendingPair::new(C33_SEQ).await;
    let cid = p.fixture.conversation_id;
    scope_ds_clock(p.clock.clone(), async {
        let (acceptance, settled) = (p.acceptance(), p.coordinator_state().await);
        let relay = || {
            scope_sim_ds(
                Arc::clone(&p.seq_hooks),
                coordinator_accept_direct_request(
                    &p.seq_pool,
                    &p.seq_runtime,
                    C33_HOME,
                    cid,
                    &acceptance,
                ),
            )
        };
        *p.relationships.lock().unwrap() = Some(Err(TransportError::Network));
        let unavailable = relay().await.expect_err("relationship source unreachable");
        assert!(
            matches!(
                unavailable,
                crate::federation::FederationError::RelationshipPolicyUnavailable { .. }
            ),
            "{unavailable:?}"
        );
        assert_eq!(unavailable.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(p.coordinator_state().await, settled);

        *p.relationships.lock().unwrap() = None;
        break_inserts(&p.seq_pool, "chat.direct_request_acceptance_claims").await;
        let failed = relay().await.expect_err("store failing");
        heal_inserts(&p.seq_pool, "chat.direct_request_acceptance_claims").await;
        assert!(
            matches!(failed, crate::federation::FederationError::Database(_)),
            "{failed:?}"
        );
        assert_eq!(failed.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(p.coordinator_state().await, settled);

        relay()
            .await
            .expect("the identical relay once the coordinator can decide");
    })
    .await;
}

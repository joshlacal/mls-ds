//! `O7` signed entry-ACK relay and `D` ordered group-entry stream regressions on
//! real PostgreSQL. Delivery services meet only through the sim transport: it
//! serves DID documents and routes each XRPC into the peer's real router, or
//! drops it while the link is partitioned.

use super::entry_ack_relay::{accept_entry_ack_relay, EntryAckRelay};
use super::*;
use crate::{
    auth::{AuthMiddleware, VerifiedServicePrincipal},
    chat_protocol::{
        repository::entry_read::{remote_group_standing, RemoteGroupStanding},
        test_support::{
            seed_clean_slate_application_fixture_unsealed,
            seed_clean_slate_application_fixture_with_sender_home,
            seed_remote_clean_slate_application_fixture,
            seed_remote_group_application_routing_fixture, CleanSlateApplicationFixture,
        },
    },
    common::{
        executor_seed::{clock_now, seed_actor_at},
        fresh_db::fresh_fully_migrated_db,
        http_acceptance::ensure_fence,
    },
    federation::{
        group_fanout::PreparedGroupEntryFanout,
        outbound::OutboundClient,
        queue::{OutboundQueue, CLAIM_DUE_HEADS_SQL},
        resolver::{DsResolver, ValidatedRemoteDestination},
        ServiceAuthClient,
    },
    handlers::chat::acknowledge_entries_for_principal,
    sim_hooks::{
        current_utc, scope_ds_clock, scope_sim_ds, ManualDsClock, SimDsHooks, SimHttpRequest,
        SimHttpTransport,
    },
};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey,
};
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Mutex,
    },
};
use tower_util::ServiceExt as _;

const SEQ: &str = "did:web:ack-sequencer.example.com";
const HOME: &str = "did:web:ack-home.example.com";
const OTHER: &str = "did:web:ack-other.example.com";
const HMAC: &str = "s2s-stream-regression-secret";
const ACK_NSID: &str = "blue.catbird.chat.acknowledgeEntries";
const DELIVER_NSID_PATH: &str = "/xrpc/blue.catbird.mlsDS.deliverGroupEntry";

fn host(did: &str) -> &str {
    did.trim_start_matches("did:web:")
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn pem(key: &SigningKey) -> String {
    key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
}

#[derive(Clone, Default)]
struct Network {
    routers: Arc<Mutex<HashMap<String, Router>>>,
    documents: Arc<Mutex<HashMap<String, Value>>>,
    partitioned: Arc<AtomicBool>,
    delivered: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}

impl Network {
    fn new(identities: &[(&str, &SigningKey)]) -> Self {
        let network = Self::default();
        network
            .documents
            .lock()
            .unwrap()
            .extend(identities.iter().map(|(did, key)| {
                let document = json!({
                    "id": did,
                    "verificationMethod": [{
                        "id": format!("{did}#atproto"),
                        "type": "Multikey",
                        "controller": did,
                        "publicKeyMultibase":
                            crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
                    }],
                });
                (host(did).to_owned(), document)
            }));
        network
    }

    fn serve(&self, did: &str, router: Router) {
        self.routers
            .lock()
            .unwrap()
            .insert(host(did).to_owned(), router);
    }

    fn partition(&self, partitioned: bool) {
        self.partitioned.store(partitioned, SeqCst);
    }

    /// The `seq` of every `deliverGroupEntry` for `conversation_id` that reached
    /// the home's router, in arrival order.
    fn deliveries(&self, conversation_id: Uuid) -> Vec<i64> {
        self.delivered
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path == DELIVER_NSID_PATH)
            .filter_map(|(_, body)| serde_json::from_slice::<DeliverGroupEntryRequest>(body).ok())
            .filter(|request| request.conversation_id == conversation_id)
            .filter_map(|request| request.entry["seq"].as_i64())
            .collect()
    }

    fn transport(&self) -> SimHttpTransport {
        let network = self.clone();
        Arc::new(move |request: SimHttpRequest| {
            let network = network.clone();
            Box::pin(async move {
                let host = request.url.host_str().unwrap_or_default().to_owned();
                let respond = |status: StatusCode, body: Vec<u8>| {
                    http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap()
                };
                if request.url.path() == /* did-web-test */ "/.well-known/did.json" {
                    let document = network.documents.lock().unwrap().get(&host).cloned();
                    return document
                        .map(|document| respond(StatusCode::OK, document.to_string().into_bytes()))
                        .ok_or_else(|| format!("no DID document for {host}"));
                }
                if network.partitioned.load(SeqCst) {
                    return Err(format!("partitioned from {host}"));
                }
                let router = network
                    .routers
                    .lock()
                    .unwrap()
                    .get(&host)
                    .cloned()
                    .ok_or_else(|| format!("no route to {host}"))?;
                network
                    .delivered
                    .lock()
                    .unwrap()
                    .push((request.url.path().to_owned(), request.body.clone()));
                let mut builder = axum::http::Request::builder()
                    .method(request.method)
                    .uri(request.url.path());
                for (name, value) in &request.headers {
                    builder = builder.header(name, value);
                }
                let response = router
                    .oneshot(builder.body(axum::body::Body::from(request.body)).unwrap())
                    .await
                    .unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(respond(status, body.to_vec()))
            })
        })
    }
}

fn hooks(did: &str, key: Option<&SigningKey>, hmac: bool, network: &Network) -> Arc<SimDsHooks> {
    Arc::new(SimDsHooks {
        service_did: did.to_owned(),
        self_endpoint: format!("https://{}", host(did)),
        signing_key_pem: key.map(pem),
        group_relay_hmac_secret: hmac.then(|| HMAC.to_owned()),
        http_transport: network.transport(),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
        retain_application_ciphertext: false,
    })
}

/// Every DS DID resolves to its `did:web` host, pinned to a public address the
/// sim transport intercepts.
fn resolver(pool: &DbPool, did: &str) -> DsResolver {
    DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        did.to_owned(),
        format!("https://{}", host(did)),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(|target: &str| {
        let host = host(target).to_owned();
        Some(Box::pin(async move {
            Ok(ValidatedRemoteDestination {
                url: format!("https://{host}/").parse().unwrap(),
                host,
                addrs: vec!["93.184.216.34:443".parse().unwrap()],
            })
        }))
    }))
}

fn manual_clock() -> Arc<ManualDsClock> {
    let now = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
    Arc::new(ManualDsClock::new(now))
}

async fn prepare(pool: &DbPool) {
    ensure_fence(pool).await;
    for peer in [SEQ, HOME, OTHER] {
        sqlx::query(
            "INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow') \
             ON CONFLICT(ds_did) DO UPDATE SET status='allow'",
        )
        .bind(peer)
        .execute(pool)
        .await
        .unwrap();
    }
}

/// A device's signed `acknowledgeEntries` body, exactly as a client builds it.
fn ack_body(
    device_id: Uuid,
    key_id: &str,
    seed: &[u8; 32],
    conversation_id: Uuid,
    up_to_seq: i64,
) -> Vec<u8> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Transcript<'a> {
        key_id: &'a str,
        up_to_seq: i64,
        signed_at: &'a str,
        generation: i64,
        actor_device_id: String,
        auth_generation: i64,
        conversation_id: String,
    }
    let signed_at = current_utc().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut transcript = b"CATBIRD-CHAT-ACK-ENTRIES\0".to_vec();
    transcript.extend(
        serde_ipld_dagcbor::to_vec(&Transcript {
            key_id,
            up_to_seq,
            signed_at: &signed_at,
            generation: 0,
            actor_device_id: device_id.to_string(),
            auth_generation: 1,
            conversation_id: conversation_id.to_string(),
        })
        .unwrap(),
    );
    let signature = ed25519_dalek::SigningKey::from_bytes(seed).sign(&transcript);
    serde_json::to_vec(&json!({
        "conversationId": conversation_id,
        "generation": 0,
        "actorDeviceId": device_id,
        "keyId": key_id,
        "authGeneration": 1,
        "upToSeq": up_to_seq,
        "signedAt": signed_at,
        "signature": { "$bytes": STANDARD.encode(signature.to_bytes()) },
    }))
    .unwrap()
}

async fn local_ack(pool: &DbPool, user_did: &str, body: Vec<u8>) -> Value {
    let (status, body) = ack_response(pool, user_did, body).await;
    assert_eq!(status, StatusCode::OK, "local ACK: {body}");
    body
}

async fn ack_response(pool: &DbPool, user_did: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let principal = VerifiedServicePrincipal::for_federated_s2s(user_did, ACK_NSID);
    let response = acknowledge_entries_for_principal(pool, principal, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    (status, body)
}

#[allow(clippy::too_many_arguments)]
fn signed_relay(
    key: &SigningKey,
    home_did: &str,
    sequencer_did: &str,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
    acked_through_seq: i64,
) -> EntryAckRelay {
    let mut relay = EntryAckRelay {
        home_did: home_did.to_owned(),
        sequencer_did: sequencer_did.to_owned(),
        conversation_id,
        generation: 0,
        user_did: user_did.to_owned(),
        device_id,
        acked_through_seq,
        signature: String::new(),
    };
    let signature: Signature = key.sign(&relay.signing_bytes());
    relay.signature = STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes());
    relay
}

fn edited(mut relay: EntryAckRelay, edit: impl FnOnce(&mut EntryAckRelay)) -> EntryAckRelay {
    edit(&mut relay);
    relay
}

/// The ACK and payload state a relay may change at the sequencer: ACK rows,
/// their watermark sum, retained application ciphertexts and send payloads,
/// and retained I13 receipts.
async fn ack_state(pool: &DbPool, conversation_id: Uuid) -> Vec<i64> {
    sqlx::query_scalar(
        "SELECT ARRAY[ \
            (SELECT count(*) FROM chat.device_entry_acks WHERE conversation_id = $1), \
            (SELECT COALESCE(sum(acked_through_seq), 0)::bigint FROM chat.device_entry_acks \
              WHERE conversation_id = $1), \
            (SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND entry_kind = $2 \
                AND accepted_payload_bytes IS NOT NULL AND payload_pruned_at IS NULL), \
            (SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 \
                AND signed_request_bytes IS NOT NULL), \
            (SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND entry_kind = $2 \
                AND sequencer_receipt_bytes IS NOT NULL AND accepted_payload_sha256 IS NOT NULL \
                AND request_digest IS NOT NULL AND signature IS NOT NULL) \
         ]::bigint[]",
    )
    .bind(conversation_id)
    .bind("blue.catbird.chat.defs#applicationEntry")
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_rejected(
    state: &GroupRelayState,
    caller: &str,
    relay: &EntryAckRelay,
    conversation_id: Uuid,
    status: StatusCode,
    code: &str,
) {
    let before = ack_state(&state.pool, conversation_id).await;
    let response = accept_entry_ack_relay(state, caller, &serde_json::to_vec(relay).unwrap())
        .await
        .expect_err("the relay must be rejected");
    let actual = response.status();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual, status, "{caller}: {body}");
    assert_eq!(body["error"], code, "{caller}: {body}");
    assert_eq!(ack_state(&state.pool, conversation_id).await, before);
}

/// `(id, target, status, retry_count, next_retry_at, payload)` of each queued row.
type QueueRow = (String, String, String, i32, DateTime<Utc>, Vec<u8>);

async fn queue_rows(pool: &DbPool, conversation_id: Uuid) -> Vec<QueueRow> {
    sqlx::query_as(
        "SELECT id, target_ds_did, status, retry_count, next_retry_at, payload \
           FROM outbound_queue WHERE convo_id = $1 ORDER BY id",
    )
    .bind(conversation_id.to_string())
    .fetch_all(pool)
    .await
    .unwrap()
}

type RelayedSendState = (i64, i64, i64, i64, i64);

async fn relayed_send_state(pool: &DbPool, conversation_id: Uuid) -> RelayedSendState {
    sqlx::query_as(
        "SELECT c.next_entry_seq,c.current_generation,c.current_state_version, \
                (SELECT count(*) FROM chat.entries e WHERE e.conversation_id=c.conversation_id), \
                (SELECT count(*) FROM chat.message_sends m WHERE m.conversation_id=c.conversation_id) + \
                (SELECT count(*) FROM outbound_queue q WHERE q.convo_id=c.conversation_id::text) \
           FROM chat.conversations c WHERE c.conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn receipted_relay_refuses_an_archive_less_group_send_before_any_effect() {
    crate::federation::open_federation_for_test();
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    prepare(&seq_pool).await;
    prepare(&home_pool).await;
    let missing =
        seed_clean_slate_application_fixture_unsealed(&seq_pool, false, SEQ, None, Some(HOME))
            .await
            .unwrap();
    let valid = seed_clean_slate_application_fixture_unsealed(
        &seq_pool,
        false,
        SEQ,
        Some([0x5c; 32]),
        Some(HOME),
    )
    .await
    .unwrap();
    let (seq_key, home_key) = (key(0x35), key(0x36));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    for fixture in [&missing, &valid] {
        network.declare_user(&fixture.sender_did, HOME);
        network.authorize_device(
            &fixture.sender_did,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed)
                .verifying_key()
                .to_bytes(),
        );
        network.declare_user(&fixture.recipient_did, SEQ);
        network.authorize_device(
            &fixture.recipient_did,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
                .verifying_key()
                .to_bytes(),
        );
    }
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), true, &network);
    let home_hooks = hooks(HOME, Some(&home_key), false, &network);
    let state = GroupRelayState::for_test(
        seq_pool.clone(),
        SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(I13ReceiptSigner::new(
            seq_key.clone(),
            SEQ.to_owned(),
        ))),
    )
    .with_sim_hooks(seq_hooks)
    .with_clock(clock.clone());
    network.serve(SEQ, group_relay_router(state));

    let relay = |fixture: &CleanSlateApplicationFixture| RelayGroupMutationRequest {
        conversation_id: fixture.conversation_id,
        endpoint: "blue.catbird.chat.sendMessage".to_owned(),
        actor_did: fixture.sender_did.clone(),
        actor_device_id: fixture.sender_device_id,
        signed_request: fixture.signed_request.clone(),
        signed_request_bytes: None,
    };
    scope_ds_clock(
        clock,
        scope_sim_ds(home_hooks, async {
            let before = relayed_send_state(&seq_pool, missing.conversation_id).await;
            let rejected = relay_group_mutation_to_sequencer(
                &format!("https://{}", host(SEQ)),
                HOME,
                SEQ,
                HMAC.as_bytes(),
                &relay(&missing),
            )
            .await;
            assert!(
                matches!(
                    rejected,
                    Err(GroupRelayError::Rejected(
                        crate::chat_protocol::error::ChatProtocolErrorCode::InvalidApplicationMessage
                    ))
                ),
                "{rejected:?}"
            );
            assert_eq!(
                relayed_send_state(&seq_pool, missing.conversation_id).await,
                before
            );

            let valid_before = relayed_send_state(&seq_pool, valid.conversation_id).await;
            let request = relay(&valid);
            let accepted = relay_group_mutation_to_sequencer(
                &format!("https://{}", host(SEQ)),
                HOME,
                SEQ,
                HMAC.as_bytes(),
                &request,
            )
            .await
            .expect("archive-bound group send");
            assert_eq!(accepted.entry["seq"], valid_before.0);
            assert!(accepted.entry["sequencerReceipt"].is_object());
            let accepted_state = relayed_send_state(&seq_pool, valid.conversation_id).await;
            let replay = relay_group_mutation_to_sequencer(
                &format!("https://{}", host(SEQ)),
                HOME,
                SEQ,
                HMAC.as_bytes(),
                &request,
            )
            .await
            .expect("exact replay");
            assert_eq!(
                serde_json::to_value(replay).unwrap(),
                serde_json::to_value(accepted).unwrap()
            );
            assert_eq!(
                relayed_send_state(&seq_pool, valid.conversation_id).await,
                accepted_state
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn sequencer_prunes_only_after_the_remote_home_relays_its_device_ack() {
    crate::federation::open_federation_for_test();
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    prepare(&seq_pool).await;
    prepare(&home_pool).await;
    // The sender's device is homed at HOME; the recipient's device is local.
    // Unsealed: the sequencer's own (simulation) authority collects the
    // sender's traffic evidence, as a relayed send now requires.
    let fixture = seed_clean_slate_application_fixture_unsealed(
        &seq_pool,
        false,
        SEQ,
        Some([0x5a; 32]),
        Some(HOME),
    )
    .await
    .unwrap();
    let cid = fixture.conversation_id;
    let (seq_key, home_key, other_key) = (key(0x31), key(0x32), key(0x33));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key), (OTHER, &other_key)]);
    let clock = manual_clock();
    // SEQ signs the entries-pruned notice its prune owes HOME; HOME is not
    // served, so the entry queued for it stays queued.
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    let home_hooks = hooks(HOME, Some(&home_key), false, &network);
    let seq_state = GroupRelayState::for_test(
        seq_pool.clone(),
        SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(I13ReceiptSigner::new(
            seq_key.clone(),
            SEQ.to_owned(),
        ))),
    )
    .with_sim_hooks(Arc::clone(&seq_hooks))
    .with_clock(clock.clone());
    network.serve(SEQ, group_relay_router(seq_state.clone()));
    let queue = OutboundQueue::new(
        home_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(resolver(&home_pool, HOME)),
    );
    let outbound = OutboundClient::new(5, 5);
    let auth = ServiceAuthClient::from_es256_pem(
        HOME.to_owned(),
        pem(&home_key).as_bytes(),
        Some("#atproto".to_owned()),
    )
    .unwrap();
    let auth_sign = move |target: &str, method: &str| {
        auth.sign_request(target, method)
            .map_err(|error| error.to_string())
    };

    scope_ds_clock(clock.clone(), async {
        let request = RelayGroupMutationRequest {
            conversation_id: cid,
            endpoint: "blue.catbird.chat.sendMessage".to_owned(),
            actor_did: fixture.sender_did.clone(),
            actor_device_id: fixture.sender_device_id,
            signed_request: fixture.signed_request.clone(),
            signed_request_bytes: None,
        };
        let entry = scope_sim_ds(
            Arc::clone(&seq_hooks),
            sequence_relayed_group_application_send(&seq_state, HOME, &request),
        )
        .await
        .expect("sequence the remote sender's application")
        .entry;
        let seq = entry["seq"].as_i64().unwrap();
        assert!(entry.get("sequencerReceipt").is_some(), "I13 receipt");

        // The local device's ACK alone never prunes the remote-homed audience.
        let local = scope_sim_ds(
            Arc::clone(&seq_hooks),
            local_ack(
                &seq_pool,
                &fixture.recipient_did,
                ack_body(
                    fixture.recipient_device_id,
                    &fixture.recipient_key_id,
                    &fixture.recipient_ed25519_seed,
                    cid,
                    seq,
                ),
            ),
        )
        .await;
        assert_eq!(local["prunedCount"], 0);
        assert_eq!(ack_state(&seq_pool, cid).await, [1, seq, 1, 1, 1]);

        scope_sim_ds(Arc::clone(&seq_hooks), async {
            let sender = fixture.sender_did.as_str();
            let device = fixture.sender_device_id;
            let genuine = signed_relay(&home_key, HOME, SEQ, cid, sender, device, seq);
            let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
            let tampered = (StatusCode::FORBIDDEN, "InvalidSignature");
            let cases = [
                // Wrong home: a peer that genuinely signed for a device homed elsewhere.
                (
                    OTHER,
                    signed_relay(&other_key, OTHER, SEQ, cid, sender, device, seq),
                    forbidden,
                ),
                (OTHER, genuine.clone(), forbidden),
                (
                    HOME,
                    signed_relay(&home_key, HOME, OTHER, cid, sender, device, seq),
                    forbidden,
                ),
                (
                    HOME,
                    signed_relay(&home_key, HOME, SEQ, cid, sender, Uuid::new_v4(), seq),
                    forbidden,
                ),
                (
                    HOME,
                    signed_relay(&home_key, HOME, SEQ, cid, sender, device, seq + 1),
                    (StatusCode::BAD_REQUEST, "InvalidRequest"),
                ),
                // Every signed field, altered after signing.
                (
                    HOME,
                    edited(genuine.clone(), |r| r.home_did = OTHER.to_owned()),
                    forbidden,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| r.sequencer_did = OTHER.to_owned()),
                    forbidden,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| r.conversation_id = Uuid::new_v4()),
                    tampered,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| r.generation = 1),
                    tampered,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| {
                        r.user_did = fixture.recipient_did.clone();
                    }),
                    tampered,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| {
                        r.device_id = fixture.recipient_device_id
                    }),
                    tampered,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| r.acked_through_seq = seq - 1),
                    tampered,
                ),
                (
                    HOME,
                    edited(genuine.clone(), |r| {
                        let mut signature = STANDARD.decode(&r.signature).unwrap();
                        signature[63] ^= 1;
                        r.signature = STANDARD.encode(signature);
                    }),
                    tampered,
                ),
            ];
            for (caller, relay, (status, code)) in cases {
                assert_rejected(&seq_state, caller, &relay, cid, status, code).await;
            }
        })
        .await;

        // HOME queues the relay with its local ACK's effect; a partition is
        // retried, never dropped, and then the relay delivers.
        let mut tx = home_pool.begin().await.unwrap();
        scope_sim_ds(
            Arc::clone(&home_hooks),
            enqueue_entry_ack_relay(
                &mut tx,
                SEQ,
                cid,
                0,
                &fixture.sender_did,
                fixture.sender_device_id,
                seq,
                current_utc(),
            ),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        network.partition(true);
        scope_sim_ds(
            Arc::clone(&home_hooks),
            queue.process_pending_batch(&outbound, &auth_sign),
        )
        .await
        .unwrap();
        let rows = queue_rows(&home_pool, cid).await;
        assert_eq!(rows.len(), 1);
        let (_, target, status, retries, due, _) = &rows[0];
        assert_eq!(
            (target.as_str(), status.as_str(), *retries),
            (SEQ, "pending", 1)
        );
        assert_eq!(ack_state(&seq_pool, cid).await, [1, seq, 1, 1, 1]);
        network.partition(false);
        clock.set_utc(*due);
        let delivered = scope_sim_ds(
            Arc::clone(&home_hooks),
            queue.process_pending_batch(&outbound, &auth_sign),
        )
        .await
        .unwrap();
        assert_eq!(delivered, 1);
        let rows = queue_rows(&home_pool, cid).await;
        assert_eq!(rows[0].2, "delivered");
        // Both devices acknowledged: ciphertext and send payload are gone, the
        // I13 receipt and immutable metadata remain.
        assert_eq!(ack_state(&seq_pool, cid).await, [2, 2 * seq, 0, 0, 1]);

        // A duplicate and an older relay are idempotent no-ops.
        let pruned = ack_state(&seq_pool, cid).await;
        let older = signed_relay(
            &home_key,
            HOME,
            SEQ,
            cid,
            &fixture.sender_did,
            fixture.sender_device_id,
            seq - 1,
        );
        for body in [rows[0].5.clone(), serde_json::to_vec(&older).unwrap()] {
            let out = scope_sim_ds(
                Arc::clone(&seq_hooks),
                accept_entry_ack_relay(&seq_state, HOME, &body),
            )
            .await
            .expect("an idempotent relay is accepted");
            assert_eq!(out["accepted"], true);
            assert_eq!(out["acknowledgedSeq"], seq);
            assert_eq!(out["prunedCount"], 0);
            assert_eq!(ack_state(&seq_pool, cid).await, pruned);
        }
    })
    .await;
}

#[tokio::test]
async fn local_acks_at_a_mirror_or_c33_home_queue_one_bound_signed_relay() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let mirror = seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, None)
        .await
        .unwrap();
    // A C33 inbox naming SEQ as coordinator; its recipient is homed here.
    let c33 = Uuid::new_v4();
    let actor = format!("did:web:c33-{}.example.com", Uuid::new_v4().simple());
    let actor_device = Uuid::new_v4();
    let actor_seed = [0x44; 32];
    let actor_key_id = seed_actor_at(
        &pool,
        &actor,
        actor_device,
        &ed25519_dalek::SigningKey::from_bytes(&actor_seed)
            .verifying_key()
            .to_bytes(),
        clock_now(&pool).await,
    )
    .await;
    let opening = b"c33-entry-ack-relay-fixture";
    sqlx::query(
        "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id, \
             coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry, \
             signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt, \
             import_until,status) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10,$9,$9,$11,'accepted')",
    )
    .bind(Uuid::new_v4())
    .bind(c33)
    .bind(Uuid::new_v4())
    .bind(SEQ)
    .bind(&mirror.sender_did)
    .bind(mirror.sender_device_id)
    .bind(&actor)
    .bind(actor_device)
    .bind(opening.as_slice())
    .bind(Sha256::digest(opening).as_slice())
    .bind(Utc::now() + chrono::Duration::days(1))
    .execute(&pool)
    .await
    .unwrap();
    let transport_entry = |conversation_id: Uuid, seq: i64| {
        let pool = pool.clone();
        async move {
            let entry_id = Uuid::new_v4();
            let bytes = serde_json::to_vec(&json!({
                "$type": "blue.catbird.chat.defs#commitEntry",
                "conversationId": conversation_id,
                "entryId": entry_id,
                "seq": seq,
            }))
            .unwrap();
            crate::chat_protocol::repository::delivery::insert_transport_entry(
                &mut pool.acquire().await.unwrap(),
                conversation_id,
                seq,
                entry_id,
                &bytes,
                Utc::now(),
            )
            .await
            .unwrap();
        }
    };
    transport_entry(c33, 1).await;

    let home_key = key(0x32);
    let network = Network::default();
    let clock = manual_clock();
    let expected =
        |conversation_id: Uuid, user_did: &str, device_id: Uuid, seq: i64| EntryAckRelay {
            home_did: HOME.to_owned(),
            sequencer_did: SEQ.to_owned(),
            conversation_id,
            generation: 0,
            user_did: user_did.to_owned(),
            device_id,
            acked_through_seq: seq,
            signature: String::new(),
        };
    let assert_one_relay = |rows: Vec<QueueRow>, relay: EntryAckRelay| {
        assert_eq!(rows.len(), 1, "exactly one relay per stored watermark");
        let (id, target, status, retries, due, payload) = &rows[0];
        assert_eq!(
            id,
            &format!(
                "entry-ack-{}-{}-{:020}",
                relay.conversation_id, relay.device_id, relay.acked_through_seq
            )
        );
        assert_eq!(
            (target.as_str(), status.as_str(), *retries),
            (SEQ, "pending", 0)
        );
        assert!(*due <= current_utc(), "the relay is due immediately");
        let signed: EntryAckRelay = serde_json::from_slice(payload).unwrap();
        let signature =
            Signature::from_slice(&STANDARD.decode(&signed.signature).unwrap()).unwrap();
        home_key
            .verifying_key()
            .verify(&signed.signing_bytes(), &signature)
            .expect("signed by the home's #atproto key");
        assert_eq!(
            EntryAckRelay {
                signature: String::new(),
                ..signed
            },
            relay
        );
    };

    scope_ds_clock(
        clock,
        scope_sim_ds(hooks(HOME, Some(&home_key), false, &network), async {
            let mirror_ack = |seq: i64| {
                ack_body(
                    mirror.recipient_device_id,
                    &mirror.recipient_key_id,
                    &mirror.recipient_ed25519_seed,
                    mirror.conversation_id,
                    seq,
                )
            };
            // A group mirror relays its device's ACK; a repeat adds nothing.
            for _ in 0..2 {
                local_ack(&pool, &mirror.recipient_did, mirror_ack(3)).await;
                assert_one_relay(
                    queue_rows(&pool, mirror.conversation_id).await,
                    expected(
                        mirror.conversation_id,
                        &mirror.recipient_did,
                        mirror.recipient_device_id,
                        3,
                    ),
                );
            }
            // A newer watermark supersedes the still-pending older relay.
            transport_entry(mirror.conversation_id, 4).await;
            local_ack(&pool, &mirror.recipient_did, mirror_ack(4)).await;
            assert_one_relay(
                queue_rows(&pool, mirror.conversation_id).await,
                expected(
                    mirror.conversation_id,
                    &mirror.recipient_did,
                    mirror.recipient_device_id,
                    4,
                ),
            );
            // A C33 home relays to the inbox coordinator.
            local_ack(
                &pool,
                &actor,
                ack_body(actor_device, &actor_key_id, &actor_seed, c33, 1),
            )
            .await;
            assert_one_relay(
                queue_rows(&pool, c33).await,
                expected(c33, &actor, actor_device, 1),
            );
        }),
    )
    .await;
}

/// SEQ's real queue and fan-out to HOME's real router, which mirrors `cid`.
struct GroupStream {
    _dbs: [crate::common::fresh_db::DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    cid: Uuid,
    seq_hooks: Arc<SimDsHooks>,
    network: Network,
    clock: Arc<ManualDsClock>,
    resolver: DsResolver,
    queue: OutboundQueue,
    outbound: OutboundClient,
    auth: ServiceAuthClient,
}

impl GroupStream {
    async fn new() -> Self {
        crate::federation::open_federation_for_test();
        let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let seq_pool = seq_db.connect(4).await;
        let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let home_pool = home_db.connect(4).await;
        prepare(&seq_pool).await;
        prepare(&home_pool).await;
        let cid = seed_remote_group_application_routing_fixture(&home_pool, HOME, SEQ)
            .await
            .unwrap()
            .conversation_id;
        let (seq_key, home_key) = (key(0x31), key(0x32));
        let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
        let clock = manual_clock();
        network.serve(
            HOME,
            group_relay_router(
                GroupRelayState::for_test(
                    home_pool.clone(),
                    HOME.to_owned(),
                    HMAC.as_bytes(),
                    None,
                )
                .with_sim_hooks(hooks(HOME, Some(&home_key), true, &network))
                .with_clock(clock.clone()),
            ),
        );
        let resolver = resolver(&seq_pool, SEQ);
        Self {
            _dbs: [seq_db, home_db],
            queue: OutboundQueue::new(
                seq_pool.clone(),
                AuthMiddleware::new(),
                Arc::new(resolver.clone()),
            ),
            seq_pool,
            home_pool,
            cid,
            seq_hooks: hooks(SEQ, Some(&seq_key), true, &network),
            network,
            clock,
            resolver,
            outbound: OutboundClient::new(5, 5),
            auth: ServiceAuthClient::from_es256_pem(
                SEQ.to_owned(),
                pem(&seq_key).as_bytes(),
                Some("#atproto".to_owned()),
            )
            .unwrap(),
        }
    }

    /// `seq` of `conversation_id`, queued in its own committed sequencing
    /// transaction exactly as `prepare_group_entry_fanout` queues it.
    async fn sequenced(&self, conversation_id: Uuid, seq: i64) -> PreparedGroupEntryFanout {
        let fanout = PreparedGroupEntryFanout::for_test(
            SEQ,
            HOME,
            DeliverGroupEntryRequest {
                conversation_id,
                generation: 0,
                space_uri: format!(
                    "at://{SEQ}/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
                ),
                recipient_dids: Vec::new(),
                recipient_devices: Vec::new(),
                entry: json!({
                    "$type": "blue.catbird.chat.defs#applicationEntry",
                    "conversationId": conversation_id,
                    "entryId": Uuid::new_v4(),
                    "seq": seq,
                }),
                close_authority: None,
            },
        );
        let mut tx = self.seq_pool.begin().await.unwrap();
        fanout.enqueue(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        fanout
    }

    async fn send(&self, fanout: PreparedGroupEntryFanout) -> Result<(), String> {
        fanout.deliver(&self.seq_pool, Some(&self.resolver)).await
    }

    /// One production queue-worker pass.
    async fn drain_once(&self) -> usize {
        let auth = &self.auth;
        let sign = move |target: &str, method: &str| {
            auth.sign_request(target, method)
                .map_err(|error| error.to_string())
        };
        self.queue
            .process_pending_batch(&self.outbound, &sign)
            .await
            .unwrap()
    }

    /// The lowest pending `seq` of a conversation's stream to HOME.
    async fn head(&self, conversation_id: Uuid) -> QueueRow {
        let prefix = format!("group-entry-{conversation_id}-");
        queue_rows(&self.seq_pool, conversation_id)
            .await
            .into_iter()
            .filter(|row| row.2 == "pending")
            .min_by_key(|row| {
                row.0
                    .strip_prefix(&prefix)
                    .and_then(|rest| rest.split('-').next())
                    .and_then(|seq| seq.parse::<i64>().ok())
                    .expect("a group-entry queue id")
            })
            .expect("a pending head")
    }

    async fn mirrored(&self) -> Vec<i64> {
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

#[tokio::test]
async fn back_to_back_group_entries_reach_their_home_in_seq_order() {
    let s = GroupStream::new().await;
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            // Both entries commit before either post-commit send runs, and the
            // later entry's send runs first: it delivers 4, then 5.
            let four = s.sequenced(s.cid, 4).await;
            let five = s.sequenced(s.cid, 5).await;
            s.send(five).await.unwrap();
            assert_eq!(s.network.deliveries(s.cid), [4, 5]);
            s.send(four).await.unwrap();
            assert_eq!(s.network.deliveries(s.cid), [4, 5], "4 is never resent");
            // Racing sends: one holds the in-flight head, the other defers to it.
            let six = s.sequenced(s.cid, 6).await;
            let seven = s.sequenced(s.cid, 7).await;
            let (late, early) = tokio::join!(s.send(seven), s.send(six));
            late.unwrap();
            early.unwrap();
            // The home applies each delivery before answering it.
            assert_eq!(s.network.deliveries(s.cid), [4, 5, 6, 7]);
            assert_eq!(s.mirrored().await, [4, 5, 6, 7]);
            assert!(
                queue_rows(&s.seq_pool, s.cid).await.is_empty(),
                "a delivered entry leaves no queued ciphertext"
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn group_entries_queue_behind_a_partitioned_predecessor_and_deliver_in_seq_order() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            // The partition fails entry 4: it backs off at the head of its stream.
            s.network.partition(true);
            let four = s.sequenced(cid, 4).await;
            assert!(s.send(four).await.is_err());
            // Healed, entries 5..=15 still never go around the queued 4.
            s.network.partition(false);
            for seq in 5..=15 {
                let fanout = s.sequenced(cid, seq).await;
                s.send(fanout)
                    .await
                    .expect("queued behind its predecessor, not failed");
            }
            assert!(s.network.deliveries(cid).is_empty(), "no send around 4");
            let rows = queue_rows(&s.seq_pool, cid).await;
            assert_eq!(rows.len(), 12);
            assert!(rows.iter().all(|row| row.2 == "pending"));

            // Transient failures never dead-letter the head of the stream, and
            // nothing behind it is claimable meanwhile.
            s.network.partition(true);
            for attempt in 2..=7 {
                let (id, _, _, _, due, _) = s.head(cid).await;
                assert!(id.contains(&format!("{cid}-4-")), "{id}");
                s.clock.set_utc(due);
                assert_eq!(s.drain_once().await, 1, "only the head is eligible");
                assert_eq!(s.head(cid).await.3, attempt);
            }

            // After the heal the queue delivers 4, then each successor, by seq
            // (9 before 10 although every id shares one created_at).
            s.network.partition(false);
            s.clock.set_utc(s.head(cid).await.4);
            for _ in 4..=15 {
                assert_eq!(s.drain_once().await, 1);
            }
            assert_eq!(s.network.deliveries(cid), (4..=15).collect::<Vec<_>>());
            assert!(queue_rows(&s.seq_pool, cid).await.is_empty());
            assert_eq!(
                s.mirrored().await,
                (4..=15).collect::<Vec<_>>(),
                "mirror complete"
            );

            // An unprovisioned mirror answers a typed predecessor gap (409
            // `PredecessorMissing`): retried in order without exhausting,
            // never dead-lettered.
            let gap = Uuid::new_v4();
            let fanout = s.sequenced(gap, 1).await;
            let error = s.send(fanout).await.unwrap_err();
            assert!(error.contains("409"), "{error}");
            assert_eq!(s.head(gap).await.3, 0, "the gap consumed no attempt");
            s.clock.set_utc(s.head(gap).await.4);
            assert_eq!(s.drain_once().await, 1);
            let (status, retries, last_error): (String, i32, String) = sqlx::query_as(
                "SELECT status, retry_count, last_error FROM outbound_queue WHERE convo_id = $1",
            )
            .bind(gap.to_string())
            .fetch_one(&s.seq_pool)
            .await
            .unwrap();
            assert_eq!((status.as_str(), retries), ("pending", 0));
            assert!(
                last_error.starts_with(crate::federation::errors::PREDECESSOR_MISSING_ERROR),
                "{last_error}"
            );
            let dead: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM outbound_queue WHERE status IN ('dead', 'failed')",
            )
            .fetch_one(&s.seq_pool)
            .await
            .unwrap();
            assert_eq!(dead, 0);
        }),
    )
    .await;
}

/// Under load a kick's claim statement can snapshot 4 as its stream's due head
/// and reach 4's row lock only after the worker's claim of 4 committed. The
/// lock rechecks the claim against the row the worker holds in flight, so 4
/// keeps one sender. If that sender dies mid-send, 5 still waits behind 4 until
/// 4's lease expires and the queue re-sends 4; a late send is only ever 4 again.
#[tokio::test]
async fn a_claim_that_snapshots_a_head_before_a_rival_claims_it_never_sends_it_twice() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            let four = s.sequenced(cid, 4).await;
            let five = s.sequenced(cid, 5).await;
            // A cursor holds the kick's statement between its snapshot and its lock.
            let mut kick = s.seq_pool.begin().await.unwrap();
            sqlx::query(&format!("DECLARE kick CURSOR FOR {CLAIM_DUE_HEADS_SQL}"))
                .bind(1_i64)
                .bind(current_utc())
                .bind(cid.to_string())
                .bind(HOME)
                .bind("blue.catbird.mlsDS.deliverGroupEntry")
                .execute(&mut *kick)
                .await
                .unwrap();
            let worker = s.queue.claim_due_batch(10).await.unwrap();
            assert_eq!(worker.len(), 1);
            assert!(
                worker[0].id.contains(&format!("{cid}-4-")),
                "{}",
                worker[0].id
            );
            let rival: Vec<(String,)> = sqlx::query_as("FETCH ALL FROM kick")
                .fetch_all(&mut *kick)
                .await
                .unwrap();
            kick.commit().await.unwrap();
            assert!(rival.is_empty(), "a second claim of in-flight 4: {rival:?}");

            // The worker dies holding 4: the kicks send nothing around it, and
            // once its 120 s lease expires the queue re-sends 4, then 5.
            s.send(five).await.unwrap();
            assert!(s.network.deliveries(cid).is_empty(), "5 never overtakes 4");
            s.clock.advance(chrono::TimeDelta::seconds(121));
            assert_eq!(s.drain_once().await, 1);
            s.send(four).await.unwrap();
            assert_eq!(s.network.deliveries(cid), [4, 5]);

            // The dead sender's late request is 4, which the home already holds.
            let sign = |target: &str, method: &str| {
                s.auth
                    .sign_request(target, method)
                    .map_err(|error| error.to_string())
            };
            s.queue.process_item(&worker[0], &s.outbound, &sign).await;
            assert_eq!(s.network.deliveries(cid), [4, 5, 4]);
            assert_eq!(s.mirrored().await, [4, 5]);
            assert!(queue_rows(&s.seq_pool, cid).await.is_empty());
        }),
    )
    .await;
}

const LATE: &str = "did:web:late-member.example.com";
const ADMIN: &str = "did:web:group-admin.example.com";

/// An account's device whose key HOME retained.
struct Actor {
    did: &'static str,
    device: Uuid,
    key_id: String,
    key: ed25519_dalek::SigningKey,
}

impl Actor {
    async fn at_home(s: &GroupStream, did: &'static str, seed: u8) -> Self {
        let device = Uuid::new_v4();
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let key_id = seed_actor_at(
            &s.home_pool,
            did,
            device,
            &key.verifying_key().to_bytes(),
            clock_now(&s.home_pool).await,
        )
        .await;
        Self {
            did,
            device,
            key_id,
            key,
        }
    }

    /// This device's signed `entry_type` entry `seq` over `body`, with the
    /// entry kind's sequencer-recorded `server_fields`.
    fn entry(
        &self,
        entry_type: &str,
        mut body: Value,
        cid: Uuid,
        seq: i64,
        server_fields: Value,
    ) -> Value {
        let at = current_utc().to_rfc3339_opts(SecondsFormat::Millis, true);
        body["actorDid"] = json!(self.did);
        body["actorDeviceId"] = json!(self.device);
        body["keyId"] = json!(self.key_id);
        body["authGeneration"] = json!(1);
        body["idempotencyKey"] = json!(Uuid::new_v4());
        body["signedAt"] = json!(at);
        let signed =
            crate::chat_protocol::test_support::sign_mutation_json_for_test(&body, &self.key)
                .unwrap();
        let mut entry = json!({
            "$type": format!("blue.catbird.chat.defs#{entry_type}"),
            "conversationId": cid,
            "entryId": Uuid::new_v4(),
            "seq": seq,
            "receivedAt": at,
            "signedRequest": signed,
        });
        if let Value::Object(fields) = server_fields {
            entry.as_object_mut().unwrap().extend(fields);
        }
        crate::chat_protocol::transcript::decode_and_verify_control_entry(
            &serde_json::to_vec(&entry).unwrap(),
            &self.key.verifying_key().to_bytes(),
        )
        .unwrap_or_else(|error| panic!("a well-formed signed {entry_type}: {error:?}"));
        entry
    }
}

const GROUP_ID: [u8; 32] = [0x61; 32];
const CONTEXT_HASH: [u8; 32] = [0x62; 32];
const CONFIRMATION_TAG: [u8; 32] = [0x63; 32];
const KEY_PACKAGE_REF: [u8; 32] = [0x64; 32];

/// `cid`'s coordinates at `state_version`, in signed-body presentation.
fn signed_coordinates(cid: Uuid, state_version: i64) -> Value {
    json!({
        "conversationId": cid,
        "generation": 0,
        "stateVersion": state_version,
        "groupId": STANDARD.encode(GROUP_ID),
        "epoch": 1,
        "groupContextHash": STANDARD.encode(CONTEXT_HASH),
        "confirmationTag": STANDARD.encode(CONFIRMATION_TAG),
        "lifecycle": "active",
    })
}

/// The administrator's signed policy entry `seq` applying `changes`.
fn policy_entry(admin: &Actor, cid: Uuid, seq: i64, transition: Uuid, changes: Value) -> Value {
    admin.entry(
        "policyEntry",
        json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\u{0}",
            "transitionId": transition,
            "prior": signed_coordinates(cid, seq),
            "next": signed_coordinates(cid, seq + 1),
            "participantChanges": changes,
        }),
        cid,
        seq,
        json!({}),
    )
}

fn provenance(admin: &Actor, transition: Uuid) -> Value {
    json!({
        "invitationTransitionId": transition,
        "invitedByDid": admin.did,
        "invitedByDeviceId": admin.device,
    })
}

/// `admin`'s invitation of LATE in policy transition `transition`.
fn invite(admin: &Actor, transition: Uuid) -> Value {
    json!([{
        "$type": "blue.catbird.chat.defs#addParticipant",
        "userDid": LATE,
        "role": "member",
        "status": "pending",
        "invitationProvenance": provenance(admin, transition),
    }])
}

fn remove(user: &str) -> Value {
    json!([{"$type": "blue.catbird.chat.defs#removeParticipant", "userDid": user}])
}

/// A base64 artifact and its SHA-256, in wire presentation.
fn artifact(bytes: &[u8]) -> (String, String) {
    (
        STANDARD.encode(bytes),
        STANDARD.encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)),
    )
}

/// `invitee`'s own signed acceptance at `seq` of the invitation `provenance`,
/// with the add-recovery reservation SEQ recorded beside it.
fn acceptance_entry(invitee: &Actor, cid: Uuid, seq: i64, provenance: Value) -> Value {
    let recovery = Uuid::new_v4();
    let at = current_utc().to_rfc3339_opts(SecondsFormat::Millis, true);
    let bound = signed_coordinates(cid, seq + 1);
    let (key_package, key_package_sha256) = artifact(b"opaque-test-key-package");
    invitee.entry(
        "participantAcceptanceEntry",
        json!({
            "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
            "signatureDomain": "CATBIRD-CHAT-ACCEPT\u{0}",
            "transitionId": Uuid::new_v4(),
            "recoveryRequestId": recovery,
            "prior": signed_coordinates(cid, seq),
            "next": bound,
            "invitationProvenance": provenance,
        }),
        cid,
        seq,
        json!({"recovery": {
            "recoveryRequestId": recovery,
            "conversationId": cid,
            "requesterDid": invitee.did,
            "requesterDeviceId": invitee.device,
            "recoveryKind": "add",
            "boundCoordinate": bound,
            "reservation": {
                "recoveryRequestId": recovery,
                "conversationId": cid,
                "boundCoordinate": bound,
                "requesterDid": invitee.did,
                "requesterDeviceId": invitee.device,
                "requesterKeyId": invitee.key_id,
                "requesterAuthGeneration": 1,
                "keyPackageRef": STANDARD.encode(KEY_PACKAGE_REF),
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": at,
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": key_package,
                    "sha256": key_package_sha256,
                    "keyPackageRef": STANDARD.encode(KEY_PACKAGE_REF),
                },
            },
            "status": "open",
            "requestedAt": at,
            "expiresAt": at,
        }}),
    )
}

/// `admin`'s signed fulfilment at `seq` of `invitee`'s add recovery: one
/// Welcome `welcome` for `invitee`'s device.
fn fulfilment_entry(admin: &Actor, invitee: &Actor, cid: Uuid, seq: i64, welcome: Uuid) -> Value {
    let recovery = Uuid::new_v4();
    let transition = Uuid::new_v4();
    let identifier = |id: Uuid| STANDARD.encode(id.as_bytes());
    let (commit, commit_sha256) = artifact(b"opaque-test-commit");
    let (opaque_welcome, welcome_sha256) = artifact(b"opaque-test-welcome");
    let (ciphertext, ciphertext_sha256) = artifact(&[0x65; 16]);
    admin.entry(
        "leafRecoveryFulfillmentEntry",
        json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0}",
            "recoveryRequestId": recovery,
            "transitionId": transition,
            "prior": signed_coordinates(cid, seq),
            "next": signed_coordinates(cid, seq + 1),
            "aad": {
                "protocolVersion": "1",
                "conversationId": identifier(cid),
                "generation": 0,
                "transitionId": identifier(transition),
                "prior": {
                    "conversationId": identifier(cid),
                    "generation": 0,
                    "stateVersion": seq,
                    "groupId": STANDARD.encode(GROUP_ID),
                    "epoch": 1,
                    "groupContextHash": STANDARD.encode(CONTEXT_HASH),
                    "confirmationTag": STANDARD.encode(CONFIRMATION_TAG),
                    "lifecycle": "active",
                },
            },
            "manifest": {
                "participantChanges": [],
                "leafChanges": [],
                "welcomeBundle": {
                    "welcomeId": welcome,
                    "framing": "mlsMessage",
                    "contentType": "welcome",
                    "opaqueWelcome": opaque_welcome,
                    "sha256": welcome_sha256,
                    "deliveries": [{
                        "recipientDid": invitee.did,
                        "recipientDeviceId": invitee.device,
                        "provenance": {
                            "recoveryRequestId": recovery,
                            "keyPackageRef": STANDARD.encode(KEY_PACKAGE_REF),
                        },
                    }],
                },
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": commit,
                "sha256": commit_sha256,
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": identifier(cid),
                    "generation": 0,
                    "groupId": STANDARD.encode(GROUP_ID),
                    "epoch": 2,
                    "groupContextHash": STANDARD.encode(CONTEXT_HASH),
                    "confirmationTag": STANDARD.encode(CONFIRMATION_TAG),
                },
                "originTransitionId": transition,
                "metadataVersion": 1,
                "nonce": STANDARD.encode([0x66; 12]),
                "ciphertext": ciphertext,
                "ciphertextSha256": ciphertext_sha256,
                "ciphertextSize": 16,
                "authorProof": {
                    "authorDid": admin.did,
                    "authorDeviceId": admin.device,
                    "authorKeyId": admin.key_id,
                    "signaturePublicKey": STANDARD.encode(admin.key.verifying_key().to_bytes()),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": transition,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
        }),
        cid,
        seq,
        json!({}),
    )
}

/// An entry kind the home's membership index ignores.
fn unsigned_entry(cid: Uuid, seq: i64, entry_type: &str, body_type: &str) -> Value {
    json!({
        "$type": entry_type,
        "conversationId": cid,
        "entryId": Uuid::new_v4(),
        "seq": seq,
        "signedRequest": {"body": {"$type": body_type}},
    })
}

impl GroupStream {
    /// `entry`, queued for HOME in its own committed sequencing transaction
    /// with the frozen device audience `devices`.
    async fn queued(&self, entry: Value, devices: &[(&str, Uuid)]) -> PreparedGroupEntryFanout {
        let fanout = PreparedGroupEntryFanout::for_test(
            SEQ,
            HOME,
            DeliverGroupEntryRequest {
                conversation_id: self.cid,
                generation: 0,
                space_uri: format!(
                    "at://{SEQ}/space/blue.catbird.labyrinth.conversation/{}-0",
                    self.cid
                ),
                recipient_dids: devices.iter().map(|(did, _)| did.to_string()).collect(),
                recipient_devices: devices
                    .iter()
                    .map(|(did, device)| (did.to_string(), *device))
                    .collect(),
                entry,
                close_authority: None,
            },
        );
        let mut tx = self.seq_pool.begin().await.unwrap();
        fanout.enqueue(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        fanout
    }

    /// `(status, evidence_seq)` of `user`'s HOME index row.
    async fn indexed(&self, user: &str) -> Option<(String, i64)> {
        sqlx::query_as(
            "SELECT status, evidence_seq FROM chat.remote_group_memberships \
              WHERE conversation_id = $1 AND user_did = $2",
        )
        .bind(self.cid)
        .bind(user)
        .fetch_optional(&self.home_pool)
        .await
        .unwrap()
    }

    /// The seqs HOME granted `device` of `user`.
    async fn granted(&self, user: &str, device: Uuid) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT seq FROM chat.group_transport_entry_recipients \
              WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3 ORDER BY seq",
        )
        .bind(self.cid)
        .bind(user)
        .bind(device)
        .fetch_all(&self.home_pool)
        .await
        .unwrap()
    }

    /// `(welcome_id, evidence_seq)` of the Welcome markers HOME keeps for
    /// `device` of `user`.
    async fn welcome_markers(&self, user: &str, device: Uuid) -> Vec<(Uuid, i64)> {
        sqlx::query_as(
            "SELECT welcome_id, evidence_seq FROM chat.remote_group_pending_welcomes \
              WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3 \
              ORDER BY evidence_seq",
        )
        .bind(self.cid)
        .bind(user)
        .bind(device)
        .fetch_all(&self.home_pool)
        .await
        .unwrap()
    }

    async fn standing(&self, user: &str) -> RemoteGroupStanding {
        let mut conn = self.home_pool.acquire().await.unwrap();
        remote_group_standing(&mut conn, self.cid, user)
            .await
            .unwrap()
    }
}

/// An account homed at HOME is invited into SEQ's group only after a commit, a
/// metadata change and a removal, which the mirror's prefix replay cannot
/// follow. HOME learns the membership from SEQ's ordered, actor-signed policy
/// entry, even across a partition, and grants the member's device exactly the
/// entries addressed to it from then on. The signed removal ends every read;
/// a late redelivery of the older invitation never revives it.
#[tokio::test]
async fn a_late_invitee_joins_its_homes_index_through_a_partition_and_a_removal_ends_its_reads() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x5a).await;
    let invitee = Actor::at_home(&s, LATE, 0x5b).await;
    let late_device = invitee.device;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(LATE, HOME);
    let late = [(LATE, late_device)];

    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            // History the prefix replay cannot follow; none of it names LATE.
            for (seq, entry_type, body_type) in [
                (4, "commitEntry", "commitTransitionBody"),
                (5, "metadataEntry", "metadataTransitionBody"),
                (6, "policyEntry", "policyTransitionBody"),
            ] {
                let entry = unsigned_entry(
                    cid,
                    seq,
                    &format!("blue.catbird.chat.defs#{entry_type}"),
                    &format!("blue.catbird.chat.defs#{body_type}"),
                );
                s.send(s.queued(entry, &[]).await).await.unwrap();
            }
            assert_eq!(s.indexed(LATE).await, None);

            // The invitation and two entries addressed to LATE meet a partition:
            // each backs off at the head of the stream, in order.
            s.network.partition(true);
            let transition = Uuid::new_v4();
            let invitation = policy_entry(&admin, cid, 7, transition, invite(&admin, transition));
            assert!(s
                .send(s.queued(invitation.clone(), &late).await)
                .await
                .is_err());
            for seq in 8..=9 {
                let entry = json!({
                    "$type": "blue.catbird.chat.defs#applicationEntry",
                    "conversationId": cid,
                    "entryId": Uuid::new_v4(),
                    "seq": seq,
                });
                s.send(s.queued(entry, &late).await)
                    .await
                    .expect("queued behind the invitation");
            }
            assert_eq!(s.network.deliveries(cid), [4, 5, 6]);
            assert_eq!(s.indexed(LATE).await, None, "nothing crossed the partition");

            s.network.partition(false);
            s.clock.set_utc(s.head(cid).await.4);
            for _ in 7..=9 {
                assert_eq!(s.drain_once().await, 1);
            }
            assert_eq!(s.network.deliveries(cid), (4..=9).collect::<Vec<_>>());
            assert_eq!(s.indexed(LATE).await, Some(("pending".into(), 7)));
            assert_eq!(s.standing(LATE).await, RemoteGroupStanding::IndexOnly);
            assert_eq!(s.granted(LATE, late_device).await, [7, 8, 9]);

            // The signed removal ends LATE's membership: no grant for it or
            // for anything after, and no reads at all.
            let removal = policy_entry(&admin, cid, 10, Uuid::new_v4(), remove(LATE));
            s.send(s.queued(removal, &late).await).await.unwrap();
            let after = json!({
                "$type": "blue.catbird.chat.defs#applicationEntry",
                "conversationId": cid,
                "entryId": Uuid::new_v4(),
                "seq": 11,
            });
            s.send(s.queued(after, &late).await).await.unwrap();
            assert_eq!(s.indexed(LATE).await, Some(("removed".into(), 10)));
            assert_eq!(s.standing(LATE).await, RemoteGroupStanding::Removed);
            assert_eq!(s.granted(LATE, late_device).await, [7, 8, 9]);

            // A late redelivery of the older invitation changes nothing.
            s.send(s.queued(invitation, &late).await).await.unwrap();
            assert_eq!(s.network.deliveries(cid), [4, 5, 6, 7, 8, 9, 10, 11, 7]);
            assert_eq!(s.indexed(LATE).await, Some(("removed".into(), 10)));
            assert_eq!(s.granted(LATE, late_device).await, [7, 8, 9]);

            assert!(queue_rows(&s.seq_pool, cid).await.is_empty());
            let dead: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM outbound_queue WHERE status IN ('dead', 'failed')",
            )
            .fetch_one(&s.seq_pool)
            .await
            .unwrap();
            assert_eq!(dead, 0, "the partition dead-lettered nothing");
        }),
    )
    .await;
}

/// A policy entry naming a local account that its actor's key does not verify
/// never enters the index, and its delivery is refused rather than stored.
#[tokio::test]
async fn an_invitation_its_actor_did_not_sign_never_enters_the_homes_index() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x5c).await;
    let late_device = Actor::at_home(&s, LATE, 0x5d).await.device;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(LATE, HOME);
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            let transition = Uuid::new_v4();
            let mut forged = policy_entry(&admin, cid, 4, transition, invite(&admin, transition));
            forged["signedRequest"]["signature"] = json!(STANDARD.encode([0_u8; 64]));
            let error = s
                .send(s.queued(forged, &[(LATE, late_device)]).await)
                .await
                .unwrap_err();
            assert!(error.contains("401"), "{error}");
            assert_eq!(s.indexed(LATE).await, None);
            assert!(s.granted(LATE, late_device).await.is_empty());
            assert!(
                s.mirrored().await.is_empty(),
                "the forged entry is not stored"
            );
        }),
    )
    .await;
}

/// DQ.G11: the fan-out keeps the home's typed answer. A permanent refusal
/// (the unsigned invitation above) ends its entry at once instead of being
/// retried forever; a send the partition stopped decided nothing and is
/// retried with backoff, one attempt in.
#[tokio::test]
async fn a_fanout_refusal_is_dead_at_once_and_a_partitioned_send_is_retried() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x6c).await;
    let late_device = Actor::at_home(&s, LATE, 0x6d).await.device;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(LATE, HOME);
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            let transition = Uuid::new_v4();
            let mut forged = policy_entry(&admin, cid, 4, transition, invite(&admin, transition));
            forged["signedRequest"]["signature"] = json!(STANDARD.encode([0_u8; 64]));
            s.send(s.queued(forged, &[(LATE, late_device)]).await)
                .await
                .unwrap_err();
            let refused: Vec<(String, i32)> = queue_rows(&s.seq_pool, cid)
                .await
                .into_iter()
                .map(|row| (row.2, row.3))
                .collect();
            assert_eq!(refused, [("dead".to_owned(), 0)]);

            let partitioned = Uuid::new_v4();
            s.network.partition(true);
            s.send(s.sequenced(partitioned, 1).await).await.unwrap_err();
            let head = s.head(partitioned).await;
            assert_eq!((head.2.as_str(), head.3), ("pending", 1));
        }),
    )
    .await;
}

/// The invitee's own acceptance and the administrator's fulfilment reach its
/// home in order across a partition: HOME's index turns the pending member
/// active and records the Welcome its device fetches by relay; the signed
/// removal that follows clears that Welcome and every later grant.
#[tokio::test]
async fn an_invitees_acceptance_and_fulfilment_cross_a_partition_into_its_homes_index() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x5e).await;
    let invitee = Actor::at_home(&s, LATE, 0x5f).await;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(LATE, HOME);
    let audience = [(LATE, invitee.device)];
    let welcome = Uuid::new_v4();
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            let transition = Uuid::new_v4();
            let invitation = policy_entry(&admin, cid, 4, transition, invite(&admin, transition));
            s.send(s.queued(invitation, &audience).await).await.unwrap();
            assert_eq!(s.indexed(LATE).await, Some(("pending".into(), 4)));
            assert!(s.welcome_markers(LATE, invitee.device).await.is_empty());

            s.network.partition(true);
            let acceptance = acceptance_entry(&invitee, cid, 5, provenance(&admin, transition));
            assert!(s.send(s.queued(acceptance, &audience).await).await.is_err());
            let fulfilment = fulfilment_entry(&admin, &invitee, cid, 6, welcome);
            s.send(s.queued(fulfilment, &audience).await)
                .await
                .expect("queued behind the acceptance");
            assert_eq!(s.indexed(LATE).await, Some(("pending".into(), 4)));

            s.network.partition(false);
            s.clock.set_utc(s.head(cid).await.4);
            for _ in 5..=6 {
                assert_eq!(s.drain_once().await, 1);
            }
            assert_eq!(s.network.deliveries(cid), [4, 5, 6]);
            assert_eq!(s.indexed(LATE).await, Some(("active".into(), 5)));
            assert_eq!(s.standing(LATE).await, RemoteGroupStanding::IndexOnly);
            assert_eq!(
                s.welcome_markers(LATE, invitee.device).await,
                [(welcome, 6)]
            );
            assert_eq!(s.granted(LATE, invitee.device).await, [4, 5, 6]);

            let removal = policy_entry(&admin, cid, 7, Uuid::new_v4(), remove(LATE));
            s.send(s.queued(removal, &audience).await).await.unwrap();
            assert_eq!(s.indexed(LATE).await, Some(("removed".into(), 7)));
            assert!(s.welcome_markers(LATE, invitee.device).await.is_empty());
            assert_eq!(s.granted(LATE, invitee.device).await, [4, 5, 6]);
            assert!(queue_rows(&s.seq_pool, cid).await.is_empty());
        }),
    )
    .await;
}

/// A reader locks its device row, then conversation heads. A delivery whose
/// grant references that device takes its device locks before the head, so
/// the reader still gets the head: the delivery waits for it, then lands.
#[tokio::test]
async fn a_delivery_waits_for_a_readers_device_lock_before_taking_the_head() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x60).await;
    let invitee = Actor::at_home(&s, LATE, 0x61).await;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(LATE, HOME);
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(Arc::clone(&s.seq_hooks), async {
            let mut reader = s.home_pool.begin().await.unwrap();
            sqlx::query(
                "SELECT 1 FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
            )
            .bind(LATE)
            .bind(invitee.device)
            .fetch_one(&mut *reader)
            .await
            .unwrap();
            let transition = Uuid::new_v4();
            let invitation = policy_entry(&admin, cid, 4, transition, invite(&admin, transition));
            let fanout = s.queued(invitation, &[(LATE, invitee.device)]).await;
            let read_head = async {
                // Once the delivery waits on a lock, the reader takes the head. A
                // row-lock waiter waits on the holder's transaction id, which
                // `pg_locks` lists with a NULL database: match the waiting backend.
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        let waiting: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM pg_stat_activity \
                              WHERE datname = current_database() AND wait_event_type = 'Lock'",
                        )
                        .fetch_one(&s.home_pool)
                        .await
                        .unwrap();
                        if waiting > 0 {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the delivery waits on the reader's device lock");
                let head = sqlx::query(
                    "SELECT 1 FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
                )
                .bind(cid)
                .fetch_one(&mut *reader)
                .await
                .map(|_| ());
                (head, reader.commit().await)
            };
            let ((head, committed), delivered) = tokio::join!(read_head, s.send(fanout));
            head.expect("the reader takes the head after its device row");
            committed.unwrap();
            delivered.expect("the delivery lands once the reader commits");
            assert_eq!(s.indexed(LATE).await, Some(("pending".into(), 4)));
            assert_eq!(s.granted(LATE, invitee.device).await, [4]);
        }),
    )
    .await;
}

use super::entry_ack_relay::{
    accept_entries_pruned_notice, enqueue_entries_pruned_notice, EntriesPrunedNotice,
};

fn signed_notice(
    key: &SigningKey,
    sequencer_did: &str,
    home_did: &str,
    conversation_id: Uuid,
    seqs: Vec<i64>,
) -> EntriesPrunedNotice {
    let mut notice = EntriesPrunedNotice {
        sequencer_did: sequencer_did.to_owned(),
        home_did: home_did.to_owned(),
        conversation_id,
        generation: 0,
        seqs,
        signature: String::new(),
    };
    let signature: Signature = key.sign(&notice.signing_bytes());
    notice.signature = STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes());
    notice
}

#[tokio::test]
async fn a_sequencer_prune_without_the_remote_member_ack_notifies_its_home() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let fixture = seed_clean_slate_application_fixture_unsealed(
        &pool,
        false,
        SEQ,
        Some([0x5b; 32]),
        Some(HOME),
    )
    .await
    .unwrap();
    let cid = fixture.conversation_id;
    let (seq_key, home_key) = (key(0x31), key(0x32));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    let state = GroupRelayState::for_test(
        pool.clone(),
        SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(I13ReceiptSigner::new(
            seq_key.clone(),
            SEQ.to_owned(),
        ))),
    )
    .with_sim_hooks(Arc::clone(&seq_hooks))
    .with_clock(clock.clone());
    let queue = OutboundQueue::new(
        pool.clone(),
        AuthMiddleware::new(),
        Arc::new(resolver(&pool, SEQ)),
    );

    scope_ds_clock(
        clock.clone(),
        scope_sim_ds(seq_hooks, async {
            let request = RelayGroupMutationRequest {
                conversation_id: cid,
                endpoint: "blue.catbird.chat.sendMessage".to_owned(),
                actor_did: fixture.sender_did.clone(),
                actor_device_id: fixture.sender_device_id,
                signed_request: fixture.signed_request.clone(),
                signed_request_bytes: None,
            };
            // HOME is unreachable, so the entry fanned out to it stays queued.
            let seq = sequence_relayed_group_application_send(&state, HOME, &request)
                .await
                .expect("sequence the remote member's application")
                .entry["seq"]
                .as_i64()
                .unwrap();
            // The remote-homed device never ACKs again: like its removal, its
            // dormancy drops it from the audience the sequencer waits for,
            // while its home's mirror still counts it.
            sqlx::query(
                "UPDATE chat.devices SET dormant_at = $3 WHERE user_did = $1 AND device_id = $2",
            )
            .bind(&fixture.sender_did)
            .bind(fixture.sender_device_id)
            .bind(current_utc())
            .execute(&pool)
            .await
            .unwrap();
            for expected_pruned in [1, 0] {
                let ack = local_ack(
                    &pool,
                    &fixture.recipient_did,
                    ack_body(
                        fixture.recipient_device_id,
                        &fixture.recipient_key_id,
                        &fixture.recipient_ed25519_seed,
                        cid,
                        seq,
                    ),
                )
                .await;
                assert_eq!(ack["prunedCount"], expected_pruned);
                let notices: Vec<QueueRow> = queue_rows(&pool, cid)
                    .await
                    .into_iter()
                    .filter(|row| row.0.starts_with("entries-pruned-"))
                    .collect();
                assert_eq!(notices.len(), 1, "one notice per pruned set and home");
                let (id, target, status, retries, due, payload) = &notices[0];
                assert_eq!(id, &format!("entries-pruned-{cid}-{seq:020}-{HOME}"));
                assert_eq!(
                    (target.as_str(), status.as_str(), *retries),
                    (HOME, "pending", 0)
                );
                assert!(*due <= current_utc(), "the notice is due immediately");
                let notice: EntriesPrunedNotice = serde_json::from_slice(payload).unwrap();
                let signature =
                    Signature::from_slice(&STANDARD.decode(&notice.signature).unwrap()).unwrap();
                seq_key
                    .verifying_key()
                    .verify(&notice.signing_bytes(), &signature)
                    .expect("signed by the sequencer's #atproto key");
                assert_eq!(notice, signed_notice(&seq_key, SEQ, HOME, cid, vec![seq]));
            }
            // The notice waits behind HOME's undelivered entry.
            clock.advance(chrono::TimeDelta::seconds(6));
            let claimed = queue.claim_due_batch(10).await.unwrap();
            assert_eq!(
                claimed
                    .iter()
                    .map(|item| item.method.as_str())
                    .collect::<Vec<_>>(),
                ["blue.catbird.mlsDS.deliverGroupEntry"]
            );
        }),
    )
    .await;
}

#[tokio::test]
async fn a_group_mirror_prunes_exactly_the_sequences_its_sequencer_notifies() {
    crate::federation::open_federation_for_test();
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    prepare(&home_pool).await;
    prepare(&seq_pool).await;
    let mirror = seed_remote_group_application_routing_fixture(&home_pool, HOME, SEQ)
        .await
        .unwrap();
    let local = crate::chat_protocol::test_support::seed_clean_slate_application_fixture(
        &home_pool, false, HOME, None,
    )
    .await
    .unwrap()
    .conversation_id;
    let cid = mirror.conversation_id;
    // The mirror holds the application at seq 4 with its I13 receipt.
    let entry_id = Uuid::new_v4();
    let entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": entry_id,
        "conversationId": cid,
        "seq": 4,
        "receivedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": mirror.signed_request,
        "sequencerReceipt": { "sequencerDid": SEQ, "seq": 4 },
    });
    let original = serde_json::to_vec(&entry).unwrap();
    crate::chat_protocol::repository::delivery::insert_transport_entry(
        &mut home_pool.acquire().await.unwrap(),
        cid,
        4,
        entry_id,
        &original,
        Utc::now(),
    )
    .await
    .unwrap();
    type MirrorRow = (Vec<u8>, Option<DateTime<Utc>>, Vec<u8>, Option<Vec<u8>>);
    let mirror_row = || {
        let pool = home_pool.clone();
        async move {
            sqlx::query_as::<_, MirrorRow>(
                "SELECT entry_bytes, payload_pruned_at, original_entry_sha256, \
                        application_metadata_bytes \
                   FROM chat.direct_request_transport_entries \
                  WHERE conversation_id = $1 AND seq = 4",
            )
            .bind(cid)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let (seq_key, home_key, other_key) = (key(0x31), key(0x32), key(0x33));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key), (OTHER, &other_key)]);
    let clock = manual_clock();
    let home_hooks = hooks(HOME, Some(&home_key), false, &network);
    let home_state =
        GroupRelayState::for_test(home_pool.clone(), HOME.to_owned(), HMAC.as_bytes(), None)
            .with_sim_hooks(Arc::clone(&home_hooks))
            .with_clock(clock.clone());
    network.serve(HOME, group_relay_router(home_state.clone()));
    let queue = OutboundQueue::new(
        seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(resolver(&seq_pool, SEQ)),
    );
    let outbound = OutboundClient::new(5, 5);
    let auth = ServiceAuthClient::from_es256_pem(
        SEQ.to_owned(),
        pem(&seq_key).as_bytes(),
        Some("#atproto".to_owned()),
    )
    .unwrap();
    let auth_sign = move |target: &str, method: &str| {
        auth.sign_request(target, method)
            .map_err(|error| error.to_string())
    };

    scope_ds_clock(clock.clone(), async {
        let unpruned = mirror_row().await;
        assert!(unpruned.1.is_none());
        scope_sim_ds(Arc::clone(&home_hooks), async {
            let genuine = signed_notice(&seq_key, SEQ, HOME, cid, vec![4]);
            let mut wrong_conversation = genuine.clone();
            wrong_conversation.conversation_id = local;
            let mut wrong_generation = genuine.clone();
            wrong_generation.generation = 1;
            let mut wrong_seqs = genuine.clone();
            wrong_seqs.seqs = vec![3, 4];
            let mut wrong_signature = genuine.clone();
            let mut signature = STANDARD.decode(&genuine.signature).unwrap();
            signature[63] ^= 1;
            wrong_signature.signature = STANDARD.encode(signature);
            let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
            let tampered = (StatusCode::FORBIDDEN, "InvalidSignature");
            let cases = [
                // Another DS, even one signing for itself, is not the sequencer.
                (
                    OTHER,
                    signed_notice(&other_key, OTHER, HOME, cid, vec![4]),
                    forbidden,
                ),
                (OTHER, genuine.clone(), forbidden),
                (
                    SEQ,
                    signed_notice(&seq_key, SEQ, OTHER, cid, vec![4]),
                    forbidden,
                ),
                // Only this sequencer's group mirror follows its notices.
                (
                    SEQ,
                    signed_notice(&seq_key, SEQ, HOME, local, vec![4]),
                    forbidden,
                ),
                (
                    SEQ,
                    signed_notice(&seq_key, SEQ, HOME, Uuid::new_v4(), vec![4]),
                    (StatusCode::NOT_FOUND, "ConversationNotFound"),
                ),
                (
                    SEQ,
                    signed_notice(&seq_key, SEQ, HOME, cid, vec![4, 4]),
                    (StatusCode::BAD_REQUEST, "InvalidRequest"),
                ),
                // Every signed field, altered after signing.
                (SEQ, wrong_conversation, tampered),
                (SEQ, wrong_generation, tampered),
                (SEQ, wrong_seqs, tampered),
                (SEQ, wrong_signature, tampered),
            ];
            for (caller, notice, (status, code)) in cases {
                let response = accept_entries_pruned_notice(
                    &home_state,
                    caller,
                    &serde_json::to_vec(&notice).unwrap(),
                )
                .await
                .expect_err("the notice must be rejected");
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
                assert_eq!(mirror_row().await, unpruned, "a rejection changes nothing");
            }
        })
        .await;

        // The sequencer's queue delivers the notice; a partition is retried.
        scope_sim_ds(hooks(SEQ, Some(&seq_key), false, &network), async {
            let mut tx = seq_pool.begin().await.unwrap();
            enqueue_entries_pruned_notice(&mut tx, HOME, cid, 0, &[4], current_utc())
                .await
                .unwrap();
            tx.commit().await.unwrap();
            network.partition(true);
            queue
                .process_pending_batch(&outbound, &auth_sign)
                .await
                .unwrap();
            let rows = queue_rows(&seq_pool, cid).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(
                (rows[0].1.as_str(), rows[0].2.as_str(), rows[0].3),
                (HOME, "pending", 1)
            );
            assert_eq!(mirror_row().await, unpruned);
            network.partition(false);
            clock.set_utc(rows[0].4);
            let delivered = queue
                .process_pending_batch(&outbound, &auth_sign)
                .await
                .unwrap();
            assert_eq!(delivered, 1);
            assert_eq!(queue_rows(&seq_pool, cid).await[0].2, "delivered");
        })
        .await;
        let (bytes, pruned_at, digest, metadata) = mirror_row().await;
        assert!(pruned_at.is_some(), "the notified sequence is pruned");
        assert_eq!(digest, Sha256::digest(&original).to_vec());
        assert!(metadata.is_some());
        assert_eq!(metadata, unpruned.3, "immutable metadata is retained");
        let projection: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(projection["payloadPruned"], true);
        assert_eq!(projection["sequencerReceipt"], entry["sequencerReceipt"]);
        assert!(projection.get("signedRequest").is_none());

        // A redelivered notice is an idempotent no-op.
        let pruned = mirror_row().await;
        let payload = queue_rows(&seq_pool, cid).await.remove(0).5;
        let out = scope_sim_ds(
            Arc::clone(&home_hooks),
            accept_entries_pruned_notice(&home_state, SEQ, &payload),
        )
        .await
        .expect("a duplicate notice is accepted");
        assert_eq!(
            (out["accepted"].as_bool(), out["prunedCount"].as_u64()),
            (Some(true), Some(0))
        );
        assert_eq!(mirror_row().await, pruned);
    })
    .await;
}

/// The queued `entries-pruned-` notices of `conversation_id`.
async fn notice_rows(pool: &DbPool, conversation_id: Uuid) -> Vec<QueueRow> {
    queue_rows(pool, conversation_id)
        .await
        .into_iter()
        .filter(|row| row.0.starts_with("entries-pruned-"))
        .collect()
}

/// A SEQ-sequenced group whose sender is homed at HOME, with one application
/// relayed from HOME and sequenced (and queued for HOME) under `hooks`.
async fn relayed_application(
    pool: &DbPool,
    hooks: Arc<SimDsHooks>,
    clock: Arc<ManualDsClock>,
    seq_key: &SigningKey,
) -> (
    crate::chat_protocol::test_support::CleanSlateApplicationFixture,
    GroupRelayState,
    i64,
) {
    let fixture = seed_clean_slate_application_fixture_unsealed(
        pool,
        false,
        SEQ,
        Some([0x5c; 32]),
        Some(HOME),
    )
    .await
    .unwrap();
    let state = GroupRelayState::for_test(
        pool.clone(),
        SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(I13ReceiptSigner::new(
            seq_key.clone(),
            SEQ.to_owned(),
        ))),
    )
    .with_sim_hooks(Arc::clone(&hooks))
    .with_clock(clock.clone());
    let request = RelayGroupMutationRequest {
        conversation_id: fixture.conversation_id,
        endpoint: "blue.catbird.chat.sendMessage".to_owned(),
        actor_did: fixture.sender_did.clone(),
        actor_device_id: fixture.sender_device_id,
        signed_request: fixture.signed_request.clone(),
        signed_request_bytes: None,
    };
    let seq = scope_ds_clock(
        clock,
        scope_sim_ds(
            hooks,
            sequence_relayed_group_application_send(&state, HOME, &request),
        ),
    )
    .await
    .expect("sequence the remote member's application")
    .entry["seq"]
        .as_i64()
        .unwrap();
    (fixture, state, seq)
}

#[tokio::test]
async fn a_30_day_ceiling_prune_notifies_the_homes_it_fanned_out_to() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let (seq_key, home_key) = (key(0x31), key(0x32));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    let (fixture, _, seq) =
        relayed_application(&pool, Arc::clone(&seq_hooks), clock.clone(), &seq_key).await;
    let cid = fixture.conversation_id;
    let expired = crate::sim_hooks::DsClock::now_utc(clock.as_ref()) + chrono::Duration::days(31);
    let sweep = |hooks: Arc<SimDsHooks>| {
        let pool = pool.clone();
        scope_ds_clock(clock.clone(), async move {
            scope_sim_ds(
                hooks,
                crate::chat_protocol::repository::expiry_sweep::prune_expired_application_payloads(
                    &pool, expired,
                ),
            )
            .await
            .unwrap()
        })
    };
    assert_eq!(ack_state(&pool, cid).await, [0, 0, 1, 1, 1]);

    // Without its signer the sequencer prunes nothing it would have to notify.
    assert_eq!(sweep(hooks(SEQ, None, false, &network)).await, 0);
    assert_eq!(ack_state(&pool, cid).await, [0, 0, 1, 1, 1]);
    assert!(notice_rows(&pool, cid).await.is_empty());

    // The ceiling prune and HOME's signed notice commit together; the I13
    // receipt and immutable evidence stay.
    assert_eq!(sweep(Arc::clone(&seq_hooks)).await, 1);
    assert_eq!(ack_state(&pool, cid).await, [0, 0, 0, 0, 1]);
    let notices = notice_rows(&pool, cid).await;
    assert_eq!(notices.len(), 1);
    let (id, target, status, _, _, payload) = &notices[0];
    assert_eq!(id, &format!("entries-pruned-{cid}-{seq:020}-{HOME}"));
    assert_eq!((target.as_str(), status.as_str()), (HOME, "pending"));
    let notice: EntriesPrunedNotice = serde_json::from_slice(payload).unwrap();
    assert_eq!(notice, signed_notice(&seq_key, SEQ, HOME, cid, vec![seq]));
    // A rerun prunes and notifies nothing more.
    assert_eq!(sweep(seq_hooks).await, 0);
    assert_eq!(notice_rows(&pool, cid).await.len(), 1);
}

#[tokio::test]
async fn effects_needing_a_signed_relay_or_notice_fail_closed_without_a_signer() {
    let (seq_key, home_key) = (key(0x31), key(0x32));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    let clock = manual_clock();
    let refused = |(status, body): (StatusCode, Value)| {
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("CutoverRequired")),
            "{body}"
        );
    };

    // A mirror's device ACK owes its sequencer a signed relay.
    let mirror_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let mirror_pool = mirror_db.connect(4).await;
    prepare(&mirror_pool).await;
    let mirror = seed_remote_clean_slate_application_fixture(&mirror_pool, HOME, SEQ, None)
        .await
        .unwrap();
    scope_ds_clock(
        clock.clone(),
        scope_sim_ds(hooks(HOME, None, false, &network), async {
            let ack = ack_body(
                mirror.recipient_device_id,
                &mirror.recipient_key_id,
                &mirror.recipient_ed25519_seed,
                mirror.conversation_id,
                3,
            );
            refused(ack_response(&mirror_pool, &mirror.recipient_did, ack).await);
            assert_eq!(ack_state(&mirror_pool, mirror.conversation_id).await[0], 0);
            assert!(queue_rows(&mirror_pool, mirror.conversation_id)
                .await
                .is_empty());
        }),
    )
    .await;

    // A sequencer prune owes HOME a signed notice.
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let keyless = hooks(SEQ, None, false, &network);
    let (fixture, state, seq) =
        relayed_application(&pool, Arc::clone(&keyless), clock.clone(), &seq_key).await;
    let cid = fixture.conversation_id;
    scope_ds_clock(
        clock.clone(),
        scope_sim_ds(keyless, async {
            let recipient_ack = || {
                ack_body(
                    fixture.recipient_device_id,
                    &fixture.recipient_key_id,
                    &fixture.recipient_ed25519_seed,
                    cid,
                    seq,
                )
            };
            // The local device's ACK prunes nothing yet, so it needs no notice.
            let ack = local_ack(&pool, &fixture.recipient_did, recipient_ack()).await;
            assert_eq!(ack["prunedCount"], 0);
            assert_eq!(ack_state(&pool, cid).await, [1, seq, 1, 1, 1]);
            // HOME's relay completes the audience: its prune would need a notice.
            let relay = signed_relay(
                &home_key,
                HOME,
                SEQ,
                cid,
                &fixture.sender_did,
                fixture.sender_device_id,
                seq,
            );
            let response =
                accept_entry_ack_relay(&state, HOME, &serde_json::to_vec(&relay).unwrap())
                    .await
                    .expect_err("no signer for the notice");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 16)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["error"], "SignerUnavailable");
            assert_eq!(ack_state(&pool, cid).await, [1, seq, 1, 1, 1]);
            // So does a local ACK that completes it.
            sqlx::query(
                "UPDATE chat.devices SET dormant_at = $3 WHERE user_did = $1 AND device_id = $2",
            )
            .bind(&fixture.sender_did)
            .bind(fixture.sender_device_id)
            .bind(current_utc())
            .execute(&pool)
            .await
            .unwrap();
            refused(ack_response(&pool, &fixture.recipient_did, recipient_ack()).await);
            assert_eq!(ack_state(&pool, cid).await, [1, seq, 1, 1, 1]);
            assert!(notice_rows(&pool, cid).await.is_empty());
        }),
    )
    .await;
}

#[tokio::test]
async fn signed_relay_404s_retry_unless_the_target_authenticates_its_absence() {
    crate::federation::open_federation_for_test();
    const BARE: &str = "did:web:ack-bare.example.com";
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    let other_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let other_pool = other_db.connect(4).await;
    for pool in [&seq_pool, &home_pool, &other_pool] {
        prepare(pool).await;
    }
    for pool in [&seq_pool, &home_pool] {
        sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
            .bind(BARE)
            .execute(pool)
            .await
            .unwrap();
    }
    // SEQ sequences `cid` for a member homed at HOME; neither HOME nor OTHER
    // mirrors it. HOME mirrors `mirrored`, which SEQ no longer holds, and
    // `bare_mirrored`, sequenced by BARE.
    let cid = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        false,
        SEQ,
        None,
        Some(HOME),
    )
    .await
    .unwrap()
    .conversation_id;
    let mirrored = seed_remote_clean_slate_application_fixture(&home_pool, HOME, SEQ, None)
        .await
        .unwrap();
    let bare_mirrored = seed_remote_clean_slate_application_fixture(&home_pool, HOME, BARE, None)
        .await
        .unwrap();
    let (seq_key, home_key, other_key, bare_key) = (key(0x31), key(0x32), key(0x33), key(0x34));
    let network = Network::new(&[
        (SEQ, &seq_key),
        (HOME, &home_key),
        (OTHER, &other_key),
        (BARE, &bare_key),
    ]);
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    let home_hooks = hooks(HOME, Some(&home_key), false, &network);
    let serve = |did: &str, pool: &DbPool, hooks: Arc<SimDsHooks>| {
        group_relay_router(
            GroupRelayState::for_test(pool.clone(), did.to_owned(), HMAC.as_bytes(), None)
                .with_sim_hooks(hooks)
                .with_clock(clock.clone()),
        )
    };
    network.serve(SEQ, serve(SEQ, &seq_pool, Arc::clone(&seq_hooks)));
    network.serve(HOME, serve(HOME, &home_pool, Arc::clone(&home_hooks)));
    network.serve(
        OTHER,
        serve(
            OTHER,
            &other_pool,
            hooks(OTHER, Some(&other_key), false, &network),
        ),
    );
    // An endpoint without the route answers an undeclared 404.
    network.serve(BARE, Router::new());
    let drain = |pool: &DbPool, did: &str, key: &SigningKey| {
        let queue = OutboundQueue::new(
            pool.clone(),
            AuthMiddleware::new(),
            Arc::new(resolver(pool, did)),
        );
        let auth = ServiceAuthClient::from_es256_pem(
            did.to_owned(),
            pem(key).as_bytes(),
            Some("#atproto".to_owned()),
        )
        .unwrap();
        async move {
            let sign = move |target: &str, method: &str| {
                auth.sign_request(target, method)
                    .map_err(|error| error.to_string())
            };
            queue
                .process_pending_batch(&OutboundClient::new(5, 5), &sign)
                .await
                .unwrap()
        }
    };
    let row = |pool: &DbPool, conversation_id: Uuid, target: &str| {
        let (pool, target) = (pool.clone(), target.to_owned());
        async move {
            queue_rows(&pool, conversation_id)
                .await
                .into_iter()
                .find(|row| row.1 == target)
                .map(|(_, _, status, retries, _, _)| (status, retries))
                .expect("a queued item")
        }
    };

    scope_ds_clock(clock.clone(), async {
        scope_sim_ds(Arc::clone(&seq_hooks), async {
            let mut tx = seq_pool.begin().await.unwrap();
            for home in [HOME, OTHER, BARE] {
                enqueue_entries_pruned_notice(&mut tx, home, cid, 0, &[4], current_utc())
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
            assert_eq!(drain(&seq_pool, SEQ, &seq_key).await, 3);
        })
        .await;
        // HOME homes a member SEQ addressed: its declared 404 cannot prove it
        // holds nothing, so the notice is retried.
        assert_eq!(row(&seq_pool, cid, HOME).await, ("pending".to_owned(), 1));
        // An undeclared 404 is retried too.
        assert_eq!(row(&seq_pool, cid, BARE).await, ("pending".to_owned(), 1));
        // OTHER declares ConversationNotFound and was never addressed: terminal.
        assert_eq!(row(&seq_pool, cid, OTHER).await, ("failed".to_owned(), 0));

        // An ACK relay's target is the conversation's sequencer, its authority.
        // SEQ no longer holds `mirrored`: a removed member's home never learns
        // of the close, so without SEQ's word its relay would retry forever.
        // The same declaration from a DS that does not sequence it, or an
        // undeclared 404 from one that does, is retried.
        scope_sim_ds(Arc::clone(&home_hooks), async {
            let mut tx = home_pool.begin().await.unwrap();
            for (sequencer, fixture, user_did, device_id) in [
                (
                    SEQ,
                    &mirrored,
                    &mirrored.recipient_did,
                    mirrored.recipient_device_id,
                ),
                (
                    OTHER,
                    &mirrored,
                    &mirrored.sender_did,
                    mirrored.sender_device_id,
                ),
                (
                    BARE,
                    &bare_mirrored,
                    &bare_mirrored.recipient_did,
                    bare_mirrored.recipient_device_id,
                ),
            ] {
                enqueue_entry_ack_relay(
                    &mut tx,
                    sequencer,
                    fixture.conversation_id,
                    0,
                    user_did,
                    device_id,
                    3,
                    current_utc(),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
            assert_eq!(drain(&home_pool, HOME, &home_key).await, 3);
        })
        .await;
        assert_eq!(
            row(&home_pool, mirrored.conversation_id, SEQ).await,
            ("failed".to_owned(), 0)
        );
        assert_eq!(
            row(&home_pool, mirrored.conversation_id, OTHER).await,
            ("pending".to_owned(), 1)
        );
        assert_eq!(
            row(&home_pool, bare_mirrored.conversation_id, BARE).await,
            ("pending".to_owned(), 1)
        );
    })
    .await;
}

/// A peer whose inbound gate is closed (kill switch, or federation mode off)
/// answers the gate's retryable 503. Prune notices, ACK relays and
/// account-deletion relays stay queued for retry instead of being
/// dead-lettered, so nothing refused during the closed window is lost.
#[tokio::test]
async fn durable_relays_to_a_federation_disabled_peer_stay_queued_for_retry() {
    crate::federation::open_federation_for_test();
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_db.connect(4).await;
    for pool in [&seq_pool, &home_pool] {
        prepare(pool).await;
    }
    let cid = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        false,
        SEQ,
        None,
        Some(HOME),
    )
    .await
    .unwrap()
    .conversation_id;
    // One mirror per relay: each conversation and target is its own stream head.
    let acked = seed_remote_clean_slate_application_fixture(&home_pool, HOME, SEQ, None)
        .await
        .unwrap();
    let deleted = seed_remote_clean_slate_application_fixture(&home_pool, HOME, SEQ, None)
        .await
        .unwrap();
    let (seq_key, home_key) = (key(0x35), key(0x36));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    let clock = manual_clock();
    let seq_hooks = hooks(SEQ, Some(&seq_key), false, &network);
    let home_hooks = hooks(HOME, Some(&home_key), false, &network);
    let closed_gate = Router::new().fallback(|| async {
        crate::federation::FederationError::FederationDisabled {
            reason: "Federation emergency kill switch is enabled".into(),
        }
        .into_response()
    });
    network.serve(SEQ, closed_gate.clone());
    network.serve(HOME, closed_gate);
    let drain = |pool: &DbPool, did: &str, key: &SigningKey| {
        let queue = OutboundQueue::new(
            pool.clone(),
            AuthMiddleware::new(),
            Arc::new(resolver(pool, did)),
        );
        let auth = ServiceAuthClient::from_es256_pem(
            did.to_owned(),
            pem(key).as_bytes(),
            Some("#atproto".to_owned()),
        )
        .unwrap();
        async move {
            let sign = move |target: &str, method: &str| {
                auth.sign_request(target, method)
                    .map_err(|error| error.to_string())
            };
            queue
                .process_pending_batch(&OutboundClient::new(5, 5), &sign)
                .await
                .unwrap()
        }
    };

    scope_ds_clock(clock.clone(), async {
        scope_sim_ds(Arc::clone(&seq_hooks), async {
            let mut tx = seq_pool.begin().await.unwrap();
            enqueue_entries_pruned_notice(&mut tx, HOME, cid, 0, &[4], current_utc())
                .await
                .unwrap();
            tx.commit().await.unwrap();
            assert_eq!(drain(&seq_pool, SEQ, &seq_key).await, 1);
        })
        .await;
        scope_sim_ds(Arc::clone(&home_hooks), async {
            let mut tx = home_pool.begin().await.unwrap();
            enqueue_entry_ack_relay(
                &mut tx,
                SEQ,
                acked.conversation_id,
                0,
                &acked.recipient_did,
                acked.recipient_device_id,
                3,
                current_utc(),
            )
            .await
            .unwrap();
            enqueue_account_deletion_relays(&mut tx, &deleted.recipient_did, current_utc(), None)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            assert_eq!(drain(&home_pool, HOME, &home_key).await, 2);
        })
        .await;
    })
    .await;
    for (pool, conversation_id) in [
        (&seq_pool, cid),
        (&home_pool, acked.conversation_id),
        (&home_pool, deleted.conversation_id),
    ] {
        let rows = queue_rows(pool, conversation_id).await;
        assert_eq!(rows.len(), 1, "one relay queued for {conversation_id}");
        for (id, _, status, retries, _, _) in rows {
            assert_eq!(
                (status.as_str(), retries),
                ("pending", 1),
                "{id} must be retried, never dead-lettered"
            );
        }
    }
}

/// C33 delivery services, named so the remote sender's coordinator is SEQ: a
/// pair's coordinator is the lesser of its two declared homes.
const C33_SEQ: &str = "did:web:c33-a-sequencer.example.com";
const C33_HOME: &str = "did:web:c33-b-home.example.com";
const C33_OTHER: &str = "did:web:c33-c-other.example.com";

impl Network {
    /// Declare `did`'s `#atproto_mls` delivery service at its own host, as a
    /// chat authority's DID document does.
    fn declare_delivery_service(&self, did: &str) {
        self.documents
            .lock()
            .unwrap()
            .get_mut(host(did))
            .expect("a published DS DID document")["service"] = json!([{
            "id": "#atproto_mls",
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": format!("https://{}", host(did)),
        }]);
    }

    /// Publish `user`'s DID document and, on its own PDS, the chat declaration
    /// naming `delivery_service` as its home.
    fn declare_user(&self, user: &str, delivery_service: &str) {
        let pds = format!("pds-{}", host(user));
        self.documents.lock().unwrap().insert(
            host(user).to_owned(),
            json!({
                "id": user,
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": format!("https://{pds}"),
                }],
            }),
        );
        let record = json!({
            "uri": format!("at://{user}/blue.catbird.chat.declaration/self"),
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "protocolVersion": "2",
                "deliveryService": delivery_service,
            },
        });
        self.routers.lock().unwrap().insert(
            pds,
            Router::new().route(
                "/xrpc/com.atproto.repo.getRecord",
                axum::routing::get(move || {
                    let record = record.clone();
                    async move { Json(record) }
                }),
            ),
        );
    }

    /// Publish `user`'s one `blue.catbird.chat.device` record on its PDS.
    fn authorize_device(&self, user: &str, public_key: &[u8]) {
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
        let mut routers = self.routers.lock().unwrap();
        let pds_router = routers.remove(&pds).expect("a declared user's PDS").route(
            "/xrpc/com.atproto.repo.listRecords",
            axum::routing::get(move || {
                let records = records.clone();
                async move { Json(records) }
            }),
        );
        routers.insert(pds, pds_router);
    }
}

/// The C33 coordinator records no home for a remote party: it learns that
/// home only from the user's PDS declaration. It applies the declared home's
/// signed ACK relay for the transport-only device it sequences for and prunes
/// once its whole frozen audience acknowledged.
#[tokio::test]
async fn c33_sequencer_applies_the_declared_homes_ack_relay_for_its_transport_only_device() {
    crate::federation::open_federation_for_test();
    let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = seq_db.connect(4).await;
    ensure_fence(&seq_pool).await;
    for peer in [C33_HOME, C33_OTHER] {
        sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
            .bind(peer)
            .execute(&seq_pool)
            .await
            .unwrap();
    }
    // A direct pair: the sender is remote (no recorded home), the recipient local.
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &seq_pool,
        true,
        C33_SEQ,
        Some([0x5c; 32]),
        None,
    )
    .await
    .unwrap();
    let cid = fixture.conversation_id;
    let (seq_key, home_key, other_key) = (key(0x41), key(0x42), key(0x43));
    let network = Network::new(&[
        (C33_SEQ, &seq_key),
        (C33_HOME, &home_key),
        (C33_OTHER, &other_key),
    ]);
    for ds in [C33_SEQ, C33_HOME, C33_OTHER] {
        network.declare_delivery_service(ds);
    }
    network.declare_user(&fixture.sender_did, C33_HOME);
    network.declare_user(&fixture.recipient_did, C33_SEQ);
    let clock = manual_clock();
    let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
    let seq_state =
        GroupRelayState::for_test(seq_pool.clone(), C33_SEQ.to_owned(), HMAC.as_bytes(), None)
            .with_sim_hooks(Arc::clone(&seq_hooks))
            .with_clock(clock.clone());
    let runtime = Arc::new(
        crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(I13ReceiptSigner::new(seq_key.clone(), C33_SEQ.to_owned())),
    );

    scope_ds_clock(
        clock,
        scope_sim_ds(Arc::clone(&seq_hooks), async {
            // The sender's declared home relays its message; SEQ coordinates.
            let sequenced = crate::federation::canonical_relay::coordinator_handle_message(
                &seq_pool,
                &runtime,
                C33_HOME,
                cid,
                &fixture.signed_request,
            )
            .await
            .expect("coordinate the remote sender's application");
            let seq = sequenced["entry"]["seq"].as_i64().unwrap();
            assert!(sequenced.get("sequencerReceipt").is_some(), "I13 receipt");

            // The local recipient's ACK alone never prunes the remote device's payload.
            let local = local_ack(
                &seq_pool,
                &fixture.recipient_did,
                ack_body(
                    fixture.recipient_device_id,
                    &fixture.recipient_key_id,
                    &fixture.recipient_ed25519_seed,
                    cid,
                    seq,
                ),
            )
            .await;
            assert_eq!(local["prunedCount"], 0);
            assert_eq!(ack_state(&seq_pool, cid).await, [1, seq, 1, 1, 1]);

            let sender = fixture.sender_did.as_str();
            let device = fixture.sender_device_id;
            let genuine = signed_relay(&home_key, C33_HOME, C33_SEQ, cid, sender, device, seq);
            let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
            let tampered = (StatusCode::FORBIDDEN, "InvalidSignature");
            let cases = [
                // Wrong home: a genuine signature from a DS the sender never declared.
                (
                    C33_OTHER,
                    signed_relay(&other_key, C33_OTHER, C33_SEQ, cid, sender, device, seq),
                    forbidden,
                ),
                (C33_OTHER, genuine.clone(), forbidden),
                // The declared home cannot speak for the local recipient.
                (
                    C33_HOME,
                    signed_relay(
                        &home_key,
                        C33_HOME,
                        C33_SEQ,
                        cid,
                        &fixture.recipient_did,
                        fixture.recipient_device_id,
                        seq,
                    ),
                    forbidden,
                ),
                // Bound to another sequencer, or to a device outside the audience.
                (
                    C33_HOME,
                    signed_relay(&home_key, C33_HOME, C33_OTHER, cid, sender, device, seq),
                    forbidden,
                ),
                (
                    C33_HOME,
                    signed_relay(
                        &home_key,
                        C33_HOME,
                        C33_SEQ,
                        cid,
                        sender,
                        Uuid::new_v4(),
                        seq,
                    ),
                    forbidden,
                ),
                // Beyond the sequenced head.
                (
                    C33_HOME,
                    signed_relay(&home_key, C33_HOME, C33_SEQ, cid, sender, device, seq + 1),
                    (StatusCode::BAD_REQUEST, "InvalidRequest"),
                ),
                // Altered after signing.
                (
                    C33_HOME,
                    edited(genuine.clone(), |r| r.acked_through_seq = seq - 1),
                    tampered,
                ),
                (
                    C33_HOME,
                    edited(genuine.clone(), |r| {
                        r.device_id = fixture.recipient_device_id
                    }),
                    tampered,
                ),
                (
                    C33_HOME,
                    edited(genuine.clone(), |r| {
                        let mut signature = STANDARD.decode(&r.signature).unwrap();
                        signature[63] ^= 1;
                        r.signature = STANDARD.encode(signature);
                    }),
                    tampered,
                ),
            ];
            for (caller, relay, (status, code)) in cases {
                assert_rejected(&seq_state, caller, &relay, cid, status, code).await;
            }

            // The declared home's relay completes the frozen audience: the
            // ciphertext and send payload go; digests, seq and I13 receipt stay.
            let applied = accept_entry_ack_relay(
                &seq_state,
                C33_HOME,
                &serde_json::to_vec(&genuine).unwrap(),
            )
            .await
            .expect("the declared home's relay is accepted");
            assert_eq!(applied["acknowledgedSeq"], seq);
            assert_eq!(applied["prunedCount"], 1);
            let pruned = [2, 2 * seq, 0, 0, 1];
            assert_eq!(ack_state(&seq_pool, cid).await, pruned);

            // A duplicate, or an older watermark, changes nothing.
            let older = signed_relay(&home_key, C33_HOME, C33_SEQ, cid, sender, device, seq - 1);
            for relay in [genuine, older] {
                let out = accept_entry_ack_relay(
                    &seq_state,
                    C33_HOME,
                    &serde_json::to_vec(&relay).unwrap(),
                )
                .await
                .expect("an idempotent relay is accepted");
                assert_eq!(out["acknowledgedSeq"], seq);
                assert_eq!(out["prunedCount"], 0);
                assert_eq!(ack_state(&seq_pool, cid).await, pruned);
            }
        }),
    )
    .await;
}

#[path = "account_deletion_relay_tests.rs"]
mod account_deletion;

#[path = "direct_request_relay_tests.rs"]
mod direct_request_relay;

//! A sender home relays `prepareDirectRequest` and `publishDirectRequest` to
//! the pair's remote coordinator through its production chat router. Not
//! reaching that coordinator (its closed federation gate, a refused
//! connection) is the declared retryable `CapacityUnavailable` with a retry
//! hint and commits nothing, so the identical retry succeeds once it answers;
//! the coordinator's own refusal stays `RequestPolicyDenied`. A home that
//! coordinates the pair itself answers the same way while the recipient's
//! policy source or home cannot answer, and its identical retry resumes the
//! same reservation; an authoritative answer stays the durable refusal. A
//! route no coordinator answered binds its pair only until no preparation its
//! signed prepare could produce is live, and is swept an hour after it was
//! recorded.

use super::*;
use crate::{
    chat_protocol::{
        direct_request_transcript::{direct_request_signing_bytes, DirectRequestKind},
        relationship_policy::{PublicResponse, SimSourceFault, TransportError},
        repository::{
            direct_request_receipts::DirectRequestReceiptSigner,
            expiry_sweep::delete_unanswered_outbound_routes,
        },
        test_support::{
            original_sender_attestation_json_for_test,
            seed_clean_slate_pending_direct_request_fixture, seed_published_request_keys,
            CleanSlatePendingDirectRequestFixture,
        },
    },
    common::http_acceptance as http,
    federation::{
        canonical_relay::{
            coordinator_get_outcome, coordinator_prepare_direct_request, live_actor_key,
            local_release_recipient_bootstrap, local_reserve_recipient_bootstrap,
            ReleaseRecipientBootstrapInput, ReserveRecipientBootstrapInput,
            ReserveRecipientBootstrapOutput,
        },
        FederationError,
    },
    handlers::chat::ChatRuntime,
};
use axum::http::header::RETRY_AFTER;

// A pair's coordinator is the lesser of its two declared homes: the remote one.
const COORDINATOR_DS: &str = "did:web:dr-relay-a-coordinator.example.com";
const SENDER_DS: &str = "did:web:dr-relay-b-home.example.com";
// A recipient homed at the greater `RECIPIENT_DS` makes this home the coordinator.
const RECIPIENT_DS: &str = "did:web:dr-relay-c-recipient.example.com";
// A recipient that moves to `MOVED_DS` moves its pair's coordinator there.
const MOVED_DS: &str = "did:web:dr-relay-a-moved.example.com";
const PREPARE: &str = "blue.catbird.chat.prepareDirectRequest";
const PUBLISH: &str = "blue.catbird.chat.publishDirectRequest";
const RELAY_PREPARE: &str = "blue.catbird.mlsDS.prepareDirectRequest";
const RELAY_PUBLISH: &str = "blue.catbird.mlsDS.publishDirectRequest";
const RESERVE: &str = "/xrpc/blue.catbird.mlsDS.reserveRecipientBootstrap";
const VECTORS: &str = include_str!("../../tests/fixtures/direct_request_vectors.json");

/// The sender's one device at its home: its service-auth identity and the
/// Ed25519 key its direct requests are signed with.
struct Sender {
    device: http::Device,
    key_id: String,
    signing: ed25519_dalek::SigningKey,
}

impl Sender {
    /// `did`, declared at the sender's home, whose DID document publishes its
    /// service-auth key, whose PDS authorizes its device key and whose device
    /// the home registered.
    async fn at_home(network: &Network, pool: &DbPool, did: &str) -> Self {
        network.declare_user(did, SENDER_DS);
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x6e; 32]);
        network.authorize_device(did, &signing.verifying_key().to_bytes());
        let auth = key(0x6d);
        let jwk = http::public_jwk(&auth);
        network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(did))
            .expect("the sender's DID document")["verificationMethod"] = json!([{
            "id": format!("{did}#atproto"),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk,
        }]);
        let device_id = Uuid::new_v4();
        let key_id = seed_actor_at(
            pool,
            did,
            device_id,
            &signing.verifying_key().to_bytes(),
            clock_now(pool).await,
        )
        .await;
        Self {
            device: http::Device {
                did: did.to_owned(),
                device_id,
                jkt: http::jwk_thumbprint(&jwk),
                jwk,
                signing: auth,
            },
            key_id,
            signing,
        }
    }

    /// The schema-shaped fixture `kind` body for `recipient` and `request_id`,
    /// signed now by this device.
    fn sign(&self, kind: DirectRequestKind, recipient: &str, request_id: Uuid) -> Value {
        let actor = (
            self.device.did.as_str(),
            self.device.device_id,
            self.key_id.as_str(),
        );
        sign_request(kind, &self.signing, actor, recipient, request_id)
    }
}

/// The schema-shaped fixture `kind` body of an actor's device (its DID, device
/// ID and key ID) for `recipient` and `request_id`, signed now with `signing`.
fn sign_request(
    kind: DirectRequestKind,
    signing: &ed25519_dalek::SigningKey,
    (did, device_id, key_id): (&str, Uuid, &str),
    recipient: &str,
    request_id: Uuid,
) -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let name = format!("{kind:?}");
    let fixture = vectors["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["kind"] == name.as_str())
        .expect("a fixture body for the kind");
    let mut body = fixture["body"].clone();
    let signed_at = current_utc().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    for (field, value) in [
        ("actorDid", json!(did)),
        ("actorDeviceId", json!(device_id)),
        ("keyId", json!(key_id)),
        ("recipientDid", json!(recipient)),
        ("requestId", json!(request_id)),
        ("idempotencyKey", json!(request_id)),
        ("signedAt", json!(signed_at)),
    ] {
        body[field] = value;
    }
    if kind == DirectRequestKind::Publish {
        let archive_commitment: [u8; 32] = STANDARD
            .decode(body["archiveCommitment"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        body["originalSenderAttestation"] = original_sender_attestation_json_for_test(
            did,
            device_id,
            signing,
            body["conversationId"].as_str().unwrap(),
            body["firstMessageId"].as_str().unwrap(),
            &archive_commitment,
        );
    }
    let bytes = serde_json::to_vec(&body).unwrap();
    let message = direct_request_signing_bytes(kind, &bytes).unwrap();
    let signature = STANDARD.encode(signing.sign(&message).to_bytes());
    json!({ "body": body, "signature": signature })
}

/// `signed` through the home's production chat router: the status, the
/// `Retry-After` hint and the JSON body.
async fn call(
    router: &Router,
    hooks: &Arc<SimDsHooks>,
    sender: &Sender,
    nsid: &str,
    signed: &Value,
) -> (StatusCode, Option<String>, Value) {
    let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
    scope_sim_ds(Arc::clone(hooks), async {
        let response = router
            .clone()
            .oneshot(http::unsigned_json_request(&sender.device, nsid, body))
            .await
            .unwrap();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
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

/// Every `chat.direct_request_*` table's row count at the home.
async fn effects(pool: &DbPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT table_name::text || '=' || (xpath('/row/c/text()', query_to_xml( \
                format('SELECT count(*) AS c FROM chat.%I', table_name), \
                false, true, '')))[1]::text \
           FROM information_schema.tables \
          WHERE table_schema = 'chat' AND table_type = 'BASE TABLE' \
            AND table_name LIKE 'direct_request_%' \
          ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The coordinator the home routed `request_id` to, if it recorded one.
async fn route(pool: &DbPool, request_id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT coordinator_did FROM chat.direct_request_outbound_routes WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// Whether the coordinator answered the route the home recorded for
/// `request_id`, if it recorded one.
async fn answered(pool: &DbPool, request_id: Uuid) -> Option<bool> {
    sqlx::query_scalar(
        "SELECT answered_at IS NOT NULL FROM chat.direct_request_outbound_routes \
         WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// Until when the route the home recorded for `request_id` binds its pair, if
/// it recorded one: `Some(None)` once a coordinator answered, for good.
async fn binding(pool: &DbPool, request_id: Uuid) -> Option<Option<DateTime<Utc>>> {
    sqlx::query_scalar(
        "SELECT binding_expires_at FROM chat.direct_request_outbound_routes \
         WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// The text column `sql` selects for `request_id`, row by row.
async fn texts(pool: &DbPool, sql: &str, request_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(sql)
        .bind(request_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

/// Every key package ref `table` holds for `request_id`, in base64.
async fn package_refs(pool: &DbPool, table: &str, request_id: Uuid) -> Vec<String> {
    let sql = format!(
        "SELECT encode(key_package_ref, 'base64') FROM chat.{table} \
         WHERE request_id = $1"
    );
    texts(pool, &sql, request_id).await
}

/// Every body the network delivered to `path`, in order.
fn delivered(network: &Network, path: &str) -> Vec<Vec<u8>> {
    network
        .delivered
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, _)| at == path)
        .map(|(_, body)| body.clone())
        .collect()
}

/// Every `signedRequest` the coordinator was sent through `method`, in order.
fn relayed(network: &Network, method: &str) -> Vec<Value> {
    delivered(network, &format!("/xrpc/{method}"))
        .iter()
        .map(|body| serde_json::from_slice::<Value>(body).unwrap()["signedRequest"].clone())
        .collect()
}

/// A delivery service's closed inbound federation gate: its 503.
fn disabled() -> axum::response::Response {
    FederationError::FederationDisabled {
        reason: "Federation emergency kill switch is enabled".into(),
    }
    .into_response()
}

/// A coordinator whose inbound federation gate is closed answers its 503.
fn closed_gate() -> Router {
    Router::new().fallback(|| async { disabled() })
}

/// A coordinator that refuses the request itself.
fn refusing() -> Router {
    Router::new().fallback(|| async {
        FederationError::Forbidden("sender key is not authorized".into()).into_response()
    })
}

/// A coordinator answering every relay with `outcome`.
fn answering(outcome: Value) -> Router {
    Router::new().fallback(move || {
        let outcome = outcome.clone();
        async move { Json(outcome) }
    })
}

/// A coordinator's prepared outcome for `request_id`.
fn prepared(request_id: Uuid) -> Value {
    json!({ "outcome": {
        "$type": "blue.catbird.chat.defs#directRequestPreparedOutcome",
        "preparation": { "requestId": request_id },
    }})
}

/// RECIPIENT_DS's `reserveRecipientBootstrap` for this home, its pair
/// coordinator: the production reservation on the recipient home's `pool`. It
/// records every lease it answers in `answers`, and its first answer is lost
/// to a 503.
fn reserving_home(
    pool: DbPool,
    hooks: Arc<SimDsHooks>,
    answers: Arc<std::sync::Mutex<Vec<Value>>>,
) -> Router {
    Router::new().route(
        RESERVE,
        axum::routing::post(move |Json(input): Json<ReserveRecipientBootstrapInput>| {
            let (pool, hooks, answers) = (pool.clone(), Arc::clone(&hooks), Arc::clone(&answers));
            async move {
                let reserved = scope_sim_ds(
                    hooks,
                    local_reserve_recipient_bootstrap(&pool, SENDER_DS, &input),
                )
                .await;
                let selected_devices = match reserved {
                    Ok(devices) => devices,
                    Err(error) => return error.into_response(),
                };
                let mut answered = answers.lock().unwrap();
                answered.push(serde_json::to_value(&selected_devices).unwrap());
                if answered.len() == 1 {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                Json(ReserveRecipientBootstrapOutput { selected_devices }).into_response()
            }
        }),
    )
}

/// A sender home whose pair coordinator is the remote `COORDINATOR_DS`, beside
/// `RECIPIENT_DS` and `MOVED_DS`: its database (held for the test), pool, the sim network,
/// its sender, a recipient declared at the coordinator, its hooks, its
/// production router and the fault its relationship-policy sources answer.
/// With `clock`, the router runs on it (chat routes scope their runtime's
/// clock), so a test that advances it moves the home's time too.
async fn relay_home(
    clock: Option<Arc<ManualDsClock>>,
) -> (
    impl Sized,
    DbPool,
    Network,
    Sender,
    String,
    Arc<SimDsHooks>,
    Router,
    SimSourceFault,
) {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    ensure_fence(&pool).await;
    for peer in [COORDINATOR_DS, RECIPIENT_DS, MOVED_DS] {
        sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
            .bind(peer)
            .execute(&pool)
            .await
            .unwrap();
    }
    let (home_key, remote_key, receipt_key) = (key(0x6a), key(0x6b), key(0x6c));
    let network = Network::new(&[
        (SENDER_DS, &home_key),
        (COORDINATOR_DS, &remote_key),
        (RECIPIENT_DS, &key(0x6f)),
        (MOVED_DS, &key(0x70)),
    ]);
    for ds in [SENDER_DS, COORDINATOR_DS, RECIPIENT_DS, MOVED_DS] {
        network.declare_delivery_service(ds);
    }
    let unique = Uuid::new_v4().simple();
    let recipient = format!("did:web:dr-relay-recipient-{unique}.example.com");
    network.declare_user(&recipient, COORDINATOR_DS);
    let sender = Sender::at_home(
        &network,
        &pool,
        &format!("did:web:dr-relay-sender-{unique}.example.com"),
    )
    .await;
    let home_hooks = hooks(SENDER_DS, Some(&home_key), false, &network);
    let fault = SimSourceFault::default();
    let router = {
        let (receipt_pem, service_pem) = (pem(&receipt_key), pem(&home_key));
        let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
            SENDER_DS,
            receipt_key.verifying_key(),
        )
        .to_string();
        let (runtime_hooks, runtime_fault) = (Arc::clone(&home_hooks), Arc::clone(&fault));
        scope_sim_ds(
            Arc::clone(&home_hooks),
            http::router_for_validated_acceptance_with(pool.clone(), move |runtime| {
                let runtime = runtime
                    .with_request_receipt_keys(&receipt_pem, &service_pem, &document)
                    .expect("the home's request receipt authority")
                    .with_request_producers()
                    .with_sim_faulty_relationships(runtime_fault)
                    .expect("the home's relationship authority")
                    .with_sim_hooks(runtime_hooks);
                match clock {
                    Some(clock) => runtime.with_clock(clock),
                    None => runtime,
                }
            }),
        )
        .await
    };
    (
        db, pool, network, sender, recipient, home_hooks, router, fault,
    )
}

/// The sender home relays both requests to the remote coordinator. While that
/// coordinator's gate is closed, or the link refuses the connection, each is
/// the retryable `CapacityUnavailable` with `Retry-After` and leaves every
/// direct-request table as it was; the identical signed request then succeeds
/// once the coordinator answers. The coordinator's refusal stays
/// `RequestPolicyDenied`, which carries no retry hint.
#[tokio::test]
async fn an_unreachable_pair_coordinator_is_retryable_and_commits_nothing() {
    let (_db, pool, network, sender, recipient, home_hooks, router, _) = relay_home(None).await;
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5"),
        Some("CapacityUnavailable"),
    );
    let refused = (StatusCode::BAD_REQUEST, None, Some("RequestPolicyDenied"));

    // prepareDirectRequest: the route it records before the relay is withdrawn.
    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    network.serve(COORDINATOR_DS, closed_gate());
    let before = effects(&pool).await;
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        unavailable,
        "{body}"
    );
    assert_eq!(relayed(&network, RELAY_PREPARE), [prepare.clone()]);
    assert_eq!(effects(&pool).await, before, "nothing was decided");

    let prepared = prepared(request_id);
    network.serve(COORDINATOR_DS, answering(prepared.clone()));
    assert_eq!(
        call(&router, &home_hooks, &sender, PREPARE, &prepare).await,
        (StatusCode::OK, None, prepared)
    );
    assert_eq!(relayed(&network, RELAY_PREPARE), vec![prepare; 2]);
    assert_eq!(
        route(&pool, request_id).await.as_deref(),
        Some(COORDINATOR_DS)
    );

    network.serve(COORDINATOR_DS, refusing());
    let other = sender.sign(DirectRequestKind::Prepare, &recipient, Uuid::new_v4());
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &other).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        refused,
        "{body}"
    );

    // publishDirectRequest: no route is recorded until the coordinator answers.
    let request_id = Uuid::new_v4();
    let publish = sender.sign(DirectRequestKind::Publish, &recipient, request_id);
    network.serve(COORDINATOR_DS, closed_gate());
    let before = effects(&pool).await;
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PUBLISH, &publish).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        unavailable,
        "{body}"
    );
    assert_eq!(relayed(&network, RELAY_PUBLISH), [publish.clone()]);
    assert_eq!(effects(&pool).await, before, "nothing was decided");

    // A refused connection, resolving or relaying, is just as retryable.
    network.partition(true);
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PUBLISH, &publish).await;
    network.partition(false);
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        unavailable,
        "{body}"
    );
    assert_eq!(relayed(&network, RELAY_PUBLISH), [publish.clone()]);
    assert_eq!(effects(&pool).await, before, "nothing was decided");

    let receipt = json!({ "outcome": {
        "$type": "blue.catbird.chat.defs#directRequestUnknownOutcome",
        "requestId": request_id,
    }});
    network.serve(COORDINATOR_DS, answering(receipt.clone()));
    assert_eq!(
        call(&router, &home_hooks, &sender, PUBLISH, &publish).await,
        (StatusCode::OK, None, receipt)
    );
    assert_eq!(relayed(&network, RELAY_PUBLISH), vec![publish; 2]);
    assert_eq!(
        route(&pool, request_id).await.as_deref(),
        Some(COORDINATOR_DS)
    );

    network.serve(COORDINATOR_DS, refusing());
    let other = sender.sign(DirectRequestKind::Publish, &recipient, Uuid::new_v4());
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PUBLISH, &other).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        refused,
        "{body}"
    );
}

/// Two identical prepares race at the sender home. The first records the
/// route and its relay is held until the coordinator has answered the second,
/// which rewrote that route; only then does the first fail transiently. The
/// answered prepare keeps its route: a failing prepare withdraws only the row
/// version it wrote itself.
#[tokio::test]
async fn a_failed_identical_prepare_never_withdraws_an_answered_route() {
    let (_db, pool, network, sender, recipient, home_hooks, router, _) = relay_home(None).await;
    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    let prepared = prepared(request_id);
    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let second_answered = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    network.serve(COORDINATOR_DS, {
        let (first_arrived, second_answered) = (first_arrived.clone(), second_answered.clone());
        let prepared = prepared.clone();
        Router::new().fallback(move || {
            let (first_arrived, second_answered) = (first_arrived.clone(), second_answered.clone());
            let (calls, prepared) = (calls.clone(), prepared.clone());
            async move {
                if calls.fetch_add(1, SeqCst) == 0 {
                    first_arrived.notify_one();
                    second_answered.notified().await;
                    return disabled();
                }
                second_answered.notify_one();
                Json(prepared).into_response()
            }
        })
    });

    let first = call(&router, &home_hooks, &sender, PREPARE, &prepare);
    let second = async {
        first_arrived.notified().await;
        call(&router, &home_hooks, &sender, PREPARE, &prepare).await
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        (first.0, first.1.as_deref(), first.2["error"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("5"),
            Some("CapacityUnavailable")
        ),
        "{}",
        first.2
    );
    assert_eq!(second, (StatusCode::OK, None, prepared));
    assert_eq!(relayed(&network, RELAY_PREPARE), vec![prepare; 2]);
    assert_eq!(
        route(&pool, request_id).await.as_deref(),
        Some(COORDINATOR_DS),
        "the answered prepare keeps its route"
    );
}

/// The sender's non-coordinator home loses the coordinator's first successful
/// prepare answer, then sends the byte-identical request again before
/// publication. The coordinator returns the retained preparation bytes and
/// executes no second preparation.
#[tokio::test]
async fn c33_lost_prepare_answer_replays_the_retained_prepared_outcome() {
    let (_home_db, _home_pool, network, sender, recipient, home_hooks, home_router, _) =
        relay_home(None).await;
    let coordinator_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let coordinator_pool = coordinator_db.connect(4).await;
    ensure_fence(&coordinator_pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(SENDER_DS)
        .execute(&coordinator_pool)
        .await
        .unwrap();

    let (recipient_key, _) = seed_published_request_keys(&coordinator_pool, &recipient, 1)
        .await
        .expect("the recipient's published request key");
    network.authorize_device(&recipient, &recipient_key);

    let coordinator_key = key(0x6b);
    let receipt_key = key(0x7a);
    let receipt_pem = pem(&receipt_key);
    let service_pem = pem(&coordinator_key);
    let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
        COORDINATOR_DS,
        receipt_key.verifying_key(),
    )
    .to_string();
    let mut built = None;
    let _ = http::router_for_authenticated_acceptance_with(coordinator_pool.clone(), |runtime| {
        built = Some(ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8))).unwrap());
        runtime
    })
    .await;
    let coordinator_hooks = hooks(COORDINATOR_DS, Some(&coordinator_key), false, &network);
    let coordinator_runtime = built
        .unwrap()
        .with_request_receipt_keys(&receipt_pem, &service_pem, &document)
        .unwrap()
        .with_sim_allow_all_relationships()
        .unwrap()
        .with_sim_hooks(Arc::clone(&coordinator_hooks));
    coordinator_runtime
        .validate_protocol_fence(&coordinator_pool)
        .await
        .unwrap();
    let coordinator_runtime = Arc::new(coordinator_runtime);

    let first_answer = Arc::new(std::sync::Mutex::new(None));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    network.serve(COORDINATOR_DS, {
        let pool = coordinator_pool.clone();
        let runtime = Arc::clone(&coordinator_runtime);
        let hooks = Arc::clone(&coordinator_hooks);
        let retained = Arc::clone(&first_answer);
        let calls = Arc::clone(&calls);
        Router::new().route(
            "/xrpc/blue.catbird.mlsDS.prepareDirectRequest",
            axum::routing::post(move |Json(input): Json<Value>| {
                let pool = pool.clone();
                let runtime = Arc::clone(&runtime);
                let hooks = Arc::clone(&hooks);
                let retained = Arc::clone(&retained);
                let calls = Arc::clone(&calls);
                async move {
                    match scope_sim_ds(
                        hooks,
                        coordinator_prepare_direct_request(&pool, &runtime, SENDER_DS, &input),
                    )
                    .await
                    {
                        Ok(outcome) if calls.fetch_add(1, SeqCst) == 0 => {
                            *retained.lock().unwrap() = Some(serde_json::to_vec(&outcome).unwrap());
                            StatusCode::SERVICE_UNAVAILABLE.into_response()
                        }
                        Ok(outcome) => Json(outcome).into_response(),
                        Err(error) => error.into_response(),
                    }
                }
            }),
        )
    });

    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    let conversation_id =
        Uuid::parse_str(prepare["body"]["conversationId"].as_str().unwrap()).unwrap();
    let (status, retry_after, body) =
        call(&home_router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("5"),
            Some("CapacityUnavailable")
        ),
        "the first successful coordinator answer was lost: {body}"
    );
    let retained_answer = first_answer
        .lock()
        .unwrap()
        .clone()
        .expect("the coordinator prepared before its answer was lost");
    let retained_effects = effects(&coordinator_pool).await;
    let retained_attempt: (
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        DateTime<Utc>,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT xmin::text,status,prepare_response,terminal_response,prepared_at,lease_expires_at \
             FROM chat.direct_request_attempts WHERE request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&coordinator_pool)
    .await
    .unwrap();
    assert_eq!(retained_attempt.1, "prepared");
    assert!(retained_attempt.3.is_none(), "no terminal receipt exists");
    let sequence_position: Option<i64> = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_optional(&coordinator_pool)
    .await
    .unwrap();
    assert_eq!(
        sequence_position, None,
        "publication has not allocated a seq"
    );

    let (status, _, replay) = call(&home_router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the identical retry did not receive the retained prepared outcome: {replay}"
    );
    assert_eq!(
        replay["outcome"]["$type"],
        "blue.catbird.chat.defs#directRequestPreparedOutcome"
    );
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        retained_answer,
        "the replayed answer changed bytes"
    );
    let relays = delivered(&network, "/xrpc/blue.catbird.mlsDS.prepareDirectRequest");
    assert_eq!(relays.len(), 2);
    assert_eq!(relays[0], relays[1], "the retried request changed bytes");
    assert_eq!(
        effects(&coordinator_pool).await,
        retained_effects,
        "the replay created a second direct-request effect"
    );
    let replayed_attempt: (
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        DateTime<Utc>,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT xmin::text,status,prepare_response,terminal_response,prepared_at,lease_expires_at \
         FROM chat.direct_request_attempts WHERE request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&coordinator_pool)
    .await
    .unwrap();
    assert_eq!(
        replayed_attempt, retained_attempt,
        "the replay rewrote the preparation or created a receipt"
    );
    let replayed_sequence: Option<i64> = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_optional(&coordinator_pool)
    .await
    .unwrap();
    assert_eq!(
        replayed_sequence, sequence_position,
        "the replay allocated a sequence position"
    );
}

/// This home coordinates a pair it also homes. A DID document its policy
/// source does not find is an authoritative answer: the durable signed
/// `RequestPolicyDenied`, which replays after the source recovers. While that
/// source cannot answer at all, prepare is the retryable `CapacityUnavailable`
/// and records nothing; the identical signed prepare then reserves one of the
/// recipient's two packages and leaves the other in its pool.
#[tokio::test]
async fn a_policy_source_that_cannot_answer_decides_nothing_at_the_coordinator() {
    let (_db, pool, network, sender, _, home_hooks, router, fault) = relay_home(None).await;
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5"),
        Some("CapacityUnavailable"),
    );
    let attempt = "SELECT status FROM chat.direct_request_attempts WHERE request_id = $1";
    let unique = Uuid::new_v4().simple();

    // Refused before any preparation of this sender holds its budget.
    let gone = format!("did:web:dr-relay-gone-{unique}.example.com");
    network.declare_user(&gone, SENDER_DS);
    let refused_id = Uuid::new_v4();
    let refused = sender.sign(DirectRequestKind::Prepare, &gone, refused_id);
    *fault.lock().unwrap() = Some(Ok(PublicResponse::new(404, Vec::new())));
    let (status, retry_after, receipt) =
        call(&router, &home_hooks, &sender, PREPARE, &refused).await;
    *fault.lock().unwrap() = None;
    assert_eq!((status, retry_after), (StatusCode::OK, None), "{receipt}");
    let decided = &receipt["outcome"]["body"]["receipt"];
    assert_eq!(
        (decided["$type"].as_str(), decided["code"].as_str()),
        (
            Some("blue.catbird.chat.defs#directRequestRejectedReceipt"),
            Some("RequestPolicyDenied")
        ),
        "{receipt}"
    );
    assert_eq!(texts(&pool, attempt, refused_id).await, ["rejected"]);
    assert_eq!(
        call(&router, &home_hooks, &sender, PREPARE, &refused).await,
        (StatusCode::OK, None, receipt),
        "the durable refusal replays"
    );

    let recipient = format!("did:web:dr-relay-local-{unique}.example.com");
    network.declare_user(&recipient, SENDER_DS);
    let (_, packages) = seed_published_request_keys(&pool, &recipient, 2)
        .await
        .expect("the recipient's published request keys");
    let packages: Vec<String> = packages.iter().map(|p| STANDARD.encode(p)).collect();
    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    *fault.lock().unwrap() = Some(Err(TransportError::Network));
    let before = effects(&pool).await;
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        unavailable,
        "{body}"
    );
    assert_eq!(effects(&pool).await, before, "nothing was decided");
    assert!(texts(&pool, attempt, request_id).await.is_empty());

    *fault.lock().unwrap() = None;
    let (status, _, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, &body["outcome"]["preparation"]["requestId"]),
        (StatusCode::OK, &json!(request_id)),
        "{body}"
    );
    let selected = package_refs(&pool, "direct_request_selected_devices", request_id).await;
    assert!(
        selected.len() == 1 && packages.contains(&selected[0]),
        "{selected:?}"
    );
    let consumed = texts(
        &pool,
        "SELECT encode(p.key_package_ref, 'base64') FROM chat.key_packages p \
           JOIN chat.direct_request_attempts a ON a.recipient_did = p.owner_did \
          WHERE a.request_id = $1 AND p.status <> 'available'",
        request_id,
    )
    .await;
    assert_eq!(consumed, selected, "one package left the pool");
}

/// This home coordinates a pair whose recipient is homed at RECIPIENT_DS. That
/// home records the lease, but its answer is lost (503): prepare is the
/// retryable `CapacityUnavailable` and keeps its pending reservation intent,
/// with no attempt or receipt. The identical retry sends the home the
/// byte-identical reservation; it answers the same lease, and this home stages
/// and prepares exactly that package.
#[tokio::test]
async fn a_lost_reservation_answer_resumes_the_same_lease_on_the_identical_retry() {
    let (_db, pool, network, sender, _, home_hooks, router, _) = relay_home(None).await;
    let recipient_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let recipient_pool = recipient_db.connect(4).await;
    ensure_fence(&recipient_pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(SENDER_DS)
        .execute(&recipient_pool)
        .await
        .unwrap();
    let unique = Uuid::new_v4().simple();
    let recipient = format!("did:web:dr-relay-remote-{unique}.example.com");
    network.declare_user(&recipient, RECIPIENT_DS);
    let (device_key, _) = seed_published_request_keys(&recipient_pool, &recipient, 2)
        .await
        .expect("the recipient's published request keys");
    network.authorize_device(&recipient, &device_key);
    let answers = Arc::new(std::sync::Mutex::new(Vec::new()));
    network.serve(
        RECIPIENT_DS,
        reserving_home(
            recipient_pool.clone(),
            hooks(RECIPIENT_DS, None, false, &network),
            Arc::clone(&answers),
        ),
    );
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5"),
        Some("CapacityUnavailable"),
    );
    let intent = "SELECT status FROM chat.direct_request_reservation_intents \
                  WHERE request_id = $1";

    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    let before = effects(&pool).await;
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        unavailable,
        "{body}"
    );
    let after = effects(&pool).await;
    let changed: Vec<&str> = after
        .iter()
        .filter(|row| !before.contains(row))
        .map(String::as_str)
        .collect();
    assert_eq!(
        changed,
        ["direct_request_reservation_intents=1"],
        "no attempt or receipt"
    );
    assert_eq!(texts(&pool, intent, request_id).await, ["pending"]);
    let leased = package_refs(&recipient_pool, "direct_request_remote_leases", request_id).await;
    assert_eq!(leased.len(), 1, "the recipient home applied it");

    let (status, _, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, &body["outcome"]["preparation"]["requestId"]),
        (StatusCode::OK, &json!(request_id)),
        "{body}"
    );
    let reservations = delivered(&network, RESERVE);
    assert_eq!(reservations.len(), 2);
    assert_eq!(reservations[0], reservations[1], "byte-identical");
    let reservation: Value = serde_json::from_slice(&reservations[0]).unwrap();
    assert_eq!(
        (&reservation["requestId"], &reservation["signedPrepare"]),
        (&json!(request_id), &prepare)
    );
    let answers = answers.lock().unwrap().clone();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0], answers[1], "the home answered the same lease");
    assert_eq!(answers[0][0]["keyPackageRef"], leased[0]);
    assert_eq!(
        package_refs(&recipient_pool, "direct_request_remote_leases", request_id).await,
        leased,
        "no other package was leased"
    );
    for table in [
        "direct_request_reserved_remote_packages",
        "direct_request_selected_devices",
    ] {
        assert_eq!(
            package_refs(&pool, table, request_id).await,
            leased,
            "{table}"
        );
    }
    assert_eq!(texts(&pool, intent, request_id).await, ["pending"]);
}

/// Two identical prepares relayed to `COORDINATOR_DS` both fail transiently.
/// The second rewrote the route the first recorded, so neither withdraws it:
/// the route is left behind, unanswered.
async fn leave_route(
    network: &Network,
    router: &Router,
    hooks: &Arc<SimDsHooks>,
    sender: &Sender,
    prepare: &Value,
) {
    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let second_arrived = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    network.serve(COORDINATOR_DS, {
        let (first_arrived, second_arrived) = (first_arrived.clone(), second_arrived.clone());
        Router::new().fallback(move || {
            let (first_arrived, second_arrived) = (first_arrived.clone(), second_arrived.clone());
            let calls = calls.clone();
            async move {
                if calls.fetch_add(1, SeqCst) == 0 {
                    first_arrived.notify_one();
                    second_arrived.notified().await;
                } else {
                    second_arrived.notify_one();
                }
                disabled()
            }
        })
    });
    let first = call(router, hooks, sender, PREPARE, prepare);
    let second = async {
        first_arrived.notified().await;
        call(router, hooks, sender, PREPARE, prepare).await
    };
    let (first, second) = tokio::join!(first, second);
    for (status, retry_after, body) in [first, second] {
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
                Some("CapacityUnavailable")
            ),
            "{body}"
        );
    }
}

/// Two identical prepares both fail transiently and leave their route behind,
/// unanswered, holding one of the actor's hourly slots. With that hour
/// otherwise full, a new request is refused before any relay, while the
/// identical retry reuses the leftover's row: one row, its creation time
/// unchanged, the byte-identical request relayed again. An hour after it was
/// recorded the leftover no longer counts, and the refused request is
/// admitted, its route answered.
#[tokio::test]
async fn a_leftover_route_holds_one_slot_until_it_ages_out_of_the_hourly_quota() {
    let clock = manual_clock();
    let (_db, pool, network, sender, recipient, home_hooks, router, _) =
        relay_home(Some(clock.clone())).await;
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5"),
        Some("CapacityUnavailable"),
    );
    let routed = "SELECT created_at::text FROM chat.direct_request_outbound_routes \
                  WHERE request_id = $1";
    scope_ds_clock(clock.clone(), async {
        let request_id = Uuid::new_v4();
        let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
        leave_route(&network, &router, &home_hooks, &sender, &prepare).await;
        let recorded = texts(&pool, routed, request_id).await;
        assert_eq!(recorded.len(), 1, "neither failure withdrew the route");
        assert_eq!(answered(&pool, request_id).await, Some(false));

        // Half an hour on, nineteen other requests' routes, each answered, fill
        // the actor's hour: a new request is refused unrelayed.
        clock.advance(chrono::Duration::minutes(30));
        sqlx::query(
            "INSERT INTO chat.direct_request_outbound_routes (request_id, actor_did, \
                 actor_device_id, recipient_did, coordinator_did, created_at, answered_at) \
             SELECT gen_random_uuid(), $1, $2, $3, $4, $5, $5 FROM generate_series(1, 19)",
        )
        .bind(&sender.device.did)
        .bind(sender.device.device_id)
        .bind(&recipient)
        .bind(COORDINATOR_DS)
        .bind(current_utc())
        .execute(&pool)
        .await
        .unwrap();
        let later_id = Uuid::new_v4();
        let later = sender.sign(DirectRequestKind::Prepare, &recipient, later_id);
        let (status, retry_after, body) =
            call(&router, &home_hooks, &sender, PREPARE, &later).await;
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                Some("CapacityUnavailable")
            ),
            "{body}"
        );

        // The identical retry needs no new slot: it reuses the leftover's row
        // and relays the same bytes.
        network.serve(COORDINATOR_DS, closed_gate());
        let (status, retry_after, body) =
            call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            unavailable,
            "{body}"
        );
        let relays = delivered(&network, &format!("/xrpc/{RELAY_PREPARE}"));
        assert_eq!(relays, vec![relays[0].clone(); 3], "byte-identical");
        assert_eq!(relayed(&network, RELAY_PREPARE), vec![prepare.clone(); 3]);
        assert_eq!(texts(&pool, routed, request_id).await, recorded);
        assert_eq!(route(&pool, later_id).await, None);

        // An hour after the leftover was recorded it no longer counts.
        clock.advance(chrono::Duration::minutes(30));
        network.serve(COORDINATOR_DS, answering(prepared(later_id)));
        assert_eq!(
            call(&router, &home_hooks, &sender, PREPARE, &later).await,
            (StatusCode::OK, None, prepared(later_id))
        );
        assert_eq!(answered(&pool, later_id).await, Some(true));
        assert_eq!(answered(&pool, request_id).await, Some(false));
    })
    .await;
}

/// A route no coordinator answered binds its pair until no preparation made
/// from its signed prepare could still be live: a coordinator admits the
/// prepare until its `signedAt` is 300 s old, and leases what it prepares for
/// 300 s. The home persists that deadline with the route, and an identical
/// retry leaves it. When the recipient moves its home, and with it the pair's
/// coordinator, a new request is refused until the deadline and admitted from
/// it, routed to the new coordinator. A route the old coordinator answered
/// keeps binding.
#[tokio::test]
async fn a_leftover_route_binds_its_pair_only_while_its_preparation_could_be_live() {
    let clock = manual_clock();
    let (_db, pool, network, sender, recipient, home_hooks, router, _) =
        relay_home(Some(clock.clone())).await;
    let unique = Uuid::new_v4().simple();
    let settled = format!("did:web:dr-relay-settled-{unique}.example.com");
    network.declare_user(&settled, COORDINATOR_DS);
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5"),
        Some("CapacityUnavailable"),
    );
    let conflict = (StatusCode::BAD_REQUEST, None, Some("PreparationConflict"));
    scope_ds_clock(clock.clone(), async {
        // The old coordinator answers one pair's prepare and never the other's.
        let settled_id = Uuid::new_v4();
        let settled_prepare = sender.sign(DirectRequestKind::Prepare, &settled, settled_id);
        network.serve(COORDINATOR_DS, answering(prepared(settled_id)));
        assert_eq!(
            call(&router, &home_hooks, &sender, PREPARE, &settled_prepare).await,
            (StatusCode::OK, None, prepared(settled_id))
        );
        assert_eq!(binding(&pool, settled_id).await, Some(None));
        let leftover_id = Uuid::new_v4();
        let leftover = sender.sign(DirectRequestKind::Prepare, &recipient, leftover_id);
        let signed_at = leftover["body"]["signedAt"].as_str().unwrap();
        let deadline = signed_at.parse::<DateTime<Utc>>().unwrap() + chrono::Duration::seconds(600);
        // Recorded after it was signed, the route still binds from `signedAt`.
        clock.advance(chrono::Duration::seconds(30));
        leave_route(&network, &router, &home_hooks, &sender, &leftover).await;
        assert_eq!(answered(&pool, leftover_id).await, Some(false));
        assert_eq!(binding(&pool, leftover_id).await, Some(Some(deadline)));

        // The identical retry, minutes later, leaves the deadline where it was.
        clock.advance(chrono::Duration::minutes(4));
        network.serve(COORDINATOR_DS, closed_gate());
        let (status, retry_after, body) =
            call(&router, &home_hooks, &sender, PREPARE, &leftover).await;
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            unavailable,
            "{body}"
        );
        assert_eq!(binding(&pool, leftover_id).await, Some(Some(deadline)));

        // Both recipients move to MOVED_DS, their pairs' coordinator from now on.
        for user in [&recipient, &settled] {
            network.declare_user(user, MOVED_DS);
        }
        clock.set_utc(deadline - chrono::Duration::milliseconds(1));
        let moved_id = Uuid::new_v4();
        let moved = sender.sign(DirectRequestKind::Prepare, &recipient, moved_id);
        network.serve(MOVED_DS, answering(prepared(moved_id)));
        let (status, retry_after, body) =
            call(&router, &home_hooks, &sender, PREPARE, &moved).await;
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            conflict,
            "{body}"
        );
        assert_eq!(route(&pool, moved_id).await, None);

        clock.set_utc(deadline);
        assert_eq!(
            call(&router, &home_hooks, &sender, PREPARE, &moved).await,
            (StatusCode::OK, None, prepared(moved_id))
        );
        assert_eq!(route(&pool, moved_id).await.as_deref(), Some(MOVED_DS));
        assert_eq!(answered(&pool, moved_id).await, Some(true));
        assert_eq!(binding(&pool, moved_id).await, Some(None));

        // The answered route still binds its pair to the old coordinator.
        let other = sender.sign(DirectRequestKind::Prepare, &settled, Uuid::new_v4());
        let (status, retry_after, body) =
            call(&router, &home_hooks, &sender, PREPARE, &other).await;
        assert_eq!(
            (status, retry_after.as_deref(), body["error"].as_str()),
            conflict,
            "{body}"
        );
    })
    .await;
}

/// The expiry sweeper deletes a route no coordinator answered an hour after it
/// was recorded, and nothing else: not a younger leftover, not the route of an
/// answered prepare or publish however old, and no other direct-request row.
#[tokio::test]
async fn the_sweep_deletes_only_routes_left_unanswered_for_an_hour() {
    let clock = manual_clock();
    let (_db, pool, network, sender, recipient, home_hooks, router, _) =
        relay_home(Some(clock.clone())).await;
    scope_ds_clock(clock.clone(), async {
        let prepared_id = Uuid::new_v4();
        let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, prepared_id);
        network.serve(COORDINATOR_DS, answering(prepared(prepared_id)));
        assert_eq!(
            call(&router, &home_hooks, &sender, PREPARE, &prepare).await,
            (StatusCode::OK, None, prepared(prepared_id))
        );
        let published_id = Uuid::new_v4();
        let publish = sender.sign(DirectRequestKind::Publish, &recipient, published_id);
        let unknown = json!({ "outcome": {
            "$type": "blue.catbird.chat.defs#directRequestUnknownOutcome",
            "requestId": published_id,
        }});
        network.serve(COORDINATOR_DS, answering(unknown.clone()));
        assert_eq!(
            call(&router, &home_hooks, &sender, PUBLISH, &publish).await,
            (StatusCode::OK, None, unknown)
        );
        let leftover_id = Uuid::new_v4();
        let leftover = sender.sign(DirectRequestKind::Prepare, &recipient, leftover_id);
        leave_route(&network, &router, &home_hooks, &sender, &leftover).await;
        clock.advance(chrono::Duration::minutes(30));
        let younger_id = Uuid::new_v4();
        let younger = sender.sign(DirectRequestKind::Prepare, &recipient, younger_id);
        leave_route(&network, &router, &home_hooks, &sender, &younger).await;
        assert_eq!(answered(&pool, prepared_id).await, Some(true));
        assert_eq!(answered(&pool, published_id).await, Some(true));

        clock.advance(chrono::Duration::minutes(30));
        let sweep = || delete_unanswered_outbound_routes(&pool, current_utc(), 128);
        let before = effects(&pool).await;
        assert_eq!(sweep().await.unwrap(), 1);
        let after = effects(&pool).await;
        let changed: Vec<&str> = after
            .iter()
            .filter(|row| !before.contains(row))
            .map(String::as_str)
            .collect();
        assert_eq!(
            changed,
            ["direct_request_outbound_routes=3"],
            "nothing else is touched"
        );
        assert_eq!(route(&pool, leftover_id).await, None);
        for kept in [prepared_id, published_id, younger_id] {
            assert_eq!(route(&pool, kept).await.as_deref(), Some(COORDINATOR_DS));
        }
        assert_eq!(sweep().await.unwrap(), 0);
    })
    .await;
}

const RELEASE: &str = "/xrpc/blue.catbird.mlsDS.releaseRecipientBootstrap";

/// A coordinator whose answer no retry can use (a body that is not JSON) is a
/// definitive refusal at the sender home, as the coordinator's own 4xx is:
/// `RequestPolicyDenied`, never the retryable `CapacityUnavailable` of a link
/// that could not reach it.
#[tokio::test]
async fn a_coordinator_answer_no_retry_can_use_is_a_refusal() {
    let (_db, _pool, network, sender, recipient, home_hooks, router, _) = relay_home(None).await;
    network.serve(
        COORDINATOR_DS,
        Router::new().fallback(|| async { "not a direct request outcome" }),
    );
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, Uuid::new_v4());
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        (StatusCode::BAD_REQUEST, None, Some("RequestPolicyDenied")),
        "{body}"
    );
}

/// RECIPIENT_DS's production `reserveRecipientBootstrap` and
/// `releaseRecipientBootstrap` for this home, its pair coordinator, on the
/// recipient home's `pool`.
fn recipient_home(pool: DbPool, hooks: Arc<SimDsHooks>) -> Router {
    let release = (pool.clone(), Arc::clone(&hooks));
    Router::new()
        .route(
            RESERVE,
            axum::routing::post(move |Json(input): Json<ReserveRecipientBootstrapInput>| {
                let (pool, hooks) = (pool.clone(), Arc::clone(&hooks));
                async move {
                    scope_sim_ds(
                        hooks,
                        local_reserve_recipient_bootstrap(&pool, SENDER_DS, &input),
                    )
                    .await
                    .map(|selected_devices| {
                        Json(ReserveRecipientBootstrapOutput { selected_devices })
                    })
                }
            }),
        )
        .route(
            RELEASE,
            axum::routing::post(move |Json(input): Json<ReleaseRecipientBootstrapInput>| {
                let (pool, hooks) = (release.0.clone(), Arc::clone(&release.1));
                async move {
                    scope_sim_ds(
                        hooks,
                        local_release_recipient_bootstrap(
                            &pool,
                            SENDER_DS,
                            input.request_id,
                            &input.recipient_did,
                        ),
                    )
                    .await
                    .map(|()| Json(json!({ "released": true })))
                }
            }),
        )
}

/// This home coordinates a pair whose recipient is homed at RECIPIENT_DS, and
/// already holds the recipient's device under another key. Staging the device
/// the recipient home leases refuses that identity: prepare is the definitive
/// `RecipientKeysUnavailable` and releases the lease, never the storage failure
/// that hid the refusal and kept the lease.
#[tokio::test]
async fn a_leased_device_identity_staging_refuses_is_recipient_keys_unavailable() {
    let (_db, pool, network, sender, _, home_hooks, router, _) = relay_home(None).await;
    let recipient_db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let recipient_pool = recipient_db.connect(4).await;
    ensure_fence(&recipient_pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(SENDER_DS)
        .execute(&recipient_pool)
        .await
        .unwrap();
    let unique = Uuid::new_v4().simple();
    let recipient = format!("did:web:dr-relay-conflict-{unique}.example.com");
    network.declare_user(&recipient, RECIPIENT_DS);
    let (device_key, _) = seed_published_request_keys(&recipient_pool, &recipient, 1)
        .await
        .expect("the recipient's published request keys");
    network.authorize_device(&recipient, &device_key);
    network.serve(
        RECIPIENT_DS,
        recipient_home(
            recipient_pool.clone(),
            hooks(RECIPIENT_DS, None, false, &network),
        ),
    );
    let device_id: Uuid =
        sqlx::query_scalar("SELECT device_id FROM chat.devices WHERE user_did = $1")
            .bind(&recipient)
            .fetch_one(&recipient_pool)
            .await
            .unwrap();
    let conflicting = ed25519_dalek::SigningKey::from_bytes(&[0x7c; 32]);
    seed_actor_at(
        &pool,
        &recipient,
        device_id,
        &conflicting.verifying_key().to_bytes(),
        clock_now(&pool).await,
    )
    .await;

    let request_id = Uuid::new_v4();
    let prepare = sender.sign(DirectRequestKind::Prepare, &recipient, request_id);
    let (status, retry_after, body) = call(&router, &home_hooks, &sender, PREPARE, &prepare).await;
    assert_eq!(
        (status, retry_after.as_deref(), body["error"].as_str()),
        (
            StatusCode::BAD_REQUEST,
            None,
            Some("RecipientKeysUnavailable")
        ),
        "{body}"
    );
    assert!(
        package_refs(&pool, "direct_request_reserved_remote_packages", request_id)
            .await
            .is_empty(),
        "nothing was staged"
    );
    assert_eq!(
        texts(
            &recipient_pool,
            "SELECT status FROM chat.direct_request_remote_leases WHERE request_id = $1",
            request_id,
        )
        .await,
        ["released"]
    );
}

/// A delivered request's sender key is looked up at the sender's PDS before
/// the recipient home ingests it. A PDS that could not answer now decides
/// nothing: the retryable 502 the coordinator's queue retries, never the empty
/// key set that refused the delivery for good (403). A PDS that refuses the
/// listing is definitive (404); one that answers yields the named key.
#[tokio::test]
async fn a_sender_key_lookup_that_fails_is_typed_never_an_empty_key_set() {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(2).await;
    let network = Network::new(&[(RECIPIENT_DS, &key(0x6f))]);
    let actor = format!(
        "did:web:dr-relay-actor-{}.example.com",
        Uuid::new_v4().simple()
    );
    network.declare_user(&actor, SENDER_DS);
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x6e; 32]);
    let public = signing.verifying_key().to_bytes();
    let key_id = crate::chat_protocol::validation::ed25519_key_id(&public)
        .unwrap()
        .as_str()
        .to_owned();
    let recipient_hooks = hooks(RECIPIENT_DS, None, false, &network);
    let lookup = || {
        let (pool, actor, key_id) = (pool.clone(), actor.clone(), key_id.clone());
        scope_sim_ds(Arc::clone(&recipient_hooks), async move {
            let resolver = DsResolver::with_default_endpoint(
                pool,
                crate::federation::resolver::build_resolver_http_client(),
                crate::identity::service_did(),
                crate::identity::self_endpoint(),
                None,
                0,
            );
            live_actor_key(&resolver, &actor, &key_id).await
        })
    };
    let pds = format!("pds-{}", host(&actor));

    network.serve(
        &pds,
        Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    );
    let unavailable = lookup().await.expect_err("the PDS could not answer");
    assert!(unavailable.is_retryable(), "{unavailable:?}");
    assert_eq!(unavailable.status_code(), StatusCode::BAD_GATEWAY);

    network.serve(&pds, Router::new());
    let refused = lookup().await.expect_err("the PDS refused the listing");
    assert!(!refused.is_retryable(), "{refused:?}");
    assert_eq!(refused.status_code(), StatusCode::NOT_FOUND);

    network.authorize_device(&actor, &public);
    assert_eq!(lookup().await.unwrap(), Some(public.to_vec()));
}

/// COORDINATOR_DS holding an actor's published request to a recipient (its
/// attempt), with its request receipt authority readied by the startup check:
/// its database (held for the test), pool, the sim network, its hooks, its
/// runtime and the request.
async fn coordinator_of_a_published_request() -> (
    impl Sized,
    DbPool,
    Network,
    Arc<SimDsHooks>,
    Arc<ChatRuntime>,
    CleanSlatePendingDirectRequestFixture,
) {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    ensure_fence(&pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(SENDER_DS)
        .execute(&pool)
        .await
        .unwrap();
    let (coordinator_key, receipt_key) = (key(0x6b), key(0x7a));
    let network = Network::new(&[(SENDER_DS, &key(0x6a)), (COORDINATOR_DS, &coordinator_key)]);
    for ds in [SENDER_DS, COORDINATOR_DS] {
        network.declare_delivery_service(ds);
    }
    let (receipt_pem, service_pem) = (pem(&receipt_key), pem(&coordinator_key));
    let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
        COORDINATOR_DS,
        receipt_key.verifying_key(),
    )
    .to_string();
    let signer =
        DirectRequestReceiptSigner::configured(&receipt_pem, &service_pem, &document).unwrap();
    let unique = Uuid::new_v4().simple();
    let request = seed_clean_slate_pending_direct_request_fixture(
        &pool,
        &signer,
        &format!("did:web:dr-relay-actor-{unique}.example.com"),
        &format!("did:web:dr-relay-peer-{unique}.example.com"),
    )
    .await
    .unwrap();
    // The harness scopes the cutover environment (the cursor sealer the
    // startup check needs) to runtime construction.
    let mut built = None;
    let _ = http::router_for_authenticated_acceptance_with(pool.clone(), |runtime| {
        built = Some(ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8))).unwrap());
        runtime
    })
    .await;
    let runtime = built
        .unwrap()
        .with_request_receipt_keys(&receipt_pem, &service_pem, &document)
        .unwrap()
        .with_sim_allow_all_relationships()
        .unwrap();
    runtime.validate_protocol_fence(&pool).await.unwrap();
    let runtime = Arc::new(runtime);
    let hooks = hooks(COORDINATOR_DS, Some(&coordinator_key), false, &network);
    (db, pool, network, hooks, runtime, request)
}

/// Take the `chat` table `from` out of service as `to`, or back.
async fn rename(pool: &DbPool, from: &str, to: &str) {
    sqlx::query(&format!("ALTER TABLE chat.{from} RENAME TO {to}"))
        .execute(pool)
        .await
        .unwrap();
}

/// A home reads an outcome only once the coordinator resolves it as either
/// party's declared home. While neither party's home can be resolved that
/// decided nothing: the retryable 502, never the `Unauthorized` a peer takes as
/// final. A DS both resolved homes rule out is still refused.
#[tokio::test]
async fn an_outcome_read_whose_homes_cannot_resolve_now_is_retryable_not_unauthorized() {
    let (_db, pool, network, hooks, runtime, request) = coordinator_of_a_published_request().await;
    let undecided = scope_sim_ds(
        Arc::clone(&hooks),
        coordinator_get_outcome(
            &pool,
            &runtime,
            SENDER_DS,
            request.request_id,
            request.actor_device_id,
        ),
    )
    .await
    .expect_err("neither party's home resolves");
    assert!(undecided.is_retryable(), "{undecided:?}");
    assert_eq!(undecided.status_code(), StatusCode::BAD_GATEWAY);

    network.declare_user(&request.actor_did, SENDER_DS);
    network.declare_user(&request.recipient_did, COORDINATOR_DS);
    let refused = scope_sim_ds(
        Arc::clone(&hooks),
        coordinator_get_outcome(
            &pool,
            &runtime,
            MOVED_DS,
            request.request_id,
            request.actor_device_id,
        ),
    )
    .await
    .expect_err("MOVED_DS homes neither party");
    assert!(
        matches!(refused, FederationError::AuthFailed { .. }),
        "{refused:?}"
    );
}

/// The coordinator store that cannot serve a home's outcome read decided
/// nothing: the retryable 503, never the 400 its caller takes as final. The
/// identical read answers once the store does.
#[tokio::test]
async fn an_outcome_read_the_coordinator_store_cannot_serve_is_retryable() {
    let (_db, pool, network, hooks, runtime, request) = coordinator_of_a_published_request().await;
    network.declare_user(&request.actor_did, SENDER_DS);
    network.declare_user(&request.recipient_did, COORDINATOR_DS);
    let read = || {
        scope_sim_ds(
            Arc::clone(&hooks),
            coordinator_get_outcome(
                &pool,
                &runtime,
                SENDER_DS,
                request.request_id,
                request.actor_device_id,
            ),
        )
    };
    rename(
        &pool,
        "direct_request_budget",
        "direct_request_budget_offline",
    )
    .await;
    let failed = read().await;
    rename(
        &pool,
        "direct_request_budget_offline",
        "direct_request_budget",
    )
    .await;
    let error = failed.expect_err("the store cannot serve the read");
    // This DS's own store: a 5xx its caller retries, never the old 400.
    assert!(error.status_code().is_server_error(), "{error:?}");
    let answered = read().await.expect("the identical read answers");
    assert!(answered["outcome"].is_object(), "{answered}");
}

/// A relayed prepare the coordinator already recorded replays its answer. A
/// replay its store cannot serve decided nothing: the retryable 503, never the
/// 409 the sender home makes the definitive `PreparationConflict`, and the
/// recorded attempt is unchanged.
#[tokio::test]
async fn a_prepare_replay_the_coordinator_store_cannot_serve_is_retryable() {
    let (_db, pool, network, hooks, runtime, request) = coordinator_of_a_published_request().await;
    network.declare_user(&request.actor_did, SENDER_DS);
    network.declare_user(&request.recipient_did, COORDINATOR_DS);
    let device = ed25519_dalek::SigningKey::from_bytes(&request.actor_ed25519_seed);
    network.authorize_device(&request.actor_did, &device.verifying_key().to_bytes());
    let signed = sign_request(
        DirectRequestKind::Prepare,
        &device,
        (
            &request.actor_did,
            request.actor_device_id,
            &request.actor_key_id,
        ),
        &request.recipient_did,
        request.request_id,
    );
    let input = json!({
        "signedRequest": signed,
        "senderDeviceKey": {
            "deviceId": request.actor_device_id,
            "keyId": request.actor_key_id,
            "authGeneration": signed["body"]["authGeneration"],
            "signingPublicKey": STANDARD.encode(device.verifying_key().to_bytes()),
        },
    });
    let attempt = "SELECT status FROM chat.direct_request_attempts WHERE request_id = $1";
    let before = texts(&pool, attempt, request.request_id).await;
    rename(&pool, "device_keys", "device_keys_offline").await;
    let replayed = scope_sim_ds(
        Arc::clone(&hooks),
        coordinator_prepare_direct_request(&pool, &runtime, SENDER_DS, &input),
    )
    .await;
    rename(&pool, "device_keys_offline", "device_keys").await;
    let error = replayed.expect_err("the store cannot serve the replay");
    // This DS's own store: a 5xx its caller retries, never the old 409.
    assert!(error.status_code().is_server_error(), "{error:?}");
    assert_eq!(
        texts(&pool, attempt, request.request_id).await,
        before,
        "nothing was decided"
    );
}

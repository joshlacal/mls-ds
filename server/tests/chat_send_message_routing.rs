//! Real sendMessage HTTP admission, durable entry replay, and federation routing.
//!
//! Initial two-member MLS history and external relationship responses are test
//! fixtures. Service JWT and body signature validation, operation admission,
//! message persistence, and federation enqueue use production code.
//! Each case owns a fresh PostgreSQL database; no Docker or production service
//! is contacted. Unique example.com actor homes make direct-resolution failure
//! explicit while a group must succeed without consulting that resolver.

mod common;

use axum::{http::StatusCode, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_server::chat_protocol::test_support::{
    decode_canonical_signed_mutation, seed_clean_slate_application_fixture,
    seed_remote_clean_slate_application_fixture, sign_mutation_json_for_test,
    CleanSlateApplicationFixture,
};
use common::http_acceptance as http;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};
use tower_util::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

const NSID: &str = "blue.catbird.chat.sendMessage";
const REMOTE_SERVICE: &str = "did:web:remote.routing.example.com";
const DELIVER_MESSAGE: &str = "blue.catbird.mlsDS.deliverMessage";
const DELIVER_ENTRY: &str = "blue.catbird.mlsDS.deliverMessageEntry";
const DELIVER_GROUP_ENTRY: &str = "blue.catbird.mlsDS.deliverGroupEntry";

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl Write for TraceCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn setup(
    direct: bool,
) -> (
    PgPool,
    common::fresh_db::DisposableDatabase,
    CleanSlateApplicationFixture,
    http::Device,
    Router,
) {
    setup_routing(direct, false, true).await
}

async fn setup_routing(
    direct: bool,
    remote_group: bool,
    signer_configured: bool,
) -> (
    PgPool,
    common::fresh_db::DisposableDatabase,
    CleanSlateApplicationFixture,
    http::Device,
    Router,
) {
    // Every case selects the same process environment. Only the fixture's
    // persisted, signed kind differs; no router or resolver test hook is used.
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");
    let (pool, database) = common::fresh_db::fresh_legacy_pool("chat_sendrouting_", 4, 1).await;
    http::ensure_fence(&pool).await;
    let archive_commitment = signer_configured.then_some([0xa7_u8; 32]);
    let fixture = if remote_group {
        assert!(!direct, "remote regression is specific to group sequencing");
        seed_remote_clean_slate_application_fixture(
            &pool,
            REMOTE_SERVICE,
            REMOTE_SERVICE,
            archive_commitment,
        )
        .await
    } else {
        seed_clean_slate_application_fixture(&pool, direct, REMOTE_SERVICE, archive_commitment)
            .await
    }
    .expect("genuine ready MLS history and validated traffic projection");
    assert!(application_entries(&pool, &fixture).await.is_empty());
    assert!(federation_jobs(&pool, &fixture).await.is_empty());
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    let device = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing,
        jwk,
    };
    http::cache_device_did(&device).await;
    let router = if signer_configured {
        http::router_for_authenticated_acceptance(pool.clone()).await
    } else {
        http::router_for_authenticated_acceptance_without_i13(pool.clone()).await
    };
    (pool, database, fixture, device, router)
}

async fn post(router: &Router, device: &http::Device, signed: &Value) -> (StatusCode, Value) {
    let (status, response, _) = post_with_trace(router, device, signed).await;
    (status, response)
}

async fn post_with_trace(
    router: &Router,
    device: &http::Device,
    signed: &Value,
) -> (StatusCode, Value, String) {
    let capture = TraceCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_writer(capture.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    // A timeout is a failing test, never evidence that the direct resolver ran.
    let (status, response) = tokio::time::timeout(
        Duration::from_secs(20),
        http::send(
            router.clone(),
            http::unsigned_json_request(
                device,
                NSID,
                serde_json::to_vec(&json!({"signedRequest": signed})).unwrap(),
            ),
        )
        .with_subscriber(subscriber),
    )
    .await
    .expect("sendMessage completed within the resolver deadline");
    let trace = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    (status, response, trace)
}

async fn application_entries(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
) -> Vec<(Uuid, i64, Vec<u8>)> {
    sqlx::query_as(
        "SELECT entry_id,seq,signed_request_bytes FROM chat.entries \
         WHERE conversation_id=$1 AND message_id=$2 ORDER BY seq",
    )
    .bind(fixture.conversation_id)
    .bind(fixture.message_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn federation_jobs(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
) -> Vec<(String, String, String, Vec<u8>, Vec<u8>)> {
    sqlx::query_as(
        "SELECT id,method,target_service_did,payload,payload_sha256 \
         FROM federation_outbox WHERE conversation_id=$1 ORDER BY id",
    )
    .bind(fixture.conversation_id.to_string())
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn assert_no_direct_delivery(pool: &PgPool, fixture: &CleanSlateApplicationFixture) {
    let count: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM federation_outbox WHERE conversation_id=$1 AND method=$2) \
              + (SELECT count(*) FROM outbound_queue WHERE convo_id=$1 AND method=$2)",
    )
    .bind(fixture.conversation_id.to_string())
    .bind(DELIVER_ENTRY)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "no direct-request entry delivery is queued");
}

async fn business_snapshot(pool: &PgPool, fixture: &CleanSlateApplicationFixture) -> Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(\
         'head', (SELECT to_jsonb(c) FROM chat.conversations c WHERE conversation_id=$1), \
         'entries', (SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id=$1), \
         'recipients', (SELECT jsonb_agg(to_jsonb(r) ORDER BY seq,user_did,device_id) FROM chat.entry_recipients r WHERE conversation_id=$1), \
         'sends', (SELECT jsonb_agg(to_jsonb(s)) FROM chat.message_sends s WHERE conversation_id=$1), \
         'claims', (SELECT jsonb_agg(to_jsonb(c)) FROM chat.operation_claims c WHERE operation_id=$2), \
         'receipts', (SELECT jsonb_agg(to_jsonb(i)) FROM chat.idempotency_records i WHERE operation_id=$2))",
    )
    .bind(fixture.conversation_id)
    .bind(fixture.message_id)
    .fetch_one(pool)
    .await
    .expect("snapshot head and durable send/entry/operation state")
}

async fn assert_single_application_and_job(pool: &PgPool, fixture: &CleanSlateApplicationFixture) {
    let entries = application_entries(pool, fixture).await;
    assert_eq!(entries.len(), 1, "exactly one accepted application entry");
    assert_eq!(
        entries[0].1, 4,
        "application follows real Creation/Acceptance/Add history"
    );
    let persisted: Value = serde_json::from_slice(&entries[0].2).unwrap();
    assert_eq!(
        persisted, fixture.signed_request,
        "original signed request survives persistence"
    );
    assert_eq!(
        entries[0].2,
        serde_json::to_vec(&fixture.signed_request).unwrap(),
        "exact originally serialized signed-request bytes survive persistence"
    );
    let jobs = federation_jobs(pool, fixture).await;
    assert_eq!(jobs.len(), 1, "exactly one ordinary federation delivery");
    assert_eq!(jobs[0].1, DELIVER_MESSAGE);
    assert_eq!(jobs[0].2, REMOTE_SERVICE);
    assert_eq!(jobs[0].4, Sha256::digest(&jobs[0].3).to_vec());
    let payload: Value = serde_json::from_slice(&jobs[0].3).unwrap();
    assert_eq!(payload["recipientDid"], fixture.recipient_did);
    assert_eq!(payload["entryLocator"]["entryId"], entries[0].0.to_string());
    assert_eq!(payload["entryLocator"]["seq"], 4);
    assert_no_direct_delivery(pool, fixture).await;
}

/// Each queued delivery's stable identity; status and retry columns move while
/// the post-commit sender retries the unreachable fixture home.
async fn group_entry_deliveries(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
) -> Vec<(String, String, String, Vec<u8>)> {
    sqlx::query_as(
        "SELECT id, method, target_ds_did, payload FROM outbound_queue \
          WHERE convo_id=$1 ORDER BY id",
    )
    .bind(fixture.conversation_id.to_string())
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A group application reaches its remote home only through the ordered
/// `deliverGroupEntry` stream: one delivery for its seq, no `deliverMessage`.
async fn assert_single_application_and_group_entry(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
) {
    let entries = application_entries(pool, fixture).await;
    assert_eq!(entries.len(), 1, "exactly one accepted application entry");
    assert_eq!(
        entries[0].1, 4,
        "application follows real Creation/Acceptance/Add history"
    );
    assert_eq!(
        entries[0].2,
        serde_json::to_vec(&fixture.signed_request).unwrap(),
        "exact originally serialized signed-request bytes survive persistence"
    );
    assert!(
        federation_jobs(pool, fixture).await.is_empty(),
        "a group replicates no application through deliverMessage"
    );
    let deliveries = group_entry_deliveries(pool, fixture).await;
    assert_eq!(
        deliveries.len(),
        1,
        "exactly one ordered group-entry delivery"
    );
    let (id, method, target, payload) = &deliveries[0];
    assert_eq!(
        id,
        &format!("group-entry-{}-4-{REMOTE_SERVICE}", fixture.conversation_id)
    );
    assert_eq!(method, DELIVER_GROUP_ENTRY);
    assert_eq!(target, REMOTE_SERVICE);
    let payload: Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(
        payload["conversationId"],
        fixture.conversation_id.to_string()
    );
    assert_eq!(payload["entry"]["seq"], 4);
    assert_eq!(payload["entry"]["entryId"], entries[0].0.to_string());
    assert!(
        payload["recipientDids"]
            .as_array()
            .is_some_and(|dids| dids.iter().any(|did| did == &fixture.recipient_did)),
        "the remote recipient is in the delivery's frozen audience: {payload}"
    );
    assert_no_direct_delivery(pool, fixture).await;
}

fn request_presentation_of_response(response: &Value) -> Value {
    let mut wrapper = response.clone();
    // Only the known byte fields of this attachment-free application may
    // change JSON presentation. Unknown fields/tags remain for the strict
    // request parser to reject; no signed data or database bytes are rewritten.
    for pointer in [
        "/signature",
        "/body/prior/groupId",
        "/body/prior/groupContextHash",
        "/body/prior/confirmationTag",
        "/body/aad/conversationId",
        "/body/aad/messageId",
        "/body/aad/prior/conversationId",
        "/body/aad/prior/groupId",
        "/body/aad/prior/groupContextHash",
        "/body/aad/archiveCommitment",
        "/body/aad/originalSenderAttestation/senderTransportPubkey",
        "/body/aad/originalSenderAttestation/signature",
        "/body/aad/prior/confirmationTag",
        "/body/applicationMessage/bytes",
        "/body/applicationMessage/sha256",
    ] {
        let field = wrapper
            .pointer_mut(pointer)
            .expect("known application byte field");
        let object = field.as_object().expect("response byte field is an object");
        assert_eq!(
            object.len(),
            1,
            "byte wrapper has no extra fields at {pointer}"
        );
        let encoded = object
            .get("$bytes")
            .and_then(Value::as_str)
            .expect("exact $bytes string");
        let decoded = STANDARD
            .decode(encoded)
            .expect("valid response byte encoding");
        assert_eq!(
            STANDARD.encode(&decoded),
            encoded,
            "canonical base64 at {pointer}"
        );
        *field = Value::String(encoded.to_owned());
    }
    wrapper
}

fn archive_less_request(fixture: &CleanSlateApplicationFixture) -> Value {
    let mut body = fixture.signed_request["body"].clone();
    let aad = body["aad"].as_object_mut().expect("application AAD object");
    assert!(aad.remove("archiveCommitment").is_some());
    assert!(aad.remove("originalSenderAttestation").is_some());
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    sign_mutation_json_for_test(&body, &signing_key).expect("sign archive-less request")
}

async fn application_receipt_state(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
) -> (i64, Vec<(i64, Option<Vec<u8>>)>) {
    let next_entry_seq = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let entries = sqlx::query_as(
        "SELECT seq,sequencer_receipt_bytes FROM chat.entries \
         WHERE conversation_id=$1 AND message_id=$2 ORDER BY seq",
    )
    .bind(fixture.conversation_id)
    .bind(fixture.message_id)
    .fetch_all(pool)
    .await
    .unwrap();
    (next_entry_seq, entries)
}

#[tokio::test]
async fn group_send_and_exact_replay_keep_one_ordered_group_entry_delivery() {
    let (pool, _database, fixture, device, router) = setup(false).await;
    assert!(application_entries(&pool, &fixture).await.is_empty());
    assert!(federation_jobs(&pool, &fixture).await.is_empty());
    let (status, response, trace) =
        post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "group send response: {response}");
    assert!(
        !trace.contains("Failed to resolve application entry peer"),
        "group avoids direct resolver: {trace}"
    );
    // HTTP output renders protocol byte values as {$bytes: ...}; compare the
    // authenticated transcript and signature across that presentation change.
    // The database assertion below separately requires the original JSON bytes.
    let sent =
        decode_canonical_signed_mutation(&serde_json::to_vec(&fixture.signed_request).unwrap())
            .unwrap();
    let returned = decode_canonical_signed_mutation(
        &serde_json::to_vec(&request_presentation_of_response(
            &response["entry"]["signedRequest"],
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(returned.transcript_bytes(), sent.transcript_bytes());
    assert_eq!(returned.signature(), sent.signature());
    assert_single_application_and_group_entry(&pool, &fixture).await;
    let entries_before = application_entries(&pool, &fixture).await;
    let deliveries_before = group_entry_deliveries(&pool, &fixture).await;

    let (status, replay, trace) = post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "group replay response: {replay}");
    assert!(
        !trace.contains("Failed to resolve application entry peer"),
        "group replay avoids direct resolver: {trace}"
    );
    assert_eq!(
        replay, response,
        "same accepted entry on byte-identical body retry"
    );
    assert_eq!(application_entries(&pool, &fixture).await, entries_before);
    assert!(federation_jobs(&pool, &fixture).await.is_empty());
    assert_eq!(
        group_entry_deliveries(&pool, &fixture).await,
        deliveries_before,
        "a replay queues no second delivery"
    );
    assert_no_direct_delivery(&pool, &fixture).await;
}

#[tokio::test]
async fn signer_configured_send_requires_archive_commitment_before_sequencing() {
    let (pool, _database, fixture, device, router) = setup(false).await;
    let (expected_seq, initial_entries) = application_receipt_state(&pool, &fixture).await;
    assert_eq!(expected_seq, 4);
    assert!(initial_entries.is_empty());

    let archive_less = archive_less_request(&fixture);
    let (status, refusal) = post(&router, &device, &archive_less).await;
    let (after_bad_next, after_bad_entries) = application_receipt_state(&pool, &fixture).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "archive-less result: status={status}, body={refusal}, \
         next_entry_seq={after_bad_next}, entries={after_bad_entries:?}"
    );
    assert_eq!(refusal["error"], "InvalidApplicationMessage");
    assert_eq!(after_bad_next, expected_seq);
    assert!(after_bad_entries.is_empty());

    let (status, accepted) = post(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "well-formed send: {accepted}");
    assert_eq!(accepted["entry"]["seq"].as_i64(), Some(expected_seq));
    assert!(accepted["sequencerReceipt"].is_object());
    assert!(accepted["entry"]["sequencerReceipt"].is_object());
    let accepted_state = application_receipt_state(&pool, &fixture).await;
    assert_eq!(accepted_state.0, expected_seq + 1);
    assert_eq!(accepted_state.1.len(), 1);
    assert_eq!(accepted_state.1[0].0, expected_seq);
    assert!(
        accepted_state.1[0]
            .1
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty()),
        "accepted entry stores its sequencer receipt"
    );

    let (status, replay) = post(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "accepted replay: {replay}");
    assert_eq!(replay, accepted);
    assert_eq!(
        application_receipt_state(&pool, &fixture).await,
        accepted_state,
        "accepted replay neither sequences nor rewrites the receipt"
    );
}

#[tokio::test]
async fn signerless_server_still_sequences_archive_less_send_without_receipt() {
    let (pool, _database, fixture, device, router) = setup_routing(false, false, false).await;
    assert!(fixture
        .signed_request
        .pointer("/body/aad/archiveCommitment")
        .is_none());
    let (expected_seq, initial_entries) = application_receipt_state(&pool, &fixture).await;
    assert_eq!(expected_seq, 4);
    assert!(initial_entries.is_empty());

    let (status, accepted) = post(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "signer-less send: {accepted}");
    assert!(accepted.get("sequencerReceipt").is_none());
    assert!(accepted["entry"].get("sequencerReceipt").is_none());
    let (next_entry_seq, entries) = application_receipt_state(&pool, &fixture).await;
    assert_eq!(next_entry_seq, expected_seq + 1);
    assert_eq!(entries, vec![(expected_seq, None)]);
}

/// Status, `Retry-After` and body of one send through `router`.
async fn post_answer(
    router: &Router,
    device: &http::Device,
    signed: &Value,
) -> (StatusCode, Option<String>, Value) {
    let request = http::unsigned_json_request(
        device,
        NSID,
        serde_json::to_vec(&json!({"signedRequest": signed})).unwrap(),
    );
    let response = tokio::time::timeout(Duration::from_secs(20), router.clone().oneshot(request))
        .await
        .expect("sendMessage completed within its deadline")
        .unwrap();
    let status = response.status();
    let retry_after = response
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        retry_after,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

/// `(status, Retry-After, error)` of an answer.
fn answered(
    answer: &(StatusCode, Option<String>, Value),
) -> (StatusCode, Option<&str>, Option<&str>) {
    (answer.0, answer.1.as_deref(), answer.2["error"].as_str())
}

/// The send decided nothing: its head, send, entry, operation and federation
/// rows are exactly `before`.
async fn assert_nothing_committed(
    pool: &PgPool,
    fixture: &CleanSlateApplicationFixture,
    before: &Value,
    attempt: &str,
) {
    assert_eq!(
        &business_snapshot(pool, fixture).await,
        before,
        "{attempt}: no head, send, entry or operation change"
    );
    assert!(
        application_entries(pool, fixture).await.is_empty(),
        "{attempt}"
    );
    assert!(federation_jobs(pool, fixture).await.is_empty(), "{attempt}");
    assert!(
        group_entry_deliveries(pool, fixture).await.is_empty(),
        "{attempt}"
    );
}

/// Only its sequencer sequences a remote group. Its replica's own read of the
/// group failing is storage, not an unknown conversation. A closed federation
/// gate, or a sequencer route that could not answer now, decided nothing:
/// `RelationshipPolicyUnavailable` with `Retry-After: 5`, never the local
/// path's `NotAuthorized`. A sequencer that cannot be routed is refused, and
/// the replica's store failing while routing is storage. Nothing is committed
/// or relayed; once the gate is open and the sequencer resolves, the identical
/// send is relayed once and answered with the sequencer's entry.
#[tokio::test]
async fn remote_group_send_is_only_ever_sequenced_by_its_sequencer() {
    use catbird_server::federation::{
        errors::{FederationError, ResolutionFailureKind},
        resolver::{DsResolver, ValidatedRemoteDestination},
        FederationMode,
    };
    #[derive(Clone, Copy)]
    enum Route {
        Unreachable,
        Unroutable,
        StoreFailing,
        Resolves,
    }
    let (pool, _database, fixture, device, _) = setup_routing(false, true, true).await;
    let routing: (String, bool, Option<String>, i64) = sqlx::query_as(
        "SELECT kind,is_remote,sequencer_ds,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        routing,
        ("group".to_owned(), true, Some(REMOTE_SERVICE.to_owned()), 4),
        "the immutable replica routing identity is seeded before admission"
    );

    // The group's sequencer: counts relays and answers its sequenced entry.
    let entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "conversationId": fixture.conversation_id,
        "entryId": Uuid::new_v4(),
        "seq": 4,
        "signedRequest": fixture.signed_request,
        "receivedAt": "2026-11-05T00:00:00.000Z",
    });
    let relays = Arc::new(AtomicUsize::new(0));
    let sequencer = Router::new().route(
        "/xrpc/blue.catbird.mlsDS.relayGroupMutation",
        axum::routing::post({
            let (relays, entry) = (Arc::clone(&relays), entry.clone());
            move || async move {
                relays.fetch_add(1, SeqCst);
                axum::Json(json!({ "entry": entry }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, sequencer).await.unwrap() });
    // What resolving the sequencer answers.
    let route = Arc::new(Mutex::new(Route::Unreachable));
    let hook_route = Arc::clone(&route);
    let resolver = DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        "did:web:chat.catbird.blue".to_owned(),
        "https://chat.catbird.blue".to_owned(),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(move |did: &str| {
        let (route, did) = (*hook_route.lock().unwrap(), did.to_owned());
        Some(Box::pin(async move {
            match route {
                Route::Unreachable => Err(FederationError::DsUnreachable {
                    endpoint: did,
                    reason: "sequencer unreachable".to_owned(),
                }),
                Route::Unroutable => Err(FederationError::ResolutionFailed {
                    did,
                    kind: ResolutionFailureKind::DnsNxdomain("no such host".to_owned()),
                }),
                Route::StoreFailing => Err(FederationError::Database(sqlx::Error::PoolTimedOut)),
                Route::Resolves => Ok(ValidatedRemoteDestination {
                    url: format!("http://{address}").parse().unwrap(),
                    host: address.ip().to_string(),
                    addrs: vec![address],
                }),
            }
        }))
    }));
    let router = http::router_for_authenticated_acceptance_with(pool.clone(), |runtime| {
        runtime.with_resolver(Arc::new(resolver))
    })
    .await;
    std::env::set_var(
        "FEDERATION_GROUP_RELAY_HMAC_SECRET",
        "send-routing-relay-secret",
    );
    let before = business_snapshot(&pool, &fixture).await;
    assert!(before["sends"].is_null());
    assert!(before["claims"].is_null());
    assert!(before["receipts"].is_null());

    let hidden = |from: &str, to: &str| {
        format!("ALTER TABLE chat.conversations RENAME COLUMN {from} TO {to}")
    };
    sqlx::query(&hidden("sequencer_ds", "sequencer_ds_hidden"))
        .execute(&pool)
        .await
        .unwrap();
    let answer = post_answer(&router, &device, &fixture.signed_request).await;
    sqlx::query(&hidden("sequencer_ds_hidden", "sequencer_ds"))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        answered(&answer),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some("InternalServerError")
        ),
        "replica's own read failing: {}",
        answer.2
    );
    assert_nothing_committed(&pool, &fixture, &before, "replica's own read failing").await;

    FederationMode::set_runtime_override(Some(FederationMode::Off));
    for _ in 0..2 {
        let answer = post_answer(&router, &device, &fixture.signed_request).await;
        assert_eq!(
            answered(&answer),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
                Some("RelationshipPolicyUnavailable")
            ),
            "gate closed: {}",
            answer.2
        );
        assert_nothing_committed(&pool, &fixture, &before, "gate closed").await;
    }

    catbird_server::federation::open_federation_for_test();
    for (answer_route, expected, attempt) in [
        (
            Route::Unreachable,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
                Some("RelationshipPolicyUnavailable"),
            ),
            "sequencer unreachable",
        ),
        (
            Route::Unroutable,
            (StatusCode::UNAUTHORIZED, None, Some("NotAuthorized")),
            "sequencer unroutable",
        ),
        (
            Route::StoreFailing,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                Some("InternalServerError"),
            ),
            "replica's store failing while routing",
        ),
    ] {
        *route.lock().unwrap() = answer_route;
        let answer = post_answer(&router, &device, &fixture.signed_request).await;
        assert_eq!(answered(&answer), expected, "{attempt}: {}", answer.2);
        assert_nothing_committed(&pool, &fixture, &before, attempt).await;
    }
    assert_eq!(relays.load(SeqCst), 0, "nothing reached the sequencer");

    *route.lock().unwrap() = Route::Resolves;
    let (status, _, response) = post_answer(&router, &device, &fixture.signed_request).await;
    FederationMode::set_runtime_override(None);
    std::env::remove_var("FEDERATION_GROUP_RELAY_HMAC_SECRET");
    assert_eq!(status, StatusCode::OK, "sequencer answering: {response}");
    assert_eq!(relays.load(SeqCst), 1, "relayed once");
    assert_eq!(response["entry"]["entryId"], entry["entryId"]);
    assert_eq!(response["entry"]["seq"], 4);
    assert_nothing_committed(&pool, &fixture, &before, "relayed").await;
}

/// A local send whose relationship source cannot answer now decided nothing:
/// `RelationshipPolicyUnavailable` with `Retry-After: 5`, and nothing is
/// committed. Once the source answers, the identical send is accepted.
#[tokio::test]
async fn local_send_is_retryable_while_its_relationship_source_cannot_answer() {
    use catbird_server::chat_protocol::relationship_policy::{SimSourceFault, TransportError};
    let (pool, _database, fixture, device, _) = setup(false).await;
    let source = SimSourceFault::default();
    let router = http::router_for_authenticated_acceptance_with(pool.clone(), {
        let source = source.clone();
        move |runtime| {
            runtime
                .with_sim_faulty_relationships(source)
                .expect("the faulty relationship authority")
        }
    })
    .await;
    // No fresh fallback is cached: the send collects its traffic graph live.
    sqlx::query("TRUNCATE chat.relationship_projection_snapshots CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    let before = business_snapshot(&pool, &fixture).await;

    *source.lock().unwrap() = Some(Err(TransportError::Network));
    let answer = post_answer(&router, &device, &fixture.signed_request).await;
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
    assert_nothing_committed(&pool, &fixture, &before, "relationship source unreachable").await;

    *source.lock().unwrap() = None;
    let (status, _, response) = post_answer(&router, &device, &fixture.signed_request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "relationship source answering: {response}"
    );
    assert_single_application_and_group_entry(&pool, &fixture).await;
}

#[tokio::test]
async fn ordinary_direct_send_uses_queued_envelope_without_c33_redelivery() {
    let (pool, _database, fixture, device, router) = setup(true).await;
    let (status, response, trace) =
        post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "direct response: {response}");
    assert!(
        !trace.contains("Failed to resolve application entry peer")
            && !trace.contains("Failed to resolve PDS endpoint from DID document"),
        "ordinary Direct must not enter the C33 delivery path: {trace}"
    );
    // This is an ordinary Direct conversation, not a published C33 request.
    // Its signed clean envelope was queued atomically with the accepted entry,
    // so a redundant post-commit deliverMessageEntry would only duplicate it.
    assert_single_application_and_job(&pool, &fixture).await;
    let entries_before = application_entries(&pool, &fixture).await;
    let jobs_before = federation_jobs(&pool, &fixture).await;

    let (status, replay, trace) = post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(status, StatusCode::OK, "direct replay: {replay}");
    assert_eq!(replay, response);
    assert!(
        !trace.contains("Failed to resolve application entry peer")
            && !trace.contains("Failed to resolve PDS endpoint from DID document"),
        "ordinary Direct replay must not enter the C33 delivery path: {trace}"
    );
    assert_eq!(application_entries(&pool, &fixture).await, entries_before);
    assert_eq!(federation_jobs(&pool, &fixture).await, jobs_before);
    assert_no_direct_delivery(&pool, &fixture).await;
}

#[tokio::test]
async fn invalid_application_signature_creates_no_entry_or_federation_job() {
    let (pool, _database, fixture, device, router) = setup(false).await;
    let mut invalid = fixture.signed_request.clone();
    invalid["signature"] = json!(STANDARD.encode([0_u8; 64]));
    let (status, response) = post(&router, &device, &invalid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "invalid signature response: {response}"
    );
    assert_eq!(response["error"], "InvalidSignature");
    assert!(application_entries(&pool, &fixture).await.is_empty());
    assert!(federation_jobs(&pool, &fixture).await.is_empty());
    assert_no_direct_delivery(&pool, &fixture).await;
}

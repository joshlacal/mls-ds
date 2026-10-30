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
    decode_canonical_signed_mutation, seed_application_routing_fixture,
    seed_remote_group_application_routing_fixture, ApplicationRoutingFixture,
};
use common::http_acceptance as http;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

const NSID: &str = "blue.catbird.chat.sendMessage";
const REMOTE_SERVICE: &str = "did:web:remote.routing.example.com";
const DELIVER_MESSAGE: &str = "blue.catbird.mlsDS.deliverMessage";
const DELIVER_ENTRY: &str = "blue.catbird.mlsDS.deliverMessageEntry";

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
    ApplicationRoutingFixture,
    http::Device,
    Router,
) {
    setup_routing(direct, false).await
}

async fn setup_routing(
    direct: bool,
    remote_group: bool,
) -> (
    PgPool,
    common::fresh_db::DisposableDatabase,
    ApplicationRoutingFixture,
    http::Device,
    Router,
) {
    // Every case selects the same process environment. Only the fixture's
    // persisted, signed kind differs; no router or resolver test hook is used.
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");
    let (pool, database) = common::fresh_db::fresh_legacy_pool("chat_sendrouting_", 4, 1).await;
    http::ensure_fence(&pool).await;
    let fixture = if remote_group {
        assert!(!direct, "remote regression is specific to group sequencing");
        seed_remote_group_application_routing_fixture(&pool, REMOTE_SERVICE, REMOTE_SERVICE).await
    } else {
        seed_application_routing_fixture(&pool, direct, REMOTE_SERVICE).await
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
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
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
    fixture: &ApplicationRoutingFixture,
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
    fixture: &ApplicationRoutingFixture,
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

async fn assert_no_direct_delivery(pool: &PgPool, fixture: &ApplicationRoutingFixture) {
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

async fn business_snapshot(pool: &PgPool, fixture: &ApplicationRoutingFixture) -> Value {
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

async fn assert_single_application_and_job(pool: &PgPool, fixture: &ApplicationRoutingFixture) {
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

#[tokio::test]
async fn group_send_and_exact_replay_keep_one_ordinary_federation_job() {
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
    assert_single_application_and_job(&pool, &fixture).await;
    let entries_before = application_entries(&pool, &fixture).await;
    let jobs_before = federation_jobs(&pool, &fixture).await;

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
    assert_eq!(federation_jobs(&pool, &fixture).await, jobs_before);
    assert_no_direct_delivery(&pool, &fixture).await;
}

#[tokio::test]
async fn remote_group_send_is_rejected_before_any_message_or_operation_is_committed() {
    let (pool, _database, fixture, device, router) = setup_routing(false, true).await;
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
    let before = business_snapshot(&pool, &fixture).await;
    assert!(before["sends"].is_null());
    assert!(before["claims"].is_null());
    assert!(before["receipts"].is_null());
    for _ in 0..2 {
        // An exact repeat remains a rejected first admission: no completed
        // receipt may be minted for an operation this replica cannot sequence.
        let (status, response, trace) =
            post_with_trace(&router, &device, &fixture.signed_request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "remote group: {response}");
        assert_eq!(response["error"], "NotAuthorized");
        assert!(
            !trace.contains("Failed to resolve application entry peer"),
            "a remote group must not enter direct-request resolution: {trace}"
        );
        assert_eq!(
            business_snapshot(&pool, &fixture).await,
            before,
            "remote rejection must not advance the head or retain send/entry/operation rows"
        );
        assert!(application_entries(&pool, &fixture).await.is_empty());
        assert!(federation_jobs(&pool, &fixture).await.is_empty());
        assert_no_direct_delivery(&pool, &fixture).await;
    }
}

#[tokio::test]
async fn direct_send_preserves_authoritative_resolution_failure_after_commit() {
    let (pool, _database, fixture, device, router) = setup(true).await;
    let (status, response, trace) =
        post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "direct response: {response}"
    );
    assert_eq!(response, json!({"error": "InternalServerError"}));
    assert!(
        trace.contains("Failed to resolve application entry peer"),
        "exact post-commit resolver failure: {trace}"
    );
    assert!(
        trace.contains("Failed to resolve PDS endpoint from DID document"),
        "example.com fixture authority cannot resolve: {trace}"
    );
    // The genuine local direct send was admitted and committed before the
    // unchanged direct coordinator resolver rejected the unique example.com fixture home.
    assert_single_application_and_job(&pool, &fixture).await;
    let entries_before = application_entries(&pool, &fixture).await;
    let jobs_before = federation_jobs(&pool, &fixture).await;

    let (status, replay, trace) = post_with_trace(&router, &device, &fixture.signed_request).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "direct replay: {replay}"
    );
    assert_eq!(replay, response);
    assert!(
        trace.contains("Failed to resolve application entry peer"),
        "replay retains direct resolver path: {trace}"
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

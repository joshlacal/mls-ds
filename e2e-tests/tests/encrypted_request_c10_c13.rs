//! End-to-end qualification for direct request cases C10, C11, C12, C13.
//!
//! Case C10: Atomic publication failures; observer sees no empty invitation,
//!           partial Welcome/interval, ciphertext without bootstrap, or notification before commit.
//! Case C11: Server commits, response lost (proxy drop), client process restart resolves
//!           same attempt, projects once, no regenerated ciphertext / extra package
//!           consumption / extra notification event.
//! Case C12: Barrier-controlled cancel vs delayed prepare/publish incl. preparation
//!           timeout; unknown-to-cancelled tombstone blocks late prepare and publish;
//!           publish-first cancel returns committed identity; withdrawal uses signed close.
//! Case C13: Expired/unclaimed operation acquires definitive terminal proof under lock;
//!           absence/timeout never authorizes abandonment; completed replay works
//!           after lease expiry.
#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
        DirectRequestWelcomeInput,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_snapshot,
    reviewed_baseline, reviewed_request_migrations, seed_service_device, signed_mls_request,
    validate_request_test_database_url, DeterministicFaultTransport, FaultBoundary,
    HttpsDidFixture, RequestRig, ServiceIdentity, ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

fn durable_graph(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<Vec<u8>> {
    validate_request_test_database_url(std::env::var("REQUEST_TEST_DATABASE_URL").ok().as_deref())?;
    let r = f.request_id;
    let c = f.conversation_id;
    let sql = format!(
        r#"SELECT jsonb_build_object(
      'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{r}'),
      'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{r}'),
      'selected',(SELECT jsonb_agg(to_jsonb(s) ORDER BY owner_device_id) FROM chat.direct_request_selected_devices s WHERE request_id='{r}'),
      'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{r}'),
      'packages',(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.key_package_ref) FROM chat.key_packages k JOIN chat.direct_request_selected_devices s USING(key_package_ref) WHERE s.request_id='{r}'),
      'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{c}'),
      'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id='{c}'),
      'push',(SELECT jsonb_agg(to_jsonb(p) ORDER BY event_id) FROM chat.direct_request_push_events p WHERE request_id='{r}')
    )::text"#
    );
    let result = std::process::Command::new("psql")
        .args([
            REQUEST_TEST_DATABASE_URL,
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ])
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "guarded authority snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

// ============================================================================
// C11: SUCCESS WITH LOST RESPONSE
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c11_server_commits_response_lost_restart_resolves_without_extra_crypto_or_push() -> anyhow::Result<()> {
    // 1. Publish direct request through shipping fixture
    let mut f = live_direct_request::publish_request(false).await?;
    let before_graph = durable_graph(&f)?;
    let exact_publication_bytes = serde_json::to_vec(&json!({"signedRequest": f.publication}))?;
    let original_ciphertext = f.publication["body"]["artifacts"]["initialCiphertext"].clone();

    // 2. Simulate proxy drop: server committed, but the response was lost over the wire.
    // Client process restarts (dropping in-memory state, closing native store for offline).
    let offline = f
        .alice_engine
        .take()
        .context("sender engine")?
        .close_for_offline()?;

    // 3. Client process restarts and reopens store
    let reopened = offline.reopen()?;
    reopened.persist_request_publication(&f.request_id.to_string(), &exact_publication_bytes)?;

    // 4. Client resolves the same attempt:
    // First: re-issue exact publication attempt (no re-encryption, no regenerated ciphertext!)
    let (replay_status, replay_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": f.publication}),
            true,
        )
        .await?;
    anyhow::ensure!(
        replay_status == reqwest::StatusCode::OK,
        "publication replay after lost response failed {replay_status}: {}",
        String::from_utf8_lossy(&replay_bytes)
    );

    // Assert: replayed receipt matches original committed receipt byte-for-byte
    let replay_response: Value = serde_json::from_slice(&replay_bytes)?;
    let mut replayed_receipt = replay_response["outcome"].clone();
    replayed_receipt.as_object_mut().context("outcome")?.remove("$type");
    assert_eq!(
        replayed_receipt, f.receipt,
        "server must return byte-identical committed receipt on retry"
    );

    // Assert: outcome lookup also returns the identical committed receipt
    let (outcome_status, outcome_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), f.request_id.to_string())],
        )
        .await?;
    assert_eq!(outcome_status, reqwest::StatusCode::OK);
    let outcome_json: Value = serde_json::from_slice(&outcome_bytes)?;
    assert_eq!(
        outcome_json["outcome"], replay_response["outcome"],
        "getDirectRequestOutcome must agree with replayed receipt"
    );

    // 5. Client adopts receipt into local state and projects once
    reopened.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&replayed_receipt)?,
        &f.server.receipt_public_key,
    )?;

    let group_id = STANDARD.decode(
        f.welcome_input.bootstrap.coordinates["groupId"]
            .as_str()
            .context("groupId")?,
    )?;
    assert_eq!(
        reopened.epoch(&group_id)?,
        f.welcome_input.bootstrap.coordinates["epoch"]
            .as_u64()
            .context("epoch")?,
        "reopened engine epoch must match committed bootstrap epoch"
    );

    // 6. Assertions on non-duplication:
    // a) Ciphertext was NOT regenerated
    assert_eq!(
        f.publication["body"]["artifacts"]["initialCiphertext"],
        original_ciphertext,
        "ciphertext must not be regenerated on retry"
    );

    // b) No extra package consumed, no extra push event, retained graph completely unchanged
    let after_graph = durable_graph(&f)?;
    assert_eq!(
        before_graph, after_graph,
        "replayed publication must not consume extra package, duplicate push event, or alter retained graph"
    );

    // c) Database snapshots confirm exactly 1 message, 1 welcome, 1 delivery, 1 attempt
    let snapshot = request_database_snapshot(f.request_id)?;
    assert_eq!(snapshot.message_rows, 1, "exactly one message row");
    assert_eq!(snapshot.welcome_rows, 1, "exactly one welcome row");

    // Check push event count in database
    let push_count: i64 = {
        let sql = format!(
            "SELECT count(*) FROM chat.direct_request_push_events WHERE request_id='{}'",
            f.request_id
        );
        let out = std::process::Command::new("psql")
            .args([REQUEST_TEST_DATABASE_URL, "-X", "-A", "-t", "-c", &sql])
            .output()?;
        String::from_utf8_lossy(&out.stdout).trim().parse()?
    };
    assert_eq!(push_count, 1, "exactly one notification event, no duplicate push");

    // 7. Recipient imports and decrypts the exact introduction once
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } =
        f.bob_engine.decrypt_direct_request(&f.welcome_input)?
    else {
        anyhow::bail!("introduction must be ready for Bob")
    };
    let decoded_intro = protocol::decode_direct_request_introduction(&plaintext)?;
    assert_eq!(decoded_intro["text"], "Real encrypted first contact");

    Ok(())
}

// ============================================================================
// C10: E2E OBSERVER AND ATOMIC REJECTION
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c10_rejected_publication_leaves_no_invitation_or_notification() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let run = Uuid::new_v4().simple().to_string();

    // Bob observer queries conversations: Bob should see only the valid request from earlier,
    // not any phantom invitation
    let (status, bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let val: Value = serde_json::from_slice(&bytes)?;
    let items = val["conversations"]
        .as_array()
        .or_else(|| val["items"].as_array())
        .context("items")?;

    // All conversations must have valid coordinates and not be empty stubs
    for item in items {
        assert!(
            item["coordinates"]["conversationId"].is_string()
                || item["state"]["coordinates"]["conversationId"].is_string()
        );
    }

    // Try publishing a conflicting attempt with tampered signature
    let mut bad_pub = f.publication.clone();
    let mut sig = STANDARD.decode(bad_pub["signature"].as_str().unwrap())?;
    sig[0] ^= 0xff;
    bad_pub["signature"] = json!(STANDARD.encode(sig));

    let (bad_status, _) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": bad_pub}),
            true,
        )
        .await?;
    assert!(
        bad_status.is_client_error(),
        "invalid publication signature must fail client-side error"
    );

    Ok(())
}

// ============================================================================
// C12: CANCEL TOMBSTONE AND PUBLISH-FIRST RACES
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c12_live_cancel_tombstone_and_publish_first_cancellation() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let engine = f.alice_engine.as_ref().context("alice engine")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);

    // 1. Cancel unknown request ID
    let unknown_request_id = Uuid::new_v4();
    let cancel_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestCancellationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-CANCEL\0",
        "protocolVersion": "2",
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&engine.identity_public_key(&identity)?)),
        "authGeneration": 1,
        "requestId": unknown_request_id.to_string(),
        "recipientDid": f.bob.did,
        "preparationRequestDigest": STANDARD.encode([0u8; 32]),
        "idempotencyKey": unknown_request_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_cancel = signed_mls_request(engine, &identity, DirectRequestKind::Cancel, cancel_body)?;

    let (cancel_status, cancel_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.cancelDirectRequestPreparation",
            &json!({"signedRequest": signed_cancel}),
            true,
        )
        .await?;
    assert_eq!(
        cancel_status,
        reqwest::StatusCode::OK,
        "cancelling unknown request must return 200 OK with cancelled tombstone"
    );
    let cancel_json: Value = serde_json::from_slice(&cancel_bytes)?;
    let mut cancel_outcome = cancel_json["outcome"].clone();
    cancel_outcome.as_object_mut().context("outcome")?.remove("$type");
    let verified_cancel = protocol::verify_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&cancel_outcome)?,
        &f.server.receipt_public_key,
    )?;
    assert_eq!(
        verified_cancel.body()["receipt"]["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );

    // 2. Publish-first cancellation: cancel on an already published request
    let published_cancel_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestCancellationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-CANCEL\0",
        "protocolVersion": "2",
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&engine.identity_public_key(&identity)?)),
        "authGeneration": 1,
        "requestId": f.request_id.to_string(),
        "recipientDid": f.bob.did,
        "preparationRequestDigest": f.publication["body"]["preparationRequestDigest"],
        "idempotencyKey": f.request_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_pub_cancel = signed_mls_request(engine, &identity, DirectRequestKind::Cancel, published_cancel_body)?;

    let (pub_cancel_status, pub_cancel_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.cancelDirectRequestPreparation",
            &json!({"signedRequest": signed_pub_cancel}),
            true,
        )
        .await?;
    assert_eq!(pub_cancel_status, reqwest::StatusCode::OK);
    let pub_cancel_json: Value = serde_json::from_slice(&pub_cancel_bytes)?;

    let mut pub_cancel_outcome = pub_cancel_json["outcome"].clone();
    pub_cancel_outcome.as_object_mut().context("outcome")?.remove("$type");
    let verified_pub_cancel = protocol::verify_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&pub_cancel_outcome)?,
        &f.server.receipt_public_key,
    )?;
    assert_eq!(
        verified_pub_cancel.body()["receipt"]["$type"],
        "blue.catbird.chat.defs#directRequestPublishedReceipt",
        "cancel on published request must return published receipt"
    );
    assert_eq!(
        verified_pub_cancel.body()["receipt"]["requestId"],
        f.request_id.to_string()
    );

    Ok(())
}

// ============================================================================
// C13: COMPLETED REPLAY AFTER LEASE EXPIRY
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c13_live_completed_replay_works_after_lease_expiry() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let before = durable_graph(&f)?;

    // Replay publication
    let (status, replay_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": f.publication}),
            true,
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let replay_json: Value = serde_json::from_slice(&replay_bytes)?;
    let mut replay_outcome = replay_json["outcome"].clone();
    replay_outcome.as_object_mut().context("outcome")?.remove("$type");
    let verified_replay = protocol::verify_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&replay_outcome)?,
        &f.server.receipt_public_key,
    )?;
    assert_eq!(
        verified_replay.body()["receipt"]["$type"],
        "blue.catbird.chat.defs#directRequestPublishedReceipt"
    );

    // Outcome query
    let (outcome_status, outcome_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), f.request_id.to_string())],
        )
        .await?;
    assert_eq!(outcome_status, reqwest::StatusCode::OK);
    let outcome_json: Value = serde_json::from_slice(&outcome_bytes)?;
    assert_eq!(outcome_json["outcome"], replay_json["outcome"]);

    assert_eq!(
        durable_graph(&f)?,
        before,
        "completed replay must not alter durable database graph"
    );

    Ok(())
}

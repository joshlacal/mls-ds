//! Evidence harness for encrypted first-message requests.
//!
//! Tests call the shipping router with real service JWTs and independent native
//! MLS stores. Case results are bounded to the assertions actually executed;
//! test support must never substitute synthetic authority for a live case.

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
    canonical_future, canonical_now, connect_guarded_request_database, push_auth_snapshot,
    request_database_snapshot, reviewed_baseline, reviewed_request_migrations, seed_service_device,
    signed_mls_request, validate_request_test_database_url, DeterministicFaultTransport,
    FaultBoundary, HttpsDidFixture, PushFixtureConfig, RequestRig, ServiceIdentity,
    ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Write as _,
    process::{Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

#[test]
fn database_url_gate_accepts_only_the_exact_local_target() {
    assert!(validate_request_test_database_url(None).is_err());
    assert!(
        validate_request_test_database_url(Some("postgresql://127.0.0.1:5432/postgres")).is_err()
    );
    assert_eq!(
        validate_request_test_database_url(Some(REQUEST_TEST_DATABASE_URL)).unwrap(),
        "catbird_direct_requests_test_20260919"
    );
}

#[test]
fn reviewed_baseline_has_exactly_fourteen_ordered_entries() {
    let baseline = reviewed_baseline();
    assert_eq!(baseline.len(), 14);
    assert!(baseline
        .windows(2)
        .all(|pair| pair[0].version < pair[1].version));
}

#[test]
fn deterministic_fault_transport_fires_at_the_selected_occurrence() -> anyhow::Result<()> {
    let mut transport = DeterministicFaultTransport::default()
        .fail_on(FaultBoundary::AfterRequestBeforeResponse, 2)?;
    transport.checkpoint(FaultBoundary::BeforeRequest)?;
    transport.checkpoint(FaultBoundary::AfterRequestBeforeResponse)?;
    let error = transport
        .checkpoint(FaultBoundary::AfterRequestBeforeResponse)
        .unwrap_err();
    assert!(error.to_string().contains("AfterRequestBeforeResponse"));
    assert_eq!(transport.trace().len(), 3);
    let _future_boundary = FaultBoundary::AfterCommittedResponse;
    Ok(())
}

#[tokio::test]
async fn guarded_database_is_local_owned_and_contains_reviewed_baseline() -> anyhow::Result<()> {
    let authority = connect_guarded_request_database(1).await?;
    assert_eq!(authority.database, "catbird_direct_requests_test_20260919");
    assert_eq!(authority.user, authority.owner);
    assert_eq!(authority.server_address, "127.0.0.1");
    assert_eq!(authority.baseline_migrations, 14);
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_uses_independent_real_mls_stores() -> anyhow::Result<()> {
    let mut rig = RequestRig::local().await?;
    rig.enroll("alice", 2).await?;
    rig.enroll("bob", 1).await?;
    assert_eq!(rig.independent_device_count("alice")?, 2);
    assert_eq!(rig.independent_device_count("bob")?, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_request_handlers_fail_closed_instead_of_passing() -> anyhow::Result<()> {
    let mut rig = RequestRig::local().await?;
    rig.enroll("alice", 1).await?;
    rig.enroll("bob", 1).await?;
    let error = rig
        .start_request("alice", "bob", "Hello, Bob")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("T02/T03/T04"));
    Ok(())
}

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

#[tokio::test(flavor = "multi_thread")]
async fn c01_real_router_auth_live_preparation_and_native_recipient_preview() -> anyhow::Result<()>
{
    let _fixture = live_direct_request::publish_request(true).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_service_jwts_preserve_device_generation_and_replay_fails_closed(
) -> anyhow::Result<()> {
    const READ_NSID: &str = "blue.catbird.chat.getOwnDevices";
    const PUSH_NSID: &str = "blue.catbird.chat.updatePushToken";

    let fixture = live_direct_request::publish_request(false).await?;
    let before = push_auth_snapshot(&fixture.bob, "apns")?;
    anyhow::ensure!(
        before.device_auth_generation == 1 && before.key_enrollment_auth_generation == 1,
        "fixture device did not retain acknowledged enrollment generation"
    );

    let read_url = format!(
        "{}/xrpc/{READ_NSID}?actorDeviceId={}",
        fixture.server.base_url, fixture.bob.device_id
    );
    let first_jti = Uuid::new_v4();
    let first_token = fixture.bob.scoped_jwt_with_jti(READ_NSID, first_jti);
    let first = fixture
        .client
        .get(&read_url)
        .bearer_auth(&first_token)
        .send()
        .await?;
    anyhow::ensure!(
        first.status() == reqwest::StatusCode::OK,
        "first fresh service JWT was rejected: {}",
        first.status()
    );
    let first_body: Value = serde_json::from_slice(&first.bytes().await?)?;
    anyhow::ensure!(
        first_body
            .to_string()
            .contains(&fixture.bob.device_id.to_string()),
        "first authenticated read omitted the enrolled device"
    );

    let second_token = fixture.bob.scoped_jwt_with_jti(READ_NSID, Uuid::new_v4());
    let second = fixture
        .client
        .get(&read_url)
        .bearer_auth(second_token)
        .send()
        .await?;
    anyhow::ensure!(
        second.status() == reqwest::StatusCode::OK,
        "second fresh service JWT was rejected: {}",
        second.status()
    );
    let second_body: Value = serde_json::from_slice(&second.bytes().await?)?;
    anyhow::ensure!(
        second_body
            .to_string()
            .contains(&fixture.bob.device_id.to_string()),
        "second authenticated read omitted the enrolled device"
    );

    let after_fresh = push_auth_snapshot(&fixture.bob, "apns")?;
    anyhow::ensure!(
        after_fresh.device_auth_generation == before.device_auth_generation
            && after_fresh.key_enrollment_auth_generation == before.key_enrollment_auth_generation
            && after_fresh.registration_id == before.registration_id
            && after_fresh.token_generation == before.token_generation
            && after_fresh.binding_digest_hex == before.binding_digest_hex,
        "fresh account service JWTs changed device or push-binding authority"
    );
    anyhow::ensure!(
        after_fresh.service_jti_rows == before.service_jti_rows + 2
            && after_fresh.chat_admission_rows == before.chat_admission_rows + 2,
        "fresh service JWTs did not create two independent replay admissions"
    );

    let replay = fixture
        .client
        .get(&read_url)
        .bearer_auth(&first_token)
        .send()
        .await?;
    let replay_status = replay.status();
    let replay_body = replay.bytes().await?;
    anyhow::ensure!(
        replay_status == reqwest::StatusCode::UNAUTHORIZED
            && String::from_utf8_lossy(&replay_body).contains("NotAuthorized"),
        "replayed service JTI did not fail closed: {replay_status} {}",
        String::from_utf8_lossy(&replay_body)
    );
    anyhow::ensure!(
        push_auth_snapshot(&fixture.bob, "apns")? == after_fresh,
        "replayed service JTI changed durable authority rows"
    );

    let invented_token = format!("invented-generation-{}", Uuid::new_v4().simple());
    let mut invented_body: catbird_mls::atproto::blue_catbird::chat::PushRegistrationBody =
        serde_json::from_value(fixture.push_registration_request["registration"]["body"].clone())?;
    invented_body.auth_generation = before.device_auth_generation + 1;
    invented_body.token_generation = before.token_generation + 1;
    invented_body.token_sha256 = Sha256::digest(invented_token.as_bytes()).to_vec().into();
    invented_body.signed_at = canonical_now().parse()?;
    let transcript = catbird_mls::atproto::push_registration::transcript(&invented_body)?;
    let bob_identity = format!("{}#{}", fixture.bob.did, fixture.bob.device_id);
    let signature = fixture
        .bob_engine
        .sign_identity(&bob_identity, transcript)?;
    let invented_registration = catbird_mls::atproto::blue_catbird::chat::SignedPushRegistration {
        body: invented_body,
        signature: signature.into(),
        extra_data: None,
    };
    let invented_request = json!({"token":invented_token,"registration":invented_registration});
    let invented = fixture
        .client
        .post(format!("{}/xrpc/{PUSH_NSID}", fixture.server.base_url))
        .bearer_auth(fixture.bob.scoped_jwt_with_jti(PUSH_NSID, Uuid::new_v4()))
        .json(&invented_request)
        .send()
        .await?;
    let invented_status = invented.status();
    let invented_response = invented.bytes().await?;
    anyhow::ensure!(
        invented_status == reqwest::StatusCode::CONFLICT
            && String::from_utf8_lossy(&invented_response).contains("StaleAuthGeneration"),
        "invented higher generation did not fail closed: {invented_status} {}",
        String::from_utf8_lossy(&invented_response)
    );
    let after_invented = push_auth_snapshot(&fixture.bob, "apns")?;
    anyhow::ensure!(
        after_invented.device_auth_generation == after_fresh.device_auth_generation
            && after_invented.key_enrollment_auth_generation
                == after_fresh.key_enrollment_auth_generation
            && after_invented.registration_id == after_fresh.registration_id
            && after_invented.token_generation == after_fresh.token_generation
            && after_invented.binding_digest_hex == after_fresh.binding_digest_hex,
        "invented generation changed device or push-binding authority"
    );
    anyhow::ensure!(
        after_invented.service_jti_rows == after_fresh.service_jti_rows + 1
            && after_invented.chat_admission_rows == after_fresh.chat_admission_rows,
        "failed higher-generation registration changed the wrong replay ledger"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c02_sender_offline_recipient_accepts_replies_sender_reopens_and_decrypts(
) -> anyhow::Result<()> {
    live_direct_request::accept_reply_offline(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c06_acceptance_before_welcome_import_does_not_require_another_add() -> anyhow::Result<()> {
    live_direct_request::accept_reply_offline(true).await
}

struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.take().expect("child already consumed").wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn wait_json(path: &std::path::Path, timeout: Duration) -> anyhow::Result<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            return serde_json::from_slice(&bytes)
                .with_context(|| format!("parse paired artifact {}", path.display()));
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for paired artifact {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn run_t16_paired(expect_canonical_ineligible: bool) -> anyhow::Result<()> {
    let fixture = live_direct_request::publish_request(true).await?;
    if expect_canonical_ineligible {
        live_direct_request::accept_existing_fixture(&fixture).await?;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let ds_port = listener.local_addr()?.port();
    drop(listener);

    let run = Uuid::new_v4().simple().to_string();
    let paired_dir = std::path::PathBuf::from(format!("/tmp/t16-paired-nest-{run}"));
    std::fs::create_dir(&paired_dir)?;
    let ready_path = paired_dir.join("nest-ready.json");
    let nest_result_path = paired_dir.join("nest-result.json");
    let nest_stdout = std::fs::File::create(paired_dir.join("nest.stdout.log"))?;
    let nest_stderr = std::fs::File::create(paired_dir.join("nest.stderr.log"))?;
    let eligibility_credential = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let eligibility_url =
        format!("http://127.0.0.1:{ds_port}/internal/chat/request-push-eligibility");
    let nest_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../nest/catbird")
        .canonicalize()?;
    let mut child = Command::new("cargo")
        .args([
            "test",
            "--lib",
            "services::push::request_events::paired_harness::live_ds_worker_to_nest",
            "--",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(nest_root)
        .env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .env(
            "CATBIRD_REQUEST_PUSH_TEST_DB",
            "postgres://joshlacalamito@127.0.0.1:5432/catbird_request_push_test_20260919",
        )
        .env("CATBIRD_REQUEST_PUSH_PAIRED_DIR", &paired_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(nest_stdout))
        .stderr(Stdio::from(nest_stderr))
        .spawn()
        .context("start paired Nest test process")?;
    let stdin_fixture = json!({
        "eventId": fixture.push_event_id.to_string(),
        "recipientDid": fixture.bob.did,
        "authorityDidDocument": serde_json::from_slice::<Value>(&fixture.server.receipt_document)?,
        "eligibilityUrl": eligibility_url,
        "eligibilityCredential": eligibility_credential,
        "registrationRequest": fixture.push_registration_request,
        "registrationAck": fixture.push_registration_ack,
        "expectCanonicalIneligible": expect_canonical_ineligible,
    });
    child
        .stdin
        .take()
        .context("paired Nest stdin unavailable")?
        .write_all(&serde_json::to_vec(&stdin_fixture)?)?;
    // Closing stdin bounds the one process-local fixture. The credential and
    // synthetic token never enter a retained file or test output.
    let nest = ChildGuard(Some(child));

    let ready = wait_json(&ready_path, Duration::from_secs(180)).await?;
    anyhow::ensure!(
        ready["eventId"] == fixture.push_event_id.to_string(),
        "Nest readiness event identity mismatch"
    );
    let trigger_path = paired_dir.join("ds-trigger");
    let ds_result_path = paired_dir.join("ds-result.json");
    let push = PushFixtureConfig {
        listen_port: ds_port,
        event_url: ready["ingressUrl"]
            .as_str()
            .context("Nest readiness lacks ingressUrl")?
            .to_owned(),
        eligibility_bearer: eligibility_credential,
        event_id: fixture.push_event_id,
        trigger_path: trigger_path.clone(),
        result_path: ds_result_path.clone(),
    };
    let _push_server = ShippingServerFixture::start_with_push(&fixture._https, &push)?;
    std::fs::write(&trigger_path, b"dispatch\n")?;

    let ds_result = wait_json(&ds_result_path, Duration::from_secs(30)).await?;
    anyhow::ensure!(
        ds_result["ok"] == true
            && ds_result["claimed"] == 1
            && ds_result["eventId"] == fixture.push_event_id.to_string(),
        "DS targeted worker did not complete exact ACK: {ds_result}"
    );
    let nest_result = wait_json(&nest_result_path, Duration::from_secs(180)).await?;
    anyhow::ensure!(nest_result["eventId"] == fixture.push_event_id.to_string());
    if expect_canonical_ineligible {
        anyhow::ensure!(nest_result["status"] == "suppressed");
        anyhow::ensure!(nest_result["result"] == "canonical_ineligible");
        anyhow::ensure!(nest_result["apnsCalls"] == 0 && nest_result["fcmCalls"] == 0);
        anyhow::ensure!(nest_result["exactGenericPayloadVerified"] == false);
    } else {
        anyhow::ensure!(nest_result["status"] == "delivered");
        anyhow::ensure!(nest_result["result"] == "provider_accepted");
        anyhow::ensure!(nest_result["apnsCalls"] == 2 && nest_result["fcmCalls"] == 0);
        anyhow::ensure!(nest_result["exactGenericPayloadVerified"] == true);
    }

    let status = tokio::task::spawn_blocking(move || nest.wait())
        .await
        .context("join Nest waiter")??;
    anyhow::ensure!(
        status.success(),
        "paired Nest test process failed: {status}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t16_live_ds_worker_to_nest_and_fake_apns() -> anyhow::Result<()> {
    run_t16_paired(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t16_accepted_request_is_canonically_ineligible_before_provider() -> anyhow::Result<()> {
    run_t16_paired(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c06_both_recipient_devices_import_same_welcome_after_account_acceptance(
) -> anyhow::Result<()> {
    live_direct_request::accept_before_both_recipient_imports().await
}

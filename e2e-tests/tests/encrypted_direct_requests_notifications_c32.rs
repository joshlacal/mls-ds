//! C32 Notifications paired integration tests.
//!
//! Exercises real paired DS + Nest local processes with controlled provider adapter:
//! 1. Provider-accepted-but-ACK-lost retry with stable event identity and deduplication
//! 2. Close-before-push canonical ineligible suppression (0 provider calls)

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
    ShippingServerFixture, request_database_url,
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

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl ChildGuard {
    fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.take().unwrap().wait()
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

fn execute_psql(sql: &str) -> anyhow::Result<()> {
    let output = Command::new("psql")
        .args([
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-q",
            "-d",
            request_database_url(),
            "-c",
            sql,
        ])
        .output()
        .context("launch psql mutation for C32 harness")?;
    anyhow::ensure!(
        output.status.success(),
        "psql mutation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn run_c32_paired(scenario: &str) -> anyhow::Result<()> {
    let fixture = live_direct_request::publish_request(true).await?;
    let (push_req, push_ack) = if scenario == "fcm_routing" {
        let bob_identity = format!("{}#{}", fixture.bob.did, fixture.bob.device_id);
        let bob_public = fixture.bob_engine.identity_public_key(&bob_identity)?;
        let synthetic_fcm_token = format!("request-fcm-fixture-{}", Uuid::new_v4().simple());
        let fcm_body: catbird_mls::atproto::blue_catbird::chat::PushRegistrationBody =
            serde_json::from_value(json!({
                "protocolVersion":"2", "signatureDomain":"CATBIRD-CHAT-PUSH-BINDING\0",
                "authorityDid":"did:web:chat.catbird.blue", "actorDid":fixture.bob.did,
                "actorDeviceId":fixture.bob.device_id.to_string(), "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
                "authGeneration":1,"registrationId":Uuid::new_v4().to_string(),"provider":"fcm",
                "appId":"blue.catbird","tokenGeneration":2,"tokenSha256":{"$bytes":STANDARD.encode(Sha256::digest(synthetic_fcm_token.as_bytes()))},
                "enabled":true,"signedAt":canonical_now()
            }))?;
        let fcm_transcript = catbird_mls::atproto::push_registration::transcript(&fcm_body)?;
        let fcm_sig = fixture.bob_engine.sign_identity(&bob_identity, fcm_transcript)?;
        let fcm_registration = catbird_mls::atproto::blue_catbird::chat::SignedPushRegistration {
            body: fcm_body.clone(),
            signature: fcm_sig.into(),
            extra_data: None,
        };
        let fcm_req = json!({"token":synthetic_fcm_token,"registration":fcm_registration});
        let (fcm_status, fcm_bytes) = fixture.bob.post(
            &fixture.client,
            &fixture.server.base_url,
            "blue.catbird.chat.updatePushToken",
            &fcm_req,
            true,
        ).await?;
        anyhow::ensure!(fcm_status == reqwest::StatusCode::OK, "fcm registration failed {fcm_status}");
        let fcm_ack: Value = serde_json::from_slice(&fcm_bytes)?;
        (fcm_req, fcm_ack)
    } else {
        if scenario == "close_before_push" {
            // Transition consent to non-pending before push dispatch
            live_direct_request::accept_existing_fixture(&fixture).await?;
        }
        (fixture.push_registration_request.clone(), fixture.push_registration_ack.clone())
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let ds_port = listener.local_addr()?.port();
    drop(listener);

    let run = Uuid::new_v4().simple().to_string();
    let paired_dir = std::path::PathBuf::from(format!("/tmp/c32-paired-nest-{run}"));
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
            "services::push::request_events::c32_paired_harness::live_ds_worker_to_nest_c32",
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
        "registrationRequest": push_req,
        "registrationAck": push_ack,
        "scenario": scenario,
    });
    child
        .stdin
        .take()
        .context("paired Nest stdin unavailable")?
        .write_all(&serde_json::to_vec(&stdin_fixture)?)?;
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

    match scenario {
        "close_before_push" => {
            anyhow::ensure!(
                nest_result["status"] == "suppressed",
                "expected suppressed status, got {}",
                nest_result["status"]
            );
            anyhow::ensure!(
                nest_result["result"] == "canonical_ineligible",
                "expected canonical_ineligible result, got {}",
                nest_result["result"]
            );
            anyhow::ensure!(
                nest_result["apnsCalls"] == 0 && nest_result["fcmCalls"] == 0,
                "closed request must make 0 provider calls"
            );
            anyhow::ensure!(nest_result["exactGenericPayloadVerified"] == false);
        }
        "provider_accepted_ack_lost" => {
            anyhow::ensure!(
                nest_result["status"] == "delivered",
                "expected delivered status, got {}",
                nest_result["status"]
            );
            anyhow::ensure!(
                nest_result["result"] == "provider_accepted",
                "expected provider_accepted result, got {}",
                nest_result["result"]
            );
            anyhow::ensure!(
                nest_result["apnsCalls"] == 2 && nest_result["fcmCalls"] == 0,
                "expected 2 APNs calls (accepted first, then retried after lost ACK)"
            );
            anyhow::ensure!(nest_result["stableIdentityVerified"] == true);
            anyhow::ensure!(nest_result["ackLostRetryVerified"] == true);
            anyhow::ensure!(nest_result["exactGenericPayloadVerified"] == true);
            anyhow::ensure!(nest_result["exactClaimCount"] == 1);
        }
        "fcm_routing" => {
            anyhow::ensure!(
                nest_result["status"] == "delivered",
                "expected delivered status, got {}",
                nest_result["status"]
            );
            anyhow::ensure!(
                nest_result["result"] == "provider_accepted",
                "expected provider_accepted result, got {}",
                nest_result["result"]
            );
            anyhow::ensure!(
                nest_result["fcmCalls"] == 1 && nest_result["apnsCalls"] == 0,
                "expected 1 FCM call and 0 APNs calls"
            );
            anyhow::ensure!(nest_result["exactGenericPayloadVerified"] == true);
            anyhow::ensure!(nest_result["tokenGeneration"] == 2);
        }
        _ => {}
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
async fn c32_provider_accepted_but_ack_lost_retry_has_stable_identity() -> anyhow::Result<()> {
    run_c32_paired("provider_accepted_ack_lost").await
}

#[tokio::test(flavor = "multi_thread")]
async fn c32_close_before_push_is_canonically_ineligible_before_provider() -> anyhow::Result<()> {
    run_c32_paired("close_before_push").await
}

#[tokio::test(flavor = "multi_thread")]
async fn c32_fcm_routing_dispatches_only_to_fcm_provider() -> anyhow::Result<()> {
    run_c32_paired("fcm_routing").await
}

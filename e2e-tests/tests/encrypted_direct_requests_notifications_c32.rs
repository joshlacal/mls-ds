//! C32 Notifications paired integration tests.
//!
//! Exercises the real DS worker and Nest's production D2 Push Gateway as
//! paired local processes with a controlled provider adapter:
//! 1. Provider-accepted-but-ACK-lost retry with stable wake identity
//! 2. Close-before-push canonical ineligible suppression (0 provider calls)
//! 3. FCM-only routing after the device re-registers with an FCM token

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
    reviewed_request_migrations, seed_service_device, signed_mls_request,
    validate_request_test_database_url, HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
pub mod live_direct_request;

#[path = "support/paired_push.rs"]
mod paired_push;

async fn run_c32_paired(scenario: &str) -> anyhow::Result<()> {
    let fixture = live_direct_request::publish_request(true).await?;
    if scenario == "close_before_push" {
        // Transition consent to non-pending before push dispatch
        live_direct_request::accept_existing_fixture(&fixture).await?;
    }
    let (harness_scenario, platforms): (&str, &[&str]) = match scenario {
        "close_before_push" => ("canonical_ineligible", &["apns"]),
        // The device replaces its APNs registration with an FCM token; its DS
        // binding follows the latest opaque key.
        "fcm_routing" => ("fcm_routing", &["apns", "fcm"]),
        "provider_accepted_ack_lost" => ("provider_accepted_ack_lost", &["apns"]),
        other => anyhow::bail!("unknown C32 scenario {other}"),
    };
    let outcome = paired_push::run(
        &fixture,
        "c32-paired-nest-",
        "services::push::request_events::c32_paired_harness::live_ds_worker_to_nest_c32",
        harness_scenario,
        platforms,
    )
    .await?;
    let nest_result = &outcome.nest;
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
            anyhow::ensure!(outcome.ds["suppressed"] == true && outcome.ds["woken"] == 0);
            anyhow::ensure!(outcome.outbox == ("delivered".to_owned(), 0));
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
            anyhow::ensure!(
                outcome.outbox == ("delivered".to_owned(), 1),
                "the lost ACK costs exactly one durable retry: {:?}",
                outcome.outbox
            );
        }
        _ => {
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
            anyhow::ensure!(nest_result["exactClaimCount"] == 1);
        }
    }
    anyhow::ensure!(nest_result["tokenPrivacyVerified"] == true);
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

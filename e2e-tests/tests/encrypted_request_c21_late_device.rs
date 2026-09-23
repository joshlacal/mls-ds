//! C21: late, new, or reinstalled device versus a published direct request.
//!
//! Live shipping router and guarded database. Account acceptance must not
//! hand an unaddressed device the request's keys; the device's app-facing
//! projection (`MLSOrchestrator::refresh_request_preview`, see
//! `support/live_orchestrator.rs`: app-metadata storage is the core-test
//! mock, crypto/projection/HTTP are real) reports the truthful unavailable
//! state. The post-acceptance leaf-recovery clause is not yet exercised here
//! (see the DevicesC21C22 report).

#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    atproto::blue_catbird::chat::{
        get_conversations::GetConversationsOutput, get_pending_welcomes::GetPendingWelcomesOutput,
    },
    chat_v2::transcript::{
        decode_strict_json, direct_request::{self as protocol, DirectRequestKind},
        project_signed_body, SignedMutationKind, SigningTranscript,
    },
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
        DirectRequestWelcomeInput,
    },
    RequestConsent, RequestCrypto, RequestPreview,
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    request_database_snapshot, reviewed_request_migrations, seed_service_device,
    signed_mls_request, validate_request_test_database_url, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

fn sign_mutation(
    engine: &MlsEngine,
    identity: &str,
    kind: SignedMutationKind,
    body: Value,
) -> anyhow::Result<Value> {
    let strict = decode_strict_json(&serde_json::to_vec(&body)?)?;
    let transcript = SigningTranscript::build_for(kind, &project_signed_body(kind, &strict)?)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    Ok(json!({"body": body, "signature": STANDARD.encode(signature)}))
}

/// Real inventory read for one device: open a scoped session, then return the
/// pending-Welcome items that name this request.
async fn request_welcomes(
    f: &live_direct_request::PublishedRequestFixture,
    service: &ServiceIdentity,
) -> anyhow::Result<Vec<Value>> {
    let mut params = vec![
        ("limit".to_owned(), "100".to_owned()),
        ("supportedProtocolVersions".to_owned(), "1".to_owned()),
        ("supportedProtocolVersions".to_owned(), "2".to_owned()),
    ];
    let (status, body) = service
        .get(&f.client, &f.server.base_url, "blue.catbird.chat.getConversations", &params)
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getConversations {status}");
    let conversations: Value = serde_json::from_slice(&body)?;
    params.push((
        "inventorySessionId".to_owned(),
        conversations["inventorySessionId"]
            .as_str()
            .context("inventorySessionId")?
            .to_owned(),
    ));
    let (status, body) = service
        .get(&f.client, &f.server.base_url, "blue.catbird.chat.getPendingWelcomes", &params)
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getPendingWelcomes {status}");
    let welcomes: Value = serde_json::from_slice(&body)?;
    Ok(welcomes["items"]
        .as_array()
        .context("items")?
        .iter()
        .filter(|item| item["welcomeId"] == f.request_id.to_string())
        .cloned()
        .collect())
}

fn group_id(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(
        f.welcome_input.bootstrap.coordinates["groupId"]
            .as_str()
            .context("groupId")?,
    )?)
}

fn input_for(
    f: &live_direct_request::PublishedRequestFixture,
    identity: &str,
    package_ref: &[u8],
) -> DirectRequestWelcomeInput {
    let mut input = f.welcome_input.clone();
    input.local_identity = identity.as_bytes().to_vec();
    input.local_package_ref = package_ref.to_vec();
    input
}

#[tokio::test(flavor = "multi_thread")]
async fn c21_late_and_reinstalled_devices_get_no_request_keys_and_show_unavailable(
) -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let conversation = f.conversation_id.to_string();
    let group = group_id(&f)?;

    // A new device of the recipient enrolls only after publication committed.
    let late = live_direct_request::siblings::enroll(&f.bob, &f.client, &f.server.base_url).await?;
    assert_ne!(late.service.device_id, f.bob.device_id);

    // Account consent through the real signed acceptance.
    live_direct_request::accept_existing_fixture(&f).await?;

    // 1. Acceptance handed the late device nothing: no Welcome offered, a
    //    typed refusal on claiming one, no group state, no readable intro.
    assert!(
        request_welcomes(&f, &late.service).await?.is_empty(),
        "late device must not be offered the request Welcome"
    );
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(late.engine.identity_public_key(&late.identity)?));
    let claim = sign_mutation(
        &late.engine,
        &late.identity,
        SignedMutationKind::WelcomeAcknowledgement,
        json!({
            "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
            "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
            "welcomeId": f.request_id.to_string(),
            "transitionSeq": 1,
            "coordinates": f.publication["body"]["next"],
            "actorDid": late.service.did,
            "actorDeviceId": late.service.device_id.to_string(),
            "keyId": key_id,
            "authGeneration": 1,
            "idempotencyKey": Uuid::new_v4().to_string(),
            "signedAt": canonical_now()
        }),
    )?;
    let (status, body) = late
        .service
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acknowledgeWelcome",
            &json!({"signedRequest": claim}),
            true,
        )
        .await?;
    let refusal: Value = serde_json::from_slice(&body)?;
    assert!(status.is_client_error(), "late claim must fail: {status} {refusal}");
    assert_eq!(refusal["error"], "WelcomeNotFound", "typed refusal: {refusal}");
    let late_input = input_for(&f, &late.identity, &late.package_ref);
    assert!(late.engine.epoch(&group).is_err(), "no group keys by acceptance");
    assert!(
        late.engine.decrypt_direct_request(&late_input).is_err(),
        "no intro readable by acceptance"
    );

    // 2. The projection the app renders for the late device is truthful.
    let receipt_document = f.server.receipt_document.clone();
    let late_client = live_orchestrator::live_orchestrator(
        late.engine.context(),
        &late.service,
        &f.client,
        &f.server.base_url,
        receipt_document.clone(),
    )
    .await?;
    let late_view = late_client.refresh_request_preview(&conversation).await?;
    println!("C21 late device view: {late_view:?}");
    assert_eq!(late_view.crypto, RequestCrypto::Unavailable);
    assert_eq!(
        late_view.preview,
        Some(RequestPreview::Unavailable { code: "DeviceNotAddressed".into() })
    );
    assert!(!late_view.capabilities.can_preview, "no preview without keys");
    assert!(!late_view.capabilities.can_send, "no false send readiness");
    late_client.shutdown().await;
    assert!(late.engine.epoch(&group).is_err(), "projection refresh imported nothing");

    // 3. Reinstalled addressed device: the native store is wiped, while the
    //    device UUID and full signing identity survive in the keychain and
    //    are re-imported (as `devices.rs` does after a reinstall). The fresh
    //    store holds none of the request's KeyPackage secrets.
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let surviving_identity = f.bob_engine.context().export_identity_key(bob_identity.clone())?;
    let reinstalled = MlsEngine::new("c21-bob-reinstalled")?;
    reinstalled
        .context()
        .import_identity_key(bob_identity.clone(), surviving_identity)?;
    assert!(reinstalled.epoch(&group).is_err());
    let reinstalled_client = live_orchestrator::live_orchestrator(
        reinstalled.context(),
        &f.bob,
        &f.client,
        &f.server.base_url,
        receipt_document.clone(),
    )
    .await?;
    let reinstalled_view = reinstalled_client.refresh_request_preview(&conversation).await?;
    println!("C21 reinstalled device view: {reinstalled_view:?}");
    assert_eq!(reinstalled_view.crypto, RequestCrypto::Unavailable);
    // Key loss surfaces through the core's existing import-failure code.
    assert_eq!(
        reinstalled_view.preview,
        Some(RequestPreview::Unavailable { code: "InvalidBootstrap".into() }),
        "fresh store cannot show the introduction"
    );
    assert!(!reinstalled_view.capabilities.can_preview && !reinstalled_view.capabilities.can_send);
    reinstalled_client.shutdown().await;
    assert!(reinstalled.epoch(&group).is_err(), "fresh store gained no group keys");
    assert!(
        reinstalled
            .decrypt_direct_request(&input_for(&f, &bob_identity, &f.welcome_input.local_package_ref))
            .is_err(),
        "fresh store cannot decrypt the introduction"
    );

    Ok(())
}

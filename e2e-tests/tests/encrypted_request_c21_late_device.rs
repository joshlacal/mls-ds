//! C21: late, new, or reinstalled device versus a published direct request.
//!
//! Live shipping router and guarded database. Account acceptance must not
//! hand an unaddressed device the request's keys; the device's app-facing
//! projection (`MLSOrchestrator::refresh_request_preview`, see
//! `support/live_orchestrator.rs`: app-metadata storage and credentials are
//! the core-test mocks, crypto/projection/HTTP are real) reports the truthful
//! unavailable state. After acceptance the late device uses the allowed
//! recovery path: the core publishes its recovery KeyPackage and signs
//! `requestLeafRecovery` (`join_or_rejoin`), a current leaf (the addressed
//! recipient device) fulfills it with `fulfill_leaf_recovery`
//! (`submitTransition#signedLeafRecoveryFulfillment`), and the late device
//! joins at the successor epoch without ever gaining the introduction.
//! Authorized device keys for the mock credential store come from the live
//! `getDeviceKey` RPC.

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

use live_orchestrator::{live_orchestrator_with_credentials, mock_credentials::MockCredentials};

/// A device's signing key as served by the live device directory.
async fn directory_key(
    f: &live_direct_request::PublishedRequestFixture,
    owner: &ServiceIdentity,
    engine: &MlsEngine,
) -> anyhow::Result<Vec<u8>> {
    let identity = format!("{}#{}", owner.did, owner.device_id);
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(engine.identity_public_key(&identity)?));
    let (status, body) = f
        .alice
        .get_device_key(&f.client, &f.server.base_url, &owner.did, owner.device_id, &key_id)
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getDeviceKey {status}");
    let key: Value = serde_json::from_slice(&body)?;
    Ok(STANDARD.decode(
        key["signaturePublicKey"]["$bytes"]
            .as_str()
            .context("signaturePublicKey")?,
    )?)
}

fn credentials(
    f: &live_direct_request::PublishedRequestFixture,
    keys: &[(&str, Vec<Vec<u8>>)],
) -> MockCredentials {
    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(f.server.receipt_document.clone());
    for (did, keys) in keys {
        credentials.set_authorized_device_keys(did, keys.clone());
    }
    credentials
}

/// Read-only JSON query against the routed guarded database.
fn db_json(sql: &str) -> anyhow::Result<Value> {
    let output = std::process::Command::new("psql")
        .args([
            encrypted_requests::request_database_url(),
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "guarded read failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn recovery_rows(conversation: &str) -> anyhow::Result<Value> {
    db_json(&format!(
        "SELECT COALESCE(json_agg(json_build_object('device',requester_device_id,'kind',recovery_kind,'status',status,'source',source) ORDER BY requested_at),'[]') FROM chat.leaf_recovery_requests WHERE conversation_id='{conversation}'"
    ))
}

fn entry_kinds(conversation: &str) -> anyhow::Result<Value> {
    db_json(&format!(
        "SELECT COALESCE(json_object_agg(k,n),'{{}}') FROM (SELECT entry_kind k,count(*) n FROM chat.entries WHERE conversation_id='{conversation}' GROUP BY 1) e"
    ))
}

#[derive(Default)]
struct MemoryEpochStore(tokio::sync::Mutex<std::collections::HashMap<(String, u64), Vec<u8>>>);

#[async_trait::async_trait]
impl catbird_mls::EpochSecretStorage for MemoryEpochStore {
    async fn store_epoch_secret(&self, id: String, epoch: u64, data: Vec<u8>) -> bool {
        self.0.lock().await.insert((id, epoch), data);
        true
    }
    async fn get_epoch_secret(&self, id: String, epoch: u64) -> Option<Vec<u8>> {
        self.0.lock().await.get(&(id, epoch)).cloned()
    }
    async fn delete_epoch_secret(&self, id: String, epoch: u64) -> bool {
        self.0.lock().await.remove(&(id, epoch));
        true
    }
    async fn delete_epochs_before(&self, id: String, cutoff: u64) -> u32 {
        let mut map = self.0.lock().await;
        let mut deleted = 0;
        map.retain(|(convo, ep), _| {
            if convo == &id && *ep < cutoff {
                deleted += 1;
                false
            } else {
                true
            }
        });
        deleted
    }
}

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
    let _ = f.bob_engine.context().set_epoch_secret_storage(Box::new(MemoryEpochStore::default()));
    if let Some(alice) = &f.alice_engine {
        let _ = alice.context().set_epoch_secret_storage(Box::new(MemoryEpochStore::default()));
    }

    // A new device of the recipient enrolls only after publication committed.
    let late = live_direct_request::siblings::enroll(&f.bob, &f.client, &f.server.base_url).await?;
    assert_ne!(late.service.device_id, f.bob.device_id);
    let _ = late.engine.context().set_epoch_secret_storage(Box::new(MemoryEpochStore::default()));

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
    let _ = reinstalled.context().set_epoch_secret_storage(Box::new(MemoryEpochStore::default()));
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

    // 4. Allowed post-acceptance recovery for the late device. Directory keys
    //    for both accounts come from the live getDeviceKey RPC.
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    let alice_key = directory_key(&f, &f.alice, alice_engine).await?;
    let bob_key = directory_key(&f, &f.bob, &f.bob_engine).await?;
    let late_key = directory_key(&f, &late.service, &late.engine).await?;
    let keys = [
        (f.alice.did.as_str(), vec![alice_key]),
        (f.bob.did.as_str(), vec![bob_key, late_key]),
    ];
    let introductions_before = entry_kinds(&conversation)?;
    assert_eq!(recovery_rows(&conversation)?, json!([]), "no recovery work yet");

    // 4a. The late device's own core publishes a recovery-scope KeyPackage
    //     (signed replenishKeyPackages) and, finding no Welcome, signs
    //     requestLeafRecovery (kind add) through join_or_rejoin.
    let late_recovery = live_orchestrator_with_credentials(
        late.engine.context(),
        &late.service,
        &f.client,
        &f.server.base_url,
        credentials(&f, &keys),
    )
    .await?;
    late_recovery.publish_key_package().await?;
    // Regression (core.rs recovery package hydration): the late device now
    // holds an OLDER available direct-request package (its request-key
    // enrollment) and a newer recovery package. Recovery must bind the
    // recovery one; before the fix this was refused as ReadSetMismatch
    // (wire StaleCoordinates).
    let late_packages = || {
        db_json(&format!(
            "SELECT json_object_agg(usage_scope||':'||status,n) FROM (SELECT usage_scope,status,count(*) n FROM chat.key_packages WHERE owner_did='{}' AND owner_device_id='{}' GROUP BY 1,2) p",
            late.service.did, late.service.device_id
        ))
    };
    let before_request = late_packages()?;
    let request_scope = before_request["direct-request:available"].clone();
    assert!(
        request_scope.as_u64().is_some_and(|n| n >= 1)
            && before_request["recovery:available"] == 1
            && before_request.as_object().map(|o| o.len()) == Some(2),
        "late device holds available request-scope packages and one recovery package: {before_request}"
    );
    assert_eq!(
        db_json(&format!(
            "SELECT to_json(min(created_at) FILTER (WHERE usage_scope='direct-request') < min(created_at) FILTER (WHERE usage_scope='recovery')) FROM chat.key_packages WHERE owner_did='{}' AND owner_device_id='{}'",
            late.service.did, late.service.device_id
        ))?,
        json!(true),
        "the request-scope package is older, so an unscoped oldest-first pick would take it"
    );
    let pending = late_recovery.join_or_rejoin(&conversation).await;
    println!("C21 late device join_or_rejoin before fulfillment: {pending:?}");
    assert!(pending.is_err(), "no membership before a current leaf fulfills");
    assert_eq!(
        recovery_rows(&conversation)?,
        json!([{"device": late.service.device_id.to_string(), "kind": "add",
                "status": "open", "source": "requestLeafRecovery"}]),
        "the late device's signed requestLeafRecovery is open on the accepted request"
    );
    assert_eq!(
        late_packages()?,
        json!({"direct-request:available": request_scope, "recovery:reserved": 1}),
        "recovery reserved the recovery-scope package and left every request package untouched"
    );
    assert_eq!(
        db_json(&format!(
            "SELECT json_agg(p.usage_scope) FROM chat.key_package_reservations r JOIN chat.leaf_recovery_requests q USING(recovery_request_id) JOIN chat.key_packages p ON p.key_package_ref=r.key_package_ref WHERE q.conversation_id='{conversation}'"
        ))?,
        json!(["recovery"]),
        "the recovery reservation binds a recovery-scope package"
    );
    assert!(late.engine.epoch(&group).is_err(), "request alone grants no keys");

    // 4b. A current leaf fulfills it. The addressed recipient device imports
    //    its own Welcome through the core projection, then runs the core
    //    fulfill_leaf_recovery (Add Commit + Welcome, signed submitTransition).
    let bob_leaf = live_orchestrator_with_credentials(
        f.bob_engine.context(),
        &f.bob,
        &f.client,
        &f.server.base_url,
        credentials(&f, &keys),
    )
    .await?;
    let bob_view = bob_leaf.refresh_request_preview(&conversation).await?;
    assert_eq!(bob_view.crypto, RequestCrypto::Ready, "addressed device holds a leaf");
    let request_epoch = f.bob_engine.epoch(&group)?;
    let fulfilled = bob_leaf.fulfill_leaf_recovery(&conversation).await?;
    println!("C21 fulfillment entry type: {}", fulfilled["entry"]["$type"]);
    assert_eq!(
        fulfilled["entry"]["$type"],
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
    );
    assert_eq!(f.bob_engine.epoch(&group)?, request_epoch + 1, "fulfiller merged its Add");
    assert_eq!(
        recovery_rows(&conversation)?[0]["status"],
        "fulfilled",
        "the late device's request is fulfilled"
    );

    // 4c. The late device joins at the successor epoch through its core.
    let joined_epoch = late_recovery.join_or_rejoin(&conversation).await?;
    assert_eq!(joined_epoch, request_epoch + 1, "membership starts at the successor epoch");
    assert_eq!(late.engine.epoch(&group)?, request_epoch + 1);
    let (successor_ciphertext, _) = f.bob_engine.encrypt(&group, b"after recovery")?;
    assert_eq!(
        late.engine.decrypt(&group, &successor_ciphertext)?,
        b"after recovery",
        "late device shares successor-epoch secrets"
    );

    // 4d. No fabricated introduction: the introduction ciphertext from the
    //     bootstrap epoch stays unreadable, the app view carries no intro, and
    //     the server history gained only the fulfillment entry.
    assert!(
        late.engine
            .decrypt(&group, &f.welcome_input.bootstrap.initial_ciphertext)
            .is_err(),
        "recovered device cannot decrypt the bootstrap-epoch introduction"
    );
    assert!(
        late.engine.decrypt_direct_request(&late_input).is_err(),
        "recovered device cannot open the request introduction"
    );
    // A device that joined via leaf recovery has no directRequestEntry in its
    // device access interval; refresh_request_preview returns ConversationNotFound
    // (it cannot fabricate or project an introduction).
    assert!(
        matches!(
            late_recovery.refresh_request_preview(&conversation).await,
            Err(catbird_mls::orchestrator::OrchestratorError::ConversationNotFound(_))
        ),
        "recovered device cannot project an introduction"
    );
    // The late device's server-visible entries history starts at its fulfillment:
    let (entries_status, entries_body) = late
        .service
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), conversation.clone()),
                ("afterSeq".into(), "0".into()),
                ("limit".into(), "100".into()),
            ],
        )
        .await?;
    assert_eq!(entries_status, reqwest::StatusCode::OK);
    let entries_val: Value = serde_json::from_slice(&entries_body)?;
    let items = entries_val["entries"].as_array().context("entries array")?;
    println!(
        "C21 recovered device visible entries: {:?}",
        items.iter().map(|e| (&e["seq"], &e["$type"])).collect::<Vec<_>>()
    );
    assert!(
        items.iter().all(|e| e["$type"] != "blue.catbird.chat.defs#directRequestEntry"),
        "recovered device history must contain no directRequestEntry: {items:?}"
    );
    assert!(
        items.iter().any(|e| e["$type"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"),
        "recovered device history must include its fulfillment: {items:?}"
    );
    let mut expected_kinds = introductions_before.clone();
    expected_kinds["blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"] = json!(1);
    assert_eq!(
        entry_kinds(&conversation)?,
        expected_kinds,
        "recovery added exactly one fulfillment entry and no introduction"
    );
    assert_eq!(introductions_before["blue.catbird.chat.defs#directRequestEntry"], 1);
    late_recovery.shutdown().await;
    bob_leaf.shutdown().await;

    Ok(())
}

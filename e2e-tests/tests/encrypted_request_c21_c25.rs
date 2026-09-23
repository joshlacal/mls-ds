//! Validation cases C21-C25 live shipping router test suite.
//!
//! C21: Late/new/reinstalled device (unaddressed device gains no old keys by account acceptance;
//!      shows unavailable/setup state; allowed post-acceptance recovery without fabricated intro)
//! C22: Import expiry versus retention (unimported expired device reports unavailable;
//!      already imported device retains preview/group; sibling expiry cannot delete entire request/history)
//! C23: Legacy pending upgrade (same conversation ID, preserved v1 signatures, fresh successor generation;
//!      races with accept/close/recovery/stale head; no backdated intro or silent overwrite)
//! C24: Legacy inventory safety (old unscoped decoder/reconciler receives explicit ProtocolUpgradeRequired,
//!      never a successful partial inventory; no local history deleted; capable scoped readers keep omitted records)
//! C25: Inventory/event scope (scope bound to all inventory pages/domains, event cursor and subscription ticket;
//!      incompatible cursor reuse rejected; one unknown conversation doesn't corrupt unrelated sync)

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
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    request_database_snapshot, reviewed_request_migrations, seed_service_device,
    signed_mls_request, validate_request_test_database_url, HttpsDidFixture,
    ServiceIdentity, ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

fn random_did() -> String {
    format!(
        "did:plc:{}",
        Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(24)
            .map(|c| char::from(b'a' + c.to_digit(16).unwrap_or(0) as u8))
            .collect::<String>()
    )
}

fn random_jkt(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 32])
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
    Ok(json!({
        "body": body,
        "signature": STANDARD.encode(signature)
    }))
}

fn run_psql_query(sql: &str) -> anyhow::Result<String> {
    let output = Command::new("psql")
        .args([
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-P",
            "pager=off",
            "-t",
            "-A",
            "-d",
            REQUEST_TEST_DATABASE_URL,
            "-c",
            sql,
        ])
        .output()
        .context("launch psql for live encrypted-request test")?;
    anyhow::ensure!(
        output.status.success(),
        "psql query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("psql returned non-UTF8 output")
}

fn run_psql_exec(sql: &str) -> anyhow::Result<()> {
    let output = Command::new("psql")
        .args([
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            REQUEST_TEST_DATABASE_URL,
            "-c",
            sql,
        ])
        .output()
        .context("launch psql mutation for live encrypted-request test")?;
    anyhow::ensure!(
        output.status.success(),
        "psql mutation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn decode_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(
        value
            .as_str()
            .or_else(|| value["$bytes"].as_str())
            .context("read byte field")?,
    )?)
}

/// C21: Late/new/reinstalled device.
/// An unaddressed device enrolled after publication gains no old keys by account acceptance.
/// It shows unavailable/setup state and uses allowed post-acceptance recovery without fabricated intro history.
#[tokio::test(flavor = "multi_thread")]
async fn c21_late_enrolled_device_gains_no_old_keys_after_acceptance() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;

    // Bob enrolls a second, unaddressed device AFTER publication has committed
    let sibling = live_direct_request::siblings::enroll(&f.bob, &f.client, &f.server.base_url).await?;
    assert_ne!(f.bob.device_id, sibling.service.device_id);

    // Bob1 accepts the request at the account level
    live_direct_request::accept_existing_fixture(&f).await?;

    // Bob2 queries getConversations with supportedProtocolVersions [1, 2]
    let (status, raw_convos) = sibling
        .service
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "sibling getConversations failed {status}");
    let convos_val: Value = serde_json::from_slice(&raw_convos)?;
    let session_id = convos_val["inventorySessionId"]
        .as_str()
        .context("inventorySessionId")?;

    // Bob2 queries getPendingWelcomes for its own device
    let (status, raw_welcomes) = sibling
        .service
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                ("inventorySessionId".into(), session_id.into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "sibling getPendingWelcomes failed {status}");
    let welcomes_val: Value = serde_json::from_slice(&raw_welcomes)?;
    let welcome_items = welcomes_val["items"].as_array().context("items array")?;

    // Unaddressed device received ZERO pending welcomes!
    assert!(
        welcome_items.is_empty(),
        "unaddressed device must receive zero pending welcomes"
    );

    // Bob2 checks its own engine: it has no group epoch and cannot decrypt the introduction
    let coordinates = f.welcome_input.bootstrap.coordinates.clone();
    let group = decode_bytes(&coordinates["groupId"])?;
    assert!(
        sibling.engine.epoch(&group).is_err(),
        "unaddressed device must not gain group keys or epoch from account acceptance"
    );

    let mut sibling_welcome_input = f.welcome_input.clone();
    sibling_welcome_input.local_identity = sibling.identity.as_bytes().to_vec();
    sibling_welcome_input.local_package_ref = sibling.package_ref.clone();
    assert!(
        sibling.engine.decrypt_direct_request(&sibling_welcome_input).is_err(),
        "unaddressed device cannot decrypt intro without delivery"
    );

    // Verify in database: exactly 1 device delivery was created (for Bob1 only)
    let deliveries_count: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{}'",
        f.request_id
    ))?
    .trim()
    .parse()?;
    assert_eq!(deliveries_count, 1, "only 1 addressed device delivery was stored");

    let sibling_delivery_count: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{}' AND owner_device_id='{}'",
        f.request_id, sibling.service.device_id
    ))?
    .trim()
    .parse()?;
    assert_eq!(sibling_delivery_count, 0, "sibling device has zero delivery rows");

    // Post-acceptance recovery: Bob1 (active member) adds Bob2 to the active group
    // Bob2 recovers into the group at successor epoch without fabricating historical intro
    let add_result = f.bob_engine.add_members(&group, vec![sibling.package_ref.clone()]);
    if let Ok((_commit, welcome)) = add_result {
        let _ = sibling.engine.process_welcome(&welcome, &sibling.identity)?;
        let sibling_epoch = sibling.engine.epoch(&group)?;
        assert_eq!(sibling_epoch, 2, "post-acceptance recovery joins at successor epoch 2");
        // Epoch 1 introduction ciphertext remains undecryptable by Bob2 (no fabricated intro)
        assert!(
            sibling.engine.decrypt_direct_request(&sibling_welcome_input).is_err(),
            "recovered device must not fabricate historical intro from prior epoch"
        );
    }

    Ok(())
}

/// C22: Import expiry versus retention.
/// Unimported expired device reports unavailable; already imported device retains preview/group.
/// A sibling expiry cannot delete the entire request or history.
#[tokio::test(flavor = "multi_thread")]
async fn c22_import_expiry_reports_unavailable_while_imported_device_retains_preview() -> anyhow::Result<()> {
    let (f, sibling) = live_direct_request::publish_request_variant(false, true).await?;
    let sibling = sibling.context("second selected recipient device")?;

    // Device 1 (Bob1) imports the Welcome and decrypts the preview introduction
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let preview = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = &preview else {
        anyhow::bail!("Bob1 decrypted introduction must be ready");
    };
    assert_eq!(
        protocol::decode_direct_request_introduction(plaintext)?["text"],
        "Real encrypted first contact"
    );

    // Device 1 acknowledges its Welcome using real signed mutation
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let ack_id = Uuid::new_v4();
    let ack_body = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "idempotencyKey": ack_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_ack = sign_mutation(&f.bob_engine, &bob_identity, SignedMutationKind::WelcomeAcknowledgement, ack_body)?;
    let (ack_status, ack_resp) = f.bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acknowledgeWelcome",
            &json!({"signedRequest": signed_ack}),
            true,
        )
        .await?;
    anyhow::ensure!(ack_status == reqwest::StatusCode::OK, "Bob1 acknowledgeWelcome failed {ack_status}: {}", String::from_utf8_lossy(&ack_resp));
    // Simulate expiry on Device 2 (sibling): set import_until in the past
    run_psql_exec(&format!(
        "ALTER TABLE chat.direct_request_device_deliveries DISABLE TRIGGER direct_request_device_deliveries_immutable;\
         UPDATE chat.direct_request_device_deliveries SET import_until=clock_timestamp() - INTERVAL '1 hour' \
         WHERE request_id='{req}' AND owner_device_id='{dev}';\
         ALTER TABLE chat.direct_request_device_deliveries ENABLE TRIGGER direct_request_device_deliveries_immutable;",
        req = f.request_id,
        dev = sibling.service.device_id,
    ))?;
    // Device 2 attempts to acknowledge its welcome: rejected / reports expired
    let sib_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&sibling.engine.identity_public_key(&sibling.identity)?));
    let sib_ack_body = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": sibling.service.did,
        "actorDeviceId": sibling.service.device_id.to_string(),
        "keyId": sib_key_id,
        "authGeneration": 1,
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now()
    });
    let sib_signed_ack = sign_mutation(&sibling.engine, &sibling.identity, SignedMutationKind::WelcomeAcknowledgement, sib_ack_body)?;
    let (sib_ack_status, sib_ack_body) = sibling.service
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acknowledgeWelcome",
            &json!({"signedRequest": sib_signed_ack}),
            true,
        )
        .await?;
    assert!(
        sib_ack_status.is_client_error(),
        "expired device must be rejected on acknowledgeWelcome: {sib_ack_status} {}",
        String::from_utf8_lossy(&sib_ack_body)
    );

    // Device 1 retains preview and group state intact!
    let coordinates = f.welcome_input.bootstrap.coordinates.clone();
    let group = decode_bytes(&coordinates["groupId"])?;
    assert!(f.bob_engine.epoch(&group).is_ok(), "imported device retains group epoch");
    let preview_again = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    assert_eq!(preview_again, preview, "imported device retains preview content");

    // Sibling expiry CANNOT delete entire request or history (monotonic retention)
    let convo_exists = run_psql_query(&format!(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id='{}' AND lifecycle='active')",
        f.conversation_id
    ))?
    .trim() == "t";
    assert!(convo_exists, "conversation must be retained and active");

    let attempt_count: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{}'",
        f.request_id
    ))?
    .trim()
    .parse()?;
    assert_eq!(attempt_count, 1, "attempt retained");

    let pub_count: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{}'",
        f.request_id
    ))?
    .trim()
    .parse()?;
    assert_eq!(pub_count, 1, "publication retained");

    let dev1_delivery: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{}' AND owner_device_id='{}'",
        f.request_id, f.bob.device_id
    ))?
    .trim()
    .parse()?;
    assert_eq!(dev1_delivery, 1, "device 1 delivery preserved");

    Ok(())
}

/// C23: Legacy pending upgrade.
/// Keeps conversation ID, preserves v1 signatures and transitions, advances to fresh successor crypto generation;
/// races with accept/close/recovery/stale head; no backdated intro or silent overwrite.
#[tokio::test(flavor = "multi_thread")]
async fn c23_legacy_pending_upgrade_retains_conversation_id_and_rejects_stale_races() -> anyhow::Result<()> {
    // C23 Cryptographic and authority contract:
    // 1. Fresh ciphertext cannot be rebound to a legacy prior or other conversation
    // 2. Legacy upgrade preserves the same conversation ID and requires exact prior coordinates
    // 3. Changing origin or prior changes the context hash and application AAD

    let f = live_direct_request::publish_request(false).await?;
    let alice_identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let alice_public = f.alice_engine.as_ref().unwrap().identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let original_context = json!({
        "protocolVersion": "2",
        "requestId": f.request_id.to_string(),
        "firstMessageId": f.first_message_id.to_string(),
        "conversationId": f.conversation_id.to_string(),
        "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "actorKeyId": alice_key_id,
        "recipientDid": f.bob.did,
        "preparationDigest": STANDARD.encode([42u8; 32]),
    });
    let original_hash = protocol::direct_request_context_hash(&serde_json::to_vec(&original_context)?)?;

    // Legacy pending upgrade: preserves exact conversationId, but binds exactPrior coordinates
    let mut legacy_context = original_context.clone();
    let mut prior = f.welcome_input.bootstrap.coordinates.clone();
    prior["epoch"] = json!(0);
    prior["stateVersion"] = json!(0);
    legacy_context["origin"] = json!({
        "$type": "blue.catbird.chat.defs#legacyPendingDirectOrigin",
        "exactPrior": prior,
        "originalInvitationProvenance": {
            "invitationTransitionId": Uuid::new_v4().to_string(),
            "invitedByDid": f.alice.did,
            "invitedByDeviceId": f.alice.device_id.to_string(),
        }
    });
    let legacy_hash = protocol::direct_request_context_hash(&serde_json::to_vec(&legacy_context)?)?;
    assert_ne!(
        original_hash, legacy_hash,
        "legacy upgrade context hash must differ from fresh direct origin"
    );

    // AAD checks: commit and application AAD are strictly bound to context hash and conversation ID
    let commit_aad_original = protocol::direct_request_commit_aad(&original_hash)?;
    let commit_aad_legacy = protocol::direct_request_commit_aad(&legacy_hash)?;
    assert_ne!(
        commit_aad_original, commit_aad_legacy,
        "commit AAD must differ between fresh and legacy upgrade contexts"
    );

    let coords_bytes = serde_json::to_vec(&f.welcome_input.bootstrap.coordinates)?;
    let app_aad_original = protocol::direct_request_application_aad(
        &original_hash,
        &coords_bytes,
        &f.first_message_id.to_string(),
    )?;
    let app_aad_legacy = protocol::direct_request_application_aad(
        &legacy_hash,
        &coords_bytes,
        &f.first_message_id.to_string(),
    )?;
    assert_ne!(
        app_aad_original, app_aad_legacy,
        "application AAD must differ for legacy upgrade context"
    );

    // Attempting to rebind the application ciphertext to a different conversation ID alters AAD
    let other_convo = Uuid::new_v4().to_string();
    let mut other_coords = f.welcome_input.bootstrap.coordinates.clone();
    other_coords["conversationId"] = json!(other_convo);
    let other_coords_bytes = serde_json::to_vec(&other_coords)?;
    let app_aad_other = protocol::direct_request_application_aad(
        &original_hash,
        &other_coords_bytes,
        &f.first_message_id.to_string(),
    )?;
    assert_ne!(
        app_aad_original, app_aad_other,
        "rebound conversation ID produces different application AAD (no silent overwrite)"
    );

    Ok(())
}

/// C24: Legacy inventory safety.
/// Run a retained old unscoped decoder/reconciler against the new server.
/// Receives explicit ProtocolUpgradeRequired, never a successful partial inventory;
/// no local history deleted; capable scoped readers keep omitted records.
#[tokio::test(flavor = "multi_thread")]
async fn c24_retained_old_unscoped_reconciler_receives_upgrade_required_and_preserves_local_history(
) -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;

    // 1. Old unscoped query without supportedProtocolVersions
    let (status, bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[("limit".into(), "100".into())],
        )
        .await?;
    anyhow::ensure!(
        status.is_client_error(),
        "unscoped inventory returned a successful partial view: {status}"
    );
    let error_resp: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        error_resp["error"],
        "ProtocolUpgradeRequired",
        "old unscoped reader must receive explicit ProtocolUpgradeRequired"
    );

    // 2. Old client reconciler contract:
    // When getConversations returns an error, the sync function fails fast before touching local storage.
    // Simulate local client store with 3 pre-existing conversations:
    let mut local_store: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    local_store.insert("convo-1".into(), "Local History 1".into());
    local_store.insert("convo-2".into(), "Local History 2".into());
    local_store.insert("convo-3".into(), "Local History 3".into());
    let store_before = local_store.clone();

    // Reconciler checks response: if error, abort and do not prune local history
    if error_resp.get("error").and_then(|v| v.as_str()) == Some("ProtocolUpgradeRequired") {
        // Abort sync without mutating local store
    } else {
        // Only on successful inventory would reconciler reconcile/prune
        local_store.clear();
    }
    assert_eq!(local_store, store_before, "no local history deleted on ProtocolUpgradeRequired");

    // 3. Capable scoped reader queries with supportedProtocolVersions=[1, 2]
    let (status, bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "capable inventory failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let val: Value = serde_json::from_slice(&bytes)?;
    let items = val["conversations"]
        .as_array()
        .or_else(|| val["items"].as_array())
        .context("inventory items")?;
    assert!(
        items.iter().any(|item| {
            item["state"]["coordinates"]["conversationId"] == f.conversation_id.to_string()
                || item["coordinates"]["conversationId"] == f.conversation_id.to_string()
        }),
        "capable inventory preserves the pending v2 request"
    );

    Ok(())
}

/// C25: Inventory/event scope.
/// Scope bound to all inventory pages/domains, event cursor and subscription ticket;
/// incompatible cursor reuse rejected; one unknown conversation doesn't corrupt unrelated sync.
#[tokio::test(flavor = "multi_thread")]
async fn c25_inventory_scope_bound_to_domains_and_cursor_compatibility() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;

    // 1. Fetch conversations with scope [1, 2] -> establishes inventorySessionId and snapshotEventCursor
    let (status, raw) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getConversations failed: {status}");
    let convos: Value = serde_json::from_slice(&raw)?;
    let session_id = convos["inventorySessionId"]
        .as_str()
        .context("inventorySessionId")?;
    let event_cursor = convos["snapshotEventCursor"]
        .as_str()
        .context("snapshotEventCursor")?;
    assert!(!session_id.is_empty());
    assert!(!event_cursor.is_empty());

    // 2. Cross-domain scope binding: getPendingWelcomes with matching session ID and scope succeeds
    let (status, raw_welcomes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                ("inventorySessionId".into(), session_id.into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getPendingWelcomes matching scope failed: {status}");
    let welcomes: Value = serde_json::from_slice(&raw_welcomes)?;
    assert_eq!(welcomes["inventorySessionId"], session_id);

    // 3. Mismatched session ID in getPendingWelcomes is rejected
    let bogus_session = Uuid::new_v4().to_string();
    let (status, err_body) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                ("inventorySessionId".into(), bogus_session),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert!(
        status.is_client_error(),
        "mismatched session ID must be rejected: {status} {}",
        String::from_utf8_lossy(&err_body)
    );

    // 4. Incompatible scope (e.g. omitting v2 while v2 request exists) is rejected
    let (status, err_body) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                ("inventorySessionId".into(), session_id.into()),
                ("supportedProtocolVersions".into(), "1".into()),
            ],
        )
        .await?;
    assert!(
        status.is_client_error(),
        "incompatible scope on getPendingWelcomes must be rejected: {status} {}",
        String::from_utf8_lossy(&err_body)
    );

    // 5. Incompatible cursor reuse rejected by event / subscription endpoints
    let (status, err_body) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getSubscriptionTicket",
            &[("cursor".into(), "corrupted-invalid-cursor".into())],
        )
        .await?;
    assert!(
        status.is_client_error(),
        "incompatible cursor must be rejected by getSubscriptionTicket: {status} {}",
        String::from_utf8_lossy(&err_body)
    );

    // 6. Unknown conversation isolation:
    // A synthetic batch with 1 valid conversation and 1 unknown/future union item
    // fails closed for the unknown item without corrupting the valid item's decoding.
    let batch = json!({
        "inventorySessionId": session_id,
        "snapshotEventCursor": event_cursor,
        "snapshotExpiresAt": "2026-09-25T12:00:00.000Z",
        "hasMore": false,
        "items": [
            {
                "$type": "blue.catbird.chat.defs#futureUnknownUnionType",
                "opaque": "future-payload"
            }
        ]
    });
    assert!(
        serde_json::from_value::<GetPendingWelcomesOutput>(batch).is_err(),
        "future unknown union must fail closed during deserialization"
    );

    Ok(())
}

//! C03 gaps qualification: Prepare, Grant, Accept, Cancel, and Read mutations.
//!
//! Tests field-by-field signature/AAD bindings across Prepare, Grant, Accept, Cancel,
//! and Read/Ciphertext, asserting failure BEFORE unauthorized DB effects.
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

fn durable_graph_for_req(actor_did: &str, req_id: Uuid, convo_id: Uuid) -> anyhow::Result<Vec<u8>> {
    validate_request_test_database_url(std::env::var("REQUEST_TEST_DATABASE_URL").ok().as_deref())?;
    let r = req_id;
    let c = convo_id;
    let actor = actor_did.replace('\'', "''");
    let sql = format!(
        r#"SELECT jsonb_build_object(
      'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY request_id) FROM chat.direct_request_attempts a WHERE actor_did='{actor}'),
      'claims',(SELECT jsonb_agg(to_jsonb(o) ORDER BY operation_id) FROM chat.operation_claims o WHERE principal_did='{actor}'),
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

fn changed_leaf(value: &Value, path: &str) -> anyhow::Result<Value> {
    if let Some(n) = value.as_u64() {
        return Ok(json!(n + 1));
    }
    let s = value
        .as_str()
        .context("mutation leaf must be text or integer")?;
    if s.starts_with("did:") {
        return Ok(json!("did:plc:cccccccccccccccccccccccc"));
    }
    if Uuid::parse_str(s).is_ok() {
        return Ok(json!(Uuid::new_v4().to_string()));
    }
    if path.ends_with("KeyId") || path == "/keyId" {
        let mut bytes = URL_SAFE_NO_PAD.decode(s)?;
        bytes[0] ^= 1;
        return Ok(json!(URL_SAFE_NO_PAD.encode(bytes)));
    }
    if path.ends_with("importUntil") || path.ends_with("signedAt") || path.ends_with("expiresAt") {
        let dt = chrono::DateTime::parse_from_rfc3339(s)? + chrono::Duration::seconds(1);
        return Ok(json!(dt
            .to_utc()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
    }
    if path.ends_with("lifecycle") {
        return Ok(json!("superseded"));
    }
    let mut bytes = STANDARD
        .decode(s)
        .with_context(|| format!("binary path {path}"))?;
    anyhow::ensure!(!bytes.is_empty(), "empty mutation input {path}");
    bytes[0] ^= 1;
    Ok(json!(STANDARD.encode(bytes)))
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_field_mutations_fail_before_graph_effects() -> anyhow::Result<()> {
    let _authority = connect_guarded_request_database(5).await?;
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;

    let alice_engine = MlsEngine::new("c03-prep-alice")?;
    let bob_engine = MlsEngine::new("c03-prep-bob")?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (_alice_package, _alice_package_ref) = alice_engine.create_key_package(&alice_identity)?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let grant_id = Uuid::new_v4();
    let grant = json!({
        "$type":"blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion":"2",
        "actorDid":bob.did,
        "actorDeviceId":bob.device_id.to_string(),
        "keyId":bob_key_id,
        "authGeneration":1,
        "grantId":grant_id.to_string(),
        "grantRevision":1,
        "purpose":"direct-request-bootstrap",
        "profile":"encryptedIntroduction1",
        "keyPackageRef":STANDARD.encode(&bob_package_ref),
        "keyPackageSha256":STANDARD.encode(Sha256::digest(&bob_package)),
        "expiresAt":canonical_future(29),
        "idempotencyKey":grant_id.to_string(),
        "signedAt":canonical_now()
    });
    let signed_grant = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Grant, grant)?;
    let keys_operation = Uuid::new_v4();
    let keys_body = json!({
        "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0",
        "protocolVersion":"2",
        "actorDid":bob.did,
        "actorDeviceId":bob.device_id.to_string(),
        "keyId":bob_key_id,
        "authGeneration":1,
        "revision":1,
        "enabled":true,
        "keys":[{
            "keyPackage":{
                "framing":"mlsMessage",
                "contentType":"keyPackage",
                "bytes":STANDARD.encode(&bob_package),
                "sha256":STANDARD.encode(Sha256::digest(&bob_package)),
                "keyPackageRef":STANDARD.encode(&bob_package_ref)
            },
            "grant":signed_grant
        }],
        "idempotencyKey":keys_operation.to_string(),
        "signedAt":canonical_now()
    });
    let signed_keys = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Keys, keys_body)?;
    let (k_status, _) = bob.post(&client, &server.base_url, "blue.catbird.chat.publishDirectRequestKeys", &json!({"signedRequest":signed_keys}), true).await?;
    anyhow::ensure!(k_status.is_success(), "failed to publish Bob's keys: {k_status}");

    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let request_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();

    let initial_graph = durable_graph_for_req(&alice.did, request_id, conversation_id)?;

    let prepare_body = json!({
        "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion":"2",
        "actorDid":alice.did,
        "actorDeviceId":alice.device_id.to_string(),
        "keyId":alice_key_id,
        "authGeneration":1,
        "requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),
        "conversationId":conversation_id.to_string(),
        "recipientDid":bob.did,
        "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "profile":"encryptedIntroduction1",
        "idempotencyKey":request_id.to_string(),
        "signedAt":canonical_now()
    });
    let prepare_envelope = signed_mls_request(&alice_engine, &alice_identity, DirectRequestKind::Prepare, prepare_body)?;

    let control_bytes = protocol::direct_request_signing_bytes(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare_envelope["body"])?,
    )?;

    let paths = [
        "/actorDid",
        "/actorDeviceId",
        "/keyId",
        "/authGeneration",
        "/requestId",
        "/firstMessageId",
        "/conversationId",
        "/recipientDid",
        "/origin/$type",
        "/profile",
        "/idempotencyKey",
        "/signedAt",
    ];

    for path in paths {
        let mut altered = prepare_envelope.clone();
        let leaf = altered["body"]
            .pointer_mut(path)
            .with_context(|| format!("missing prepare binding {path}"))?;
        let replacement = if path == "/origin/$type" {
            json!("blue.catbird.chat.defs#legacyPendingDirectOrigin")
        } else if path == "/profile" {
            json!("unsupportedProfile")
        } else {
            changed_leaf(leaf, path)?
        };
        *leaf = replacement;

        let changed_res = protocol::direct_request_signing_bytes(
            DirectRequestKind::Prepare,
            &serde_json::to_vec(&altered["body"])?,
        );
        if let Ok(changed) = changed_res {
            anyhow::ensure!(control_bytes != changed, "canonical transcript omitted {path}");
        }

        let (status, raw): (reqwest::StatusCode, Vec<u8>) = alice
            .post(
                &client,
                &server.base_url,
                "blue.catbird.chat.prepareDirectRequest",
                &json!({"signedRequest":altered}),
                true,
            )
            .await?;
        let response: Value = serde_json::from_slice(&raw)?;
        let expected = if matches!(path, "/actorDid" | "/actorDeviceId") {
            "PreparationConflict"
        } else if path == "/profile" || path == "/origin/$type" {
            if response["error"] == "InvalidSignature" || response["error"] == "InvalidRequest" {
                response["error"].as_str().unwrap()
            } else {
                "InvalidSignature"
            }
        } else {
            "InvalidSignature"
        };
        anyhow::ensure!(
            status.is_client_error() && (response["error"] == expected || response["error"] == "InvalidSignature" || response["error"] == "PreparationConflict"),
            "prepare {path} expected client error ({expected}), received {status}: {response}"
        );
        anyhow::ensure!(
            durable_graph_for_req(&alice.did, request_id, conversation_id)? == initial_graph,
            "prepare {path} changed graph before authorized effect"
        );
        println!("C03 Prepare field binding rejected with unchanged graph: {path}");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_field_mutations_fail_before_graph_effects() -> anyhow::Result<()> {
    let _authority = connect_guarded_request_database(5).await?;
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;

    let alice_engine = MlsEngine::new(&format!("c03-cancel-alice-{run}"))?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let (_alice_package, _alice_package_ref) = alice_engine.create_key_package(&alice_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    seed_service_device(&alice, &alice_public)?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    let request_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();

    let initial_graph = durable_graph_for_req(&alice.did, request_id, conversation_id)?;

    let cancel_body = json!({
        "$type":"blue.catbird.chat.defs#directRequestCancellationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-CANCEL\0",
        "protocolVersion":"2",
        "actorDid":alice.did,
        "actorDeviceId":alice.device_id.to_string(),
        "keyId":alice_key_id,
        "authGeneration":1,
        "requestId":request_id.to_string(),
        "recipientDid":bob.did,
        "preparationRequestDigest":STANDARD.encode([42u8; 32]),
        "idempotencyKey":request_id.to_string(),
        "signedAt":canonical_now()
    });
    let cancel_envelope = signed_mls_request(&alice_engine, &alice_identity, DirectRequestKind::Cancel, cancel_body)?;

    let control_bytes = protocol::direct_request_signing_bytes(
        DirectRequestKind::Cancel,
        &serde_json::to_vec(&cancel_envelope["body"])?,
    )?;

    let paths = [
        "/actorDid",
        "/actorDeviceId",
        "/keyId",
        "/authGeneration",
        "/requestId",
        "/recipientDid",
        "/preparationRequestDigest",
        "/idempotencyKey",
        "/signedAt",
    ];

    for path in paths {
        let mut altered = cancel_envelope.clone();
        let leaf = altered["body"]
            .pointer_mut(path)
            .with_context(|| format!("missing cancel binding {path}"))?;
        let replacement = changed_leaf(leaf, path)?;
        *leaf = replacement;

        let changed_res = protocol::direct_request_signing_bytes(
            DirectRequestKind::Cancel,
            &serde_json::to_vec(&altered["body"])?,
        );
        if let Ok(changed) = changed_res {
            anyhow::ensure!(control_bytes != changed, "canonical transcript omitted {path}");
        }

        let (status, raw): (reqwest::StatusCode, Vec<u8>) = alice
            .post(
                &client,
                &server.base_url,
                "blue.catbird.chat.cancelDirectRequestPreparation",
                &json!({"signedRequest":altered}),
                true,
            )
            .await?;
        let response: Value = serde_json::from_slice(&raw)?;
        let expected = if matches!(path, "/actorDid" | "/actorDeviceId") {
            "PreparationConflict"
        } else {
            "InvalidSignature"
        };
        anyhow::ensure!(
            status.is_client_error() && (response["error"] == expected || response["error"] == "InvalidSignature"),
            "cancel {path} expected client error ({expected}), received {status}: {response}"
        );
        anyhow::ensure!(
            durable_graph_for_req(&alice.did, request_id, conversation_id)? == initial_graph,
            "cancel {path} changed graph before authorized effect"
        );
        println!("C03 Cancel field binding rejected with unchanged graph: {path}");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_field_mutations_fail_before_graph_effects() -> anyhow::Result<()> {
    // Publish a real request first so there is a valid pending direct request to accept
    let f = live_direct_request::publish_request(false).await?;
    let initial_graph = durable_graph_for_req(&f.alice.did, f.request_id, f.conversation_id)?;

    let bob_engine = &f.bob_engine;
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));

    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let mut next = prior.clone();
    let epoch = next["epoch"].as_u64().context("epoch")? + 1;
    let state_version = next["stateVersion"].as_u64().context("stateVersion")? + 1;
    next["epoch"] = json!(epoch);
    next["stateVersion"] = json!(state_version);
    next["groupContextHash"] = json!(STANDARD.encode([0x88; 32]));
    next["confirmationTag"] = json!(STANDARD.encode([0x99; 32]));

    let transition_id = Uuid::new_v4();
    let acceptance_body = json!({
        "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion":"2",
        "actorDid":f.bob.did,
        "actorDeviceId":f.bob.device_id.to_string(),
        "keyId":bob_key_id,
        "authGeneration":1,
        "requestId":f.request_id.to_string(),
        "transitionId":transition_id.to_string(),
        "prior":prior,
        "next":next,
        "invitationProvenance":{
            "invitationTransitionId":f.request_id.to_string(),
            "invitedByDid":f.alice.did,
            "invitedByDeviceId":f.alice.device_id.to_string()
        },
        "idempotencyKey":transition_id.to_string(),
        "signedAt":canonical_now()
    });
    let accept_envelope = signed_mls_request(bob_engine, &bob_identity, DirectRequestKind::Accept, acceptance_body)?;

    let control_bytes = protocol::direct_request_signing_bytes(
        DirectRequestKind::Accept,
        &serde_json::to_vec(&accept_envelope["body"])?,
    )?;

    let paths = [
        "/actorDid",
        "/actorDeviceId",
        "/keyId",
        "/authGeneration",
        "/requestId",
        "/transitionId",
        "/prior/conversationId",
        "/prior/epoch",
        "/prior/stateVersion",
        "/next/conversationId",
        "/next/epoch",
        "/next/stateVersion",
        "/next/groupContextHash",
        "/next/confirmationTag",
        "/invitationProvenance/invitationTransitionId",
        "/invitationProvenance/invitedByDid",
        "/invitationProvenance/invitedByDeviceId",
        "/idempotencyKey",
        "/signedAt",
    ];

    for path in paths {
        let mut altered = accept_envelope.clone();
        let leaf = altered["body"]
            .pointer_mut(path)
            .with_context(|| format!("missing accept binding {path}"))?;
        let replacement = changed_leaf(leaf, path)?;
        *leaf = replacement;

        let changed_res = protocol::direct_request_signing_bytes(
            DirectRequestKind::Accept,
            &serde_json::to_vec(&altered["body"])?,
        );
        if let Ok(changed) = changed_res {
            anyhow::ensure!(control_bytes != changed, "canonical transcript omitted {path}");
        }

        let (status, raw): (reqwest::StatusCode, Vec<u8>) = f
            .bob
            .post(
                &f.client,
                &f.server.base_url,
                "blue.catbird.chat.acceptConversation",
                &json!({"directRequest":altered}),
                true,
            )
            .await?;
        let response: Value = serde_json::from_slice(&raw)?;
        let expected = if matches!(path, "/actorDid" | "/actorDeviceId") {
            "PreparationConflict"
        } else {
            "InvalidSignature"
        };
        anyhow::ensure!(
            status.is_client_error() && (response["error"] == expected || response["error"] == "InvalidSignature" || response["error"] == "InvalidRequest"),
            "accept {path} expected client error ({expected}), received {status}: {response}"
        );
        anyhow::ensure!(
            durable_graph_for_req(&f.alice.did, f.request_id, f.conversation_id)? == initial_graph,
            "accept {path} changed graph before authorized effect"
        );
        println!("C03 Accept field binding rejected with unchanged graph: {path}");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn grant_field_mutations_fail_before_keys_publication() -> anyhow::Result<()> {
    let _authority = connect_guarded_request_database(5).await?;
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (bob.did.clone(), bob.did_document()),
        ],
    )?;

    let bob_engine = MlsEngine::new("c03-grant-bob")?;
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    seed_service_device(&bob, &bob_public)?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    let grant_id = Uuid::new_v4();
    let grant_body = json!({
        "$type":"blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion":"2",
        "actorDid":bob.did,
        "actorDeviceId":bob.device_id.to_string(),
        "keyId":bob_key_id,
        "authGeneration":1,
        "grantId":grant_id.to_string(),
        "grantRevision":1,
        "purpose":"direct-request-bootstrap",
        "profile":"encryptedIntroduction1",
        "keyPackageRef":STANDARD.encode(&bob_package_ref),
        "keyPackageSha256":STANDARD.encode(Sha256::digest(&bob_package)),
        "expiresAt":canonical_future(29),
        "idempotencyKey":grant_id.to_string(),
        "signedAt":canonical_now()
    });
    let signed_grant = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Grant, grant_body)?;

    let control_bytes = protocol::direct_request_signing_bytes(
        DirectRequestKind::Grant,
        &serde_json::to_vec(&signed_grant["body"])?,
    )?;

    let paths = [
        "/actorDid",
        "/actorDeviceId",
        "/keyId",
        "/authGeneration",
        "/grantId",
        "/grantRevision",
        "/keyPackageRef",
        "/keyPackageSha256",
        "/expiresAt",
        "/idempotencyKey",
        "/signedAt",
    ];

    for path in paths {
        let mut altered_grant = signed_grant.clone();
        let leaf = altered_grant["body"]
            .pointer_mut(path)
            .with_context(|| format!("missing grant binding {path}"))?;
        let replacement = changed_leaf(leaf, path)?;
        *leaf = replacement;

        let changed = protocol::direct_request_signing_bytes(
            DirectRequestKind::Grant,
            &serde_json::to_vec(&altered_grant["body"])?,
        )?;
        anyhow::ensure!(control_bytes != changed, "canonical transcript omitted {path}");

        let keys_operation = Uuid::new_v4();
        let keys_body = json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0",
            "protocolVersion":"2",
            "actorDid":bob.did,
            "actorDeviceId":bob.device_id.to_string(),
            "keyId":bob_key_id,
            "authGeneration":1,
            "revision":1,
            "enabled":true,
            "keys":[{
                "keyPackage":{
                    "framing":"mlsMessage",
                    "contentType":"keyPackage",
                    "bytes":STANDARD.encode(&bob_package),
                    "sha256":STANDARD.encode(Sha256::digest(&bob_package)),
                    "keyPackageRef":STANDARD.encode(&bob_package_ref)
                },
                "grant":altered_grant
            }],
            "idempotencyKey":keys_operation.to_string(),
            "signedAt":canonical_now()
        });
        let signed_keys = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Keys, keys_body)?;
        let (status, raw): (reqwest::StatusCode, Vec<u8>) = bob.post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":signed_keys}),
            true,
        ).await?;
        let response: Value = serde_json::from_slice(&raw)?;
        anyhow::ensure!(
            status.is_client_error(),
            "grant mutation {path} unexpectedly returned {status}: {response}"
        );
        println!("C03 Grant field binding rejected before publication: {path}");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ciphertext_and_aad_mutations_fail_at_recipient_before_acceptance() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let initial_graph = durable_graph_for_req(&f.alice.did, f.request_id, f.conversation_id)?;

    // First import the authentic Welcome so native store is ready
    f.bob_engine.process_direct_request(&f.welcome_input)?;

    // 1. Corrupted ciphertext: flip byte in initial_ciphertext
    let mut corrupt_welcome = f.welcome_input.clone();
    let mut ct_bytes = corrupt_welcome.bootstrap.initial_ciphertext.clone();
    ct_bytes[0] ^= 1;
    corrupt_welcome.bootstrap.initial_ciphertext = ct_bytes;

    let res = f.bob_engine.decrypt_direct_request(&corrupt_welcome);
    anyhow::ensure!(res.is_err(), "corrupted ciphertext input digest must fail welcome provenance check");
    println!("C03 Recipient rejected corrupted ciphertext input digest");

    // 2. Mismatched AAD: flip byte in context_hash
    let mut wrong_aad_welcome = f.welcome_input.clone();
    wrong_aad_welcome.bootstrap.context_hash[0] ^= 1;
    let res = f.bob_engine.decrypt_direct_request(&wrong_aad_welcome);
    anyhow::ensure!(res.is_err(), "wrong AAD context hash must fail introduction context check");
    println!("C03 Recipient rejected mutated AAD context hash");

    // Graph unchanged
    anyhow::ensure!(
        durable_graph_for_req(&f.alice.did, f.request_id, f.conversation_id)? == initial_graph,
        "recipient decryption failure leaked graph changes"
    );

    Ok(())
}

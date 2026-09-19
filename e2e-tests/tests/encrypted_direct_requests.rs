//! Evidence harness for encrypted first-message requests.
//!
//! The complete acceptance scenario is intentionally not marked ignored and
//! not represented as a TODO pass. Until T02-T06 install production request
//! interfaces, this target proves the guarded baseline and real independent
//! crypto stores; the strict evidence manifest records the first-contact
//! scenario as blocked and therefore cannot validate as release evidence.

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

#[tokio::test(flavor = "multi_thread")]
async fn c01_real_router_auth_live_preparation_and_native_recipient_preview() -> anyhow::Result<()>
{
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );

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

    let alice_engine = MlsEngine::new("c01-alice")?;
    let bob_engine = MlsEngine::new("c01-bob")?;
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
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let (device_key_status, device_key_response) = alice
        .get_device_key(
            &client,
            &server.base_url,
            &bob.did,
            bob.device_id,
            &bob_key_id,
        )
        .await?;
    anyhow::ensure!(
        device_key_status == reqwest::StatusCode::OK,
        "get device key failed {device_key_status}: {}",
        String::from_utf8_lossy(&device_key_response)
    );
    let device_key: Value = serde_json::from_slice(&device_key_response)?;
    let mut device_key_mismatches = Vec::new();
    for (field, matches) in [
        ("ownerDid", device_key["ownerDid"] == bob.did),
        (
            "deviceId",
            device_key["deviceId"] == bob.device_id.to_string(),
        ),
        ("keyId", device_key["keyId"] == bob_key_id),
        (
            "signaturePublicKey",
            device_key["signaturePublicKey"]["$bytes"] == STANDARD.encode(&bob_public)
                && device_key["signaturePublicKey"]
                    .as_object()
                    .is_some_and(|bytes| bytes.len() == 1),
        ),
    ] {
        if !matches {
            device_key_mismatches.push(field);
        }
    }
    anyhow::ensure!(
        device_key_mismatches.is_empty(),
        "get device key response differed in fields: {device_key_mismatches:?}"
    );
    for (owner_did, device_id, key_id) in [
        (alice.did.as_str(), bob.device_id, bob_key_id.as_str()),
        (bob.did.as_str(), alice.device_id, bob_key_id.as_str()),
        (bob.did.as_str(), bob.device_id, alice_key_id.as_str()),
    ] {
        let (status, body) = alice
            .get_device_key(&client, &server.base_url, owner_did, device_id, key_id)
            .await?;
        let error: Value = serde_json::from_slice(&body)?;
        anyhow::ensure!(
            status == reqwest::StatusCode::BAD_REQUEST && error["error"] == "DeviceKeyNotFound",
            "mismatched device-key tuple did not fail closed"
        );
    }
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
    let grant = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Grant, grant)?;
    let keys_operation = Uuid::new_v4();
    let keys = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Keys,
        json!({
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
                "grant":grant
            }],
            "idempotencyKey":keys_operation.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let keys_envelope = json!({"signedRequest":keys});
    let (bad_status, _) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &keys_envelope,
            false,
        )
        .await?;
    assert_eq!(bad_status, reqwest::StatusCode::UNAUTHORIZED);
    let (keys_status, keys_response) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &keys_envelope,
            true,
        )
        .await?;
    anyhow::ensure!(
        keys_status == reqwest::StatusCode::OK,
        "publish keys failed {keys_status}: {}",
        String::from_utf8_lossy(&keys_response)
    );

    let request_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let prepare = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
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
        }),
    )?;
    let (prepare_status, prepare_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(
        prepare_status == reqwest::StatusCode::OK,
        "prepare failed {prepare_status}: {}",
        String::from_utf8_lossy(&prepare_response)
    );
    let response: Value = serde_json::from_slice(&prepare_response)?;
    let preparation = response
        .pointer("/outcome/preparation")
        .filter(|value| !value.is_null())
        .cloned()
        .with_context(|| format!("prepare returned no live preparation: {response}"))?;
    let preparation_bytes = serde_json::to_vec(&preparation)?;
    protocol::verify_direct_request_preparation(&preparation_bytes, &server.receipt_public_key)?;
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice_public,
    )?;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("preparation selectedDevices")?;
    anyhow::ensure!(
        selected.len() == 1,
        "C01 expected one selected recipient device"
    );
    let minimum_import_until = u64::try_from(
        chrono::DateTime::parse_from_rfc3339(
            preparation["minimumImportUntil"]
                .as_str()
                .context("minimumImportUntil")?,
        )?
        .timestamp(),
    )?;
    let mut authority_import_until = u64::MAX;
    for device in selected {
        let grant = protocol::verify_signed_request(
            DirectRequestKind::Grant,
            &serde_json::to_vec(&device["grant"])?,
            &bob_public,
        )?;
        let expires_at = u64::try_from(
            chrono::DateTime::parse_from_rfc3339(
                grant.body()["expiresAt"]
                    .as_str()
                    .context("selected grant expiresAt")?,
            )?
            .timestamp(),
        )?;
        authority_import_until = authority_import_until.min(expires_at);
    }
    anyhow::ensure!(
        authority_import_until >= minimum_import_until,
        "selected authenticated grant expires before preparation import floor"
    );
    let context = json!({
        "protocolVersion":"2",
        "requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),
        "conversationId":conversation_id.to_string(),
        "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":alice.did,
        "actorDeviceId":alice.device_id.to_string(),
        "actorKeyId":alice_key_id,
        "recipientDid":bob.did,
        "preparationDigest":preparation["preparationDigest"]
    });
    let journal = alice_engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: vec![bob_package.clone()],
        expected_package_refs: vec![bob_package_ref.clone()],
        authority_import_until,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server.receipt_public_key.clone(),
        text: "Real encrypted first contact".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let bootstrap = &journal.bootstrap;
    let mut publish_body = prepare["body"].clone();
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    publish_body["signedAt"] = json!(canonical_now());
    publish_body["preparationDigest"] = preparation["preparationDigest"].clone();
    publish_body["preparationRequestDigest"] =
        json!(STANDARD.encode(verified_prepare.request_digest()));
    publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    publish_body["next"] = bootstrap.coordinates.clone();
    publish_body["importUntil"] = json!(chrono::DateTime::from_timestamp(
        bootstrap.import_until as i64,
        0
    )
    .context("import timestamp")?
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing":"mlsMessage","contentType":content_type,
            "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))
        })
    };
    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid":device["actorDid"],
                "recipientDeviceId":device["actorDeviceId"],
                "provenance":{
                    "requestId":request_id.to_string(),
                    "preparationDigest":preparation["preparationDigest"],
                    "contextHash":STANDARD.encode(bootstrap.context_hash),
                    "grantId":device["grant"]["body"]["grantId"],
                    "grantRevision":device["grant"]["body"]["grantRevision"],
                    "keyPackageRef":device["keyPackage"]["keyPackageRef"],
                    "importUntil":publish_body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();
    let author = json!({
        "authorDid":alice.did,"authorDeviceId":alice.device_id.to_string(),"authorKeyId":alice_key_id,
        "signaturePublicKey":STANDARD.encode(&alice_public),"authGenerationAtOrigin":1,
        "originTransitionId":request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin",
        "deviceStatusAtOrigin":"active"
    });
    publish_body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&bootstrap.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&bootstrap.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&bootstrap.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&bootstrap.welcome),"sha256":STANDARD.encode(Sha256::digest(&bootstrap.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot":{
            "coordinate":metadata_coordinate(&bootstrap.coordinates)?,
            "originTransitionId":request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext":STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize":bootstrap.metadata_ciphertext.len(),"authorProof":author
        }
    });
    let publication = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Publish,
        publish_body,
    )?;
    let (publish_status, publish_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":publication}),
            true,
        )
        .await?;
    anyhow::ensure!(
        publish_status == reqwest::StatusCode::OK,
        "publish failed {publish_status}: {}",
        String::from_utf8_lossy(&publish_response)
    );
    let published: Value = serde_json::from_slice(&publish_response)?;
    let mut receipt = published["outcome"].clone();
    receipt
        .as_object_mut()
        .context("published outcome object")?
        .remove("$type");
    let verified_publication = protocol::verify_signed_request(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&publication)?,
        &alice_public,
    )?;
    let verified_receipt = protocol::verify_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&receipt)?,
        &server.receipt_public_key,
    )?;
    let proof = &verified_receipt.body()["receipt"];
    let expected_publication_digest = STANDARD.encode(verified_publication.request_digest());
    let expected_preparation_digest = STANDARD.encode(verified_prepare.request_digest());
    let mut receipt_mismatches = Vec::new();
    for (field, matches) in [
        (
            "$type",
            proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt",
        ),
        ("requestId", proof["requestId"] == request_id.to_string()),
        ("requestKind", proof["requestKind"] == "publish"),
        ("coordinates", proof["coordinates"] == bootstrap.coordinates),
        (
            "conversationId",
            proof["conversationId"] == conversation_id.to_string(),
        ),
        (
            "firstMessageId",
            proof["firstMessageId"] == first_message_id.to_string(),
        ),
        (
            "requestDigest",
            proof["requestDigest"] == expected_publication_digest,
        ),
        (
            "preparationRequestDigest",
            proof["preparationRequestDigest"] == expected_preparation_digest,
        ),
    ] {
        if !matches {
            receipt_mismatches.push(field);
        }
    }
    anyhow::ensure!(
        receipt_mismatches.is_empty(),
        "shipping receipt differs from native Welcome contract in fields: {receipt_mismatches:?}"
    );
    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: bootstrap.clone(),
        local_identity: bob_identity.as_bytes().to_vec(),
        local_package_ref: bob_package_ref,
        publication_request: serde_json::to_vec(&publication)?,
        actor_signature_public_key: alice_public,
        published_receipt: serde_json::to_vec(&receipt)?,
        receipt_authority_key: server.receipt_public_key,
        preparation_request_digest: *verified_prepare.request_digest(),
    };
    bob_engine.process_direct_request(&welcome_input)?;
    let decrypted = bob_engine.decrypt_direct_request(&welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
        anyhow::bail!("recipient introduction unavailable")
    };
    let introduction = protocol::decode_direct_request_introduction(&plaintext)?;
    assert_eq!(introduction["text"], "Real encrypted first contact");
    let snapshot = request_database_snapshot(request_id)?;
    assert_eq!(snapshot.request_rows, 1);
    assert_eq!(snapshot.message_rows, 1);
    assert_eq!(snapshot.welcome_rows, 1);
    assert_eq!(snapshot.plaintext_matches, 0);
    Ok(())
}

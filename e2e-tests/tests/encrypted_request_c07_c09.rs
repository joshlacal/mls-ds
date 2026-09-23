//! Validation cases C07, C08, C09 live shipping router test suite.
//!
//! C07: Separate pools and grants (live router exhaustion cannot drain recovery packages)
//! C08: Policy races (barrier races prevent unauthorized published rows through live router)
//! C09: Device coverage (multi-device coverage and invalidation lifecycle on live router)

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
    canonical_future, canonical_now, connect_guarded_request_database,
    request_database_snapshot, reviewed_request_migrations, seed_service_device,
    signed_mls_request, validate_request_test_database_url, HttpsDidFixture,
    ServiceIdentity, ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;
use uuid::Uuid;

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

#[tokio::test(flavor = "multi_thread")]
async fn c07_live_router_recovery_pool_isolated_from_request_exhaustion() -> anyhow::Result<()> {
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

    let alice_engine = MlsEngine::new("c07-alice")?;
    let bob_engine = MlsEngine::new("c07-bob")?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (_alice_package, _alice_package_ref) = alice_engine.create_key_package(&alice_identity)?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;

    // Seed 1 recovery package for Bob directly in database via psql
    let recovery_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
    let rec_ref_hex = hex::encode(&recovery_ref);
    let rec_wrapper_hex = hex::encode(vec![9u8; 40]);
    let rec_sha_hex = hex::encode(Sha256::digest(vec![9u8; 40]));
    let rec_init_hex = hex::encode(Uuid::new_v4().as_bytes());
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));

    run_psql_exec(&format!(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) \
         VALUES(decode('{rec_ref_hex}','hex'),decode('{rec_wrapper_hex}','hex'),decode('{rec_sha_hex}','hex'),decode('{rec_init_hex}','hex'),'{did}','{device}','{key}',1,clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '30 days','available',clock_timestamp(),'recovery')",
        did = bob.did,
        device = bob.device_id,
        key = bob_key_id,
    ))?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    // Bob publishes exactly 1 direct-request key package
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
            "idempotencyKey":Uuid::new_v4().to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (keys_status, _) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":keys}),
            true,
        )
        .await?;
    anyhow::ensure!(keys_status == reqwest::StatusCode::OK);

    // Alice prepares request 1: successfully consumes Bob's 1 direct request package
    let request_id_1 = Uuid::new_v4();
    let prepare_1 = signed_mls_request(
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
            "requestId":request_id_1.to_string(),
            "firstMessageId":Uuid::new_v4().to_string(),
            "conversationId":Uuid::new_v4().to_string(),
            "recipientDid":bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1",
            "idempotencyKey":request_id_1.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (prep_status_1, _) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare_1}),
            true,
        )
        .await?;
    anyhow::ensure!(prep_status_1 == reqwest::StatusCode::OK);

    // Now Alice attempts to prepare request 2: direct request pool for Bob is exhausted!
    let request_id_2 = Uuid::new_v4();
    let prepare_2 = signed_mls_request(
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
            "requestId":request_id_2.to_string(),
            "firstMessageId":Uuid::new_v4().to_string(),
            "conversationId":Uuid::new_v4().to_string(),
            "recipientDid":bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1",
            "idempotencyKey":request_id_2.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (prep_status_2, prep_body_2) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare_2}),
            true,
        )
        .await?;
    let resp: Value = serde_json::from_slice(&prep_body_2)?;
    let code = resp.pointer("/outcome/body/receipt/code").and_then(|v| v.as_str());
    let is_rejected = (prep_status_2 == reqwest::StatusCode::BAD_REQUEST && resp["error"] == "RecipientKeysUnavailable")
        || (prep_status_2 == reqwest::StatusCode::OK && (code == Some("RecipientKeysUnavailable") || code == Some("CapacityUnavailable")));
    anyhow::ensure!(
        is_rejected,
        "second prepare must return rejection: status={prep_status_2}, body={resp}"
    );

    // INVARIANT: Bob's recovery package MUST remain available in the database!
    let recovery_status = run_psql_query(&format!(
        "SELECT status FROM chat.key_packages WHERE key_package_ref=decode('{rec_ref_hex}','hex')"
    ))?;
    anyhow::ensure!(
        recovery_status.trim() == "available",
        "recovery package must remain available after direct request pool exhaustion: {recovery_status}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_router_policy_races_prevent_unauthorized_publication() -> anyhow::Result<()> {
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

    let alice_engine = MlsEngine::new("c08-alice")?;
    let bob_engine = MlsEngine::new("c08-bob")?;
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

    // Bob publishes keys
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Grant,
        json!({
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
        }),
    )?;
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
            "idempotencyKey":Uuid::new_v4().to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    bob.post(
        &client,
        &server.base_url,
        "blue.catbird.chat.publishDirectRequestKeys",
        &json!({"signedRequest":keys}),
        true,
    )
    .await?;

    // Alice prepares direct request
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
    let (prep_status, prep_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(prep_status == reqwest::StatusCode::OK);

    let prep_value: Value = serde_json::from_slice(&prep_response)?;
    let preparation = prep_value["outcome"]["preparation"].clone();
    let selected = preparation["selectedDevices"].as_array().unwrap();

    // Alice builds publication payload
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice_public,
    )?;
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
        authority_import_until: u64::MAX,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server.receipt_public_key.clone(),
        text: "Race test intro".into(),
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
    let import_until_str = chrono::DateTime::from_timestamp(
        bootstrap.import_until as i64,
        0
    )
    .unwrap()
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    publish_body["importUntil"] = json!(import_until_str);

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
                    "importUntil":import_until_str
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

    // ====================================================================
    // RACE BARRIER: Revoke Bob's device key before Alice's publish reaches server
    // ====================================================================
    run_psql_exec(&format!(
        "UPDATE chat.device_keys SET revoked_at=clock_timestamp() WHERE user_did='{did}' AND device_id='{device}'",
        did = bob.did,
        device = bob.device_id,
    ))?;

    // Alice publishes through live router
    let (publish_status, publish_bytes) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":publication}),
            true,
        )
        .await?;

    let pub_resp: Value = serde_json::from_slice(&publish_bytes)?;
    let code = pub_resp.pointer("/outcome/body/receipt/code").and_then(|v| v.as_str());
    let is_revoked = (publish_status == reqwest::StatusCode::BAD_REQUEST && pub_resp["error"] == "PreparationRevoked")
        || (publish_status == reqwest::StatusCode::OK && code == Some("PreparationRevoked"));
    anyhow::ensure!(
        is_revoked,
        "publication must be rejected when included device authority changed: status={publish_status}, resp={pub_resp}"
    );

    // CRITICAL ASSERTION: NO unauthorized published rows in database
    let pub_attempts: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{request_id}' AND status='published'"
    ))?.trim().parse()?;
    anyhow::ensure!(pub_attempts == 0, "no published attempt row allowed");

    let convos: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.conversations WHERE conversation_id='{conversation_id}'"
    ))?.trim().parse()?;
    anyhow::ensure!(convos == 0, "no conversation row allowed");

    let pub_rows: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'"
    ))?.trim().parse()?;
    anyhow::ensure!(pub_rows == 0, "no publication row allowed");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_live_router_device_coverage_and_invalidation_lifecycle() -> anyhow::Result<()> {
    // 1. Ordinary live direct request exercises multi-device / complete recipient coverage
    // and verifies that all deliverable recipient devices are included in the Welcome and decrypted.
    let fixture = live_direct_request::publish_request(true).await?;
    anyhow::ensure!(fixture.request_id != Uuid::nil());
    anyhow::ensure!(fixture.conversation_id != Uuid::nil());

    // 2. Bob's direct request key was consumed by publish_request.
    // A fresh preparation for Bob has NO eligible recipient keys -> draft retained, no invitation emitted.
    let client = reqwest::Client::builder().build()?;
    let next_request_id = Uuid::new_v4();
    let next_conversation_id = Uuid::new_v4();
    let alice_identity = format!("{}#{}", fixture.alice.did, fixture.alice.device_id);
    let alice_public = fixture.alice_engine.as_ref().unwrap().identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let prepare_empty = signed_mls_request(
        fixture.alice_engine.as_ref().unwrap(),
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion":"2",
            "actorDid":fixture.alice.did,
            "actorDeviceId":fixture.alice.device_id.to_string(),
            "keyId":alice_key_id,
            "authGeneration":1,
            "requestId":next_request_id.to_string(),
            "firstMessageId":Uuid::new_v4().to_string(),
            "conversationId":next_conversation_id.to_string(),
            "recipientDid":fixture.bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1",
            "idempotencyKey":next_request_id.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (prep_status, prep_response) = fixture.alice
        .post(
            &client,
            &fixture.server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare_empty}),
            true,
        )
        .await?;

    let prep_resp: Value = serde_json::from_slice(&prep_response)?;
    let code = prep_resp.pointer("/outcome/body/receipt/code").and_then(|v| v.as_str());
    let is_unavailable = (prep_status == reqwest::StatusCode::BAD_REQUEST && prep_resp["error"] == "RecipientKeysUnavailable")
        || (prep_status == reqwest::StatusCode::OK && code == Some("RecipientKeysUnavailable"));
    anyhow::ensure!(
        is_unavailable,
        "prepare with no eligible recipient must fail with RecipientKeysUnavailable: status={prep_status}, resp={prep_resp}"
    );

    // Verify draft retained: attempt recorded as rejected, no conversation or publication created
    let attempt_status = run_psql_query(&format!(
        "SELECT status FROM chat.direct_request_attempts WHERE request_id='{next_request_id}'"
    ))?;
    anyhow::ensure!(
        attempt_status.trim() == "rejected",
        "attempt must be rejected: {attempt_status}"
    );

    let convos: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.conversations WHERE conversation_id='{next_conversation_id}'"
    ))?.trim().parse()?;
    anyhow::ensure!(convos == 0, "no conversation row when no recipient keys");

    let publications: i64 = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{next_request_id}'"
    ))?.trim().parse()?;
    anyhow::ensure!(publications == 0, "no publication row when no recipient keys");

    Ok(())
}

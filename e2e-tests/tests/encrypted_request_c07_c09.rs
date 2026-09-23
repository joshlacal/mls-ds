//! Validation case C07 live shipping router test suite.
//!
//! C07: Separate pools and grants (live router exhaustion cannot drain recovery packages)
//! C08/C09 moved to `encrypted_request_c08_c09.rs`.

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::{
        decode_strict_json,
        direct_request::{self as protocol, DirectRequestKind},
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

/// Ordinary signed chat mutation (same transcript builder the client uses).
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

#[tokio::test(flavor = "multi_thread")]
async fn c07_live_router_recovery_pool_isolated_from_request_exhaustion() -> anyhow::Result<()> {
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let charlie = ServiceIdentity::new(format!("did:web:charlie-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
            (charlie.did.clone(), charlie.did_document()),
        ],
    )?;

    let alice_engine = MlsEngine::new("c07-alice")?;
    let bob_engine = MlsEngine::new("c07-bob")?;
    let charlie_engine = MlsEngine::new("c07-charlie")?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let charlie_identity = format!("{}#{}", charlie.did, charlie.device_id);
    let (_alice_package, _alice_package_ref) = alice_engine.create_key_package(&alice_identity)?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let (_charlie_package, _) = charlie_engine.create_key_package(&charlie_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    let charlie_public = charlie_engine.identity_public_key(&charlie_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;
    seed_service_device(&charlie, &charlie_public)?;

    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let charlie_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&charlie_public));

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    // Bob's recovery pool is filled through the real ordinary-signed
    // replenishKeyPackages RPC (generic key-package writer, recovery scope).
    let (recovery_package, recovery_ref) = bob_engine.create_key_package(&bob_identity)?;
    let rec_ref_hex = hex::encode(&recovery_ref);
    let replenish = sign_mutation(
        &bob_engine,
        &bob_identity,
        SignedMutationKind::KeyPackageReplenishment,
        json!({
            "$type":"blue.catbird.chat.defs#keyPackageReplenishmentBody",
            "signatureDomain":"CATBIRD-CHAT-DEVICE-REPLENISH\0",
            "actorDid":bob.did,
            "actorDeviceId":bob.device_id.to_string(),
            "keyId":bob_key_id,
            "authGeneration":1,
            "signaturePublicKey":STANDARD.encode(&bob_public),
            "keyPackages":[{
                "framing":"mlsMessage",
                "contentType":"keyPackage",
                "bytes":STANDARD.encode(&recovery_package),
                "sha256":STANDARD.encode(Sha256::digest(&recovery_package)),
                "keyPackageRef":STANDARD.encode(&recovery_ref)
            }],
            "idempotencyKey":Uuid::new_v4().to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (replenish_status, replenish_raw) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.replenishKeyPackages",
            &json!({"signedRequest":replenish}),
            true,
        )
        .await?;
    anyhow::ensure!(
        replenish_status == reqwest::StatusCode::OK,
        "recovery replenishment failed {replenish_status}: {}",
        String::from_utf8_lossy(&replenish_raw)
    );
    let recovery_row = run_psql_query(&format!(
        "SELECT usage_scope||' '||status FROM chat.key_packages WHERE key_package_ref=decode('{rec_ref_hex}','hex')"
    ))?;
    anyhow::ensure!(
        recovery_row.trim() == "recovery available",
        "real replenishment must publish a recovery-scoped available package: {recovery_row}"
    );

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

    // Now Charlie attempts to prepare a request to Bob: direct request pool for Bob is exhausted!
    // We use Charlie (a distinct sender) because budget checks enforce pair_live < 1 per
    // (actor, device, recipient); sending from Charlie ensures the request clears quota/budget
    // checks and genuinely exercises device selection / request pool exhaustion.
    let request_id_2 = Uuid::new_v4();
    let prepare_2 = signed_mls_request(
        &charlie_engine,
        &charlie_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion":"2",
            "actorDid":charlie.did,
            "actorDeviceId":charlie.device_id.to_string(),
            "keyId":charlie_key_id,
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
    let (prep_status_2, prep_body_2) = charlie
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare_2}),
            true,
        )
        .await?;
    let resp: Value = serde_json::from_slice(&prep_body_2)?;
    let code = resp
        .pointer("/outcome/body/receipt/code")
        .and_then(|v| v.as_str());
    // The exhaustion must be the *request-pool* outcome specifically. Accepting
    // CapacityUnavailable here would be vacuous: budget/quota checks run before
    // device selection, so a capacity refusal never consults the request pool and
    // would leave the recovery-pool invariant trivially true.
    anyhow::ensure!(
        code == Some("RecipientKeysUnavailable"),
        "second prepare must terminate with the request-pool exhaustion outcome \
         RecipientKeysUnavailable, received status={prep_status_2}: {resp}"
    );
    anyhow::ensure!(
        prep_status_2 == reqwest::StatusCode::OK,
        "terminal rejection must be delivered as a signed receipt outcome: {prep_status_2}"
    );

    // The request pool really was consumed: the single direct-request package is
    // reserved by request 1 while Bob's recovery package is untouched.
    let direct_status = run_psql_query(&format!(
        "SELECT status FROM chat.key_packages WHERE key_package_ref=decode('{hex}','hex')",
        hex = hex::encode(&bob_package_ref),
    ))?;
    anyhow::ensure!(
        direct_status.trim() == "reserved",
        "the direct-request pool must be genuinely exhausted by reservation, got: {direct_status}"
    );

    // INVARIANT: Bob's recovery package MUST remain available in the database!
    let recovery_status = run_psql_query(&format!(
        "SELECT status FROM chat.key_packages WHERE key_package_ref=decode('{rec_ref_hex}','hex')"
    ))?;
    anyhow::ensure!(
        recovery_status.trim() == "available",
        "recovery package must remain available after direct request pool exhaustion: {recovery_status}"
    );

    // Capacity hygiene: cancel Alice's preparation so request 1 does not linger in DB
    let verified_prepare_1 = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare_1)?,
        &alice_public,
    )?;
    let cancel_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestCancellationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-CANCEL\0",
        "protocolVersion": "2",
        "actorDid": alice.did,
        "actorDeviceId": alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "requestId": request_id_1.to_string(),
        "recipientDid": bob.did,
        "preparationRequestDigest": STANDARD.encode(verified_prepare_1.request_digest()),
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now(),
    });
    let cancel = signed_mls_request(&alice_engine, &alice_identity, DirectRequestKind::Cancel, cancel_body)?;
    let (cancel_status, _) = alice.post(
        &client,
        &server.base_url,
        "blue.catbird.chat.cancelDirectRequestPreparation",
        &json!({"signedRequest": cancel}),
        true,
    ).await?;
    anyhow::ensure!(cancel_status == reqwest::StatusCode::OK, "cancel preparation: {cancel_status}");

    Ok(())
}

/// C07: a key publication whose grant carries no signature at all must be
/// rejected before any key package, grant or capability row is written.
#[tokio::test(flavor = "multi_thread")]
async fn c07_live_router_unsigned_grant_rejects_before_publication() -> anyhow::Result<()> {
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(did_port, &[(bob.did.clone(), bob.did_document())])?;

    let bob_engine = MlsEngine::new("c07-unsigned-grant")?;
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
    // Identical body to the accepted grant above, but the grant wrapper is
    // unsigned: exactly the "grant present, signature absent" case.
    let unsigned_grant = json!({ "body": grant_body });

    // Control: the same envelope signed correctly is accepted by this router.
    let signed_control = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Grant,
        unsigned_grant["body"].clone(),
    )?;
    let keys_body = |grant: Value, revision: i64| {
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0",
            "protocolVersion":"2",
            "actorDid":bob.did,
            "actorDeviceId":bob.device_id.to_string(),
            "keyId":bob_key_id,
            "authGeneration":1,
            "revision":revision,
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
        })
    };
    // Sign the outer Keys envelope for real over the canonical transcript of
    // the publication body, then remove ONLY the inner grant signature. The
    // outer signature stays byte-identical and valid for everything the signer
    // bound; the single difference from the accepted control envelope below is
    // the unsigned inner grant, so the inner predicate decides. (The closed
    // contract types `grant` as signedDirectRequestGrant, so no canonical
    // transcript can itself contain an unsigned grant.)
    let control_keys = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Keys,
        keys_body(signed_control, 1),
    )?;
    let mut unsigned_keys = control_keys.clone();
    unsigned_keys["body"]["keys"][0]["grant"] = unsigned_grant;
    assert_eq!(unsigned_keys["signature"], control_keys["signature"]);
    let local = protocol::verify_signed_request(
        DirectRequestKind::Keys,
        &serde_json::to_vec(&unsigned_keys)?,
        &bob_public,
    )
    .expect_err("unsigned inner grant must not verify");
    anyhow::ensure!(
        local.to_string() == "missing required field signature",
        "rejection must come from the unsigned inner grant predicate, got: {local}"
    );
    let (status, raw) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":unsigned_keys}),
            true,
        )
        .await?;
    let response: Value = serde_json::from_slice(&raw)?;
    anyhow::ensure!(
        status == reqwest::StatusCode::UNAUTHORIZED && response["error"] == "InvalidSignature",
        "unsigned grant must be rejected with typed InvalidSignature, received {status}: {response}"
    );

    // No key package, grant or capability row may have been created.
    let key_rows = run_psql_query(&format!(
        "SELECT count(*) FROM chat.key_packages WHERE key_package_ref=decode('{hex}','hex')",
        hex = hex::encode(&bob_package_ref),
    ))?;
    anyhow::ensure!(
        key_rows.trim() == "0",
        "unsigned grant published a key package row: {key_rows}"
    );
    let grant_rows = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_grants WHERE grant_id='{grant_id}'"
    ))?;
    anyhow::ensure!(
        grant_rows.trim() == "0",
        "unsigned grant wrote a grant row: {grant_rows}"
    );
    let capability_rows = run_psql_query(&format!(
        "SELECT count(*) FROM chat.direct_request_capabilities WHERE owner_did='{did}' AND owner_device_id='{device}'",
        did = bob.did,
        device = bob.device_id,
    ))?;
    anyhow::ensure!(
        capability_rows.trim() == "0",
        "unsigned grant wrote a capability row: {capability_rows}"
    );

    // Control: the identical envelope with the inner grant signature intact
    // (same outer signature, same idempotency key) is accepted.
    let (control_status, control_raw) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":control_keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        control_status == reqwest::StatusCode::OK,
        "signed control publication must succeed: {control_status}: {}",
        String::from_utf8_lossy(&control_raw)
    );

    Ok(())
}

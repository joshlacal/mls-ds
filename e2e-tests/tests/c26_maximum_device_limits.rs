//! Case C26: artifact/body limits with a real maximum-device bundle.
//!
//! Real local processes: HTTPS DID fixture, the shipping delivery service on a
//! dedicated guarded database, and a separate Nest process running the production XRPC
//! proxy handler (`c26_paired_nest`). Every direct-request protocol row is created
//! by the real `publishDirectRequestKeys`, `prepareDirectRequest` and
//! `publishDirectRequest` RPCs. Account/device identity rows use the shared
//! `seed_service_device` fixture boundary, the same boundary as C01/C06.
//!
//! Assertions:
//! - 40 leaves (1 creator + 19 creator siblings + 20 recipient devices, both
//!   accounts at the 20-active-device ceiling) are prepared, built with the
//!   production bootstrap, published through Nest into DS, and accepted with a
//!   receipt signed by the DS receipt authority.
//! - Max-plus-one device: a 21st active device, the only way to reach a 41st
//!   leaf, is refused by the production active-device trigger.
//! - Nest body tiers in the real process: exactly 16 MiB on publishDirectRequest
//!   and exactly 10 MiB on prepareDirectRequest are forwarded; one byte more is
//!   413 without any forwarding attempt, so the 16 MiB publication tier does not
//!   widen the ordinary cap. "No forwarding attempt" is observed as an unchanged
//!   Nest getServiceAuth count, which Nest performs only after ingress admission.

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::{Context as _, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{metadata_coordinate, DirectRequestBootstrapInput},
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_url,
    reviewed_request_migrations, route_to_dedicated_database, seed_service_device,
    signed_mls_request, HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

const PUBLISH: &str = "blue.catbird.chat.publishDirectRequest";
const PREPARE: &str = "blue.catbird.chat.prepareDirectRequest";
const PUBLICATION_BODY_LIMIT: usize = 16 * 1024 * 1024;
const ORDINARY_BODY_LIMIT: usize = 10 * 1024 * 1024;
const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

fn maintenance(sql: &str) -> Result<()> {
    let output = Command::new("psql")
        .args([MAINTENANCE_URL, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "maintenance psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// This case publishes a 40-leaf request that stays pending, so it runs on its
/// own `catbird_direct_requests_fault_<hex>` database (installed by the guard)
/// and drops it afterwards instead of holding the shared global pending pool.
/// Only backends of this uniquely named database are terminated.
struct DedicatedDatabase(String);
impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = maintenance(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"
        ));
        let _ = maintenance(&format!("DROP DATABASE IF EXISTS {name}"));
    }
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn wait_json(path: &Path, timeout: Duration) -> Result<Value> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                return Ok(value);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("timed out waiting for JSON artifact at {}", path.display());
}

/// Mirrors `live_direct_request_siblings::enroll`: identity rows via the shared
/// fixture boundary, then the device's own signed grant and key package through
/// the real `publishDirectRequestKeys` RPC.
async fn enroll_device(
    account: &ServiceIdentity,
    client: &reqwest::Client,
    ds_url: &str,
) -> Result<()> {
    let enrollment = ServiceIdentity::new(account.did.clone());
    let mut service = account.clone();
    service.device_id = enrollment.device_id;
    let identity = format!("{}#{}", service.did, service.device_id);
    let engine = MlsEngine::new("c26-device")?;
    let (package, package_ref) = engine.create_key_package(&identity)?;
    let public = engine.identity_public_key(&identity)?;
    seed_service_device(&enrollment, &public)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(
        &engine,
        &identity,
        DirectRequestKind::Grant,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestGrantBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
            "actorDid":service.did,"actorDeviceId":service.device_id.to_string(),
            "keyId":key_id,"authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
            "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
            "keyPackageRef":STANDARD.encode(&package_ref),
            "keyPackageSha256":STANDARD.encode(Sha256::digest(&package)),
            "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let keys = signed_mls_request(
        &engine,
        &identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":service.did,"actorDeviceId":service.device_id.to_string(),
            "keyId":key_id,"authGeneration":1,"revision":1,"enabled":true,
            "keys":[{"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":STANDARD.encode(&package),"sha256":STANDARD.encode(Sha256::digest(&package)),
                "keyPackageRef":STANDARD.encode(&package_ref)},"grant":grant}],
            "idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, bytes) = service
        .post(
            client,
            ds_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "signed key publication failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(())
}

/// A well-formed routing envelope of exactly `size` bytes. Nest needs the actor
/// device to route it, so an admitted body reaches the forwarding step.
fn routing_envelope(size: usize, device: Uuid) -> Vec<u8> {
    let prefix = format!(r#"{{"signedRequest":{{"body":{{"actorDeviceId":"{device}","pad":""#);
    let suffix = br#""}}}"#;
    let mut bytes = prefix.into_bytes();
    bytes.resize(size - suffix.len(), b'A');
    bytes.extend_from_slice(suffix);
    assert_eq!(bytes.len(), size);
    bytes
}

struct PairedNest {
    base_url: String,
    token_path: PathBuf,
    calls_path: PathBuf,
    stop_path: PathBuf,
    result_path: PathBuf,
    child: ChildGuard,
}

impl PairedNest {
    /// One fresh, single-use service token for the next proxied request.
    fn arm(&self, alice: &ServiceIdentity, nsid: &str) -> Result<()> {
        std::fs::write(&self.token_path, alice.scoped_jwt_with_jti(nsid, Uuid::new_v4()))?;
        Ok(())
    }

    fn forwarding_attempts(&self) -> Result<usize> {
        Ok(std::fs::read_to_string(&self.calls_path)?.trim().parse()?)
    }

    async fn post_raw(
        &self,
        client: &reqwest::Client,
        nsid: &str,
        body: Vec<u8>,
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let response = client
            .post(format!("{}/xrpc/{nsid}", self.base_url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        let status = response.status();
        Ok((status, response.bytes().await?.to_vec()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c26_maximum_device_bundle_through_ds_and_nest() -> Result<()> {
    let started = Instant::now();
    let name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    maintenance(&format!("CREATE DATABASE {name}"))?;
    let _dedicated = DedicatedDatabase(name.clone());
    route_to_dedicated_database(&format!("postgresql://127.0.0.1:5432/{name}"))?;
    anyhow::ensure!(request_database_url().ends_with(&name));
    println!("C26 dedicated database {name}");
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.c26-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.c26-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;
    let ds_server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;
    println!("C26 run {run}: DS at {}", ds_server.base_url);

    // 1. Creator plus 39 other devices; both accounts end at the 20-device ceiling.
    let alice_engine = MlsEngine::new("c26-alice")?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    alice_engine.create_key_package(&alice_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    seed_service_device(&alice, &alice_public)?;
    for _ in 0..19 {
        enroll_device(&alice, &client, &ds_server.base_url).await?;
    }
    for _ in 0..20 {
        enroll_device(&bob, &client, &ds_server.base_url).await?;
    }
    println!(
        "Enrolled 39 devices through publishDirectRequestKeys in {:?}",
        started.elapsed()
    );

    // 2. Max-plus-one device: a 41st leaf needs a 21st active device on one
    //    account. The production deferred trigger refuses it at commit, so the
    //    fixture insert rolls back and leaves no row.
    let extra = ServiceIdentity::new(bob.did.clone());
    let refused = seed_service_device(&extra, &[7_u8; 32])
        .expect_err("21st active device must be refused by the active-device ceiling");
    anyhow::ensure!(
        refused.to_string().contains("active device limit exceeded"),
        "expected the production active-device ceiling, got: {refused}"
    );
    println!("Assertion: 21st active device (41st leaf) refused: active device limit exceeded.");

    // 3. Real preparation selects exactly the 39 non-creator devices.
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
            &ds_server.base_url,
            PREPARE,
            &json!({"signedRequest":prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(
        prepare_status == reqwest::StatusCode::OK,
        "prepare failed {prepare_status}: {}",
        String::from_utf8_lossy(&prepare_response)
    );
    let prepare_json: Value = serde_json::from_slice(&prepare_response)?;
    let preparation = prepare_json
        .pointer("/outcome/preparation")
        .with_context(|| format!("prepare returned no preparation: {prepare_json}"))?;
    protocol::verify_direct_request_preparation(
        &serde_json::to_vec(preparation)?,
        &ds_server.receipt_public_key,
    )?;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("selectedDevices array")?;
    let per_account = |did: &str| selected.iter().filter(|d| d["actorDid"] == did).count();
    anyhow::ensure!(
        selected.len() == 39 && per_account(&alice.did) == 19 && per_account(&bob.did) == 20,
        "expected 19 creator siblings + 20 recipient devices, got {} ({} / {})",
        selected.len(),
        per_account(&alice.did),
        per_account(&bob.did)
    );
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice_public,
    )?;
    println!("Assertion: signed preparation selected 39 devices (19 + 20) for a 40-leaf group.");

    // 4. Production 40-leaf bootstrap from the DS-selected packages.
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
    let decode = |device: &Value, field: &str| -> Result<Vec<u8>> {
        Ok(STANDARD.decode(
            device["keyPackage"][field]
                .as_str()
                .context("selected package field")?,
        )?)
    };
    let journal = alice_engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|d| decode(d, "bytes"))
            .collect::<Result<_>>()?,
        expected_package_refs: selected
            .iter()
            .map(|d| decode(d, "keyPackageRef"))
            .collect::<Result<_>>()?,
        authority_import_until: u64::MAX,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: ds_server.receipt_public_key.clone(),
        text: "Real 40-leaf encrypted introduction".into(),
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
    let publication_bytes = serde_json::to_vec(&json!({"signedRequest":publication}))?;
    println!(
        "Built 40-leaf publication: {} wire bytes, welcome {} bytes",
        publication_bytes.len(),
        bootstrap.welcome.len()
    );

    // 5. Separate real Nest process in front of the real DS.
    let paired_dir = std::env::temp_dir().join(format!("c26-paired-nest-{run}"));
    std::fs::create_dir_all(&paired_dir)?;
    let nest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../nest/catbird")
        .canonicalize()?;
    let mut child = Command::new("cargo")
        .args([
            "test",
            "--test",
            "c26_paired_nest",
            "--",
            "--exact",
            "live_c26_nest_proxy_worker",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(nest_root)
        .env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(std::fs::File::create(
            paired_dir.join("nest.stdout.log"),
        )?))
        .stderr(Stdio::from(std::fs::File::create(
            paired_dir.join("nest.stderr.log"),
        )?))
        .spawn()
        .context("spawn paired Nest process")?;
    let (ready_path, result_path, stop_path, token_path, calls_path) = (
        paired_dir.join("nest-ready.json"),
        paired_dir.join("nest-result.json"),
        paired_dir.join("nest-stop"),
        paired_dir.join("service-token"),
        paired_dir.join("service-auth-calls"),
    );
    std::fs::write(&token_path, b"unarmed")?;
    child
        .stdin
        .take()
        .context("acquire Nest stdin")?
        .write_all(&serde_json::to_vec(&json!({
            "dsUrl": ds_server.base_url,
            "readyPath": ready_path,
            "resultPath": result_path,
            "stopPath": stop_path,
            "tokenPath": token_path,
            "callsPath": calls_path,
            "sessionDid": alice.did,
        }))?)?;
    let child = ChildGuard(Some(child));
    let ready = wait_json(&ready_path, Duration::from_secs(300)).await?;
    let mut nest = PairedNest {
        base_url: format!(
            "http://127.0.0.1:{}",
            ready["nestPort"].as_u64().context("nestPort")?
        ),
        token_path,
        calls_path,
        stop_path,
        result_path,
        child,
    };
    anyhow::ensure!(nest.forwarding_attempts()? == 0, "Nest forwarded before use");

    // 6. Exact maximum: the real 40-leaf bundle through Nest into DS.
    nest.arm(&alice, PUBLISH)?;
    let (status, response) = nest.post_raw(&client, PUBLISH, publication_bytes).await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "40-leaf publication through Nest failed {status}: {}",
        String::from_utf8_lossy(&response)
    );
    anyhow::ensure!(nest.forwarding_attempts()? == 1, "publication was not forwarded once");
    let published: Value = serde_json::from_slice(&response)?;
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
        &ds_server.receipt_public_key,
    )?;
    let proof = &verified_receipt.body()["receipt"];
    anyhow::ensure!(
        proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt"
            && proof["requestId"] == request_id.to_string()
            && proof["conversationId"] == conversation_id.to_string()
            && proof["requestDigest"] == STANDARD.encode(verified_publication.request_digest())
            && proof["coordinates"] == bootstrap.coordinates,
        "published receipt does not bind this 40-leaf publication: {proof}"
    );
    println!("Assertion: exact 40-leaf bundle accepted through Nest into DS with a DS-signed published receipt.");

    // 7. Body tiers in the real Nest process. Admitted bodies are forwarded
    //    (count + 1, DS answers them); one byte over is 413 with no attempt.
    let device = alice.device_id;
    for (nsid, size, admitted) in [
        (PUBLISH, PUBLICATION_BODY_LIMIT, true),
        (PUBLISH, PUBLICATION_BODY_LIMIT + 1, false),
        (PREPARE, ORDINARY_BODY_LIMIT, true),
        (PREPARE, ORDINARY_BODY_LIMIT + 1, false),
    ] {
        nest.arm(&alice, nsid)?;
        let before = nest.forwarding_attempts()?;
        let (status, body) = nest
            .post_raw(&client, nsid, routing_envelope(size, device))
            .await?;
        let after = nest.forwarding_attempts()?;
        println!("{nsid} {size} bytes -> {status}, forwarding attempts {before} -> {after}");
        if admitted {
            // Admission is proven by Nest's forwarding attempt; the status is
            // DS's answer to a padded, unsigned envelope and is only recorded.
            anyhow::ensure!(
                after == before + 1,
                "{nsid} at exactly {size} bytes must be forwarded, got {status} ({before} -> {after}): {}",
                String::from_utf8_lossy(&body)
            );
        } else {
            let error: Value = serde_json::from_slice(&body)?;
            anyhow::ensure!(
                after == before
                    && status == reqwest::StatusCode::PAYLOAD_TOO_LARGE
                    && error["error"] == "RequestTooLarge",
                "{nsid} at {size} bytes must be refused by Nest before forwarding, got {status} ({before} -> {after}): {error}"
            );
        }
    }
    println!("Assertion: exactly 16 MiB publish and 10 MiB ordinary forwarded; one byte more refused 413 by Nest before DS.");

    // 8. Clean shutdown; Nest's own count must agree.
    std::fs::write(&nest.stop_path, b"stop\n")?;
    let result = wait_json(&nest.result_path, Duration::from_secs(30)).await?;
    anyhow::ensure!(
        result["status"] == "completed"
            && result["serviceAuthCalls"].as_u64() == Some(nest.forwarding_attempts()? as u64),
        "paired Nest result disagrees: {result}"
    );
    let exit = nest.child.0.take().context("Nest child")?.wait()?;
    anyhow::ensure!(exit.success(), "paired Nest process failed: {exit}");
    println!(
        "Assertion: paired Nest process exited cleanly ({} forwarding attempts); total {:?}.",
        result["serviceAuthCalls"],
        started.elapsed()
    );
    Ok(())
}

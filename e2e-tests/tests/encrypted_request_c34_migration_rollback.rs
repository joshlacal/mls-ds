//! Case C34: Migration and compatible rollback verification.
//!
//! Contract (validation doc line 61):
//! Additive migration from recorded baseline; new histories readable after
//! disabling new creation and booting the retained compatible reader. Old
//! binary cannot be selected when its constraints reject v2 rows.
//!
//! Verified flow:
//! 1. Create a dedicated loopback database `catbird_direct_requests_fault_<16 hex>`.
//! 2. Install the server's whole migration catalog in strict production
//!    version order, as its startup migrator would (the reviewed baseline,
//!    prerequisite and request migrations are checked against their pinned
//!    checksums), and validate the full ledger in public._sqlx_migrations.
//! 3. Route test harness to the dedicated DB and connect authority.
//! 4. Create v2 request histories through the live shipping router:
//!    - Request 1: published, previewed, and accepted by Bob (acceptance history).
//!    - Request 2: published and previewed by Bob, left pending (publication & preview history).
//! 5. Disable new request creation via the production switch (CHAT_DIRECT_REQUESTS_ENABLED=0).
//! 6. Boot the current server as the retained compatible reader:
//!    - Assert new creations fail: prepareDirectRequest, publishDirectRequestKeys,
//!      and publishDirectRequest return 400 CutoverRequired.
//!    - Read back histories through real HTTP RPCs:
//!      * Published outcome receipt (getDirectRequestOutcome) returns signed receipt.
//!      * Preview / pending conversation state (getConversationState) returns incomingPending.
//!      * Pending Welcomes (getPendingWelcomes) returns directRequestWelcomeView.
//!      * Accepted conversation state (getConversationState) returns accepted state.
//!      * Accepted outcome (getDirectRequestOutcome) returns accepted receipt.
//!      * Accepted entries (getEntries) returns introduction message.
//! 7. Build and run pre-change baseline server (revision c9fd0c5f85610de70b5d083bfec2c597cba5b247):
//!    - Assert standard startup migration check REFUSES against the v2 DB with the exact
//!      failure "migration <v> was previously applied but is missing in the resolved
//!      migrations", where <v> is the first installed migration the baseline revision's
//!      `server/migrations` does not ship (20260919000001 before the 2026-10-04 merge).
//!    - Assert SKIP_MIGRATIONS=1 run has no direct request endpoints.
//! 8. Drop dedicated database cleanly.

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
use encrypted_requests::*;

use anyhow::{Context as _, Result};
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
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::BufRead,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

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

fn db_query(url: &str, sql: &str) -> Result<String> {
    let output = Command::new("psql")
        .args([url, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "db_query failed on {url}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

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

/// The pre-change baseline server's revision. Its binary is prebuilt at
/// /tmp/catbird-server-baseline-c34.
const BASELINE_REVISION: &str = "c9fd0c5f85610de70b5d083bfec2c597cba5b247";

/// The first installed migration that the baseline revision does not ship:
/// the version its sqlx migrator names when it refuses the database.
fn first_migration_missing_from_baseline(installed: &[i64]) -> Result<i64> {
    let output = Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "ls-tree",
            "--name-only",
            &format!("{BASELINE_REVISION}:server/migrations"),
        ])
        .output()
        .context("list the baseline revision's migrations")?;
    anyhow::ensure!(
        output.status.success(),
        "git ls-tree {BASELINE_REVISION}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shipped: HashSet<i64> = String::from_utf8(output.stdout)?
        .lines()
        .filter(|name| name.ends_with(".sql"))
        .filter_map(|name| name.split_once('_')?.0.parse().ok())
        .collect();
    installed
        .iter()
        .copied()
        .find(|version| !shipped.contains(version))
        .context("the baseline revision ships every installed migration")
}

struct ReaderServerProcess {
    child: Child,
    base_url: String,
}

impl Drop for ReaderServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_reader_server(
    dedicated_url: &str,
    https: &HttpsDidFixture,
    cursor_key_id: &str,
    receipt_pem: &str,
    service_pem: &str,
    receipt_document: &str,
) -> Result<ReaderServerProcess> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = manifest_dir
        .parent()
        .context("e2e parent")?
        .join("target/debug/encrypted_request_server_fixture");
    anyhow::ensure!(
        binary.exists(),
        "fixture binary missing at {}",
        binary.display()
    );

    let mut command = Command::new(&binary);
    command
        .env("TEST_DATABASE_URL", dedicated_url)
        .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
        .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
        .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
        .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
        .env("CHAT_CUTOVER_ENABLED", "1")
        .env("CHAT_DIRECT_REQUESTS_ENABLED", "0")
        .env("CHAT_CURSOR_KEY_ID", cursor_key_id)
        .env(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        )
        .env(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents",
        )
        .env("CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM", receipt_pem)
        .env("SIGNING_KEY_PEM", service_pem)
        .env(
            "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
            receipt_document,
        )
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = command.spawn().context("spawn reader server fixture")?;
    let stdout = child.stdout.take().context("reader stdout")?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let ready: Value = serde_json::from_str(line.trim()).context("parse reader readiness")?;
    let base_url = ready["baseUrl"]
        .as_str()
        .context("baseUrl in readiness")?
        .to_owned();

    Ok(ReaderServerProcess { child, base_url })
}

#[tokio::test(flavor = "multi_thread")]
async fn c34_migration_and_compatible_rollback() -> Result<()> {
    let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // =========================================================================
    // Step 1: Dedicated loopback DB and pre-request baseline ledger install
    // =========================================================================
    let db_name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    let dedicated_url = format!("postgresql://127.0.0.1:5432/{db_name}");
    println!("C34: Creating dedicated loopback database {db_name}");
    maintenance(&format!("CREATE DATABASE {db_name}"))?;
    let _dedicated_guard = DedicatedDatabase(db_name.clone());

    // 1a. Install the server's whole migration catalog, as its startup
    //     migrator would, with the reviewed pins checked.
    println!("C34: Installing the server migration catalog...");
    let installed = install_server_migration_catalog(&dedicated_url)?;

    // 1b. Verify the full migration ledger in public._sqlx_migrations
    let ledger_rows: Vec<Value> = serde_json::from_str(&db_query(
        &dedicated_url,
        "SELECT coalesce(json_agg(json_build_object('version',version,'description',description,'success',success,'checksum',encode(checksum,'hex')) ORDER BY version),'[]'::json)::text FROM public._sqlx_migrations",
    )?)?;
    assert_eq!(
        ledger_rows.len(),
        installed,
        "ledger must contain exactly the {installed}-migration server catalog"
    );
    for row in &ledger_rows {
        assert_eq!(
            row["success"], true,
            "migration {} failed in ledger",
            row["version"]
        );
    }
    let ledger_versions = ledger_rows
        .iter()
        .map(|row| row["version"].as_i64().context("ledger version"))
        .collect::<Result<Vec<_>>>()?;
    println!("C34: Verified {installed}/{installed} migrations installed successfully in strict order.");

    // 1g. Route test harness to dedicated DB and connect authority
    std::env::set_var("REQUEST_TEST_DATABASE_URL", &dedicated_url);
    route_to_dedicated_database(&dedicated_url)?;
    assert_eq!(request_database_url(), dedicated_url);
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(authority.baseline_migrations, reviewed_baseline().len());
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );
    println!("C34: Connected guarded authority to dedicated database {db_name}");

    // =========================================================================
    // Step 2: Create v2 request histories through the live router
    // =========================================================================
    println!("C34: Creating Request 1 (accepted history)...");
    let mut fixture1 = live_direct_request::publish_request(true).await?;
    let req1_id = fixture1.request_id;
    let req1_convo_id = fixture1.conversation_id;

    // Bob accepts Request 1
    let prior1 = fixture1.welcome_input.bootstrap.coordinates.clone();
    let bob_identity1 = format!("{}#{}", fixture1.bob.did, fixture1.bob.device_id);
    let bob_public1 = fixture1.bob_engine.identity_public_key(&bob_identity1)?;
    let bob_key_id1 = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public1));
    let transition1 = Uuid::new_v4();
    let mut next1 = prior1.clone();
    next1["stateVersion"] = json!(prior1["stateVersion"].as_u64().unwrap() + 1);
    let acceptance1 = signed_mls_request(
        &fixture1.bob_engine,
        &bob_identity1,
        DirectRequestKind::Accept,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody", "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0", "protocolVersion":"2",
            "actorDid":fixture1.bob.did, "actorDeviceId":fixture1.bob.device_id.to_string(), "keyId":bob_key_id1, "authGeneration":1,
            "requestId":req1_id.to_string(), "transitionId":transition1.to_string(), "prior":prior1, "next":next1,
            "invitationProvenance":{"invitationTransitionId":req1_id.to_string(),"invitedByDid":fixture1.alice.did,"invitedByDeviceId":fixture1.alice.device_id.to_string()},
            "idempotencyKey":transition1.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (acc1_status, acc1_bytes) = fixture1
        .bob
        .post(
            &fixture1.client,
            &fixture1.server.base_url,
            "blue.catbird.chat.acceptConversation",
            &json!({"directRequest":acceptance1}),
            true,
        )
        .await?;
    assert_eq!(acc1_status, reqwest::StatusCode::OK);
    let acc1_val: Value = serde_json::from_slice(&acc1_bytes)?;
    let acc1_proof = protocol::verify_received_direct_request_acceptance_proof(
        &serde_json::to_vec(&acc1_val["acceptanceProof"])?,
        &fixture1.server.receipt_public_key,
        &bob_public1,
    )?;
    assert_eq!(
        acc1_proof["receipt"]["body"]["requestId"],
        req1_id.to_string()
    );
    println!("C34: Request 1 accepted and confirmed with proof.");

    // Create Request 2: left in pending state (preview / pending history)
    println!("C34: Creating Request 2 (pending published history)...");
    let mut fixture2 = live_direct_request::publish_request(false).await?;
    let req2_id = fixture2.request_id;
    let req2_convo_id = fixture2.conversation_id;
    let req2_context_hash = fixture2.welcome_input.bootstrap.context_hash;
    println!("C34: Request 2 published and left in pending state.");

    // Craft a well-formed but never-committed publication attempt against a
    // fresh request id. `admit_publication` finds no durable attempt row and
    // returns a candidate; the disabled-producer gate must then refuse it.
    let alice_identity2 = format!("{}#{}", fixture2.alice.did, fixture2.alice.device_id);
    let alice_public2 = fixture2
        .alice_engine
        .as_ref()
        .unwrap()
        .identity_public_key(&alice_identity2)?;
    let alice_key_id2 = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public2));
    let mut pub3_body = fixture2.publication["body"].clone();
    pub3_body["requestId"] = json!(Uuid::new_v4().to_string());
    pub3_body["firstMessageId"] = json!(Uuid::new_v4().to_string());
    pub3_body["conversationId"] = json!(Uuid::new_v4().to_string());
    pub3_body["idempotencyKey"] = json!(Uuid::new_v4().to_string());
    pub3_body["signedAt"] = json!(canonical_now());
    let publication3 = signed_mls_request(
        fixture2.alice_engine.as_ref().unwrap(),
        &alice_identity2,
        DirectRequestKind::Publish,
        pub3_body,
    )?;

    // Retain configuration information needed for reader
    let receipt_document_str = String::from_utf8(fixture2.server.receipt_document.clone())?;
    let cursor_key_id = db_query(
        &dedicated_url,
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )?
    .trim()
    .to_owned();

    // =========================================================================
    // Step 3: Boot current server as retained compatible reader (producers disabled)
    // =========================================================================
    println!("C34: Booting current server as retained compatible reader (CHAT_DIRECT_REQUESTS_ENABLED=0)...");
    let receipt_key = SigningKey::from_bytes((&[41_u8; 32]).into())?;
    let service_key = SigningKey::from_bytes((&[42_u8; 32]).into())?;
    let receipt_pem = receipt_key.to_pkcs8_pem(LineEnding::LF)?;
    let service_pem = service_key.to_pkcs8_pem(LineEnding::LF)?;

    let reader_server = start_reader_server(
        &dedicated_url,
        &fixture2._https,
        &cursor_key_id,
        receipt_pem.as_str(),
        service_pem.as_str(),
        &receipt_document_str,
    )?;
    println!(
        "C34: Retained reader server booted at {}",
        reader_server.base_url
    );

    // 3a. Assert new creations FAIL on reader (CutoverRequired)
    println!("C34: Proving new direct request creation is refused on reader...");
    let req4_prepare = signed_mls_request(
        fixture2.alice_engine.as_ref().unwrap(),
        &alice_identity2,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion":"2",
            "actorDid":fixture2.alice.did,
            "actorDeviceId":fixture2.alice.device_id.to_string(),
            "keyId":alice_key_id2,
            "authGeneration":1,
            "requestId":Uuid::new_v4().to_string(),
            "firstMessageId":Uuid::new_v4().to_string(),
            "conversationId":Uuid::new_v4().to_string(),
            "recipientDid":fixture2.bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1",
            "idempotencyKey":Uuid::new_v4().to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (refused_prep_status, refused_prep_bytes) = fixture2
        .alice
        .post(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":req4_prepare}),
            true,
        )
        .await?;
    assert_eq!(
        refused_prep_status,
        reqwest::StatusCode::BAD_REQUEST,
        "prepareDirectRequest must be refused when producers are disabled"
    );
    let refused_prep_err: Value = serde_json::from_slice(&refused_prep_bytes)?;
    assert_eq!(
        refused_prep_err["error"], "CutoverRequired",
        "prepareDirectRequest refusal must report CutoverRequired"
    );

    // Publishing an uncommitted preparation MUST be refused when producers are disabled
    let (refused_pub_status, refused_pub_bytes) = fixture2
        .alice
        .post(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":publication3}),
            true,
        )
        .await?;
    assert_eq!(
        refused_pub_status,
        reqwest::StatusCode::BAD_REQUEST,
        "publishDirectRequest on uncommitted preparation must be refused when producers are disabled"
    );
    let refused_pub_err: Value = serde_json::from_slice(&refused_pub_bytes)?;
    assert_eq!(
        refused_pub_err["error"], "CutoverRequired",
        "publishDirectRequest refusal must report CutoverRequired"
    );

    // Exact replay of already committed publication MUST succeed (200 OK)
    let (replayed_pub_status, replayed_pub_bytes) = fixture2
        .alice
        .post(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":fixture2.publication}),
            true,
        )
        .await?;
    assert_eq!(
        replayed_pub_status,
        reqwest::StatusCode::OK,
        "exact replay of already-published request must succeed"
    );
    let replayed_val: Value = serde_json::from_slice(&replayed_pub_bytes)?;
    assert_eq!(
        replayed_val["outcome"]["$type"],
        "blue.catbird.chat.defs#signedDirectRequestReceipt"
    );
    println!("C34: New creations verified refused with typed CutoverRequired, exact replay preserved.");

    // 3b. Read histories back through reader (publication, preview, acceptance)
    println!("C34: Reading histories back through retained compatible reader...");

    // Read publication outcome for Request 2
    let (r2_out_status, r2_out_bytes) = fixture2
        .bob
        .get(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), req2_id.to_string())],
        )
        .await?;
    assert_eq!(
        r2_out_status,
        reqwest::StatusCode::OK,
        "getDirectRequestOutcome must succeed on reader"
    );
    let r2_out_val: Value = serde_json::from_slice(&r2_out_bytes)?;
    assert_eq!(
        r2_out_val["outcome"]["$type"],
        "blue.catbird.chat.defs#signedDirectRequestReceipt"
    );

    // Read preview/pending conversation state for Request 2 (incomingPending for Bob)
    let (r2_state_status, r2_state_bytes) = fixture2
        .bob
        .get(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), req2_convo_id.to_string())],
        )
        .await?;
    assert_eq!(r2_state_status, reqwest::StatusCode::OK);
    let r2_state_val: Value = serde_json::from_slice(&r2_state_bytes)?;
    assert_eq!(
        r2_state_val["state"]["directRequest"]["consent"],
        "incomingPending"
    );
    let r2_request = protocol::normalize_read_presentation(
        &serde_json::to_vec(&r2_state_val["state"]["directRequest"])?,
        "directRequestState",
        false,
    )?;
    assert_eq!(r2_request["contextHash"], STANDARD.encode(req2_context_hash));

    // Read preview/pending conversation state for Request 2 (outgoingPending for Alice)
    let (r2_alice_status, r2_alice_bytes) = fixture2
        .alice
        .get(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), req2_convo_id.to_string())],
        )
        .await?;
    assert_eq!(r2_alice_status, reqwest::StatusCode::OK);
    let r2_alice_val: Value = serde_json::from_slice(&r2_alice_bytes)?;
    assert_eq!(
        r2_alice_val["state"]["directRequest"]["consent"],
        "outgoingPending"
    );

    // Read pending Welcomes for Request 2 (two-step: inventory session, then page)
    let (inv_status, inv_bytes) = fixture2
        .bob
        .get(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(inv_status, reqwest::StatusCode::OK);
    let inv_val: Value = serde_json::from_slice(&inv_bytes)?;
    let inventory_session = inv_val["inventorySessionId"]
        .as_str()
        .context("reader inventory session")?
        .to_owned();
    let (welcomes_status, welcomes_bytes) = fixture2
        .bob
        .get(
            &fixture2.client,
            &reader_server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                ("inventorySessionId".into(), inventory_session),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(welcomes_status, reqwest::StatusCode::OK);
    let welcomes_val: Value = serde_json::from_slice(&welcomes_bytes)?;
    let welcome_items = welcomes_val["items"].as_array().context("welcome items")?;
    assert!(
        welcome_items
            .iter()
            .any(|w| w["welcomeId"] == req2_id.to_string()),
        "pending welcomes must contain request 2"
    );

    // Request 1 belongs to a different account run, so it needs a reader bound
    // to that run's HTTPS DID fixture (JWT authority is per-run).
    drop(reader_server);
    let reader1 = start_reader_server(
        &dedicated_url,
        &fixture1._https,
        &cursor_key_id,
        receipt_pem.as_str(),
        service_pem.as_str(),
        &receipt_document_str,
    )?;
    println!(
        "C34: Second retained reader (request 1 authority) booted at {}",
        reader1.base_url
    );

    // Read accepted conversation state for Request 1
    let (r1_state_status, r1_state_bytes) = fixture1
        .bob
        .get(
            &fixture1.client,
            &reader1.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), req1_convo_id.to_string())],
        )
        .await?;
    assert_eq!(r1_state_status, reqwest::StatusCode::OK);
    let r1_state_val: Value = serde_json::from_slice(&r1_state_bytes)?;
    assert_eq!(
        r1_state_val["state"]["directRequest"]["consent"],
        "accepted"
    );

    // Read accepted outcome for Request 1
    let (r1_out_status, r1_out_bytes) = fixture1
        .bob
        .get(
            &fixture1.client,
            &reader1.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), req1_id.to_string())],
        )
        .await?;
    assert_eq!(r1_out_status, reqwest::StatusCode::OK);
    let r1_out_val: Value = serde_json::from_slice(&r1_out_bytes)?;
    assert_eq!(
        r1_out_val["outcome"]["$type"],
        "blue.catbird.chat.defs#signedDirectRequestReceipt"
    );

    // Read entries for Request 1
    let (entries_status, entries_bytes) = fixture1
        .bob
        .get(
            &fixture1.client,
            &reader1.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), req1_convo_id.to_string()),
                ("afterSeq".into(), "0".into()),
            ],
        )
        .await?;
    assert_eq!(entries_status, reqwest::StatusCode::OK);
    let entries_val: Value = serde_json::from_slice(&entries_bytes)?;
    let entry_items = entries_val["entries"].as_array().context("entry items")?;
    assert!(
        !entry_items.is_empty(),
        "accepted conversation must return entries"
    );
    println!("C34: Retained reader successfully read back publication, preview, and acceptance histories.");

    // Stop reader servers
    drop(reader1);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // =========================================================================
    // Step 4: Prove pre-change baseline server refuses selection against v2 DB
    // =========================================================================
    println!("C34: Testing pre-change baseline server binary against v2 DB...");
    let baseline_binary = Path::new("/tmp/catbird-server-baseline-c34");
    anyhow::ensure!(
        baseline_binary.exists(),
        "baseline binary missing at {}",
        baseline_binary.display()
    );

    // 4a. Standard startup: migration check refuses missing migrations
    let output = Command::new(baseline_binary)
        .env("DATABASE_URL", &dedicated_url)
        .output()
        .context("execute baseline binary")?;

    assert!(
        !output.status.success(),
        "pre-change baseline server MUST refuse to start against v2 DB"
    );
    assert_eq!(output.status.code(), Some(1));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined_refusal = format!("{stdout_str}\n{stderr_str}");

    let expected_refusal_phrase = format!(
        "migration {} was previously applied but is missing in the resolved migrations",
        first_migration_missing_from_baseline(&ledger_versions)?
    );
    assert!(
        combined_refusal.contains(&expected_refusal_phrase),
        "refusal output must contain exact migration check failure. Got:\n{combined_refusal}"
    );
    assert!(
        combined_refusal.contains("Failed to run migrations"),
        "refusal output must indicate migration failure. Got:\n{combined_refusal}"
    );
    println!("C34: Captured exact baseline server refusal: {expected_refusal_phrase}");

    // 4b. Forced SKIP_MIGRATIONS=1 run: verify baseline has no direct request routes
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let skip_port = listener.local_addr()?.port();
    drop(listener);

    let mut skip_child = Command::new(baseline_binary)
        .env("DATABASE_URL", &dedicated_url)
        .env("SKIP_MIGRATIONS", "1")
        .env("SERVICE_DID", "did:web:chat.catbird.blue")
        .env("SELF_ENDPOINT", "https://chat.catbird.blue")
        .env("SERVER_HOST", "127.0.0.1")
        .env("SERVER_PORT", skip_port.to_string())
        .env("PORT", skip_port.to_string())
        .env("S3_ACCESS_KEY", "test")
        .env("S3_SECRET_KEY", "test")
        .env("S3_BUCKET", "test")
        .env("S3_ENDPOINT", "http://127.0.0.1:9000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn baseline with SKIP_MIGRATIONS")?;

    // Wait for baseline server readiness (replaces flaky sleep)
    let stdout = skip_child.stdout.take().context("skip_child stdout")?;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let stdout_reader = std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut lines = Vec::new();
        let mut line = String::new();
        let mut signaled = false;
        let mut ready_sender = Some(ready_tx);
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if line.contains("Server listening on") && !signaled {
                signaled = true;
                if let Some(tx) = ready_sender.take() {
                    let _ = tx.send(());
                }
            }
            lines.push(std::mem::take(&mut line));
        }
        lines.join("")
    });

    let _ = tokio::time::timeout(Duration::from_secs(15), ready_rx).await;

    // Probe direct-request route on running baseline: must be 404 / route absence
    let probe_client = reqwest::Client::builder().build()?;
    let probe_url = format!("http://127.0.0.1:{skip_port}/xrpc/blue.catbird.chat.prepareDirectRequest");
    let probe_resp = probe_client.post(&probe_url).send().await
        .context("probe baseline server route")?;
    assert_eq!(
        probe_resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "baseline server must return 404 for direct request routes"
    );
    println!("C34: Confirmed baseline server returns 404 for direct-request route");

    let _ = skip_child.kill();
    let skip_out = skip_child.wait_with_output()?;
    let skip_stdout = stdout_reader.join().unwrap_or_default();
    let skip_combined = format!(
        "{}\n{}",
        skip_stdout,
        String::from_utf8_lossy(&skip_out.stderr)
    );
    assert!(
        skip_combined.contains("SKIP_MIGRATIONS set — skipping migration check"),
        "expected SKIP_MIGRATIONS log marker"
    );

    // Save evidence artifacts: only write to a custom evidence directory when
    // C34_EVIDENCE_DIR is explicitly configured. Default to an isolated run-scoped
    // temp directory so test runs never silently clobber recorded artifact sha256s.
    let evidence_dir = std::env::var("C34_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("c34_run_{}", Uuid::new_v4().simple()))
        });
    std::fs::create_dir_all(&evidence_dir)?;

    let refusal_log_path = evidence_dir.join("c34-baseline-refusal.log");
    std::fs::write(&refusal_log_path, combined_refusal.as_bytes())?;

    let skip_log_path = evidence_dir.join("c34-baseline-skip-migrations.log");
    std::fs::write(&skip_log_path, skip_combined.as_bytes())?;
    println!(
        "C34: Saved baseline refusal logs to {}",
        evidence_dir.display()
    );

    let ended_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    println!("C34 completed successfully at {ended_at} (started {started_at}).");

    Ok(())
}

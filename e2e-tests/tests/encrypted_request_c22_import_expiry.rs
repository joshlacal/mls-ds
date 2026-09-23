//! C22: import expiry versus retention, on the real expiry branches.
//!
//! Import deadlines are at least seven days out, so this binary runs with
//! every clock under one libfaketime control file: the test process (client
//! MLS stores and signatures), the server fixture it spawns, and a dedicated
//! loopback PostgreSQL cluster (`support/faketime_postgres.py --clock-file`)
//! to which the whole harness is routed. The request is published at offset
//! +0; the shared clock then advances past the immutable `import_until`. No
//! protocol row is written by the test.
//!
//! Run (built with `--no-run`, then the test binary directly, because
//! `cargo` is not faked):
//!   printf '+0\n' > $CLOCK
//!   DYLD_INSERT_LIBRARIES=/opt/homebrew/opt/libfaketime/lib/faketime/libfaketime.1.dylib \
//!   DYLD_FORCE_FLAT_NAMESPACE=1 FAKETIME_TIMESTAMP_FILE=$CLOCK FAKETIME_NO_CACHE=1 \
//!   FAKETIME_DONT_FAKE_MONOTONIC=1 <test-binary> --nocapture --test-threads=1
//!
//! The client projection is read through the public facade
//! `MLSOrchestrator::refresh_request_preview` (see `support/live_orchestrator.rs`;
//! app-metadata storage there is the core-test mock, crypto/projection/HTTP
//! are real).

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
    canonical_future, canonical_now, connect_guarded_request_database, request_database_url,
    request_database_snapshot, reviewed_request_migrations, route_to_dedicated_database,
    seed_service_device, signed_mls_request, validate_request_test_database_url, HttpsDidFixture,
    ServiceIdentity, ShippingServerFixture, REQUEST_TEST_DATABASE_URL,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::Command};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

use catbird_mls::{RequestConsent, RequestCrypto, RequestPreview};

/// A private faketime cluster, stopped and deleted on drop.
struct FaketimeCluster {
    dir: PathBuf,
    url: String,
}

fn launcher() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("support/faketime_postgres.py")
}

impl FaketimeCluster {
    fn start(clock_file: &str) -> anyhow::Result<Self> {
        let run = &Uuid::new_v4().simple().to_string()[..12];
        let dir = std::env::temp_dir().join(format!("c22-faketime-{run}"));
        let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let db = format!("catbird_direct_requests_faketime_c22_{run}");
        let out = Command::new("python3")
            .arg(launcher())
            .args(["start", "--dir"])
            .arg(&dir)
            .args(["--port", &port.to_string(), "--db", &db, "--clock-file", clock_file])
            .output()
            .context("launch faketime cluster")?;
        anyhow::ensure!(
            out.status.success(),
            "faketime cluster failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let started: Value = serde_json::from_slice(&out.stdout)?;
        println!("C22 faketime cluster: {started}");
        let url = started["url"].as_str().context("cluster url")?.to_owned();
        Ok(Self { dir, url })
    }

    fn advance_seconds(&self, seconds: i64) -> anyhow::Result<()> {
        let out = Command::new("python3")
            .arg(launcher())
            .args(["advance", "--dir"])
            .arg(&self.dir)
            .args(["--offset", &format!("+{seconds}")])
            .output()?;
        anyhow::ensure!(out.status.success(), "advance failed");
        Ok(())
    }
}

impl Drop for FaketimeCluster {
    fn drop(&mut self) {
        let log = std::fs::read_to_string(self.dir.join("postgres.log")).unwrap_or_default();
        let errors: Vec<&str> = log.lines().filter(|l| l.contains("ERROR")).collect();
        println!("C22 cluster postgres ERROR lines ({}):", errors.len());
        for line in errors.iter().rev().take(20) {
            println!("  {line}");
        }
        let _ = Command::new("python3")
            .arg(launcher())
            .args(["stop", "--dir"])
            .arg(&self.dir)
            .status();
    }
}

fn db_query(sql: &str) -> anyhow::Result<String> {
    let out = Command::new("psql")
        .args(["-X", "-v", "ON_ERROR_STOP=1", "-At", "-d", request_database_url(), "-c", sql])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

/// The protocol clock: the dedicated cluster's (possibly advanced) now.
fn db_now() -> anyhow::Result<String> {
    db_query(
        "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')",
    )
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

/// Real signed acknowledgeWelcome for one device's request Welcome.
async fn acknowledge(
    f: &live_direct_request::PublishedRequestFixture,
    service: &ServiceIdentity,
    engine: &MlsEngine,
    identity: &str,
    signed_at: String,
) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(engine.identity_public_key(identity)?));
    let body = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": service.did,
        "actorDeviceId": service.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": signed_at
    });
    let signed = sign_mutation(engine, identity, SignedMutationKind::WelcomeAcknowledgement, body)?;
    let (status, bytes) = service
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acknowledgeWelcome",
            &json!({"signedRequest": signed}),
            true,
        )
        .await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("acknowledgeWelcome body: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, value))
}

async fn get_json(
    f: &live_direct_request::PublishedRequestFixture,
    service: &ServiceIdentity,
    nsid: &str,
    params: &[(String, String)],
) -> anyhow::Result<Value> {
    let (status, bytes) = service.get(&f.client, &f.server.base_url, nsid, params).await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "{nsid} failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

/// Real inventory read: open a scoped session, then list this device's
/// pending Welcomes in it.
async fn pending_welcomes(
    f: &live_direct_request::PublishedRequestFixture,
    service: &ServiceIdentity,
) -> anyhow::Result<(Value, Vec<Value>)> {
    let versions = [
        ("supportedProtocolVersions".to_owned(), "1".to_owned()),
        ("supportedProtocolVersions".to_owned(), "2".to_owned()),
    ];
    let mut params = vec![("limit".to_owned(), "100".to_owned())];
    params.extend(versions.iter().cloned());
    let conversations = get_json(f, service, "blue.catbird.chat.getConversations", &params).await?;
    let session = conversations["inventorySessionId"]
        .as_str()
        .context("inventorySessionId")?
        .to_owned();
    params.push(("inventorySessionId".to_owned(), session));
    let welcomes = get_json(f, service, "blue.catbird.chat.getPendingWelcomes", &params).await?;
    let items = welcomes["items"]
        .as_array()
        .context("getPendingWelcomes items")?
        .iter()
        .filter(|item| item["welcomeId"] == f.request_id.to_string())
        .cloned()
        .collect();
    Ok((conversations, items))
}

fn conversation_listed(conversations: &Value, conversation_id: Uuid) -> bool {
    conversations.to_string().contains(&conversation_id.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn c22_expired_unimported_device_is_unavailable_while_imported_sibling_and_history_remain(
) -> anyhow::Result<()> {
    let clock_file = std::env::var("FAKETIME_TIMESTAMP_FILE").context(
        "C22 must run with the whole process under libfaketime; see the module docs",
    )?;
    anyhow::ensure!(
        std::env::var("DYLD_INSERT_LIBRARIES").is_ok_and(|lib| lib.contains("libfaketime")),
        "C22 test process is not running under libfaketime"
    );
    let cluster = FaketimeCluster::start(&clock_file)?;
    route_to_dedicated_database(&cluster.url)?;
    assert_eq!(request_database_url(), cluster.url);

    // Two selected recipient devices of Bob, published at real time.
    let (f, sibling) = live_direct_request::publish_request_variant(false, true).await?;
    let sibling = sibling.context("second selected recipient device")?;
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let import_until = chrono::DateTime::parse_from_rfc3339(
        f.publication["body"]["importUntil"]
            .as_str()
            .context("publication importUntil")?,
    )?;
    println!("C22 request {} importUntil {import_until}", f.request_id);

    // Both devices are offered their exact Welcome before expiry.
    let (_, bob_items) = pending_welcomes(&f, &f.bob).await?;
    let (_, sibling_items) = pending_welcomes(&f, &sibling.service).await?;
    assert_eq!(bob_items.len(), 1, "addressed device offered its Welcome");
    assert_eq!(sibling_items.len(), 1, "sibling offered its Welcome before expiry");
    assert_eq!(sibling_items[0]["status"], "pending");
    assert_eq!(sibling_items[0]["recipientDeviceId"], sibling.service.device_id.to_string());

    // Device 1 imports within the deadline, decrypts the preview, and ACKs.
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let preview = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = &preview else {
        anyhow::bail!("imported device preview must be ready: {preview:?}");
    };
    let text = protocol::decode_direct_request_introduction(plaintext)?["text"].clone();
    assert_eq!(text, "Real encrypted first contact");
    let (ack_status, ack) =
        acknowledge(&f, &f.bob, &f.bob_engine, &bob_identity, canonical_now()).await?;
    assert_eq!(ack_status, reqwest::StatusCode::OK, "imported device ACK: {ack}");

    // Advance every clock one hour past the immutable deadline.
    let before = chrono::Utc::now();
    let skew = (import_until.with_timezone(&chrono::Utc) - before).num_seconds() + 3600;
    anyhow::ensure!(skew > 7 * 86_400, "deadline must be at least seven days out, got {skew}s");
    cluster.advance_seconds(skew)?;
    let client_now = chrono::Utc::now();
    let advanced = chrono::DateTime::parse_from_rfc3339(&db_now()?)?;
    assert!(client_now > import_until, "client clock {client_now} must pass {import_until}");
    assert!(advanced > import_until, "cluster clock {advanced} must pass {import_until}");
    println!("C22 all clocks advanced by {skew}s: client {client_now}, database {advanced}");

    // Expired unimported device: no longer offered, and its import claim gets
    // the typed terminal error from the real expiry branch.
    let (_, sibling_items) = pending_welcomes(&f, &sibling.service).await?;
    assert!(sibling_items.is_empty(), "expired Welcome must not be offered: {sibling_items:?}");
    let (status, expired) = acknowledge(
        &f,
        &sibling.service,
        &sibling.engine,
        &sibling.identity,
        canonical_now(),
    )
    .await?;
    assert!(status.is_client_error(), "expired ACK must fail: {status} {expired}");
    assert_eq!(expired["error"], "WelcomeExpired", "typed expiry: {expired}");
    let mut sibling_input = f.welcome_input.clone();
    sibling_input.local_identity = sibling.identity.as_bytes().to_vec();
    sibling_input.local_package_ref = sibling.package_ref.clone();
    let group = STANDARD.decode(
        f.welcome_input.bootstrap.coordinates["groupId"]
            .as_str()
            .context("groupId")?,
    )?;
    // The shared-core projection the app renders for the expired device.
    let receipt_document = f.server.receipt_document.clone();
    let sibling_client = live_orchestrator::live_orchestrator(
        sibling.engine.context(),
        &sibling.service,
        &f.client,
        &f.server.base_url,
        receipt_document.clone(),
    )
    .await?;
    let expired_view = sibling_client
        .refresh_request_preview(&f.conversation_id.to_string())
        .await?;
    println!("C22 expired device view: {expired_view:?}");
    assert_eq!(expired_view.consent, RequestConsent::IncomingPending);
    assert_eq!(expired_view.crypto, RequestCrypto::Unavailable);
    assert_eq!(
        expired_view.preview,
        Some(RequestPreview::Unavailable { code: "ImportExpired".into() })
    );
    assert!(!expired_view.capabilities.can_preview && !expired_view.capabilities.can_send);
    sibling_client.shutdown().await;
    assert!(sibling.engine.epoch(&group).is_err(), "expired device has no group state");
    assert!(
        sibling.engine.decrypt_direct_request(&sibling_input).is_err(),
        "expired unimported device cannot read the introduction"
    );

    // Sibling expiry deletes nothing: the conversation stays listed for the
    // imported device and every request/history row is retained.
    let (bob_conversations, _) = pending_welcomes(&f, &f.bob).await?;
    assert!(
        conversation_listed(&bob_conversations, f.conversation_id),
        "request conversation stays in the imported device's inventory"
    );
    let retained = db_query(&format!(
        "SELECT (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r}')||','||\
                (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{r}')||','||\
                (SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{r}')||','||\
                (SELECT lifecycle FROM chat.conversations WHERE conversation_id='{c}')||','||\
                (SELECT string_agg(status,'+' ORDER BY status) FROM chat.direct_request_welcome_outcomes WHERE request_id='{r}')",
        r = f.request_id,
        c = f.conversation_id
    ))?;
    println!("C22 retained rows publication,attempt,deliveries,lifecycle,outcomes = {retained}");
    assert_eq!(retained, "1,1,2,active,acknowledged+expired");

    // The imported device reopens its retained encrypted store in a fresh
    // native context after expiry and still reads the preview, both natively
    // and through the app-facing projection.
    let bob = f.bob.clone();
    let (client, base_url, conversation) =
        (f.client.clone(), f.server.base_url.clone(), f.conversation_id);
    let (reopened, input, server) = f_bob_reopen(f)?;
    let again = reopened.decrypt_direct_request(&input)?;
    assert_eq!(again, preview, "imported preview survives expiry and store reopen");
    assert!(reopened.epoch(&group).is_ok(), "imported device keeps its group");
    let bob_client = live_orchestrator::live_orchestrator(
        reopened.context(),
        &bob,
        &client,
        &base_url,
        receipt_document,
    )
    .await?;
    let retained_view = bob_client.refresh_request_preview(&conversation.to_string()).await?;
    println!("C22 imported device view after expiry: {retained_view:?}");
    assert_eq!(retained_view.crypto, RequestCrypto::Ready);
    assert_eq!(
        retained_view.preview,
        Some(RequestPreview::Ready {
            invitation: None,
            text: text.as_str().context("text")?.into()
        })
    );
    bob_client.shutdown().await;
    drop(server);
    drop(cluster);
    Ok(())
}

/// Close the imported device's native context and reopen its exact store;
/// the live server stays up.
fn f_bob_reopen(
    f: live_direct_request::PublishedRequestFixture,
) -> anyhow::Result<(MlsEngine, DirectRequestWelcomeInput, ShippingServerFixture)> {
    let input = f.welcome_input.clone();
    let closed = f.bob_engine.close_for_offline()?;
    Ok((closed.reopen()?, input, f.server))
}

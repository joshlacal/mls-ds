//! Labyrinth encrypted history backup end to end: real `MLSOrchestrator`s
//! (catbird-mls, feature `labyrinth`) against a locally started mls-ds that
//! serves the shipping clean-chat router and, behind `LABYRINTH_ENABLED`, the
//! `blue.catbird.labyrinth.*` router, over a fully migrated PostgreSQL
//! database.
//!
//! Real: every MLS operation, every clean-chat and Labyrinth HTTP exchange
//! (scoped service-auth JWTs verified by the server against DID documents it
//! resolves over HTTPS, the core's signed `labyrinthWriteBody` and
//! device-signed read headers verified against the registered chat device
//! keys), the server's PostgreSQL state, and each device's encrypted MLS
//! database (which also holds its Labyrinth state and archive queue). As in
//! the other live-orchestrator tests, chat devices are seeded rather than
//! enrolled, and app-metadata storage is the core-test mock.
//!
//! Flow (mirrors catbird-mls `src/labyrinth/tests.rs`
//! `orchestrator_archives_a_send_and_a_restored_device_imports_it` and
//! `archive_restore_load_and_revoke_over_the_gateway`):
//! 1. Alice's phone (device A) creates a conversation with Bob (mls-ds only
//!    accepts application messages that have an accepted recipient). Bob
//!    and the phone enable backup (each account's mailbox is created on
//!    mls-ds); the phone sends and flushes the archive queue, Bob reads
//!    those messages from history, and the phone creates a recovery code.
//! 2. Alice's tablet (device B) restores with the code and imports the
//!    conversation's history into its own storage.
//! 3. The phone revokes the tablet's Labyrinth device (a new epoch opens).
//!    Sends after the rotation, by the phone and by Bob (who addresses
//!    Alice's new epoch), are archived and readable; the revoked tablet can
//!    no longer open the mailbox.
//!
//! The account mailbox stays on mls-ds: the gateway reports no PDS Space
//! (`labyrinth_space_enabled` is false) and no PDS `mailboxKeys`.
//!
//! Requires `REQUEST_SERVER_FIXTURE_BINARY` (the `encrypted_request_server_fixture`
//! built with `--features test-support`), a loopback PostgreSQL on
//! 127.0.0.1:5432 whose OS-user role can create databases (each run creates
//! and drops its own database), and, behind an HTTP(S) proxy, `NO_PROXY`
//! covering `.request-fixture.catbird.blue` so the server reaches the
//! loopback DID fixture:
//!
//! ```sh
//! cargo build --manifest-path server/Cargo.toml --features test-support \
//!     --bin encrypted_request_server_fixture
//! REQUEST_SERVER_FIXTURE_BINARY=$PWD/target/debug/encrypted_request_server_fixture \
//!     cargo test --manifest-path e2e-tests/Cargo.toml --features labyrinth \
//!     --test labyrinth_live_orchestrator -- --nocapture
//! ```
#![cfg(feature = "labyrinth")]
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "../../../catbird-mls/tests/epoch_secret_test_support.rs"]
mod epoch_secret_test_support;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result};
use catbird_mls::labyrinth::QueueConfig;
use catbird_mls::orchestrator::MLSStorageBackend as _;
use encrypted_requests::{
    install_server_migration_catalog, route_to_dedicated_database, seed_service_device,
    HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use live_orchestrator::{mock_credentials::MockCredentials, LiveOrchestrator};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::Value;
use sha2::Digest as _;
use uuid::Uuid;

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";
const LABYRINTH: &str = "blue.catbird.labyrinth.";

fn psql(url: &str, sql: &str) -> Result<String> {
    let mut child = Command::new("psql")
        .args([
            "-X",
            "-q",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            url,
            "-f",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("launch psql")?;
    child
        .stdin
        .take()
        .context("psql stdin")?
        .write_all(sql.as_bytes())?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

/// A dedicated loopback database, dropped (with any lingering sessions) on
/// drop. The name uses the harness's dedicated-clone pattern so both the
/// harness and the server fixture accept it.
struct DedicatedDatabase {
    name: String,
    url: String,
}

impl DedicatedDatabase {
    fn create() -> Result<Self> {
        let name = format!(
            "catbird_direct_requests_fault_{}",
            &Uuid::new_v4().simple().to_string()[..16]
        );
        psql(MAINTENANCE_URL, &format!("CREATE DATABASE {name};"))?;
        let url = format!("postgresql://127.0.0.1:5432/{name}");
        Ok(Self { name, url })
    }
}

impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        if std::env::var_os("LABYRINTH_E2E_KEEP_DATABASE").is_some() {
            eprintln!("keeping {}", self.name);
            return;
        }
        if let Err(error) = psql(
            MAINTENANCE_URL,
            &format!("DROP DATABASE IF EXISTS {} WITH (FORCE);", self.name),
        ) {
            eprintln!("could not drop {}: {error:#}", self.name);
        }
    }
}

/// The key `owner` registered for its device, as served by the live device
/// directory (`getDeviceKey`).
async fn directory_key(
    reader: &ServiceIdentity,
    client: &reqwest::Client,
    base_url: &str,
    owner: &ServiceIdentity,
    key: &[u8],
) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key));
    let (status, body) = reader
        .get_device_key(client, base_url, &owner.did, owner.device_id, &key_id)
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getDeviceKey {status}");
    let served: Value = serde_json::from_slice(&body)?;
    Ok(base64::engine::general_purpose::STANDARD.decode(
        served["signaturePublicKey"]["$bytes"]
            .as_str()
            .context("signaturePublicKey")?,
    )?)
}

/// One chat device: its own MLS engine (encrypted database) and MLS
/// identity key.
fn chat_device(identity: &ServiceIdentity, label: &str) -> Result<(MlsEngine, Vec<u8>)> {
    let engine = MlsEngine::new(label)?;
    epoch_secret_test_support::install(&engine.context());
    let mls_identity = format!("{}#{}", identity.did, identity.device_id);
    engine.create_key_package(&mls_identity)?;
    let public = engine.identity_public_key(&mls_identity)?;
    Ok((engine, public))
}

/// Seeds a further active chat device of an already seeded account.
/// `seed_service_device` gives every device the account JWT key's
/// thumbprint as its legacy DPoP JKT, which is unique per active device of
/// an account; a standard service-authenticated device has none.
fn seed_additional_device(url: &str, identity: &ServiceIdentity, public: &[u8]) -> Result<()> {
    use base64::Engine as _;
    let key_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(public));
    psql(
        url,
        &format!(
            "BEGIN; \
             INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES('{did}','{device}','labyrinth-fixture','active',NULL,1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp()); \
             INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES('{did}','{device}','{key_id}',decode('{public}','hex'),1,clock_timestamp()); COMMIT;",
            did = identity.did,
            device = identity.device_id,
            public = hex::encode(public),
        ),
    )
    .map(drop)
}

/// Every non-2xx Labyrinth exchange of `orchestrator`, for failure messages.
fn labyrinth_failures(orchestrator: &LiveOrchestrator) -> Vec<(String, u16, String)> {
    orchestrator.api_client().failures(LABYRINTH)
}

fn count(orchestrator: &LiveOrchestrator, nsid: &str) -> usize {
    orchestrator.api_client().responses(nsid).len()
}

/// Flushes `orchestrator`'s archive queue and requires `expected` rows to
/// leave it with nothing quarantined or failed.
async fn flush(orchestrator: &LiveOrchestrator, expected: usize) -> Result<()> {
    let flushed = orchestrator
        .labyrinth_flush_archive()
        .await
        .with_context(|| format!("flush: {:?}", labyrinth_failures(orchestrator)))?;
    let status = orchestrator.labyrinth_archive_status().await?;
    anyhow::ensure!(
        flushed == expected,
        "flushed {flushed} of {expected}; status {status:?}; failures {:?}",
        labyrinth_failures(orchestrator)
    );
    anyhow::ensure!(
        status.pending == 0 && status.quarantined.is_empty(),
        "archive queue not drained: {status:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn labyrinth_backup_restore_import_and_revocation_against_live_mlsds() -> Result<()> {
    // ── server: dedicated database, full catalog, chat + Labyrinth router ──
    let database = DedicatedDatabase::create()?;
    route_to_dedicated_database(&database.url)?;
    let installed = install_server_migration_catalog(&database.url)?;
    println!("installed {installed} migrations into {}", database.name);

    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!(
        "did:web:lab-alice-{run}.request-fixture.catbird.blue"
    ));
    // The tablet: the same account (DID, DID-document key), its own device.
    let mut alice_tablet = alice.clone();
    alice_tablet.device_id = Uuid::new_v4();
    // Bob: the conversation's other member (mls-ds accepts an application
    // message only when it has an accepted recipient) and a second account
    // whose own mailbox the archive addresses.
    let bob = ServiceIdentity::new(format!(
        "did:web:lab-bob-{run}.request-fixture.catbird.blue"
    ));
    let https = HttpsDidFixture::start(
        HttpsDidFixture::reserve_port()?,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;
    // Both accounts publish the Catbird chat declaration (served by the PDS
    // fixture), which admits Bob's group invitation and names this service.
    for identity in [&alice, &bob] {
        let declarations = https.root.join("_policy/catbirdDeclaration");
        std::fs::create_dir_all(&declarations)?;
        std::fs::write(
            declarations.join(identity.did.replace(':', "%3A")),
            serde_json::to_vec(&serde_json::json!({
                "$type": "blue.catbird.chat.declaration",
                "protocolVersion": "1",
                "allowIncoming": "all",
                "deliveryService": "did:web:chat.catbird.blue",
                "createdAt": encrypted_requests::canonical_now()
            }))?,
        )?;
    }
    // The fixture inherits this process's environment; the shipping server
    // gates the Labyrinth router on the same variable.
    std::env::set_var("LABYRINTH_ENABLED", "1");
    let server = ShippingServerFixture::start_with_client_runtime(
        &https,
        "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
    )?;
    let base = server.base_url.clone();
    let client = reqwest::Client::builder().build()?;

    // ── devices ────────────────────────────────────────────────────────────
    let (phone_engine, phone_public) = chat_device(&alice, "lab-alice-phone")?;
    seed_service_device(&alice, &phone_public)?;
    let (tablet_engine, tablet_public) = chat_device(&alice_tablet, "lab-alice-tablet")?;
    seed_additional_device(&database.url, &alice_tablet, &tablet_public)?;
    let (bob_engine, bob_public) = chat_device(&bob, "lab-bob")?;
    seed_service_device(&bob, &bob_public)?;
    let (bob_package, _) =
        bob_engine.create_key_package(&format!("{}#{}", bob.did, bob.device_id))?;
    // Authorized device keys come from the live device directory.
    let alice_keys = vec![
        directory_key(&alice, &client, &base, &alice, &phone_public).await?,
        directory_key(&alice, &client, &base, &alice_tablet, &tablet_public).await?,
    ];
    let bob_keys = vec![directory_key(&alice, &client, &base, &bob, &bob_public).await?];
    let credentials = || {
        let credentials = MockCredentials::new();
        credentials.set_authorized_device_keys(&alice.did, alice_keys.clone());
        credentials.set_authorized_device_keys(&bob.did, bob_keys.clone());
        credentials
    };
    let phone = live_orchestrator::live_orchestrator_with_key_packages(
        phone_engine.context(),
        &alice,
        &client,
        &base,
        credentials(),
        vec![catbird_mls::orchestrator::KeyPackageRef {
            did: bob.did.clone(),
            key_package_data: bob_package,
            hash: None,
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        }],
    )
    .await?;
    let bob_orchestrator = live_orchestrator::live_orchestrator_with_credentials(
        bob_engine.context(),
        &bob,
        &client,
        &base,
        credentials(),
    )
    .await?;
    let tablet_credentials = credentials();
    let tablet = live_orchestrator::live_orchestrator_with_credentials(
        tablet_engine.context(),
        &alice_tablet,
        &client,
        &base,
        tablet_credentials,
    )
    .await?;

    // ── 1. the phone backs up a conversation ───────────────────────────────
    let created = phone
        .create_group("Labyrinth live history", None, None)
        .await
        .context("live create_group")?;
    let cid = created.conversation_id.clone();
    // Bob is invited, accepts, and gets his leaf (the phone's real leaf
    // recovery fulfilment), exactly as in the live send test.
    phone
        .add_members(&cid, std::slice::from_ref(&bob.did))
        .await
        .context("live add_members")?;
    bob_orchestrator.publish_key_package().await?;
    bob_orchestrator
        .accept_conversation(&cid)
        .await
        .context("live accept_conversation")?;
    let fulfilled = phone
        .fulfill_leaf_recovery(&cid)
        .await
        .context("live leaf recovery fulfilment")?;
    // Bob joins the MLS group from the Welcome the fulfilment carried.
    let welcome = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(
            fulfilled["welcomes"][0]["opaqueWelcome"]["$bytes"]
                .as_str()
                .with_context(|| format!("fulfilment Welcome: {fulfilled}"))?,
        )?
    };
    bob_orchestrator
        .join_group(&welcome)
        .await
        .context("bob joins from the Welcome")?;
    let before = phone.send_message(&cid, "before backup").await?;
    anyhow::ensure!(
        count(&phone, "blue.catbird.labyrinth.appendBatch") == 0,
        "a send before enabling must not archive"
    );
    anyhow::ensure!(!phone.labyrinth_is_enabled().await?, "backup is off");

    // Bob's account has its own mailbox, so the archive addresses him too.
    let bob_key = bob_orchestrator.labyrinth_enable().await.with_context(|| {
        format!(
            "bob labyrinth_enable: {:?}",
            labyrinth_failures(&bob_orchestrator)
        )
    })?;
    let phone_key = phone
        .labyrinth_enable()
        .await
        .with_context(|| format!("labyrinth_enable: {:?}", labyrinth_failures(&phone)))?;
    anyhow::ensure!(phone.labyrinth_is_enabled().await?);
    println!("phone enabled backup; Labyrinth device {phone_key} (bob {bob_key})");
    // Hold archiving until the explicit flush.
    phone.labyrinth_set_archive_policy(QueueConfig {
        max_batch: 1000,
        max_delay: std::time::Duration::from_secs(3600),
    });
    let first = phone.send_message(&cid, "remember me").await?;
    let second = phone.send_message(&cid, "and me too").await?;
    anyhow::ensure!(
        count(&phone, "blue.catbird.labyrinth.appendBatch") == 0,
        "the send path itself writes no batch"
    );
    flush(&phone, 2).await?;
    anyhow::ensure!(count(&phone, "blue.catbird.labyrinth.appendBatch") >= 1);
    let page = phone.labyrinth_load_history(&cid, None, None).await?;
    let ids: Vec<&str> = page
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    anyhow::ensure!(
        ids == [first.id.as_str(), second.id.as_str()],
        "phone history {ids:?} (undecryptable {})",
        page.undecryptable
    );
    anyhow::ensure!(
        page.messages
            .iter()
            .all(|m| m.sender.as_deref() == Some(alice.did.as_str())),
        "sender-mode copies carry the author"
    );
    // Bob reads Alice's archived messages from his own mailbox's MEKs.
    let bob_page = bob_orchestrator
        .labyrinth_load_history(&cid, None, None)
        .await
        .with_context(|| format!("bob history: {:?}", labyrinth_failures(&bob_orchestrator)))?;
    let bob_ids: Vec<&str> = bob_page
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    anyhow::ensure!(
        bob_ids == [first.id.as_str(), second.id.as_str()],
        "bob history {bob_ids:?} (undecryptable {})",
        bob_page.undecryptable
    );
    let code = phone
        .labyrinth_create_recovery_code()
        .await
        .with_context(|| format!("recovery code: {:?}", labyrinth_failures(&phone)))?;
    println!("phone archived 2 messages in {cid} and created a recovery code");

    // Server-side: the batches and the account's devices are on mls-ds.
    let stored = psql(
        &database.url,
        &format!(
            "SELECT count(*) FROM labyrinth.batches WHERE conversation_id = '{cid}' AND author_did = '{}';",
            alice.did
        ),
    )?;
    anyhow::ensure!(
        stored.trim().parse::<i64>()? >= 1,
        "batches on mls-ds: {stored}"
    );

    // ── 2. the tablet restores and imports the history ─────────────────────
    anyhow::ensure!(!tablet.labyrinth_is_enabled().await?);
    let tablet_key = tablet
        .labyrinth_restore_with_recovery_code(&code)
        .await
        .with_context(|| format!("restore: {:?}", labyrinth_failures(&tablet)))?;
    anyhow::ensure!(
        tablet_key != phone_key,
        "the tablet is its own Labyrinth device"
    );
    let report = tablet
        .labyrinth_import_history(&cid)
        .await
        .with_context(|| format!("import: {:?}", labyrinth_failures(&tablet)))?;
    anyhow::ensure!(
        report.imported == 2 && report.undecryptable == 0,
        "import report {report:?}"
    );
    for (sent, text) in [(&first, "remember me"), (&second, "and me too")] {
        anyhow::ensure!(tablet.storage().message_exists(&sent.id).await?);
        let stored = tablet.storage().get_messages(&cid, 10, None).await?;
        let message = stored
            .iter()
            .find(|m| m.id == sent.id)
            .context("imported message")?;
        anyhow::ensure!(message.text == text && message.is_own, "{message:?}");
    }
    anyhow::ensure!(
        !tablet.storage().message_exists(&before.id).await?,
        "a message sent before backup was enabled is not in the archive"
    );
    let again = tablet.labyrinth_import_history(&cid).await?;
    anyhow::ensure!(
        (again.imported, again.already_present) == (0, 2),
        "re-import {again:?}"
    );
    println!("tablet restored with the recovery code and imported {report:?}");

    // ── 3. the phone revokes the tablet; a later send still archives ──────
    let epoch = phone
        .labyrinth_revoke_device(&tablet_key)
        .await
        .with_context(|| format!("revoke: {:?}", labyrinth_failures(&phone)))?;
    anyhow::ensure!(epoch >= 1, "revocation opens a new epoch ({epoch})");
    let third = phone.send_message(&cid, "after rotation").await?;
    flush(&phone, 1).await?;
    let page = phone.labyrinth_load_history(&cid, None, None).await?;
    let ids: Vec<&str> = page
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    anyhow::ensure!(
        ids == [first.id.as_str(), second.id.as_str(), third.id.as_str()],
        "phone history after rotation {ids:?} (undecryptable {})",
        page.undecryptable
    );
    // Bob is still addressed after Alice's rotation.
    let bob_page = bob_orchestrator
        .labyrinth_load_history(&cid, None, None)
        .await?;
    let bob_ids: Vec<&str> = bob_page
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    anyhow::ensure!(
        bob_ids == [first.id.as_str(), second.id.as_str(), third.id.as_str()],
        "bob history after rotation {bob_ids:?} (undecryptable {})",
        bob_page.undecryptable
    );
    // Bob, sending after the rotation, addresses Alice's new epoch: the
    // phone (still a member) reads his message from history.
    bob_orchestrator.labyrinth_set_archive_policy(QueueConfig {
        max_batch: 1000,
        max_delay: std::time::Duration::from_secs(3600),
    });
    let from_bob = bob_orchestrator
        .send_message(&cid, "bob after rotation")
        .await
        .context("bob send")?;
    flush(&bob_orchestrator, 1).await?;
    let page = phone.labyrinth_load_history(&cid, None, None).await?;
    let bobs = page
        .messages
        .iter()
        .find(|m| m.message_id == from_bob.id)
        .with_context(|| {
            format!(
                "bob's post-rotation message is not readable by the phone (undecryptable {})",
                page.undecryptable
            )
        })?;
    anyhow::ensure!(bobs.sender.as_deref() == Some(bob.did.as_str()), "{bobs:?}");
    // Server side: the tablet's Labyrinth device is revoked, Alice has two
    // epochs, and both accounts' sender batches are stored.
    let server_view = psql(
        &database.url,
        &format!(
            "SELECT (SELECT revoked_at IS NOT NULL FROM labyrinth.devices \
                      WHERE owner_did = '{alice}' AND device_key = decode('{tablet_key}', 'hex')) \
                 || ',' || (SELECT count(*) FROM labyrinth.epochs WHERE owner_did = '{alice}') \
                 || ',' || (SELECT count(DISTINCT author_did) FROM labyrinth.batches \
                             WHERE conversation_id = '{cid}');",
            alice = alice.did,
        ),
    )?;
    anyhow::ensure!(
        server_view.trim() == "true,2,2",
        "server view (tablet revoked, alice epochs, batch authors): {server_view}"
    );
    // Forward secrecy of the revocation: the post-rotation MEKs (each
    // author's newest batch, the phone's `third` and Bob's message) address
    // Alice at the epoch the revocation opened, whose head the directory
    // serves, and not at epoch 0, which the revoked tablet still holds.
    // Alice also minted a second MEK rather than reusing the epoch-0 one.
    let addressed = psql(
        &database.url,
        &format!(
            "SELECT (SELECT max(epoch_number) FROM labyrinth.epoch_heads WHERE did = '{alice}') \
                 || ',' || (SELECT count(DISTINCT mek_id) FROM labyrinth.batches \
                             WHERE conversation_id = '{cid}' AND author_did = '{alice}') \
                 || ',' || (SELECT count(*) FROM labyrinth.batches b \
                              JOIN labyrinth.meks m USING (conversation_id, author_did, mek_id) \
                              CROSS JOIN LATERAL jsonb_array_elements(m.record->'recipients') r \
                             WHERE b.conversation_id = '{cid}' \
                               AND b.seq IN (SELECT max(seq) FROM labyrinth.batches \
                                              WHERE conversation_id = '{cid}' GROUP BY author_did) \
                               AND r->>'did' = '{alice}' \
                               AND r->'recipientEpochHead'->>'$bytes' = \
                                   (SELECT rtrim(encode(epoch_head, 'base64'), '=') \
                                      FROM labyrinth.epoch_heads \
                                     WHERE did = '{alice}' AND epoch_number = {epoch}));",
            alice = alice.did,
        ),
    )?;
    anyhow::ensure!(
        addressed.trim() == format!("{epoch},2,2"),
        "post-rotation addressing (alice head epoch, alice MEKs, alice entries at the new head): {addressed}"
    );
    // The revoked tablet can no longer open the mailbox, because it is not a
    // member of the new epoch.
    tablet.labyrinth_close();
    let refusal = match tablet.labyrinth_load_history(&cid, None, None).await {
        Ok(page) => anyhow::bail!(
            "a revoked device reopened the mailbox: {} messages",
            page.messages.len()
        ),
        Err(error) => error.to_string(),
    };
    anyhow::ensure!(
        refusal.contains("device is not a member of this epoch"),
        "revoked tablet refused for another reason: {refusal}"
    );
    // The crate also reports a failed member lookup as NotEpochMember, so
    // check the exclusion on the server: the tablet is in epoch 0 only.
    let tablet_epochs = psql(
        &database.url,
        &format!(
            "SELECT string_agg(epoch_number::text, ',' ORDER BY epoch_number) \
               FROM labyrinth.epoch_members \
              WHERE owner_did = '{}' AND device_key = decode('{tablet_key}', 'hex');",
            alice.did
        ),
    )?;
    anyhow::ensure!(
        tablet_epochs.trim() == "0",
        "tablet epoch memberships: {tablet_epochs}"
    );
    println!(
        "phone revoked the tablet (epoch {epoch}); post-rotation sends by the phone and bob address only the new epoch; tablet refused: {refusal}"
    );

    // The only refusals are the crate's own "absent" probes (`get_opt`: the
    // next epoch, or a head before the account has one); best-effort hooks
    // hid nothing else.
    let (probes, unexpected): (Vec<_>, Vec<_>) = labyrinth_failures(&phone)
        .into_iter()
        .chain(labyrinth_failures(&tablet))
        .chain(labyrinth_failures(&bob_orchestrator))
        .partition(|(nsid, status, body)| {
            *status == 404
                && (nsid == "blue.catbird.labyrinth.getEpoch"
                    || nsid == "blue.catbird.labyrinth.getEpochHead")
                && body.contains("\"EpochNotFound\"")
        });
    anyhow::ensure!(
        unexpected.is_empty(),
        "unexpected Labyrinth refusals: {unexpected:?}"
    );
    let exercised: Vec<String> = [
        "createDevice",
        "createEpoch",
        "createEpochMember",
        "publishEpochHead",
        "createVirtualDevice",
        "markDeviceRevoked",
        "createMek",
        "appendBatch",
        "findMeks",
        "listBatches",
    ]
    .iter()
    .map(|name| {
        let nsid = format!("{LABYRINTH}{name}");
        let n: usize = [&phone, &tablet, &bob_orchestrator]
            .iter()
            .map(|o| count(o, &nsid))
            .sum();
        format!("{name}={n}")
    })
    .collect();
    println!(
        "Labyrinth exchanges {}; {} absent-epoch probes (404 EpochNotFound), no other refusal",
        exercised.join(" "),
        probes.len()
    );

    phone.shutdown().await;
    tablet.shutdown().await;
    bob_orchestrator.shutdown().await;
    drop(server);
    drop(https);
    drop(database);
    Ok(())
}

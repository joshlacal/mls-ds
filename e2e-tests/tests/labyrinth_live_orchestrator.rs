//! Labyrinth encrypted history backup end to end over the native ATProto Spaces
//! path: real `CatbirdMlsClient`s (catbird-mls's shipping native client, feature
//! `labyrinth`, whose verified native archive exchanges Space credentials, signs
//! RFC 9421 presentations and verifies `Atproto-Space-Mac`) against a locally
//! started mls-ds (`clean_slate_federation_fixture`: the shipping chat,
//! Labyrinth and Option A Space-host routers over a freshly migrated PostgreSQL
//! database) and a loopback ATProto Spaces PDS (`support/native_spaces.rs`).
//!
//! Real: every MLS operation and HTTP exchange (scoped service-auth JWTs the DS
//! verifies against each account's registered `#atproto` key, PDS OAuth
//! sessions, delegation → Space credential exchanges, credential reads relayed
//! through the home DS, the PDS's service-authenticated `notifyRepoUpdate` to the
//! Space authority), the DS's PostgreSQL state, the PDS's committed Space repos,
//! and each device's encrypted MLS database (which also holds its Labyrinth
//! state and archive queue).
//!
//! Mailboxes are Spaces-only (catbird-mls 06349f0b): an account's personal
//! mailbox Space on its PDS holds its Labyrinth devices and epochs, and the
//! conversation Space (authority: the sequencing mls-ds) holds each member's
//! sender and witness batches and MEKs in that member's own repo. mls-ds keeps
//! only epoch heads (`appendBatch`/`getEpoch` are gone, mls-ds 7b1f093b4), and
//! backup is on from enrollment (D4).
//!
//! Flow (mirrors catbird-mls `src/labyrinth/tests.rs`
//! `spaces_only_enable_archive_flush_restore_and_rearchive_before_leave` and
//! catbird-sim's fresh-device recovery):
//! 1. Alice's phone creates a group with Bob (mls-ds only accepts application
//!    messages that have an accepted recipient), who joins from the Welcome.
//!    The phone sends twice: the sends write nothing to the Space until the
//!    queue flushes, and the flush commits Alice's sealed batches and MEKs to
//!    her repo in the conversation Space, notified to the DS. A fresh Bob device
//!    restores from Bob's recovery code and reads Alice's messages with Bob's
//!    own mailbox keys.
//! 2. Alice's tablet (a fresh device) restores with the phone's recovery code,
//!    is its own Labyrinth device, and imports the conversation's history; a
//!    second import is a no-op.
//! 3. The phone revokes the tablet's Labyrinth device (a new epoch opens).
//!    Post-rotation sends by the phone and by Bob are archived and address only
//!    Alice's new epoch; a fresh Alice device restores all four messages with
//!    the recovery code; the revoked tablet can no longer open the mailbox.
//!
//! Requires `clean_slate_federation_fixture` in mls-ds/target/debug (built with
//! `--features test-support`) and a loopback PostgreSQL instance whose role can
//! create databases. Each run creates and drops its own database. Set
//! `CLEAN_SLATE_PG_ADMIN_URL` for a private instance on another port.
//! The default is `postgresql://127.0.0.1:5432/postgres`.
//!
//! ```sh
//! cargo build --manifest-path server/Cargo.toml --features test-support \
//!     --bin clean_slate_federation_fixture
//! cargo test --manifest-path e2e-tests/Cargo.toml --features labyrinth \
//!     --test labyrinth_live_orchestrator -- --nocapture
//! ```
#![cfg(feature = "labyrinth")]

#[allow(dead_code)]
#[path = "support/native_spaces.rs"]
mod native_spaces;

use std::{collections::BTreeSet, path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use catbird_mls::{
    client::{CatbirdMlsClient, CatbirdMlsClientConfig, REQUIRED_LABYRINTH_OAUTH_SCOPES},
    MLSError,
};
use labyrinth::records::{nsid, Batch, Device, EpochMember, MekDistribution};
use native_spaces::{
    assert_authority_notified, CleanSlateDsProcess, ClientTransport, DidDirectory, MemoryKeyStore,
    SpacesPds,
};
use p256::ecdsa::SigningKey;
use serde_json::Value;
use uuid::Uuid;

const DS_DID: &str = "did:web:ds.labyrinth-e2e.catbird.blue";
const PDS_DID: &str = "did:web:pds.labyrinth-e2e.catbird.blue";
const ALICE: &str = "did:plc:labyrinthaliceaccount234";
const BOB: &str = "did:plc:labyrinthbobaccount23456";
const S2S_SECRET: &[u8] = b"labyrinth-live-orchestrator-s2s-secret!";

/// One device: a native client over its own encrypted database and keychain,
/// signed in to its account's PDS and homed on the DS.
struct DeviceUnderTest {
    label: String,
    client: Arc<CatbirdMlsClient>,
    transport: Arc<ClientTransport>,
}

impl DeviceUnderTest {
    async fn open(
        root: &Path,
        label: &str,
        (did, key, pds_session): (&str, &SigningKey, &str),
        ds: &CleanSlateDsProcess,
        pds: &SpacesPds,
    ) -> Result<Self> {
        let transport = Arc::new(pds.client_transport(&ds.base_url));
        transport.set_account(did, key.clone(), DS_DID, &pds.base_url, pds_session);
        let config = CatbirdMlsClientConfig {
            storage_root: root.join(label).to_string_lossy().into(),
            account_did: did.into(),
            device_id: Uuid::new_v4().to_string(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: ds.base_url.clone(),
            pds_endpoint: pds.base_url.clone(),
        };
        let platform = transport.clone();
        let client = tokio::task::spawn_blocking(move || {
            CatbirdMlsClient::open(config, Arc::new(MemoryKeyStore::new()), platform, None)
        })
        .await??;
        Ok(Self {
            label: label.into(),
            client,
            transport,
        })
    }

    /// Runs one blocking client call, as a platform's background queue does.
    async fn run<T: Send + 'static>(
        &self,
        call: impl FnOnce(&CatbirdMlsClient) -> Result<T, MLSError> + Send + 'static,
    ) -> Result<T> {
        let client = self.client.clone();
        tokio::task::spawn_blocking(move || call(&client))
            .await?
            .with_context(|| {
                let Some(exchange) = self.transport.exchanges().pop() else {
                    return self.label.clone();
                };
                let endpoint = exchange.url.split('?').next().unwrap_or(&exchange.url);
                format!(
                    "{}: {} {endpoint} returned {}",
                    self.label, exchange.method, exchange.status
                )
            })
    }

    async fn send(&self, cid: &str, text: &str) -> Result<String> {
        let (cid, text, id) = (cid.to_owned(), text.to_owned(), Uuid::new_v4().to_string());
        let sent = self.run(move |c| c.send_message(&cid, &id, &text)).await?;
        Ok(sent.message_id)
    }

    async fn flush(&self) -> Result<u32> {
        self.run(|c| c.flush_labyrinth_queue()).await
    }

    async fn queued(&self, cid: &str) -> Result<Vec<String>> {
        let cid = cid.to_owned();
        let queued = self
            .run(move |c| c.list_pending_labyrinth_queue(Some(&cid), 100))
            .await?;
        Ok(queued.into_iter().map(|q| q.message_id).collect())
    }

    /// `(message id, sender, text, is_own)` of every local message, in order.
    async fn history(&self, cid: &str) -> Result<Vec<(String, String, String, bool)>> {
        let cid = cid.to_owned();
        let mut rows = self.run(move |c| c.list_messages(&cid, None, 100)).await?;
        // Conversation order: the sequencer's `seq` (the list API pages newest first).
        rows.sort_by_key(|row| row.seq);
        rows.into_iter()
            .map(|row| {
                let text = serde_json::from_str::<Value>(&row.plaintext_json)?["text"]
                    .as_str()
                    .with_context(|| format!("message frame without text: {}", row.plaintext_json))?
                    .to_owned();
                Ok((row.message_id, row.sender_did, text, row.is_own))
            })
            .collect()
    }

    /// Restores from the account's recovery code, then imports `cid`'s history.
    async fn restore(&self, code: &str, cid: &str) -> Result<u32> {
        let code = code.to_owned();
        self.run(move |c| c.restore_with_recovery_code(&code))
            .await?;
        self.import(cid).await
    }

    async fn import(&self, cid: &str) -> Result<u32> {
        let cid = cid.to_owned();
        self.run(move |c| c.restore_conversation_from_owner_mailbox(&cid))
            .await
    }
}

fn scopes() -> Vec<String> {
    REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect()
}

fn mailbox(did: &str) -> String {
    format!("at:space/{did}/blue.catbird.labyrinth.mailbox/self")
}

fn decode<T: serde::de::DeserializeOwned>(records: Vec<(String, Value)>) -> Result<Vec<T>> {
    records
        .into_iter()
        .map(|(rkey, value)| {
            serde_json::from_value(value).with_context(|| format!("record {rkey}"))
        })
        .collect()
}

/// Physical Labyrinth device keys (hex) in `did`'s personal mailbox Space.
fn mailbox_devices(pds: &SpacesPds, did: &str) -> Result<Vec<Device>> {
    let devices: Vec<Device> = decode(pds.space_records(&mailbox(did), did, nsid::DEVICE))?;
    Ok(devices.into_iter().filter(|d| !d.r#virtual).collect())
}

/// The MEK sealing `message_id` in `writer`'s repo of the conversation Space.
fn mek_for(
    pds: &SpacesPds,
    space: &str,
    writer: &str,
    message_id: &str,
) -> Result<MekDistribution> {
    let batches: Vec<Batch> = decode(pds.space_records(space, writer, nsid::BATCH))?;
    let mek_id = batches
        .iter()
        .flat_map(|batch| &batch.items)
        .find(|item| item.message_id == message_id)
        .map(|item| item.mek_id.0.clone())
        .with_context(|| format!("{writer} archived no batch item for {message_id}"))?;
    decode::<MekDistribution>(pds.space_records(space, writer, nsid::MEK))?
        .into_iter()
        .find(|mek| mek.mek_id.0 == mek_id)
        .with_context(|| format!("{writer} archived no MEK for {message_id}"))
}

async fn epoch_head(ds: &CleanSlateDsProcess, did: &str, epoch: i64) -> Result<Vec<u8>> {
    Ok(ds
        .pool
        .query_one(
            "SELECT epoch_head FROM labyrinth.epoch_heads WHERE did = $1 AND epoch_number = $2",
            &[&did, &epoch],
        )
        .await
        .with_context(|| format!("{did} has no epoch head {epoch} on the DS"))?
        .get(0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn labyrinth_backup_restore_import_and_revocation_against_live_mlsds() -> Result<()> {
    // ── topology: the DS, the PDS both accounts live on, the DID directory ──
    let ds = CleanSlateDsProcess::spawn(DS_DID, S2S_SECRET).await?;
    let http = reqwest::Client::new();
    // The DS reaches its own Space host for credentials and listRepos (relay target).
    ds.register_ds(&http, &ds).await?;
    let directory = DidDirectory::new();
    directory.publish(&ds.service_did, ds.did_document.clone());
    let pds = SpacesPds::start(PDS_DID, true, directory).await;
    let alice_key = SigningKey::random(&mut rand::rngs::OsRng);
    let bob_key = SigningKey::random(&mut rand::rngs::OsRng);
    pds.add_account(ALICE, alice_key.clone(), "alice-phone-oauth");
    pds.add_account(BOB, bob_key.clone(), "bob-phone-oauth");
    for (did, session) in [
        (ALICE, "alice-tablet-oauth"),
        (ALICE, "alice-laptop-oauth"),
        (BOB, "bob-tablet-oauth"),
    ] {
        pds.add_session(did, session);
    }
    for (did, key) in [(ALICE, &alice_key), (BOB, &bob_key)] {
        ds.register_did(&http, did, key.verifying_key(), &pds.base_url)
            .await?;
    }
    let root = tempfile::tempdir()?;
    let alice = |session| (ALICE, &alice_key, session);
    let phone = DeviceUnderTest::open(
        root.path(),
        "alice-phone",
        alice("alice-phone-oauth"),
        &ds,
        &pds,
    )
    .await?;
    let bob = DeviceUnderTest::open(
        root.path(),
        "bob-phone",
        (BOB, &bob_key, "bob-phone-oauth"),
        &ds,
        &pds,
    )
    .await?;

    // ── 1. enrollment turns backup on; the phone backs up a conversation ──
    for (device, did) in [(&phone, ALICE), (&bob, BOB)] {
        let enrolled = device.run(|c| c.enroll_device(&scopes())).await?;
        anyhow::ensure!(
            enrolled.labyrinth_backup_enabled && enrolled.mailbox_space_uri == mailbox(did),
            "{}: enrollment receipt {enrolled:?}",
            device.label
        );
        anyhow::ensure!(device.run(|c| c.labyrinth_status()).await?.backup_enabled);
    }
    let cid = Uuid::new_v4().to_string();
    let created = {
        let cid = cid.clone();
        phone
            .run(move |c| {
                c.create_group(
                    &cid,
                    DS_DID,
                    vec![BOB.into()],
                    Some("Labyrinth live history".into()),
                    None,
                )
            })
            .await?
    };
    let space = created
        .space_uri
        .clone()
        .context("a live group pins its conversation Space")?;
    anyhow::ensure!(
        space == format!("at:space/{DS_DID}/blue.catbird.labyrinth.conversation/{cid}-0"),
        "conversation Space {space}"
    );
    // Bob accepts the invitation, the phone fulfils his leaf recovery, and Bob
    // joins from the Welcome.
    bob.run(|c| c.sync()).await?;
    phone.run(|c| c.sync()).await?;
    bob.run(|c| c.sync()).await?;
    for device in [&phone, &bob] {
        let cid = cid.clone();
        let members: BTreeSet<String> = device
            .run(move |c| c.list_members(&cid))
            .await?
            .into_iter()
            .collect();
        anyhow::ensure!(
            members == BTreeSet::from([ALICE.to_owned(), BOB.to_owned()]),
            "{} group members {members:?}",
            device.label
        );
    }

    // Bob's account has its own mailbox (his archive session opens with his
    // recovery code), so the phone's archive addresses him too.
    let bob_code = bob.run(|c| c.setup_recovery_code()).await?;
    let first = phone.send(&cid, "remember me").await?;
    let second = phone.send(&cid, "and me too").await?;
    // The send path itself writes nothing to the Space: the queue holds both
    // until the flush.
    anyhow::ensure!(phone.queued(&cid).await? == [first.clone(), second.clone()]);
    anyhow::ensure!(
        pds.space_records(&space, ALICE, nsid::BATCH).is_empty(),
        "a send wrote to the conversation Space before the flush"
    );
    anyhow::ensure!(
        phone.flush().await? == 2,
        "the phone's flush must archive both sends"
    );
    anyhow::ensure!(
        phone.queued(&cid).await?.is_empty(),
        "the archive queue drained"
    );
    // Space record writes: Alice's sealed sender copies and their MEK, in her
    // own repo of the conversation Space, committed after the DS accepted the
    // PDS's notifyRepoUpdate for exactly that commit.
    let archived: BTreeSet<String> =
        decode::<Batch>(pds.space_records(&space, ALICE, nsid::BATCH))?
            .into_iter()
            .flat_map(|batch| batch.items)
            .map(|item| item.message_id)
            .collect();
    anyhow::ensure!(
        archived == BTreeSet::from([first.clone(), second.clone()]),
        "alice's archived batch items {archived:?}"
    );
    let mek = mek_for(&pds, &space, ALICE, &first)?;
    let addressed: BTreeSet<&str> = mek.recipients.iter().map(|r| r.did.as_str()).collect();
    anyhow::ensure!(
        addressed == BTreeSet::from([ALICE, BOB]),
        "sender-mode MEK addresses {addressed:?}"
    );
    assert_authority_notified(&ds, &pds, &space, ALICE).await?;
    // Alice's personal mailbox Space: the phone's Labyrinth device and epoch 0,
    // whose head the DS serves.
    let phone_devices = mailbox_devices(&pds, ALICE)?;
    anyhow::ensure!(
        phone_devices.len() == 1,
        "alice's mailbox devices {}",
        phone_devices.len()
    );
    let epoch0 = phone.run(|c| c.labyrinth_status()).await?.epoch_seq;
    let head0 = epoch_head(&ds, ALICE, epoch0 as i64).await?;
    anyhow::ensure!(mek
        .recipients
        .iter()
        .any(|r| r.did == ALICE && r.recipient_epoch_head.0 == head0));

    // Bob receives both messages live and archives his witness copies.
    bob.run(|c| c.sync()).await?;
    let received = bob.history(&cid).await?;
    for (id, text) in [(&first, "remember me"), (&second, "and me too")] {
        anyhow::ensure!(
            received
                .iter()
                .any(|m| &m.0 == id && m.1 == ALICE && m.2 == text && !m.3),
            "bob did not receive {text:?}: {received:?}"
        );
    }
    let bob_witnessed = bob.flush().await?;
    println!("phone archived 2 sends; bob archived {bob_witnessed} witness copies");
    if bob_witnessed > 0 {
        assert_authority_notified(&ds, &pds, &space, BOB).await?;
    }
    let alice_code = phone.run(|c| c.setup_recovery_code()).await?;

    // A fresh Bob device reads Alice's archived messages with Bob's own mailbox keys.
    let bob_tablet = DeviceUnderTest::open(
        root.path(),
        "bob-tablet",
        (BOB, &bob_key, "bob-tablet-oauth"),
        &ds,
        &pds,
    )
    .await?;
    let restored = bob_tablet.restore(&bob_code, &cid).await?;
    let bob_restored = bob_tablet.history(&cid).await?;
    anyhow::ensure!(
        restored == 2
            && bob_restored
                == [
                    (
                        first.clone(),
                        ALICE.to_owned(),
                        "remember me".to_owned(),
                        false
                    ),
                    (
                        second.clone(),
                        ALICE.to_owned(),
                        "and me too".to_owned(),
                        false
                    ),
                ],
        "bob's fresh device restored {restored}: {bob_restored:?}"
    );
    println!("phone archived 2 messages in {cid}; bob's fresh device read them back");

    // ── 2. the tablet restores and imports the history ─────────────────────
    let tablet = DeviceUnderTest::open(
        root.path(),
        "alice-tablet",
        alice("alice-tablet-oauth"),
        &ds,
        &pds,
    )
    .await?;
    let imported = tablet.restore(&alice_code, &cid).await?;
    let tablet_history = tablet.history(&cid).await?;
    anyhow::ensure!(
        imported == 2
            && tablet_history
                == [
                    (
                        first.clone(),
                        ALICE.to_owned(),
                        "remember me".to_owned(),
                        true
                    ),
                    (
                        second.clone(),
                        ALICE.to_owned(),
                        "and me too".to_owned(),
                        true
                    ),
                ],
        "tablet imported {imported}: {tablet_history:?}"
    );
    anyhow::ensure!(
        tablet.import(&cid).await? == 0,
        "a second import is a no-op"
    );
    // The tablet is its own Labyrinth device in Alice's mailbox.
    let tablet_device: Vec<Device> = mailbox_devices(&pds, ALICE)?
        .into_iter()
        .filter(|d| {
            !phone_devices
                .iter()
                .any(|p| p.device_key_pubkey == d.device_key_pubkey)
        })
        .collect();
    let [tablet_device] = &tablet_device[..] else {
        anyhow::bail!(
            "the tablet enrolled {} Labyrinth devices",
            tablet_device.len()
        );
    };
    let tablet_key = hex::encode(&tablet_device.device_key_pubkey.0);
    println!("tablet restored with the recovery code and imported {imported} messages");

    // ── 3. the phone revokes the tablet; later sends address the new epoch ──
    let rotated = {
        let tablet_key = tablet_key.clone();
        phone
            .run(move |c| c.revoke_labyrinth_device(&tablet_key))
            .await?
    };
    anyhow::ensure!(
        rotated.status.epoch_seq > epoch0,
        "revocation opens a new epoch ({rotated:?})"
    );
    let head1 = epoch_head(&ds, ALICE, rotated.status.epoch_seq as i64).await?;
    anyhow::ensure!(head1 != head0);
    let revoked = mailbox_devices(&pds, ALICE)?
        .into_iter()
        .find(|d| d.device_key_pubkey == tablet_device.device_key_pubkey)
        .context("the tablet's device record")?;
    anyhow::ensure!(
        revoked.revoked_at.is_some(),
        "the tablet's device is not marked revoked"
    );
    let memberships: BTreeSet<u64> =
        decode::<EpochMember>(pds.space_records(&mailbox(ALICE), ALICE, nsid::EPOCH_MEMBER))?
            .into_iter()
            .filter(|m| m.device_key_pubkey == tablet_device.device_key_pubkey)
            .map(|m| m.epoch_number)
            .collect();
    // The tablet's restore opened the epoch it joined; the revocation's epoch excludes it.
    anyhow::ensure!(
        !memberships.is_empty()
            && memberships
                .iter()
                .all(|epoch| *epoch < rotated.status.epoch_seq),
        "tablet epoch memberships {memberships:?} (revocation epoch {})",
        rotated.status.epoch_seq
    );

    let third = phone.send(&cid, "after rotation").await?;
    anyhow::ensure!(phone.flush().await? == 1);
    bob.run(|c| c.sync()).await?;
    let from_bob = bob.send(&cid, "bob after rotation").await?;
    let bob_flushed = bob.flush().await?;
    anyhow::ensure!(
        bob_flushed >= 1,
        "bob's flush must archive his post-rotation send"
    );
    phone.run(|c| c.sync()).await?;
    // Forward secrecy of the revocation: the MEKs sealing the post-rotation
    // messages (the phone's and Bob's) address Alice at the head the rotation
    // opened, which the revoked tablet cannot open, never at epoch 0.
    for (writer, id) in [(ALICE, &third), (BOB, &from_bob)] {
        let mek = mek_for(&pds, &space, writer, id)?;
        let alice_heads: Vec<&[u8]> = mek
            .recipients
            .iter()
            .filter(|r| r.did == ALICE)
            .map(|r| r.recipient_epoch_head.0.as_slice())
            .collect();
        anyhow::ensure!(
            alice_heads == [head1.as_slice()],
            "{writer}'s post-rotation MEK addresses alice at {} heads, not only the new one",
            alice_heads.len()
        );
        assert_authority_notified(&ds, &pds, &space, writer).await?;
    }
    // A fresh Alice device restores every message with the recovery code, Bob's
    // post-rotation message included.
    let laptop = DeviceUnderTest::open(
        root.path(),
        "alice-laptop",
        alice("alice-laptop-oauth"),
        &ds,
        &pds,
    )
    .await?;
    let restored = laptop.restore(&alice_code, &cid).await?;
    let laptop_history = laptop.history(&cid).await?;
    let expected = vec![
        (
            first.clone(),
            ALICE.to_owned(),
            "remember me".to_owned(),
            true,
        ),
        (
            second.clone(),
            ALICE.to_owned(),
            "and me too".to_owned(),
            true,
        ),
        (
            third.clone(),
            ALICE.to_owned(),
            "after rotation".to_owned(),
            true,
        ),
        (
            from_bob.clone(),
            BOB.to_owned(),
            "bob after rotation".to_owned(),
            false,
        ),
    ];
    anyhow::ensure!(
        restored == 4 && laptop_history == expected,
        "fresh alice device restored {restored}: {laptop_history:?}"
    );
    // Bob stays addressed after Alice's rotation: his fresh device imports both
    // post-rotation messages.
    let bob_more = bob_tablet.import(&cid).await?;
    anyhow::ensure!(
        bob_more == 2,
        "bob's fresh device imported {bob_more} post-rotation messages"
    );
    // The revoked tablet can no longer open the mailbox.
    let refusal = match tablet.import(&cid).await {
        Ok(n) => anyhow::bail!("the revoked tablet reopened the mailbox and imported {n}"),
        Err(error) => format!("{error:#}"),
    };
    anyhow::ensure!(
        refusal.contains("device is not a member of this epoch"),
        "revoked tablet refused for another reason: {refusal}"
    );
    println!(
        "phone revoked the tablet (epoch {}); post-rotation sends address only the new epoch; tablet refused: {refusal}",
        rotated.status.epoch_seq
    );

    // The only refusals are absence probes: records not written yet (the next
    // epoch, an unpublished mailboxKeys) and the Spaces eligibility probe, a
    // parameterless getSpace; nothing was refused or failed for another reason.
    let probe = |e: &native_spaces::Exchange| {
        (e.status == 404 && e.error.as_deref() == Some("RecordNotFound"))
            || (e.status == 400
                && e.error.as_deref() == Some("InvalidRequest")
                && e.url.ends_with("/xrpc/com.atproto.space.getSpace"))
    };
    let (probes, unexpected): (Vec<_>, Vec<_>) = [&phone, &bob, &bob_tablet, &tablet, &laptop]
        .iter()
        .flat_map(|device| {
            device
                .transport
                .exchanges()
                .into_iter()
                .filter(|e| !(200..300).contains(&e.status))
                .map(|e| (device.label.clone(), e))
                .collect::<Vec<_>>()
        })
        .partition(|(_, e)| probe(e));
    anyhow::ensure!(unexpected.is_empty(), "unexpected refusals: {unexpected:?}");
    println!("{} absence probes, no other refusal", probes.len());
    for device in [&phone, &bob, &bob_tablet, &tablet, &laptop] {
        anyhow::ensure!(
            device
                .transport
                .blocked_attempts
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0,
            "{} contacted a host outside its DS and PDS",
            device.label
        );
    }
    Ok(())
}

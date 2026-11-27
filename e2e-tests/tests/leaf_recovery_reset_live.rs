//! R4 leaf recovery and admin reset end to end: real `CatbirdMlsClient`s
//! (catbird-mls's shipping native client) against one locally started mls-ds
//! (`clean_slate_federation_fixture`: the shipping chat routers over a freshly
//! migrated PostgreSQL database) and a loopback ATProto Spaces PDS
//! (`support/native_spaces.rs`), set up as `labyrinth_live_orchestrator` is.
//!
//! 1. A new device of an existing member (same account and key, new device ID,
//!    own sign-in) signs its own `requestLeafRecovery`; the pending view the
//!    admin's leaf reads carries exactly that signed request; the admin
//!    fulfills it once, the device joins and messages flow to and from it.
//! 2. Only an admin resets: a member's `reset_conversation` is refused with no
//!    effect. The admin's reset retires the member, who signs an add request
//!    bound to the successor; the admin fulfills it from her verified roster,
//!    the member rejoins his existing row, messages flow in the successor
//!    generation, and a send into the retired generation is refused.
//!
//! Requires `clean_slate_federation_fixture` in mls-ds/target/debug (built with
//! `--features test-support`) and a loopback PostgreSQL on 127.0.0.1:5432 whose
//! OS-user role can create databases (each test creates and drops its own).
//! One test per process:
//!
//! ```sh
//! cargo build --manifest-path server/Cargo.toml --features test-support \
//!     --bin clean_slate_federation_fixture
//! cargo test --manifest-path e2e-tests/Cargo.toml --features labyrinth \
//!     --test leaf_recovery_reset_live -- --exact <test> --test-threads=1 --nocapture
//! ```
#![cfg(feature = "labyrinth")]

#[allow(dead_code)]
#[path = "support/native_spaces.rs"]
mod native_spaces;

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result};
use catbird_mls::{
    client::{
        chat_wire, CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest,
        PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
    },
    storage::ConversationRow,
    MLSError,
};
use native_spaces::{
    CleanSlateDsProcess, ClientTransport, DidDirectory, MemoryKeyStore, SpacesPds,
};
use openmls_basic_credential::SignatureKeyPair;
use p256::ecdsa::SigningKey;
use serde_json::Value;
use uuid::Uuid;

const DS_DID: &str = "did:web:ds.recovery-e2e.catbird.blue";
const PDS_DID: &str = "did:web:pds.recovery-e2e.catbird.blue";
const ALICE: &str = "did:plc:recoveryaliceaccount2345";
const BOB: &str = "did:plc:recoverybobaccount234567";
const S2S_SECRET: &[u8] = b"leaf-recovery-reset-live-s2s-secret!";
const LEAF_RECOVERY_REQUEST_PATH: &str = "/xrpc/blue.catbird.chat.requestLeafRecovery";

/// The DS's durable record of one conversation that only a transition, a
/// request or an entry changes: head, entry cursor, transitions by kind, reset
/// requests, and every leaf-recovery request (oldest first).
const LEDGER: &str = "\
SELECT json_build_object(
    'generation', c.current_generation,
    'stateVersion', c.current_state_version,
    'nextEntrySeq', c.next_entry_seq,
    'transitions', (SELECT COALESCE(json_object_agg(t.kind, t.n), '{}'::json)
                      FROM (SELECT kind, count(*) AS n FROM chat.transitions
                             WHERE conversation_id = c.conversation_id GROUP BY kind) t),
    'resetRequests', (SELECT count(*) FROM chat.reset_requests r
                       WHERE r.conversation_id = c.conversation_id),
    'recoveries', (SELECT COALESCE(json_agg(json_build_object(
                          'id', q.recovery_request_id, 'did', q.requester_did,
                          'device', q.requester_device_id, 'kind', q.recovery_kind,
                          'source', q.source, 'status', q.status, 'generation', q.generation)
                        ORDER BY q.requested_at, q.recovery_request_id), '[]'::json)
                     FROM chat.leaf_recovery_requests q
                    WHERE q.conversation_id = c.conversation_id)
)::text
  FROM chat.conversations c
 WHERE c.conversation_id = $1";

/// A device's platform transport: [`ClientTransport`] (D1 firewall, service
/// auth, PDS session) that keeps every `requestLeafRecovery` body the DS
/// accepted from this device, i.e. exactly what the device signed.
struct Recorder {
    inner: ClientTransport,
    recovery_requests: Mutex<Vec<Value>>,
}

impl Recorder {
    fn recovery_requests(&self) -> Vec<Value> {
        self.recovery_requests.lock().unwrap().clone()
    }
}

impl PlatformTransport for Recorder {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let recovery = request
            .url
            .ends_with(LEAF_RECOVERY_REQUEST_PATH)
            .then(|| request.body.clone())
            .flatten();
        let response = self.inner.execute_http(request)?;
        if let Some(body) = recovery.filter(|_| (200..300).contains(&response.status)) {
            let body =
                serde_json::from_slice(&body).map_err(|e| MLSError::Internal(e.to_string()))?;
            self.recovery_requests.lock().unwrap().push(body);
        }
        Ok(response)
    }

    fn connect_realtime_stream(
        &self,
        endpoint: String,
        cursor: Option<i64>,
    ) -> Result<(), MLSError> {
        self.inner.connect_realtime_stream(endpoint, cursor)
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        self.inner.disconnect_realtime_stream()
    }
}

/// The DS, the PDS both accounts live on, and the devices' storage.
struct Net {
    ds: CleanSlateDsProcess,
    pds: SpacesPds,
    root: tempfile::TempDir,
    keys: Vec<(&'static str, SigningKey)>,
}

impl Net {
    async fn start() -> Result<Self> {
        let ds = CleanSlateDsProcess::spawn(DS_DID, S2S_SECRET).await?;
        let http = reqwest::Client::new();
        // The DS reaches its own Space host for credentials and listRepos (relay target).
        ds.register_ds(&http, &ds).await?;
        let directory = DidDirectory::new();
        directory.publish(&ds.service_did, ds.did_document.clone());
        let pds = SpacesPds::start(PDS_DID, true, directory).await;
        let mut keys = Vec::new();
        for did in [ALICE, BOB] {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            pds.add_account(did, key.clone(), &format!("{did}-oauth"));
            ds.register_did(&http, did, key.verifying_key(), &pds.base_url)
                .await?;
            keys.push((did, key));
        }
        Ok(Self {
            ds,
            pds,
            root: tempfile::tempdir()?,
            keys,
        })
    }

    /// Opens and enrolls a fresh device of `did`: new UUIDv4 device ID, own
    /// encrypted database and keychain, own PDS sign-in, the account's key.
    async fn device(&self, label: &str, did: &str) -> Result<DeviceUnderTest> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(account, _)| *account == did)
            .context("unknown account")?;
        let session = format!("{label}-oauth");
        self.pds.add_session(did, &session);
        let inner = self.pds.client_transport(&self.ds.base_url);
        inner.set_account(did, key.clone(), DS_DID, &self.pds.base_url, &session);
        let transport = Arc::new(Recorder {
            inner,
            recovery_requests: Mutex::default(),
        });
        let keys = Arc::new(MemoryKeyStore::new());
        let device_id = Uuid::new_v4().to_string();
        let config = CatbirdMlsClientConfig {
            storage_root: self.root.path().join(label).to_string_lossy().into(),
            account_did: did.into(),
            device_id: device_id.clone(),
            home_ds_did: DS_DID.into(),
            home_ds_endpoint: self.ds.base_url.clone(),
            pds_endpoint: self.pds.base_url.clone(),
        };
        let (keystore, platform) = (keys.clone(), transport.clone());
        let client = tokio::task::spawn_blocking(move || {
            CatbirdMlsClient::open(config, keystore, platform, None)
        })
        .await??;
        let device = DeviceUnderTest {
            label: label.into(),
            device_id,
            ds_url: self.ds.base_url.clone(),
            client,
            keys,
            transport,
        };
        let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect();
        device.run(move |c| c.enroll_device(&scopes)).await?;
        Ok(device)
    }

    async fn ledger(&self, cid: &str) -> Result<Value> {
        let row = self
            .ds
            .pool
            .query_one(LEDGER, &[&Uuid::parse_str(cid)?])
            .await
            .context("DS ledger")?;
        Ok(serde_json::from_str(&row.get::<_, String>(0))?)
    }

    async fn recoveries(&self, cid: &str) -> Result<Vec<Value>> {
        let ledger = self.ledger(cid).await?;
        Ok(ledger["recoveries"]
            .as_array()
            .context("recoveries")?
            .clone())
    }

    async fn recovery_status(&self, cid: &str, recovery_request_id: &str) -> Result<String> {
        let recoveries = self.recoveries(cid).await?;
        let request = recoveries
            .iter()
            .find(|r| r["id"] == recovery_request_id)
            .with_context(|| format!("the DS holds no recovery request {recovery_request_id}"))?;
        Ok(request["status"].as_str().unwrap_or_default().to_owned())
    }

    /// The generation the DS sequenced application message `id` in, if it did.
    async fn sequenced_generation(&self, cid: &str, id: &str) -> Result<Option<i64>> {
        let row = self
            .ds
            .pool
            .query_opt(
                "SELECT generation FROM chat.entries \
                  WHERE conversation_id = $1 AND message_id = $2 \
                    AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'",
                &[&Uuid::parse_str(cid)?, &Uuid::parse_str(id)?],
            )
            .await?;
        Ok(row.and_then(|row| row.get::<_, Option<i64>>(0)))
    }
}

/// One device: a native client over its own encrypted database and keychain,
/// signed in to its account's PDS and homed on the DS.
struct DeviceUnderTest {
    label: String,
    device_id: String,
    ds_url: String,
    client: Arc<CatbirdMlsClient>,
    keys: Arc<MemoryKeyStore>,
    transport: Arc<Recorder>,
}

impl DeviceUnderTest {
    /// Runs one blocking client call, as a platform's background queue does.
    async fn run<T: Send + 'static>(
        &self,
        call: impl FnOnce(&CatbirdMlsClient) -> Result<T, MLSError> + Send + 'static,
    ) -> Result<T> {
        let client = self.client.clone();
        tokio::task::spawn_blocking(move || call(&client))
            .await?
            .with_context(|| self.label.clone())
    }

    async fn sync(&self) -> Result<u32> {
        self.run(|c| c.sync()).await
    }

    /// Syncs until `done` holds: at most 40 passes, 250 ms apart. A sync that
    /// fails (including one conversation's `SyncIncomplete`) fails the test.
    async fn sync_until(
        &self,
        what: &str,
        mut done: impl AsyncFnMut() -> Result<bool>,
    ) -> Result<()> {
        for _ in 0..40 {
            self.sync()
                .await
                .with_context(|| format!("syncing until it {what}"))?;
            if done().await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::bail!("{} never {what} (40 syncs)", self.label)
    }

    /// `(account DID, device ID)`: this device's leaf identity.
    fn leaf(&self) -> (String, String) {
        (self.client.account_did().to_owned(), self.device_id.clone())
    }

    async fn members(&self, cid: &str) -> Result<BTreeSet<String>> {
        let cid = cid.to_owned();
        Ok(self
            .run(move |c| c.list_members(&cid))
            .await?
            .into_iter()
            .collect())
    }

    async fn row(&self, cid: &str) -> Result<ConversationRow> {
        let rows = self.run(|c| c.list_conversations(None, 100)).await?;
        rows.into_iter()
            .find(|row| row.conversation_id == cid)
            .with_context(|| format!("{} has no row for {cid}", self.label))
    }

    /// This device's verified roster of `cid` (`{did: {role, status}}`), if any.
    async fn roster(&self, cid: &str) -> Result<Option<Value>> {
        let key = chat_wire::conversation_roster_key(cid);
        let raw = self
            .run(move |c| c.db().read_tx(|tx| tx.get_account_meta(&key)))
            .await?;
        Ok(raw.map(|raw| serde_json::from_str(&raw)).transpose()?)
    }

    async fn reset(&self, cid: &str) -> Result<()> {
        let cid = cid.to_owned();
        self.run(move |c| c.reset_conversation(&cid).map(drop))
            .await
    }

    async fn send(&self, cid: &str, text: &str) -> Result<String> {
        let (cid, text, id) = (cid.to_owned(), text.to_owned(), Uuid::new_v4().to_string());
        let sent = self.run(move |c| c.send_message(&cid, &id, &text)).await?;
        Ok(sent.message_id)
    }

    /// `(message id, sender DID, sender device, text)` of every local message,
    /// in conversation order (the list API pages newest first). A row without
    /// a text frame (e.g. an undecryptable gap) reads as its raw JSON.
    async fn history(&self, cid: &str) -> Result<Vec<(String, String, String, String)>> {
        let cid = cid.to_owned();
        let mut rows = self.run(move |c| c.list_messages(&cid, None, 100)).await?;
        rows.sort_by_key(|row| row.seq);
        Ok(rows
            .into_iter()
            .map(|row| {
                let text = serde_json::from_str::<Value>(&row.plaintext_json)
                    .ok()
                    .and_then(|frame| frame["text"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| row.plaintext_json.clone());
                (row.message_id, row.sender_did, row.sender_device_id, text)
            })
            .collect())
    }

    /// Whether this device decrypted `id`, sent by `sender`'s device, reading `text`.
    async fn has(&self, cid: &str, id: &str, sender: &DeviceUnderTest, text: &str) -> Result<bool> {
        let (did, device) = sender.leaf();
        let want = (id.to_owned(), did, device, text.to_owned());
        Ok(self.history(cid).await?.contains(&want))
    }

    /// `getConversationState` as this device reads it: a signed read (`M-F07`).
    async fn conversation_state(&self, cid: &str) -> Result<Value> {
        let raw = PlatformKeyStore::load_signature_keypair(
            &*self.keys,
            format!("mls-signer:{}", self.client.account_did_hash()),
        )?
        .context("enrolled signer")?;
        let signer: SignatureKeyPair = serde_json::from_slice(&raw)?;
        let nsid = "blue.catbird.chat.getConversationState";
        let query = chat_wire::canonical_query_string(&[
            ("actorDeviceId", self.device_id.as_str()),
            ("conversationId", cid),
        ]);
        let headers = chat_wire::build_chat_read_headers(
            nsid,
            &query,
            self.client.account_did(),
            &self.device_id,
            &signer,
            chrono::Utc::now().timestamp_millis(),
        )?;
        let request = PlatformHttpRequest {
            method: "GET".into(),
            url: format!("{}/xrpc/{nsid}?{query}", self.ds_url),
            headers,
            body: None,
        };
        let transport = self.transport.clone();
        let response =
            tokio::task::spawn_blocking(move || transport.execute_http(request)).await??;
        anyhow::ensure!(
            response.status == 200,
            "{}: getConversationState HTTP {}: {}",
            self.label,
            response.status,
            String::from_utf8_lossy(&response.body)
        );
        Ok(serde_json::from_slice(&response.body)?)
    }
}

fn pair() -> BTreeSet<String> {
    BTreeSet::from([ALICE.to_owned(), BOB.to_owned()])
}

fn count(ledger: &Value, transition_kind: &str) -> i64 {
    ledger["transitions"][transition_kind].as_i64().unwrap_or(0)
}

/// `value` with every ATProto `{"$bytes": b64}` presentation as its bare base64
/// string: the client signs bytes fields bare, the DS's lexicon projection
/// presents them as `$bytes`; the base64 itself must be identical.
fn bare_bytes(value: &Value) -> Value {
    match value {
        Value::Object(map) => match map.get("$bytes") {
            Some(Value::String(b64)) if map.len() == 1 => Value::String(b64.clone()),
            _ => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), bare_bytes(value)))
                    .collect(),
            ),
        },
        Value::Array(items) => Value::Array(items.iter().map(bare_bytes).collect()),
        other => other.clone(),
    }
}

/// `(DID, device)` of every leaf a `getConversationState` answer lists.
fn leaves(state: &Value) -> Result<BTreeSet<(String, String)>> {
    state["state"]["leaves"]
        .as_array()
        .context("state.leaves")?
        .iter()
        .map(|leaf| {
            Ok((
                leaf["userDid"].as_str().context("leaf userDid")?.to_owned(),
                leaf["deviceId"]
                    .as_str()
                    .context("leaf deviceId")?
                    .to_owned(),
            ))
        })
        .collect()
}

/// Alice creates a titled group with `bob`'s account: `bob` accepts the
/// invitation, Alice fulfills the recovery his acceptance authorized, and
/// `bob` joins from the Welcome. Joining signs no recovery request.
async fn titled_group(net: &Net, alice: &DeviceUnderTest, bob: &DeviceUnderTest) -> Result<String> {
    let cid = Uuid::new_v4().to_string();
    {
        let cid = cid.clone();
        alice
            .run(move |c| {
                c.create_group(
                    &cid,
                    DS_DID,
                    vec![BOB.into()],
                    Some("R4 recovery".into()),
                    None,
                )
            })
            .await?;
    }
    bob.sync_until("accepts the invitation", async || {
        Ok(!net.recoveries(&cid).await?.is_empty())
    })
    .await?;
    alice
        .sync_until("fulfills Bob's acceptance", async || {
            Ok(net
                .recoveries(&cid)
                .await?
                .iter()
                .all(|r| r["status"] == "fulfilled"))
        })
        .await?;
    bob.sync_until("joins from the Welcome", async || {
        Ok(bob
            .members(&cid)
            .await
            .is_ok_and(|members| members == pair()))
    })
    .await?;
    anyhow::ensure!(
        alice.members(&cid).await? == pair(),
        "Alice's group members"
    );
    let recoveries = net.recoveries(&cid).await?;
    anyhow::ensure!(
        matches!(&recoveries[..], [r] if r["device"] == bob.device_id.as_str()
            && r["source"] == "acceptConversation" && r["status"] == "fulfilled"),
        "Bob's acceptance creates his only recovery: {recoveries:?}"
    );
    anyhow::ensure!(
        bob.transport.recovery_requests().is_empty(),
        "{} signed recovery requests while joining from its acceptance: {:?}",
        bob.label,
        bob.transport.recovery_requests()
    );
    Ok(cid)
}

/// `a` sends `text_a` and `b` decrypts it; `b` answers `text_b` and `a` decrypts it.
async fn round_trip(
    cid: &str,
    (a, text_a): (&DeviceUnderTest, &str),
    (b, text_b): (&DeviceUnderTest, &str),
) -> Result<[String; 2]> {
    let first = a.send(cid, text_a).await?;
    b.sync_until(&format!("decrypts {text_a:?}"), async || {
        b.has(cid, &first, a, text_a).await
    })
    .await?;
    let second = b.send(cid, text_b).await?;
    a.sync_until(&format!("decrypts {text_b:?}"), async || {
        a.has(cid, &second, b, text_b).await
    })
    .await?;
    Ok([first, second])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_recovery_adds_an_existing_members_new_device_from_its_signed_request(
) -> Result<()> {
    let net = Net::start().await?;
    let alice = net.device("alice", ALICE).await?;
    let bob1 = net.device("bob-1", BOB).await?;
    let cid = titled_group(&net, &alice, &bob1).await?;
    let joined = net.ledger(&cid).await?;

    // Bob's second device: an active member's account, no local row, so it owes
    // a recovery and signs the add request itself.
    let bob2 = net.device("bob-2", BOB).await?;
    bob2.sync_until("signs its own leaf recovery request", async || {
        Ok(!bob2.transport.recovery_requests().is_empty())
    })
    .await?;
    let sent = bob2.transport.recovery_requests();
    let [sent] = &sent[..] else {
        anyhow::bail!("Bob 2 sent {} recovery requests: {sent:?}", sent.len());
    };
    let signed = &sent["signedRequest"];
    let body = &signed["body"];
    anyhow::ensure!(
        body["$type"] == "blue.catbird.chat.defs#leafRecoveryRequestBody"
            && body["actorDid"] == BOB
            && body["actorDeviceId"] == bob2.device_id.as_str()
            && body["recoveryKind"] == "add"
            && body["prior"]["conversationId"] == cid.as_str()
            && body["prior"]["generation"] == joined["generation"]
            && body["prior"]["stateVersion"] == joined["stateVersion"],
        "Bob 2's signed request: {body}"
    );
    let rid = body["recoveryRequestId"]
        .as_str()
        .context("recoveryRequestId")?
        .to_owned();

    // The pending view Alice's leaf reads carries exactly what Bob 2 signed.
    let state = alice.conversation_state(&cid).await?;
    let pending = state["pendingLeafRecoveryRequests"]
        .as_array()
        .context("pendingLeafRecoveryRequests")?;
    let [view] = &pending[..] else {
        anyhow::bail!("Alice's pending leaf recoveries: {pending:?}");
    };
    anyhow::ensure!(
        view["recoveryRequestId"] == rid.as_str()
            && view["requesterDid"] == BOB
            && view["requesterDeviceId"] == bob2.device_id.as_str()
            && view["recoveryKind"] == "add"
            && view["status"] == "open",
        "pending view {view}"
    );
    anyhow::ensure!(
        bare_bytes(&view["signedRequest"]) == bare_bytes(signed),
        "the pending view must carry Bob 2's exact signed request\n view: {}\n sent: {signed}",
        view["signedRequest"]
    );
    println!("Bob 2 signed recovery {rid}; Alice's pending view carries exactly that request");

    // Alice verifies and fulfills it: exactly one more recovery transition.
    alice
        .sync_until("fulfills Bob 2's signed request", async || {
            Ok(net.recovery_status(&cid, &rid).await? == "fulfilled")
        })
        .await?;
    let fulfilled = net.ledger(&cid).await?;
    anyhow::ensure!(
        count(&fulfilled, "leafRecovery") == count(&joined, "leafRecovery") + 1,
        "one recovery fulfillment: {joined} -> {fulfilled}"
    );

    bob2.sync_until("joins from the recovery Welcome", async || {
        Ok(bob2
            .members(&cid)
            .await
            .is_ok_and(|members| members == pair()))
    })
    .await?;
    let three = BTreeSet::from([alice.leaf(), bob1.leaf(), bob2.leaf()]);
    anyhow::ensure!(
        leaves(&alice.conversation_state(&cid).await?)? == three,
        "the DS leaves must be Alice, Bob 1 and Bob 2"
    );

    // Messages flow Alice <-> Bob 2, and Bob 1 decrypts Bob 2's message.
    let [_, from_bob2] = round_trip(
        &cid,
        (&alice, "hello, Bob's second device"),
        (&bob2, "hello from Bob's second device"),
    )
    .await?;
    bob1.sync_until("decrypts Bob 2's message", async || {
        bob1.has(&cid, &from_bob2, &bob2, "hello from Bob's second device")
            .await
    })
    .await?;

    // A re-sync of every device adds nothing more.
    let settled = net.ledger(&cid).await?;
    for device in [&alice, &bob1, &bob2] {
        device.sync().await?;
    }
    let resynced = net.ledger(&cid).await?;
    anyhow::ensure!(
        resynced == settled,
        "a re-sync changed the DS: {settled} -> {resynced}"
    );
    let recoveries = net.recoveries(&cid).await?;
    anyhow::ensure!(
        matches!(&recoveries[..], [first, second]
            if first["source"] == "acceptConversation" && first["device"] == bob1.device_id.as_str()
                && second["id"] == rid.as_str() && second["source"] == "requestLeafRecovery"
                && second["kind"] == "add" && second["device"] == bob2.device_id.as_str()
                && [first, second].iter().all(|r| r["status"] == "fulfilled")),
        "recoveries after the re-sync: {recoveries:?}"
    );
    anyhow::ensure!(
        bob2.transport.recovery_requests().len() == 1,
        "Bob 2 signed another recovery request: {:?}",
        bob2.transport.recovery_requests()
    );
    anyhow::ensure!(leaves(&alice.conversation_state(&cid).await?)? == three);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_reset_retires_members_who_rejoin_from_signed_requests() -> Result<()> {
    let net = Net::start().await?;
    let alice = net.device("alice", ALICE).await?;
    let bob = net.device("bob", BOB).await?;
    let cid = titled_group(&net, &alice, &bob).await?;
    let [before_reset, _] = round_trip(
        &cid,
        (&alice, "before the reset"),
        (&bob, "also before the reset"),
    )
    .await?;
    // Bob's join attested the roster: Alice is its admin, Bob a member.
    let attested = bob
        .roster(&cid)
        .await?
        .context("Bob's join recorded no verified roster")?;
    anyhow::ensure!(
        attested[ALICE]["role"] == "admin" && attested[BOB]["role"] == "member",
        "Bob's attested roster: {attested}"
    );

    // Bob is no admin: his reset is refused before any effect, by his roster
    // (`InsufficientPermissions`) or by the DS (`AdminRequired`).
    let head = net.ledger(&cid).await?;
    let bob_row = bob.row(&cid).await?;
    let refused = bob
        .reset(&cid)
        .await
        .err()
        .context("Bob's reset must be refused")?;
    let reason = refused.downcast_ref::<MLSError>();
    anyhow::ensure!(
        matches!(reason, Some(MLSError::InsufficientPermissions { .. }))
            || matches!(reason, Some(MLSError::InvalidState(code)) if code == "AdminRequired"),
        "Bob's reset was refused for another reason: {refused:#}"
    );
    anyhow::ensure!(
        net.ledger(&cid).await? == head,
        "Bob's refused reset changed the DS"
    );
    anyhow::ensure!(
        bob.row(&cid).await? == bob_row,
        "Bob's refused reset moved his row"
    );
    println!("Bob's reset refused: {refused:#}");

    // Alice, the admin, resets: her row moves to the successor's genesis group.
    let prior = alice.row(&cid).await?;
    alice.reset(&cid).await?;
    let successor = alice.row(&cid).await?;
    anyhow::ensure!(
        successor.generation == prior.generation + 1
            && successor.epoch == 0
            && successor.group_id != prior.group_id,
        "Alice's successor row {successor:?} (prior {prior:?})"
    );
    anyhow::ensure!(
        alice.members(&cid).await? == BTreeSet::from([ALICE.to_owned()]),
        "the successor's genesis group holds only Alice"
    );
    let reset = net.ledger(&cid).await?;
    anyhow::ensure!(
        reset["generation"] == successor.generation && count(&reset, "resetActivation") == 1,
        "the DS after Alice's reset: {reset}"
    );
    anyhow::ensure!(
        leaves(&alice.conversation_state(&cid).await?)? == BTreeSet::from([alice.leaf()]),
        "the successor's only DS leaf is Alice"
    );

    // Bob has not synced: his send into the retired generation is refused.
    let stale = Uuid::new_v4().to_string();
    let stale_text = "into the retired generation";
    let refused_send = {
        let (cid, id) = (cid.clone(), stale.clone());
        bob.run(move |c| c.send_message(&cid, &id, stale_text))
            .await
    };
    let Err(refused_send) = refused_send else {
        anyhow::bail!("Bob's send into the retired generation was accepted");
    };
    anyhow::ensure!(net.sequenced_generation(&cid, &stale).await?.is_none());
    println!("old-generation send refused: {refused_send:#}");

    // Bob syncs: Alice's activation verifies against his attested roster and
    // retires his row; he signs an add request bound to the successor.
    bob.sync_until("retires and signs his rejoin request", async || {
        Ok(!bob.transport.recovery_requests().is_empty())
    })
    .await?;
    anyhow::ensure!(
        bob.members(&cid).await.is_err(),
        "Bob's retired row still holds an MLS group"
    );
    let sent = bob.transport.recovery_requests();
    let [sent] = &sent[..] else {
        anyhow::bail!("Bob sent {} recovery requests: {sent:?}", sent.len());
    };
    let body = &sent["signedRequest"]["body"];
    anyhow::ensure!(
        body["actorDid"] == BOB
            && body["actorDeviceId"] == bob.device_id.as_str()
            && body["recoveryKind"] == "add"
            && body["prior"]["generation"] == successor.generation
            && chat_wire::json_bytes(&body["prior"]["groupId"])? == successor.group_id,
        "Bob's rejoin request must be an add bound to the successor: {body}"
    );
    let rid = body["recoveryRequestId"]
        .as_str()
        .context("recoveryRequestId")?
        .to_owned();

    // Alice fulfills it: Bob holds no leaf, her roster says he is active.
    alice
        .sync_until("fulfills Bob's rejoin request", async || {
            Ok(net.recovery_status(&cid, &rid).await? == "fulfilled")
        })
        .await?;
    bob.sync_until("rejoins from the Welcome", async || {
        Ok(bob
            .members(&cid)
            .await
            .is_ok_and(|members| members == pair()))
    })
    .await?;
    let rejoined = bob.row(&cid).await?;
    anyhow::ensure!(
        rejoined.group_id == successor.group_id && rejoined.generation == successor.generation,
        "Bob rejoined at {rejoined:?}, Alice is at {successor:?}"
    );
    anyhow::ensure!(
        bob.history(&cid).await?.iter().any(|m| m.0 == before_reset),
        "Bob's existing row kept its history"
    );
    anyhow::ensure!(
        leaves(&alice.conversation_state(&cid).await?)?
            == BTreeSet::from([alice.leaf(), bob.leaf()])
    );

    // Messages flow both ways in the successor generation.
    for id in round_trip(
        &cid,
        (&alice, "after the reset"),
        (&bob, "rejoined after the reset"),
    )
    .await?
    {
        anyhow::ensure!(
            net.sequenced_generation(&cid, &id).await? == Some(successor.generation),
            "message {id} was not sequenced in the successor generation"
        );
    }
    anyhow::ensure!(net.sequenced_generation(&cid, &stale).await?.is_none());
    anyhow::ensure!(
        !alice.history(&cid).await?.iter().any(|m| m.3 == stale_text),
        "Alice received the retired-generation send"
    );
    let recoveries = net.recoveries(&cid).await?;
    anyhow::ensure!(
        bob.transport.recovery_requests().len() == 1
            && matches!(&recoveries[..], [first, second]
                if first["source"] == "acceptConversation"
                    && second["id"] == rid.as_str() && second["source"] == "requestLeafRecovery"
                    && second["generation"] == successor.generation
                    && [first, second].iter().all(|r| r["status"] == "fulfilled")),
        "Bob signed one rejoin request; his acceptance and rejoin are both fulfilled: {recoveries:?}"
    );
    Ok(())
}

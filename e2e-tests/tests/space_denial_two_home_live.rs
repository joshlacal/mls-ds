//! R4 signed Space denial against two live homes. Bob (homed on `ds-b`) creates a group that
//! `ds-b` sequences, so `ds-b` is its conversation Space's authority, with Alice (homed on `ds-a`:
//! a foreign authority) and Carol (homed on `ds-b`: the same home). Each sends one message she
//! never flushes, Bob removes both, and each removed device rescues the pre-kick messages it holds
//! (its own send and the other's) into its owner mailbox. A fresh device per removed member
//! restores with the recovery code and imports the conversation through its own home's real
//! `relaySpaceCredential`:
//! - the authority's signed denial, relayed byte for byte, is removal proof: the import restores
//!   exactly the owner-rescued pre-kick messages;
//! - the same refusal unsigned (missing denial), with a forged signature, with altered claims, or
//!   replayed from an earlier request inside its 60 s window proves nothing: the import stays
//!   `ArchiveRestorePending` and imports nothing.
//!
//! Each device's D1 firewall admits only its home DS and its PDS, so no device reaches the
//! foreign authority. Every outcome is collected, so a run against the pre-change tuple lists
//! each one it gets wrong.
//!
//! Requires `clean_slate_federation_fixture` in mls-ds/target/debug (built with
//! `--features test-support`) and a loopback PostgreSQL on 127.0.0.1:5432 whose OS-user role can
//! create databases (each run creates and drops its own):
//!
//! ```sh
//! cargo build --manifest-path server/Cargo.toml --features test-support \
//!     --bin clean_slate_federation_fixture
//! cargo test --manifest-path e2e-tests/Cargo.toml --features labyrinth \
//!     --test space_denial_two_home_live -- --nocapture
//! ```
#![cfg(feature = "labyrinth")]

#[allow(dead_code)]
#[path = "support/native_spaces.rs"]
mod native_spaces;

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_mls::{
    client::{
        CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest, PlatformHttpResponse,
        PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
    },
    groups::lifecycle::MemberRole,
    MLSError,
};
use labyrinth::records::nsid;
use native_spaces::{
    CleanSlateDsProcess, ClientTransport, DidDirectory, MemoryKeyStore, SpacesPds,
};
use p256::ecdsa::{signature::Verifier as _, Signature, SigningKey};
use serde_json::{json, Value};
use uuid::Uuid;

const DS_A: &str = "did:web:ds-a.space-denial.catbird.blue";
const DS_B: &str = "did:web:ds-b.space-denial.catbird.blue";
const PDS_DID: &str = "did:web:pds.space-denial.catbird.blue";
const ALICE: &str = "did:plc:spacedenialalicehome2345";
const BOB: &str = "did:plc:spacedenialbobadminhome2";
const CAROL: &str = "did:plc:spacedenialcarolhomeb234";
const S2S_SECRET: &[u8] = b"space-denial-two-home-s2s-secret-32b!";
const RELAY_CREDENTIAL: &str = "/xrpc/blue.catbird.chat.relaySpaceCredential";

/// What a removed member's home relay hands its fresh device for a credential refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relay {
    /// The authority's refusal exactly as the home relayed it.
    Faithful,
    /// The same refusal without its `denial` (an unsigned refusal).
    Unsigned,
    /// One bit of the denial's ES256 signature flipped.
    ForgedSignature,
    /// The denial's `jti` claim altered under the original signature.
    AlteredClaims,
    /// The first refusal this device received (another request's, still live) in place of this one.
    Replayed,
}

/// A fresh device's platform transport: its home's answers pass through, except a relayed
/// credential refusal, which `relay` rewrites. Every refusal is recorded as the home relayed it.
struct DenialRelay {
    inner: Arc<ClientTransport>,
    relay: Mutex<Relay>,
    refusals: Mutex<Vec<Vec<u8>>>,
}

impl PlatformTransport for DenialRelay {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let relayed = request.url.ends_with(RELAY_CREDENTIAL);
        let mut response = self.inner.execute_http(request)?;
        if relayed && response.status == 403 {
            let mut refusals = self.refusals.lock().unwrap();
            let first = refusals.first().cloned();
            refusals.push(response.body.clone());
            response.body = rewrite(*self.relay.lock().unwrap(), &response.body, first);
        }
        Ok(response)
    }

    fn connect_realtime_stream(&self, url: String, cursor: Option<i64>) -> Result<(), MLSError> {
        self.inner.connect_realtime_stream(url, cursor)
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        self.inner.disconnect_realtime_stream()
    }
}

/// `body` as `relay` delivers it; a refusal without a denial has nothing to tamper with.
fn rewrite(relay: Relay, body: &[u8], first: Option<Vec<u8>>) -> Vec<u8> {
    let Ok(mut refusal) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    let Some(denial) = refusal["denial"].as_str().map(str::to_owned) else {
        return body.to_vec();
    };
    let (input, signature) = denial.rsplit_once('.').expect("compact JWS");
    let (header, claims) = input.split_once('.').expect("compact JWS");
    match relay {
        Relay::Faithful => return body.to_vec(),
        Relay::Replayed => return first.unwrap_or_else(|| body.to_vec()),
        Relay::Unsigned => {
            refusal.as_object_mut().unwrap().remove("denial");
        }
        Relay::ForgedSignature => {
            let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
            signature[7] ^= 1;
            refusal["denial"] = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)).into();
        }
        Relay::AlteredClaims => {
            let mut claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
            claims["jti"] = format!("{}-altered", claims["jti"].as_str().unwrap()).into();
            let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            refusal["denial"] = format!("{header}.{claims}.{signature}").into();
        }
    }
    serde_json::to_vec(&refusal).unwrap()
}

/// Claims of the signed denial in a relayed refusal, once its ES256 signature verified under the
/// authority's `#atproto` key.
fn verified_denial(body: &[u8], authority: &SigningKey) -> Result<Value> {
    let refusal: Value = serde_json::from_slice(body).context("refusal JSON")?;
    anyhow::ensure!(refusal["error"] == "NotAuthorized", "refusal {refusal}");
    let jws = refusal["denial"]
        .as_str()
        .with_context(|| format!("relayed refusal carries no signed denial: {refusal}"))?;
    let (input, signature) = jws.rsplit_once('.').context("compact JWS")?;
    let (header, claims) = input.split_once('.').context("compact JWS")?;
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).context("base64url");
    anyhow::ensure!(
        serde_json::from_slice::<Value>(&decode(header)?)?
            == json!({"alg": "ES256", "typ": "catbird-space-denial+jwt", "kid": "#atproto"}),
        "denial header"
    );
    authority
        .verifying_key()
        .verify(
            input.as_bytes(),
            &Signature::from_slice(&decode(signature)?)?,
        )
        .context("the authority's signature")?;
    Ok(serde_json::from_slice(&decode(claims)?)?)
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

/// A device's platform transport: signed in to `did`'s PDS session, homed on `home`, and
/// firewalled to exactly those two hosts (D1).
fn firewalled(
    (did, key, session): (&str, &SigningKey, &str),
    home: &CleanSlateDsProcess,
    pds: &SpacesPds,
) -> Arc<ClientTransport> {
    let transport = Arc::new(ClientTransport::new(vec![
        home.base_url.clone(),
        pds.base_url.clone(),
    ]));
    transport.set_account(did, key.clone(), &home.service_did, &pds.base_url, session);
    transport
}

async fn open(
    root: &Path,
    label: &str,
    did: &str,
    home: &CleanSlateDsProcess,
    pds: &SpacesPds,
    platform: Arc<dyn PlatformTransport>,
) -> Result<Arc<CatbirdMlsClient>> {
    let config = CatbirdMlsClientConfig {
        storage_root: root.join(label).to_string_lossy().into(),
        account_did: did.into(),
        device_id: Uuid::new_v4().to_string(),
        home_ds_did: home.service_did.clone(),
        home_ds_endpoint: home.base_url.clone(),
        pds_endpoint: pds.base_url.clone(),
    };
    Ok(tokio::task::spawn_blocking(move || {
        CatbirdMlsClient::open(config, Arc::new(MemoryKeyStore::new()), platform, None)
    })
    .await??)
}

/// One blocking client call, as a platform's background queue makes it.
async fn run<T: Send + 'static>(
    client: &Arc<CatbirdMlsClient>,
    call: impl FnOnce(&CatbirdMlsClient) -> Result<T, MLSError> + Send + 'static,
) -> Result<T, MLSError> {
    let client = client.clone();
    tokio::task::spawn_blocking(move || call(&client))
        .await
        .expect("client call panicked")
}

async fn members(client: &Arc<CatbirdMlsClient>, cid: &str) -> Result<BTreeSet<String>, MLSError> {
    let cid = cid.to_owned();
    Ok(run(client, move |c| c.list_members(&cid))
        .await?
        .into_iter()
        .collect())
}

/// Message ids of every local message in `cid`.
async fn history(client: &Arc<CatbirdMlsClient>, cid: &str) -> Result<Vec<String>> {
    let cid = cid.to_owned();
    Ok(run(client, move |c| c.list_messages(&cid, None, 100))
        .await?
        .into_iter()
        .map(|row| row.message_id)
        .collect())
}

/// Every exchange a device's transport carried that did not succeed, for a failure message.
fn unsuccessful(transports: &[(&str, Arc<ClientTransport>)]) -> Vec<String> {
    transports
        .iter()
        .flat_map(|(label, transport)| {
            transport
                .exchanges()
                .into_iter()
                .filter(|e| !(200..300).contains(&e.status))
                .map(move |e| format!("{label} {} {} {} {:?}", e.method, e.url, e.status, e.error))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_members_restore_only_on_the_authoritys_signed_denial_relayed_by_either_home(
) -> Result<()> {
    // ── topology: two homes, one PDS, the DID directory every resolveDid reads ──
    let ds_a = CleanSlateDsProcess::spawn(DS_A, S2S_SECRET).await?;
    let ds_b = CleanSlateDsProcess::spawn(DS_B, S2S_SECRET).await?;
    let http = reqwest::Client::new();
    // Each home reaches the other, and its own Space host, as a federation peer and relay target.
    for ds in [&ds_a, &ds_b] {
        ds.register_ds(&http, &ds_a).await?;
        ds.register_ds(&http, &ds_b).await?;
    }
    let directory = DidDirectory::new();
    directory.publish(&ds_a.service_did, ds_a.did_document.clone());
    directory.publish(&ds_b.service_did, ds_b.did_document.clone());
    let pds = SpacesPds::start(PDS_DID, true, directory).await;
    let alice_key = SigningKey::random(&mut rand::rngs::OsRng);
    let bob_key = SigningKey::random(&mut rand::rngs::OsRng);
    let carol_key = SigningKey::random(&mut rand::rngs::OsRng);
    let session = |did: &str, device: &str| format!("{did}-{device}-oauth");
    for (did, key) in [(ALICE, &alice_key), (BOB, &bob_key), (CAROL, &carol_key)] {
        pds.add_account(did, key.clone(), &session(did, "phone"));
        pds.add_session(did, &session(did, "fresh"));
        for ds in [&ds_a, &ds_b] {
            ds.register_did(&http, did, key.verifying_key(), &pds.base_url)
                .await?;
        }
    }
    let root = tempfile::tempdir()?;
    let mut transports = Vec::new();
    let mut device =
        |label: &'static str, did: &'static str, key: &SigningKey, home: &CleanSlateDsProcess| {
            let transport = firewalled((did, key, &session(did, "phone")), home, &pds);
            transports.push((label, transport.clone()));
            (label, did, transport)
        };
    let mut phones = Vec::new();
    for (label, did, transport) in [
        device("alice-phone", ALICE, &alice_key, &ds_a),
        device("bob-phone", BOB, &bob_key, &ds_b),
        device("carol-phone", CAROL, &carol_key, &ds_b),
    ] {
        let home = if did == ALICE { &ds_a } else { &ds_b };
        let client = open(root.path(), label, did, home, &pds, transport).await?;
        let enrolled = run(&client, |c| c.enroll_device(&scopes())).await?;
        anyhow::ensure!(
            enrolled.labyrinth_backup_enabled,
            "{label}: enrollment turns backup on"
        );
        phones.push(client);
    }
    let [alice, bob, carol] = &phones[..] else {
        unreachable!()
    };

    // ── the group ds-b sequences: its conversation Space's authority is ds-b ──
    let cid = Uuid::new_v4().to_string();
    let created = {
        let cid = cid.clone();
        run(bob, move |c| {
            c.create_group(
                &cid,
                DS_B,
                vec![ALICE.into(), CAROL.into()],
                Some("Signed denial".into()),
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
        created.sequencer_did == DS_B
            && space == format!("at:space/{DS_B}/blue.catbird.labyrinth.conversation/{cid}-0"),
        "conversation Space {space} sequenced by {}",
        created.sequencer_did
    );
    // Alice (through ds-a) joins first: ds-a mirrors the group from its opening prefix (creation,
    // acceptance, fulfillment); Carol (on ds-b) joins after. Each joiner accepts, Bob fulfils her
    // leaf recovery, and she joins from the Welcome; ds-b delivers its commits to ds-a after
    // committing, so rounds repeat.
    let conversation = Uuid::parse_str(&cid)?;
    for (joiner, did) in [(alice, ALICE), (carol, CAROL)] {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            for client in [joiner, bob, joiner] {
                run(client, |c| c.sync()).await?;
            }
            if members(joiner, &cid).await.is_ok_and(|m| m.contains(did)) {
                break;
            }
            if Instant::now() >= deadline {
                let entries: Vec<String> = ds_b
                    .pool
                    .query(
                        "SELECT seq, entry_kind, actor_did FROM chat.entries \
                         WHERE conversation_id = $1 ORDER BY seq",
                        &[&conversation],
                    )
                    .await?
                    .iter()
                    .map(|row| {
                        format!(
                            "{} {} {}",
                            row.get::<_, i64>(0),
                            row.get::<_, String>(1),
                            row.get::<_, String>(2)
                        )
                    })
                    .collect();
                anyhow::bail!(
                    "{did} must join the ds-b-sequenced group: joiner {:?}, bob {:?}; ds-b entries {entries:#?}; unsuccessful exchanges {:#?}",
                    members(joiner, &cid).await,
                    members(bob, &cid).await,
                    unsuccessful(&transports)
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    let everyone = BTreeSet::from([ALICE.to_owned(), BOB.to_owned(), CAROL.to_owned()]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut rosters = Vec::new();
        for client in [alice, bob, carol] {
            run(client, |c| c.sync()).await?;
            rosters.push(members(client, &cid).await);
        }
        if rosters
            .iter()
            .all(|r| r.as_ref().is_ok_and(|m| *m == everyone))
        {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "every member must hold all three: alice, bob, carol rosters {rosters:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // ── pre-kick: recovery codes, one unflushed send each, then Bob removes both ──
    let alice_code = run(alice, |c| c.setup_recovery_code()).await?;
    let carol_code = run(carol, |c| c.setup_recovery_code()).await?;
    let mut sent = Vec::new();
    for (client, text) in [
        (alice, "alice before her removal"),
        (carol, "carol before hers"),
    ] {
        let (cid, id) = (cid.clone(), Uuid::new_v4().to_string());
        sent.push(
            run(client, move |c| c.send_message(&cid, &id, text))
                .await?
                .message_id,
        );
    }
    for did in [ALICE, CAROL] {
        let cid = cid.clone();
        run(bob, move |c| {
            c.remove_group_member(MemberRole::Admin, &cid, did)
        })
        .await?;
    }
    // Each removed device applies its removal (alice's arrives through ds-a) and rescues the
    // pre-kick messages it holds into its owner mailbox.
    for (client, did) in [(alice, ALICE), (carol, CAROL)] {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            run(client, |c| c.sync()).await?;
            let removed = !members(client, &cid).await.is_ok_and(|m| m.contains(did));
            if removed
                && !pds
                    .space_records(&mailbox(did), did, nsid::OWNER_BATCH)
                    .is_empty()
            {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "{did}: the removal must apply and rescue the pre-kick send: members {:?}; unsuccessful exchanges {:#?}",
                members(client, &cid).await,
                unsuccessful(&transports)
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    // ── fresh devices: restore through each home's relay ──
    let mut violations = Vec::new();
    let pre_kick: BTreeSet<String> = sent.iter().cloned().collect();
    for (label, did, key, home, code) in [
        ("alice-fresh", ALICE, &alice_key, &ds_a, &alice_code),
        ("carol-fresh", CAROL, &carol_key, &ds_b, &carol_code),
    ] {
        let place = if home.service_did == DS_B {
            "home ds-b, the authority"
        } else {
            "home ds-a, foreign authority ds-b"
        };
        let inner = firewalled((did, key, &session(did, "fresh")), home, &pds);
        transports.push((label, inner.clone()));
        let relay = Arc::new(DenialRelay {
            inner,
            relay: Mutex::new(Relay::Faithful),
            refusals: Mutex::new(Vec::new()),
        });
        let fresh = open(root.path(), label, did, home, &pds, relay.clone()).await?;
        {
            let code = code.clone();
            run(&fresh, move |c| c.restore_with_recovery_code(&code)).await?;
        }
        let mut replayed_at = 0;
        for mode in [
            Relay::Unsigned,
            Relay::ForgedSignature,
            Relay::AlteredClaims,
            Relay::Replayed,
            Relay::Faithful,
        ] {
            *relay.relay.lock().unwrap() = mode;
            let before = relay.refusals.lock().unwrap().len();
            if mode == Relay::Replayed {
                replayed_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            }
            let outcome = {
                let cid = cid.clone();
                run(&fresh, move |c| {
                    c.restore_conversation_from_owner_mailbox(&cid)
                })
                .await
            };
            let imported = history(&fresh, &cid).await?;
            let refusals = relay.refusals.lock().unwrap().len() - before;
            let ok = match (&outcome, mode) {
                (Ok(n), Relay::Faithful) => {
                    *n as usize == pre_kick.len()
                        && imported.iter().cloned().collect::<BTreeSet<_>>() == pre_kick
                }
                (Err(MLSError::InvalidState(code)), _) => {
                    mode != Relay::Faithful
                        && code == "ArchiveRestorePending"
                        && imported.is_empty()
                }
                _ => false,
            };
            println!("{label} ({place}) {mode:?}: {outcome:?}, {refusals} relayed refusal(s), history {imported:?}");
            if !ok || refusals == 0 {
                violations.push(format!(
                    "{label} ({place}) {mode:?}: got {outcome:?} with history {imported:?} after {refusals} relayed refusal(s); expected {}",
                    if mode == Relay::Faithful {
                        format!("Ok({}) restoring exactly the pre-kick messages {pre_kick:?}", pre_kick.len())
                    } else {
                        "ArchiveRestorePending with nothing imported".to_owned()
                    }
                ));
            }
        }

        // What the home relayed is the authority's signed denial of each request: ds-b's
        // `#atproto` key over this member, this Space, its generation and MLS group, and a fresh
        // PoP key per request, live exactly 60 s.
        let refusals = relay.refusals.lock().unwrap().clone();
        let mut kids = BTreeSet::new();
        for (index, body) in refusals.iter().enumerate() {
            match verified_denial(body, &ds_b.signing_key) {
                Ok(claims) => {
                    let iat = claims["iat"].as_u64().unwrap_or_default();
                    let expected = json!({
                        "iss": DS_B, "sub": space, "aud": did, "iat": iat, "exp": iat + 60,
                        "jti": claims["jti"], "cnf": claims["cnf"],
                        "conversationId": cid, "generation": 0,
                        "groupId": hex::encode(&created.group_id), "reason": "notActiveMember",
                    });
                    let kid = claims["cnf"]["kid"].as_str().unwrap_or_default();
                    if claims != expected
                        || !kid.starts_with("did:key:z")
                        || claims["jti"].as_str().is_none_or(str::is_empty)
                    {
                        violations.push(format!("{label}: denial claims {claims} != {expected}"));
                    }
                    // Only the request binding refused the replay: the replayed denial was live.
                    if index == 0 && iat + 60 <= replayed_at {
                        violations.push(format!(
                            "{label}: the replayed denial had expired ({}) when replayed ({replayed_at})",
                            iat + 60
                        ));
                    }
                    kids.insert(kid.to_owned());
                }
                Err(error) => violations.push(format!("{label} ({place}): {error:#}")),
            }
        }
        println!(
            "{label} ({place}): {} relayed refusals, {} distinct cnf.kid",
            refusals.len(),
            kids.len()
        );
        if kids.len() != refusals.len() {
            violations.push(format!(
                "{label}: {} refusals bound only {} distinct request PoP keys",
                refusals.len(),
                kids.len()
            ));
        }
    }

    for (label, transport) in &transports {
        if transport.blocked_attempts.load(Ordering::SeqCst) != 0 {
            violations.push(format!(
                "{label} contacted a host outside its home DS and PDS"
            ));
        }
    }
    anyhow::ensure!(violations.is_empty(), "{violations:#?}");
    Ok(())
}

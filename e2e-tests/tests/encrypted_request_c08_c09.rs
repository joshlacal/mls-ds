//! Validation cases C08 (policy races) and C09 (device coverage) through the
//! live shipping router against the guarded request database.
//!
//! Policy evidence is real: the router's relationship authority fetches the
//! recipient declaration and the appview graph from the HTTPS fixture, persists
//! the projection, and `verify_direct_request_policy` decides. Tests change the
//! fixture's opt-in `_policy` override files, never protocol tables.
//!
//! Races are real: a separate PostgreSQL session holds the recipient's
//! principal/device/key rows (principal row only for the revoke race)
//! `FOR UPDATE` as a barrier; both the authority mutation (real
//! `publishDirectRequestKeys` disable or real `revokeDevice`) and the real
//! `publishDirectRequest` queue on it in a chosen order, the barrier is
//! released, and the router serializes them. Both orderings run.
#![allow(dead_code)]

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
    signed_mls_request, validate_request_test_database_url, HttpsDidFixture, ServiceIdentity,
    request_database_url, ShippingServerFixture,
};

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

use live_direct_request::siblings::{self, RecipientSibling};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Database reads (read-only projections of server state)
// ---------------------------------------------------------------------------

fn psql(sql: &str) -> anyhow::Result<String> {
    validate_request_test_database_url(Some(request_database_url()))?;
    let output = Command::new("psql")
        .args([
            request_database_url(),
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn count(sql: &str) -> anyhow::Result<i64> {
    Ok(psql(sql)?.parse()?)
}

/// Every server row a published (or partially published) request could leave.
#[derive(Debug, PartialEq, Eq)]
struct RequestRows {
    published_attempts: i64,
    publications: i64,
    deliveries: i64,
    conversations: i64,
    entries: i64,
}

fn request_rows(request_id: Uuid, conversation_id: Uuid) -> anyhow::Result<RequestRows> {
    let row = psql(&format!(
        "SELECT (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{request_id}' AND status='published'), \
                (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.conversations WHERE conversation_id='{conversation_id}'), \
                (SELECT count(*) FROM chat.entries WHERE transition_id='{request_id}')"
    ))?;
    let f: Vec<i64> = row
        .split('|')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(f.len() == 5, "unexpected row projection {row}");
    Ok(RequestRows {
        published_attempts: f[0],
        publications: f[1],
        deliveries: f[2],
        conversations: f[3],
        entries: f[4],
    })
}

const NO_ROWS: RequestRows = RequestRows {
    published_attempts: 0,
    publications: 0,
    deliveries: 0,
    conversations: 0,
    entries: 0,
};

fn attempt_status(request_id: Uuid) -> anyhow::Result<String> {
    psql(&format!(
        "SELECT status FROM chat.direct_request_attempts WHERE request_id='{request_id}'"
    ))
}

// ---------------------------------------------------------------------------
// Fixture policy overrides (served by support/https_did_fixture.py)
// ---------------------------------------------------------------------------

/// Python `urllib.parse.quote(part, safe="")`.
fn quote(part: &str) -> String {
    part.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn set_policy(root: &Path, parts: &[&str], value: &Value) -> anyhow::Result<()> {
    let mut path = root.join("_policy");
    for part in &parts[..parts.len() - 1] {
        path = path.join(quote(part));
    }
    std::fs::create_dir_all(&path)?;
    std::fs::write(
        path.join(quote(parts[parts.len() - 1])),
        serde_json::to_vec(value)?,
    )?;
    Ok(())
}

/// Direct admission orients the only graph request as actor=recipient,
/// others=[inviter] (`plan_admission_graph` with the inviter as sink), so every
/// block direction is expressed on that one appview row.
fn set_recipient_view(root: &Path, recipient: &str, inviter: &str, row: Value) -> anyhow::Result<()> {
    set_policy(root, &["relationship", recipient, inviter], &row)
}

fn set_incoming(root: &Path, recipient: &str, incoming: &str) -> anyhow::Result<()> {
    set_policy(
        root,
        &["declaration", recipient],
        &json!({"$type":"chat.bsky.actor.declaration","allowIncoming":incoming}),
    )
}

fn record_uri(owner: &str, collection: &str) -> String {
    format!("at://{owner}/{collection}/3jzfcijpj2z2a")
}

// ---------------------------------------------------------------------------
// Accounts, keys, prepare, publish
// ---------------------------------------------------------------------------

struct Account {
    svc: ServiceIdentity,
    engine: MlsEngine,
    identity: String,
    public: Vec<u8>,
    key_id: String,
    package: Vec<u8>,
    package_ref: Vec<u8>,
}

impl Account {
    fn new(svc: ServiceIdentity, label: &str) -> anyhow::Result<Self> {
        let engine = MlsEngine::new(label)?;
        let identity = format!("{}#{}", svc.did, svc.device_id);
        let (package, package_ref) = engine.create_key_package(&identity)?;
        let public = engine.identity_public_key(&identity)?;
        seed_service_device(&svc, &public)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        Ok(Self {
            svc,
            engine,
            identity,
            public,
            key_id,
            package,
            package_ref,
        })
    }
    fn did(&self) -> &str {
        &self.svc.did
    }
}

fn identity(label: &str, run: &str) -> ServiceIdentity {
    ServiceIdentity::new(format!("did:web:{label}-{run}.request-fixture.catbird.blue"))
}

struct Rig {
    https: HttpsDidFixture,
    server: ShippingServerFixture,
    client: reqwest::Client,
}

async fn rig(identities: &[&ServiceIdentity]) -> anyhow::Result<Rig> {
    let authority = connect_guarded_request_database(5).await?;
    anyhow::ensure!(authority.additive_migrations == reviewed_request_migrations().len());
    let documents = identities
        .iter()
        .map(|id| (id.did.clone(), id.did_document()))
        .collect::<Vec<_>>();
    let https = HttpsDidFixture::start(HttpsDidFixture::reserve_port()?, &documents)?;
    let server = ShippingServerFixture::start(&https)?;
    Ok(Rig {
        https,
        server,
        client: reqwest::Client::builder().build()?,
    })
}

async fn post(
    rig: &Rig,
    who: &ServiceIdentity,
    nsid: &str,
    body: &Value,
) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let (status, bytes) = who
        .post(&rig.client, &rig.server.base_url, nsid, body, true)
        .await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{nsid} {status}: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, value))
}

fn keys_envelope(a: &Account, revision: i64, enabled: bool) -> anyhow::Result<Value> {
    let keys = if enabled {
        let grant_id = Uuid::new_v4();
        let grant = signed_mls_request(
            &a.engine,
            &a.identity,
            DirectRequestKind::Grant,
            json!({
                "$type":"blue.catbird.chat.defs#directRequestGrantBody",
                "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
                "actorDid":a.did(),"actorDeviceId":a.svc.device_id.to_string(),
                "keyId":a.key_id,"authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
                "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
                "keyPackageRef":STANDARD.encode(&a.package_ref),
                "keyPackageSha256":STANDARD.encode(Sha256::digest(&a.package)),
                "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),
                "signedAt":canonical_now()
            }),
        )?;
        json!([{"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
            "bytes":STANDARD.encode(&a.package),"sha256":STANDARD.encode(Sha256::digest(&a.package)),
            "keyPackageRef":STANDARD.encode(&a.package_ref)},"grant":grant}])
    } else {
        json!([])
    };
    let keys = signed_mls_request(
        &a.engine,
        &a.identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":a.did(),"actorDeviceId":a.svc.device_id.to_string(),
            "keyId":a.key_id,"authGeneration":1,"revision":revision,"enabled":enabled,
            "keys":keys,"idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
        }),
    )?;
    Ok(json!({"signedRequest":keys}))
}

async fn publish_keys(rig: &Rig, a: &Account) -> anyhow::Result<()> {
    let (status, body) = post(
        rig,
        &a.svc,
        "blue.catbird.chat.publishDirectRequestKeys",
        &keys_envelope(a, 1, true)?,
    )
    .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "publish keys {status}: {body}");
    Ok(())
}

struct Prep {
    request_id: Uuid,
    conversation_id: Uuid,
    first_message_id: Uuid,
    prepare: Value,
    prepare_digest: [u8; 32],
    status: reqwest::StatusCode,
    response: Value,
}

impl Prep {
    fn preparation(&self) -> anyhow::Result<&Value> {
        anyhow::ensure!(
            self.status == reqwest::StatusCode::OK
                && self.response["outcome"]["$type"]
                    == "blue.catbird.chat.defs#directRequestPreparedOutcome",
            "expected prepared outcome, got {}: {}",
            self.status,
            self.response
        );
        Ok(&self.response["outcome"]["preparation"])
    }
    fn selected_device_ids(&self) -> anyhow::Result<BTreeSet<String>> {
        Ok(self.preparation()?["selectedDevices"]
            .as_array()
            .context("selectedDevices")?
            .iter()
            .map(|d| d["actorDeviceId"].as_str().unwrap_or_default().to_owned())
            .collect())
    }
}

async fn prepare(rig: &Rig, alice: &Account, recipient: &str) -> anyhow::Result<Prep> {
    let request_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let prepare = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":alice.did(),"actorDeviceId":alice.svc.device_id.to_string(),
            "keyId":alice.key_id,"authGeneration":1,"requestId":request_id.to_string(),
            "firstMessageId":first_message_id.to_string(),"conversationId":conversation_id.to_string(),
            "recipientDid":recipient,"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1","idempotencyKey":request_id.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let prepare_digest = *protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice.public,
    )?
    .request_digest();
    let (status, response) = post(
        rig,
        &alice.svc,
        "blue.catbird.chat.prepareDirectRequest",
        &json!({"signedRequest":prepare}),
    )
    .await?;
    Ok(Prep {
        request_id,
        conversation_id,
        first_message_id,
        prepare,
        prepare_digest,
        status,
        response,
    })
}

/// Build the complete signed publication from the live preparation with the
/// real native bootstrap (same construction as the C01 fixture).
fn build_publication(
    rig: &Rig,
    alice: &Account,
    recipient: &str,
    prep: &Prep,
) -> anyhow::Result<(Value, catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrap)> {
    let preparation = prep.preparation()?;
    let preparation = protocol::verify_direct_request_preparation(
        &serde_json::to_vec(preparation)?,
        &rig.server.receipt_public_key,
    )?;
    let preparation = &preparation;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("selectedDevices")?;
    let mut authority_import_until = u64::MAX;
    for device in selected {
        let expires = chrono::DateTime::parse_from_rfc3339(
            device["grant"]["body"]["expiresAt"]
                .as_str()
                .context("grant expiresAt")?,
        )?
        .timestamp();
        authority_import_until = authority_import_until.min(u64::try_from(expires)?);
    }
    let decode = |device: &Value, field: &str| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(
            device["keyPackage"][field]
                .as_str()
                .context("selected package field")?,
        )?)
    };
    let context = json!({
        "protocolVersion":"2","requestId":prep.request_id.to_string(),
        "firstMessageId":prep.first_message_id.to_string(),
        "conversationId":prep.conversation_id.to_string(),
        "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":alice.did(),"actorDeviceId":alice.svc.device_id.to_string(),
        "actorKeyId":alice.key_id,"recipientDid":recipient,
        "preparationDigest":preparation["preparationDigest"]
    });
    let journal = alice.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|d| decode(d, "bytes"))
            .collect::<anyhow::Result<_>>()?,
        expected_package_refs: selected
            .iter()
            .map(|d| decode(d, "keyPackageRef"))
            .collect::<anyhow::Result<_>>()?,
        authority_import_until,
        preparation_request_digest: prep.prepare_digest,
        receipt_authority_key: rig.server.receipt_public_key.clone(),
        text: "C08/C09 encrypted first contact".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let bootstrap = journal.bootstrap.clone();
    let mut body = prep.prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = preparation["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(prep.prepare_digest));
    body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    body["next"] = bootstrap.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(bootstrap.import_until as i64, 0)
        .context("import timestamp")?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({"framing":"mlsMessage","contentType":content_type,
            "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))})
    };
    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid":device["actorDid"],"recipientDeviceId":device["actorDeviceId"],
                "provenance":{
                    "requestId":prep.request_id.to_string(),
                    "preparationDigest":preparation["preparationDigest"],
                    "contextHash":STANDARD.encode(bootstrap.context_hash),
                    "grantId":device["grant"]["body"]["grantId"],
                    "grantRevision":device["grant"]["body"]["grantRevision"],
                    "keyPackageRef":device["keyPackage"]["keyPackageRef"],
                    "importUntil":body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();
    let author = json!({
        "authorDid":alice.did(),"authorDeviceId":alice.svc.device_id.to_string(),"authorKeyId":alice.key_id,
        "signaturePublicKey":STANDARD.encode(&alice.public),"authGenerationAtOrigin":1,
        "originTransitionId":prep.request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin",
        "deviceStatusAtOrigin":"active"
    });
    body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&bootstrap.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&bootstrap.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&bootstrap.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&bootstrap.welcome),
            "sha256":STANDARD.encode(Sha256::digest(&bootstrap.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot":{
            "coordinate":metadata_coordinate(&bootstrap.coordinates)?,
            "originTransitionId":prep.request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext":STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize":bootstrap.metadata_ciphertext.len(),"authorProof":author
        }
    });
    let publication =
        signed_mls_request(&alice.engine, &alice.identity, DirectRequestKind::Publish, body)?;
    Ok((json!({"signedRequest":publication}), bootstrap))
}

/// Capacity hygiene: release a published request through the recipient's real
/// signed acceptance (the same body as the C01 fixture's accept).
async fn release_by_accept(
    rig: &Rig,
    accepter: (&MlsEngine, &str, &ServiceIdentity),
    alice: &Account,
    prep: &Prep,
    bootstrap: &catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrap,
) -> anyhow::Result<()> {
    let (engine, identity, svc) = accepter;
    let public = engine.identity_public_key(identity)?;
    let prior = bootstrap.coordinates.clone();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("state version")? + 1);
    // The shared DB is contended by concurrent suites; acceptance admission
    // masks transient storage failures as InvalidSignature. Re-sign and retry
    // so capacity is still released (a committed first try would fail loudly).
    let mut last = None;
    for _ in 0..3 {
        let transition = Uuid::new_v4();
        let signed = signed_mls_request(
            engine,
            identity,
            DirectRequestKind::Accept,
            json!({
                "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
                "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0","protocolVersion":"2",
                "actorDid":svc.did,"actorDeviceId":svc.device_id.to_string(),
                "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":1,
                "requestId":prep.request_id.to_string(),"transitionId":transition.to_string(),
                "prior":prior,"next":next,
                "invitationProvenance":{"invitationTransitionId":prep.request_id.to_string(),
                    "invitedByDid":alice.did(),"invitedByDeviceId":alice.svc.device_id.to_string()},
                "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
            }),
        )?;
        let (status, body) = post(
            rig,
            svc,
            "blue.catbird.chat.acceptConversation",
            &json!({"directRequest":signed}),
        )
        .await?;
        if status == reqwest::StatusCode::OK {
            println!("RELEASE request {} accepted by {}", prep.request_id, svc.device_id);
            return Ok(());
        }
        println!("RELEASE retry after accept {status}: {body}");
        last = Some((status, body));
    }
    anyhow::bail!("release accept failed: {last:?}")
}

/// Verify the router's signed receipt against the receipt authority key and
/// return `(receipt $type suffix, code)`.
fn receipt(rig: &Rig, response: &Value) -> anyhow::Result<(String, Option<String>)> {
    anyhow::ensure!(
        response["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "expected signed receipt, got {response}"
    );
    let mut signed = response["outcome"].clone();
    signed
        .as_object_mut()
        .context("receipt object")?
        .remove("$type");
    let verified = protocol::verify_received_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&signed)?,
        &rig.server.receipt_public_key,
    )?;
    let proof = &verified.body()["receipt"];
    Ok((
        proof["$type"]
            .as_str()
            .context("receipt type")?
            .trim_start_matches("blue.catbird.chat.defs#")
            .to_owned(),
        proof["code"].as_str().map(str::to_owned),
    ))
}

fn expect_rejected(
    rig: &Rig,
    status: reqwest::StatusCode,
    response: &Value,
    code: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{status}: {response}");
    let (kind, got) = receipt(rig, response)?;
    anyhow::ensure!(
        kind == "directRequestRejectedReceipt" && got.as_deref() == Some(code),
        "expected rejected {code}, got {kind} {got:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Real signed device revocation (G6 revokeDevice)
// ---------------------------------------------------------------------------

fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    use catbird_mls::chat_v2::transcript::{
        decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
    };
    let canonical = project_signed_body(
        SignedMutationKind::from_type_id(body["$type"].as_str().context("signed type")?)
            .context("signed kind")?,
        &decode_strict_json(&serde_json::to_vec(&body)?)?,
    )?;
    let transcript = SigningTranscript::build(&canonical)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
}

fn revoke_envelope(actor: &RecipientSibling, target_device: Uuid) -> anyhow::Result<Value> {
    let public = actor.engine.identity_public_key(&actor.identity)?;
    let signed = signed_ordinary(
        &actor.engine,
        &actor.identity,
        json!({
            "$type":"blue.catbird.chat.defs#deviceRevocationBody",
            "actorDid":actor.service.did,"actorDeviceId":actor.service.device_id.to_string(),
            "authGeneration":1,"targetDeviceId":target_device.to_string(),"targetAuthGeneration":1,
            "idempotencyKey":Uuid::new_v4().to_string(),
            "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),
            "signatureDomain":"CATBIRD-CHAT-DEVICE-REVOKE\0","signedAt":canonical_now()
        }),
    )?;
    Ok(json!({"signedRequest":signed}))
}

// ---------------------------------------------------------------------------
// Row-lock barrier held by an independent PostgreSQL session
// ---------------------------------------------------------------------------

struct Barrier {
    child: Child,
    stdin: ChildStdin,
    pid: i64,
}

impl Barrier {
    /// Lock the account's principal, device and key rows in the same canonical
    /// tables the router's identity-scope prefix and every authority writer lock.
    fn hold(did: &str) -> anyhow::Result<Self> {
        Self::hold_rows(&format!(
            "SELECT count(*) FROM (SELECT 1 FROM chat.principals WHERE user_did='{did}' FOR UPDATE) p;\n\
             SELECT count(*) FROM (SELECT 1 FROM chat.devices WHERE user_did='{did}' FOR UPDATE) d;\n\
             SELECT count(*) FROM (SELECT 1 FROM chat.device_keys WHERE user_did='{did}' FOR UPDATE) k;"
        ))
    }

    /// Lock only the account's principal row: the first identity lock of both
    /// the publication and the G6 revocation transaction. Unlike [`hold`], a
    /// `revokeDevice` admission (which locks only the actor device/key rows)
    /// passes, so the revocation queues here *after* its lock-free G6 scope
    /// discovery and queue order is commit order.
    fn hold_principal(did: &str) -> anyhow::Result<Self> {
        Self::hold_rows(&format!(
            "SELECT count(*) FROM (SELECT 1 FROM chat.principals WHERE user_did='{did}' FOR UPDATE) p;"
        ))
    }

    fn hold_rows(locks: &str) -> anyhow::Result<Self> {
        let mut child = Command::new("psql")
            .args([request_database_url(), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().context("barrier stdin")?;
        writeln!(stdin, "BEGIN;\nSELECT pg_backend_pid();\n{locks}\n\\echo BARRIER-HELD")?;
        stdin.flush()?;
        let mut lines = BufReader::new(child.stdout.take().context("barrier stdout")?).lines();
        let pid: i64 = lines.next().context("barrier pid")??.trim().parse()?;
        for line in lines.by_ref() {
            if line?.trim() == "BARRIER-HELD" {
                return Ok(Self { child, stdin, pid });
            }
        }
        anyhow::bail!("barrier session exited before holding locks")
    }

    /// Backends waiting (directly or transitively) behind this barrier. Runs
    /// use a dedicated database, so no foreign session can be counted.
    fn waiters(&self) -> anyhow::Result<i64> {
        count(&format!(
            "WITH RECURSIVE w(pid) AS (SELECT pid FROM pg_stat_activity WHERE {b}=ANY(pg_blocking_pids(pid)) \
             UNION SELECT a.pid FROM pg_stat_activity a JOIN w ON w.pid=ANY(pg_blocking_pids(a.pid))) \
             SELECT count(*) FROM w",
            b = self.pid
        ))
    }

    async fn wait_for_waiters(&self, at_least: i64) -> anyhow::Result<i64> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let n = self.waiters()?;
            if n >= at_least {
                return Ok(n);
            }
            anyhow::ensure!(Instant::now() < deadline, "only {n} waiters behind barrier");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn release(mut self) -> anyhow::Result<()> {
        writeln!(self.stdin, "COMMIT;\n\\q")?;
        self.stdin.flush()?;
        anyhow::ensure!(self.child.wait()?.success(), "barrier session failed");
        Ok(())
    }
}

type Posted = tokio::task::JoinHandle<anyhow::Result<(reqwest::StatusCode, Vec<u8>)>>;

fn spawn_post(rig: &Rig, who: &ServiceIdentity, nsid: &'static str, body: Value) -> Posted {
    let (who, client, base) = (who.clone(), rig.client.clone(), rig.server.base_url.clone());
    tokio::spawn(async move { who.post(&client, &base, nsid, &body, true).await })
}

struct RaceResult {
    first: (reqwest::StatusCode, Value),
    second: (reqwest::StatusCode, Value),
}

/// Queue `first` then `second` behind `barrier`, confirm both are in flight
/// inside the server, then release so the router serializes them.
async fn race(
    rig: &Rig,
    barrier: Barrier,
    first: (&ServiceIdentity, &'static str, Value),
    second: (&ServiceIdentity, &'static str, Value),
    label: &str,
) -> anyhow::Result<RaceResult> {
    let a = spawn_post(rig, first.0, first.1, first.2);
    let queued_first = barrier.wait_for_waiters(1).await?;
    let b = spawn_post(rig, second.0, second.1, second.2);
    let queued_both = barrier.wait_for_waiters(2).await?;
    // Let the second request's HTTP body reach its lock wait before release.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let at_release = barrier.waiters()?;
    println!(
        "RACE {label}: barrier pid {} waiters after first={queued_first} after second={queued_both} at release={at_release}; first={} second={}",
        barrier.pid, first.1, second.1
    );
    barrier.release()?;
    let decode = |(status, bytes): (reqwest::StatusCode, Vec<u8>)| -> anyhow::Result<_> {
        Ok((status, serde_json::from_slice::<Value>(&bytes).with_context(|| {
            format!("{status}: {}", String::from_utf8_lossy(&bytes))
        })?))
    };
    Ok(RaceResult {
        first: decode(a.await??)?,
        second: decode(b.await??)?,
    })
}

// ===========================================================================
// C08 — admission policy through the real relationship projection path
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_block_and_preference_denials_use_real_projection() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let labels = [
        "c08-blk-a2b",
        "c08-blk-b2a",
        "c08-lst-a2b",
        "c08-lst-b2a",
        "c08-in-none",
        "c08-in-follow-no",
        "c08-in-follow-ok",
    ];
    let alice_id = identity("alice", &run);
    let ids: Vec<ServiceIdentity> = labels.iter().map(|l| identity(l, &run)).collect();
    let mut all: Vec<&ServiceIdentity> = ids.iter().collect();
    all.push(&alice_id);
    let rig = rig(&all).await?;
    let alice = Account::new(alice_id.clone(), "c08-alice")?;
    let bobs = ids
        .iter()
        .zip(labels)
        .map(|(id, label)| Account::new(id.clone(), label))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for bob in &bobs {
        publish_keys(&rig, bob).await?;
    }
    let root = &rig.https.root;
    let a = alice.did();
    let [direct_actor, direct_recipient, list_actor, list_recipient, none, following, control] =
        &bobs[..]
    else {
        unreachable!()
    };
    // alice blocks bob: bob's view of alice is blockedBy.
    set_recipient_view(root, direct_actor.did(), a,
        json!({"blockedBy":record_uri(a, "app.bsky.graph.block")}))?;
    // bob blocks alice.
    set_recipient_view(root, direct_recipient.did(), a,
        json!({"blocking":record_uri(direct_recipient.did(), "app.bsky.graph.block")}))?;
    // alice blocks bob through a moderation list.
    set_recipient_view(root, list_actor.did(), a,
        json!({"blockedByList":record_uri(a, "app.bsky.graph.list")}))?;
    // bob blocks alice through a moderation list.
    set_recipient_view(root, list_recipient.did(), a,
        json!({"blockingByList":record_uri(list_recipient.did(), "app.bsky.graph.list")}))?;
    set_incoming(root, none.did(), "none")?;
    set_incoming(root, following.did(), "following")?;
    // Control: identical path, recipient requires following and does follow alice.
    set_incoming(root, control.did(), "following")?;
    set_recipient_view(root, control.did(), a,
        json!({"following":record_uri(control.did(), "app.bsky.graph.follow")}))?;

    for (bob, scenario) in bobs[..6].iter().zip(labels) {
        let prep = prepare(&rig, &alice, bob.did()).await?;
        expect_rejected(&rig, prep.status, &prep.response, "RequestPolicyDenied")
            .with_context(|| scenario.to_owned())?;
        anyhow::ensure!(attempt_status(prep.request_id)? == "rejected", "{scenario}");
        anyhow::ensure!(
            count(&format!(
                "SELECT count(*) FROM chat.direct_request_selected_devices WHERE request_id='{}'",
                prep.request_id
            ))? == 0,
            "{scenario}: no device reservation after policy denial"
        );
        anyhow::ensure!(request_rows(prep.request_id, prep.conversation_id)? == NO_ROWS, "{scenario}");
        println!("C08 {scenario}: prepare -> RequestPolicyDenied, attempt rejected, zero reservation/publication rows");
    }

    let prep = prepare(&rig, &alice, control.did()).await?;
    let selected = prep.selected_device_ids()?;
    anyhow::ensure!(selected == BTreeSet::from([control.svc.device_id.to_string()]));
    // The admitted decision persisted the real fallback projection carrying the
    // fixture's follow edge (evidence the same collection path ran).
    anyhow::ensure!(
        count(&format!(
            "SELECT count(*) FROM chat.relationship_projection_relationships r \
             JOIN chat.relationship_projection_snapshots s USING(projection_id) \
             WHERE s.operation_scope='directRequestPreparation' AND r.actor_did='{}' AND r.other_did='{a}' \
             AND r.following AND NOT (r.blocking OR r.blocked_by OR r.blocking_by_list OR r.blocked_by_list)",
            control.did()
        ))? >= 1,
        "admitted control did not persist its relationship projection"
    );
    let (publication, bootstrap) = build_publication(&rig, &alice, control.did(), &prep)?;
    let (status, response) =
        post(&rig, &alice.svc, "blue.catbird.chat.publishDirectRequest", &publication).await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{status}: {response}");
    anyhow::ensure!(receipt(&rig, &response)?.0 == "directRequestPublishedReceipt");
    println!("C08 control (following + followed): prepare admitted, projection persisted, published");
    release_by_accept(&rig, (&control.engine, &control.identity, &control.svc), &alice, &prep, &bootstrap).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_publish_time_policy_recheck_denies_after_preparation() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let alice_id = identity("alice", &run);
    let block_id = identity("c08-rc-block", &run);
    let none_id = identity("c08-rc-none", &run);
    let rig = rig(&[&alice_id, &block_id, &none_id]).await?;
    let alice = Account::new(alice_id, "c08-alice")?;
    let blocked = Account::new(block_id, "c08-rc-block")?;
    let disabled = Account::new(none_id, "c08-rc-none")?;
    publish_keys(&rig, &blocked).await?;
    publish_keys(&rig, &disabled).await?;
    let mut pending = Vec::new();
    for bob in [&blocked, &disabled] {
        let prep = prepare(&rig, &alice, bob.did()).await?;
        let (publication, _) = build_publication(&rig, &alice, bob.did(), &prep)?;
        pending.push((bob, prep, publication));
    }
    // Policy changes after reservation, before publication.
    set_recipient_view(&rig.https.root, blocked.did(), alice.did(),
        json!({"blocking":record_uri(blocked.did(), "app.bsky.graph.block")}))?;
    set_incoming(&rig.https.root, disabled.did(), "none")?;
    // The admission projection is reused for 60s (`load_fallback_relationship_projection`);
    // publish after it ages out so the recheck collects the changed evidence.
    tokio::time::sleep(Duration::from_secs(62)).await;
    for (bob, prep, publication) in &pending {
        let (status, response) =
            post(&rig, &alice.svc, "blue.catbird.chat.publishDirectRequest", publication).await?;
        expect_rejected(&rig, status, &response, "RequestPolicyDenied")
            .with_context(|| bob.did().to_owned())?;
        anyhow::ensure!(attempt_status(prep.request_id)? == "rejected");
        anyhow::ensure!(request_rows(prep.request_id, prep.conversation_id)? == NO_ROWS);
        let reserved: String = psql(&format!(
            "SELECT string_agg(status,',') FROM chat.key_packages WHERE owner_did='{}'",
            bob.did()
        ))?;
        println!(
            "C08 publish-time recheck {}: publish -> RequestPolicyDenied, attempt rejected, zero publication rows, recipient packages [{reserved}]",
            bob.did()
        );
    }
    Ok(())
}

// ===========================================================================
// C08 — concurrent authority mutation vs publication (both orderings)
// ===========================================================================

async fn grant_disable_race(mutation_first: bool) -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let alice_id = identity("alice", &run);
    let bob_id = identity("c08-grant-race", &run);
    let rig = rig(&[&alice_id, &bob_id]).await?;
    let alice = Account::new(alice_id, "c08-alice")?;
    let bob = Account::new(bob_id, "c08-grant-race")?;
    publish_keys(&rig, &bob).await?;
    let prep = prepare(&rig, &alice, bob.did()).await?;
    let (publication, bootstrap) = build_publication(&rig, &alice, bob.did(), &prep)?;
    let disable = (
        &bob.svc,
        "blue.catbird.chat.publishDirectRequestKeys",
        keys_envelope(&bob, 2, false)?,
    );
    let publish = (&alice.svc, "blue.catbird.chat.publishDirectRequest", publication);
    let label = if mutation_first { "grant-disable-first" } else { "publish-first/grant-disable" };
    let result = if mutation_first {
        race(&rig, Barrier::hold(bob.did())?, disable, publish, label).await?
    } else {
        race(&rig, Barrier::hold(bob.did())?, publish, disable, label).await?
    };
    let (disable_result, publish_result) = if mutation_first {
        (result.first, result.second)
    } else {
        (result.second, result.first)
    };
    let published = publish_result.0 == reqwest::StatusCode::OK
        && receipt(&rig, &publish_result.1)?.0 == "directRequestPublishedReceipt";
    if published {
        release_by_accept(&rig, (&bob.engine, &bob.identity, &bob.svc), &alice, &prep, &bootstrap).await?;
    }
    anyhow::ensure!(
        disable_result.0 == reqwest::StatusCode::OK && disable_result.1["enabled"] == false,
        "disable {}: {}",
        disable_result.0,
        disable_result.1
    );
    let grant_revoked = count(&format!(
        "SELECT count(*) FROM chat.direct_request_grants WHERE owner_did='{}' AND revoked_at IS NOT NULL",
        bob.did()
    ))?;
    anyhow::ensure!(grant_revoked == 1, "grant disable must revoke the selected grant");
    let rows = request_rows(prep.request_id, prep.conversation_id)?;
    if mutation_first {
        expect_rejected(&rig, publish_result.0, &publish_result.1, "PreparationRevoked")?;
        anyhow::ensure!(rows == NO_ROWS, "{rows:?}");
        println!("C08 {label}: disable committed first; publish -> PreparationRevoked; rows {rows:?}");
    } else {
        anyhow::ensure!(publish_result.0 == reqwest::StatusCode::OK, "{}", publish_result.1);
        anyhow::ensure!(receipt(&rig, &publish_result.1)?.0 == "directRequestPublishedReceipt");
        anyhow::ensure!(rows.publications == 1 && rows.deliveries == 1 && rows.published_attempts == 1);
        // The published delivery is bound to the grant that was live when the
        // publication committed; the disable was serialized after it.
        let authorized = count(&format!(
            "SELECT count(*) FROM chat.direct_request_device_deliveries d \
             JOIN chat.direct_request_grants g ON g.grant_id=d.grant_id AND g.revision=d.grant_revision \
             JOIN chat.direct_request_publications p ON p.request_id=d.request_id \
             WHERE d.request_id='{}' AND g.revoked_at > p.created_at",
            prep.request_id
        ))?;
        anyhow::ensure!(authorized == 1, "published delivery references a grant revoked before publication");
        println!("C08 {label}: publish committed first with live grant; disable serialized after; rows {rows:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_grant_disable_race_disable_first() -> anyhow::Result<()> {
    grant_disable_race(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_grant_disable_race_publish_first() -> anyhow::Result<()> {
    grant_disable_race(false).await
}

async fn device_revoke_race(mutation_first: bool) -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let alice_id = identity("alice", &run);
    let bob_id = identity("c08-rv-race", &run);
    let rig = rig(&[&alice_id, &bob_id]).await?;
    let alice = Account::new(alice_id, "c08-alice")?;
    let bob = Account::new(bob_id, "c08-rv-race")?;
    publish_keys(&rig, &bob).await?;
    let sibling = siblings::enroll(&bob.svc, &rig.client, &rig.server.base_url).await?;
    let prep = prepare(&rig, &alice, bob.did()).await?;
    anyhow::ensure!(
        prep.selected_device_ids()?
            == BTreeSet::from([bob.svc.device_id.to_string(), sibling.service.device_id.to_string()])
    );
    let (publication, bootstrap) = build_publication(&rig, &alice, bob.did(), &prep)?;
    let revoke = (
        &sibling.service,
        "blue.catbird.chat.revokeDevice",
        revoke_envelope(&sibling, bob.svc.device_id)?,
    );
    let publish = (&alice.svc, "blue.catbird.chat.publishDirectRequest", publication);
    let label = if mutation_first { "revoke-first" } else { "publish-first/revoke" };
    // Principal-only barrier: both transactions queue on their first identity
    // lock, the revocation only after its lock-free G6 scope discovery. Queue
    // order is therefore commit order, and in publish-first the revocation's
    // discovery provably predates the publication's commit, so its locked
    // rediscovery must see the new conversation (G6 DiscoveryDrift, F18).
    let barrier = Barrier::hold_principal(bob.did())?;
    let result = if mutation_first {
        race(&rig, barrier, revoke, publish, label).await?
    } else {
        race(&rig, barrier, publish, revoke, label).await?
    };
    let (revoke_result, publish_result) = if mutation_first {
        (result.first, result.second)
    } else {
        (result.second, result.first)
    };
    let published = publish_result.0 == reqwest::StatusCode::OK
        && receipt(&rig, &publish_result.1)?.0 == "directRequestPublishedReceipt";
    // Target's interval/leaf in the request conversation, read before the
    // release by acceptance can touch the conversation.
    let target_access = psql(&format!(
        "SELECT (SELECT count(*) FROM chat.application_intervals WHERE conversation_id='{c}' \
                 AND recipient_did='{d}' AND recipient_device_id='{v}' AND terminal_seq IS NULL)||','|| \
                (SELECT count(*) FROM chat.member_devices WHERE conversation_id='{c}' \
                 AND user_did='{d}' AND device_id='{v}' AND active)",
        c = prep.conversation_id,
        d = bob.did(),
        v = bob.svc.device_id
    ))?;
    if published {
        release_by_accept(
            &rig,
            (&sibling.engine, &sibling.identity, &sibling.service),
            &alice,
            &prep,
            &bootstrap,
        )
        .await?;
    }
    anyhow::ensure!(
        revoke_result.0 == reqwest::StatusCode::OK,
        "revokeDevice {}: {}",
        revoke_result.0,
        revoke_result.1
    );
    let revoked = psql(&format!(
        "SELECT d.status||','||(k.revoked_at IS NOT NULL) FROM chat.devices d JOIN chat.device_keys k USING(user_did,device_id) \
         WHERE d.user_did='{}' AND d.device_id='{}'",
        bob.did(),
        bob.svc.device_id
    ))?;
    anyhow::ensure!(revoked == "revoked,true", "target not revoked: {revoked}");
    let rows = request_rows(prep.request_id, prep.conversation_id)?;
    if mutation_first {
        expect_rejected(&rig, publish_result.0, &publish_result.1, "PreparationRevoked")?;
        anyhow::ensure!(rows == NO_ROWS, "{rows:?}");
        // The preparation-held (Reserved, no recovery reservation) request
        // package is retired by the revocation itself (F25).
        let packages = request_packages_revoked(bob.did(), bob.svc.device_id)?;
        println!("C08/C09 {label}: included device revoked first; publish -> PreparationRevoked; rows {rows:?}; request packages total,revoked-by-revocation={packages}");
    } else {
        // Publication rejects a revoked included device (revoke-first arm), so
        // its success proves it committed while the target was still active.
        anyhow::ensure!(published, "{}", publish_result.1);
        anyhow::ensure!(rows.publications == 1 && rows.deliveries == 2, "{rows:?}");
        // G6 revocation is immediate authority state; it never fabricates an
        // MLS Remove or closes an application interval (state_machine.rs
        // plan_device_revocation_inner). Closing is a later Remove commit.
        anyhow::ensure!(
            target_access == "1,1",
            "revoked device's request interval/leaf changed by revocation: {target_access}"
        );
        println!(
            "C08 {label}: publish committed first; revocation discovered scope before it, rediscovered after, \
             retried and committed; target interval+leaf open/active={target_access}; rows {rows:?}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_included_device_revoke_race_revoke_first() -> anyhow::Result<()> {
    device_revoke_race(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c08_live_included_device_revoke_race_publish_first() -> anyhow::Result<()> {
    device_revoke_race(false).await
}

/// `total,revoked-by-this-revocation` for the device's request-scope packages;
/// fails unless every one is Revoked bound to the device's revocation row.
fn request_packages_revoked(did: &str, device: Uuid) -> anyhow::Result<String> {
    let packages = psql(&format!(
        "SELECT count(*)||','||count(*) FILTER (WHERE p.status='revoked' AND p.terminal_revocation_id=r.revocation_id \
                AND p.terminal_at=r.accepted_at) \
           FROM chat.key_packages p JOIN chat.device_revocations r \
             ON r.target_did=p.owner_did AND r.target_device_id=p.owner_device_id \
          WHERE p.owner_did='{did}' AND p.owner_device_id='{device}' AND p.usage_scope='direct-request'"
    ))?;
    let (total, revoked) = packages.split_once(',').context("package projection")?;
    anyhow::ensure!(total != "0" && total == revoked, "request packages not all revoked: {packages}");
    Ok(packages)
}

/// F25 wider case: a device that disabled its request keys (packages retired
/// to Reserved without any preparation) can still be revoked, and the
/// revocation retires those packages.
#[tokio::test(flavor = "multi_thread")]
async fn c08_live_revoke_device_with_retired_request_packages() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let bob_id = identity("c08-rv-retired", &run);
    let rig = rig(&[&bob_id]).await?;
    let bob = Account::new(bob_id, "c08-rv-retired")?;
    publish_keys(&rig, &bob).await?;
    let sibling = siblings::enroll(&bob.svc, &rig.client, &rig.server.base_url).await?;
    let (status, body) = post(
        &rig,
        &bob.svc,
        "blue.catbird.chat.publishDirectRequestKeys",
        &keys_envelope(&bob, 2, false)?,
    )
    .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK && body["enabled"] == false, "disable {status}: {body}");
    let retired = count(&format!(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did='{}' AND owner_device_id='{}' \
         AND usage_scope='direct-request' AND status='reserved'",
        bob.did(),
        bob.svc.device_id
    ))?;
    anyhow::ensure!(retired > 0, "disable left no retired request packages");
    let (status, body) = post(
        &rig,
        &sibling.service,
        "blue.catbird.chat.revokeDevice",
        &revoke_envelope(&sibling, bob.svc.device_id)?,
    )
    .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "revokeDevice {status}: {body}");
    let packages = request_packages_revoked(bob.did(), bob.svc.device_id)?;
    println!("C08 retired-packages revoke: {retired} retired request packages; revoke 200; total,revoked-by-revocation={packages}");
    Ok(())
}

// ===========================================================================
// C09 — device coverage
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c09_live_snapshot_includes_every_deliverable_device_and_ignores_unrelated_enrollment(
) -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let alice_id = identity("alice", &run);
    let bob_id = identity("c09-bob", &run);
    let carol_id = identity("c09-carol", &run);
    let rig = rig(&[&alice_id, &bob_id, &carol_id]).await?;
    let alice = Account::new(alice_id, "c09-alice")?;
    let bob = Account::new(bob_id, "c09-bob")?;
    let carol = Account::new(carol_id, "c09-carol")?;
    publish_keys(&rig, &bob).await?;
    let bob_sibling = siblings::enroll(&bob.svc, &rig.client, &rig.server.base_url).await?;
    let alice_sibling = siblings::enroll(&alice.svc, &rig.client, &rig.server.base_url).await?;

    let prep = prepare(&rig, &alice, bob.did()).await?;
    let expected = BTreeSet::from([
        bob.svc.device_id.to_string(),
        bob_sibling.service.device_id.to_string(),
        alice_sibling.service.device_id.to_string(),
    ]);
    let selected = prep.selected_device_ids()?;
    anyhow::ensure!(selected == expected, "snapshot {selected:?} != deliverable {expected:?}");
    let reserved: BTreeSet<String> = psql(&format!(
        "SELECT string_agg(owner_device_id::text, ',') FROM chat.direct_request_selected_devices WHERE request_id='{}'",
        prep.request_id
    ))?
    .split(',')
    .map(str::to_owned)
    .collect();
    anyhow::ensure!(reserved == expected, "reserved {reserved:?}");
    println!("C09 snapshot: selected = reserved = {{bob, bob sibling, alice sibling}}; calling device excluded");

    // Enrollment after the snapshot: a new device for the recipient and an
    // unrelated account both publish request keys through the real router.
    let late = siblings::enroll(&bob.svc, &rig.client, &rig.server.base_url).await?;
    publish_keys(&rig, &carol).await?;
    let (publication, bootstrap) = build_publication(&rig, &alice, bob.did(), &prep)?;
    let (status, response) =
        post(&rig, &alice.svc, "blue.catbird.chat.publishDirectRequest", &publication).await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{status}: {response}");
    anyhow::ensure!(receipt(&rig, &response)?.0 == "directRequestPublishedReceipt");
    let delivered: BTreeSet<String> = psql(&format!(
        "SELECT string_agg(owner_device_id::text, ',') FROM chat.direct_request_device_deliveries WHERE request_id='{}'",
        prep.request_id
    ))?
    .split(',')
    .map(str::to_owned)
    .collect();
    anyhow::ensure!(delivered == expected, "delivered {delivered:?}");
    anyhow::ensure!(!delivered.contains(&late.service.device_id.to_string()));
    anyhow::ensure!(request_database_snapshot(prep.request_id)?.welcome_rows == 3);

    // Every included device imports the one Welcome and reads the introduction.
    let mut published = response["outcome"].clone();
    published.as_object_mut().context("outcome")?.remove("$type");
    let publication_request = serde_json::to_vec(&publication["signedRequest"])?;
    for (engine, identity, package_ref) in [
        (&bob.engine, bob.identity.clone(), bob.package_ref.clone()),
        (&bob_sibling.engine, bob_sibling.identity.clone(), bob_sibling.package_ref.clone()),
        (&alice_sibling.engine, alice_sibling.identity.clone(), alice_sibling.package_ref.clone()),
    ] {
        let input = DirectRequestWelcomeInput {
            bootstrap: bootstrap.clone(),
            local_identity: identity.as_bytes().to_vec(),
            local_package_ref: package_ref,
            publication_request: publication_request.clone(),
            actor_signature_public_key: alice.public.clone(),
            published_receipt: serde_json::to_vec(&published)?,
            receipt_authority_key: rig.server.receipt_public_key.clone(),
            preparation_request_digest: prep.prepare_digest,
        };
        engine.process_direct_request(&input)?;
        let DirectRequestIntroductionResult::Ready { plaintext } =
            engine.decrypt_direct_request(&input)?
        else {
            anyhow::bail!("{identity}: introduction unavailable")
        };
        anyhow::ensure!(
            protocol::decode_direct_request_introduction(&plaintext)?["text"]
                == "C08/C09 encrypted first contact"
        );
    }
    release_by_accept(&rig, (&bob.engine, &bob.identity, &bob.svc), &alice, &prep, &bootstrap).await?;
    println!("C09 unrelated enrollment: late recipient device + unrelated account enrolled after snapshot; publish succeeded with exactly the snapshot (3 deliveries), late device excluded; all 3 included devices imported and decrypted");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_live_no_eligible_recipient_emits_no_invitation() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let alice_id = identity("alice", &run);
    let keyless_id = identity("c09-keyless", &run);
    let disabled_id = identity("c09-disabled", &run);
    let rig = rig(&[&alice_id, &keyless_id, &disabled_id]).await?;
    let alice = Account::new(alice_id, "c09-alice")?;
    let keyless = Account::new(keyless_id, "c09-keyless")?;
    let disabled = Account::new(disabled_id, "c09-disabled")?;
    publish_keys(&rig, &disabled).await?;
    let (status, body) = post(
        &rig,
        &disabled.svc,
        "blue.catbird.chat.publishDirectRequestKeys",
        &keys_envelope(&disabled, 2, false)?,
    )
    .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{body}");
    for (bob, scenario) in [(&keyless, "never published keys"), (&disabled, "request keys disabled")] {
        let prep = prepare(&rig, &alice, bob.did()).await?;
        expect_rejected(&rig, prep.status, &prep.response, "RecipientKeysUnavailable")?;
        anyhow::ensure!(attempt_status(prep.request_id)? == "rejected");
        anyhow::ensure!(request_rows(prep.request_id, prep.conversation_id)? == NO_ROWS);
        anyhow::ensure!(
            count(&format!(
                "SELECT count(*) FROM chat.participants WHERE user_did='{}'",
                bob.did()
            ))? == 0,
            "no invitation/participant for {scenario}"
        );
        let mut signed = prep.response["outcome"].clone();
        signed.as_object_mut().context("receipt")?.remove("$type");
        let fields: BTreeSet<&str> = signed["body"]["receipt"]
            .as_object()
            .context("receipt fields")?
            .keys()
            .map(String::as_str)
            .collect();
        println!("C09 no eligible recipient ({scenario}): prepare -> signed RecipientKeysUnavailable receipt, attempt rejected, zero conversation/publication/delivery/participant rows; receipt fields {fields:?}");
    }
    Ok(())
}


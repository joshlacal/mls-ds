//! C25: inventory/event scope, against the live shipping router and guarded DB.
//!
//! One owner device receives three real direct requests (three distinct
//! senders, real prepare/bootstrap/publish), so its scoped inventory has three
//! conversation items and three pending Welcomes. With `limit=1` every domain
//! pages through real continuation cursors. Asserted:
//! - every page of all three domains carries the same inventory session,
//!   snapshot event cursor, expiry and `inventoryScope` ([1,2] + digest);
//! - continuations with a changed scope, changed limit, or another domain's
//!   cursor are refused with the typed `InventorySessionMismatch`;
//! - `getSubscriptionTicket` (POST + JSON body) with the scope-[1,2] cursor
//!   succeeds, and reusing that cursor under another scope, without scope, or
//!   against another session is refused with `InventorySessionMismatch`;
//! - `subscribeEvents` (real WebSocket upgrade handshake over TCP): a ticket
//!   minted under one scope is refused (`InvalidTicket`) with the other
//!   scope's cursor, upgrades (101) with its own, and is one-use;
//! - real core sync (`MLSOrchestrator::ingest_authenticated_inventory_snapshot`)
//!   over the exact server pages, with and without one unknown inventory item
//!   next to the valid ones. The observed behaviour is recorded as-is.
//! Every published request is accepted at the end (capacity hygiene).

#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::{
        authenticated_inventory::AuthenticatedInventorySnapshot,
        direct_request_bootstrap::{metadata_coordinate, DirectRequestBootstrapInput},
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    reviewed_request_migrations, seed_service_device, signed_mls_request, HttpsDidFixture,
    ServiceIdentity, ShippingServerFixture,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const CONVERSATIONS: &str = "blue.catbird.chat.getConversations";
const WELCOMES: &str = "blue.catbird.chat.getPendingWelcomes";
const RECOVERY: &str = "blue.catbird.chat.getLeafRecoveryInbox";
const TICKET: &str = "blue.catbird.chat.getSubscriptionTicket";
const SENDERS: usize = 3;

struct Party {
    svc: ServiceIdentity,
    engine: MlsEngine,
    identity: String,
    public: Vec<u8>,
    key_id: String,
}

impl Party {
    fn new(svc: ServiceIdentity, label: &str) -> anyhow::Result<Self> {
        let engine = MlsEngine::new(label)?;
        let identity = format!("{}#{}", svc.did, svc.device_id);
        engine.create_key_package(&identity)?;
        let public = engine.identity_public_key(&identity)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        seed_service_device(&svc, &public)?;
        Ok(Self { svc, engine, identity, public, key_id })
    }
}

struct Published {
    request_id: Uuid,
    conversation_id: Uuid,
    coordinates: Value,
    sender: usize,
}

struct World {
    owner: Party,
    senders: Vec<Party>,
    published: Vec<Published>,
    server: ShippingServerFixture,
    client: reqwest::Client,
    _https: HttpsDidFixture,
}

fn key_entry(p: &Party) -> anyhow::Result<Value> {
    let (package, reference) = p.engine.create_key_package(&p.identity)?;
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(&p.engine, &p.identity, DirectRequestKind::Grant, json!({
        "$type":"blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
        "actorDid":p.svc.did,"actorDeviceId":p.svc.device_id.to_string(),"keyId":p.key_id,
        "authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
        "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
        "keyPackageRef":STANDARD.encode(&reference),
        "keyPackageSha256":STANDARD.encode(Sha256::digest(&package)),
        "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),
        "signedAt":canonical_now()
    }))?;
    Ok(json!({"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
        "bytes":STANDARD.encode(&package),"sha256":STANDARD.encode(Sha256::digest(&package)),
        "keyPackageRef":STANDARD.encode(&reference)},"grant":grant}))
}

async fn post(w: &World, who: &ServiceIdentity, nsid: &str, body: &Value) -> anyhow::Result<(StatusCode, Value)> {
    let (status, bytes) = who.post(&w.client, &w.server.base_url, nsid, body, true).await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{nsid} {status}: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, value))
}

/// Real preparation, native bootstrap and signed publication sender -> owner.
async fn publish(w: &World, sender: usize) -> anyhow::Result<Published> {
    let s = &w.senders[sender];
    let owner = &w.owner.svc;
    let (request_id, first_message_id, conversation_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let prepare = signed_mls_request(&s.engine, &s.identity, DirectRequestKind::Prepare, json!({
        "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
        "actorDid":s.svc.did,"actorDeviceId":s.svc.device_id.to_string(),"keyId":s.key_id,
        "authGeneration":1,"requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),"conversationId":conversation_id.to_string(),
        "recipientDid":owner.did,"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "profile":"encryptedIntroduction1","idempotencyKey":request_id.to_string(),
        "signedAt":canonical_now()
    }))?;
    let (status, response) = post(w, &s.svc, "blue.catbird.chat.prepareDirectRequest", &json!({"signedRequest":prepare})).await?;
    anyhow::ensure!(status == StatusCode::OK, "prepare {status}: {response}");
    let snapshot = response.pointer("/outcome/preparation").filter(|v| !v.is_null()).cloned()
        .with_context(|| format!("no live preparation: {response}"))?;
    protocol::verify_direct_request_preparation(&serde_json::to_vec(&snapshot)?, &w.server.receipt_public_key)?;
    let verified = protocol::verify_signed_request(DirectRequestKind::Prepare, &serde_json::to_vec(&prepare)?, &s.public)?;
    let selected = snapshot["selectedDevices"].as_array().context("selectedDevices")?;
    anyhow::ensure!(selected.len() == 1 && selected[0]["actorDeviceId"] == owner.device_id.to_string(),
        "preparation must select exactly the owner device: {selected:?}");
    let minimum_import_until = u64::try_from(chrono::DateTime::parse_from_rfc3339(
        snapshot["minimumImportUntil"].as_str().context("minimumImportUntil")?)?.timestamp())?;
    let mut authority_import_until = u64::MAX;
    for device in selected {
        let grant = protocol::verify_signed_request(DirectRequestKind::Grant,
            &serde_json::to_vec(&device["grant"])?, &w.owner.public)?;
        let expires_at = u64::try_from(chrono::DateTime::parse_from_rfc3339(
            grant.body()["expiresAt"].as_str().context("selected grant expiresAt")?)?.timestamp())?;
        authority_import_until = authority_import_until.min(expires_at);
    }
    anyhow::ensure!(authority_import_until >= minimum_import_until,
        "selected grant expires before preparation import floor");
    let bytes_of = |d: &Value, k: &str| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(d["keyPackage"][k].as_str().context("package field")?)?)
    };
    let context = json!({
        "protocolVersion":"2","requestId":request_id.to_string(),"firstMessageId":first_message_id.to_string(),
        "conversationId":conversation_id.to_string(),"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":s.svc.did,"actorDeviceId":s.svc.device_id.to_string(),"actorKeyId":s.key_id,
        "recipientDid":owner.did,"preparationDigest":snapshot["preparationDigest"]
    });
    let journal = s.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected.iter().map(|d| bytes_of(d, "bytes")).collect::<anyhow::Result<_>>()?,
        expected_package_refs: selected.iter().map(|d| bytes_of(d, "keyPackageRef")).collect::<anyhow::Result<_>>()?,
        authority_import_until,
        preparation_request_digest: *verified.request_digest(),
        receipt_authority_key: w.server.receipt_public_key.clone(),
        text: format!("C25 introduction {sender}"),
        invitation: None,
        metadata: GroupMetadataV1 { version: 1, title: String::new(), description: String::new(), avatar_blob_locator: None, avatar_content_type: None },
    })?;
    let b = &journal.bootstrap;
    let mut body = prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = snapshot["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(b.context_hash));
    body["next"] = b.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(b.import_until as i64, 0)
        .context("import")?.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], kind: &str| json!({"framing":"mlsMessage","contentType":kind,
        "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))});
    let deliveries = selected.iter().map(|d| json!({"recipientDid":d["actorDid"],"recipientDeviceId":d["actorDeviceId"],
        "provenance":{"requestId":request_id.to_string(),"preparationDigest":snapshot["preparationDigest"],
        "contextHash":STANDARD.encode(b.context_hash),"grantId":d["grant"]["body"]["grantId"],
        "grantRevision":d["grant"]["body"]["grantRevision"],"keyPackageRef":d["keyPackage"]["keyPackageRef"],
        "importUntil":body["importUntil"]}})).collect::<Vec<_>>();
    let author = json!({"authorDid":s.svc.did,"authorDeviceId":s.svc.device_id.to_string(),"authorKeyId":s.key_id,
        "signaturePublicKey":STANDARD.encode(&s.public),"authGenerationAtOrigin":1,
        "originTransitionId":request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"});
    body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&b.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&b.initial_ciphertext),
        "metadataSnapshot":{"coordinate":metadata_coordinate(&b.coordinates)?,"originTransitionId":request_id.to_string(),
            "metadataVersion":1,"nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),
            "ciphertextSize":b.metadata_ciphertext.len(),"authorProof":author}
    });
    let publication = signed_mls_request(&s.engine, &s.identity, DirectRequestKind::Publish, body)?;
    let (status, published) = post(w, &s.svc, "blue.catbird.chat.publishDirectRequest", &json!({"signedRequest":publication})).await?;
    anyhow::ensure!(status == StatusCode::OK, "publish {status}: {published}");
    anyhow::ensure!(
        published["outcome"]["body"]["receipt"]["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt",
        "publication was not a fresh published receipt: {published}"
    );
    Ok(Published { request_id, conversation_id, coordinates: b.coordinates.clone(), sender })
}

async fn world() -> anyhow::Result<World> {
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(authority.additive_migrations, reviewed_request_migrations().len());
    let run = Uuid::new_v4().simple().to_string();
    let host = |role: &str| format!("did:web:{role}-{run}.request-fixture.catbird.blue");
    let owner_svc = ServiceIdentity::new(host("c25owner"));
    let sender_svcs: Vec<_> = (0..SENDERS).map(|i| ServiceIdentity::new(host(&format!("c25sender{i}")))).collect();
    let mut docs = vec![(owner_svc.did.clone(), owner_svc.did_document())];
    docs.extend(sender_svcs.iter().map(|s| (s.did.clone(), s.did_document())));
    let https = HttpsDidFixture::start(HttpsDidFixture::reserve_port()?, &docs)?;
    let owner = Party::new(owner_svc, "c25-owner")?;
    let senders = sender_svcs.into_iter().enumerate()
        .map(|(i, s)| Party::new(s, &format!("c25-sender{i}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let server = ShippingServerFixture::start(&https)?;
    let mut w = World { owner, senders, published: Vec::new(), server, client: reqwest::Client::new(), _https: https };

    // The owner publishes one request-only package per sender (revision 1).
    let keys = (0..SENDERS).map(|_| key_entry(&w.owner)).collect::<anyhow::Result<Vec<_>>>()?;
    let signed = signed_mls_request(&w.owner.engine, &w.owner.identity, DirectRequestKind::Keys, json!({
        "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
        "actorDid":w.owner.svc.did,"actorDeviceId":w.owner.svc.device_id.to_string(),"keyId":w.owner.key_id,
        "authGeneration":1,"revision":1,"enabled":true,"keys":keys,
        "idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
    }))?;
    let (status, body) = post(&w, &w.owner.svc, "blue.catbird.chat.publishDirectRequestKeys", &json!({"signedRequest":signed})).await?;
    anyhow::ensure!(status == StatusCode::OK, "owner keys {status}: {body}");
    for i in 0..SENDERS {
        match publish(&w, i).await {
            Ok(p) => w.published.push(p),
            Err(error) => {
                // Capacity hygiene: never leave earlier publications open.
                let released = accept_all(&w).await;
                return Err(error.context(format!(
                    "publication {i} failed; released {} earlier publication(s): {released:?}", w.published.len())));
            }
        }
    }
    Ok(w)
}

/// Release every published request (capacity hygiene) through real signed
/// acceptance. Attempts all of them, then reports every refusal.
async fn accept_all(w: &World) -> anyhow::Result<()> {
    let mut refused = Vec::new();
    for p in &w.published {
        if let Err(error) = accept_one(w, p).await {
            refused.push(format!("{}: {error:#}", p.request_id));
        }
    }
    anyhow::ensure!(refused.is_empty(), "release refused: {}", refused.join("; "));
    Ok(())
}

async fn accept_one(w: &World, p: &Published) -> anyhow::Result<()> {
    let s = &w.senders[p.sender];
    let transition = Uuid::new_v4();
    let mut next = p.coordinates.clone();
    next["stateVersion"] = json!(p.coordinates["stateVersion"].as_u64().context("state version")? + 1);
    let signed = signed_mls_request(&w.owner.engine, &w.owner.identity, DirectRequestKind::Accept, json!({
        "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0","protocolVersion":"2",
        "actorDid":w.owner.svc.did,"actorDeviceId":w.owner.svc.device_id.to_string(),"keyId":w.owner.key_id,
        "authGeneration":1,"requestId":p.request_id.to_string(),"transitionId":transition.to_string(),
        "prior":p.coordinates,"next":next,
        "invitationProvenance":{"invitationTransitionId":p.request_id.to_string(),
            "invitedByDid":s.svc.did,"invitedByDeviceId":s.svc.device_id.to_string()},
        "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
    }))?;
    let (status, body) = post(w, &w.owner.svc, "blue.catbird.chat.acceptConversation", &json!({"directRequest":signed})).await?;
    anyhow::ensure!(status == StatusCode::OK, "release accept {status}: {body}");
    Ok(())
}

async fn read(
    w: &World, nsid: &str, limit: u16, versions: &[&str], session: Option<&str>, cursor: Option<&str>,
) -> anyhow::Result<(StatusCode, Value, Vec<u8>)> {
    let mut params = vec![("limit".to_owned(), limit.to_string())];
    params.extend(versions.iter().map(|v| ("supportedProtocolVersions".to_owned(), (*v).to_owned())));
    if let Some(s) = session { params.push(("inventorySessionId".to_owned(), s.to_owned())); }
    if let Some(c) = cursor { params.push(("pageCursor".to_owned(), c.to_owned())); }
    let (status, raw) = w.owner.svc.get(&w.client, &w.server.base_url, nsid, &params).await?;
    let value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    Ok((status, value, raw))
}

fn typed(status: StatusCode, body: &Value, code: &str, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: expected 400 {code}, got {status} {body}");
    assert_eq!(body["error"], code, "{what}: typed error code: {body}");
    println!("C25 rejected [{what}] -> {status} {}", body["error"]);
}
/// Strict rejection check: must be 400 with the typed code. Until OQ-11 is
/// fixed (InventorySessionMismatch undeclared on getConversations so the
/// handler downgrades it to a 500), this records the failure and carries on
/// so every later clause still runs; the test then fails on the summary.
fn rejected(status: StatusCode, body: &Value, code: &str, what: &str, failures: &mut Vec<String>) {
    if status == StatusCode::BAD_REQUEST && body["error"] == code {
        println!("C25 rejected [{what}] -> {status} {}", body["error"]);
    } else {
        let detail = format!("{what}: expected 400 {code}, got {status} {} {body}", body["error"]);
        if status == StatusCode::INTERNAL_SERVER_ERROR && body["error"] == "InternalServerError" {
            println!("C25 FAILURE [OQ-11] [{what}] -> {status} (InventorySessionMismatch undeclared on getConversations; downgraded to InternalServerError)");
        }
        failures.push(detail);
    }
}

/// Fence fields every page of one session must repeat byte-for-byte.
fn fence(page: &Value) -> Value {
    json!({"session":page["inventorySessionId"],"cursor":page["snapshotEventCursor"],
        "expires":page["snapshotExpiresAt"],"scope":page["inventoryScope"]})
}

struct Paged { pages: Vec<Vec<u8>>, items: Vec<Value>, fence: Value }

/// Page one domain to completion; every page must repeat the same fence.
/// `Ok(None)` only for the one transient the shared DB can produce: another
/// run's event made this session stale, so the server re-materialized it.
async fn page_all(w: &World, nsid: &str, limit: u16, versions: &[&str], session: Option<&str>) -> anyhow::Result<Option<Paged>> {
    let (mut pages, mut items, mut first_fence, mut cursor) = (Vec::new(), Vec::new(), None::<Value>, None::<String>);
    loop {
        let (status, page, raw) = read(w, nsid, limit, versions, session, cursor.as_deref()).await?;
        if status == StatusCode::BAD_REQUEST && page["error"] == "InventorySessionMismatch" && cursor.is_none() && session.is_some() {
            println!("C25 transient: {nsid} session re-materialized by a concurrent event; restarting");
            return Ok(None);
        }
        anyhow::ensure!(status == StatusCode::OK, "{nsid} page {} {status}: {page}", pages.len() + 1);
        let f = fence(&page);
        match &first_fence {
            None => first_fence = Some(f),
            Some(expected) => assert_eq!(&f, expected, "{nsid} page {} changed the bound fence", pages.len() + 1),
        }
        let rows = page["items"].as_array().context("items")?;
        assert!(rows.len() <= limit as usize, "{nsid} page exceeds limit");
        items.extend(rows.iter().cloned());
        pages.push(raw);
        let next = page["nextPageCursor"].as_str().map(str::to_owned);
        assert_eq!(page["hasMore"].as_bool(), Some(next.is_some()), "{nsid} hasMore/nextPageCursor disagree");
        match next { Some(n) => cursor = Some(n), None => break }
    }
    Ok(Some(Paged { pages, items, fence: first_fence.context("no page")? }))
}

struct Session { id: String, conversations: Paged, welcomes: Paged, recovery: Paged }

/// Open one scoped session and consume all three domains to their final page.
async fn scoped_session(w: &World, limit: u16, versions: &[&str]) -> anyhow::Result<Session> {
    for attempt in 1..=6 {
        let Some(conversations) = page_all(w, CONVERSATIONS, limit, versions, None).await? else { continue };
        let id = conversations.fence["session"].as_str().context("inventorySessionId")?.to_owned();
        let Some(welcomes) = page_all(w, WELCOMES, limit, versions, Some(&id)).await? else { continue };
        let Some(recovery) = page_all(w, RECOVERY, limit, versions, Some(&id)).await? else { continue };
        println!("C25 scoped session {versions:?} limit={limit} ready on attempt {attempt}");
        return Ok(Session { id, conversations, welcomes, recovery });
    }
    anyhow::bail!("scoped session never stabilized across six attempts")
}

async fn mint(w: &World, session: &str, cursor: &str, versions: Option<&[&str]>) -> anyhow::Result<(StatusCode, Value)> {
    let mut body = json!({"actorDeviceId":w.owner.svc.device_id.to_string(),"inventorySessionId":session,"eventCursor":cursor});
    if let Some(v) = versions { body["supportedProtocolVersions"] = json!(v); }
    post(w, &w.owner.svc, TICKET, &body).await
}

/// A real RFC 6455 upgrade request over TCP. Returns the status code and, for
/// a refused upgrade, the JSON body.
async fn subscribe(w: &World, cursor: &str, ticket: &str) -> anyhow::Result<(u16, Value)> {
    let authority = w.server.base_url.strip_prefix("http://").context("plain loopback fixture")?;
    let mut stream = tokio::net::TcpStream::connect(authority).await?;
    let request = format!(
        "GET /xrpc/blue.catbird.chat.subscribeEvents?cursor={cursor}&ticket={ticket} HTTP/1.1\r\n\
         Host: {authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n",
        STANDARD.encode(rand::random::<[u8; 16]>())
    );
    stream.write_all(request.as_bytes()).await?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut chunk)).await??;
        anyhow::ensure!(n > 0, "subscribeEvents closed before response head");
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") { break i + 4; }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let status: u16 = head.split_whitespace().nth(1).context("status")?.parse()?;
    if status == 101 { return Ok((status, Value::Null)); }
    let length: usize = head.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_owned()))
        .context("content-length")?.parse()?;
    while buffer.len() < head_end + length {
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "truncated refusal body");
        buffer.extend_from_slice(&chunk[..n]);
    }
    Ok((status, serde_json::from_slice(&buffer[head_end..head_end + length])?))
}

fn snapshot(w: &World, s: &Session) -> anyhow::Result<AuthenticatedInventorySnapshot> {
    let scope = &s.conversations.fence["scope"];
    let digest = scope["scopeDigest"].as_str().or_else(|| scope["scopeDigest"]["$bytes"].as_str()).context("scopeDigest")?;
    Ok(AuthenticatedInventorySnapshot {
        owner_did: w.owner.svc.did.clone(),
        actor_device_id: w.owner.svc.device_id.to_string(),
        auth_generation: 1,
        inventory_session_id: s.id.clone(),
        event_cursor: s.conversations.fence["cursor"].as_str().context("cursor")?.to_owned(),
        expires_at: s.conversations.fence["expires"].as_str().context("expires")?.to_owned(),
        scope_digest: digest.to_owned(),
        conversation_pages: s.conversations.pages.clone(),
        welcome_pages: s.welcomes.pages.clone(),
        recovery_pages: s.recovery.pages.clone(),
    })
}

type Fenced = catbird_mls::orchestrator::Result<catbird_mls::orchestrator::authenticated_inventory::AppliedInventoryFence>;

/// Main's contract: an unknown inventory item fails the snapshot closed with
/// the typed `InvalidInput` naming the unknown union variant.
fn poison_must_fail_closed(result: Fenced, when: &str) {
    match result {
        Err(catbird_mls::orchestrator::OrchestratorError::InvalidInput(message)) => {
            assert!(message.contains("unknown read union variant"), "{when}: typed cause: {message}");
            println!("C25 core sync [{when}]: unknown item -> InvalidInput({message})");
        }
        other => panic!("{when}: expected typed InvalidInput, got {:?}", other.map(|f| f.inventory_session_id().to_owned())),
    }
}

/// Byte view of all local sync state: orchestrator caches (sorted, serde)
/// plus the full persisted mock storage (Debug of its maps).
async fn local_state(o: &live_orchestrator::LiveOrchestrator) -> String {
    let conversations: std::collections::BTreeMap<String, Value> = o.conversations().lock().await.iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).expect("conversation view"))).collect();
    let groups: std::collections::BTreeMap<String, Value> = o.group_states().lock().await.iter()
        .map(|(k, v)| (format!("{k:?}"), serde_json::to_value(v).expect("group state"))).collect();
    format!("{}\n{}\n{:?}", serde_json::to_string(&conversations).expect("json"),
        serde_json::to_string(&groups).expect("json"), o.storage())
}

async fn conversation_ids(o: &live_orchestrator::LiveOrchestrator) -> std::collections::BTreeSet<String> {
    o.conversations().lock().await.keys().cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn c25_inventory_and_event_scope_on_live_router() -> anyhow::Result<()> {
    let w = std::sync::Arc::new(world().await?);
    // The scenario runs in its own task so that a failed assertion (panic) or
    // error still reaches the release below; the failure is re-raised after.
    let outcome = tokio::spawn(scenario(w.clone())).await;
    accept_all(&w).await?;
    println!("C25 released {} published requests through acceptance", w.published.len());
    let failures = match outcome {
        Ok(result) => result?,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => return Err(join.into()),
    };
    // Surface every failed rejection check (currently the OQ-11 500s) as one
    // summarizing test failure after all clauses have run.
    anyhow::ensure!(failures.is_empty(),
        "C25 typed-rejection failures (OQ-11: InventorySessionMismatch undeclared on getConversations):\n{}",
        failures.join("\n"));
    Ok(())
}

/// Every C25 clause; returns the recorded typed-rejection failures.
async fn scenario(w: std::sync::Arc<World>) -> anyhow::Result<Vec<String>> {
    let w = &*w;
    let mut failures: Vec<String> = Vec::new();
    let expected: std::collections::BTreeSet<String> =
        w.published.iter().map(|p| p.conversation_id.to_string()).collect();
    println!("C25 owner {} device {}; conversations {expected:?}", w.owner.svc.did, w.owner.svc.device_id);

    // 1. Scope bound to every page of all three domains (limit=1 forces paging).
    let s12 = scoped_session(w, 1, &["1", "2"]).await?;
    let scope = &s12.conversations.fence["scope"];
    assert_eq!(scope["supportedProtocolVersions"], json!(["1", "2"]), "inventoryScope versions");
    assert!(scope["scopeDigest"].as_str().or_else(|| scope["scopeDigest"]["$bytes"].as_str()).is_some(), "scopeDigest");
    assert_eq!(s12.conversations.fence["cursor"], json!(s12.id), "event cursor is the session capability");
    for (name, paged) in [("conversations", &s12.conversations), ("welcomes", &s12.welcomes), ("recovery", &s12.recovery)] {
        assert_eq!(paged.fence, s12.conversations.fence, "{name} domain is bound to the same session/cursor/scope");
        println!("C25 {name}: {} page(s), {} item(s), fence identical", paged.pages.len(), paged.items.len());
    }
    assert_eq!(s12.conversations.pages.len(), SENDERS, "one conversation per page at limit=1");
    assert_eq!(s12.welcomes.pages.len(), SENDERS, "one pending Welcome per page at limit=1");
    let seen: std::collections::BTreeSet<String> = s12.conversations.items.iter()
        .filter_map(|i| i["state"]["coordinates"]["conversationId"].as_str().map(str::to_owned)).collect();
    assert_eq!(seen, expected, "paged conversations enumerate exactly the published set");

    // 2. Continuations with a changed scope/limit/domain are refused; the
    //    compatible continuation still succeeds afterwards.
    let (status, first, _) = read(w, CONVERSATIONS, 1, &["1", "2"], None, None).await?;
    assert_eq!(status, StatusCode::OK);
    let next = first["nextPageCursor"].as_str().context("page 1 continuation")?.to_owned();
    let session = first["inventorySessionId"].as_str().context("session")?.to_owned();
    let (st, b1, _) = read(w, CONVERSATIONS, 1, &["1"], None, Some(&next)).await?;
    rejected(st, &b1, "InventorySessionMismatch", "conversations continuation under scope [1]", &mut failures);
    let (st, b2, _) = read(w, CONVERSATIONS, 1, &["2"], None, Some(&next)).await?;
    rejected(st, &b2, "InventorySessionMismatch", "conversations continuation under scope [2]", &mut failures);
    let (st, b3, _) = read(w, CONVERSATIONS, 1, &[], None, Some(&next)).await?;
    rejected(st, &b3, "InventorySessionMismatch", "conversations continuation without scope", &mut failures);
    let (st, b4, _) = read(w, CONVERSATIONS, 2, &["1", "2"], None, Some(&next)).await?;
    rejected(st, &b4, "InventorySessionMismatch", "conversations continuation with changed limit", &mut failures);
    let (st, b5, _) = read(w, WELCOMES, 1, &["1", "2"], Some(&session), Some(&next)).await?;
    rejected(st, &b5, "InventorySessionMismatch", "conversations cursor replayed on welcomes domain", &mut failures);
    let (st, b, _) = read(w, WELCOMES, 1, &["1"], Some(&session), None).await?;
    typed(st, &b, "InventorySessionMismatch", "welcomes with the [1,2] session under scope [1]");
    let (st, b, _) = read(w, RECOVERY, 1, &["1"], Some(&session), None).await?;
    typed(st, &b, "InventorySessionMismatch", "recovery with the [1,2] session under scope [1]");
    let (st, page2, _) = read(w, CONVERSATIONS, 1, &["1", "2"], None, Some(&next)).await?;
    assert_eq!(st, StatusCode::OK, "compatible continuation after refusals: {page2}");
    assert_eq!(fence(&page2), fence(&first), "compatible continuation keeps the fence");

    // 3. Event cursor + subscription ticket scope binding.
    let s1 = scoped_session(w, 100, &["1"]).await?;
    assert_ne!(s1.id, s12.id, "scope [1] is a distinct session capability");
    assert_eq!(s1.conversations.fence["scope"]["supportedProtocolVersions"], json!(["1"]));
    assert!(s1.conversations.items.is_empty(), "v2 conversations are outside scope [1]");
    let (st, b) = w.owner.svc.get(&w.client, &w.server.base_url, TICKET, &[]).await
        .map(|(s, raw)| (s, serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null)))?;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED, "control: GET is not the ticket method ({b})");
    let (st, b) = mint(w, &s12.id, &s12.id, Some(&["1"])).await?;
    typed(st, &b, "InventorySessionMismatch", "[1,2] cursor reused under scope [1]");
    let (st, b) = mint(w, &s12.id, &s12.id, None).await?;
    typed(st, &b, "InventorySessionMismatch", "[1,2] cursor reused without scope");
    let (st, b) = mint(w, &s12.id, &s1.id, Some(&["1", "2"])).await?;
    typed(st, &b, "InventorySessionMismatch", "[1] session cursor reused against the [1,2] session");
    let (st, b) = mint(w, &s1.id, &s12.id, Some(&["1"])).await?;
    typed(st, &b, "InventorySessionMismatch", "[1,2] cursor reused against the [1] session");
    let (st, t12) = mint(w, &s12.id, &s12.id, Some(&["1", "2"])).await?;
    assert_eq!(st, StatusCode::OK, "compatible [1,2] ticket: {t12}");
    // The ticket endpoint may serialize scopeDigest as a $bytes array; compare versions only.
    assert_eq!(t12["inventoryScope"]["supportedProtocolVersions"],
        s12.conversations.fence["scope"]["supportedProtocolVersions"], "ticket versions match session scope");
    let (st, t12b) = mint(w, &s12.id, &s12.id, Some(&["1", "2"])).await?;
    assert_eq!(st, StatusCode::OK, "compatible reuse mints again: {t12b}");
    assert_ne!(t12["ticket"], t12b["ticket"], "each mint is a distinct one-use ticket");
    let (st, t1) = mint(w, &s1.id, &s1.id, Some(&["1"])).await?;
    assert_eq!(st, StatusCode::OK, "compatible [1] ticket: {t1}");
    let (t12, t12b, t1) = (
        t12["ticket"].as_str().context("ticket")?.to_owned(),
        t12b["ticket"].as_str().context("ticket")?.to_owned(),
        t1["ticket"].as_str().context("ticket")?.to_owned(),
    );

    // 4. subscribeEvents: tickets are bound to their scope's cursor.
    let bogus = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let (code, b) = subscribe(w, &s12.id, &bogus).await?;
    assert_eq!((code, b["error"].as_str()), (400, Some("InvalidTicket")), "control: handshake reaches the ticket gate");
    let (code, b) = subscribe(w, &s1.id, &t12).await?;
    assert_eq!((code, b["error"].as_str()), (400, Some("InvalidTicket")), "[1,2] ticket with the [1] cursor: {b}");
    let (code, b) = subscribe(w, &s12.id, &t1).await?;
    assert_eq!((code, b["error"].as_str()), (400, Some("InvalidTicket")), "[1] ticket with the [1,2] cursor: {b}");
    let (code, _) = subscribe(w, &s12.id, &t12).await?;
    assert_eq!(code, 101, "[1,2] ticket upgrades with its own cursor after the refused attempt");
    let (code, b) = subscribe(w, &s12.id, &t12).await?;
    assert_eq!((code, b["error"].as_str()), (400, Some("InvalidTicket")), "consumed ticket is one-use: {b}");
    let (code, _) = subscribe(w, &s1.id, &t1).await?;
    assert_eq!(code, 101, "[1] ticket upgrades with its own cursor");
    let (code, _) = subscribe(w, &s12.id, &t12b).await?;
    assert_eq!(code, 101, "second compatible [1,2] ticket upgrades");
    println!("C25 subscribeEvents: foreign-scope cursors refused, own cursors upgraded (101), replay refused");

    // 5. Real core sync over the exact server pages (single page per domain).
    //    Contract (Main decision): an unknown item fails the whole snapshot
    //    closed with typed InvalidInput, applies nothing, leaves existing local
    //    state byte-unchanged, and the next clean snapshot applies everything.
    let exact = scoped_session(w, 100, &["1", "2"]).await?;
    let clean = snapshot(w, &exact)?;
    let mut poisoned = clean.clone();
    let mut page: Value = serde_json::from_slice(&poisoned.conversation_pages[0])?;
    let unknown = Uuid::new_v4().to_string();
    page["items"].as_array_mut().context("items")?.push(json!({
        "$type":"blue.catbird.chat.defs#conversationInventoryFutureVariant","conversationId":unknown
    }));
    poisoned.conversation_pages[0] = serde_json::to_vec(&page)?;
    let orch = live_orchestrator::live_orchestrator(
        w.owner.engine.context(), &w.owner.svc, &w.client, &w.server.base_url, w.server.receipt_document.clone(),
    ).await?;
    // (a) Empty device: nothing is applied.
    let before = local_state(&orch).await;
    poison_must_fail_closed(orch.ingest_authenticated_inventory_snapshot(&poisoned).await, "empty device");
    assert_eq!(local_state(&orch).await, before, "failed ingest leaves empty local state byte-unchanged");
    assert!(conversation_ids(&orch).await.is_empty(), "zero conversations applied");
    // (b) Clean snapshot applies all capable conversations.
    let fence = orch.ingest_authenticated_inventory_snapshot(&clean).await.context("clean exact snapshot must ingest")?;
    assert!(fence.matches_snapshot(&clean), "fence binds the clean snapshot");
    let synced = conversation_ids(&orch).await;
    assert!(expected.is_subset(&synced) && !synced.contains(&unknown), "clean snapshot applies all capable conversations: {synced:?}");
    println!("C25 core sync [clean]: applied {synced:?}");
    // (c) Populated device: the poisoned snapshot changes nothing.
    let populated = local_state(&orch).await;
    poison_must_fail_closed(orch.ingest_authenticated_inventory_snapshot(&poisoned).await, "populated device");
    assert_eq!(local_state(&orch).await, populated, "existing local state byte-unchanged after fail-closed ingest");
    // (d) The next clean snapshot applies all again.
    let fence = orch.ingest_authenticated_inventory_snapshot(&clean).await.context("next clean snapshot must ingest")?;
    assert!(fence.matches_snapshot(&clean), "next clean fence binds the snapshot");
    let resynced = conversation_ids(&orch).await;
    assert!(expected.is_subset(&resynced), "next clean snapshot applies all: {resynced:?}");
    orch.shutdown().await;
    println!("C25 ISOLATION: fail-closed whole snapshot (typed InvalidInput, zero applied, local state byte-unchanged, next clean applies all)");
    Ok(failures)
}

//! Case C33 (unsupported federation), recipient-homed-elsewhere branch, through
//! the live shipping router against the guarded request database.
//!
//! The recipient's public `blue.catbird.chat.declaration/self` names another
//! delivery service while the sender's authority is canonical. The router reads
//! that declaration from the recipient's PDS (the HTTPS DID fixture's opt-in
//! `_policy/catbirdDeclaration/<did>` override) and must refuse preparation
//! with the typed `RecipientAuthorityUnsupported` signed receipt before any
//! package selection or lease. The recipient deliberately *has* available
//! direct-request packages here, so the refusal cannot be the old
//! `RecipientKeysUnavailable` degradation.
//!
//! The second test drives the real `MLSOrchestrator::start_direct_request`
//! over the same router: the client surfaces the typed unsupported capability,
//! retains the draft, reserves nothing, and submits only canonical
//! direct-request wire requests (no legacy federation fallback).
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind};
use catbird_mls::orchestrator::{
    api_client::MLSAPIClient,
    canonical_transport::{GatewayResponse, PreparedRequest},
    CredentialStore, MLSOrchestrator, MlsCryptoContext, OrchestratorConfig, OrchestratorError,
};
use catbird_mls::{DirectRequestInput, MLSContext, MLSError};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    request_database_url, reviewed_request_migrations, route_to_dedicated_database,
    seed_service_device, signed_mls_request, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
use live_orchestrator::{mock_credentials::MockCredentials, mock_storage::MockStorage};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

const CANONICAL_AUTHORITY: &str = "did:web:chat.catbird.blue";
/// A publicly shaped foreign delivery service. It is never contacted: the
/// canonical authority refuses from the declaration alone.
const FOREIGN_AUTHORITY: &str = "did:web:chat.federated-peer.org";
/// Special-use TLDs are not public DIDs; such a declaration is malformed.
const NON_PUBLIC_AUTHORITY: &str = "did:web:chat.federation.example";

// ---------------------------------------------------------------------------
// Read-only database projections
// ---------------------------------------------------------------------------

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

fn maintenance(sql: &str) -> anyhow::Result<()> {
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

/// This process's dedicated `catbird_direct_requests_fault_<16hex>` database,
/// dropped on every exit path (including panic unwinding).
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

fn psql(sql: &str) -> anyhow::Result<String> {
    let output = Command::new("psql")
        .args([request_database_url(), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
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

fn available_request_packages(owner: &str) -> anyhow::Result<i64> {
    count(&format!(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did='{owner}' \
         AND usage_scope='direct-request' AND status='available'"
    ))
}

/// Everything a preparation lease or a publication could leave for one attempt:
/// (status, prepared_at/lease/response present, selected devices, publications,
/// deliveries, conversations, entries).
fn attempt_footprint(request_id: Uuid, conversation_id: Uuid) -> anyhow::Result<String> {
    psql(&format!(
        "SELECT (SELECT status FROM chat.direct_request_attempts WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{request_id}' \
                   AND (prepared_at IS NOT NULL OR lease_expires_at IS NOT NULL OR prepare_response IS NOT NULL)), \
                (SELECT count(*) FROM chat.direct_request_selected_devices WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{request_id}'), \
                (SELECT count(*) FROM chat.conversations WHERE conversation_id='{conversation_id}'), \
                (SELECT count(*) FROM chat.entries WHERE transition_id='{request_id}')"
    ))
}

/// Canonical rows that would exist for this pair if any request, Welcome or
/// conversation had been created by any path.
fn pair_footprint(alice: &str, bob: &str) -> anyhow::Result<String> {
    psql(&format!(
        "SELECT (SELECT count(*) FROM chat.direct_request_publications WHERE actor_did='{alice}' AND recipient_did='{bob}'), \
                (SELECT count(*) FROM chat.participants WHERE user_did IN ('{alice}','{bob}')), \
                (SELECT count(*) FROM chat.welcome_deliveries WHERE recipient_did='{bob}'), \
                (SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did='{alice}' AND status IN ('prepared','published'))"
    ))
}

// ---------------------------------------------------------------------------
// Fixture policy overrides (served by support/https_did_fixture.py)
// ---------------------------------------------------------------------------

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

/// Publish `did`'s public `blue.catbird.chat.declaration/self` naming
/// `delivery_service` on the fixture PDS.
fn declare_chat_authority(root: &Path, did: &str, delivery_service: &str) -> anyhow::Result<()> {
    let dir = root.join("_policy").join("catbirdDeclaration");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(quote(did)),
        serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": delivery_service,
            "protocolVersion": "1",
            "createdAt": canonical_now(),
        }))?,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Accounts, keys, prepare, cancel
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
        Ok(Self { svc, engine, identity, public, key_id, package, package_ref })
    }
    fn did(&self) -> &str {
        &self.svc.did
    }
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
    Ok(Rig { https, server, client: reqwest::Client::builder().build()? })
}

fn identity(label: &str, run: &str) -> ServiceIdentity {
    ServiceIdentity::new(format!("did:web:{label}-{run}.request-fixture.catbird.blue"))
}

async fn post(rig: &Rig, who: &ServiceIdentity, nsid: &str, body: &Value) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let (status, bytes) = who.post(&rig.client, &rig.server.base_url, nsid, body, true).await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{nsid} {status}: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, value))
}

async fn publish_keys(rig: &Rig, a: &Account) -> anyhow::Result<()> {
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
    let keys = signed_mls_request(
        &a.engine,
        &a.identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":a.did(),"actorDeviceId":a.svc.device_id.to_string(),
            "keyId":a.key_id,"authGeneration":1,"revision":1,"enabled":true,
            "keys":[{"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":STANDARD.encode(&a.package),"sha256":STANDARD.encode(Sha256::digest(&a.package)),
                "keyPackageRef":STANDARD.encode(&a.package_ref)},"grant":grant}],
            "idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, body) =
        post(rig, &a.svc, "blue.catbird.chat.publishDirectRequestKeys", &json!({"signedRequest":keys})).await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "publish keys {status}: {body}");
    Ok(())
}

struct Prep {
    request_id: Uuid,
    conversation_id: Uuid,
    prepare_digest: [u8; 32],
    status: reqwest::StatusCode,
    response: Value,
}

async fn prepare(rig: &Rig, alice: &Account, recipient: &str) -> anyhow::Result<Prep> {
    let request_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let prepare = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":alice.did(),"actorDeviceId":alice.svc.device_id.to_string(),
            "keyId":alice.key_id,"authGeneration":1,"requestId":request_id.to_string(),
            "firstMessageId":Uuid::new_v4().to_string(),"conversationId":conversation_id.to_string(),
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
    let (status, response) =
        post(rig, &alice.svc, "blue.catbird.chat.prepareDirectRequest", &json!({"signedRequest":prepare})).await?;
    Ok(Prep { request_id, conversation_id, prepare_digest, status, response })
}

async fn cancel(rig: &Rig, alice: &Account, recipient: &str, prep: &Prep) -> anyhow::Result<()> {
    let body = json!({
        "$type":"blue.catbird.chat.defs#directRequestCancellationBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-CANCEL\0","protocolVersion":"2",
        "actorDid":alice.did(),"actorDeviceId":alice.svc.device_id.to_string(),
        "keyId":alice.key_id,"authGeneration":1,"requestId":prep.request_id.to_string(),
        "recipientDid":recipient,"preparationRequestDigest":STANDARD.encode(prep.prepare_digest),
        "idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
    });
    let signed = signed_mls_request(&alice.engine, &alice.identity, DirectRequestKind::Cancel, body)?;
    let (status, response) = post(
        rig,
        &alice.svc,
        "blue.catbird.chat.cancelDirectRequestPreparation",
        &json!({"signedRequest":signed}),
    )
    .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "cancel {status}: {response}");
    Ok(())
}

/// Verify the router's signed receipt and return (receipt kind, code).
fn receipt(response: &Value, key: &[u8]) -> anyhow::Result<(String, Option<String>, Value)> {
    anyhow::ensure!(
        response["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "expected signed receipt, got {response}"
    );
    let mut signed = response["outcome"].clone();
    signed.as_object_mut().context("receipt object")?.remove("$type");
    let verified =
        protocol::verify_signed_request(DirectRequestKind::Outcome, &serde_json::to_vec(&signed)?, key)?;
    let proof = verified.body()["receipt"].clone();
    Ok((
        proof["$type"]
            .as_str()
            .context("receipt type")?
            .trim_start_matches("blue.catbird.chat.defs#")
            .to_owned(),
        proof["code"].as_str().map(str::to_owned),
        proof,
    ))
}

// ---------------------------------------------------------------------------
// Router-level refusal
// ---------------------------------------------------------------------------

/// C33: a recipient whose public chat declaration names another delivery
/// service is refused at preparation with the typed signed
/// `RecipientAuthorityUnsupported` receipt; no lease, no package reservation,
/// no publication/conversation/Welcome. Controls: the same recipient declaring
/// the canonical authority is prepared normally (then cancelled to release),
/// and an undeclared recipient without keys keeps `RecipientKeysUnavailable`.
async fn router_refuses_foreign_recipient_before_any_lease() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let (alice_id, bob_id, carol_id) = (identity("alice", &run), identity("bob", &run), identity("carol", &run));
    let rig = rig(&[&alice_id, &bob_id, &carol_id]).await?;
    let alice = Account::new(alice_id, "c33-alice")?;
    let bob = Account::new(bob_id, "c33-bob")?;
    let carol = Account::new(carol_id, "c33-carol")?;
    publish_keys(&rig, &bob).await?;
    assert_eq!(available_request_packages(bob.did())?, 1, "bob has a usable request package");

    // Foreign-homed recipient (sender's authority canonical).
    declare_chat_authority(&rig.https.root, bob.did(), FOREIGN_AUTHORITY)?;
    let refused = prepare(&rig, &alice, bob.did()).await?;
    assert_eq!(refused.status, reqwest::StatusCode::OK, "{}", refused.response);
    let (kind, code, proof) = receipt(&refused.response, &rig.server.receipt_public_key)?;
    println!("C33 foreign-recipient receipt: {proof}");
    assert_eq!(kind, "directRequestRejectedReceipt");
    assert_eq!(code.as_deref(), Some("RecipientAuthorityUnsupported"), "typed unsupported capability");
    assert_eq!(proof["requestKind"], "prepare");
    assert_eq!(proof["requestId"], refused.request_id.to_string());
    let footprint = attempt_footprint(refused.request_id, refused.conversation_id)?;
    println!("C33 refused attempt footprint: {footprint}");
    assert_eq!(footprint, "rejected|0|0|0|0|0|0", "terminal refusal, no lease/selection/publication");
    assert_eq!(available_request_packages(bob.did())?, 1, "no recipient package consumed or reserved");
    assert_eq!(pair_footprint(alice.did(), bob.did())?, "0|0|0|0", "no request/Welcome/conversation rows");

    // Exact replay of the same signed prepare returns the same terminal receipt.
    // (Idempotent terminal state; the refusal is not re-evaluated into a lease.)
    let replay_rows = count(&format!(
        "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{}'",
        refused.request_id
    ))?;
    assert_eq!(replay_rows, 1);

    // Control 1: the same recipient declaring the canonical authority passes the
    // authority gate and gets a real preparation (then released by signed cancel).
    declare_chat_authority(&rig.https.root, bob.did(), CANONICAL_AUTHORITY)?;
    let prepared = prepare(&rig, &alice, bob.did()).await?;
    assert_eq!(
        prepared.response["outcome"]["$type"], "blue.catbird.chat.defs#directRequestPreparedOutcome",
        "canonical-homed recipient must be preparable: {}",
        prepared.response
    );
    assert_eq!(attempt_footprint(prepared.request_id, prepared.conversation_id)?, "prepared|1|1|0|0|0|0");
    cancel(&rig, &alice, bob.did(), &prepared).await?;
    let released = attempt_footprint(prepared.request_id, prepared.conversation_id)?;
    assert!(released.starts_with("cancelled|"), "control lease released by signed cancel: {released}");

    // Control 2: a recipient with no chat declaration at all (fixture answers
    // the typed RecordNotFound) and no request keys keeps the pre-existing
    // RecipientKeysUnavailable refusal: absence never becomes "unsupported".
    let keyless = prepare(&rig, &alice, carol.did()).await?;
    let (_, keyless_code, _) = receipt(&keyless.response, &rig.server.receipt_public_key)?;
    assert_eq!(keyless_code.as_deref(), Some("RecipientKeysUnavailable"));

    // Control 3: an unreadable/malformed chat declaration (non-public DID)
    // fails closed like the consent declaration read, never as "unsupported"
    // and never as a lease.
    declare_chat_authority(&rig.https.root, bob.did(), NON_PUBLIC_AUTHORITY)?;
    let malformed = prepare(&rig, &alice, bob.did()).await?;
    let (_, malformed_code, _) = receipt(&malformed.response, &rig.server.receipt_public_key)?;
    assert_eq!(malformed_code.as_deref(), Some("RequestPolicyDenied"));
    assert_eq!(attempt_footprint(malformed.request_id, malformed.conversation_id)?, "rejected|0|0|0|0|0|0");
    Ok(())
}

// ---------------------------------------------------------------------------
// Real orchestrator over the live router
// ---------------------------------------------------------------------------

/// Live transport for the real orchestrator. Every canonical wire request is
/// forwarded unchanged through the scoped service-auth path and recorded.
/// `getConversations` is served by the real router and must be empty for this
/// fresh pair; every other legacy transport method fails loudly.
struct RecordingLiveApi {
    service: ServiceIdentity,
    client: reqwest::Client,
    base_url: String,
    paths: Arc<Mutex<Vec<String>>>,
}

fn outside(method: &str) -> OrchestratorError {
    OrchestratorError::Api(format!("{method} is outside the C33 request path"))
}

type ApiResult<T> = catbird_mls::orchestrator::Result<T>;

impl RecordingLiveApi {
    async fn forward(&self, method: reqwest::Method, path: &str, body: Option<&[u8]>) -> ApiResult<(u16, Vec<u8>)> {
        self.paths.lock().await.push(path.to_owned());
        let (path, query) = match path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path, None),
        };
        let nsid = path
            .strip_prefix("/xrpc/")
            .ok_or_else(|| OrchestratorError::Api(format!("unexpected path {path}")))?;
        let (status, bytes) = self
            .service
            .forward_exact_service_request(&self.client, &self.base_url, method, nsid, query, body)
            .await
            .map_err(|error| OrchestratorError::Api(format!("{error:#}")))?;
        Ok((status.as_u16(), bytes))
    }
}

#[async_trait::async_trait]
impl MLSAPIClient for RecordingLiveApi {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        did == self.service.did
    }
    async fn current_did(&self) -> Option<String> {
        Some(self.service.did.clone())
    }
    async fn submit_prepared_request(&self, request: PreparedRequest) -> ApiResult<GatewayResponse> {
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            other => return Err(OrchestratorError::Api(format!("method {other}"))),
        };
        let (status, body) = self.forward(method, &request.path, request.body.as_deref()).await?;
        Ok(GatewayResponse { status, content_type: Some("application/json".into()), body })
    }
    async fn get_conversations(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
    ) -> ApiResult<catbird_mls::orchestrator::ConversationListPage> {
        let path = format!(
            "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={}&limit=100&supportedProtocolVersions=1&supportedProtocolVersions=2",
            self.service.device_id
        );
        let (status, body) = self.forward(reqwest::Method::GET, &path, None).await?;
        let value: Value = serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if status != 200 || value["items"].as_array().is_none_or(|items| !items.is_empty()) {
            return Err(OrchestratorError::Api(format!("C33 expects an empty live inventory: {status} {value}")));
        }
        Ok(catbird_mls::orchestrator::ConversationListPage { conversations: Vec::new(), cursor: None })
    }
    async fn get_messages(
        &self,
        _convo_id: &str,
        _cursor: Option<&str>,
        _limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> ApiResult<(Vec<catbird_mls::orchestrator::IncomingEnvelope>, Option<String>)> {
        Err(outside("get_messages"))
    }
    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        _dids: &[String],
    ) -> ApiResult<Vec<catbird_mls::orchestrator::KeyPackageRef>> {
        Err(outside("get_key_packages"))
    }
    async fn get_key_package_stats(&self) -> ApiResult<catbird_mls::orchestrator::KeyPackageStats> {
        Err(outside("get_key_package_stats"))
    }
    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> ApiResult<catbird_mls::orchestrator::KeyPackageSyncResult> {
        Err(outside("sync_key_packages"))
    }
    async fn list_devices(&self, _actor_device_id: &str) -> ApiResult<Vec<catbird_mls::orchestrator::DeviceInfo>> {
        Err(outside("list_devices"))
    }
    async fn get_group_info(&self, _convo_id: &str) -> ApiResult<Vec<u8>> {
        Err(outside("get_group_info"))
    }
}

/// C33 client clauses on the live router: the real orchestrator reports the
/// typed unsupported capability, the draft is retained (intent kept with its
/// signed terminal receipt, retry allowed), no bootstrap journal/projection or
/// server lease exists, and only canonical direct-request paths were sent.
async fn orchestrator_foreign_recipient_typed_unsupported_draft_retained() -> anyhow::Result<()> {
    let run = Uuid::new_v4().simple().to_string();
    let (alice_id, bob_id) = (identity("alice", &run), identity("bob", &run));
    let rig = rig(&[&alice_id, &bob_id]).await?;
    let alice = Account::new(alice_id, "c33-orch-alice")?;
    let bob = Account::new(bob_id, "c33-orch-bob")?;
    publish_keys(&rig, &bob).await?;
    declare_chat_authority(&rig.https.root, bob.did(), FOREIGN_AUTHORITY)?;

    let paths = Arc::new(Mutex::new(Vec::new()));
    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(rig.server.receipt_document.clone());
    credentials.store_device_uuid(alice.did(), &alice.svc.device_id.to_string()).await?;
    credentials.store_mls_did(alice.did(), alice.did()).await?;
    let context: Arc<MLSContext> = alice.engine.context();
    let orchestrator = MLSOrchestrator::new(
        context.clone(),
        Arc::new(MockStorage::new()),
        Arc::new(RecordingLiveApi {
            service: alice.svc.clone(),
            client: rig.client.clone(),
            base_url: rig.server.base_url.clone(),
            paths: paths.clone(),
        }),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(alice.did()).await?;

    let draft_id = Uuid::new_v4().to_string();
    let input = DirectRequestInput {
        draft_id: draft_id.clone(),
        recipient_did: bob.did().to_owned(),
        text: "C33 draft to a recipient homed on another chat authority".into(),
        invitation: None,
    };
    let edited = DirectRequestInput {
        text: "C33 edited draft, retried while still homed elsewhere".into(),
        ..input.clone()
    };
    let reason = "Direct request recipient is homed on another chat authority";
    let prepares_sent = |sent: &[String]| {
        sent.iter()
            .filter(|p| p.as_str() == "/xrpc/blue.catbird.chat.prepareDirectRequest")
            .count()
    };

    // Attempt 1: the original draft. Attempt 2: the identical draft replays the
    // same immutable terminal attempt (no new wire request). Attempt 3: the user
    // edits the retained draft and retries, which opens a new attempt that
    // carries the first terminal attempt.
    for (attempt, draft, prepares, previous) in
        [(1, &input, 1, 0), (2, &input, 1, 0), (3, &edited, 2, 1)]
    {
        let snapshot = draft.clone();
        let result = orchestrator.start_direct_request(draft.clone()).await;
        println!("C33 orchestrator attempt {attempt}: {result:?}");
        match &result {
            Err(OrchestratorError::Mls(MLSError::OperationNotSupported { reason: got })) => assert_eq!(got, reason),
            other => panic!("attempt {attempt}: expected typed OperationNotSupported, got {other:?}"),
        }
        assert_eq!(draft, &snapshot, "caller draft unchanged");
        // Draft retained: the intent survives with its signed terminal receipt.
        let raw = context.read_direct_request_intent(&draft_id)?.expect("draft intent retained");
        let intent: Value = serde_json::from_slice(&raw)?;
        assert_eq!(intent["input"]["text"], draft.text, "retained draft text");
        assert!(intent["terminal_response"].is_array(), "signed terminal receipt retained with draft");
        assert_eq!(intent["previous_attempts"].as_array().map(Vec::len), Some(previous));
        assert!(context.list_direct_request_journal()?.is_empty(), "no bootstrap journal (no lease)");
        assert!(context.list_direct_request_projections()?.is_empty(), "no request projection");
        assert_eq!(prepares_sent(&paths.lock().await), prepares, "attempt {attempt} wire prepares");
    }

    // Server: every attempt by Alice to Bob is a terminal rejection with the
    // typed code; no lease, selection or publication; Bob's package untouched.
    let rows = psql(&format!(
        "SELECT string_agg(status||':'||(prepared_at IS NULL)::text||':'||(lease_expires_at IS NULL)::text, ',' ORDER BY created_at) \
         FROM chat.direct_request_attempts WHERE actor_did='{}' AND recipient_did='{}'",
        alice.did(), bob.did()
    ))?;
    println!("C33 orchestrator server attempts: {rows}");
    assert_eq!(rows, "rejected:true:true,rejected:true:true");
    // The stored signed receipt carries a NUL signature domain, so match its
    // exact code text rather than casting to jsonb.
    let typed = count(&format!(
        "SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did='{}' AND recipient_did='{}' \
         AND convert_from(terminal_response,'UTF8') LIKE '%\"code\":\"RecipientAuthorityUnsupported\"%'",
        alice.did(), bob.did()
    ))?;
    assert_eq!(typed, 2, "both server attempts hold the typed signed refusal");
    assert_eq!(available_request_packages(bob.did())?, 1, "no recipient package consumed");
    assert_eq!(pair_footprint(alice.did(), bob.did())?, "0|0|0|0");

    // No legacy fallback: only the canonical inventory read and the two
    // prepare submissions reached the wire.
    let sent = paths.lock().await.clone();
    println!("C33 orchestrator wire paths: {sent:?}");
    assert_eq!(prepares_sent(&sent), 2, "one prepare per immutable attempt: {sent:?}");
    for path in &sent {
        assert!(
            path == "/xrpc/blue.catbird.chat.prepareDirectRequest"
                || path.starts_with("/xrpc/blue.catbird.chat.getConversations?"),
            "unexpected wire request (legacy fallback?): {path}"
        );
        assert!(!path.contains("mlsDS.") && !path.contains("deliverMessage") && !path.contains("deliverWelcome"));
    }
    orchestrator.shutdown().await;
    Ok(())
}

/// Both C33 recipient-authority scenarios on one dedicated fault database
/// (harness routing is fixed per process), dropped at the end.
#[tokio::test(flavor = "multi_thread")]
async fn c33_live_recipient_homed_on_foreign_authority() -> anyhow::Result<()> {
    let name = format!("catbird_direct_requests_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);
    maintenance(&format!("CREATE DATABASE {name}"))?;
    let _dedicated = DedicatedDatabase(name.clone());
    route_to_dedicated_database(&format!("postgresql://127.0.0.1:5432/{name}"))?;
    anyhow::ensure!(request_database_url().ends_with(&name));
    println!("C33 dedicated database: {name}");
    router_refuses_foreign_recipient_before_any_lease().await?;
    println!("C33 router scenario: pass");
    orchestrator_foreign_recipient_typed_unsupported_draft_retained().await?;
    println!("C33 orchestrator scenario: pass");
    Ok(())
}

//! C23 (legacy pending upgrade) and C24 (legacy inventory safety) against the
//! live shipping router fixture and guarded PostgreSQL database.
//!
//! C23: a legacy client creates a v1 pending direct conversation through the
//! real `createConversation` path (`MLSOrchestrator::create_group`, which the
//! server stores as `protocol_version='1'`). The actor then upgrades it through
//! real `prepareDirectRequest`/`publishDirectRequest` carrying
//! `legacyPendingDirectOrigin`. Races run as concurrent HTTP requests against
//! the live server released by a barrier.
//!
//! No protocol row is written by this test; psql is used only for reads.

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
    orchestrator::direct_request_bootstrap::{metadata_coordinate, DirectRequestBootstrapInput},
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_url,
    route_to_dedicated_database, seed_service_device, signed_mls_request, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
use catbird_mls::orchestrator::canonical_transport;
use live_orchestrator::{mock_credentials::MockCredentials, mock_storage::MockStorage};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Read-only query against the routed guarded database.
fn db(sql: &str) -> anyhow::Result<String> {
    let out = std::process::Command::new("psql")
        .args(["-X", "-v", "ON_ERROR_STOP=1", "-At", "-d", request_database_url(), "-c", sql])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn db_json(sql: &str) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&db(sql)?)?)
}

/// In-memory epoch-secret store: the host storage callback every production
/// platform installs before MLS operations (`set_epoch_secret_storage`).
#[derive(Default)]
struct MemoryEpochStore(tokio::sync::Mutex<std::collections::HashMap<(String, u64), Vec<u8>>>);

#[async_trait::async_trait]
impl catbird_mls::EpochSecretStorage for MemoryEpochStore {
    async fn store_epoch_secret(&self, id: String, epoch: u64, data: Vec<u8>) -> bool {
        self.0.lock().await.insert((id, epoch), data);
        true
    }
    async fn get_epoch_secret(&self, id: String, epoch: u64) -> Option<Vec<u8>> {
        self.0.lock().await.get(&(id, epoch)).cloned()
    }
    async fn delete_epoch_secret(&self, id: String, epoch: u64) -> bool {
        self.0.lock().await.remove(&(id, epoch));
        true
    }
    async fn delete_epochs_before(&self, id: String, cutoff: u64) -> u32 {
        let mut map = self.0.lock().await;
        let before = map.len();
        map.retain(|(g, e), _| !(g == &id && *e < cutoff));
        (before - map.len()) as u32
    }
}

/// Each test process runs on its own `catbird_direct_requests_fault_<16hex>`
/// database (installed by the guard with the pinned ledger) and drops it on
/// exit, including failure. Run one test per process (`--exact`).
struct DedicatedDatabase(String);

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

fn maintenance(sql: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("psql")
        .args([MAINTENANCE_URL, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "maintenance psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = maintenance(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"
        ));
        let _ = maintenance(&format!("DROP DATABASE IF EXISTS {name}"));
        println!("dropped dedicated database {name}");
    }
}

async fn dedicated_database() -> anyhow::Result<DedicatedDatabase> {
    let name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    maintenance(&format!("CREATE DATABASE {name}"))?;
    let guard = DedicatedDatabase(name.clone());
    route_to_dedicated_database(&format!("postgresql://127.0.0.1:5432/{name}"))?;
    anyhow::ensure!(request_database_url().ends_with(&name));
    let authority = connect_guarded_request_database(5).await?;
    anyhow::ensure!(authority.database == name);
    println!("dedicated database {name} ({} request migrations)", authority.additive_migrations);
    Ok(guard)
}

struct Party {
    id: ServiceIdentity,
    engine: MlsEngine,
    identity: String,
    public: Vec<u8>,
    key_id: String,
}

struct Fixture {
    alice: Party,
    bob: Party,
    server: ShippingServerFixture,
    client: reqwest::Client,
    _https: HttpsDidFixture,
}

async fn fixture() -> anyhow::Result<Fixture> {
    let _authority = connect_guarded_request_database(5).await?;
    let run = Uuid::new_v4().simple().to_string()[..16].to_owned();
    let alice_id = ServiceIdentity::new(format!(
        "did:web:alice-{run}.request-fixture.catbird.blue"
    ));
    let bob_id = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        HttpsDidFixture::reserve_port()?,
        &[
            (alice_id.did.clone(), alice_id.did_document()),
            (bob_id.did.clone(), bob_id.did_document()),
        ],
    )?;
    let make = |id: ServiceIdentity, label: &str| -> anyhow::Result<Party> {
        let engine = MlsEngine::new(&format!("c23-{label}-{run}"))?;
        engine
            .context()
            .set_epoch_secret_storage(Box::new(MemoryEpochStore::default()))?;
        let identity = format!("{}#{}", id.did, id.device_id);
        engine.create_key_package(&identity)?;
        let public = engine.identity_public_key(&identity)?;
        seed_service_device(&id, &public)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        Ok(Party {
            id,
            engine,
            identity,
            public,
            key_id,
        })
    };
    let alice = make(alice_id, "alice")?;
    let bob = make(bob_id, "bob")?;
    // Both accounts are homed here and admit the direct conversation; the
    // upgrade publication must also match the sender's PDS device key.
    for party in [&alice, &bob] {
        https.declare_local_chat_account(&party.id.did)?;
        https.publish_device_key(&party.id.did, &party.public)?;
    }
    let server = ShippingServerFixture::start(&https)?;
    Ok(Fixture {
        alice,
        bob,
        server,
        client: reqwest::Client::builder().build()?,
        _https: https,
    })
}

/// Create the legacy v1 pending direct conversation through the real client
/// creation path, exactly as a pre-request client did.
async fn create_legacy_direct(f: &Fixture) -> anyhow::Result<Uuid> {
    let orchestrator = live_orchestrator::live_orchestrator(
        f.alice.engine.context(),
        &f.alice.id,
        &f.client,
        &f.server.base_url,
        f.server.receipt_document.clone(),
    )
    .await?;
    let view = orchestrator
        .create_group("", Some(&[f.bob.id.did.clone()]), None)
        .await
        .context("legacy createConversation")?;
    orchestrator.shutdown().await;
    Ok(Uuid::parse_str(&view.conversation_id)?)
}

/// Bob publishes one real signed keys publication carrying `count` fresh
/// grant-bound key packages; each prepared request consumes one.
async fn publish_bob_keys(f: &Fixture, count: usize) -> anyhow::Result<()> {
    let bob = &f.bob;
    let mut keys = Vec::new();
    for _ in 0..count {
        let (package, package_ref) = bob.engine.create_key_package(&bob.identity)?;
        let grant_id = Uuid::new_v4();
        let grant = signed_mls_request(
            &bob.engine,
            &bob.identity,
            DirectRequestKind::Grant,
            json!({
                "$type":"blue.catbird.chat.defs#directRequestGrantBody",
                "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
                "actorDid":bob.id.did,"actorDeviceId":bob.id.device_id.to_string(),"keyId":bob.key_id,
                "authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
                "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
                "keyPackageRef":STANDARD.encode(&package_ref),
                "keyPackageSha256":STANDARD.encode(Sha256::digest(&package)),
                "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),
                "signedAt":canonical_now()
            }),
        )?;
        keys.push(json!({"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
            "bytes":STANDARD.encode(&package),"sha256":STANDARD.encode(Sha256::digest(&package)),
            "keyPackageRef":STANDARD.encode(&package_ref)},"grant":grant}));
    }
    let operation = Uuid::new_v4();
    let keys = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":bob.id.did,"actorDeviceId":bob.id.device_id.to_string(),"keyId":bob.key_id,
            "authGeneration":1,"revision":1,"enabled":true,"keys":keys,
            "idempotencyKey":operation.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, body) = bob
        .id
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "publish keys failed {status}: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

/// Host transport for a real capable client: every exchange is the
/// orchestrator's own prepared request, and inventory is the canonical
/// generated `getConversations` query decoded by the shared strict decoder.
struct CapableHostApi {
    service: ServiceIdentity,
    client: reqwest::Client,
    base_url: String,
    /// A capable reader without request support scopes its inventory to
    /// protocol 1 exactly as `scope_inventory_read_path(.., false)` does.
    v1_only: bool,
    /// Every inventory exchange as (path, status), for evidence.
    inventory_log: Arc<tokio::sync::Mutex<Vec<(String, u16)>>>,
}

type ApiResult<T> = catbird_mls::orchestrator::Result<T>;

fn api_error(error: impl std::fmt::Display) -> catbird_mls::orchestrator::OrchestratorError {
    catbird_mls::orchestrator::OrchestratorError::Api(error.to_string())
}

#[async_trait::async_trait]
impl catbird_mls::orchestrator::api_client::MLSAPIClient for CapableHostApi {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        did == self.service.did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.service.did.clone())
    }

    async fn submit_prepared_request(
        &self,
        request: canonical_transport::PreparedRequest,
    ) -> ApiResult<canonical_transport::GatewayResponse> {
        let (path, query) = match request.path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.path.as_str(), None),
        };
        let nsid = path
            .strip_prefix("/xrpc/")
            .ok_or_else(|| api_error(format!("unexpected path {path}")))?;
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            other => return Err(api_error(format!("method {other}"))),
        };
        let (status, body) = self
            .service
            .forward_exact_service_request(
                &self.client,
                &self.base_url,
                method,
                nsid,
                query,
                request.body.as_deref(),
            )
            .await
            .map_err(|error| api_error(format!("{error:#}")))?;
        Ok(canonical_transport::GatewayResponse {
            status: status.as_u16(),
            content_type: Some("application/json".into()),
            body,
        })
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> ApiResult<catbird_mls::orchestrator::ConversationListPage> {
        let mut request = canonical_transport::prepare_get_conversations(
            &canonical_transport::CleanChatAuthContext::new(self.service.device_id.to_string()),
            i64::from(limit),
            cursor,
        )
        .map_err(api_error)?;
        if self.v1_only {
            request.path = request.path.replace("&supportedProtocolVersions=2", "");
        }
        let path = request.path.clone();
        let response = self.submit_prepared_request(request).await?;
        self.inventory_log.lock().await.push((path, response.status));
        if response.status != 200 {
            return Err(api_error(format!(
                "getConversations {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }
        let page =
            canonical_transport::decode_conversations_inventory(&response.body).map_err(api_error)?;
        let mut conversations = Vec::new();
        for item in page.items {
            // Tombstones carry no state; only live states become views.
            let catbird_mls::atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(item) = item else {
                continue;
            };
            let coordinates = &item.state.coordinates;
            conversations.push(catbird_mls::orchestrator::ConversationView {
                group_id: hex::encode(&coordinates.group_id),
                conversation_id: serde_json::to_value(&coordinates.conversation_id)
                    .map_err(api_error)?
                    .as_str()
                    .ok_or_else(|| api_error("conversationId"))?
                    .to_owned(),
                epoch: u64::try_from(coordinates.epoch).map_err(api_error)?,
                members: Vec::new(),
                metadata: None,
                created_at: None,
                updated_at: None,
                sequencer_did: None,
                canonical_state: Some(item.state.clone()),
            });
        }
        Ok(catbird_mls::orchestrator::ConversationListPage {
            conversations,
            cursor: page.next_page_cursor.map(|c| c.to_string()),
        })
    }

    async fn get_messages(
        &self,
        _: &str,
        _: Option<&str>,
        _: u32,
        _: Option<&str>,
        _: Option<u32>,
        _: Option<u32>,
    ) -> ApiResult<(Vec<catbird_mls::orchestrator::IncomingEnvelope>, Option<String>)> {
        Err(api_error("get_messages is outside the C23 request path"))
    }

    async fn get_key_packages(
        &self,
        _: &str,
        _: &[String],
    ) -> ApiResult<Vec<catbird_mls::orchestrator::KeyPackageRef>> {
        Err(api_error("get_key_packages is outside the C23 request path"))
    }

    async fn get_key_package_stats(&self) -> ApiResult<catbird_mls::orchestrator::KeyPackageStats> {
        Err(api_error("get_key_package_stats is outside the C23 request path"))
    }

    async fn sync_key_packages(
        &self,
        _: &[String],
        _: &str,
    ) -> ApiResult<catbird_mls::orchestrator::KeyPackageSyncResult> {
        Err(api_error("sync_key_packages is outside the C23 request path"))
    }

    async fn list_devices(&self, _: &str) -> ApiResult<Vec<catbird_mls::orchestrator::DeviceInfo>> {
        Err(api_error("list_devices is outside the C23 request path"))
    }

    async fn get_group_info(&self, _: &str) -> ApiResult<Vec<u8>> {
        Err(api_error("get_group_info is outside the C23 request path"))
    }
}

type CapableOrchestrator = catbird_mls::orchestrator::MLSOrchestrator<
    MockStorage,
    CapableHostApi,
    MockCredentials,
    catbird_mls::MLSContext,
>;

async fn capable_orchestrator(
    f: &Fixture,
    party: &Party,
    v1_only: bool,
) -> anyhow::Result<(CapableOrchestrator, MockStorage, Arc<tokio::sync::Mutex<Vec<(String, u16)>>>)> {
    use catbird_mls::orchestrator::CredentialStore as _;
    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(f.server.receipt_document.clone());
    credentials
        .store_device_uuid(&party.id.did, &party.id.device_id.to_string())
        .await?;
    credentials.store_mls_did(&party.id.did, &party.id.did).await?;
    let storage = MockStorage::new();
    let inventory_log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let orchestrator = catbird_mls::orchestrator::MLSOrchestrator::new(
        party.engine.context(),
        Arc::new(storage.clone()),
        Arc::new(CapableHostApi {
            service: party.id.clone(),
            client: f.client.clone(),
            base_url: f.server.base_url.clone(),
            v1_only,
            inventory_log: inventory_log.clone(),
        }),
        Arc::new(credentials),
        catbird_mls::orchestrator::OrchestratorConfig::default(),
    );
    orchestrator.initialize(&party.id.did).await?;
    Ok((orchestrator, storage, inventory_log))
}

/// Read-only JSON of the immutable legacy creation authority: the original
/// generation-0 creation state, the signed creation transition and entry.
fn legacy_rows(cid: Uuid) -> anyhow::Result<Value> {
    db_json(&format!(
        "SELECT json_build_object(\
         'states',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.generation,s.state_version) FROM chat.generation_states s WHERE s.conversation_id='{cid}' AND s.generation=0 AND s.state_version=0),\
         'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.transition_id) FROM chat.transitions t WHERE t.conversation_id='{cid}' AND t.kind='creation'),\
         'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.seq) FROM chat.entries e WHERE e.conversation_id='{cid}' AND e.seq=1))"
    ))
}

fn head(cid: Uuid) -> anyhow::Result<Value> {
    db_json(&format!(
        "SELECT json_build_object('protocolVersion',c.protocol_version,'lifecycle',c.lifecycle,\
         'generation',c.current_generation,'stateVersion',c.current_state_version,'nextSeq',c.next_entry_seq,\
         'groupId',encode(s.group_id,'hex'),'epoch',s.epoch,\
         'pending',(SELECT count(*) FROM chat.participants p WHERE p.conversation_id=c.conversation_id AND p.current_membership AND p.status='pending'),\
         'requests',(SELECT count(*) FROM chat.direct_request_publications r WHERE r.conversation_id=c.conversation_id))\
         FROM chat.conversations c JOIN chat.generation_states s ON s.conversation_id=c.conversation_id \
         AND s.generation=c.current_generation AND s.state_version=c.current_state_version WHERE c.conversation_id='{cid}'"
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_real_client_upgrades_legacy_pending_direct() -> anyhow::Result<()> {
    let _db = dedicated_database().await?;
    let f = fixture().await?;
    let cid = create_legacy_direct(&f).await?;
    let before = legacy_rows(cid)?;
    let legacy_head = head(cid)?;
    println!("legacy head {legacy_head}");
    assert_eq!(legacy_head["protocolVersion"], "1");
    assert_eq!(legacy_head["generation"], 0);
    assert_eq!(legacy_head["pending"], 1);
    assert_eq!(before["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(before["transitions"].as_array().map(Vec::len), Some(1));
    publish_bob_keys(&f, 1).await?;

    let (alice, _, _) = capable_orchestrator(&f, &f.alice, false).await?;
    let upgrade_started = chrono::Utc::now();
    let outcome = alice
        .start_direct_request(catbird_mls::orchestrator::DirectRequestInput {
            draft_id: Uuid::new_v4().to_string(),
            recipient_did: f.bob.id.did.clone(),
            text: "Upgraded legacy introduction".into(),
            invitation: None,
        })
        .await
        .context("real client legacy upgrade")?;
    println!("upgrade outcome {outcome:?}");
    let catbird_mls::orchestrator::DirectRequestOutcome::RequestSent {
        conversation_id,
        request_id,
        ..
    } = outcome
    else {
        anyhow::bail!("legacy upgrade did not publish: {outcome:?}");
    };
    assert_eq!(conversation_id, cid.to_string(), "upgrade must keep the conversation id");
    let after = legacy_rows(cid)?;
    assert_eq!(before, after, "v1 creation authority must be byte-exact after upgrade");
    let upgraded = head(cid)?;
    println!("upgraded head {upgraded}");
    assert_eq!(upgraded["protocolVersion"], "2");
    assert_eq!(upgraded["generation"], 1);
    assert_eq!(upgraded["requests"], 1);
    assert_ne!(upgraded["groupId"], legacy_head["groupId"], "successor needs fresh crypto");
    let request = db_json(&format!(
        "SELECT json_build_object('seq',e.seq,'kind',e.entry_kind,'createdAt',e.received_at,\
         'legacyCreatedAt',(SELECT received_at FROM chat.entries WHERE conversation_id='{cid}' AND seq=1))\
         FROM chat.entries e WHERE e.conversation_id='{cid}' AND e.seq>1 ORDER BY e.seq LIMIT 1"
    ))?;
    println!("introduction entry {request} request {request_id}");
    assert_eq!(request["seq"], legacy_head["nextSeq"], "introduction takes the next legacy seq");
    let intro_at = chrono::DateTime::parse_from_rfc3339(request["createdAt"].as_str().context("createdAt")?)?;
    assert!(
        intro_at >= upgrade_started - chrono::Duration::seconds(1),
        "introduction must not be backdated to legacy creation"
    );
    let legacy_at = chrono::DateTime::parse_from_rfc3339(
        request["legacyCreatedAt"].as_str().context("legacyCreatedAt")?,
    )?;
    assert!(intro_at > legacy_at, "introduction follows the legacy creation entry");
    alice.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Explicit signed RPC legs: the server gate and concurrent races.
// ---------------------------------------------------------------------------

/// Authoritative current state as the actor reads it through the live server.
async fn read_state(f: &Fixture, who: &Party, cid: Uuid) -> anyhow::Result<Value> {
    let (status, body) = who
        .id
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), cid.to_string())],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "getConversationState {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let response: Value = serde_json::from_slice(&body)?;
    // Reads present lexicon bytes as `{"$bytes":…}`; the shared client
    // normalizer yields the bare form signed bodies require.
    Ok(protocol::normalize_read_presentation(
        &serde_json::to_vec(&response["state"])?,
        "conversationState",
        false,
    )?)
}

fn legacy_origin_for(f: &Fixture, state: &Value) -> anyhow::Result<Value> {
    let peer = state["participants"]
        .as_array()
        .context("participants")?
        .iter()
        .find(|p| p["userDid"] == f.bob.id.did)
        .context("pending peer")?;
    Ok(json!({
        "$type":"blue.catbird.chat.defs#legacyPendingDirectOrigin",
        "exactPrior":state["coordinates"],
        "originalInvitationProvenance":peer["invitationProvenance"]
    }))
}

/// Ordinary chat mutation signed by the party's registered MLS identity key.
fn signed_ordinary(party: &Party, body: Value) -> anyhow::Result<Value> {
    use catbird_mls::chat_v2::transcript::{
        decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
    };
    let canonical = project_signed_body(
        SignedMutationKind::from_type_id(body["$type"].as_str().context("signed type")?)
            .context("signed kind")?,
        &decode_strict_json(&serde_json::to_vec(&body)?)?,
    )?;
    let transcript = SigningTranscript::build(&canonical)?;
    let signature = party
        .engine
        .sign_identity(&party.identity, transcript.bytes().to_vec())?;
    Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
}

fn successor(prior: &Value, lifecycle: &str) -> anyhow::Result<Value> {
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("stateVersion")? + 1);
    next["lifecycle"] = json!(lifecycle);
    Ok(next)
}

/// One real prepared legacy upgrade whose publication is signed but not sent.
struct PreparedUpgrade {
    request_id: Uuid,
    publication: Value,
    next: Value,
}

async fn prepare_upgrade(
    f: &Fixture,
    cid: Uuid,
    origin: Value,
    origin_seq: i64,
) -> anyhow::Result<PreparedUpgrade> {
    let alice = &f.alice;
    let request_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let prepare = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":alice.id.did,"actorDeviceId":alice.id.device_id.to_string(),"keyId":alice.key_id,
            "authGeneration":1,"requestId":request_id.to_string(),
            "firstMessageId":first_message_id.to_string(),"conversationId":cid.to_string(),
            "recipientDid":f.bob.id.did,"origin":origin,"profile":"encryptedIntroduction1",
            "idempotencyKey":request_id.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, bytes) = post_raw(
        f,
        alice,
        "blue.catbird.chat.prepareDirectRequest",
        &json!({"signedRequest":prepare}),
    )
    .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "prepare {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let response: Value = serde_json::from_slice(&bytes)?;
    let preparation = response
        .pointer("/outcome/preparation")
        .filter(|v| !v.is_null())
        .cloned()
        .with_context(|| format!("prepare returned no live preparation: {response}"))?;
    let preparation = protocol::verify_direct_request_preparation(
        &serde_json::to_vec(&preparation)?,
        &f.server.receipt_public_key,
    )?;
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice.public,
    )?;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("selectedDevices")?
        .clone();
    let mut import_until = u64::MAX;
    for device in &selected {
        let grant = protocol::verify_signed_request(
            DirectRequestKind::Grant,
            &serde_json::to_vec(&device["grant"])?,
            &f.bob.public,
        )?;
        import_until = import_until.min(u64::try_from(
            chrono::DateTime::parse_from_rfc3339(
                grant.body()["expiresAt"].as_str().context("expiresAt")?,
            )?
            .timestamp(),
        )?);
    }
    let decode = |device: &Value, field: &str| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(device["keyPackage"][field].as_str().context("package field")?)?)
    };
    let prior_generation = origin["exactPrior"]["generation"]
        .as_u64()
        .context("prior generation")?;
    let context = json!({
        "protocolVersion":"2","requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),"conversationId":cid.to_string(),
        "origin":origin,"actorDid":alice.id.did,"actorDeviceId":alice.id.device_id.to_string(),
        "actorKeyId":alice.key_id,"recipientDid":f.bob.id.did,
        "preparationDigest":preparation["preparationDigest"]
    });
    let journal = alice.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: prior_generation + 1,
        state_version: 1,
        key_packages: selected.iter().map(|d| decode(d, "bytes")).collect::<anyhow::Result<_>>()?,
        expected_package_refs: selected
            .iter()
            .map(|d| decode(d, "keyPackageRef"))
            .collect::<anyhow::Result<_>>()?,
        authority_import_until: import_until,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: f.server.receipt_public_key.clone(),
        text: "Upgraded legacy introduction".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let b = &journal.bootstrap;
    let mut body = prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = preparation["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(b.context_hash));
    body["next"] = b.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(b.import_until as i64, 0)
        .context("importUntil")?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({"framing":"mlsMessage","contentType":content_type,
            "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))})
    };
    let deliveries = selected
        .iter()
        .map(|d| {
            json!({"recipientDid":d["actorDid"],"recipientDeviceId":d["actorDeviceId"],"provenance":{
                "requestId":request_id.to_string(),"preparationDigest":preparation["preparationDigest"],
                "contextHash":STANDARD.encode(b.context_hash),"grantId":d["grant"]["body"]["grantId"],
                "grantRevision":d["grant"]["body"]["grantRevision"],
                "keyPackageRef":d["keyPackage"]["keyPackageRef"],"importUntil":body["importUntil"]}})
        })
        .collect::<Vec<_>>();
    body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&b.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&b.initial_ciphertext),
        "metadataSnapshot":{
            "coordinate":metadata_coordinate(&b.coordinates)?,
            "originTransitionId":request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&b.metadata_nonce),
            "ciphertext":STANDARD.encode(&b.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),
            "ciphertextSize":b.metadata_ciphertext.len(),
            "authorProof":{
                "authorDid":alice.id.did,"authorDeviceId":alice.id.device_id.to_string(),
                "authorKeyId":alice.key_id,"signaturePublicKey":STANDARD.encode(&alice.public),
                "authGenerationAtOrigin":1,"originTransitionId":request_id.to_string(),
                "originSeq":origin_seq,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}
        }
    });
    let publication =
        signed_mls_request(&alice.engine, &alice.identity, DirectRequestKind::Publish, body)?;
    Ok(PreparedUpgrade {
        request_id,
        publication,
        next: b.coordinates.clone(),
    })
}

/// Verified signed publication receipt (`body.receipt`) from a publish response.
fn publication_receipt(f: &Fixture, status: reqwest::StatusCode, bytes: &[u8]) -> anyhow::Result<Value> {
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "publish {status}: {}",
        String::from_utf8_lossy(bytes)
    );
    let response: Value = serde_json::from_slice(bytes)?;
    let mut outcome = response["outcome"].clone();
    outcome.as_object_mut().context("outcome object")?.remove("$type");
    let verified = protocol::verify_received_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&outcome)?,
        &f.server.receipt_public_key,
    )?;
    Ok(verified.body()["receipt"].clone())
}

fn receipt_kind(receipt: &Value) -> (&str, &str) {
    (
        receipt["$type"].as_str().unwrap_or_default(),
        receipt["code"].as_str().unwrap_or_default(),
    )
}

const PUBLISHED: &str = "blue.catbird.chat.defs#directRequestPublishedReceipt";
const REJECTED: &str = "blue.catbird.chat.defs#directRequestRejectedReceipt";

async fn post_raw(
    f: &Fixture,
    who: &Party,
    nsid: &str,
    envelope: &Value,
) -> anyhow::Result<(reqwest::StatusCode, Vec<u8>)> {
    who.id
        .post(&f.client, &f.server.base_url, nsid, envelope, true)
        .await
}

async fn publish(f: &Fixture, upgrade: &PreparedUpgrade) -> anyhow::Result<Value> {
    let (status, bytes) = post_raw(
        f,
        &f.alice,
        "blue.catbird.chat.publishDirectRequest",
        &json!({"signedRequest":upgrade.publication}),
    )
    .await?;
    publication_receipt(f, status, &bytes)
}

/// Capacity hygiene: the recipient releases a published upgrade by accepting it.
async fn release(f: &Fixture, cid: Uuid, upgrade: &PreparedUpgrade) -> anyhow::Result<()> {
    let bob = &f.bob;
    let state = read_state(f, bob, cid).await?;
    let provenance = state["participants"]
        .as_array()
        .context("participants")?
        .iter()
        .find(|p| p["userDid"] == bob.id.did)
        .context("recipient")?["invitationProvenance"]
        .clone();
    let prior = upgrade.next.clone();
    let transition = Uuid::new_v4();
    let signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Accept,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0","protocolVersion":"2",
            "actorDid":bob.id.did,"actorDeviceId":bob.id.device_id.to_string(),"keyId":bob.key_id,
            "authGeneration":1,"requestId":upgrade.request_id.to_string(),
            "transitionId":transition.to_string(),"prior":prior,"next":successor(&prior, "active")?,
            "invitationProvenance":provenance,"idempotencyKey":transition.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (status, bytes) = post_raw(
        f,
        bob,
        "blue.catbird.chat.acceptConversation",
        &json!({"directRequest":signed}),
    )
    .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "release accept {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(())
}

/// Bob tops up one ordinary key package (consumed by v1 acceptance).
async fn replenish(f: &Fixture, party: &Party) -> anyhow::Result<()> {
    let (package, package_ref) = party.engine.create_key_package(&party.identity)?;
    let op = Uuid::new_v4();
    let signed = signed_ordinary(party, json!({
        "$type":"blue.catbird.chat.defs#keyPackageReplenishmentBody",
        "signatureDomain":"CATBIRD-CHAT-DEVICE-REPLENISH\0","actorDid":party.id.did,
        "actorDeviceId":party.id.device_id.to_string(),"keyId":party.key_id,"authGeneration":1,
        "signaturePublicKey":STANDARD.encode(&party.public),
        "keyPackages":[{"framing":"mlsMessage","contentType":"keyPackage",
            "bytes":STANDARD.encode(&package),"sha256":STANDARD.encode(Sha256::digest(&package)),
            "keyPackageRef":STANDARD.encode(&package_ref)}],
        "idempotencyKey":op.to_string(),"signedAt":canonical_now()
    }))?;
    let (status, bytes) = post_raw(
        f,
        party,
        "blue.catbird.chat.replenishKeyPackages",
        &json!({"signedRequest":signed}),
    )
    .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "replenish {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(())
}

/// A fresh fixture holding a real v1 pending direct and Bob's published keys.
struct Legacy {
    f: Fixture,
    cid: Uuid,
    state: Value,
    origin: Value,
    rows: Value,
    head: Value,
    next_seq: i64,
}

async fn legacy_fixture() -> anyhow::Result<Legacy> {
    let f = fixture().await?;
    let cid = create_legacy_direct(&f).await?;
    publish_bob_keys(&f, 5).await?;
    let state = read_state(&f, &f.alice, cid).await?;
    let origin = legacy_origin_for(&f, &state)?;
    let rows = legacy_rows(cid)?;
    let head = head(cid)?;
    assert_eq!(head["protocolVersion"], "1");
    assert_eq!(head["lifecycle"], "active");
    assert_eq!(head["pending"], 1);
    let next_seq = head["nextSeq"].as_i64().context("nextSeq")?;
    Ok(Legacy { f, cid, state, origin, rows, head, next_seq })
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_server_gate_upgrades_real_legacy_pending_direct() -> anyhow::Result<()> {
    let _db = dedicated_database().await?;
    let Legacy { f, cid, state, origin, rows: before, head: legacy_head, next_seq } =
        legacy_fixture().await?;
    println!("legacy head {legacy_head}");

    // A backdated originSeq and a drifted exact prior are refused, writing nothing.
    let receipt = publish(&f, &prepare_upgrade(&f, cid, origin.clone(), next_seq - 1).await?).await?;
    println!("backdated originSeq receipt {receipt}");
    assert_eq!(receipt_kind(&receipt), (REJECTED, "InvalidBootstrap"));
    let mut drifted = origin.clone();
    drifted["exactPrior"]["stateVersion"] =
        json!(state["coordinates"]["stateVersion"].as_u64().context("sv")? + 1);
    let receipt = publish(&f, &prepare_upgrade(&f, cid, drifted, next_seq).await?).await?;
    println!("drifted exactPrior receipt {receipt}");
    assert_eq!(receipt_kind(&receipt), (REJECTED, "StaleLegacyPrior"));
    assert_eq!(head(cid)?, legacy_head, "rejected upgrades wrote nothing");

    let upgrade_started = chrono::Utc::now();
    let upgrade = prepare_upgrade(&f, cid, origin.clone(), next_seq).await?;
    let receipt = publish(&f, &upgrade).await?;
    println!("upgrade receipt {receipt}");
    assert_eq!(receipt_kind(&receipt).0, PUBLISHED);
    assert_eq!(receipt["conversationId"], cid.to_string(), "same conversation id");
    assert_eq!(receipt["coordinates"], upgrade.next);

    assert_eq!(legacy_rows(cid)?, before, "v1 signed creation authority byte-exact");
    let upgraded = head(cid)?;
    println!("upgraded head {upgraded}");
    assert_eq!(upgraded["protocolVersion"], "2");
    assert_eq!(upgraded["lifecycle"], "active");
    assert_eq!(upgraded["generation"], 1);
    assert_eq!(upgraded["stateVersion"], 1);
    assert_eq!(upgraded["epoch"], 1);
    assert_eq!(upgraded["requests"], 1);
    assert_ne!(upgraded["groupId"], legacy_head["groupId"], "fresh successor crypto generation");
    assert_eq!(
        upgraded["groupId"],
        json!(hex::encode(STANDARD.decode(upgrade.next["groupId"].as_str().context("groupId")?)?))
    );
    let states = db_json(&format!(
        "SELECT jsonb_agg(jsonb_build_object('g',generation,'sv',state_version,'kind',state_kind,'group',encode(group_id,'hex')) ORDER BY generation,state_version) \
         FROM chat.generation_states WHERE conversation_id='{cid}'"
    ))?;
    println!("generation states {states}");
    let retirement = &states[1];
    assert_eq!(retirement["g"], 0);
    assert_eq!(retirement["sv"], 1);
    assert_eq!(retirement["kind"], "directRequestRetirement", "prior generation retired, not rewritten");
    assert_eq!(retirement["group"], legacy_head["groupId"]);
    assert_eq!(states[2]["g"], 1);
    assert_eq!(states[2]["group"], upgraded["groupId"]);
    let intro = db_json(&format!(
        "SELECT json_build_object('seq',seq,'kind',entry_kind,'createdAt',received_at,\
         'legacyAt',(SELECT received_at FROM chat.entries WHERE conversation_id='{cid}' AND seq=1)) FROM chat.entries \
         WHERE conversation_id='{cid}' AND seq>1 ORDER BY seq LIMIT 1"
    ))?;
    println!("introduction entry {intro}");
    assert_eq!(intro["seq"].as_i64(), Some(next_seq), "introduction takes the next legacy seq");
    let intro_at =
        chrono::DateTime::parse_from_rfc3339(intro["createdAt"].as_str().context("createdAt")?)?;
    assert!(
        intro_at >= upgrade_started - chrono::Duration::seconds(1),
        "introduction {intro_at} backdated before upgrade {upgrade_started}"
    );
    let legacy_at =
        chrono::DateTime::parse_from_rfc3339(intro["legacyAt"].as_str().context("legacyAt")?)?;
    assert!(intro_at > legacy_at, "introduction not backdated to legacy creation");

    // Replaying the now-stale legacy head after the upgrade never publishes.
    match prepare_upgrade(&f, cid, origin, next_seq).await {
        Ok(late) => {
            let receipt = publish(&f, &late).await?;
            println!("post-upgrade stale head receipt {receipt}");
            assert_ne!(receipt_kind(&receipt).0, PUBLISHED, "stale head must never publish");
        }
        Err(error) => println!("post-upgrade stale head refused at prepare: {error:#}"),
    }
    assert_eq!(head(cid)?, upgraded, "no silent overwrite of the upgraded head");
    release(&f, cid, &upgrade).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum RaceLeg {
    Accept,
    Close,
    Reset,
    SecondUpgrade,
}

/// Build the competing signed mutation against the same legacy head.
async fn competing(
    l: &Legacy,
    leg: RaceLeg,
) -> anyhow::Result<(&'static str, Value)> {
    let f = &l.f;
    let prior = l.state["coordinates"].clone();
    let transition = Uuid::new_v4();
    Ok(match leg {
        RaceLeg::Accept => {
            replenish(f, &f.bob).await?;
            let bob = &f.bob;
            (
                "blue.catbird.chat.acceptConversation",
                json!({"signedRequest":signed_ordinary(bob, json!({
                    "$type":"blue.catbird.chat.defs#participantAcceptanceBody",
                    "signatureDomain":"CATBIRD-CHAT-ACCEPT\0","transitionId":transition.to_string(),
                    "recoveryRequestId":Uuid::new_v4().to_string(),"actorDid":bob.id.did,
                    "actorDeviceId":bob.id.device_id.to_string(),"keyId":bob.key_id,"authGeneration":1,
                    "prior":prior,"next":successor(&prior, "active")?,
                    "invitationProvenance":l.origin["originalInvitationProvenance"],
                    "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
                }))?}),
            )
        }
        RaceLeg::Close => (
            "blue.catbird.chat.closeConversation",
            json!({"signedRequest":signed_ordinary(&f.alice, json!({
                "$type":"blue.catbird.chat.defs#conversationCloseBody",
                "signatureDomain":"CATBIRD-CHAT-CLOSE\0","transitionId":transition.to_string(),
                "conversationKind":"direct","actorDid":f.alice.id.did,
                "actorDeviceId":f.alice.id.device_id.to_string(),"keyId":f.alice.key_id,"authGeneration":1,
                "prior":prior,"retired":successor(&prior, "superseded")?,
                "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
            }))?}),
        ),
        RaceLeg::Reset => (
            "blue.catbird.chat.requestReset",
            json!({"signedRequest":signed_ordinary(&f.alice, json!({
                "$type":"blue.catbird.chat.defs#resetRequestBody",
                "signatureDomain":"CATBIRD-CHAT-RESET-REQUEST\0","resetRequestId":transition.to_string(),
                "actorDid":f.alice.id.did,"actorDeviceId":f.alice.id.device_id.to_string(),
                "keyId":f.alice.key_id,"authGeneration":1,"prior":prior,"reason":"manualRecovery",
                "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
            }))?}),
        ),
        RaceLeg::SecondUpgrade => {
            // A second upgrade of the same legacy head cannot even be prepared
            // while the first preparation is live.
            let refused = match prepare_upgrade(f, l.cid, l.origin.clone(), l.next_seq).await {
                Ok(_) => anyhow::bail!("second concurrent upgrade preparation was admitted"),
                Err(error) => format!("{error:#}"),
            };
            println!("second concurrent upgrade preparation refused: {refused}");
            anyhow::ensure!(refused.contains("no live preparation"), "unexpected refusal {refused}");
            // The race is then the same signed publication delivered twice at once.
            ("blue.catbird.chat.publishDirectRequest", Value::Null)
        }
    })
}

fn pending_resets(cid: Uuid) -> anyhow::Result<String> {
    db(&format!(
        "SELECT count(*) FROM chat.reset_requests WHERE conversation_id='{cid}' AND status='pending'"
    ))
}

/// Release the upgrade publication and the competitor concurrently from a
/// barrier against the live server; exactly one authoritative outcome.
async fn race(leg: RaceLeg, label: &str) -> anyhow::Result<&'static str> {
    let l = legacy_fixture().await?;
    let (f, cid) = (&l.f, l.cid);
    let upgrade = prepare_upgrade(f, cid, l.origin.clone(), l.next_seq).await?;
    let (nsid, envelope) = competing(&l, leg).await?;
    let competitor = match leg {
        RaceLeg::Accept => &f.bob,
        _ => &f.alice,
    };
    let barrier = tokio::sync::Barrier::new(2);
    let publish_envelope = json!({"signedRequest":upgrade.publication});
    let envelope = match leg {
        RaceLeg::SecondUpgrade => publish_envelope.clone(),
        _ => envelope,
    };
    let (upgrade_result, competitor_result) = tokio::join!(
        async {
            barrier.wait().await;
            post_raw(f, &f.alice, "blue.catbird.chat.publishDirectRequest", &publish_envelope).await
        },
        async {
            barrier.wait().await;
            post_raw(f, competitor, nsid, &envelope).await
        }
    );
    let (status, bytes) = upgrade_result?;
    let upgrade_receipt = publication_receipt(f, status, &bytes)?;
    let (c_status, c_bytes) = competitor_result?;
    let after = head(cid)?;
    println!("[{label}] upgrade receipt {upgrade_receipt}");
    println!("[{label}] competitor {nsid} {c_status}: {}", String::from_utf8_lossy(&c_bytes));
    println!("[{label}] head {after}");
    assert_eq!(legacy_rows(cid)?, l.rows, "[{label}] v1 authority byte-exact");
    if matches!(leg, RaceLeg::SecondUpgrade) {
        let duplicate = publication_receipt(f, c_status, &c_bytes)?;
        assert_eq!(receipt_kind(&upgrade_receipt).0, PUBLISHED, "[{label}]");
        assert_eq!(duplicate, upgrade_receipt, "[{label}] concurrent duplicate returns the one recorded outcome");
        assert_eq!(after["protocolVersion"], "2", "[{label}]");
        assert_eq!(after["generation"], 1, "[{label}]");
        assert_eq!(after["requests"], 1, "[{label}] exactly one publication");
        let entries = db(&format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{cid}' AND seq>1"))?;
        assert_eq!(entries, "1", "[{label}] exactly one introduction entry");
        release(f, cid, &upgrade).await?;
        println!("[{label}] winner singlePublication");
        return Ok("singlePublication");
    }
    let upgrade_won = receipt_kind(&upgrade_receipt).0 == PUBLISHED;
    let competitor_won = match leg {
        _ => c_status == reqwest::StatusCode::OK,
    };
    assert!(
        upgrade_won ^ competitor_won,
        "[{label}] exactly one authoritative winner (upgrade {upgrade_won}, competitor {competitor_won})"
    );
    if !upgrade_won {
        assert_eq!(receipt_kind(&upgrade_receipt), (REJECTED, "StaleLegacyPrior"), "[{label}]");
    }
    // A losing competitor must be refused with a typed, declared protocol
    // code for its endpoint — never an untyped 500.
    if upgrade_won {
        let allowed: &[&str] = match leg {
            RaceLeg::Accept => &["StaleCoordinates", "NotParticipant", "InvitationNotPending", "ConversationNotAccepted"],
            RaceLeg::Close => &["StaleCoordinates", "NotParticipant", "ConversationNotAccepted"],
            RaceLeg::Reset => &["StaleCoordinates", "NotMember", "ConversationNotAccepted"],
            RaceLeg::SecondUpgrade => unreachable!("handled above"),
        };
        let body: Value = serde_json::from_slice(&c_bytes).unwrap_or(Value::Null);
        let code = body["error"].as_str().unwrap_or_default().to_owned();
        println!("[{label}] loser {nsid} typed code {c_status} {code}");
        assert_eq!(c_status, reqwest::StatusCode::BAD_REQUEST, "[{label}] loser must be a typed 400, got {c_status} {code}");
        assert!(allowed.contains(&code.as_str()), "[{label}] loser code {code} not a declared stale/non-pending code {allowed:?}");
    }
    let winner = match (leg, upgrade_won) {
        (_, true) => {
            assert_eq!(after["protocolVersion"], "2", "[{label}]");
            assert_eq!(after["lifecycle"], "active", "[{label}]");
            assert_eq!(after["generation"], 1, "[{label}]");
            assert_eq!(after["requests"], 1, "[{label}]");
            assert_eq!(after["pending"], 1, "[{label}] recipient still pending the request");
            assert_eq!(pending_resets(cid)?, "0", "[{label}]");
            release(f, cid, &upgrade).await?;
            "upgrade"
        }
        (RaceLeg::Accept, false) => {
            assert_eq!(after["protocolVersion"], "1", "[{label}]");
            assert_eq!(after["pending"], 0, "[{label}] recipient accepted");
            assert_eq!(after["requests"], 0, "[{label}]");
            "acceptConversation"
        }
        (RaceLeg::Close, false) => {
            assert_eq!(after["lifecycle"], "superseded", "[{label}]");
            assert_eq!(after["protocolVersion"], "1", "[{label}]");
            assert_eq!(after["requests"], 0, "[{label}]");
            "closeConversation"
        }
        (RaceLeg::Reset, false) => {
            assert_eq!(after["protocolVersion"], "1", "[{label}]");
            assert_eq!(after["requests"], 0, "[{label}]");
            assert_eq!(pending_resets(cid)?, "1", "[{label}]");
            "requestReset"
        }
        (RaceLeg::SecondUpgrade, false) => unreachable!("handled above"),
    };
    println!("[{label}] winner {winner}");
    Ok(winner)
}

async fn race_rounds(leg: RaceLeg, label: &str) -> anyhow::Result<()> {
    let _db = dedicated_database().await?;
    let mut winners = Vec::new();
    for round in 0..5 {
        winners.push(race(leg, &format!("{label}#{round}")).await?);
    }
    println!("[{label}] winners {winners:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_race_acceptance_vs_upgrade() -> anyhow::Result<()> {
    race_rounds(RaceLeg::Accept, "accept").await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_race_close_vs_upgrade() -> anyhow::Result<()> {
    race_rounds(RaceLeg::Close, "close").await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_race_recovery_reset_vs_upgrade() -> anyhow::Result<()> {
    race_rounds(RaceLeg::Reset, "reset").await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_race_stale_head_second_upgrade() -> anyhow::Result<()> {
    race_rounds(RaceLeg::SecondUpgrade, "second-upgrade").await
}

// ---------------------------------------------------------------------------
// C24: retained old client vs capable scoped reader against the same server.
// ---------------------------------------------------------------------------

/// Run the retained pre-change client (built only from the baseline tree) and
/// return its `C24_OLD_RESULT` JSON plus the full process output.
fn run_retained_old_client(
    f: &Fixture,
    party: &Party,
    local_conversations: &[String],
) -> anyhow::Result<(Value, String)> {
    let manifest = std::env::var("C24_OLD_CLIENT_MANIFEST")
        .unwrap_or_else(|_| "/tmp/c23c24-old/catbird-mls/Cargo.toml".into());
    anyhow::ensure!(
        std::path::Path::new(&manifest).exists(),
        "retained old client tree missing at {manifest}"
    );
    // Build first so fixture JWTs are minted immediately before the run.
    let build = std::process::Command::new("cargo")
        .args([
            "test", "--locked", "--manifest-path", &manifest, "--features", "echo-bot",
            "--test", "c24_retained_old_client", "--no-run", "--message-format=json",
        ])
        .env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .output()?;
    anyhow::ensure!(
        build.status.success(),
        "retained old client build failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = String::from_utf8(build.stdout)?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|m| m["target"]["name"] == "c24_retained_old_client" && m["executable"].is_string())
        .and_then(|m| m["executable"].as_str().map(str::to_owned))
        .context("retained old client executable")?;
    let tokens = (0..4)
        .map(|_| {
            party
                .id
                .scoped_jwt_with_jti("blue.catbird.chat.getConversations", Uuid::new_v4())
        })
        .collect::<Vec<_>>()
        .join(",");
    let output = std::process::Command::new(&executable)
        .args(["--exact", "c24_retained_old_client_reconciler", "--nocapture"])
        .env("C24_BASE_URL", &f.server.base_url)
        .env("C24_DID", &party.id.did)
        .env("C24_DEVICE_ID", party.id.device_id.to_string())
        .env("C24_TOKENS", tokens)
        .env("C24_LOCAL_CONVERSATIONS", local_conversations.join(","))
        .output()?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = format!("retained old client executable {executable}\n{text}");
    anyhow::ensure!(output.status.success(), "retained old client run failed:\n{text}");
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("C24_OLD_RESULT "))
        .with_context(|| format!("no C24_OLD_RESULT line:\n{text}"))?;
    Ok((serde_json::from_str(line)?, text))
}

async fn inventory(
    f: &Fixture,
    who: &Party,
    versions: &[&str],
) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let mut query = vec![("limit".to_owned(), "100".to_owned())];
    query.extend(
        versions
            .iter()
            .map(|v| ("supportedProtocolVersions".to_owned(), (*v).to_owned())),
    );
    let (status, bytes) = who
        .id
        .get(&f.client, &f.server.base_url, "blue.catbird.chat.getConversations", &query)
        .await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn listed(page: &Value, cid: Uuid) -> bool {
    page.to_string().contains(&cid.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn c24_retained_old_client_and_capable_scoped_reader() -> anyhow::Result<()> {
    let _db = dedicated_database().await?;
    let f = fixture().await?;
    publish_bob_keys(&f, 2).await?;
    // Alice's capable reader without request support holds real local history
    // for a conversation it created itself through the real client path.
    let (reader, store, reader_log) = capable_orchestrator(&f, &f.alice, true).await?;
    let view = reader
        .create_group("", Some(&[f.bob.id.did.clone()]), None)
        .await
        .context("capable reader createConversation")?;
    let cid = Uuid::parse_str(&view.conversation_id)?;
    let state = read_state(&f, &f.alice, cid).await?;
    let next_seq = head(cid)?["nextSeq"].as_i64().context("nextSeq")?;
    let upgrade = prepare_upgrade(&f, cid, legacy_origin_for(&f, &state)?, next_seq).await?;
    let receipt = publish(&f, &upgrade).await?;
    assert_eq!(receipt_kind(&receipt).0, PUBLISHED, "Alice now participates in a v2 conversation");
    assert_eq!(head(cid)?["protocolVersion"], "2");

    // Server side of the three reads, recorded as evidence.
    let (unscoped_status, unscoped) = inventory(&f, &f.alice, &[]).await?;
    println!("unscoped inventory {unscoped_status}: {unscoped}");
    assert_eq!(unscoped_status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(unscoped["error"], "ProtocolUpgradeRequired");
    let (scoped_status, scoped) = inventory(&f, &f.alice, &["1"]).await?;
    println!("v1-scoped inventory {scoped_status}: {scoped}");
    assert_eq!(scoped_status, reqwest::StatusCode::OK);
    assert!(!listed(&scoped, cid), "v1-scoped inventory omits the v2 conversation");
    let (full_status, full) = inventory(&f, &f.alice, &["1", "2"]).await?;
    println!("v1+v2 inventory {full_status}: {full}");
    assert_eq!(full_status, reqwest::StatusCode::OK);
    assert!(listed(&full, cid), "fully capable inventory lists the v2 conversation");

    // Retained old client: baseline orchestrator reconciler, unscoped read.
    let local = vec![cid.to_string(), Uuid::new_v4().to_string()];
    let (old, old_log) = run_retained_old_client(&f, &f.alice, &local)?;
    println!("retained old client result {old}");
    println!("retained old client log begin\n{old_log}\nretained old client log end");
    assert_eq!(old["syncOk"], false, "old reconciler never gets a successful partial inventory");
    assert_eq!(old["errorStatus"], 400);
    assert!(
        old["errorBody"]
            .as_str()
            .is_some_and(|b| b.contains("ProtocolUpgradeRequired")),
        "explicit upgrade-required error"
    );
    let exchanges = old["exchanges"].as_array().context("exchanges")?;
    assert!(!exchanges.is_empty());
    for exchange in exchanges {
        let path = exchange["path"].as_str().context("path")?;
        assert!(path.starts_with("/xrpc/blue.catbird.chat.getConversations?"));
        assert!(!path.contains("supportedProtocolVersions"), "baseline read is unscoped");
        assert_eq!(exchange["status"], 400);
    }
    assert_eq!(old["localHistoryUnchanged"], true, "no local history deleted");
    assert_eq!(
        old["localAfter"]["conversations"].as_array().map(Vec::len),
        Some(local.len())
    );
    assert_eq!(old["localAfter"]["messageCount"], local.len());
    assert_eq!(old["nativeGroupsAlive"], json!([true, true]));

    // Capable scoped reader: the server omits the record; the reader keeps it.
    use catbird_mls::orchestrator::MLSStorageBackend as _;
    let ids = |rows: &[catbird_mls::orchestrator::ConversationView]| {
        let mut ids = rows
            .iter()
            .map(|c| (c.conversation_id.clone(), c.group_id.clone()))
            .collect::<Vec<_>>();
        ids.sort();
        ids
    };
    let before = ids(&store.list_conversations(&f.alice.id.did).await?);
    assert!(before.iter().any(|(c, _)| c == &cid.to_string()));
    // The inventory snapshot fence is the protocol-instance-wide event head;
    // concurrent writers on the shared database advance it, and after three
    // internal retries the server answers 500 (RetryCeiling). The contract
    // is "caller re-runs the whole call", so the reader re-runs its sync and
    // every failed pass must also leave the omitted record in place.
    let mut attempts = 0;
    loop {
        attempts += 1;
        match reader.sync_with_server(true).await {
            Ok(()) => break,
            Err(error) if attempts < 8 && error.to_string().contains("getConversations 500") => {
                println!("capable reader sync attempt {attempts} hit shared-fence contention: {error}");
                assert_eq!(ids(&store.list_conversations(&f.alice.id.did).await?), before);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(error) => return Err(error).context("capable scoped reader sync"),
        }
    }
    println!("capable reader sync succeeded after {attempts} attempt(s)");
    let log = reader_log.lock().await.clone();
    println!("capable reader inventory exchanges {log:?}");
    let (last_path, last_status) = log.last().context("capable reader read inventory")?;
    assert_eq!(*last_status, 200, "final pass read a real scoped page");
    assert!(last_path.contains("supportedProtocolVersions=1"));
    assert!(!last_path.contains("supportedProtocolVersions=2"));
    let after = ids(&store.list_conversations(&f.alice.id.did).await?);
    println!("capable reader local before {before:?} after {after:?}");
    assert_eq!(before, after, "omitted record preserved by the capable scoped reader");
    reader.shutdown().await;
    release(&f, cid, &upgrade).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Controlled race orders (F36): a psql session holds the conversation head row
// FOR UPDATE (a lock only; it writes nothing). The first request is queued
// behind it, then the second; PostgreSQL grants row-lock waiters in arrival
// order, so releasing the lock makes the first-queued request win.
// ---------------------------------------------------------------------------

struct RowBarrier {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    pid: i64,
}

impl RowBarrier {
    fn hold_conversation(cid: Uuid) -> anyhow::Result<Self> {
        use std::io::{BufRead, Write};
        anyhow::ensure!(
            encrypted_requests::dedicated_request_database_name(request_database_url()).is_some(),
            "controlled races must run on a dedicated database"
        );
        let mut child = std::process::Command::new("psql")
            .args([request_database_url(), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().context("barrier stdin")?;
        writeln!(
            stdin,
            "BEGIN;\nSELECT pg_backend_pid();\n\
             SELECT 1 FROM chat.conversations WHERE conversation_id='{cid}' FOR UPDATE;\n\
             \\echo BARRIER-HELD"
        )?;
        stdin.flush()?;
        let mut lines = std::io::BufReader::new(child.stdout.take().context("barrier stdout")?).lines();
        let pid: i64 = lines.next().context("barrier pid")??.trim().parse()?;
        for line in lines.by_ref() {
            if line?.trim() == "BARRIER-HELD" {
                return Ok(Self { child, stdin, pid });
            }
        }
        anyhow::bail!("barrier session exited before holding the conversation lock")
    }

    /// Sessions blocked, directly or transitively, by the barrier session.
    fn waiters(&self) -> anyhow::Result<i64> {
        Ok(db(&format!(
            "WITH RECURSIVE w(pid) AS (SELECT pid FROM pg_stat_activity WHERE {b}=ANY(pg_blocking_pids(pid)) \
             UNION SELECT a.pid FROM pg_stat_activity a JOIN w ON w.pid=ANY(pg_blocking_pids(a.pid))) \
             SELECT count(*) FROM w",
            b = self.pid
        ))?
        .parse()?)
    }

    async fn wait_for_waiters(&self, at_least: i64) -> anyhow::Result<i64> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let n = self.waiters()?;
            if n >= at_least {
                return Ok(n);
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "only {n}/{at_least} sessions queued");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    fn release(mut self) -> anyhow::Result<()> {
        use std::io::Write;
        writeln!(self.stdin, "COMMIT;\n\\q")?;
        self.stdin.flush()?;
        anyhow::ensure!(self.child.wait()?.success(), "barrier session failed");
        Ok(())
    }
}

type PostHandle = tokio::task::JoinHandle<anyhow::Result<(reqwest::StatusCode, Vec<u8>)>>;

fn spawn_post(f: &Fixture, who: &Party, nsid: &'static str, envelope: Value) -> PostHandle {
    let (id, client, base) = (who.id.clone(), f.client.clone(), f.server.base_url.clone());
    tokio::spawn(async move { id.post(&client, &base, nsid, &envelope, true).await })
}

#[derive(Clone, Copy, Debug)]
enum Order {
    UpgradeFirst,
    CompetitorFirst,
}

/// The declared code a competitor must receive when a committed v1->v2
/// upgrade precedes it (observed under controlled order; each is in that
/// endpoint's lexicon error list):
/// - requestReset: the head is now a pending v2 request -> ConversationNotAccepted.
/// - closeConversation (declares no ConversationNotAccepted): its signed
///   generation-0 prior is stale -> StaleCoordinates.
/// - v1 acceptConversation: the pending invitation now belongs to the v2
///   request, not the v1 participant path -> NotParticipant.
fn expected_loser_code(leg: RaceLeg) -> &'static str {
    match leg {
        RaceLeg::Accept => "NotParticipant",
        RaceLeg::Close => "StaleCoordinates",
        RaceLeg::Reset => "ConversationNotAccepted",
        RaceLeg::SecondUpgrade => unreachable!(),
    }
}

async fn controlled(leg: RaceLeg, order: Order, label: &str) -> anyhow::Result<String> {
    let l = legacy_fixture().await?;
    let (f, cid) = (&l.f, l.cid);
    let upgrade = prepare_upgrade(f, cid, l.origin.clone(), l.next_seq).await?;
    let (nsid, envelope) = competing(&l, leg).await?;
    let competitor = match leg {
        RaceLeg::Accept => &f.bob,
        _ => &f.alice,
    };
    let publish_envelope = json!({"signedRequest":upgrade.publication});
    let upgrade_first = matches!(order, Order::UpgradeFirst);
    let barrier = RowBarrier::hold_conversation(cid)?;
    let spawn_upgrade = || spawn_post(f, &f.alice, "blue.catbird.chat.publishDirectRequest", publish_envelope.clone());
    let spawn_competitor = || spawn_post(f, competitor, nsid, envelope.clone());
    let first = if upgrade_first { spawn_upgrade() } else { spawn_competitor() };
    let queued_first = barrier.wait_for_waiters(1).await?;
    let second = if upgrade_first { spawn_competitor() } else { spawn_upgrade() };
    let queued_both = barrier.wait_for_waiters(2).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    barrier.release()?;
    let (first_status, first_bytes) = first.await??;
    let (second_status, second_bytes) = second.await??;
    let ((u_status, u_bytes), (c_status, c_bytes)) = if upgrade_first {
        ((first_status, first_bytes), (second_status, second_bytes))
    } else {
        ((second_status, second_bytes), (first_status, first_bytes))
    };
    let receipt = publication_receipt(f, u_status, &u_bytes)?;
    let after = head(cid)?;
    let c_body: Value = serde_json::from_slice(&c_bytes).unwrap_or(Value::Null);
    println!(
        "[{label}] queued first={queued_first} both={queued_both}; upgrade {:?}; competitor {nsid} {c_status} {}; head {after}",
        receipt_kind(&receipt),
        c_body["error"].as_str().unwrap_or("ok")
    );
    assert_eq!(legacy_rows(cid)?, l.rows, "[{label}] v1 authority byte-exact");
    let outcome = match order {
        Order::UpgradeFirst => {
            assert_eq!(receipt_kind(&receipt).0, PUBLISHED, "[{label}] upgrade queued first must publish");
            assert_eq!(after["protocolVersion"], "2", "[{label}]");
            assert_eq!(after["generation"], 1, "[{label}]");
            assert_eq!(after["lifecycle"], "active", "[{label}]");
            assert_eq!(after["requests"], 1, "[{label}]");
            assert_eq!(after["pending"], 1, "[{label}]");
            assert_eq!(pending_resets(cid)?, "0", "[{label}]");
            assert_eq!(
                (c_status, c_body["error"].as_str().unwrap_or_default()),
                (reqwest::StatusCode::BAD_REQUEST, expected_loser_code(leg)),
                "[{label}] typed loser code, body {}",
                String::from_utf8_lossy(&c_bytes)
            );
            release(f, cid, &upgrade).await?;
            format!("upgrade; loser {}", expected_loser_code(leg))
        }
        Order::CompetitorFirst => {
            assert_eq!(c_status, reqwest::StatusCode::OK, "[{label}] competitor queued first must win: {}", String::from_utf8_lossy(&c_bytes));
            assert_eq!(receipt_kind(&receipt), (REJECTED, "StaleLegacyPrior"), "[{label}]");
            assert_eq!(after["protocolVersion"], "1", "[{label}]");
            assert_eq!(after["requests"], 0, "[{label}]");
            match leg {
                RaceLeg::Accept => assert_eq!(after["pending"], 0, "[{label}]"),
                RaceLeg::Close => assert_eq!(after["lifecycle"], "superseded", "[{label}]"),
                RaceLeg::Reset => assert_eq!(pending_resets(cid)?, "1", "[{label}]"),
                RaceLeg::SecondUpgrade => unreachable!(),
            }
            "competitor; upgrade StaleLegacyPrior".to_owned()
        }
    };
    println!("[{label}] outcome {outcome}");
    Ok(outcome)
}

async fn controlled_rounds(leg: RaceLeg, order: Order) -> anyhow::Result<()> {
    let _db = dedicated_database().await?;
    let label = format!("{leg:?}-{order:?}");
    let mut outcomes = Vec::new();
    for round in 0..5 {
        outcomes.push(controlled(leg, order, &format!("{label}#{round}")).await?);
    }
    println!("[{label}] outcomes {outcomes:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_controlled_reset_loses_to_upgrade() -> anyhow::Result<()> {
    controlled_rounds(RaceLeg::Reset, Order::UpgradeFirst).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_controlled_close_loses_to_upgrade() -> anyhow::Result<()> {
    controlled_rounds(RaceLeg::Close, Order::UpgradeFirst).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_controlled_accept_loses_to_upgrade() -> anyhow::Result<()> {
    controlled_rounds(RaceLeg::Accept, Order::UpgradeFirst).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_controlled_upgrade_loses_to_reset() -> anyhow::Result<()> {
    controlled_rounds(RaceLeg::Reset, Order::CompetitorFirst).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c23_controlled_upgrade_loses_to_close() -> anyhow::Result<()> {
    controlled_rounds(RaceLeg::Close, Order::CompetitorFirst).await
}

//! C11: success with lost response.
//!
//! The shipping router commits the publication, then the deterministic
//! transport discards the real response (`AfterRequestBeforeResponse`), so the
//! sender's durable journal stays `OutcomeUnknown`. A child OS process opens
//! the SQLCipher store and is SIGKILLed while holding it; a second child process
//! reopens the store and calls production `resume_direct_request`, replaying
//! the exact signed publication to adopt the committed receipt and project once.
//! The parent checks the server graph and that the published ciphertext is the
//! durable journal's bytes (no regeneration, one package, one push event).
#![allow(dead_code)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;
#[path = "support/staged_direct_request.rs"]
mod staged;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    orchestrator::{
        api_client::MLSAPIClient,
        canonical_transport::{GatewayResponse, PreparedRequest},
        direct_request_bootstrap::DirectRequestIntroductionResult,
        direct_request_journal::{DirectRequestJournal, DirectRequestJournalPhase},
        CredentialStore, MLSOrchestrator, MlsCryptoContext, OrchestratorConfig, OrchestratorError,
    },
    DirectRequestOutcome,
};
use live_orchestrator::{
    mock_credentials::MockCredentials,
    mock_storage::MockStorage,
};
use std::sync::Arc;
use encrypted_requests::{
    canonical_now, request_database_snapshot, request_database_url, signed_mls_request,
    DeterministicFaultTransport, FaultBoundary,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::BufRead as _, path::PathBuf, process::Stdio, time::Duration};
use uuid::Uuid;

const TEST_NAME: &str = "c11_committed_publication_lost_response_resolves_after_process_restart";
const ROLE_ENV: &str = "C11_CHILD_ROLE";
const RESULT_PREFIX: &str = "C11_CHILD_RESULT ";

fn psql(sql: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("psql")
        .args([request_database_url(), "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Server rows that a duplicate publication, regenerated ciphertext, extra
/// package consumption or extra notification would change.
fn server_graph(request: Uuid, conversation: Uuid) -> anyhow::Result<String> {
    psql(&format!(
        "SELECT jsonb_build_object(\
          'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{request}'),\
          'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{request}'),\
          'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{request}'),\
          'packages',(SELECT jsonb_agg(to_jsonb(k) ORDER BY key_package_ref) FROM chat.key_packages k WHERE terminal_transition_id='{request}'),\
          'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{conversation}'),\
          'push',(SELECT jsonb_agg(to_jsonb(p) ORDER BY event_id) FROM chat.direct_request_push_events p WHERE request_id='{request}'),\
          'pushRecipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY recipient_device_id) FROM chat.direct_request_push_event_recipients r WHERE request_id='{request}')\
        )::text"
    ))
}

fn count(sql: &str) -> anyhow::Result<i64> {
    Ok(psql(sql)?.parse()?)
}

fn spawn_child(role: &str, envs: &[(&str, String)]) -> anyhow::Result<std::process::Child> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(ROLE_ENV, role)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }
    Ok(command.spawn()?)
}

fn child_result(output: &[u8]) -> anyhow::Result<Value> {
    let line = String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.split_once(RESULT_PREFIX).map(|(_, json)| json.to_owned()))
        .context("child printed no result line")?;
    Ok(serde_json::from_str(&line)?)
}

fn phase_name(journal: &DirectRequestJournal) -> String {
    format!("{:?}", journal.phase)
}

struct ResolverApiClient {
    base_url: String,
    bearer: String,
    did: String,
    client: reqwest::Client,
}

#[async_trait::async_trait]
impl MLSAPIClient for ResolverApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        did == self.did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.did.clone())
    }

    async fn submit_prepared_request(
        &self,
        request: PreparedRequest,
    ) -> Result<GatewayResponse, OrchestratorError> {
        let (path, query) = match request.path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.path.as_str(), None),
        };
        let mut url = format!("{}{}", self.base_url, path);
        if let Some(q) = query {
            url.push('?');
            url.push_str(q);
        }
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            other => return Err(OrchestratorError::Api(format!("unsupported method {other}"))),
        };
        let mut req = self
            .client
            .request(method, &url)
            .bearer_auth(&self.bearer);
        if let Some(body) = request.body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = req
            .send()
            .await
            .map_err(|error| OrchestratorError::Api(format!("request failed: {error:#}")))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| OrchestratorError::Api(format!("read body failed: {error:#}")))?
            .to_vec();
        Ok(GatewayResponse {
            status,
            content_type: Some("application/json".into()),
            body,
        })
    }

    async fn get_conversations(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
    ) -> Result<catbird_mls::orchestrator::ConversationListPage, OrchestratorError> {
        Err(OrchestratorError::Api("get_conversations outside projection".into()))
    }

    async fn get_messages(
        &self,
        _convo_id: &str,
        _cursor: Option<&str>,
        _limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> Result<(Vec<catbird_mls::orchestrator::IncomingEnvelope>, Option<String>), OrchestratorError> {
        Err(OrchestratorError::Api("get_messages outside projection".into()))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        _dids: &[String],
    ) -> Result<Vec<catbird_mls::orchestrator::KeyPackageRef>, OrchestratorError> {
        Err(OrchestratorError::Api("get_key_packages outside projection".into()))
    }

    async fn get_key_package_stats(&self) -> Result<catbird_mls::orchestrator::KeyPackageStats, OrchestratorError> {
        Err(OrchestratorError::Api("get_key_package_stats outside projection".into()))
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<catbird_mls::orchestrator::KeyPackageSyncResult, OrchestratorError> {
        Err(OrchestratorError::Api("sync_key_packages outside projection".into()))
    }

    async fn list_devices(
        &self,
        _actor_device_id: &str,
    ) -> Result<Vec<catbird_mls::orchestrator::DeviceInfo>, OrchestratorError> {
        Err(OrchestratorError::Api("list_devices outside projection".into()))
    }

    async fn get_group_info(&self, _convo_id: &str) -> Result<Vec<u8>, OrchestratorError> {
        Err(OrchestratorError::Api("get_group_info outside projection".into()))
    }
}

/// Child role `holder`: open the store in a fresh process, prove it holds the
/// unknown attempt, signal readiness, and wait to be SIGKILLed.
fn run_holder() -> anyhow::Result<()> {
    let dir = PathBuf::from(std::env::var("C11_STORE_DIR")?);
    let request = Uuid::parse_str(&std::env::var("C11_REQUEST_ID")?)?;
    let ctx = staged::open_sender_store(&dir)?;
    let journal = staged::journal(&ctx, request)?;
    println!(
        "{RESULT_PREFIX}{}",
        json!({"pid":std::process::id(),"phase":phase_name(&journal)})
    );
    std::fs::write(std::env::var("C11_READY_FILE")?, b"holding")?;
    std::thread::sleep(Duration::from_secs(120));
    anyhow::bail!("holder was not killed")
}

/// Child role `resolver`: reopen the store in another fresh process and resolve
/// the unknown attempt through the actual production client projection and
/// host conversation creation path (`MLSOrchestrator::resume_direct_request`).
async fn run_resolver() -> anyhow::Result<()> {
    let dir = PathBuf::from(std::env::var("C11_STORE_DIR")?);
    let request = Uuid::parse_str(&std::env::var("C11_REQUEST_ID")?)?;
    let actor_did = std::env::var("C11_ACTOR_DID")?;
    let actor_device = std::env::var("C11_ACTOR_DEVICE")?;
    let draft_id = std::env::var("C11_DRAFT_ID")?;
    let base_url = std::env::var("C11_BASE_URL")?;
    let bearer = std::env::var("C11_BEARER")?;
    let authority_doc = hex::decode(std::env::var("C11_AUTHORITY_DOC")?)?;

    let ctx = staged::open_sender_store(&dir)?;
    let before = staged::journal(&ctx, request)?;
    let phase_before = phase_name(&before);

    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(authority_doc);
    credentials
        .store_device_uuid(&actor_did, &actor_device)
        .await
        .map_err(|error| anyhow::anyhow!("store device uuid: {error}"))?;
    credentials
        .store_mls_did(&actor_did, &actor_did)
        .await
        .map_err(|error| anyhow::anyhow!("store mls did: {error}"))?;

    let storage = Arc::new(MockStorage::new());
    let api_client = Arc::new(ResolverApiClient {
        base_url: base_url.clone(),
        bearer: bearer.clone(),
        did: actor_did.clone(),
        client: reqwest::Client::new(),
    });

    let orchestrator = MLSOrchestrator::new(
        ctx.clone(),
        storage.clone(),
        api_client,
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator
        .initialize(&actor_did)
        .await
        .map_err(|error| anyhow::anyhow!("orchestrator init: {error}"))?;

    // 1. Invoke actual production client projection and host conversation creation
    let outcome = orchestrator
        .resume_direct_request(&draft_id)
        .await
        .map_err(|error| anyhow::anyhow!("resume direct request: {error}"))?;
    anyhow::ensure!(
        matches!(outcome, DirectRequestOutcome::RequestSent { .. }),
        "expected RequestSent, got {outcome:?}"
    );

    // 2. Verify host conversation was created in storage
    let host_conversations = storage.conversation_count();
    anyhow::ensure!(
        host_conversations == 1,
        "expected exactly 1 host conversation created, got {host_conversations}"
    );

    // 3. Verify client projection was written and persisted in MLSContext
    let journal = staged::journal(&ctx, request)?;
    let cid = journal.conversation_id.clone();
    let projection = ctx
        .read_direct_request_projection(&cid)
        .map_err(|error| anyhow::anyhow!("read projection: {error}"))?;
    anyhow::ensure!(
        projection.is_some(),
        "client projection must be persisted in storage"
    );
    let projection_count = ctx
        .list_direct_request_projections()
        .map_err(|error| anyhow::anyhow!("list projections: {error}"))?
        .len();
    anyhow::ensure!(
        projection_count == 1,
        "expected exactly 1 client projection, got {projection_count}"
    );

    // 4. Replay resolution: must be idempotent, creating NO duplicate projection or conversation
    let replay_outcome = orchestrator
        .resume_direct_request(&draft_id)
        .await
        .map_err(|error| anyhow::anyhow!("replayed resume direct request: {error}"))?;
    anyhow::ensure!(
        matches!(replay_outcome, DirectRequestOutcome::RequestSent { .. }),
        "replayed resolution must return RequestSent, got {replay_outcome:?}"
    );
    anyhow::ensure!(
        storage.conversation_count() == 1,
        "host conversation must not duplicate on replay"
    );
    anyhow::ensure!(
        ctx.list_direct_request_projections()
            .map_err(|error| anyhow::anyhow!("list projections: {error}"))?
            .len()
            == 1,
        "projection must not duplicate on replay"
    );

    let after = staged::journal(&ctx, request)?;
    let journal_rows = ctx
        .list_direct_request_journal()
        .map_err(|error| anyhow::anyhow!("list: {error}"))?
        .len();
    let receipt_bytes = after
        .terminal_receipt
        .as_deref()
        .context("terminal receipt missing from journal")?;
    let mut receipt: Value = serde_json::from_slice(receipt_bytes)?;
    if let Some(obj) = receipt.as_object_mut() {
        obj.remove("$type");
    }
    staged::close_sender_store(ctx)?;
    println!(
        "{RESULT_PREFIX}{}",
        json!({
            "pid": std::process::id(),
            "phaseBefore": phase_before,
            "phaseAfter": phase_name(&after),
            "hostConversations": storage.conversation_count(),
            "projections": projection_count,
            "journalRows": journal_rows,
            "conversationId": cid,
            "receipt": receipt,
            "journal": serde_json::to_value(&after)?
        })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c11_committed_publication_lost_response_resolves_after_process_restart(
) -> anyhow::Result<()> {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("holder") => return run_holder(),
        Ok("resolver") => return run_resolver().await,
        Ok(other) => anyhow::bail!("unknown child role {other}"),
        Err(_) => {}
    }
    let mut f = staged::stage_request("c11").await?;
    let request = f.request_id;
    let sender = f.sender.take().context("sender store")?;
    let staged_journal = staged::journal(&sender, request)?;
    assert_eq!(staged_journal.phase, DirectRequestJournalPhase::OutcomeUnknown);
    assert_eq!(staged_journal.publish_request.as_deref(), Some(f.exact_publication.as_slice()));
    let package_status_sql = format!(
        "SELECT status FROM chat.key_packages WHERE key_package_ref=decode('{}','hex')",
        hex::encode(&f.bob_package_ref)
    );
    assert_eq!(psql(&package_status_sql)?, "reserved");
    assert_eq!(
        count(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request}'"))?,
        0
    );

    // 1. Server commits; the real response is discarded before the client sees it.
    let mut transport = DeterministicFaultTransport::default()
        .fail_on(FaultBoundary::AfterRequestBeforeResponse, 1)?;
    let lost = f.post_publication(&mut transport).await;
    let error = lost.expect_err("response must be lost after the request reached the server");
    assert!(
        error.to_string().contains("AfterRequestBeforeResponse"),
        "unexpected transport failure: {error:#}"
    );
    assert_eq!(
        transport.trace(),
        &[FaultBoundary::BeforeRequest, FaultBoundary::AfterRequestBeforeResponse]
    );
    let committed_graph = server_graph(request, f.conversation_id)?;
    assert_eq!(
        count(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request}'"))?,
        1,
        "server must have committed the publication whose response was lost"
    );
    let journal = staged::journal(&sender, request)?;
    assert_eq!(
        journal.phase,
        DirectRequestJournalPhase::OutcomeUnknown,
        "client never saw the response: journal must remain OutcomeUnknown"
    );
    staged::close_sender_store(sender)?;

    // 2. A different process takes the store and is killed while holding it.
    let store_dir = f.sender_dir.to_string_lossy().into_owned();
    let ready = std::env::temp_dir().join(format!("c11-holder-ready-{}", Uuid::new_v4()));
    let mut holder = spawn_child(
        "holder",
        &[
            ("C11_STORE_DIR", store_dir.clone()),
            ("C11_REQUEST_ID", request.to_string()),
            ("C11_READY_FILE", ready.to_string_lossy().into_owned()),
        ],
    )?;
    let holder_stdout = holder.stdout.take().context("holder stdout")?;
    let holder_line = tokio::task::spawn_blocking(move || {
        std::io::BufReader::new(holder_stdout)
            .lines()
            .map_while(Result::ok)
            .find(|line| line.contains(RESULT_PREFIX))
    });
    for _ in 0..600 {
        if ready.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(ready.exists(), "holder never opened the store");
    let holder_pid = holder.id();
    holder.kill()?; // SIGKILL
    let holder_status = holder.wait()?;
    std::fs::remove_file(&ready).ok();
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(holder_status.signal(), Some(9), "holder must die by SIGKILL");
    }
    let holder_result = child_result(
        holder_line
            .await?
            .context("holder result line")?
            .as_bytes(),
    )?;
    assert_eq!(holder_result["pid"], holder_pid);
    assert_eq!(holder_result["phase"], "OutcomeUnknown");
    assert_ne!(holder_pid, std::process::id());

    // 3. A new process reopens the killed store and resolves the same attempt
    //    through the actual production client projection and host conversation creation path.
    let resolver_envs = [
        ("C11_STORE_DIR", store_dir.clone()),
        ("C11_REQUEST_ID", request.to_string()),
        ("C11_BASE_URL", f.server.base_url.clone()),
        (
            "C11_BEARER",
            f.alice.scoped_jwt_with_jti(staged::PUBLISH_NSID, Uuid::new_v4()),
        ),
        ("C11_ACTOR_DID", f.alice.did.clone()),
        ("C11_ACTOR_DEVICE", f.alice.device_id.to_string()),
        ("C11_DRAFT_ID", f.draft_id.clone()),
        ("C11_AUTHORITY_KEY", hex::encode(&f.server.receipt_public_key)),
        ("C11_AUTHORITY_DOC", hex::encode(&f.server.receipt_document)),
    ];
    let resolver = spawn_child("resolver", &resolver_envs)?;
    let output = tokio::task::spawn_blocking(move || resolver.wait_with_output()).await??;
    anyhow::ensure!(output.status.success(), "resolver process failed");
    let resolved = child_result(&output.stdout)?;
    assert_ne!(resolved["pid"], holder_pid);
    assert_ne!(resolved["pid"], std::process::id());
    assert_eq!(resolved["phaseBefore"], "OutcomeUnknown");
    assert_eq!(resolved["phaseAfter"], "RequestSent", "projected exactly once");
    assert_eq!(resolved["hostConversations"], 1, "exactly one host conversation");
    assert_eq!(resolved["projections"], 1, "exactly one projection");
    assert_eq!(resolved["journalRows"], 1);

    // Repeat process restart & resolution: a second fresh child process reopens the store
    let resolver2 = spawn_child(
        "resolver",
        &[
            ("C11_STORE_DIR", store_dir),
            ("C11_REQUEST_ID", request.to_string()),
            ("C11_BASE_URL", f.server.base_url.clone()),
            (
                "C11_BEARER",
                f.alice.scoped_jwt_with_jti(staged::PUBLISH_NSID, Uuid::new_v4()),
            ),
            ("C11_ACTOR_DID", f.alice.did.clone()),
            ("C11_ACTOR_DEVICE", f.alice.device_id.to_string()),
            ("C11_DRAFT_ID", f.draft_id.clone()),
            ("C11_AUTHORITY_KEY", hex::encode(&f.server.receipt_public_key)),
            ("C11_AUTHORITY_DOC", hex::encode(&f.server.receipt_document)),
        ],
    )?;
    let output2 = tokio::task::spawn_blocking(move || resolver2.wait_with_output()).await??;
    anyhow::ensure!(output2.status.success(), "repeat resolver process failed");
    let resolved2 = child_result(&output2.stdout)?;
    assert_ne!(resolved2["pid"], resolved["pid"]);
    assert_ne!(resolved2["pid"], std::process::id());
    assert_eq!(resolved2["phaseBefore"], "RequestSent");
    assert_eq!(resolved2["phaseAfter"], "RequestSent");
    assert_eq!(resolved2["hostConversations"], 1);
    assert_eq!(resolved2["projections"], 1);
    assert_eq!(resolved2["journalRows"], 1);

    // Verify persisted projection on disk in the parent process across repeat restarts
    let sender_reopened = staged::open_sender_store(&f.sender_dir)?;
    let persisted_proj = sender_reopened
        .read_direct_request_projection(&f.conversation_id.to_string())?
        .context("persisted projection must exist on disk")?;
    assert!(!persisted_proj.is_empty(), "persisted projection bytes must be present");
    assert_eq!(
        sender_reopened.list_direct_request_projections()?.len(),
        1,
        "exactly one persisted projection across repeat restarts"
    );
    staged::close_sender_store(sender_reopened)?;

    let receipt = f.verified_published_receipt(&resolved["receipt"])?;
    let durable: DirectRequestJournal = serde_json::from_value(resolved["journal"].clone())?;
    assert_eq!(durable.request_id, request.to_string());

    // 4. No regenerated ciphertext: server bytes equal the durable journal bytes.
    let durable_publish = durable
        .publish_request
        .as_deref()
        .context("durable journal publish bytes")?;
    assert_eq!(durable_publish, f.exact_publication.as_slice());
    let durable_wrapper: Value = serde_json::from_slice(durable_publish)?;
    let durable_ciphertext = STANDARD.decode(
        durable_wrapper["signedRequest"]["body"]["artifacts"]["initialCiphertext"]
            .as_str()
            .context("durable initial ciphertext")?,
    )?;
    assert_eq!(durable_ciphertext, durable.bootstrap.initial_ciphertext);
    let server_row = psql(&format!(
        "SELECT encode(initial_ciphertext,'hex')||' '||encode(full_welcome,'hex')||' '||encode(signed_publication,'base64') FROM chat.direct_request_publications WHERE request_id='{request}'"
    ))?;
    let mut fields = server_row.split(' ');
    assert_eq!(
        fields.next().context("ciphertext")?,
        hex::encode(&durable.bootstrap.initial_ciphertext),
        "server ciphertext must be the durable journal ciphertext"
    );
    assert_eq!(
        fields.next().context("welcome")?,
        hex::encode(&durable.bootstrap.welcome),
        "server Welcome must be the durable journal Welcome"
    );
    let server_signed: Value = serde_json::from_slice(
        &STANDARD.decode(fields.collect::<String>().replace('\n', ""))?,
    )?;
    assert_eq!(server_signed, durable_wrapper["signedRequest"]);

    // 5. Exactly-once server effects; resolution did not mutate the server.
    assert_eq!(server_graph(request, f.conversation_id)?, committed_graph);
    assert_eq!(psql(&package_status_sql)?, "consumed");
    assert_eq!(
        count(&format!("SELECT count(*) FROM chat.key_packages WHERE terminal_transition_id='{request}' AND status='consumed'"))?,
        1,
        "exactly one key package consumed"
    );
    assert_eq!(
        count(&format!("SELECT count(*) FROM chat.direct_request_push_events WHERE request_id='{request}'"))?,
        1,
        "exactly one notification event"
    );
    let snapshot = request_database_snapshot(request)?;
    assert_eq!(
        (snapshot.request_rows, snapshot.message_rows, snapshot.welcome_rows),
        (1, 1, 1)
    );

    // 6. The recipient decrypts the durable (never regenerated) introduction.
    let welcome = f.welcome_input(durable.bootstrap.clone(), &receipt)?;
    f.bob_engine.process_direct_request(&welcome)?;
    let DirectRequestIntroductionResult::Ready { plaintext } =
        f.bob_engine.decrypt_direct_request(&welcome)?
    else {
        anyhow::bail!("introduction must be ready for Bob")
    };
    assert_eq!(
        protocol::decode_direct_request_introduction(&plaintext)?["text"],
        "Real encrypted first contact"
    );
    println!(
        "C11 evidence request={request} holderPid={holder_pid} resolverPid={} ciphertextSha256={}",
        resolved["pid"],
        hex::encode(Sha256::digest(&durable.bootstrap.initial_ciphertext))
    );

    // 7. Capacity hygiene: release the committed request through the real
    //    signed acceptance RPC (the shared pending budget never frees by time).
    let prior = welcome.bootstrap.coordinates.clone();
    let bob_public = f.bob_engine.identity_public_key(&f.bob_identity)?;
    let transition = Uuid::new_v4();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("state version")? + 1);
    let accept = signed_mls_request(
        &f.bob_engine,
        &f.bob_identity,
        DirectRequestKind::Accept,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0", "protocolVersion":"2",
            "actorDid":f.bob.did, "actorDeviceId":f.bob.device_id.to_string(),
            "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)), "authGeneration":1,
            "requestId":request.to_string(), "transitionId":transition.to_string(),
            "prior":prior, "next":next,
            "invitationProvenance":{"invitationTransitionId":request.to_string(),
                "invitedByDid":f.alice.did,"invitedByDeviceId":f.alice.device_id.to_string()},
            "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, body) = f
        .bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acceptConversation",
            &json!({"directRequest":accept}),
            true,
        )
        .await?;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "release acceptance failed: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        count(&format!("SELECT count(*) FROM chat.direct_request_acceptance_claims WHERE request_id='{request}'"))?,
        1,
        "request released by exactly one acceptance claim"
    );
    println!("C11 capacity hygiene: request {request} released via signed acceptance");
    Ok(())
}

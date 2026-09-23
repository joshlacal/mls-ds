//! C11: success with lost response.
//!
//! The shipping router commits the publication, then the deterministic
//! transport discards the real response (`AfterRequestBeforeResponse`), so the
//! sender's durable journal stays `OutcomeUnknown`. A child OS process opens
//! the SQCipher store and is SIGKILLed while holding it; a second child process
//! reopens the store and resolves the same attempt through
//! `getDirectRequestOutcome` + `confirm_published_bootstrap`, projecting once.
//! The parent checks the server graph and that the published ciphertext is the
//! durable journal's bytes (no regeneration, one package, one push event).
#![allow(dead_code)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/staged_direct_request.rs"]
mod staged;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::{
    chat_v2::transcript::direct_request as protocol,
    orchestrator::{
        direct_request_bootstrap::DirectRequestIntroductionResult,
        direct_request_journal::{DirectRequestJournal, DirectRequestJournalPhase},
        MlsCryptoContext,
    },
};
use encrypted_requests::{
    request_database_snapshot, request_database_url, DeterministicFaultTransport, FaultBoundary,
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
/// the unknown attempt through the normal outcome path.
async fn run_resolver() -> anyhow::Result<()> {
    let dir = PathBuf::from(std::env::var("C11_STORE_DIR")?);
    let request = Uuid::parse_str(&std::env::var("C11_REQUEST_ID")?)?;
    let authority = hex::decode(std::env::var("C11_AUTHORITY_KEY")?)?;
    let ctx = staged::open_sender_store(&dir)?;
    let before = staged::journal(&ctx, request)?;
    anyhow::ensure!(
        before.phase == DirectRequestJournalPhase::OutcomeUnknown,
        "reopened journal must still be OutcomeUnknown, got {:?}",
        before.phase
    );
    let response = reqwest::Client::new()
        .get(format!(
            "{}/xrpc/{}",
            std::env::var("C11_BASE_URL")?,
            staged::OUTCOME_NSID
        ))
        .bearer_auth(std::env::var("C11_BEARER")?)
        .query(&[
            ("actorDeviceId", std::env::var("C11_ACTOR_DEVICE")?),
            ("requestId", request.to_string()),
        ])
        .send()
        .await?;
    anyhow::ensure!(response.status() == reqwest::StatusCode::OK, "outcome status {}", response.status());
    let outcome: Value = response.json().await?;
    let mut receipt = outcome["outcome"].clone();
    receipt.as_object_mut().context("outcome")?.remove("$type");
    let receipt_bytes = serde_json::to_vec(&receipt)?;
    let confirmed = ctx
        .confirm_published_bootstrap(&request.to_string(), &receipt_bytes, &authority)
        .map_err(|error| anyhow::anyhow!("confirm: {error}"))?;
    let confirmed_phase = phase_name(&confirmed);
    ctx.mark_direct_request_projected(&request.to_string())
        .map_err(|error| anyhow::anyhow!("project: {error}"))?;
    // Replays of resolution and projection are idempotent: no second projection.
    let reconfirmed = ctx
        .confirm_published_bootstrap(&request.to_string(), &receipt_bytes, &authority)
        .map_err(|error| anyhow::anyhow!("reconfirm: {error}"))?;
    ctx.mark_direct_request_projected(&request.to_string())
        .map_err(|error| anyhow::anyhow!("reproject: {error}"))?;
    let after = staged::journal(&ctx, request)?;
    let journal_rows = ctx
        .list_direct_request_journal()
        .map_err(|error| anyhow::anyhow!("list: {error}"))?
        .len();
    staged::close_sender_store(ctx)?;
    println!(
        "{RESULT_PREFIX}{}",
        json!({
            "pid":std::process::id(),
            "phaseBefore":phase_name(&before),
            "phaseConfirmed":confirmed_phase,
            "phaseAfter":phase_name(&after),
            "reconfirmedPhase":phase_name(&reconfirmed),
            "reconfirmedReceiptIdentical":reconfirmed.terminal_receipt == after.terminal_receipt,
            "journalRows":journal_rows,
            "receipt":receipt,
            "journal":serde_json::to_value(&after)?
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

    // 3. A new process reopens the killed store and resolves the same attempt.
    let resolver = spawn_child(
        "resolver",
        &[
            ("C11_STORE_DIR", store_dir),
            ("C11_REQUEST_ID", request.to_string()),
            ("C11_BASE_URL", f.server.base_url.clone()),
            (
                "C11_BEARER",
                f.alice.scoped_jwt_with_jti(staged::OUTCOME_NSID, Uuid::new_v4()),
            ),
            ("C11_ACTOR_DEVICE", f.alice.device_id.to_string()),
            ("C11_AUTHORITY_KEY", hex::encode(&f.server.receipt_public_key)),
        ],
    )?;
    let output = tokio::task::spawn_blocking(move || resolver.wait_with_output()).await??;
    anyhow::ensure!(output.status.success(), "resolver process failed");
    let resolved = child_result(&output.stdout)?;
    assert_ne!(resolved["pid"], holder_pid);
    assert_ne!(resolved["pid"], std::process::id());
    assert_eq!(resolved["phaseBefore"], "OutcomeUnknown");
    assert_eq!(resolved["phaseConfirmed"], "PublishedAwaitingProjection");
    assert_eq!(resolved["phaseAfter"], "RequestSent", "projected exactly once");
    assert_eq!(resolved["reconfirmedPhase"], "RequestSent", "replayed resolution does not re-project");
    assert_eq!(resolved["reconfirmedReceiptIdentical"], true);
    assert_eq!(resolved["journalRows"], 1);
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
    Ok(())
}

//! C13 (expiry and unknown outcome) and the C12 preparation-timeout race, on
//! real 300-second preparation leases.
//!
//! Leases are measured on PostgreSQL `clock_timestamp()`, so this binary runs
//! with every clock under one libfaketime control file: the test process
//! (client signatures, service JWTs), every server fixture it spawns, and a
//! dedicated loopback PostgreSQL cluster (`support/faketime_postgres.py
//! --clock-file`) to which the whole harness is routed. Requests are prepared
//! at offset +0 through the real RPCs; the shared clock then moves past the
//! lease. No protocol row is written by the test. The production expiry
//! sweeper (`run_chat_expiry_sweeper` -> `expire_due_preparations`) runs only in
//! the one fixture started with `REQUEST_FIXTURE_EXPIRY_SWEEP=1`, and only
//! after every other prepared request here is terminal.
//!
//! Run (built with `--no-run`, then the test binary directly, because
//! `cargo` is not faked):
//!   printf '+0\n' > $CLOCK
//!   REQUEST_SERVER_FIXTURE_BINARY=$PWD/target/debug/encrypted_request_server_fixture \
//!   DYLD_INSERT_LIBRARIES=/opt/homebrew/opt/libfaketime/lib/faketime/libfaketime.1.dylib \
//!   DYLD_FORCE_FLAT_NAMESPACE=1 FAKETIME_TIMESTAMP_FILE=$CLOCK FAKETIME_NO_CACHE=1 \
//!   FAKETIME_DONT_FAKE_MONOTONIC=1 <test-binary> --nocapture --test-threads=1
#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/staged_direct_request.rs"]
mod staged_direct_request;
#[path = "support/c12_c13.rs"]
mod c12_c13;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use c12_c13::*;
use encrypted_requests::{request_database_url, route_to_dedicated_database, ShippingServerFixture};
use serde_json::{json, Value};
use staged_direct_request::{stage_request, StagedRequest};
use std::{path::PathBuf, process::Command};
use uuid::Uuid;

const OK: reqwest::StatusCode = reqwest::StatusCode::OK;

/// A private faketime cluster, stopped and deleted on drop.
struct FaketimeCluster {
    dir: PathBuf,
    url: String,
}

fn launcher() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("support/faketime_postgres.py")
}

impl FaketimeCluster {
    fn start(clock_file: &str) -> anyhow::Result<Self> {
        let run = &Uuid::new_v4().simple().to_string()[..12];
        let dir = std::env::temp_dir().join(format!("c13-faketime-{run}"));
        let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let db = format!("catbird_direct_requests_faketime_c13_{run}");
        let out = Command::new("python3")
            .arg(launcher())
            .args(["start", "--dir"])
            .arg(&dir)
            .args(["--port", &port.to_string(), "--db", &db, "--clock-file", clock_file])
            .output()
            .context("launch faketime cluster")?;
        anyhow::ensure!(
            out.status.success(),
            "faketime cluster failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let started: Value = serde_json::from_slice(&out.stdout)?;
        println!("C13 faketime cluster: {started}");
        let url = started["url"].as_str().context("cluster url")?.to_owned();
        Ok(Self { dir, url })
    }

    fn advance_seconds(&self, seconds: i64) -> anyhow::Result<()> {
        let out = Command::new("python3")
            .arg(launcher())
            .args(["advance", "--dir"])
            .arg(&self.dir)
            .args(["--offset", &format!("+{seconds}")])
            .output()?;
        anyhow::ensure!(out.status.success(), "advance failed");
        Ok(())
    }
}

impl Drop for FaketimeCluster {
    fn drop(&mut self) {
        let _ = Command::new("python3")
            .arg(launcher())
            .args(["stop", "--dir"])
            .arg(&self.dir)
            .status();
    }
}

fn durable_graph(s: &StagedRequest) -> anyhow::Result<String> {
    let (r, c) = (s.request_id, s.conversation_id);
    db_query(&format!(
        r#"SELECT jsonb_build_object(
      'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{r}'),
      'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{r}'),
      'selected',(SELECT jsonb_agg(to_jsonb(s) ORDER BY owner_device_id) FROM chat.direct_request_selected_devices s WHERE request_id='{r}'),
      'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{r}'),
      'packages',(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.key_package_ref) FROM chat.key_packages k JOIN chat.direct_request_selected_devices s USING(key_package_ref) WHERE s.request_id='{r}'),
      'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{c}'),
      'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id='{c}'),
      'push',(SELECT jsonb_agg(to_jsonb(p) ORDER BY event_id) FROM chat.direct_request_push_events p WHERE request_id='{r}')
    )::text"#
    ))
}

fn assert_expired_receipt(s: &StagedRequest, response: &Value) -> anyhow::Result<()> {
    let receipt = verified_receipt(s, response)?;
    assert_eq!(receipt["$type"], "blue.catbird.chat.defs#directRequestExpiredReceipt", "{receipt}");
    assert_eq!(receipt["requestKind"], "expiry");
    assert_eq!(receipt["requestId"], s.request_id.to_string());
    assert_eq!(receipt["preparationRequestDigest"], STANDARD.encode(s.preparation_request_digest));
    assert_eq!(receipt["actorDid"], s.alice.did);
    Ok(())
}

fn set_env(key: &str, value: &str) {
    // Single-threaded test harness (--test-threads=1); read by the next fixture spawn.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(key, value)
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn c13_expiry_claims_signed_proof_under_lock_and_c12_preparation_timeout() -> anyhow::Result<()> {
    let clock_file = std::env::var("FAKETIME_TIMESTAMP_FILE")
        .context("C13 must run with the whole process under libfaketime; see the module docs")?;
    anyhow::ensure!(
        std::env::var("DYLD_INSERT_LIBRARIES").is_ok_and(|lib| lib.contains("libfaketime")),
        "C13 test process is not running under libfaketime"
    );
    let cluster = FaketimeCluster::start(&clock_file)?;
    route_to_dedicated_database(&cluster.url)?;
    assert_eq!(request_database_url(), cluster.url);

    // Four independent requests prepared at +0 through the real RPCs.
    let claimed = stage_request("c13-claim").await?;
    let replayed = stage_request("c13-replay").await?;
    let timed_out = stage_request("c12-timeout").await?;
    let swept = stage_request("c13-sweep").await?;

    // Completed request: published before its lease runs out.
    let (status, published) = post(&replayed, PUBLISH_NSID, &replayed.publication).await?;
    assert_eq!(status, OK, "{published}");
    replayed.verified_published_receipt(&published["outcome"])?;
    let graph_before = durable_graph(&replayed)?;

    // Before expiry: prepared requests report their live preparation; an
    // unknown id stays unknown and creates nothing.
    let (status, live) = outcome(&claimed, claimed.request_id).await?;
    assert_eq!(status, OK, "{live}");
    assert_eq!(live["outcome"]["$type"], "blue.catbird.chat.defs#directRequestPreparedOutcome");
    println!("C13 lease of {}: {}", claimed.request_id, live["outcome"]["preparation"]["leaseExpiresAt"]);
    let unknown = Uuid::new_v4();
    let (status, absent) = outcome(&claimed, unknown).await?;
    assert_eq!(status, OK, "{absent}");
    assert_eq!(absent["outcome"]["$type"], "blue.catbird.chat.defs#directRequestUnknownOutcome");

    // Every clock moves past the 300-second lease.
    cluster.advance_seconds(400)?;
    let ids = [claimed.request_id, timed_out.request_id, swept.request_id]
        .map(|id| format!("'{id}'"))
        .join(",");
    // Timeout alone decides nothing: all three are still unclaimed 'prepared'
    // rows, with no terminal proof, although their leases are past.
    assert_eq!(
        db_query(&format!(
            "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id IN ({ids}) \
             AND status='prepared' AND terminal_response IS NULL AND lease_expires_at <= clock_timestamp()"
        ))?,
        "3",
        "expired leases stay unclaimed until a locked claim"
    );
    let (status, still_absent) = outcome(&claimed, unknown).await?;
    assert_eq!(status, OK);
    assert_eq!(still_absent["outcome"]["$type"], "blue.catbird.chat.defs#directRequestUnknownOutcome");
    assert_eq!(
        db_query(&format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{unknown}'"))?,
        "0",
        "absence never becomes an abandonment record"
    );

    // C12 preparation timeout: a freshly signed, delayed publish after the
    // lease is refused with a signed terminal receipt; nothing is written.
    let (status, late) = post(&timed_out, PUBLISH_NSID, &fresh_publication(&timed_out)?).await?;
    assert_eq!(status, OK, "{late}");
    let refusal = verified_receipt(&timed_out, &late)?;
    assert_eq!(refusal["$type"], "blue.catbird.chat.defs#directRequestRejectedReceipt", "{refusal}");
    assert_eq!(refusal["code"], "PreparationExpired");
    assert_eq!(refusal["requestKind"], "publish");
    let (status, late_replay) = post(&timed_out, PUBLISH_NSID, &timed_out.publication).await?;
    assert_eq!(status, OK, "{late_replay}");
    assert_eq!(late_replay["outcome"], late["outcome"], "original publish bytes get the same refusal");
    let (timeout_status, timeout_body) = stored_terminal(timed_out.request_id)?;
    println!("C12 preparation timeout stored status: {timeout_status}");
    assert_eq!(timeout_body, Some(untyped_outcome(&late)?));
    assert_eq!(
        db_query(&format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r}')||'|'||\
                    (SELECT count(*) FROM chat.conversations WHERE conversation_id='{c}')",
            r = timed_out.request_id,
            c = timed_out.conversation_id
        ))?,
        "0|0"
    );

    // C13 claim under the operation lock: outcome and a late publish race for
    // the same expired request; both queue behind the held lock, nothing is
    // decided while it is held, and both return one signed expired receipt.
    let barrier = OperationBarrier::hold(claimed.request_id)?;
    let first = spawn_outcome(&claimed, claimed.request_id);
    barrier.wait_for_waiters(1).await?;
    let second = spawn_post(&claimed, PUBLISH_NSID, claimed.publication.clone());
    let queued = barrier.wait_for_waiters(2).await?;
    assert_eq!(stored_terminal(claimed.request_id)?, ("prepared".to_owned(), None), "no claim without the lock");
    println!("C13 claim: {queued} RPC sessions queued behind the operation lock");
    barrier.release()?;
    let (first_status, first_claim) = first.await??;
    let (second_status, second_claim) = second.await??;
    assert_eq!(first_status, OK, "{first_claim}");
    assert_eq!(second_status, OK, "{second_claim}");
    assert_expired_receipt(&claimed, &first_claim)?;
    assert_eq!(second_claim["outcome"], first_claim["outcome"], "concurrent claim sees the same proof");
    assert_eq!(
        stored_terminal(claimed.request_id)?,
        ("expired".to_owned(), Some(untyped_outcome(&first_claim)?))
    );
    let (_, again) = outcome(&claimed, claimed.request_id).await?;
    assert_eq!(again["outcome"], first_claim["outcome"], "the expired proof is definitive");
    assert_eq!(
        db_query(&format!(
            "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{}'",
            claimed.request_id
        ))?,
        "0"
    );

    // Completed replay after its lease expired: exact publish bytes and the
    // outcome query return the original published receipt; nothing changes.
    assert_eq!(
        db_query(&format!(
            "SELECT (lease_expires_at <= clock_timestamp())::text FROM chat.direct_request_attempts WHERE request_id='{}'",
            replayed.request_id
        ))?,
        "true",
        "published request's lease is past"
    );
    let (status, replay) = post(&replayed, PUBLISH_NSID, &replayed.publication).await?;
    assert_eq!(status, OK, "{replay}");
    assert_eq!(replay["outcome"], published["outcome"], "completed replay after lease expiry");
    let (status, replay_outcome) = outcome(&replayed, replayed.request_id).await?;
    assert_eq!(status, OK);
    assert_eq!(replay_outcome["outcome"], published["outcome"]);
    assert_eq!(durable_graph(&replayed)?, graph_before, "replay leaves the durable graph unchanged");

    // Production background expiry: the sweeper claims the last unclaimed
    // expired request without any client RPC for it.
    set_env("REQUEST_FIXTURE_EXPIRY_SWEEP", "1");
    set_env("CHAT_EXPIRY_SWEEP_INTERVAL_SECS", "1");
    set_env("REQUEST_SERVER_RUST_LOG", "warn,catbird_server::handlers::chat::expiry_worker=info");
    assert_eq!(stored_terminal(swept.request_id)?, ("prepared".to_owned(), None));
    let sweeper = ShippingServerFixture::start(&swept._https)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let stored = loop {
        let (status, body) = stored_terminal(swept.request_id)?;
        if status != "prepared" {
            assert_eq!(status, "expired");
            break body.context("expired row carries its proof")?;
        }
        anyhow::ensure!(std::time::Instant::now() < deadline, "sweeper never expired {}", swept.request_id);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    println!("C13 sweeper expired {} without a client claim", swept.request_id);
    let (status, swept_outcome) = outcome(&swept, swept.request_id).await?;
    assert_eq!(status, OK, "{swept_outcome}");
    assert_expired_receipt(&swept, &swept_outcome)?;
    assert_eq!(untyped_outcome(&swept_outcome)?, stored);
    let (status, swept_publish) = post(&swept, PUBLISH_NSID, &swept.publication).await?;
    assert_eq!(status, OK, "{swept_publish}");
    assert_eq!(swept_publish["outcome"], swept_outcome["outcome"]);
    drop(sweeper);
    drop((claimed, replayed, timed_out, swept));
    drop(cluster);
    Ok(())
}

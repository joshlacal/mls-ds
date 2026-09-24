//! F1 capacity-abuse fix, live router: published requests hold no pending
//! bytes, an unanswered published request expires after 30 days with a signed
//! expiry receipt, and closed/expired requests are pruned after 14 more days,
//! releasing retained capacity while identity rows and history remain.
//!
//! Every clock runs under one libfaketime control file: the test process, every
//! server fixture it spawns, and a dedicated loopback PostgreSQL cluster
//! (`support/faketime_postgres.py --clock-file`) to which the harness is routed.
//! Requests are prepared, published and closed through the real RPCs; expiry
//! and pruning are performed only by the production expiry sweeper running in
//! a fixture started with `REQUEST_FIXTURE_EXPIRY_SWEEP=1`. No protocol row is
//! written by the test.
//!
//! Run (built with `--no-run`, then the test binary directly):
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
use catbird_mls::chat_v2::transcript::direct_request::DirectRequestKind;
use encrypted_requests::{request_database_url, route_to_dedicated_database, ShippingServerFixture};
use serde_json::Value;
use staged_direct_request::{stage_request, StagedRequest};
use std::{path::PathBuf, process::Command, time::Duration};
use uuid::Uuid;

const OK: reqwest::StatusCode = reqwest::StatusCode::OK;
const DAY: i64 = 86_400;

struct FaketimeCluster {
    dir: PathBuf,
    url: String,
    offset: std::cell::Cell<i64>,
}

fn launcher() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("support/faketime_postgres.py")
}

impl FaketimeCluster {
    fn start(clock_file: &str) -> anyhow::Result<Self> {
        let run = &Uuid::new_v4().simple().to_string()[..12];
        let dir = std::env::temp_dir().join(format!("qf-faketime-{run}"));
        let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let db = format!("catbird_direct_requests_faketime_qf_{run}");
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
        println!("QuotaFix faketime cluster: {started}");
        let url = started["url"].as_str().context("cluster url")?.to_owned();
        Ok(Self { dir, url, offset: 0.into() })
    }

    /// Advance every faked clock to `+total` seconds past the start.
    fn advance_by(&self, seconds: i64) -> anyhow::Result<()> {
        let total = self.offset.get() + seconds;
        let out = Command::new("python3")
            .arg(launcher())
            .args(["advance", "--dir"])
            .arg(&self.dir)
            .args(["--offset", &format!("+{total}")])
            .output()?;
        anyhow::ensure!(out.status.success(), "advance failed");
        self.offset.set(total);
        Ok(())
    }
}

impl Drop for FaketimeCluster {
    fn drop(&mut self) {
        let log = std::fs::read_to_string(self.dir.join("postgres.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().filter(|l| !l.contains("LOG:  checkpoint")).collect();
        println!("faketime postgres log tail:");
        for line in lines.iter().rev().take(25).rev() {
            println!("  {line}");
        }
        let _ = Command::new("python3")
            .arg(launcher())
            .args(["stop", "--dir"])
            .arg(&self.dir)
            .status();
    }
}

fn set_env(key: &str, value: &str) {
    // Single-threaded harness (--test-threads=1); read by the next fixture spawn.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(key, value)
    };
}

fn budget() -> anyhow::Result<(i64, i64)> {
    let row = db_query(
        "SELECT pending_bytes||'|'||retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
    )?;
    let (p, r) = row.split_once('|').context("budget row")?;
    Ok((p.parse()?, r.parse()?))
}

fn scalar(sql: &str) -> anyhow::Result<String> {
    db_query(sql)
}

async fn wait_for(what: &str, sql: &str, expected: &str) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if scalar(sql)? == expected {
            return Ok(());
        }
        anyhow::ensure!(std::time::Instant::now() < deadline, "sweeper never reached: {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn publish(s: &StagedRequest) -> anyhow::Result<Value> {
    let (status, published) = post(s, PUBLISH_NSID, &s.publication).await?;
    anyhow::ensure!(status == OK, "publish {status}: {published}");
    s.verified_published_receipt(&published["outcome"])?;
    Ok(published)
}

#[tokio::test(flavor = "multi_thread")]
async fn published_request_expires_after_30_days_and_terminal_artifacts_prune_after_14(
) -> anyhow::Result<()> {
    let clock_file = std::env::var("FAKETIME_TIMESTAMP_FILE")
        .context("must run with the whole process under libfaketime; see the module docs")?;
    anyhow::ensure!(
        std::env::var("DYLD_INSERT_LIBRARIES").is_ok_and(|lib| lib.contains("libfaketime")),
        "test process is not running under libfaketime"
    );
    let cluster = FaketimeCluster::start(&clock_file)?;
    route_to_dedicated_database(&cluster.url)?;
    assert_eq!(request_database_url(), cluster.url);

    // A: published and left unanswered. B: published then closed by sender.
    let a = stage_request("qf-expire").await?;
    let installed = scalar("SELECT count(*) FROM public._sqlx_migrations WHERE version=20260919000021")?;
    assert_eq!(installed, "1", "harness installed the capacity-abuse migration");
    let (pending0, retained0) = budget()?;
    println!("budget before publication: pending={pending0} retained={retained0}");
    assert!(pending0 > 0, "a live preparation reserves pending capacity");
    publish(&a).await?;
    let (pending_a, retained_a) = budget()?;
    println!("budget after publishing A: pending={pending_a} retained={retained_a}");
    assert_eq!(pending_a, 0, "a published request holds no pending capacity");
    let charge_a: i64 = scalar(&format!(
        "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id='{}'",
        a.request_id
    ))?
    .parse()?;
    assert_eq!(retained_a, charge_a, "retained equals A's exact publication charge");

    let b = stage_request("qf-close").await?;
    publish(&b).await?;
    let (status, closed, _) = close_published(&b).await?;
    assert_eq!(status, OK, "real closeConversation of published B: {closed}");
    assert_eq!(
        scalar(&format!("SELECT consent FROM chat.direct_request_lifecycle WHERE request_id='{}'", b.request_id))?,
        "closed"
    );
    assert_eq!(budget()?.0, 0, "closed request holds no pending capacity");
    let b_entries = scalar(&format!(
        "SELECT count(*) FROM chat.entries WHERE conversation_id='{}'",
        b.conversation_id
    ))?;
    let (_, retained_before_prune) = budget()?;

    // Production sweeper fixtures. Each is started after its clock jump and
    // dropped before the next: a live fixture across a multi-day jump bursts
    // its interval timer and starves its small pool. Under libfaketime an
    // occasional clock read in the fixture falls back to real time, which makes
    // a sqlx acquire report PoolTimedOut; a short interval lets the production
    // sweeper simply run its next cycle.
    set_env("REQUEST_FIXTURE_EXPIRY_SWEEP", "1");
    set_env("CHAT_EXPIRY_SWEEP_INTERVAL_SECS", "2");
    set_env("REQUEST_SERVER_RUST_LOG", "error,catbird_server::handlers::chat::expiry_worker=info");

    // Day 29: a real sweep cycle runs; A (published day 0) must not expire.
    // B (closed day 0) is already past 14 days and may prune here.
    cluster.advance_by(29 * DAY)?;
    let sweeper = start_sweeper(&a)?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        scalar(&format!("SELECT count(*) FROM chat.direct_request_lifecycle WHERE request_id='{}'", a.request_id))?,
        "0",
        "request is still unanswered before 30 days"
    );
    drop(sweeper);

    // Day 31: A expires (signed receipt); B (closed day 0) prunes.
    cluster.advance_by(2 * DAY)?;
    let sweeper = start_sweeper(&a)?;
    wait_for(
        "A expired",
        &format!("SELECT coalesce((SELECT consent FROM chat.direct_request_lifecycle WHERE request_id='{}'),'none')", a.request_id),
        "expired",
    )
    .await?;
    let (status, expired) = outcome(&a, a.request_id).await?;
    assert_eq!(status, OK, "{expired}");
    let receipt = verified_receipt(&a, &expired)?;
    println!("A expiry receipt: {receipt}");
    assert_eq!(receipt["$type"], "blue.catbird.chat.defs#directRequestExpiredReceipt");
    assert_eq!(receipt["requestKind"], "expiry");
    assert_eq!(receipt["requestId"], a.request_id.to_string());
    assert_eq!(receipt["preparationRequestDigest"], STANDARD.encode(a.preparation_request_digest));
    let publish_digest = request_digest(DirectRequestKind::Publish, &a.publication, &a.alice_public)?;
    assert_eq!(
        receipt["requestDigest"],
        STANDARD.encode(publish_digest),
        "published expiry binds the publication digest, distinct from a lease expiry"
    );
    assert_eq!(
        untyped_outcome(&expired)?,
        serde_json::from_str::<Value>(&scalar(&format!(
            "SELECT convert_from(signed_receipt,'UTF8') FROM chat.direct_request_expiry_receipts WHERE request_id='{}'",
            a.request_id
        ))?)?,
        "outcome serves the stored signed expiry receipt"
    );
    assert_eq!(
        scalar(&format!("SELECT decision_kind FROM chat.direct_request_decision_slots WHERE request_id='{}'", a.request_id))?,
        "expire"
    );
    // Expiry is terminal (C20): the sender can no longer close it, and the
    // lifecycle row is unchanged.
    let (status, late_close, _) = close_published(&a).await?;
    assert!(status.is_client_error(), "close after expiry must be refused: {status} {late_close}");
    assert_eq!(
        scalar(&format!("SELECT consent FROM chat.direct_request_lifecycle WHERE request_id='{}'", a.request_id))?,
        "expired"
    );

    wait_for(
        "B pruned",
        &format!("SELECT count(*) FROM chat.direct_request_retained_releases WHERE request_id='{}' AND reason='closed_pruned'", b.request_id),
        "1",
    )
    .await?;
    let released_b: i64 = scalar(&format!(
        "SELECT released_bytes FROM chat.direct_request_retained_releases WHERE request_id='{}'",
        b.request_id
    ))?
    .parse()?;
    let charge_b: i64 = scalar(&format!(
        "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id='{}'",
        b.request_id
    ))?
    .parse()?;
    println!("B charge={charge_b} released={released_b}");
    // The 4 MiB decision reserve floor plus one 512 KiB Welcome slot are
    // precharged; after close+14d the unused reserve and pruned blobs return.
    assert!(
        released_b >= 4 * 1_048_576 && released_b < charge_b,
        "pruning must reclaim the bulk of B's charge ({released_b} of {charge_b})"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT (signed_publication IS NULL AND full_welcome IS NULL AND initial_ciphertext IS NULL AND pruned_at IS NOT NULL)::text FROM chat.direct_request_publications WHERE request_id='{}'",
            b.request_id
        ))?,
        "true",
        "B heavy artifacts pruned"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT (terminal_response_sha256 IS NOT NULL AND status='published')::text FROM chat.direct_request_attempts WHERE request_id='{}'",
            b.request_id
        ))?,
        "true",
        "B tombstone identity row retained"
    );
    assert_eq!(
        scalar(&format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{}'", b.conversation_id))?,
        b_entries,
        "pruning never deletes conversation history"
    );
    assert_eq!(budget()?.1, retained_before_prune - released_b, "retained drops by B's release");

    // Day 46: A (expired day 31) prunes too.
    drop(sweeper);
    cluster.advance_by(15 * DAY)?;
    println!(
        "day 46 cluster: now={} backends={} max={}",
        scalar("SELECT clock_timestamp()")?,
        scalar("SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'")?,
        scalar("SHOW max_connections")?
    );
    let sweeper = start_sweeper(&a)?;
    wait_for(
        "A pruned",
        &format!("SELECT count(*) FROM chat.direct_request_retained_releases WHERE request_id='{}' AND reason='expired_pruned'", a.request_id),
        "1",
    )
    .await?;
    let released_a: i64 = scalar(&format!(
        "SELECT released_bytes FROM chat.direct_request_retained_releases WHERE request_id='{}'",
        a.request_id
    ))?
    .parse()?;
    let (pending_end, retained_end) = budget()?;
    println!("budget after pruning: pending={pending_end} retained={retained_end} released A={released_a} B={released_b}");
    assert_eq!(pending_end, 0);
    assert!(released_a >= 4 * 1_048_576 && released_a < charge_a, "A reclaim {released_a} of {charge_a}");
    assert_eq!(retained_end, retained_before_prune - released_b - released_a);

    // Post-prune replay is fenced: the outcome is still the retained signed
    // expiry receipt, and replaying the original publish mints nothing.
    let (status, late) = outcome(&a, a.request_id).await?;
    assert_eq!(status, OK, "{late}");
    assert_eq!(late["outcome"], expired["outcome"]);
    let pubs_before = scalar(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE actor_did='{}'", a.alice.did))?;
    let (status, replay) = post(&a, PUBLISH_NSID, &a.publication).await?;
    println!("post-prune publish replay: {status} {replay}");
    assert_eq!(
        scalar(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE actor_did='{}'", a.alice.did))?,
        pubs_before,
        "post-prune replay creates no publication"
    );
    assert_eq!(
        scalar(&format!("SELECT status FROM chat.direct_request_attempts WHERE request_id='{}'", a.request_id))?,
        "published"
    );

    drop(sweeper);
    drop((a, b));
    drop(cluster);
    Ok(())
}

/// Start a sweeper fixture; a startup `connect` can hit the same libfaketime
/// real-time fallback as a sweep cycle, so retry a bounded number of times.
fn start_sweeper(s: &StagedRequest) -> anyhow::Result<ShippingServerFixture> {
    let mut last = None;
    for attempt in 1..=3 {
        match ShippingServerFixture::start(&s._https) {
            Ok(fixture) => return Ok(fixture),
            Err(error) => {
                println!("sweeper fixture start attempt {attempt} failed: {error:#}");
                last = Some(error);
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

//! C10: atomic publication failures at every write boundary.
//!
//! Runs the shipping router (real `publishDirectRequest` handler, real
//! `prepare_publication`/`execute_publication`/`complete_published_publication`)
//! against a dedicated loopback database `catbird_direct_requests_fault_<hex>`
//! migrated by the reviewed installer. Only that database gets a fault
//! trigger on every `chat.*` table (the separate service-auth admission table
//! excluded): it counts row writes per transaction and, at write N, sleeps then
//! raises. N = 1, 2, ... is tried with the SAME durable journal bytes until the
//! publish succeeds, so every write of the publication transaction is failed
//! once. During each sleep a second connection observes the in-flight
//! transaction's statement (pg_stat_activity) and asserts no committed partial
//! state; after each failure the same is asserted again. The first N beyond the
//! last write is the client retry after the fault clears, and it must commit
//! the complete publication exactly once.
#![allow(dead_code)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/staged_direct_request.rs"]
mod staged;

use anyhow::Context as _;
use catbird_mls::{
    chat_v2::transcript::direct_request as protocol,
    orchestrator::{
        direct_request_bootstrap::DirectRequestIntroductionResult,
        direct_request_journal::DirectRequestJournalPhase, MlsCryptoContext,
    },
};
use encrypted_requests::{
    request_database_url, route_to_dedicated_database, DeterministicFaultTransport,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";
const PAUSE_MS: u64 = 700;
const MAX_WRITES: usize = 400;

async fn psql_on(url: &str, sql: &str) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("psql")
        .args([url, "-X", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

async fn psql(sql: &str) -> anyhow::Result<String> {
    psql_on(request_database_url(), sql).await
}

/// Drops the dedicated database; only backends connected to this uniquely
/// named database (ours) are terminated.
struct DedicatedDatabase(String);
impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = std::process::Command::new("psql")
            .args([
                MAINTENANCE_URL,
                "-X",
                "-q",
                "-c",
                &format!("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"),
                "-c",
                &format!("DROP DATABASE IF EXISTS {name}"),
            ])
            .status();
    }
}

const FAULT_SQL: &str = r#"
CREATE SCHEMA c10_fault;
CREATE TABLE c10_fault.control(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  target integer NOT NULL DEFAULT 0, pause_ms integer NOT NULL DEFAULT 0);
INSERT INTO c10_fault.control DEFAULT VALUES;
CREATE FUNCTION c10_fault.count_write() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE armed integer; pause integer; seen integer;
BEGIN
  SELECT c.target, c.pause_ms INTO armed, pause FROM c10_fault.control c;
  IF armed > 0 THEN
    seen := coalesce(nullif(current_setting('c10_fault.seen', true), ''), '0')::integer + 1;
    PERFORM set_config('c10_fault.seen', seen::text, true);
    IF seen = armed THEN
      PERFORM pg_sleep(pause / 1000.0);
      RAISE EXCEPTION 'c10 injected fault at write % (% %.%)', seen, TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='chat' AND c.relkind IN ('r','p') AND NOT c.relispartition
             AND c.relname <> 'service_auth_admissions' LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON chat.%I FOR EACH ROW EXECUTE FUNCTION c10_fault.count_write()', 'c10_fault_' || md5(r.relname), r.relname);
  END LOOP;
END $$;
SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'c10_fault_%';
"#;

/// Committed state visible to an independent connection. Every component must
/// stay zero (and the package reserved, the attempt prepared) until commit.
async fn observed_partial_state(request: Uuid, conversation: Uuid, package_hex: &str) -> anyhow::Result<Value> {
    let row = psql(&format!(
        "SELECT jsonb_build_object(\
          'conversation',(SELECT count(*) FROM chat.conversations WHERE conversation_id='{conversation}'),\
          'invitation',(SELECT count(*) FROM chat.participants WHERE conversation_id='{conversation}'),\
          'publication',(SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request}'),\
          'welcomeDeliveries',(SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{request}'),\
          'intervals',(SELECT count(*) FROM chat.application_intervals WHERE conversation_id='{conversation}'),\
          'leaves',(SELECT count(*) FROM chat.member_devices WHERE conversation_id='{conversation}'),\
          'ciphertextEntries',(SELECT count(*) FROM chat.entries WHERE conversation_id='{conversation}'),\
          'transitions',(SELECT count(*) FROM chat.transitions WHERE conversation_id='{conversation}'),\
          'pushEvents',(SELECT count(*) FROM chat.direct_request_push_events WHERE request_id='{request}'),\
          'pushRecipients',(SELECT count(*) FROM chat.direct_request_push_event_recipients WHERE request_id='{request}'),\
          'events',(SELECT count(*) FROM chat.events WHERE position(convert_to('{conversation}','UTF8') in payload_bytes)>0),\
          'lifecycleReserve',(SELECT count(*) FROM chat.direct_request_lifecycle_reserves WHERE request_id='{request}'),\
          'packageStatus',(SELECT status FROM chat.key_packages WHERE key_package_ref=decode('{package_hex}','hex')),\
          'attemptStatus',(SELECT status FROM chat.direct_request_attempts WHERE request_id='{request}')\
        )::text"
    ))
    .await?;
    Ok(serde_json::from_str(&row)?)
}

fn assert_no_partial_state(state: &Value, when: &str) {
    for key in [
        "conversation",
        "invitation",
        "publication",
        "welcomeDeliveries",
        "intervals",
        "leaves",
        "ciphertextEntries",
        "transitions",
        "pushEvents",
        "pushRecipients",
        "events",
        "lifecycleReserve",
    ] {
        assert_eq!(state[key], 0, "{when}: observer saw {key} before commit: {state}");
    }
    assert_eq!(state["packageStatus"], "reserved", "{when}: {state}");
    assert_eq!(state["attemptStatus"], "prepared", "{when}: {state}");
}

#[tokio::test(flavor = "multi_thread")]
async fn c10_every_publication_write_fault_leaves_no_partial_state_and_retry_commits(
) -> anyhow::Result<()> {
    let name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    psql_on(MAINTENANCE_URL, &format!("CREATE DATABASE {name}")).await?;
    let _dedicated = DedicatedDatabase(name.clone());
    route_to_dedicated_database(&format!("postgresql://127.0.0.1:5432/{name}"))?;
    assert!(request_database_url().ends_with(&name));

    let f = staged::stage_request("c10").await?;
    let triggers: i64 = psql(FAULT_SQL).await?.lines().last().context("trigger count")?.parse()?;
    assert!(triggers > 40, "fault trigger must cover every chat table, got {triggers}");
    let request = f.request_id;
    let conversation = f.conversation_id;
    let package_hex = hex::encode(&f.bob_package_ref);
    assert_no_partial_state(
        &observed_partial_state(request, conversation, &package_hex).await?,
        "staged",
    );

    let mut boundaries = Vec::new();
    let mut committed = None;
    let started = Instant::now();
    for target in 1..=MAX_WRITES {
        psql(&format!(
            "UPDATE c10_fault.control SET target={target}, pause_ms={PAUSE_MS}"
        ))
        .await?;
        let mut transport = DeterministicFaultTransport::default();
        let publish = f.post_publication(&mut transport);
        let observe = async {
            // Wait for the router's transaction to reach the fault (sleeping
            // inside write N) or for the publication to finish without one.
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                let sleeping = psql(
                    "SELECT pid||E'\\t'||coalesce(backend_xid::text,'')||E'\\t'||replace(query,E'\\n',' ') FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep' AND pid<>pg_backend_pid()",
                )
                .await?;
                if !sleeping.is_empty() {
                    let during = observed_partial_state(request, conversation, &package_hex).await?;
                    let still = psql(&format!(
                        "SELECT count(*) FROM pg_stat_activity WHERE pid={} AND wait_event='PgSleep'",
                        sleeping.split('\t').next().unwrap_or("0")
                    ))
                    .await?;
                    return anyhow::Ok(Some((sleeping, during, still == "1")));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                if psql(&format!("SELECT status FROM chat.direct_request_attempts WHERE request_id='{request}'")).await? == "published" {
                    return Ok(None);
                }
            }
            anyhow::bail!("write {target}: neither a fault nor a commit was observed")
        };
        let (published, observed) = tokio::join!(publish, observe);
        let (status, body) = published?;
        match observed? {
            Some((statement, during, concurrent)) => {
                assert!(
                    concurrent,
                    "write {target}: observation must happen while the transaction is open"
                );
                assert_no_partial_state(&during, &format!("during write {target}"));
                assert!(
                    status.is_server_error(),
                    "write {target}: injected fault must fail the publish, got {status}: {}",
                    String::from_utf8_lossy(&body)
                );
                let after = observed_partial_state(request, conversation, &package_hex).await?;
                assert_no_partial_state(&after, &format!("after rollback of write {target}"));
                let mut fields = statement.splitn(3, '\t');
                let pid = fields.next().unwrap_or_default().to_owned();
                let xid = fields.next().unwrap_or_default().to_owned();
                let query = fields.next().unwrap_or_default().to_owned();
                assert!(!xid.is_empty(), "write {target}: faulted backend holds a transaction id");
                println!("C10 boundary write={target} status={status} pid={pid} xid={xid} statement={query}");
                boundaries.push(json!({"write":target,"status":status.as_u16(),"statement":query}));
            }
            None => {
                assert_eq!(
                    status,
                    reqwest::StatusCode::OK,
                    "retry after fault clears must publish: {}",
                    String::from_utf8_lossy(&body)
                );
                committed = Some(serde_json::from_slice::<Value>(&body)?);
                break;
            }
        }
    }
    psql("UPDATE c10_fault.control SET target=0").await?;
    let published = committed.context("publication never committed")?;
    println!(
        "C10 faulted {} writes then committed on write budget {}; elapsed {:?}",
        boundaries.len(),
        boundaries.len() + 1,
        started.elapsed()
    );
    // Every write of the transaction was a boundary: the statements must cover
    // the reviewed publication effects, including those added late in the path.
    let all = boundaries
        .iter()
        .map(|b| b["statement"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    for table in [
        "chat.direct_request_attempts",
        "chat.conversations",
        "chat.generations",
        "chat.generation_states",
        "chat.transitions",
        "chat.entries",
        "chat.entry_recipients",
        "chat.metadata_snapshots",
        "chat.participants",
        "chat.direct_request_publications",
        "chat.direct_request_lifecycle_reserves",
        "chat.member_devices",
        "chat.application_intervals",
        "chat.direct_request_device_deliveries",
        "chat.key_packages",
        "chat.events",
        "chat.event_recipients",
        "chat.outbox",
        "chat.direct_request_push_events",
        "chat.direct_request_push_event_recipients",
    ] {
        assert!(all.contains(table), "no injected boundary wrote {table}");
    }
    let ordered: Vec<usize> = boundaries.iter().map(|b| b["write"].as_u64().unwrap() as usize).collect();
    assert_eq!(ordered, (1..=boundaries.len()).collect::<Vec<_>>());

    // Committed exactly once, complete.
    let receipt = f.verified_published_receipt(&published["outcome"])?;
    let state = observed_partial_state(request, conversation, &package_hex).await?;
    assert_eq!(state["conversation"], 1);
    assert_eq!(state["invitation"], 2);
    assert_eq!(state["publication"], 1);
    assert_eq!(state["welcomeDeliveries"], 1);
    assert_eq!(state["intervals"], 2);
    assert_eq!(state["leaves"], 2);
    assert_eq!(state["ciphertextEntries"], 1);
    assert_eq!(state["pushEvents"], 1);
    assert_eq!(state["pushRecipients"], 1);
    assert_eq!(state["lifecycleReserve"], 1);
    assert_eq!(state["packageStatus"], "consumed");
    assert_eq!(state["attemptStatus"], "published");
    let ciphertext = psql(&format!(
        "SELECT encode(initial_ciphertext,'hex') FROM chat.direct_request_publications WHERE request_id='{request}'"
    ))
    .await?;

    // The client retried the same durable bytes; its journal resolves once.
    let sender = f.sender.as_ref().context("sender")?;
    let journal = staged::journal(sender, request)?;
    assert_eq!(journal.phase, DirectRequestJournalPhase::OutcomeUnknown);
    assert_eq!(journal.publish_request.as_deref(), Some(f.exact_publication.as_slice()));
    assert_eq!(ciphertext, hex::encode(&journal.bootstrap.initial_ciphertext));
    let resolved = sender
        .confirm_published_bootstrap(
            &request.to_string(),
            &serde_json::to_vec(&receipt)?,
            &f.server.receipt_public_key,
        )
        .map_err(|error| anyhow::anyhow!("confirm: {error}"))?;
    assert_eq!(resolved.phase, DirectRequestJournalPhase::PublishedAwaitingProjection);

    let welcome = f.welcome_input(journal.bootstrap.clone(), &receipt)?;
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
    drop(f);
    Ok(())
}

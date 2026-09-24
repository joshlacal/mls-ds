//! Shared live helpers for C12/C13: signing with the staged sender's real
//! SQLCipher identity, receipt verification against the fixture's receipt
//! authority, and a barrier that holds the production per-request operation
//! lock (`chat-operation-id:<uuid>`, see `direct_request_lock.rs`) in a
//! separate PostgreSQL session so racing RPCs queue behind it in a known order.
use super::encrypted_requests::{canonical_now, request_database_url};
use super::staged_direct_request::StagedRequest;
use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json,
    direct_request::{self as protocol, DirectRequestKind},
    project_signed_body, SignedMutationKind, SigningTranscript,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, ChildStdin, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const PREPARE_NSID: &str = "blue.catbird.chat.prepareDirectRequest";
pub const PUBLISH_NSID: &str = "blue.catbird.chat.publishDirectRequest";
pub const CANCEL_NSID: &str = "blue.catbird.chat.cancelDirectRequestPreparation";
pub const OUTCOME_NSID: &str = "blue.catbird.chat.getDirectRequestOutcome";
pub const CLOSE_NSID: &str = "blue.catbird.chat.closeConversation";

pub fn db_query(sql: &str) -> anyhow::Result<String> {
    let out = Command::new("psql")
        .args(["-X", "-v", "ON_ERROR_STOP=1", "-At", "-d", request_database_url(), "-c", sql])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

pub fn alice_identity(s: &StagedRequest) -> String {
    format!("{}#{}", s.alice.did, s.alice.device_id)
}

pub fn alice_key_id(s: &StagedRequest) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(&s.alice_public))
}

fn sign_bytes(s: &StagedRequest, transcript: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    s.sender
        .as_ref()
        .context("staged sender store")?
        .sign_with_identity_key(alice_identity(s), transcript)
        .map_err(|error| anyhow::anyhow!("sender sign: {error}"))
}

/// Direct-request signed wrapper, verified against the sender's public key.
pub fn sign_direct(s: &StagedRequest, kind: DirectRequestKind, body: Value) -> anyhow::Result<Value> {
    let transcript = protocol::direct_request_signing_bytes(kind, &serde_json::to_vec(&body)?)?;
    let wrapper = json!({"body":body,"signature":STANDARD.encode(sign_bytes(s, transcript)?)});
    protocol::verify_signed_request(kind, &serde_json::to_vec(&wrapper)?, &s.alice_public)?;
    Ok(wrapper)
}

/// Request digest of a signed direct-request wrapper (as the server derives it).
pub fn request_digest(kind: DirectRequestKind, signed: &Value, public: &[u8]) -> anyhow::Result<[u8; 32]> {
    Ok(*protocol::verify_signed_request(kind, &serde_json::to_vec(signed)?, public)?.request_digest())
}

/// Fresh signed cancellation of `request_id` bound to `prepare_digest`.
pub fn signed_cancel(s: &StagedRequest, request_id: Uuid, prepare_digest: &[u8]) -> anyhow::Result<Value> {
    sign_direct(
        s,
        DirectRequestKind::Cancel,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestCancellationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-CANCEL\0","protocolVersion":"2",
            "actorDid":s.alice.did,"actorDeviceId":s.alice.device_id.to_string(),
            "keyId":alice_key_id(s),"authGeneration":1,"requestId":request_id.to_string(),
            "recipientDid":s.bob.did,"preparationRequestDigest":STANDARD.encode(prepare_digest),
            "idempotencyKey":request_id.to_string(),"signedAt":canonical_now()
        }),
    )
}

/// The staged publication re-signed with a fresh `signedAt` (same request).
pub fn fresh_publication(s: &StagedRequest) -> anyhow::Result<Value> {
    let mut body = s.publication["body"].clone();
    body["signedAt"] = json!(canonical_now());
    sign_direct(s, DirectRequestKind::Publish, body)
}

pub async fn post(s: &StagedRequest, nsid: &str, signed: &Value) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let (status, bytes) = s
        .alice
        .post(&s.client, &s.server.base_url, nsid, &json!({"signedRequest":signed}), true)
        .await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{nsid} body: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, value))
}

/// `getDirectRequestOutcome` presents lexicon `{"$bytes":…}`; normalize it the
/// way a client does so it compares with mutation responses and retained rows.
pub fn normalized_outcome(value: Value) -> anyhow::Result<Value> {
    // Under F27, both outcome reads and mutation responses present lexicon bytes
    // uniformly at response time, so no client-side de-normalization is needed.
    Ok(value)
}

pub async fn outcome(s: &StagedRequest, request_id: Uuid) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let (status, bytes) = s
        .alice
        .get(&s.client, &s.server.base_url, OUTCOME_NSID, &[("requestId".into(), request_id.to_string())])
        .await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("outcome body: {}", String::from_utf8_lossy(&bytes)))?;
    Ok((status, normalized_outcome(value)?))
}

type Pending = tokio::task::JoinHandle<anyhow::Result<(reqwest::StatusCode, Value)>>;

/// POST in a background task (used to queue racing RPCs behind a barrier).
pub fn spawn_post(s: &StagedRequest, nsid: &'static str, signed: Value) -> Pending {
    let (alice, client, base) = (s.alice.clone(), s.client.clone(), s.server.base_url.clone());
    tokio::spawn(async move {
        let (status, bytes) = alice
            .post(&client, &base, nsid, &json!({"signedRequest":signed}), true)
            .await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    })
}

pub fn spawn_outcome(s: &StagedRequest, request_id: Uuid) -> Pending {
    let (alice, client, base) = (s.alice.clone(), s.client.clone(), s.server.base_url.clone());
    tokio::spawn(async move {
        let (status, bytes) = alice
            .get(&client, &base, OUTCOME_NSID, &[("requestId".into(), request_id.to_string())])
            .await?;
        Ok((status, normalized_outcome(serde_json::from_slice(&bytes)?)?))
    })
}

/// Verify `response.outcome` as a receipt signed by the fixture's receipt
/// authority; returns the inner `receipt` object.
pub fn verified_receipt(s: &StagedRequest, response: &Value) -> anyhow::Result<Value> {
    anyhow::ensure!(
        response["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "expected a signed receipt, got {response}"
    );
    let mut signed = response["outcome"].clone();
    signed.as_object_mut().context("receipt object")?.remove("$type");
    let verified = protocol::verify_received_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&signed)?,
        &s.server.receipt_public_key,
    )?;
    Ok(verified.body()["receipt"].clone())
}

/// Stored terminal proof of one attempt: `status|terminal_response`.
pub fn stored_terminal(request_id: Uuid) -> anyhow::Result<(String, Option<Value>)> {
    let row = db_query(&format!(
        "SELECT status||'|'||coalesce(convert_from(terminal_response,'UTF8'),'') \
         FROM chat.direct_request_attempts WHERE request_id='{request_id}'"
    ))?;
    let (status, body) = row.split_once('|').with_context(|| format!("no attempt row for {request_id}"))?;
    let body = (!body.is_empty()).then(|| serde_json::from_str(body)).transpose()?;
    Ok((status.to_owned(), body))
}

/// The response outcome without its `$type` (= the stored signed receipt).
pub fn untyped_outcome(response: &Value) -> anyhow::Result<Value> {
    let mut value = response["outcome"].clone();
    value.as_object_mut().context("outcome object")?.remove("$type");
    let raw = serde_json::to_vec(&value)?;
    let normalized = protocol::normalize_read_presentation(
        &raw,
        "signedDirectRequestReceipt",
        false,
    )?;
    Ok(normalized)
}

/// Real signed `closeConversation` by the staged sender, retiring the
/// published request's `next` coordinates. Returns (status, body, transitionId).
pub async fn close_published(s: &StagedRequest) -> anyhow::Result<(reqwest::StatusCode, Value, Uuid)> {
    let prior = s.publication["body"]["next"].clone();
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(prior["stateVersion"].as_u64().context("stateVersion")? + 1);
    retired["lifecycle"] = json!("superseded");
    let transition_id = Uuid::new_v4();
    let body = json!({
        "$type":"blue.catbird.chat.defs#conversationCloseBody",
        "signatureDomain":"CATBIRD-CHAT-CLOSE\0","transitionId":transition_id.to_string(),
        "conversationKind":"direct","actorDid":s.alice.did,
        "actorDeviceId":s.alice.device_id.to_string(),"keyId":alice_key_id(s),"authGeneration":1,
        "prior":prior,"retired":retired,"idempotencyKey":transition_id.to_string(),
        "signedAt":canonical_now()
    });
    let kind = SignedMutationKind::ConversationClose;
    let strict = decode_strict_json(&serde_json::to_vec(&body)?)?;
    let transcript = SigningTranscript::build_for(kind, &project_signed_body(kind, &strict)?)?;
    let signed = json!({"body":body,"signature":STANDARD.encode(sign_bytes(s, transcript.bytes().to_vec())?)});
    let (status, value) = post(s, CLOSE_NSID, &signed).await?;
    Ok((status, value, transition_id))
}

/// Holds the production operation lock of one request id in its own session.
pub struct OperationBarrier {
    child: Child,
    stdin: ChildStdin,
    pid: i64,
}

impl OperationBarrier {
    pub fn hold(request_id: Uuid) -> anyhow::Result<Self> {
        let mut child = Command::new("psql")
            .args(["-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-d", request_database_url()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().context("barrier stdin")?;
        writeln!(
            stdin,
            "BEGIN;\nSELECT pg_backend_pid();\n\
             SELECT pg_advisory_xact_lock(hashtextextended('chat-operation-id:{request_id}',0));\n\
             \\echo BARRIER-HELD"
        )?;
        stdin.flush()?;
        let mut lines = BufReader::new(child.stdout.take().context("barrier stdout")?).lines();
        let pid: i64 = lines.next().context("barrier pid")??.trim().parse()?;
        for line in lines.by_ref() {
            if line?.trim() == "BARRIER-HELD" {
                return Ok(Self { child, stdin, pid });
            }
        }
        anyhow::bail!("barrier session exited before holding the operation lock")
    }

    /// Server sessions currently blocked (directly or transitively) behind the barrier.
    pub fn waiters(&self) -> anyhow::Result<i64> {
        Ok(db_query(&format!(
            "WITH RECURSIVE w(pid) AS (SELECT pid FROM pg_stat_activity WHERE {b}=ANY(pg_blocking_pids(pid)) \
             UNION SELECT a.pid FROM pg_stat_activity a JOIN w ON w.pid=ANY(pg_blocking_pids(a.pid))) \
             SELECT count(*) FROM w",
            b = self.pid
        ))?
        .parse()?)
    }

    pub async fn wait_for_waiters(&self, at_least: i64) -> anyhow::Result<i64> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let n = self.waiters()?;
            if n >= at_least {
                return Ok(n);
            }
            anyhow::ensure!(Instant::now() < deadline, "only {n} waiters behind barrier");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub fn release(mut self) -> anyhow::Result<()> {
        writeln!(self.stdin, "COMMIT;\n\\q")?;
        self.stdin.flush()?;
        anyhow::ensure!(self.child.wait()?.success(), "barrier session failed");
        Ok(())
    }
}

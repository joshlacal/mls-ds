//! End-to-end qualification suite for encrypted direct request cases C14, C15, C18, C19, C20.
//! Runs against the shipping server fixture, guarded PostgreSQL database, and independent MLS stores.
#![allow(dead_code, unused_imports)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::{
        decode_strict_json, direct_request::{self as protocol, DirectRequestKind},
        project_signed_body, SignedMutationKind, SigningTranscript,
    },
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
        DirectRequestWelcomeInput,
    },
    orchestrator::{
        canonical_application_aad_bytes, MLSDeliveryAckPayload, MLSMessagePayload, MLSMessageType,
        ReactionAction,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_snapshot,
    request_database_url, reviewed_baseline, reviewed_request_migrations, seed_service_device,
    signed_mls_request, validate_request_test_database_url, DeterministicFaultTransport,
    FaultBoundary, HttpsDidFixture, RequestRig, ServiceIdentity, ShippingServerFixture,
    dedicated_request_database_name,
};
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

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

fn psql_cmd(sql: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("psql")
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
        "psql error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn durable_graph(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<Vec<u8>> {
    validate_request_test_database_url(std::env::var("REQUEST_TEST_DATABASE_URL").ok().as_deref())?;
    let r = f.request_id;
    let c = f.conversation_id;
    let sql = format!(
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
    );
    let out = psql_cmd(&sql)?;
    Ok(out.into_bytes())
}

fn sign_mutation(
    engine: &MlsEngine,
    identity: &str,
    kind: SignedMutationKind,
    body: Value,
) -> anyhow::Result<Value> {
    let strict = decode_strict_json(&serde_json::to_vec(&body)?)?;
    let transcript = SigningTranscript::build_for(kind, &project_signed_body(kind, &strict)?)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    Ok(json!({
        "body": body,
        "signature": STANDARD.encode(signature)
    }))
}
fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    let type_id = body["$type"].as_str().context("body lacks $type")?;
    let kind = SignedMutationKind::from_type_id(type_id)
        .with_context(|| format!("unknown SignedMutationKind for {type_id}"))?;
    sign_mutation(engine, identity, kind, body)
}


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

fn set_recipient_view(root: &Path, recipient: &str, inviter: &str, row: Value) -> anyhow::Result<()> {
    set_policy(root, &["relationship", recipient, inviter], &row)
}

fn record_uri(owner: &str, collection: &str) -> String {
    format!("at://{owner}/{collection}/3jzfcijpj2z2a")
}

/// Real shipping client control payloads (MLSMessagePayload) for the C18 matrix.
/// `edit` and `callSignal` have no payload variant, so they use a text carrier.
fn control_payloads() -> Vec<(&'static str, MLSMessagePayload)> {
    let target = Uuid::new_v4().to_string();
    let control = |message_type: MLSMessageType, delivery_ack: Option<MLSDeliveryAckPayload>| MLSMessagePayload {
        version: 1,
        message_type,
        text: None,
        embed: None,
        reaction: None,
        delivery_ack,
        recovery_request: None,
    };
    vec![
        ("reaction", MLSMessagePayload::reaction(&target, "👍", ReactionAction::Add)),
        ("readReceipt", control(MLSMessageType::ReadReceipt, None)),
        ("deliveryReceipt", control(MLSMessageType::DeliveryAck, Some(MLSDeliveryAckPayload { message_id: target.clone() }))),
        ("inBandTyping", control(MLSMessageType::Typing, None)),
        ("edit(textCarrier)", MLSMessagePayload::text("Edit replacement text")),
        ("callSignal(textCarrier)", MLSMessagePayload::text("Call invite audio session")),
    ]
}

fn close_envelope(
    f: &live_direct_request::PublishedRequestFixture,
    actor_alice: bool,
    prior: Option<Value>,
) -> anyhow::Result<(Value, Uuid)> {
    let (who, engine) = if actor_alice {
        (&f.alice, f.alice_engine.as_ref().context("Alice engine for close")?)
    } else {
        (&f.bob, &f.bob_engine)
    };
    let identity = format!("{}#{}", who.did, who.device_id);
    let public = engine.identity_public_key(&identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));

    let prior_coord = prior.unwrap_or_else(|| f.publication["body"]["next"].clone());
    let mut retired = prior_coord.clone();
    retired["stateVersion"] = json!(prior_coord["stateVersion"].as_u64().context("sv")? + 1);
    retired["lifecycle"] = json!("superseded");

    let transition_id = Uuid::new_v4();
    let body = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseBody",
        "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
        "transitionId": transition_id.to_string(),
        "conversationKind": "direct",
        "actorDid": who.did,
        "actorDeviceId": who.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "prior": prior_coord,
        "retired": retired,
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed = sign_mutation(engine, &identity, SignedMutationKind::ConversationClose, body)?;
    Ok((json!({"signedRequest": signed}), transition_id))
}

async fn release_by_close(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<()> {
    release_by_close_from(f, None).await
}

async fn release_by_close_from(
    f: &live_direct_request::PublishedRequestFixture,
    prior: Option<Value>,
) -> anyhow::Result<()> {
    let lifecycle: String = psql_cmd(&format!(
        "SELECT lifecycle FROM chat.conversations WHERE conversation_id='{}'",
        f.conversation_id
    ))?;
    if lifecycle != "active" {
        return Ok(());
    }
    let (envelope, _) = close_envelope(f, true, prior)?;
    let (status, bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.closeConversation",
        &envelope,
        true,
    ).await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "release_by_close failed: {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(())
}

/// Every event row addressed to the sender (the source of her subscribeEvents
/// stream) plus her direct-request push fan-out rows.
fn alice_event_audience(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<String> {
    let a = &f.alice.did;
    psql_cmd(&format!(r#"SELECT jsonb_build_object(
      'events',(SELECT jsonb_agg(jsonb_build_object('position',er.event_position,'kind',e.event_kind,'device',er.device_id,'entitlement',er.entitlement_kind) ORDER BY er.event_position,er.device_id)
                FROM chat.event_recipients er JOIN chat.events e USING(event_position) WHERE er.user_did='{a}'),
      'push',(SELECT count(*) FROM chat.direct_request_push_event_recipients WHERE recipient_did='{a}')
    )::text"#))
}

fn durable_comprehensive(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<String> {
    let (r, c, a, b) = (f.request_id, f.conversation_id, &f.alice.did, &f.bob.did);
    psql_cmd(&format!(r#"SELECT jsonb_build_object(
      'conversation',(SELECT to_jsonb(x) FROM chat.conversations x WHERE conversation_id='{c}'),
      'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{r}'),
      'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{r}'),
      'selected',(SELECT jsonb_agg(to_jsonb(s) ORDER BY owner_device_id) FROM chat.direct_request_selected_devices s WHERE request_id='{r}'),
      'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{r}'),
      'welcomeOutcomes',(SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE request_id='{r}'),
      'participants',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_did) FROM chat.participants p WHERE conversation_id='{c}'),
      'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{c}'),
      'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id='{c}'),
      'blobs',(SELECT count(*) FROM chat.blobs WHERE owner_did IN ('{a}', '{b}')),
      'blobBindings',(SELECT count(*) FROM chat.blob_bindings WHERE conversation_id='{c}'),
      'resets',(SELECT count(*) FROM chat.reset_requests WHERE conversation_id='{c}'),
      'recoveries',(SELECT count(*) FROM chat.leaf_recovery_requests WHERE conversation_id='{c}')
    )::text"#))
}

struct Barrier {
    child: Child,
    stdin: ChildStdin,
    pid: i64,
}

impl Barrier {
    /// Holds the global direct-request budget singleton, then the principal,
    /// device and key rows of `dids` — the same order the server takes them
    /// (direct_request_lock.rs) — so racing operations queue behind this session.
    /// Only valid on a dedicated per-test database, where every other session
    /// belongs to this test's own fixture server.
    fn hold(dids: &[&str]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            dedicated_request_database_name(request_database_url()).is_some(),
            "barrier races must run on a dedicated catbird_direct_requests_fault_<hex> database"
        );
        let dids = dids.iter().map(|d| format!("'{d}'")).collect::<Vec<_>>().join(",");
        let budget = "SELECT singleton FROM chat.direct_request_budget WHERE singleton FOR UPDATE;\n";
        let mut child = Command::new("psql")
            .args([request_database_url(), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().context("barrier stdin")?;
        writeln!(
            stdin,
            "BEGIN;\nSELECT pg_backend_pid();\n{budget}\
             SELECT count(*) FROM (SELECT 1 FROM chat.principals WHERE user_did IN ({dids}) FOR UPDATE) p;\n\
             SELECT count(*) FROM (SELECT 1 FROM chat.devices WHERE user_did IN ({dids}) FOR UPDATE) d;\n\
             SELECT count(*) FROM (SELECT 1 FROM chat.device_keys WHERE user_did IN ({dids}) FOR UPDATE) k;\n\
             \\echo BARRIER-HELD"
        )?;
        stdin.flush()?;
        let stdout = child.stdout.take().context("barrier stdout")?;
        let mut lines = BufReader::new(stdout).lines();
        let pid_line = lines.next().context("barrier pid")??;
        let pid: i64 = pid_line.trim().parse()?;
        for line in lines.by_ref() {
            if line?.trim() == "BARRIER-HELD" {
                return Ok(Self { child, stdin, pid });
            }
        }
        anyhow::bail!("barrier session exited before holding locks")
    }

    /// Holds chat.conversations FOR UPDATE for this conversation_id.
    /// Used for close-vs-accept races where both execution transactions
    /// lock chat.conversations FOR UPDATE OF c before transition planning.
    fn hold_conversation(conversation_id: Uuid) -> anyhow::Result<Self> {
        anyhow::ensure!(
            dedicated_request_database_name(request_database_url()).is_some(),
            "barrier races must run on a dedicated catbird_direct_requests_fault_<hex> database"
        );
        let mut child = Command::new("psql")
            .args([request_database_url(), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().context("barrier stdin")?;
        writeln!(
            stdin,
            "BEGIN;\nSELECT pg_backend_pid();\n\
             SELECT 1 FROM chat.conversations WHERE conversation_id = '{conversation_id}' FOR UPDATE;\n\
             \\echo BARRIER-HELD"
        )?;
        stdin.flush()?;
        let stdout = child.stdout.take().context("barrier stdout")?;
        let mut lines = BufReader::new(stdout).lines();
        let pid_line = lines.next().context("barrier pid")??;
        let pid: i64 = pid_line.trim().parse()?;
        for line in lines.by_ref() {
            if line?.trim() == "BARRIER-HELD" {
                return Ok(Self { child, stdin, pid });
            }
        }
        anyhow::bail!("barrier session exited before holding conversation lock")
    }

    /// Sessions of this dedicated database blocked, directly or transitively,
    /// by the barrier session.
    fn waiters(&self) -> anyhow::Result<i64> {
        let sql = format!(
            "WITH RECURSIVE w(pid) AS (SELECT pid FROM pg_stat_activity WHERE {b}=ANY(pg_blocking_pids(pid)) \
             UNION SELECT a.pid FROM pg_stat_activity a JOIN w ON w.pid=ANY(pg_blocking_pids(a.pid))) \
             SELECT count(*) FROM w",
            b = self.pid
        );
        Ok(psql_cmd(&sql)?.trim().parse()?)
    }

    async fn wait_for_waiters(&self, at_least: i64) -> anyhow::Result<i64> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let n = self.waiters()?;
            if n >= at_least {
                return Ok(n);
            }
            anyhow::ensure!(Instant::now() < deadline, "only {n}/{at_least} sessions queued behind barrier");
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

fn receipt_info(response: &Value, key: &[u8]) -> anyhow::Result<(String, Option<String>)> {
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
        key,
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

fn expect_rejected_receipt(
    status: reqwest::StatusCode,
    response: &Value,
    receipt_key: &[u8],
    code: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{status}: {response}");
    let (kind, got) = receipt_info(response, receipt_key)?;
    anyhow::ensure!(
        kind == "directRequestRejectedReceipt" && got.as_deref() == Some(code),
        "expected rejected {code}, got {kind} {got:?}"
    );
    Ok(())
}

/// Publish one fresh direct-request key package + grant for `who` via the real
/// signed publishDirectRequestKeys RPC.
async fn publish_direct_keys(
    f: &live_direct_request::PublishedRequestFixture,
    who: &ServiceIdentity,
    engine: &MlsEngine,
    revision: u64,
) -> anyhow::Result<()> {
    let identity = format!("{}#{}", who.did, who.device_id);
    let (package, package_ref) = engine.create_key_package(&identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&engine.identity_public_key(&identity)?));
    let grant_id = Uuid::new_v4();
    let signed_grant = signed_mls_request(engine, &identity, DirectRequestKind::Grant, json!({
        "$type": "blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion": "2",
        "actorDid": who.did,
        "actorDeviceId": who.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "grantId": grant_id.to_string(),
        "grantRevision": 1,
        "purpose": "direct-request-bootstrap",
        "profile": "encryptedIntroduction1",
        "keyPackageRef": STANDARD.encode(&package_ref),
        "keyPackageSha256": STANDARD.encode(Sha256::digest(&package)),
        "expiresAt": canonical_future(29),
        "idempotencyKey": grant_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let keys_op = Uuid::new_v4();
    let keys = signed_mls_request(engine, &identity, DirectRequestKind::Keys, json!({
        "$type": "blue.catbird.chat.defs#directRequestKeysPublicationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-KEYS\0",
        "protocolVersion": "2",
        "actorDid": who.did,
        "actorDeviceId": who.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "revision": revision,
        "enabled": true,
        "keys": [{
            "keyPackage": {
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(&package),
                "sha256": STANDARD.encode(Sha256::digest(&package)),
                "keyPackageRef": STANDARD.encode(&package_ref)
            },
            "grant": signed_grant
        }],
        "idempotencyKey": keys_op.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, body) = who
        .post(&f.client, &f.server.base_url, "blue.catbird.chat.publishDirectRequestKeys", &json!({"signedRequest": keys}), true)
        .await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "{} keys publication failed {status}: {}", who.did, String::from_utf8_lossy(&body));
    Ok(())
}

/// A signed fresh-direct prepareDirectRequest from `sender` to `recipient_did`.
/// Returns (signed preparation, request id, first message id, candidate
/// conversation id).
fn sign_direct_preparation(
    sender: &ServiceIdentity,
    engine: &MlsEngine,
    recipient_did: &str,
) -> anyhow::Result<(Value, Uuid, Uuid, Uuid)> {
    let identity = format!("{}#{}", sender.did, sender.device_id);
    let public = engine.identity_public_key(&identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
    let request_id = Uuid::new_v4();
    let first_msg_id = Uuid::new_v4();
    let candidate = Uuid::new_v4();
    let prepare = signed_mls_request(engine, &identity, DirectRequestKind::Prepare, json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": sender.did,
        "actorDeviceId": sender.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "requestId": request_id.to_string(),
        "firstMessageId": first_msg_id.to_string(),
        "conversationId": candidate.to_string(),
        "recipientDid": recipient_did,
        "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
        "profile": "encryptedIntroduction1",
        "idempotencyKey": request_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    Ok((prepare, request_id, first_msg_id, candidate))
}

/// Real signed prepareDirectRequest from `sender` to `recipient_did`, then the
/// sender's native engine builds the bootstrap and the signed publication.
/// Returns (signed publication, request id, candidate conversation id).
async fn prepare_direct_publication(
    f: &live_direct_request::PublishedRequestFixture,
    sender: &ServiceIdentity,
    engine: &MlsEngine,
    recipient_did: &str,
    text: &str,
) -> anyhow::Result<(Value, Uuid, Uuid)> {
    let prepared = sign_direct_preparation(sender, engine, recipient_did)?;
    let (prepare_status, prepare_body) = sender
        .post(&f.client, &f.server.base_url, "blue.catbird.chat.prepareDirectRequest", &json!({"signedRequest": prepared.0}), true)
        .await?;
    anyhow::ensure!(prepare_status == reqwest::StatusCode::OK, "{} prepare failed {prepare_status}: {}", sender.did, String::from_utf8_lossy(&prepare_body));
    let publication = direct_publication(f, sender, engine, recipient_did, &prepared, &prepare_body, text)?;
    Ok((publication, prepared.1, prepared.3))
}

/// The sender's native engine builds the bootstrap and the signed publication
/// for `prepared`, from the server's 200 prepareDirectRequest response.
fn direct_publication(
    f: &live_direct_request::PublishedRequestFixture,
    sender: &ServiceIdentity,
    engine: &MlsEngine,
    recipient_did: &str,
    prepared: &(Value, Uuid, Uuid, Uuid),
    prepare_body: &[u8],
    text: &str,
) -> anyhow::Result<Value> {
    let (prepare, request_id, first_msg_id, candidate) = prepared;
    let identity = format!("{}#{}", sender.did, sender.device_id);
    let public = engine.identity_public_key(&identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
    let prep_resp: Value = serde_json::from_slice(prepare_body)?;
    let prep_snapshot = protocol::verify_direct_request_preparation(
        &serde_json::to_vec(prep_resp.pointer("/outcome/preparation").context("preparation snapshot")?)?,
        &f.server.receipt_public_key,
    )?;

    let context = json!({
        "protocolVersion": "2",
        "requestId": request_id.to_string(),
        "firstMessageId": first_msg_id.to_string(),
        "conversationId": candidate.to_string(),
        "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid": sender.did,
        "actorDeviceId": sender.device_id.to_string(),
        "actorKeyId": key_id,
        "recipientDid": recipient_did,
        "preparationDigest": prep_snapshot["preparationDigest"]
    });
    let selected = prep_snapshot["selectedDevices"].as_array().context("selectedDevices")?;
    // Same derivation as the shared fixture: the import authority is the earliest
    // selected grant expiry, which must cover the server's preparation floor.
    let minimum_import_until = chrono::DateTime::parse_from_rfc3339(
        prep_snapshot["minimumImportUntil"].as_str().context("minimumImportUntil")?,
    )?
    .timestamp();
    let authority_import_until = selected
        .iter()
        .map(|dev| {
            Ok(chrono::DateTime::parse_from_rfc3339(dev["grant"]["body"]["expiresAt"].as_str().context("grant expiresAt")?)?
                .timestamp())
        })
        .collect::<anyhow::Result<Vec<i64>>>()?
        .into_iter()
        .min()
        .context("no selected devices")?;
    anyhow::ensure!(authority_import_until >= minimum_import_until, "selected grant expires before preparation import floor");
    let authority_import_until = u64::try_from(authority_import_until)?;
    let verified_prepare = protocol::verify_signed_request(DirectRequestKind::Prepare, &serde_json::to_vec(&prepare)?, &public)?;
    let journal = engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|dev| Ok(STANDARD.decode(dev["keyPackage"]["bytes"].as_str().context("pkg bytes")?)?))
            .collect::<anyhow::Result<Vec<_>>>()?,
        expected_package_refs: selected
            .iter()
            .map(|dev| Ok(STANDARD.decode(dev["keyPackage"]["keyPackageRef"].as_str().context("pkg ref")?)?))
            .collect::<anyhow::Result<Vec<_>>>()?,
        authority_import_until,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: f.server.receipt_public_key.clone(),
        text: text.into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let bootstrap = &journal.bootstrap;
    let mut body = prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = prep_snapshot["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    body["next"] = bootstrap.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(bootstrap.import_until as i64, 0)
        .context("import timestamp")?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing": "mlsMessage", "contentType": content_type,
            "bytes": STANDARD.encode(data), "sha256": STANDARD.encode(Sha256::digest(data))
        })
    };
    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid": device["actorDid"],
                "recipientDeviceId": device["actorDeviceId"],
                "provenance": {
                    "requestId": request_id.to_string(),
                    "preparationDigest": prep_snapshot["preparationDigest"],
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": device["grant"]["body"]["grantId"],
                    "grantRevision": device["grant"]["body"]["grantRevision"],
                    "keyPackageRef": device["keyPackage"]["keyPackageRef"],
                    "importUntil": body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();
    let author = json!({
        "authorDid": sender.did, "authorDeviceId": sender.device_id.to_string(), "authorKeyId": key_id,
        "signaturePublicKey": STANDARD.encode(&public), "authGenerationAtOrigin": 1,
        "originTransitionId": request_id.to_string(), "originSeq": 1, "roleAtOrigin": "admin",
        "deviceStatusAtOrigin": "active"
    });
    body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
            "deliveries": deliveries
        },
        "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot": {
            "coordinate": metadata_coordinate(&bootstrap.coordinates)?,
            "originTransitionId": request_id.to_string(), "metadataVersion": 1,
            "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize": bootstrap.metadata_ciphertext.len(), "authorProof": author
        }
    });
    signed_mls_request(engine, &identity, DirectRequestKind::Publish, body)
}

// ============================================================================
// Case C14: Crossed starts
// Concurrent A->B / B->A yields one direct; loser retains authored draft,
// cannot transplant ciphertext or silently accept winner.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c14_crossed_starts_yield_single_direct_and_existing_direct_receipt() -> anyhow::Result<()> {
    // Alice prepares and publishes a direct request to Bob (A -> B).
    let f = live_direct_request::publish_request(false).await?;

    let (did_low, did_high) = if f.alice.did < f.bob.did {
        (&f.alice.did, &f.bob.did)
    } else {
        (&f.bob.did, &f.alice.did)
    };

    // Confirm that exactly one active direct conversation exists for this pair
    let count_before: i64 = psql_cmd(&format!(
        "SELECT count(*) FROM chat.conversations WHERE kind='direct' AND lifecycle='active' AND direct_did_low='{did_low}' AND direct_did_high='{did_high}'"
    ))?
    .parse()?;
    assert_eq!(count_before, 1, "Expected exactly one active direct conversation after Alice's publication");

    // Alice publishes direct request keys so Bob can address Alice for B -> A,
    // then Bob prepares and publishes the crossed B -> A request.
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    publish_direct_keys(&f, &f.alice, alice_engine, 1).await?;
    let (bob_publish, _bob_request_id, bob_candidate_convo_id) =
        prepare_direct_publication(&f, &f.bob, &f.bob_engine, &f.alice.did, "Bob's candidate introduction").await?;
    let (publish_status, publish_response) = f
        .bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": bob_publish}),
            true,
        )
        .await?;
    anyhow::ensure!(
        publish_status == reqwest::StatusCode::OK,
        "Bob publish request failed {publish_status}: {}",
        String::from_utf8_lossy(&publish_response)
    );

    let pub_resp: Value = serde_json::from_slice(&publish_response)?;
    let outcome = &pub_resp["outcome"];
    assert_eq!(outcome["$type"], "blue.catbird.chat.defs#signedDirectRequestReceipt");

    let receipt = &outcome["body"]["receipt"];
    assert_eq!(
        receipt["$type"], "blue.catbird.chat.defs#directRequestExistingDirectReceipt",
        "Server must return directRequestExistingDirectReceipt for crossed start"
    );
    assert_eq!(
        receipt["conversationId"],
        f.conversation_id.to_string(),
        "Receipt must point to the winning conversation"
    );
    assert_eq!(
        receipt["requiresAcceptance"], true,
        "Bob is pending recipient in the winner, requiresAcceptance must be true"
    );

    // Confirm that STILL exactly one active direct conversation exists in the guarded database
    let count_after: i64 = psql_cmd(&format!(
        "SELECT count(*) FROM chat.conversations WHERE kind='direct' AND lifecycle='active' AND direct_did_low='{did_low}' AND direct_did_high='{did_high}'"
    ))?
    .parse()?;
    assert_eq!(count_after, 1, "Guarded database must retain exactly one direct conversation for the pair");

    // The losing candidate's proposed conversation was NOT created
    let candidate_exists = psql_cmd(&format!(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id='{bob_candidate_convo_id}')"
    ))?
    .trim()
        == "t";
    assert!(!candidate_exists, "Losing candidate conversation ID must not exist in database");
    release_by_close(&f).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c14_concurrent_crossed_publications_barrier_one_direct() -> anyhow::Result<()> {
    // Registered pair; close the fixture's direct so neither side has one.
    let f = live_direct_request::publish_request(false).await?;
    release_by_close(&f).await?;
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    publish_direct_keys(&f, &f.alice, alice_engine, 1).await?;
    publish_direct_keys(&f, &f.bob, &f.bob_engine, 2).await?;

    // Crossed starts converge at preparation: the pair fence admits one
    // in-progress request per pair (f38efd4b). Both real preparations (A -> B
    // and B -> A) queue behind a barrier holding the request budget and both
    // principals' locks, then are released together.
    let a_prep = sign_direct_preparation(&f.alice, alice_engine, &f.bob.did)?;
    let b_prep = sign_direct_preparation(&f.bob, &f.bob_engine, &f.alice.did)?;
    let barrier = Barrier::hold(&[&f.alice.did, &f.bob.did])?;
    let a_future = {
        let (who, client, base, env) = (f.alice.clone(), f.client.clone(), f.server.base_url.clone(), json!({"signedRequest": a_prep.0.clone()}));
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.prepareDirectRequest", &env, true).await })
    };
    let b_future = {
        let (who, client, base, env) = (f.bob.clone(), f.client.clone(), f.server.base_url.clone(), json!({"signedRequest": b_prep.0.clone()}));
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.prepareDirectRequest", &env, true).await })
    };
    let queued = barrier.wait_for_waiters(2).await?;
    barrier.release()?;
    let (a_status, a_bytes) = a_future.await??;
    let (b_status, b_bytes) = b_future.await??;
    let alice_won = a_status == reqwest::StatusCode::OK;
    let (won_status, lost_status, lost_bytes) = if alice_won { (a_status, b_status, &b_bytes) } else { (b_status, a_status, &a_bytes) };
    anyhow::ensure!(
        won_status == reqwest::StatusCode::OK,
        "exactly one preparation must win: Alice {a_status}: {} / Bob {b_status}: {}",
        String::from_utf8_lossy(&a_bytes),
        String::from_utf8_lossy(&b_bytes)
    );
    anyhow::ensure!(
        lost_status == reqwest::StatusCode::BAD_REQUEST
            && serde_json::from_slice::<Value>(lost_bytes)?["error"] == "PreparationConflict",
        "the crossed preparation must lose with PreparationConflict: {lost_status}: {}",
        String::from_utf8_lossy(lost_bytes)
    );
    let alice = (&f.alice, alice_engine, &a_prep, &a_bytes);
    let bob = (&f.bob, &f.bob_engine, &b_prep, &b_bytes);
    let ((winner, winner_engine, winner_prep, winner_bytes), (loser, loser_engine, loser_prep, _)) =
        if alice_won { (alice, bob) } else { (bob, alice) };
    eprintln!("C14 concurrent crossed start: queued={queued} winner={}", if alice_won { "alice" } else { "bob" });
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{}'", loser_prep.1))?,
        "0",
        "the losing preparation leaves no attempt"
    );

    // The winner publishes its preparation; the loser's later start finds
    // the winner's direct instead of creating a second one.
    const PUBLISHED: &str = "blue.catbird.chat.defs#directRequestPublishedReceipt";
    const EXISTING: &str = "blue.catbird.chat.defs#directRequestExistingDirectReceipt";
    let winner_pub = direct_publication(&f, winner, winner_engine, &loser.did, winner_prep, winner_bytes, "Winner crossed start")?;
    let (publish_status, publish_bytes) = winner
        .post(&f.client, &f.server.base_url, "blue.catbird.chat.publishDirectRequest", &json!({"signedRequest": winner_pub}), true)
        .await?;
    anyhow::ensure!(publish_status == reqwest::StatusCode::OK, "winner publish {publish_status}: {}", String::from_utf8_lossy(&publish_bytes));
    let winner_receipt = serde_json::from_slice::<Value>(&publish_bytes)?["outcome"]["body"]["receipt"].clone();
    assert_eq!(winner_receipt["$type"], PUBLISHED, "the prepared side publishes the direct: {winner_receipt}");
    let winner_convo = winner_prep.3;
    let (loser_pub, loser_req, loser_convo) =
        prepare_direct_publication(&f, loser, loser_engine, &winner.did, "Loser crossed start").await?;
    let (loser_status, loser_bytes) = loser
        .post(&f.client, &f.server.base_url, "blue.catbird.chat.publishDirectRequest", &json!({"signedRequest": loser_pub}), true)
        .await?;
    anyhow::ensure!(loser_status == reqwest::StatusCode::OK, "loser publish {loser_status}: {}", String::from_utf8_lossy(&loser_bytes));
    let loser_receipt = serde_json::from_slice::<Value>(&loser_bytes)?["outcome"]["body"]["receipt"].clone();
    assert_eq!(loser_receipt["$type"], EXISTING, "loser must get existing-direct receipt: {loser_receipt}");
    assert_eq!(loser_receipt["conversationId"], winner_convo.to_string(), "loser receipt names the winner");
    assert_eq!(loser_receipt["requiresAcceptance"], true, "loser is pending recipient; nothing silently accepted");

    let (did_low, did_high) = if f.alice.did < f.bob.did { (&f.alice.did, &f.bob.did) } else { (&f.bob.did, &f.alice.did) };
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.conversations WHERE kind='direct' AND lifecycle='active' AND direct_did_low='{did_low}' AND direct_did_high='{did_high}'"))?,
        "1",
        "exactly one active direct for the pair"
    );
    for candidate in [loser_prep.3, loser_convo] {
        assert_eq!(psql_cmd(&format!("SELECT count(*) FROM chat.conversations WHERE conversation_id='{candidate}'"))?, "0", "loser candidate not created");
    }
    assert_eq!(psql_cmd(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{loser_req}'"))?, "0", "loser ciphertext not transplanted");
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.transitions WHERE conversation_id='{winner_convo}' AND kind='directRequestAcceptance'"))?,
        "0",
        "no acceptance recorded for the winner"
    );

    // Release capacity: close the winner through the real signed RPC.
    let (close_env, _) = close_envelope(&f, alice_won, Some(winner_pub["body"]["next"].clone()))?;
    let (close_status, close_bytes) = winner.post(&f.client, &f.server.base_url, "blue.catbird.chat.closeConversation", &close_env, true).await?;
    anyhow::ensure!(close_status == reqwest::StatusCode::OK, "winner close {close_status}: {}", String::from_utf8_lossy(&close_bytes));
    Ok(())
}

fn bob_context_hash(ctx: &Value) -> anyhow::Result<String> {
    let canonical = serde_json::to_vec(ctx)?;
    Ok(STANDARD.encode(Sha256::digest(canonical)))
}

// ============================================================================
// Case C15: Retry/idempotency collision
// Same operation and exact bytes replay success; changed text/artifact/signature/
// digest conflict. Edited local draft cannot mutate an unresolved operation.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c15_exact_replay_success_and_attribute_collisions() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let before = durable_graph(&f)?;
    let engine = f.alice_engine.as_ref().context("Alice sender engine")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);

    // 1. Exact replay of identical publication envelope succeeds idempotently
    let (replay_status, replay_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": f.publication}),
            true,
        )
        .await?;
    anyhow::ensure!(replay_status == reqwest::StatusCode::OK, "Exact replay failed: {replay_status}");
    let replay_resp: Value = serde_json::from_slice(&replay_bytes)?;
    let mut replayed_receipt = replay_resp["outcome"].clone();
    replayed_receipt.as_object_mut().context("outcome obj")?.remove("$type");
    assert_eq!(replayed_receipt, f.receipt, "Replayed receipt must equal original committed proof");
    assert_eq!(durable_graph(&f)?, before, "Exact replay must not alter durable graph");

    // 2. Collisions: re-sign changed fields under the original operation ID
    for field in ["ciphertext", "digest", "firstMessageId"] {
        let mut body = f.publication["body"].clone();
        match field {
            "ciphertext" => {
                let mut b = STANDARD.decode(body["artifacts"]["initialCiphertext"].as_str().unwrap())?;
                b[0] ^= 1;
                body["artifacts"]["initialCiphertext"] = json!(STANDARD.encode(b));
            }
            "digest" => {
                body["artifacts"]["welcome"]["sha256"] = json!(STANDARD.encode([0x77; 32]));
            }
            _ => {
                body["firstMessageId"] = json!(Uuid::new_v4().to_string());
            }
        }
        let changed = signed_mls_request(engine, &identity, DirectRequestKind::Publish, body)?;
        let (status, resp_bytes) = f
            .alice
            .post(
                &f.client,
                &f.server.base_url,
                "blue.catbird.chat.publishDirectRequest",
                &json!({"signedRequest": changed}),
                true,
            )
            .await?;
        anyhow::ensure!(status.is_client_error(), "{field} collision must return 4xx error, got {status}");
        let err: Value = serde_json::from_slice(&resp_bytes)?;
        assert_eq!(err["error"], "PreparationConflict", "Expected PreparationConflict for {field}");
        assert_eq!(durable_graph(&f)?, before, "{field} collision must not alter durable database graph");
    }

    // 3. Bit-flipped signature returns InvalidSignature
    let mut bad_sig_pub = f.publication.clone();
    let mut sig = STANDARD.decode(bad_sig_pub["signature"].as_str().unwrap())?;
    sig[0] ^= 1;
    bad_sig_pub["signature"] = json!(STANDARD.encode(sig));
    let (sig_status, sig_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": bad_sig_pub}),
            true,
        )
        .await?;
    assert_eq!(sig_status, reqwest::StatusCode::UNAUTHORIZED, "Bad signature must return 401");
    let err: Value = serde_json::from_slice(&sig_bytes)?;
    assert_eq!(err["error"], "InvalidSignature");
    assert_eq!(durable_graph(&f)?, before, "Invalid signature attempt must not alter durable graph");

    // 4. Exact replay after all collision attempts still succeeds
    let (final_status, _final_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest": f.publication}),
            true,
        )
        .await?;
    assert_eq!(final_status, reqwest::StatusCode::OK);
    assert_eq!(durable_graph(&f)?, before);
    release_by_close(&f).await?;

    Ok(())
}

// ============================================================================
// Case C18: Pending authority matrix
// Creator and recipient cannot send extra apps, edits, reactions, receipts,
// typing, calls, metadata/admin changes, arbitrary Add, reset, or attachment
// binds while pending. Close/decline remain available.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c18_pending_authority_matrix_forbids_mutations_while_close_available() -> anyhow::Result<()> {
    // Start with an unaccepted, pending direct request.
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;

    let alice_identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));

    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let group = STANDARD.decode(prior["groupId"].as_str().context("group")?)?;
    let epoch = prior["epoch"].as_u64().context("epoch")?;

    // Base durable graph before any forbidden mutation attempt
    let before = durable_comprehensive(&f)?;

    // Helper closure to build a signed applicationSendBody with real encrypted ciphertext
    let make_app_send = |engine: &MlsEngine, identity: &str, did: &str, device_id: &Uuid, key_id: &str, payload: &MLSMessagePayload, blob_bindings: Value| -> anyhow::Result<Value> {
        let message_id = Uuid::new_v4();
        let mut aad_prior = prior.clone();
        aad_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
        let aad = json!({
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(f.conversation_id.as_bytes()),
            "generation": prior["generation"],
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "prior": aad_prior
        });
        let content = payload.encode()?;
        let ciphertext = engine.encrypt_canonical(&group, &content, canonical_application_aad_bytes(&aad)?, epoch)?;
        let body = json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": message_id.to_string(),
            "actorDid": did,
            "actorDeviceId": device_id.to_string(),
            "keyId": key_id,
            "authGeneration": 1,
            "prior": prior,
            "aad": aad,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&ciphertext),
                "sha256": STANDARD.encode(Sha256::digest(&ciphertext))
            },
            "blobBindings": blob_bindings,
            "signedAt": canonical_now()
        });
        signed_ordinary(engine, identity, body)
    };

    // ========================================================================
    // PART A: Creator (Alice) authority restrictions while pending
    // ========================================================================

    // 1. Extra application message: Alice attempts second message before consent
    let alice_send = make_app_send(alice_engine, &alice_identity, &f.alice.did, &f.alice.device_id, &alice_key_id, &MLSMessagePayload::text("Extra app message by creator"), json!([]))?;
    let (send_status, send_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": alice_send}), true).await?;
    assert_eq!(send_status, reqwest::StatusCode::BAD_REQUEST, "Creator extra app message must fail 400");
    let err: Value = serde_json::from_slice(&send_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Creator sendMessage rejection must leave graph unchanged");

    // 2. Typing: Alice attempts publishTyping while pending
    let alice_typing = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#typingBody",
        "signatureDomain": "CATBIRD-CHAT-TYPING\0",
        "typingId": Uuid::new_v4().to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "coordinates": prior,
        "isTyping": true,
        "signedAt": canonical_now()
    }))?;
    let (t_status, t_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.publishTyping", &json!({"signedRequest": alice_typing}), true).await?;
    assert_eq!(t_status, reqwest::StatusCode::BAD_REQUEST, "Creator typing must fail 400");
    let err: Value = serde_json::from_slice(&t_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Creator typing rejection must leave graph unchanged");

    // 3. Edits / Reactions / Receipts / Calls ride inside encrypted application
    //    content; the server is ciphertext-blind, so every one reaches it as a
    //    sendMessage. Each real client control payload is encrypted and refused by
    //    the pending-consent gate. The shipping payload model has no Edit or Call
    //    variant (MLSMessageType) and v2 editFrameBody has no Rust encoder, so those
    //    two rows use a text carrier and are recorded as partial in evidence.
    for (name, payload) in control_payloads() {
        let send_mut = make_app_send(alice_engine, &alice_identity, &f.alice.did, &f.alice.device_id, &alice_key_id, &payload, json!([]))?;
        let (status, bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": send_mut}), true).await?;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "Creator {name} frame must fail 400");
        let err: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(err["error"], "ConversationNotAccepted", "Creator {name} frame rejected: {err}");
        assert_eq!(durable_comprehensive(&f)?, before, "Creator {name} must leave graph unchanged");
    }

    // 4. Attachment bind in sendMessage: applicationAttachmentBinding in blobBindings
    let blob_binding = json!([{
        "blobId": Uuid::new_v4().to_string(),
        "ciphertextSha256": STANDARD.encode([0x88; 32]),
        "ciphertextSize": 2048,
        "purpose": "attachment"
    }]);
    let alice_blob_send = make_app_send(alice_engine, &alice_identity, &f.alice.did, &f.alice.device_id, &alice_key_id, &MLSMessagePayload::text("Message with attachment bind"), blob_binding.clone())?;
    let (bs_status, bs_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": alice_blob_send}), true).await?;
    assert_eq!(bs_status, reqwest::StatusCode::BAD_REQUEST, "Creator attachment bind must fail 400");
    let err: Value = serde_json::from_slice(&bs_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Attachment bind send must leave graph unchanged");

    // 5. Blob upload preparation: prepareBlobUpload signed by Alice
    let alice_blob_prep = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\0",
        "blobId": Uuid::new_v4().to_string(),
        "conversationId": f.conversation_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "ciphertextSha256": STANDARD.encode(Sha256::digest(b"test-attachment-payload")),
        "ciphertextSize": 4096,
        "mediaType": "image/png",
        "plaintextSize": 1024,
        "purpose": "attachment",
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now()
    }))?;
    let (bp_status, bp_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.prepareBlobUpload", &json!({"signedRequest": alice_blob_prep}), true).await?;
    assert_eq!(bp_status, reqwest::StatusCode::BAD_REQUEST, "Creator blob upload preparation must fail 400");
    let err: Value = serde_json::from_slice(&bp_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Creator blob upload preparation must leave graph unchanged");

    // 6. Metadata/admin change: submitTransition with metadataTransitionBody
    let mut next_coord = prior.clone();
    next_coord["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
    let tid_alice_meta = Uuid::new_v4().to_string();
    let alice_metadata_trans = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#metadataTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-METADATA\0",
        "transitionId": tid_alice_meta,
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next_coord,
        "metadataSnapshot": f.publication["body"]["artifacts"]["metadataSnapshot"],
        "idempotencyKey": tid_alice_meta,
        "signedAt": canonical_now()
    }))?;
    let (meta_status, meta_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.submitTransition", &json!({"signedRequest": alice_metadata_trans}), true).await?;
    assert_eq!(meta_status, reqwest::StatusCode::BAD_REQUEST, "Creator metadata transition must fail 400");
    let err: Value = serde_json::from_slice(&meta_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Creator metadata transition must leave graph unchanged");

    // 7. Arbitrary Add / admin: submitTransition with policyTransitionBody addParticipant
    // A real registered third account (from an independent published request) so
    // the Add passes device discovery and reaches the pending-consent gate.
    let third = live_direct_request::publish_request(false).await?;
    let new_user = third.alice.did.as_str();
    let tid_alice_policy = Uuid::new_v4().to_string();
    let alice_policy = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\0",
        "transitionId": tid_alice_policy,
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next_coord,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": new_user,
            "role": "member",
            "status": "pending",
            "invitationProvenance": {
                "invitationTransitionId": f.request_id.to_string(),
                "invitedByDid": f.alice.did,
                "invitedByDeviceId": f.alice.device_id.to_string()
            }
        }],
        "idempotencyKey": tid_alice_policy,
        "signedAt": canonical_now()
    }))?;
    let (pol_status, pol_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.submitTransition", &json!({"signedRequest": alice_policy}), true).await?;
    assert_eq!(pol_status, reqwest::StatusCode::BAD_REQUEST, "Creator arbitrary Add must fail 400");
    let err: Value = serde_json::from_slice(&pol_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Arbitrary Add transition must leave graph unchanged");

    // 8. Reset: requestReset by Alice
    let reset_id = Uuid::new_v4();
    let alice_reset = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
        "resetRequestId": reset_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "reason": "manualRecovery",
        "idempotencyKey": reset_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (rst_status, rst_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.requestReset", &json!({"signedRequest": alice_reset}), true).await?;
    assert_eq!(rst_status, reqwest::StatusCode::BAD_REQUEST, "Creator requestReset must fail 400");
    let err: Value = serde_json::from_slice(&rst_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Reset request must leave graph unchanged");

    // ========================================================================
    // PART B: Recipient (Bob) authority restrictions while pending
    // ========================================================================

    // Bob imports the Welcome locally so he has native crypto context at the current epoch.
    f.bob_engine.process_direct_request(&f.welcome_input)?;

    // 1. Extra application message: Bob attempts to send message before acceptance
    let bob_send = make_app_send(&f.bob_engine, &bob_identity, &f.bob.did, &f.bob.device_id, &bob_key_id, &MLSMessagePayload::text("Recipient sending message before acceptance"), json!([]))?;
    let (b_send_status, b_send_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": bob_send}), true).await?;
    assert_eq!(b_send_status, reqwest::StatusCode::BAD_REQUEST, "Recipient sendMessage must fail 400");
    let err: Value = serde_json::from_slice(&b_send_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient sendMessage must leave graph unchanged");

    // 2. Typing: Bob attempts publishTyping while pending
    let bob_typing = signed_ordinary(&f.bob_engine, &bob_identity, json!({
        "$type": "blue.catbird.chat.defs#typingBody",
        "signatureDomain": "CATBIRD-CHAT-TYPING\0",
        "typingId": Uuid::new_v4().to_string(),
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "coordinates": prior,
        "isTyping": true,
        "signedAt": canonical_now()
    }))?;
    let (b_t_status, b_t_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.publishTyping", &json!({"signedRequest": bob_typing}), true).await?;
    assert_eq!(b_t_status, reqwest::StatusCode::BAD_REQUEST, "Recipient typing must fail 400");
    let err: Value = serde_json::from_slice(&b_t_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient typing must leave graph unchanged");

    // 3. Edits / Reactions / Receipts / Calls: Bob attempts each control payload
    for (name, payload) in control_payloads() {
        let b_send_mut = make_app_send(&f.bob_engine, &bob_identity, &f.bob.did, &f.bob.device_id, &bob_key_id, &payload, json!([]))?;
        let (status, bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": b_send_mut}), true).await?;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "Recipient {name} frame must fail 400");
        let err: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(err["error"], "ConversationNotAccepted");
        assert_eq!(durable_comprehensive(&f)?, before, "Recipient {name} must leave graph unchanged");
    }

    // 3b. Attachment bind in sendMessage by Bob
    let bob_blob_send = make_app_send(&f.bob_engine, &bob_identity, &f.bob.did, &f.bob.device_id, &bob_key_id, &MLSMessagePayload::text("Recipient attachment bind"), blob_binding.clone())?;
    let (b_bs_status, b_bs_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": bob_blob_send}), true).await?;
    assert_eq!(b_bs_status, reqwest::StatusCode::BAD_REQUEST, "Recipient attachment bind must fail 400");
    let err: Value = serde_json::from_slice(&b_bs_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient attachment bind send must leave graph unchanged");

    // 4. Blob upload preparation by Bob
    let bob_blob_prep = signed_ordinary(&f.bob_engine, &bob_identity, json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\0",
        "blobId": Uuid::new_v4().to_string(),
        "conversationId": f.conversation_id.to_string(),
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "prior": prior,
        "ciphertextSha256": STANDARD.encode(Sha256::digest(b"bob-attachment-payload")),
        "ciphertextSize": 4096,
        "mediaType": "image/png",
        "plaintextSize": 1024,
        "purpose": "attachment",
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now()
    }))?;
    let (b_bp_status, b_bp_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.prepareBlobUpload", &json!({"signedRequest": bob_blob_prep}), true).await?;
    assert_eq!(b_bp_status, reqwest::StatusCode::BAD_REQUEST, "Recipient blob upload preparation must fail 400");
    let err: Value = serde_json::from_slice(&b_bp_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient blob upload preparation must leave graph unchanged");

    // 5. Reset by Bob
    let b_reset_id = Uuid::new_v4();
    let bob_reset = signed_ordinary(&f.bob_engine, &bob_identity, json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
        "resetRequestId": b_reset_id.to_string(),
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "prior": prior,
        "reason": "manualRecovery",
        "idempotencyKey": b_reset_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (b_rst_status, b_rst_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.requestReset", &json!({"signedRequest": bob_reset}), true).await?;
    assert_eq!(b_rst_status, reqwest::StatusCode::BAD_REQUEST, "Recipient requestReset must fail 400");
    let err: Value = serde_json::from_slice(&b_rst_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient reset must leave graph unchanged");

    // 6. Metadata/admin change and arbitrary Add by Bob via submitTransition
    let tid_bob_meta = Uuid::new_v4().to_string();
    let bob_metadata_trans = signed_ordinary(&f.bob_engine, &bob_identity, json!({
        "$type": "blue.catbird.chat.defs#metadataTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-METADATA\0",
        "transitionId": tid_bob_meta,
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next_coord,
        "metadataSnapshot": f.publication["body"]["artifacts"]["metadataSnapshot"],
        "idempotencyKey": tid_bob_meta,
        "signedAt": canonical_now()
    }))?;
    let (b_meta_status, b_meta_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.submitTransition", &json!({"signedRequest": bob_metadata_trans}), true).await?;
    assert_eq!(b_meta_status, reqwest::StatusCode::BAD_REQUEST, "Recipient metadata transition must fail 400");
    let err: Value = serde_json::from_slice(&b_meta_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient metadata transition must leave graph unchanged");

    let tid_bob_policy = Uuid::new_v4().to_string();
    let bob_policy = signed_ordinary(&f.bob_engine, &bob_identity, json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\0",
        "transitionId": tid_bob_policy,
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next_coord,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": new_user,
            "role": "member",
            "status": "pending",
            "invitationProvenance": {
                "invitationTransitionId": f.request_id.to_string(),
                "invitedByDid": f.bob.did,
                "invitedByDeviceId": f.bob.device_id.to_string()
            }
        }],
        "idempotencyKey": tid_bob_policy,
        "signedAt": canonical_now()
    }))?;
    let (b_pol_status, b_pol_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.submitTransition", &json!({"signedRequest": bob_policy}), true).await?;
    assert_eq!(b_pol_status, reqwest::StatusCode::BAD_REQUEST, "Recipient arbitrary Add must fail 400");
    let err: Value = serde_json::from_slice(&b_pol_bytes)?;
    assert_eq!(err["error"], "ConversationNotAccepted");
    assert_eq!(durable_comprehensive(&f)?, before, "Recipient arbitrary Add must leave graph unchanged");

    // ========================================================================
// PART C: Close / per-device Welcome rejection remain available
// ========================================================================

// 1. Per-device Welcome rejection: Bob calls rejectWelcome with real signed welcomeRejectionBody -> succeeds!
    let bob_reject_id = Uuid::new_v4();
    let bob_reject_body = json!({
        "$type": "blue.catbird.chat.defs#welcomeRejectionBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-REJECT\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": prior,
        "reason": "noMatchingKeyPackage",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "idempotencyKey": bob_reject_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_reject = sign_mutation(&f.bob_engine, &bob_identity, SignedMutationKind::WelcomeRejection, bob_reject_body)?;
    let (reject_status, reject_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.rejectWelcome", &json!({"signedRequest": signed_reject}), true).await?;
    anyhow::ensure!(
        reject_status == reqwest::StatusCode::OK,
        "Welcome rejection / decline must remain available while pending: {reject_status}: {}",
        String::from_utf8_lossy(&reject_bytes)
    );
    let reject_resp: Value = serde_json::from_slice(&reject_bytes)?;
    assert_eq!(reject_resp["status"], "rejected", "rejectWelcome outcome must be recorded as rejected");
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE request_id='{}' AND recipient_did='{}' AND status='rejected'", f.request_id, f.bob.did))?,
        "1",
        "rejectWelcome must be recorded durably in direct_request_welcome_outcomes"
    );

    // 2. Terminal close (account decline / creator close): Alice calls closeConversation with real signed conversationCloseBody -> succeeds!
    let (close_env, close_tx_id) = close_envelope(&f, true, None)?;
    let (close_status, close_bytes) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.closeConversation", &close_env, true).await?;
    anyhow::ensure!(
        close_status == reqwest::StatusCode::OK,
        "Close must remain available while pending: {close_status}: {}",
        String::from_utf8_lossy(&close_bytes)
    );
    let close_resp: Value = serde_json::from_slice(&close_bytes)?;
    assert!(close_resp["result"]["tombstone"].is_object(), "Close response must contain tombstone");
    assert_eq!(
        psql_cmd(&format!("SELECT lifecycle FROM chat.conversations WHERE conversation_id='{}'", f.conversation_id))?,
        "superseded",
        "Conversation lifecycle must be superseded after signed close"
    );
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.transitions WHERE transition_id='{close_tx_id}' AND kind='closeConversation'"))?,
        "1",
        "Production code must record closeConversation transition row"
    );

    release_by_close(&third).await?;
    Ok(())
}

// ============================================================================
// Case C19: Sender privacy
// Preview fetch/import/ACK cannot produce peer-visible read or delivery status,
// presence or typing. Exercise every status/event projection.
// Internal durability ACK remains valid.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c19_preview_fetch_import_ack_produce_no_peer_visible_signals() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);

    // 1. Capture Alice's view of conversation status and entries BEFORE Bob interacts
    let (status, convos_before_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let convos_before: Value = serde_json::from_slice(&convos_before_bytes)?;

    let (status, state_before_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let state_before: Value = serde_json::from_slice(&state_before_bytes)?;

    let (status, entries_before_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), f.conversation_id.to_string()),
                ("afterSeq".into(), "0".into()),
                ("limit".into(), "100".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entries_before: Value = serde_json::from_slice(&entries_before_bytes)?;
    // Alice's subscribeEvents stream and push fan-out are served from these
    // durable audience rows; snapshot them to prove no peer-visible event.
    let events_before = alice_event_audience(&f)?;

    // 2. Bob fetches inventory session and pending welcomes via getPendingWelcomes (preview fetch)
    let (status, convos_bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let convos_resp: Value = serde_json::from_slice(&convos_bytes)?;
    let session_id = convos_resp["inventorySessionId"].as_str().context("session id")?;

    let (status, welcomes_bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("inventorySessionId".into(), session_id.into()),
                ("limit".into(), "50".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let welcomes_resp: Value = serde_json::from_slice(&welcomes_bytes)?;
    let items = welcomes_resp["items"].as_array().context("pending welcomes items")?;
    assert!(
        items.iter().any(|item| item["welcomeId"] == f.request_id.to_string()),
        "Bob must receive the pending Welcome for this request"
    );

    // 3. Bob imports the Welcome and executes internal durability ACK via acknowledgeWelcome
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let intro = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    assert!(matches!(intro, DirectRequestIntroductionResult::Ready { .. }), "Bob natively imports and decrypts the preview");
    let ack_id = Uuid::new_v4();
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&f.bob_engine.identity_public_key(&bob_identity)?));
    let ack_body = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "idempotencyKey": ack_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_ack = sign_mutation(&f.bob_engine, &bob_identity, SignedMutationKind::WelcomeAcknowledgement, ack_body)?;

    let (ack_status, ack_resp_bytes) = f
        .bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acknowledgeWelcome",
            &json!({"signedRequest": signed_ack}),
            true,
        )
        .await?;
    anyhow::ensure!(
        ack_status == reqwest::StatusCode::OK,
        "Internal durability ACK failed {ack_status}: {}",
        String::from_utf8_lossy(&ack_resp_bytes)
    );
    let ack_resp: Value = serde_json::from_slice(&ack_resp_bytes)?;
    assert_eq!(ack_resp["status"], "acknowledged");

    // 4. Verify in database: internal durability ACK is durably valid
    let ack_recorded = psql_cmd(&format!(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_welcome_outcomes WHERE request_id='{request_id}' AND recipient_did='{recipient}' AND status='acknowledged')",
        request_id = f.request_id,
        recipient = f.bob.did
    ))?
    .trim()
        == "t";
    assert!(ack_recorded, "Internal durability ACK must be recorded in guarded database");

    // 5. Audit EVERY status projection for Alice: zero peer-visible read, delivery, presence, or typing!
    let (status, convos_after_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let convos_after: Value = serde_json::from_slice(&convos_after_bytes)?;

    let (status, state_after_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let state_after: Value = serde_json::from_slice(&state_after_bytes)?;

    let (status, entries_after_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), f.conversation_id.to_string()),
                ("afterSeq".into(), "0".into()),
                ("limit".into(), "100".into()),
            ],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entries_after: Value = serde_json::from_slice(&entries_after_bytes)?;

    // Assert that Alice's projections remain strictly identical or leak zero peer signals
    assert_eq!(
        convos_before, convos_after,
        "getConversations projection must not reveal recipient preview/ACK activity"
    );
    assert_eq!(
        state_before, state_after,
        "getConversationState projection must not reveal recipient preview/ACK activity"
    );
    assert_eq!(
        entries_before, entries_after,
        "getEntries projection must not reveal recipient preview/ACK activity"
    );
    assert_eq!(
        alice_event_audience(&f)?,
        events_before,
        "no event (read, delivery, presence, typing or other) reaches Alice's stream or push fan-out"
    );
    release_by_close(&f).await?;

    Ok(())
}

// ============================================================================
// Case C20: Close/block monotonicity
// Close during import or accept has one authoritative outcome; late events
// cannot resurrect state. Block prevents repeat requests under current rules;
// no claim of retracting already decrypted content.
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn c20_close_terminal_and_late_events_cannot_resurrect() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;

    // 1. Bob imports the Welcome and decrypts the preview locally before close
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let intro_before = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    assert!(matches!(intro_before, DirectRequestIntroductionResult::Ready { .. }), "Bob must decrypt before close");

    // 2. Authoritative signed close via the real closeConversation RPC by Bob (pending invitee)
    let (close_env, close_tx_id) = close_envelope(&f, false, None)?;
    let (close_status, close_bytes) = f.bob.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.closeConversation",
        &close_env,
        true,
    ).await?;
    anyhow::ensure!(
        close_status == reqwest::StatusCode::OK,
        "Real signed closeConversation failed: {close_status}: {}",
        String::from_utf8_lossy(&close_bytes)
    );
    let close_resp: Value = serde_json::from_slice(&close_bytes)?;
    assert!(close_resp["result"]["tombstone"].is_object(), "Close response must contain tombstone");
    assert!(close_resp["result"]["entry"].is_object(), "Close response must contain close entry");

    // Verify in database: FK linkage to transitions is produced by production code!
    let conv_row = psql_cmd(&format!(
        "SELECT lifecycle, close_transition_id, close_seq FROM chat.conversations WHERE conversation_id='{}'",
        f.conversation_id
    ))?;
    let parts: Vec<&str> = conv_row.split('|').collect();
    assert_eq!(parts[0], "superseded", "Conversation lifecycle must be superseded");
    assert_eq!(parts[1], close_tx_id.to_string(), "close_transition_id must match signed transitionId");

    let transition_count: i64 = psql_cmd(&format!(
        "SELECT count(*) FROM chat.transitions WHERE transition_id='{close_tx_id}' AND kind='closeConversation' AND conversation_id='{}'",
        f.conversation_id
    ))?.parse()?;
    assert_eq!(transition_count, 1, "chat.transitions must record closeConversation transition with exact FK");

    let consent_state: String = psql_cmd(&format!(
        "SELECT consent FROM chat.direct_request_lifecycle WHERE conversation_id='{}'",
        f.conversation_id
    ))?;
    assert_eq!(consent_state, "closed", "direct_request_lifecycle consent must be closed");

    // F1 (migration 20260919000021): publication already retired the pending
    // charge, so the signed close writes no pending release.
    let pending_releases: i64 = psql_cmd(&format!(
        "SELECT count(*) FROM chat.direct_request_pending_releases WHERE request_id='{}'",
        f.request_id
    ))?.parse()?;
    assert_eq!(pending_releases, 0, "close must not write a pending release after F1");

    let durable_after_close = durable_comprehensive(&f)?;

    // 3. Late events cannot resurrect state:
    // Attempt A: Late acceptConversation by Bob -> MUST BE REJECTED with InvitationNotPending
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "transitionId": transition_id.to_string(),
        "requestId": f.request_id.to_string(),
        "prior": f.publication["body"]["next"],
        "next": {
            "conversationId": f.conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": f.publication["body"]["next"]["groupId"],
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": f.publication["body"]["next"]["groupContextHash"],
            "confirmationTag": f.publication["body"]["next"]["confirmationTag"]
        },
        "invitationProvenance": {
            "invitationTransitionId": f.request_id.to_string(),
            "invitedByDid": f.alice.did,
            "invitedByDeviceId": f.alice.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_accept = signed_mls_request(&f.bob_engine, &bob_identity, DirectRequestKind::Accept, accept_body)?;
    let (accept_status, accept_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.acceptConversation", &json!({"directRequest": signed_accept}), true).await?;
    assert!(accept_status.is_client_error(), "Late accept must be rejected: {accept_status}");
    let accept_err: Value = serde_json::from_slice(&accept_bytes)?;
    assert_eq!(accept_err["error"], "InvitationNotPending", "Late accept must return InvitationNotPending");
    assert_eq!(durable_comprehensive(&f)?, durable_after_close, "Late accept must leave graph unchanged");

    // Attempt B: Late acknowledgeWelcome -> REJECTED
    let ack_id = Uuid::new_v4();
    let ack_body = json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "idempotencyKey": ack_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_ack = sign_mutation(&f.bob_engine, &bob_identity, SignedMutationKind::WelcomeAcknowledgement, ack_body)?;
    let (ack_status, ack_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.acknowledgeWelcome", &json!({"signedRequest": signed_ack}), true).await?;
    assert_eq!(ack_status, reqwest::StatusCode::BAD_REQUEST, "Late welcome acknowledgement on closed conversation must fail 400: {ack_status}");
    let ack_err: Value = serde_json::from_slice(&ack_bytes)?;
    assert_eq!(ack_err["error"], "WelcomeSuperseded", "Late ack on closed conversation returns typed WelcomeSuperseded error");
    assert_eq!(durable_comprehensive(&f)?, durable_after_close, "Late ack must leave graph unchanged");

    // Attempt C: Late sendMessage by Alice -> REJECTED
    let alice_identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let group = STANDARD.decode(prior["groupId"].as_str().context("group")?)?;
    let epoch = prior["epoch"].as_u64().context("epoch")?;
    let msg_id = Uuid::new_v4();
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let aad = json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(f.conversation_id.as_bytes()),
        "generation": prior["generation"],
        "messageId": STANDARD.encode(msg_id.as_bytes()),
        "prior": aad_prior
    });
    let ciphertext = alice_engine.encrypt_canonical(&group, &MLSMessagePayload::text("Late message after close").encode()?, canonical_application_aad_bytes(&aad)?, epoch)?;
    let late_send = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
        "messageId": msg_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "aad": aad,
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&ciphertext),
            "sha256": STANDARD.encode(Sha256::digest(&ciphertext))
        },
        "blobBindings": [],
        "signedAt": canonical_now()
    }))?;
    let (send_status, _) = f.alice.post(&f.client, &f.server.base_url, "blue.catbird.chat.sendMessage", &json!({"signedRequest": late_send}), true).await?;
    assert!(!send_status.is_success(), "Late sendMessage after close must fail");
    assert_eq!(durable_comprehensive(&f)?, durable_after_close, "Late send must leave graph unchanged");

    // Attempt D: Exact completed replay of the original close succeeds idempotently
    let (replay_status, replay_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.closeConversation", &close_env, true).await?;
    assert_eq!(replay_status, reqwest::StatusCode::OK, "Exact close replay must succeed 200");
    let replay_resp: Value = serde_json::from_slice(&replay_bytes)?;
    assert_eq!(replay_resp, close_resp, "Replayed close response must equal original tombstone/entry");
    assert_eq!(durable_comprehensive(&f)?, durable_after_close, "Idempotent replay must leave graph unchanged");

    // 4. No claim of retracting already decrypted content:
    // Bob's local decrypted introduction remains accessible after close.
    let intro_after = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    assert_eq!(intro_after, intro_before, "Already decrypted intro must remain readable locally");

    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn c20_close_racing_accept_close_wins() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    let (close_env, _close_tx_id) = close_envelope(&f, true, None)?;

    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "transitionId": transition_id.to_string(),
        "requestId": f.request_id.to_string(),
        "prior": f.publication["body"]["next"],
        "next": {
            "conversationId": f.conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": f.publication["body"]["next"]["groupId"],
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": f.publication["body"]["next"]["groupContextHash"],
            "confirmationTag": f.publication["body"]["next"]["confirmationTag"]
        },
        "invitationProvenance": {
            "invitationTransitionId": f.request_id.to_string(),
            "invitedByDid": f.alice.did,
            "invitedByDeviceId": f.alice.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_accept = signed_mls_request(&f.bob_engine, &bob_identity, DirectRequestKind::Accept, accept_body)?;
    let accept_env = json!({"directRequest": signed_accept});

    // Queue close first on chat.conversations FOR UPDATE (which both take in execution):
    let barrier = Barrier::hold_conversation(f.conversation_id)?;
    let close_future = {
        let (who, client, base, env) = (f.alice.clone(), f.client.clone(), f.server.base_url.clone(), close_env.clone());
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.closeConversation", &env, true).await })
    };
    let queued_first = barrier.wait_for_waiters(1).await?;

    // Then queue accept: Bob's accept blocks behind close.
    let accept_future = {
        let (who, client, base, env) = (f.bob.clone(), f.client.clone(), f.server.base_url.clone(), accept_env.clone());
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.acceptConversation", &env, true).await })
    };
    let queued_both = barrier.wait_for_waiters(2).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    barrier.release()?;

    let (close_status, close_bytes) = close_future.await??;
    let (accept_status, accept_bytes) = accept_future.await??;
    eprintln!("C20 close-vs-accept close-wins arm: queued first={queued_first} both={queued_both} close={close_status} accept={accept_status}");

    assert_eq!(close_status, reqwest::StatusCode::OK, "Close must win when queued first: {close_status}: {}", String::from_utf8_lossy(&close_bytes));
    assert_eq!(accept_status, reqwest::StatusCode::BAD_REQUEST, "Accept must fail 400 InvitationNotPending when close wins: {accept_status}");
    let accept_err: Value = serde_json::from_slice(&accept_bytes)?;
    assert_eq!(accept_err["error"], "InvitationNotPending", "Loser accept gets InvitationNotPending");

    let winners: String = psql_cmd(&format!(
        "SELECT string_agg(kind, ',' ORDER BY kind) FROM chat.transitions WHERE conversation_id='{}' AND kind IN ('closeConversation','directRequestAcceptance')",
        f.conversation_id
    ))?;
    assert_eq!(winners, "closeConversation", "only close transition is durable");
    release_by_close(&f).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_close_racing_accept_accept_wins() -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    let (close_env, _close_tx_id) = close_envelope(&f, true, None)?;

    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "transitionId": transition_id.to_string(),
        "requestId": f.request_id.to_string(),
        "prior": f.publication["body"]["next"],
        "next": {
            "conversationId": f.conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": f.publication["body"]["next"]["groupId"],
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": f.publication["body"]["next"]["groupContextHash"],
            "confirmationTag": f.publication["body"]["next"]["confirmationTag"]
        },
        "invitationProvenance": {
            "invitationTransitionId": f.request_id.to_string(),
            "invitedByDid": f.alice.did,
            "invitedByDeviceId": f.alice.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });
    let accepted_head = accept_body["next"].clone();
    let signed_accept = signed_mls_request(&f.bob_engine, &bob_identity, DirectRequestKind::Accept, accept_body)?;
    let accept_env = json!({"directRequest": signed_accept});

    // Queue accept first on chat.conversations FOR UPDATE (which both take in execution):
    let barrier = Barrier::hold_conversation(f.conversation_id)?;
    let accept_future = {
        let (who, client, base, env) = (f.bob.clone(), f.client.clone(), f.server.base_url.clone(), accept_env.clone());
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.acceptConversation", &env, true).await })
    };
    let queued_first = barrier.wait_for_waiters(1).await?;

    // Then queue close: Alice's close blocks behind accept.
    let close_future = {
        let (who, client, base, env) = (f.alice.clone(), f.client.clone(), f.server.base_url.clone(), close_env.clone());
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.closeConversation", &env, true).await })
    };
    let queued_both = barrier.wait_for_waiters(2).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    barrier.release()?;

    let (close_status, close_bytes) = close_future.await??;
    let (accept_status, accept_bytes) = accept_future.await??;
    eprintln!("C20 close-vs-accept accept-wins arm: queued first={queued_first} both={queued_both} close={close_status} accept={accept_status}");

    assert_eq!(accept_status, reqwest::StatusCode::OK, "Accept must win when queued first: {accept_status}: {}", String::from_utf8_lossy(&accept_bytes));
    assert_eq!(close_status, reqwest::StatusCode::BAD_REQUEST, "Close with stale prior must fail 400 StaleCoordinates: {close_status}");
    let close_err: Value = serde_json::from_slice(&close_bytes)?;
    assert_eq!(close_err["error"], "StaleCoordinates", "Stale prior close must return typed StaleCoordinates error");

    let winners: String = psql_cmd(&format!(
        "SELECT string_agg(kind, ',' ORDER BY kind) FROM chat.transitions WHERE conversation_id='{}' AND kind IN ('closeConversation','directRequestAcceptance')",
        f.conversation_id
    ))?;
    assert_eq!(winners, "directRequestAcceptance", "only accept transition is durable");
    release_by_close_from(&f, Some(accepted_head)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_close_racing_recipient_welcome_import_one_outcome() -> anyhow::Result<()> {
    // Publish a fresh direct request fixture
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;

    // Bob imports the Welcome natively (client-local, real OpenMLS import) and
    // decrypts the introduction; its server-visible completion is the signed
    // acknowledgeWelcome, which races Alice's signed close behind a row-lock
    // barrier on both principals.
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let intro = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    assert!(matches!(intro, DirectRequestIntroductionResult::Ready { .. }), "Bob must decrypt successfully");

    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let ack_id = Uuid::new_v4();
    let signed_ack = sign_mutation(&f.bob_engine, &bob_identity, SignedMutationKind::WelcomeAcknowledgement, json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
        "welcomeId": f.request_id.to_string(),
        "transitionSeq": 1,
        "coordinates": f.publication["body"]["next"],
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "idempotencyKey": ack_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (close_env, close_tx_id) = close_envelope(&f, true, None)?;

    let barrier = Barrier::hold(&[&f.alice.did, &f.bob.did])?;
    let close_future = {
        let (who, client, base, env) = (f.alice.clone(), f.client.clone(), f.server.base_url.clone(), close_env.clone());
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.closeConversation", &env, true).await })
    };
    let ack_future = {
        let (who, client, base, env) = (f.bob.clone(), f.client.clone(), f.server.base_url.clone(), json!({"signedRequest": signed_ack}));
        tokio::spawn(async move { who.post(&client, &base, "blue.catbird.chat.acknowledgeWelcome", &env, true).await })
    };
    let queued = barrier.wait_for_waiters(2).await?;
    barrier.release()?;
    let (close_status, close_bytes) = close_future.await??;
    let (ack_status, ack_bytes) = ack_future.await??;
    eprintln!("C20 close-vs-import race: queued={queued} close={close_status} ack={ack_status}");

    // Close is always permitted while pending, so it is the authoritative outcome
    // regardless of order; the ack is durable iff it committed before the close.
    anyhow::ensure!(close_status == reqwest::StatusCode::OK, "close must win: {close_status}: {}", String::from_utf8_lossy(&close_bytes));
    assert_eq!(
        psql_cmd(&format!("SELECT count(*) FROM chat.transitions WHERE conversation_id='{}' AND kind='closeConversation' AND transition_id='{close_tx_id}'", f.conversation_id))?,
        "1",
        "the signed close is the single durable close transition"
    );
    let acknowledged = psql_cmd(&format!(
        "SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE request_id='{}' AND status='acknowledged'",
        f.request_id
    ))?;
    if !ack_status.is_success() {
        assert_eq!(ack_status, reqwest::StatusCode::BAD_REQUEST, "Late ack must fail 400: {ack_status}");
        let ack_err: Value = serde_json::from_slice(&ack_bytes)?;
        assert_eq!(ack_err["error"], "WelcomeSuperseded", "Late ack must return typed WelcomeSuperseded error");
    }
    assert_eq!(acknowledged, if ack_status.is_success() { "1" } else { "0" }, "ack durability must match its response");

    // Authoritative outcome is that the conversation is superseded
    let lifecycle: String = psql_cmd(&format!(
        "SELECT lifecycle FROM chat.conversations WHERE conversation_id='{}'",
        f.conversation_id
    ))?;
    assert_eq!(lifecycle, "superseded", "Authoritative outcome must be superseded");

    // Bob's subsequent accept attempt is rejected with InvitationNotPending
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": bob_key_id,
        "authGeneration": 1,
        "transitionId": transition_id.to_string(),
        "requestId": f.request_id.to_string(),
        "prior": f.publication["body"]["next"],
        "next": {
            "conversationId": f.conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": f.publication["body"]["next"]["groupId"],
            "epoch": 1,
            "lifecycle": "active",
            "groupContextHash": f.publication["body"]["next"]["groupContextHash"],
            "confirmationTag": f.publication["body"]["next"]["confirmationTag"]
        },
        "invitationProvenance": {
            "invitationTransitionId": f.request_id.to_string(),
            "invitedByDid": f.alice.did,
            "invitedByDeviceId": f.alice.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });
    let signed_accept = signed_mls_request(&f.bob_engine, &bob_identity, DirectRequestKind::Accept, accept_body)?;
    let (accept_status, accept_bytes) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.acceptConversation", &json!({"directRequest": signed_accept}), true).await?;
    assert!(accept_status.is_client_error(), "Post-close accept must fail");
    let accept_err: Value = serde_json::from_slice(&accept_bytes)?;
    assert_eq!(accept_err["error"], "InvitationNotPending");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_block_prevents_repeat_request_under_current_rules() -> anyhow::Result<()> {
    // 1. Initial direct request from Alice to Bob succeeds and is published
    let f = live_direct_request::publish_request(false).await?;
    f.alice_engine.as_ref().context("Alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;

    // 2. Terminal close via real RPC by Bob
    let (close_env, _) = close_envelope(&f, false, None)?;
    let (close_status, _) = f.bob.post(&f.client, &f.server.base_url, "blue.catbird.chat.closeConversation", &close_env, true).await?;
    assert_eq!(close_status, reqwest::StatusCode::OK);

    // 3. Set relationship policy override in HTTPS fixture:
    // Direct admission queries actor=recipient (Bob), others=[inviter (Alice)].
    // Bob blocks Alice: on the row (actor=Bob, other=Alice), set "blocking" URI!
    set_recipient_view(
        &f._https.root,
        &f.bob.did,
        &f.alice.did,
        json!({"blocking": record_uri(&f.bob.did, "app.bsky.graph.block")}),
    )?;

    // Wait for the 60s fallback projection cache to age out so the router re-collects live policy
    tokio::time::sleep(Duration::from_secs(62)).await;

    // 4. Alice attempts a repeat prepareDirectRequest to Bob
    let req2_id = Uuid::new_v4();
    let alice_identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let alice_engine = f.alice_engine.as_ref().context("Alice engine")?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));

    let prep2 = signed_mls_request(
        alice_engine,
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": f.alice.did,
            "actorDeviceId": f.alice.device_id.to_string(),
            "keyId": alice_key_id,
            "authGeneration": 1,
            "requestId": req2_id.to_string(),
            "firstMessageId": Uuid::new_v4().to_string(),
            "conversationId": Uuid::new_v4().to_string(),
            "recipientDid": f.bob.did,
            "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
            "profile": "encryptedIntroduction1",
            "idempotencyKey": req2_id.to_string(),
            "signedAt": canonical_now()
        }),
    )?;

    let (prep2_status, prep2_bytes) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest": prep2}),
            true,
        )
        .await?;

    // Server must reject with RequestPolicyDenied receipt!
    let prep2_resp: Value = serde_json::from_slice(&prep2_bytes)?;
    expect_rejected_receipt(prep2_status, &prep2_resp, &f.server.receipt_public_key, "RequestPolicyDenied")?;

    // Verify in database: NO published attempt row for the new request, NO new conversation row!
    let attempts: i64 = psql_cmd(&format!(
        "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{req2_id}' AND status='published'"
    ))?.parse()?;
    assert_eq!(attempts, 0, "No published attempt allowed after block");

    Ok(())
}

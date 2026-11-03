//! Paired real DS + Nest D2 direct-request wake runner (t16, c32).
//!
//! Nest runs `services::push::request_events::*` as a second process serving
//! its production Push Gateway on loopback. Bob registers synthetic native
//! tokens there (`blue.catbird.push.registerKey`) and receives opaque push
//! keys, registers the latest key with his DS through the real
//! `registerPushGateway`, and a separate DS fixture process drives the
//! publication's durable wake through the production worker. Native tokens
//! exist only in this process and on loopback HTTP; no artifact holds them.

use super::encrypted_requests::{psql_query, PushFixtureConfig, ShippingServerFixture};
use super::live_direct_request::{
    register_push_gateway, register_push_override, PublishedRequestFixture,
};
use anyhow::Context as _;
use base64::Engine as _;
use serde_json::{json, Value};
use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

const APP_ID: &str = "blue.catbird";
const DS_DID: &str = "did:web:chat.catbird.blue";

struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.take().expect("child already consumed").wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn wait_json(path: &Path, timeout: Duration) -> anyhow::Result<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            return serde_json::from_slice(&bytes)
                .with_context(|| format!("parse paired artifact {}", path.display()));
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for paired artifact {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What both processes reported for one paired run.
pub struct PairedOutcome {
    pub ds: Value,
    pub nest: Value,
    /// `(status, attempt_count)` of the publication's durable wake row.
    pub outbox: (String, i64),
}

/// Run `scenario` against Nest's `harness` test. `platforms` are Bob's native
/// token registrations in order; the last one is his current gateway key.
pub async fn run(
    fixture: &PublishedRequestFixture,
    prefix: &str,
    harness: &str,
    scenario: &str,
    platforms: &[&str],
) -> anyhow::Result<PairedOutcome> {
    let paired_dir = std::path::PathBuf::from(format!("/tmp/{prefix}{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&paired_dir)?;
    let nest_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../nest/catbird")
        .canonicalize()?;
    let mut child = Command::new("cargo")
        .args([
            "test",
            "--lib",
            harness,
            "--",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(nest_root)
        .env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .env(
            "CATBIRD_REQUEST_PUSH_TEST_DB",
            "postgres://joshlacalamito@127.0.0.1:5432/catbird_request_push_test_20260919",
        )
        .env("CATBIRD_REQUEST_PUSH_PAIRED_DIR", &paired_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(std::fs::File::create(
            paired_dir.join("nest.stdout.log"),
        )?))
        .stderr(Stdio::from(std::fs::File::create(
            paired_dir.join("nest.stderr.log"),
        )?))
        .spawn()
        .context("start paired Nest test process")?;
    // Bob's DID document names this DS as his `#atproto_mls` service, which
    // binds every key Nest issues him to wakes signed by this DS.
    let mut recipient_document = fixture.bob.did_document();
    recipient_document["service"]
        .as_array_mut()
        .context("fixture DID document services")?
        .push(json!({
            "id": "#atproto_mls",
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": DS_DID,
        }));
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(&fixture.server.service_public_key);
    let stdin_fixture = json!({
        "eventId": fixture.push_event_id,
        "conversationId": fixture.conversation_id,
        "recipientDid": fixture.bob.did,
        "recipientDidDocument": recipient_document,
        "dsDidDocument": {
            "id": DS_DID,
            "verificationMethod": [{
                "id": format!("{DS_DID}#atproto"),
                "type": "Multikey",
                "controller": DS_DID,
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey),
            }],
        },
        "scenario": scenario,
    });
    child
        .stdin
        .take()
        .context("paired Nest stdin unavailable")?
        .write_all(&serde_json::to_vec(&stdin_fixture)?)?;
    let nest = ChildGuard(Some(child));

    let ready = wait_json(
        &paired_dir.join("nest-ready.json"),
        Duration::from_secs(300),
    )
    .await?;
    anyhow::ensure!(
        ready["eventId"] == fixture.push_event_id.to_string(),
        "Nest readiness event identity mismatch"
    );
    let field = |name: &str| -> anyhow::Result<String> {
        Ok(ready[name]
            .as_str()
            .with_context(|| format!("Nest readiness lacks {name}"))?
            .to_owned())
    };
    let (gateway_url, ingress_url, register_url) = (
        field("gatewayUrl")?,
        field("ingressUrl")?,
        field("registerUrl")?,
    );
    register_push_override(
        &fixture.client,
        &fixture.server.base_url,
        &gateway_url,
        &ingress_url,
    )
    .await?;
    for platform in platforms {
        let native_token = format!(
            "{prefix}{platform}-token-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>())
        );
        let registered: Value = fixture
            .client
            .post(&register_url)
            .json(&json!({
                "deviceId": fixture.bob.device_id,
                "appId": APP_ID,
                "platform": platform,
                "nativeToken": native_token,
            }))
            .send()
            .await?
            .error_for_status()
            .context("Nest registerKey")?
            .json()
            .await?;
        anyhow::ensure!(
            registered["gatewayUrl"] == gateway_url.as_str() && registered["appId"] == APP_ID,
            "Nest issued a key for another gateway: {registered}"
        );
        let push_key = registered["pushKey"]
            .as_str()
            .context("Nest issued no pushKey")?;
        anyhow::ensure!(
            !push_key.contains(&native_token),
            "push key embeds the token"
        );
        register_push_gateway(
            &fixture.client,
            &fixture.server.base_url,
            &fixture.bob,
            &fixture.bob_engine,
            &gateway_url,
            APP_ID,
            push_key,
        )
        .await?;
    }

    let trigger_path = paired_dir.join("ds-trigger");
    let result_path = paired_dir.join("ds-result.json");
    let push_server = ShippingServerFixture::start_with_push(
        &fixture._https,
        &PushFixtureConfig {
            event_id: fixture.push_event_id,
            trigger_path: trigger_path.clone(),
            result_path: result_path.clone(),
        },
    )?;
    register_push_override(
        &fixture.client,
        &push_server.base_url,
        &gateway_url,
        &ingress_url,
    )
    .await?;
    std::fs::write(&trigger_path, b"dispatch\n")?;

    let ds = wait_json(&result_path, Duration::from_secs(60)).await?;
    anyhow::ensure!(
        ds["ok"] == true
            && ds["claimed"] == 1
            && ds["eventId"] == fixture.push_event_id.to_string(),
        "DS targeted worker did not complete exact wake: {ds}"
    );
    let nest_result = wait_json(
        &paired_dir.join("nest-result.json"),
        Duration::from_secs(180),
    )
    .await?;
    anyhow::ensure!(nest_result["eventId"] == fixture.push_event_id.to_string());
    let status = tokio::task::spawn_blocking(move || nest.wait())
        .await
        .context("join Nest waiter")??;
    anyhow::ensure!(
        status.success(),
        "paired Nest test process failed: {status}"
    );
    let row = psql_query(&format!(
        "SELECT o.status,o.attempt_count FROM chat.outbox o \
           JOIN chat.direct_request_push_events e USING(outbox_id) \
          WHERE e.event_id='{}'",
        fixture.push_event_id
    ))?;
    let (status, attempts) = row
        .trim()
        .split_once('\t')
        .context("publication wake row")?;
    drop(push_server);
    Ok(PairedOutcome {
        ds,
        nest: nest_result,
        outbox: (status.to_owned(), attempts.parse()?),
    })
}

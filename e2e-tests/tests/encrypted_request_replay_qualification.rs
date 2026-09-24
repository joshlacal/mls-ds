//! Bounded shipping-service replay and compatibility qualification.
//! No shared fixture mutations; every database read uses the guarded local target.
#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
        DirectRequestWelcomeInput,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_snapshot,
    reviewed_baseline, reviewed_request_migrations, seed_service_device, signed_mls_request,
    validate_request_test_database_url, DeterministicFaultTransport, FaultBoundary,
    HttpsDidFixture, RequestRig, ServiceIdentity, ShippingServerFixture, request_database_url,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

/// Compare exact retained authority and crypto rows without logging their bytes.
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
    let result = std::process::Command::new("psql")
        .args([
            request_database_url(),
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ])
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "guarded authority snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

async fn replay(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<Vec<u8>> {
    let (status, response) = f
        .alice
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":f.publication}),
            true,
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "exact publication replay failed {status}: {}",
        String::from_utf8_lossy(&response)
    );
    Ok(response)
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_publication_replays_after_native_reopen_without_crypto_or_graph_changes(
) -> anyhow::Result<()> {
    let mut f = live_direct_request::publish_request(false).await?;
    let before = durable_graph(&f)?;
    let exact = serde_json::to_vec(&json!({"signedRequest":f.publication}))?;
    // The real service committed, but its receipt has never been handed to the
    // native journal. Dropping that context exercises the pre-adoption boundary.
    let offline = f
        .alice_engine
        .take()
        .context("sender")?
        .close_for_offline()?;
    let reopened = offline.reopen()?;
    reopened.persist_request_publication(&f.request_id.to_string(), &exact)?;
    let first = replay(&f).await?;
    let second = replay(&f).await?;
    anyhow::ensure!(
        first == second,
        "exact replay changed immutable response bytes"
    );
    let response: Value = serde_json::from_slice(&first)?;
    let mut receipt = response["outcome"].clone();
    receipt.as_object_mut().context("outcome")?.remove("$type");
    anyhow::ensure!(
        receipt == f.receipt,
        "replayed receipt differs from original committed proof"
    );
    reopened.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&receipt)?,
        &f.server.receipt_public_key,
    )?;
    let group = STANDARD.decode(
        f.welcome_input.bootstrap.coordinates["groupId"]
            .as_str()
            .context("groupId")?,
    )?;
    assert_eq!(
        reopened.epoch(&group)?,
        f.welcome_input.bootstrap.coordinates["epoch"]
            .as_u64()
            .context("epoch")?
    );
    let (status, outcome) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), f.request_id.to_string())],
        )
        .await?;
    assert_eq!(status, reqwest::StatusCode::OK);
    let outcome: Value = serde_json::from_slice(&outcome)?;
    anyhow::ensure!(
        outcome["outcome"] == response["outcome"],
        "outcome lookup differs from exact committed replay"
    );
    anyhow::ensure!(
        durable_graph(&f)? == before,
        "replay mutated retained crypto, consumed packages, or publication graph"
    );
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } =
        f.bob_engine.decrypt_direct_request(&f.welcome_input)?
    else {
        anyhow::bail!("intro unavailable")
    };
    assert_eq!(
        protocol::decode_direct_request_introduction(&plaintext)?["text"],
        "Real encrypted first contact"
    );
    let snapshot = request_database_snapshot(f.request_id)?;
    assert_eq!(snapshot.message_rows, 1);
    assert_eq!(snapshot.welcome_rows, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_operation_rejects_resigned_artifact_digest_id_and_signature_collisions(
) -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let before = durable_graph(&f)?;
    let engine = f.alice_engine.as_ref().context("sender")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let mut variants = Vec::new();
    for field in ["ciphertext", "digest", "firstMessageId"] {
        let mut body = f.publication["body"].clone();
        match field {
            "ciphertext" => {
                let mut b =
                    STANDARD.decode(body["artifacts"]["initialCiphertext"].as_str().unwrap())?;
                b[0] ^= 1;
                body["artifacts"]["initialCiphertext"] = json!(STANDARD.encode(b));
            }
            "digest" => body["artifacts"]["welcome"]["sha256"] = json!(STANDARD.encode([0x55; 32])),
            _ => body["firstMessageId"] = json!(Uuid::new_v4().to_string()),
        }
        variants.push((
            field,
            signed_mls_request(engine, &identity, DirectRequestKind::Publish, body)?,
        ));
    }
    let mut bad_signature = f.publication.clone();
    let mut signature =
        STANDARD.decode(bad_signature["signature"].as_str().context("signature")?)?;
    signature[0] ^= 1;
    bad_signature["signature"] = json!(STANDARD.encode(signature));
    variants.push(("signature", bad_signature));
    for (field, changed) in variants {
        let envelope = json!({"signedRequest":changed});
        anyhow::ensure!(
            engine
                .persist_request_publication(
                    &f.request_id.to_string(),
                    &serde_json::to_vec(&envelope)?
                )
                .is_err(),
            "local immutable journal accepted {field} collision"
        );
        let (status, response) = f
            .alice
            .post(
                &f.client,
                &f.server.base_url,
                "blue.catbird.chat.publishDirectRequest",
                &envelope,
                true,
            )
            .await?;
        anyhow::ensure!(
            status.is_client_error(),
            "{field} collision unexpectedly returned {status}"
        );
        let error: Value = serde_json::from_slice(&response)?;
        let expected = if field == "signature" {
            "InvalidSignature"
        } else {
            "PreparationConflict"
        };
        assert_eq!(
            error["error"], expected,
            "unexpected collision error for {field}"
        );
        anyhow::ensure!(
            durable_graph(&f)? == before,
            "{field} collision altered retained publication graph"
        );
    }
    replay(&f).await?;
    anyhow::ensure!(
        durable_graph(&f)? == before,
        "valid replay after collisions changed retained graph"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unscoped_reader_is_rejected_while_capable_reader_retains_pending_request(
) -> anyhow::Result<()> {
    let f = live_direct_request::publish_request(false).await?;
    let before = durable_graph(&f)?;
    let (status, bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[("limit".into(), "100".into())],
        )
        .await?;
    anyhow::ensure!(
        status.is_client_error(),
        "unscoped inventory returned a successful partial view"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes)?["error"],
        "ProtocolUpgradeRequired"
    );
    let (status, bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "capable inventory failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    let items = value["conversations"]
        .as_array()
        .or_else(|| value["items"].as_array())
        .context("inventory items")?;
    anyhow::ensure!(
        items
            .iter()
            .any(|item| item["state"]["coordinates"]["conversationId"]
                == f.conversation_id.to_string()
                || item["coordinates"]["conversationId"] == f.conversation_id.to_string()),
        "capable inventory omitted published request"
    );
    anyhow::ensure!(
        durable_graph(&f)? == before,
        "inventory read altered retained publication graph"
    );
    Ok(())
}

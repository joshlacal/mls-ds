//! C03 schema-valid nested publication signature binding qualification.
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
    let actor = f.alice.did.replace('\'', "''");
    let sql = format!(
        r#"SELECT jsonb_build_object(
      'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY request_id) FROM chat.direct_request_attempts a WHERE actor_did='{actor}'),
      'claims',(SELECT jsonb_agg(to_jsonb(o) ORDER BY operation_id) FROM chat.operation_claims o WHERE principal_did='{actor}'),
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

fn changed_leaf(value: &Value, path: &str) -> anyhow::Result<Value> {
    if let Some(n) = value.as_u64() {
        return Ok(json!(n + 1));
    }
    let s = value
        .as_str()
        .context("mutation leaf must be text or integer")?;
    if s.starts_with("did:") {
        return Ok(json!("did:plc:cccccccccccccccccccccccc"));
    }
    if Uuid::parse_str(s).is_ok() {
        return Ok(json!(Uuid::new_v4().to_string()));
    }
    if path.ends_with("KeyId") || path == "/keyId" {
        let mut bytes = URL_SAFE_NO_PAD.decode(s)?;
        bytes[0] ^= 1;
        return Ok(json!(URL_SAFE_NO_PAD.encode(bytes)));
    }
    if path.ends_with("importUntil") || path.ends_with("signedAt") {
        let dt = chrono::DateTime::parse_from_rfc3339(s)? + chrono::Duration::seconds(1);
        return Ok(json!(dt
            .to_utc()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
    }
    if path.ends_with("lifecycle") {
        return Ok(json!("superseded"));
    }
    let mut bytes = STANDARD
        .decode(s)
        .with_context(|| format!("binary path {path}"))?;
    anyhow::ensure!(!bytes.is_empty(), "empty mutation input {path}");
    bytes[0] ^= 1;
    Ok(json!(STANDARD.encode(bytes)))
}

#[tokio::test(flavor = "multi_thread")]
async fn schema_valid_nested_publication_mutations_fail_before_graph_effects() -> anyhow::Result<()>
{
    let f = live_direct_request::publish_request(false).await?;
    let graph = durable_graph(&f)?;
    let body = &f.publication["body"];
    let control = protocol::direct_request_signing_bytes(
        DirectRequestKind::Publish,
        &serde_json::to_vec(body)?,
    )?;
    let sender = f.alice_engine.as_ref().context("sender")?;
    let public = sender.identity_public_key(&format!("{}#{}", f.alice.did, f.alice.device_id))?;
    protocol::verify_signed_request(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&f.publication)?,
        &public,
    )?;
    let paths = [
        "/actorDid",
        "/actorDeviceId",
        "/keyId",
        "/authGeneration",
        "/requestId",
        "/firstMessageId",
        "/conversationId",
        "/recipientDid",
        "/idempotencyKey",
        "/preparationDigest",
        "/preparationRequestDigest",
        "/contextHash",
        "/importUntil",
        "/signedAt",
        "/next/conversationId",
        "/next/generation",
        "/next/stateVersion",
        "/next/groupId",
        "/next/epoch",
        "/next/groupContextHash",
        "/next/confirmationTag",
        "/next/lifecycle",
        "/artifacts/genesisGroupInfo/bytes",
        "/artifacts/genesisGroupInfo/sha256",
        "/artifacts/addCommit/bytes",
        "/artifacts/addCommit/sha256",
        "/artifacts/finalGroupInfo/bytes",
        "/artifacts/finalGroupInfo/sha256",
        "/artifacts/welcome/opaqueWelcome",
        "/artifacts/welcome/sha256",
        "/artifacts/welcome/deliveries/0/recipientDid",
        "/artifacts/welcome/deliveries/0/recipientDeviceId",
        "/artifacts/welcome/deliveries/0/provenance/requestId",
        "/artifacts/welcome/deliveries/0/provenance/preparationDigest",
        "/artifacts/welcome/deliveries/0/provenance/contextHash",
        "/artifacts/welcome/deliveries/0/provenance/grantId",
        "/artifacts/welcome/deliveries/0/provenance/grantRevision",
        "/artifacts/welcome/deliveries/0/provenance/keyPackageRef",
        "/artifacts/welcome/deliveries/0/provenance/importUntil",
        "/artifacts/metadataSnapshot/coordinate/conversationId",
        "/artifacts/metadataSnapshot/coordinate/generation",
        "/artifacts/metadataSnapshot/coordinate/groupId",
        "/artifacts/metadataSnapshot/coordinate/epoch",
        "/artifacts/metadataSnapshot/coordinate/groupContextHash",
        "/artifacts/metadataSnapshot/coordinate/confirmationTag",
        "/artifacts/metadataSnapshot/originTransitionId",
        "/artifacts/metadataSnapshot/nonce",
        "/artifacts/metadataSnapshot/ciphertext",
        "/artifacts/metadataSnapshot/ciphertextSha256",
        "/artifacts/metadataSnapshot/authorProof/authorDid",
        "/artifacts/metadataSnapshot/authorProof/authorDeviceId",
        "/artifacts/metadataSnapshot/authorProof/authorKeyId",
        "/artifacts/metadataSnapshot/authorProof/signaturePublicKey",
        "/artifacts/metadataSnapshot/authorProof/authGenerationAtOrigin",
        "/artifacts/metadataSnapshot/authorProof/originTransitionId",
        "/artifacts/metadataSnapshot/authorProof/originSeq",
        "/artifacts/initialCiphertext",
    ];
    for path in paths {
        let mut altered = f.publication.clone();
        let leaf = altered["body"]
            .pointer_mut(path)
            .with_context(|| format!("missing required binding {path}"))?;
        let replacement = changed_leaf(leaf, path)?;
        anyhow::ensure!(*leaf != replacement, "mutation must change {path}");
        *leaf = replacement;
        // Rejecting malformed schema is not evidence of a signature binding.
        let changed = protocol::direct_request_signing_bytes(
            DirectRequestKind::Publish,
            &serde_json::to_vec(&altered["body"])?,
        )
        .with_context(|| format!("mutation must preserve schema for {path}"))?;
        anyhow::ensure!(control != changed, "canonical transcript omitted {path}");
        anyhow::ensure!(
            protocol::verify_signed_request(
                DirectRequestKind::Publish,
                &serde_json::to_vec(&altered)?,
                &public
            )
            .is_err(),
            "signature accepted {path}"
        );
        let (status, raw) = f
            .alice
            .post(
                &f.client,
                &f.server.base_url,
                "blue.catbird.chat.publishDirectRequest",
                &json!({"signedRequest":altered}),
                true,
            )
            .await?;
        let response: Value = serde_json::from_slice(&raw)?;
        // Since f38efd4b the publish handler verifies the signature before store
        // admission, with the key of the authenticated principal at the claimed
        // device and keyId: an unknown device or keyId has no signer key, and a
        // foreign actorDid fails that signature.
        let expected = if matches!(path, "/actorDeviceId" | "/keyId") {
            "NotAuthorized"
        } else {
            "InvalidSignature"
        };
        anyhow::ensure!(
            status.is_client_error() && response["error"] == expected,
            "{path} expected {expected}, received {status}: {response}"
        );
        anyhow::ensure!(
            durable_graph(&f)? == graph,
            "{path} changed retained authority/crypto graph"
        );
        println!("C03 nested signature binding rejected with unchanged graph: {path}");
    }
    // A damaged attempt must not poison the original authenticated request.
    let (status, raw) = f
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
        "valid control no longer replays"
    );
    let response: Value = serde_json::from_slice(&raw)?;
    let mut receipt = response["outcome"].clone();
    receipt.as_object_mut().context("outcome")?.remove("$type");
    anyhow::ensure!(receipt == f.receipt, "valid control changed receipt");
    anyhow::ensure!(durable_graph(&f)? == graph, "valid control changed graph");
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } =
        f.bob_engine.decrypt_direct_request(&f.welcome_input)?
    else {
        anyhow::bail!("valid control intro unavailable")
    };
    assert_eq!(
        protocol::decode_direct_request_introduction(&plaintext)?["text"],
        "Real encrypted first contact"
    );
    Ok(())
}
